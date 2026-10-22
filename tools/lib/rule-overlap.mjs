// tools/lib/rule-overlap.mjs — 清理规则「跨条目整树覆盖」判据（唯一实现，门禁与合成样本共用）
//
// 为什么要有它：扫描侧每条 item 各自遍历自己的目标，跨条目**不去重**，而渲染层汇总历来
// 逐条相加。2026-10-22 真机实测 gfx 组：`nvidiaCache`（pathPs 整树）报的 387,378,791 B 与
// `nvidiaShaderCache` 清单里落在同一目录树下的 162 个文件**逐字节相等** ⇒ 界面显示 976 MB、
// 真实可清 607 MB（虚高 1.61×）。这件事旧门禁完全瞎：
//   · 装载侧登记册只收 fileKeys/regKeys 的**精确重复**，pathPs 从不入册；
//   · 原 4c 那条「父子重叠」清单只收 fileKeys、跳过一切带 `*` 的路径，且「不判红」。
//
// 判据边界（都写在这里，别再抄第二份）：
//   1. 只按**字面**比较，不触盘、不展开变量 —— 门禁必须换机器同结论；
//   2. 只有「覆盖方整树计数」才算重叠：pathPs 支恒递归且 pattern 恒 `*`，
//      fileKeys 支要 `pattern === '*'` 且 `recurse !== false`；
//   3. 被覆盖方无论 recurse/pattern 如何，它计到的文件必然落在覆盖方的根子树内；
//   4. pathPs 表达式解析不了 ⇒ 显式回报 unresolved，**不许静默跳过**
//      （静默跳过就是旧门禁的失明方式）。

const BS = String.fromCharCode(92);

/** 折叠分隔符 / 去空段 / 统一小写（只看字面，不展开变量）。 */
export function canonPath(s) {
  return String(s).toLowerCase().split('/').join(BS).split(BS).filter((x) => x !== '').join(BS);
}

/**
 * `$env:X + '\a\b'` / `('a' + $env:X)` / `'C:\x'` 三形态折成 `%X%\a\b` 字面键。
 * 解析不了返回 null（调用方必须把它当成一条待处理结果，不能忽略）。
 */
export function canonPathPs(expr) {
  const text = String(expr).trim().replace(/^\((.*)\)$/s, '$1').trim();
  if (!text) return null;
  // 按单引号外的 `+` 切段：`'\Dism++Backup'` 里的 `+` 是路径字符，
  // naive split 会把一条合法规则误报成「形态未知」（原型踩过）。
  const parts = [];
  let cur = '';
  let inQuote = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "'") {
      if (inQuote && text[i + 1] === "'") { cur += "''"; i++; continue; }
      inQuote = !inQuote;
      cur += ch;
      continue;
    }
    if (ch === '+' && !inQuote) { parts.push(cur); cur = ''; continue; }
    cur += ch;
  }
  parts.push(cur);
  let out = '';
  for (const raw of parts.map((x) => x.trim()).filter(Boolean)) {
    const env = raw.match(/^\$env:([A-Za-z][A-Za-z0-9]*)$/);
    if (env) { out += `%${env[1].toUpperCase()}%`; continue; }
    const lit = raw.match(/^'(.*)'$/s);
    if (lit) { out += lit[1].replace(/''/g, "'"); continue; }
    return null;
  }
  const c = canonPath(out);
  return c || null;
}

/** 第一个含通配的段之前的静态前缀（`%x%\nvidia\*cache` → `%x%\nvidia`）。 */
export function staticPrefix(canon) {
  const segs = String(canon).split(BS);
  const cut = segs.findIndex((x) => x.includes('*') || x.includes('?'));
  return cut < 0 ? canon : segs.slice(0, cut).join(BS);
}

/** 一条 item 的全部目标（ps 与 fileKeys 两形状）+ 解析不了的 pathPs 原文。 */
export function itemTargets(it) {
  const targets = [];
  const unresolved = [];
  if (typeof it.pathPs === 'string' && it.pathPs) {
    const c = canonPathPs(it.pathPs);
    if (c === null) unresolved.push({ id: it.id, expr: it.pathPs });
    else targets.push({ id: it.id, kind: 'ps', canon: c, coversWholeTree: true, raw: it.pathPs });
  }
  for (const fk of it.fileKeys ?? []) {
    if (!fk || typeof fk !== 'object' || typeof fk.path !== 'string') continue;
    const c = canonPath(fk.path);
    if (!c) continue;
    targets.push({
      id: it.id,
      kind: 'file',
      canon: c,
      coversWholeTree: (fk.pattern ?? '*') === '*' && fk.recurse !== false,
      raw: fk.path,
    });
  }
  return { targets, unresolved };
}

/** 覆盖方的根是否把被覆盖方的目标整段包住（同根 / 同根下的通配子段 / 更深的子树）。 */
function coveredBy(parentCanon, childCanon) {
  if (childCanon === parentCanon) return true;
  const bp = staticPrefix(childCanon);
  if (!bp || bp.length < parentCanon.length) return false;
  if (bp.length > parentCanon.length) return bp.startsWith(parentCanon + BS);
  // 静态前缀正好等于覆盖方的根，而通配段在它之下 ⇒ 展开结果必然都在根子树内
  return childCanon.startsWith(parentCanon + BS);
}

/**
 * 现算全部「跨条目整树覆盖」关系。输出**按有向覆盖关系**成行（A 整树包住 B 是一行；
 * 同根且双方都整树 ⇒ 两行，因为两侧各自都把对方的文件又算了一遍，是两个独立的虚高来源）。
 * 遍历序固定（字典序），同输入逐字节同输出。返回 `{ pairs, unresolved }`。
 */
export function findWholeTreeOverlaps(items) {
  const all = [];
  const unresolved = [];
  for (const it of items) {
    const r = itemTargets(it);
    all.push(...r.targets);
    for (const u of r.unresolved) unresolved.push(u);
  }
  const hits = new Map();
  for (const a of all) {
    if (!a.coversWholeTree) continue;
    for (const b of all) {
      if (a.id === b.id) continue;
      if (!coveredBy(a.canon, b.canon)) continue;
      const key = `${a.id}\n${b.id}\n${a.raw}\n${b.raw}`;
      hits.set(key, {
        parentId: a.id,
        childId: b.id,
        parentTarget: a.raw,
        childTarget: b.raw,
        sameDir: a.canon === b.canon,
      });
    }
  }
  const pairs = [...hits.values()].sort((x, y) =>
    x.parentId === y.parentId
      ? x.childId === y.childId
        ? x.parentTarget === y.parentTarget
          ? String(x.childTarget).localeCompare(String(y.childTarget))
          : String(x.parentTarget).localeCompare(String(y.parentTarget))
        : x.childId.localeCompare(y.childId)
      : x.parentId.localeCompare(y.parentId),
  );
  unresolved.sort((x, y) => (x.id === y.id ? String(x.expr).localeCompare(String(y.expr)) : x.id.localeCompare(y.id)));
  return { pairs, unresolved };
}

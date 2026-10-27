'use strict';
// tools/check-handle-lifecycle.mjs —— 原生层**句柄生命周期**三闸（2026-10-28 全仓重审 P2-c）
//
// 出处：A5-M01（`CreateEventW` 不判 NULL）/ A5-M02（Toolhelp 快照从不关）/
//       A5-M03 与 R5c-M03 同坐标（`FindFirstStreamW` 用 `CloseHandle` 收尾）。
//
// 三条分立的理由（写成一句「句柄要关好」就永远测不出东西）：
//   L1 收尾 API 用错家族：搜索句柄（`FindFirst*` 系）只能用 `FindClose`。`CloseHandle`
//      多数情况也能把对象释放掉 ⇒ 症状极轻、肉眼不可见；但内核侧这次枚举挂的 context
//      不会被拆。修复前全仓 `FindClose` 零命中（取数见 `R5c.md` §3）。
//   L2 获取侧不判定：不判的后果通常不是崩，而是**把失败折成合法句柄** ——
//      `CreateEventW` 失败 ⇒ NULL 被投进 `WaitForMultipleObjects` 的等待集 ⇒ wait 返回
//      WAIT_FAILED ⇒ 落进 `continue` 空转 ⇒ 该阶段测出零 ops 却报「测速完成」。
//   L3 判了却从不关：`let _ = snap;` 只消 unused 警告、不产生任何 syscall，
//      它与「真的关了」在字面上只差十来个字符 ⇒ 肉眼极易放过。
//
// 为什么不并入 `check-native-hygiene`：T1a 单元精读行数已逼近 U2 上限、余量不足，
// 按 `review-units` 自述口径「优先按执行链切」，句柄生命周期单独成门禁落 T1b 兜底位。
//
// 用法：node tools/check-handle-lifecycle.mjs

import { readFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { gate } from './lib/gate.mjs';
import { blankNonCode, splitFunctions, lineAt } from './lib/src-scan.mjs';
import { handleBindRe } from './lib/rust-parse.mjs';
import { walkRs } from './lib/fs-walk.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const ROOTS = [join(ROOT, 'src-tauri', 'src'), join(ROOT, 'native-scanner', 'src')];

// ---------- L1：搜索句柄必须由 `FindClose` 收尾 ----------
//
// 只报「有获取点、无 FindClose」这一向：没有获取点的函数自然不需要关，反向断言没有意义。
// 判定作用在 `blankNonCode` 之后的文本上 ⇒ 注释里写 `FindClose(` 不顶账。
const SEARCH_FIRST_RE = /FindFirst(?:File|Stream|FileName|Volume|ChangeNotification)\w*\s*\(/;
const FIND_CLOSE_RE = /FindClose\s*\(/;

/** 按 fn 边界切分，body 已剥注释与字符串字面量。 */
function rustFns(code) {
  const blanked = blankNonCode(code, 'rs');
  return splitFunctions(code, 'rs').map((f) => ({
    name: f.name,
    line: lineAt(code, f.start),
    body: blanked.slice(f.bodyStart, f.end - 1),
  }));
}

/** @returns {{name:string,line:number}[]} 取到搜索句柄但同函数内没有 FindClose 的函数 */
function searchHandleUnclosed(code) {
  return rustFns(code)
    .filter((f) => SEARCH_FIRST_RE.test(f.body) && !FIND_CLOSE_RE.test(f.body))
    .map((f) => ({ name: f.name, line: f.line }));
}

// ---------- L2：句柄返回值绑定后必须判定 ----------
//
// 判定形态：判空 / 判 INVALID / 与零或负一比较 / `match` / `?` 传播 / `.ok()` 转 Result。
// `\.ok\s*\(` 与 `\bOk\s*\(` 都必须收：前者是 `Result::ok()`，后者是 `if let Ok(h) = ..`，
// 漏掉后者会把「解包后再关」的合规形状（`contextmenu.rs::open_regedit_native`）误报成漏关。
const HANDLE_CHECK_RE =
  /is_null\s*\(|is_err\s*\(|is_ok\s*\(|INVALID_HANDLE|\.ok\s*\(|\bOk\s*\(|==\s*0|!=\s*0|==\s*-1|!=\s*-1|\bmatch\b|\?/;
const HANDLE_CHECK_WINDOW = 2; // 语句结束之后的余量行数（语句本身另算）

/**
 * @returns {{line:number,snippet:string}[]} 绑定句柄后窗口内无判定的获取点
 *
 * 窗口为什么按「语句」而不是固定行数往下数：多行实参调用
 * （`let h = CreateFileW(\n …\n);`）会把判定挤出固定行数窗口 ⇒ 真实的合规点被误报。
 * 另外要先压掉空行：剥完注释后原注释行只剩空白，而「获取 → 几行注释 → 判空」
 * 正是修复后 `perf.rs` 的形状。
 */
function handleUnchecked(code) {
  const kept = [];
  blankNonCode(code, 'rs')
    .split('\n')
    .forEach((t, i) => {
      if (t.trim() !== '') kept.push({ n: i + 1, t });
    });
  const out = [];
  for (let i = 0; i < kept.length; i++) {
    const m = handleBindRe().exec(kept[i].t);
    if (!m) continue;
    let end = i;
    while (end < kept.length && !kept[end].t.includes(';')) end++;
    end = Math.min(end + 1 + HANDLE_CHECK_WINDOW, kept.length);
    const win = kept
      .slice(i, end)
      .map((k) => k.t)
      .join('\n');
    if (!HANDLE_CHECK_RE.test(win)) out.push({ line: kept[i].n, snippet: `${m[1]}（未见判定）` });
  }
  return out;
}

// ---------- L3：Toolhelp 快照必须显式关 ----------
const SNAP_BIND_RE = /let\s+(?:mut\s+)?([A-Za-z_]\w*)\s*=\s*CreateToolhelp32Snapshot\s*\(/g;

/**
 * @returns {{fn:string,varName:string,line:number}[]} 取了快照但同函数内没有 CloseHandle(var) 的点
 *
 * 为什么跟别名：`CreateToolhelp32Snapshot` 返回 `Result`，句柄常先经
 * `let snap = match snap_res { Ok(s) => s, .. }` 解出，关闭点打在**外层那个变量**上，
 * 不是 `Ok(s)` 里的 `s` —— 曾按后者捕获，把合规形状误报成漏关。
 */
function snapshotUnclosed(code) {
  const out = [];
  for (const f of rustFns(code)) {
    for (const m of f.body.matchAll(SNAP_BIND_RE)) {
      const v = m[1];
      const aliases = new Set([v]);
      const viaMatch = new RegExp(`let\\s+([A-Za-z_]\\w*)\\s*=\\s*match\\s+${v}\\s*\\{`).exec(f.body);
      if (viaMatch) aliases.add(viaMatch[1]);
      const viaOk = new RegExp(`let\\s+([A-Za-z_]\\w*)\\s*=\\s*${v}\\s*\\.ok\\(\\)`).exec(f.body);
      if (viaOk) aliases.add(viaOk[1]);
      const closed = [...aliases].some((a) =>
        new RegExp(`CloseHandle\\s*\\(\\s*${a}\\s*\\)`).test(f.body),
      );
      if (!closed) out.push({ fn: f.name, varName: v, line: f.line });
    }
  }
  return out;
}

const g = gate(import.meta.url);

// ── 合成样本正向对照：每次运行都跑（判红能力必须被看见）──────────────────────
const CONTROLS = [
  {
    label: 'L1 对照a：用 FindClose 收尾 ⇒ 放行',
    probe: searchHandleUnclosed,
    code: 'unsafe fn a() { let Ok(h) = FindFirstStreamW(p, F, b, None) else { return }; let _ = FindClose(h); }',
    expect: false,
  },
  {
    label: 'L1 对照b：用 CloseHandle 关搜索句柄 ⇒ 判红（R5c-M03 原形状）',
    probe: searchHandleUnclosed,
    code: 'unsafe fn b() { let Ok(h) = FindFirstStreamW(p, F, b, None) else { return }; let _ = CloseHandle(h); }',
    expect: true,
  },
  {
    label: 'L1 对照c：注释里写了 FindClose 但没有真调用 ⇒ 仍判红',
    probe: searchHandleUnclosed,
    code: '// 记得调 FindClose( 收尾\nunsafe fn c() { let Ok(h) = FindFirstStreamW(p, F, b, None) else { return }; let _ = CloseHandle(h); }',
    expect: true,
  },
  {
    label: 'L2 对照a：绑定后立刻判空 ⇒ 放行',
    probe: handleUnchecked,
    code: 'unsafe fn a() { let ev = CreateEventW(n, 0, 0, n);\n if ev.is_null() { return; }\n}',
    expect: false,
  },
  {
    label: 'L2 对照b：绑定后直接用、无判定 ⇒ 判红（A5-M01 原形状）',
    probe: handleUnchecked,
    code: 'unsafe fn b() { let ev = CreateEventW(n, 0, 0, n);\n o.hEvent = ev;\n}',
    expect: true,
  },
  {
    label: 'L2 对照c：`.ok()?` 传播也算判定 ⇒ 放行',
    probe: handleUnchecked,
    code: 'fn c() { let snap = CreateToolhelp32Snapshot(T, 0).ok()?; let _ = CloseHandle(snap); }',
    expect: false,
  },
  {
    label: 'L2 对照d：多行实参 + 判空在语句之后 ⇒ 放行（窗口按语句取）',
    probe: handleUnchecked,
    code: 'unsafe fn d() { let h = CreateFileW(\n p,\n 0,\n);\n if h.is_null() { return; }\n}',
    expect: false,
  },
  {
    label: 'L3 对照a：成对关闭 ⇒ 放行',
    probe: snapshotUnclosed,
    code: 'fn a() { let snap = CreateToolhelp32Snapshot(T, 0).ok()?; let _ = CloseHandle(snap); }',
    expect: false,
  },
  {
    label: 'L3 对照b：`let _ = snap;` 只消警告 ⇒ 判红（A5-M02 原形状）',
    probe: snapshotUnclosed,
    code: 'fn b() { let snap = CreateToolhelp32Snapshot(T, 0).ok()?; let _ = snap; }',
    expect: true,
  },
  {
    label: 'L3 对照c：`match` 解包后再关 ⇒ 放行（跟别名）',
    probe: snapshotUnclosed,
    code:
      'fn c() { let r = CreateToolhelp32Snapshot(T, 0); let s = match r { Ok(v) => v, Err(_) => return }; let _ = CloseHandle(s); }',
    expect: false,
  },
];
{
  let ctrlBad = 0;
  for (const c of CONTROLS) {
    const hit = c.probe(c.code).length > 0;
    if (hit !== c.expect) {
      ctrlBad++;
      console.error(`✗ 正向对照失败：${c.label}（实得判红=${hit}，应为=${c.expect}）`);
    }
  }
  if (ctrlBad === 0) {
    g.ok(`正向对照 ${CONTROLS.length} 组通过（含「注释里写判定不算通过」与「解包别名认账」两组）`);
  }
}

// ── 真仓扫描 ──
const files = [];
for (const root of ROOTS) for (const f of walkRs(root)) files.push(f);

let findSites = 0;
let bindSites = 0;
let snapSites = 0;
let viol = 0;
for (const f of files) {
  const rel = relative(ROOT, f).replace(/\\/g, '/');
  // 整文件测试模块：`#[cfg(test)] mod contract_tests;` 的 cfg 属性挂在 mod.rs 的声明上、
  // 不在文件内 ⇒ 行级切割看不见，按命名约定识别（与 check-native-hygiene N10 同口径）。
  if (/_tests\.rs$/.test(rel)) continue;
  const code = readFileSync(f, 'utf8');
  findSites += rustFns(code).filter((fn) => SEARCH_FIRST_RE.test(fn.body)).length;
  bindSites += handleBindRe().test(code) ? [...code.matchAll(handleBindRe())].length : 0;
  snapSites += [...code.matchAll(SNAP_BIND_RE)].length;
  for (const v of searchHandleUnclosed(code)) {
    viol++;
    g.fail(
      `L1：${rel}::${v.name} 取到 FindFirst* 搜索句柄但函数内没有 FindClose —— ` +
        '搜索句柄只能由 FindClose 关闭，CloseHandle 不算（R5c-M03 / A5-M03）',
    );
  }
  for (const v of handleUnchecked(code)) {
    viol++;
    g.fail(
      `L2：${rel} L${v.line} 句柄 API 返回值绑定后未见判定 —— 失败时返回 NULL/INVALID，` +
        `不判会把失败折成合法句柄并静默空转（A5-M01）：${v.snippet}`,
    );
  }
  for (const v of snapshotUnclosed(code)) {
    viol++;
    g.fail(
      `L3：${rel}::${v.fn} 取了 CreateToolhelp32Snapshot 快照但函数内没有 CloseHandle(${v.varName})` +
        ' —— `let _ = snap;` 只消警告、不产生 syscall（A5-M02）',
    );
  }
}

// 语料地板：任一侧归零 ⇒ 正则或扫描面失明（那种「无违例」毫无意义，不许记绿）
if (findSites === 0) g.fail(`L1：语料失明 —— 全仓找不到任何 FindFirst* 获取点 ⇒ 识别正则已失效`);
if (bindSites === 0) g.fail(`L2：语料失明 —— 全仓找不到任何句柄绑定点 ⇒ 识别正则已失效`);
if (snapSites === 0) g.fail(`L3：语料失明 —— 全仓找不到任何 Toolhelp 快照点 ⇒ 识别正则已失效`);

if (viol === 0) {
  g.ok(
    `句柄生命周期三闸在位：搜索句柄获取点 ${findSites} 处、句柄绑定点 ${bindSites} 处、` +
      `Toolhelp 快照点 ${snapSites} 处，全部合规`,
  );
}

g.finish('check-handle-lifecycle: 全部通过');

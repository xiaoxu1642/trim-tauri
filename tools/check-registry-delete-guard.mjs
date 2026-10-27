'use strict';
// tools/check-registry-delete-guard.mjs —— 注册表**递归删树**出口的容器准入与名字形态闸
// （B1-1 / R5c-M02 + B1-2 / R5c-M01 + A6-M05，2026-10-27 全仓重审 P0）
//
// 出处：2026-10-27 全仓重审 R5c-M02（🔴）与 R5c-M01 / A6-M05。
// 根因形状（三条，各有独立坐标）：
//   ① `engine/native/registry.rs` 的 `reg_key_remove_checked` 对 `subkey == ""`
//      **零判据** ⇒ `RegDeleteTreeW(hive, "")` 的口径是「以 hKey 本身为根」，
//      目标从「某个产品叶键」变成「整个 HKCU 子树」（红线①②）；
//   ② `engine/pssteps.rs` 的注册表出口**全链没有一处禁删面**
//      （取数：`rg -n 'reg_target_block_reason|is_reg_target_protected' src-tauri/src/engine/pssteps.rs`），
//      而 `parse_ps_reg_path` 放行多个 hive
//      （取数：`rg -n 'Hive::(Cr|U|Cc)' src-tauri/src/engine/pssteps.rs`），
//      禁删面只认 HKLM/HKCU ⇒ HKCR/HKU/HKCC 这三条链
//      **既不在判定面内、又能走到原生删树出口**（无闸可达形态）；
//   ③ `engine/native/common.rs` 的 `to_wide` 不过滤 NUL，而 `PCWSTR` 以**第一个 NUL**
//      为串尾 ⇒ `to_wide("a\0b")` 交给 Win32 的是 `"a"`：「判定的字节」≠「执行的字节」
//      （红线⑨）。值名方向此前**全仓零闸**（键路径方向由 `protect::normalize_reg_target`
//      兜住，值名方向没人管）。
//
// 判据为什么不是「文件里出现过 reg_target_block_reason 就算过」（v2 §4 A-7「文本命中不算」）：
//   ① 判定作用在 `blankNonCode` 之后的文本上 ⇒ 注释/字符串里写 `reg_target_block_reason(`
//      不顶账；
//   ② 作用在**函数体**上 ⇒ 同文件另一个函数里判过不算这个调用点判过；
//   ③ 删树出口允许**同文件 1 跳**（`cleanup_execute_with_backup_root` 内的解析段判过、
//      删树段落在同一函数；`reg_import_apply_sections` 的闸在**上游函数**里，
//      由 `reg_backup_restore_guards` 判过 ⇒ 跨文件 1 跳，本门禁按「闸在删树调用点
//      之前**且**在同一条可达链上」判定，见下）。
//
// 豁免表：本门禁随 B1 落地、随 B2 兑现。`TRANSITION` 里每条都要 `{file, fn, batch, reason}`，
// 且**双向咬合**：代码补上判定后若豁免表还留着 ⇒ 判红（防「修完了台账还挂着」的第二类假绿）。
//
// 用法：node tools/check-registry-delete-guard.mjs [--verbose]

import { readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { gate } from './lib/gate.mjs';
import { blankNonCode, splitFunctions, skipBraces, lineAt } from './lib/src-scan.mjs';
import { walkRs } from './lib/fs-walk.mjs';

const ROOT = process.cwd();
const SRC = join(ROOT, 'src-tauri', 'src');

// 删树原语名（`reg_key_remove` / `reg_key_remove_checked`）。
const TREE_REMOVE = 'reg_key_remove';
// 禁删面判据（`protect::reg_target_block_reason` 是唯一真源）：
// - `reg_target_block_reason(` —— 真源本体；
// - `is_reg_target_protected(` —— 它的 bool 包装；
// - `cleanup_reg_wipe_block_reason(` —— **删树形态下**与真源等价的同源包装。
//
// 为什么第三个也算：清理域的删树形态传 `wipe_all_values = false`
// （`engine/native/cleanup.rs` 的 `wipe_form` 三态：`None`⇒删树⇒false、
// `Some("*")`⇒通配清值⇒true、`Some(具名)`⇒具名单值⇒不走本函数），
// 而 `cleanup_reg_wipe_block_reason` 的放行清单 `CLEANUP_REG_WIPE_ALLOW`
// **只在 `wipe_all_values == true` 时生效** ⇒ 删树形态拿到的判定与真源逐字相同。
// 它的放行清单只影响清值形态，而清值形态走的是 `reg_restore_delete`（删值）
// ⇒ 本门禁盯的「删树出口」（`reg_key_remove`）不受那份清单影响。
//
// 分两组计数是为了报告能看出各处用的是哪条（真源直调 vs 同源包装），
// 不影响判定结果（两组都算「过闸」）。
const DENY_FACE = ['reg_target_block_reason(', 'is_reg_target_protected('];
const DENY_FACE_WRAP = ['cleanup_reg_wipe_block_reason('];
// 名字形态闸（R5c-M01 / A6-M05）。
const NAME_GUARD = 'to_wide_checked(';
// 原语自身的形态闸（R5c-M02：空 / 仅空白 / 仅反斜杠）。
const SHAPE_GUARD = 'reg_delete_subkey_shape_is_malformed(';
const MIN_TREE_EXITS = 4; // 对象地板：低于此数说明识别正则失明，不说明仓库变安全

// B1（2026-10-27）落地后：pssteps 的删树出口已过禁删面、registry 原语已带形态闸。
// 本表只留**已裁定不补**的条目（有书面理由，不是「还没做」）。
// 新删树出口漏判即红，不许再往本表塞新条目 —— 要塞必须先答「为什么不接判据」，答不出就接判据。
const TRANSITION = [
  {
    file: 'src-tauri/src/engine/native/registry.rs',
    fn: 'reg_key_remove',
    batch: 'B1/已裁定不补',
    reason:
      '这是**原语自身**（`reg_key_remove` 只是 `reg_key_remove_checked` 的 bool 包装，无 Win32 调用）。' +
      '它自身带两道闸：① `reg_delete_subkey_shape_is_malformed`（空/仅空白/仅反斜杠 ⇒ Err(87)，R5c-M02）；' +
      '② `to_wide_checked`（含 NUL/控制字符 ⇒ Err(87)，R5c-M01）。' +
      '禁删面不放在原语里是**刻意的**：原语只拿到 `HKEY` 句柄与子键串，判定「目标是不是系统命名空间」' +
      '需要 `HKLM\\…` 形状的字符串，而 `protect::reg_target_block_reason` 吃的就是那个形状 —— ' +
      '把它下沉到原语会迫使原语反向依赖 protect（native 层依赖 engine 层的上层模块，破坏分层）。' +
      '真正的处置是**每个调用点自己过禁删面**，本门禁正是钉这一条。',
  },
];

const walk = (dir) => walkRs(dir);

/**
 * 测试面的字符区间（两种形态都要认，漏一种 = 门禁对测试夹具误报）：
 * ① `#[cfg(test)] mod xxx { … }` —— 整模块是测试；
 * ② `#[cfg(test)] fn xxx(…) { … }` —— **文件级**的测试函数（`drop_hkcu_scratch`
 *    就是这一形态：cfg 属性挂在 fn 上而不是 mod 上）；
 * ③ 整文件测试模块（`#[cfg(test)] mod contract_tests;` 的 cfg 属性挂在 mod.rs 的
 *    声明上、不在文件内 ⇒ 行级切割看不见）—— 按命名约定 `*_tests.rs` 识别
 *    （与 `check-native-hygiene` N10 同口径）。
 */
function testRanges(code, rel) {
  const blanked = blankNonCode(code, 'rs');
  const out = [];
  // ① / ②：cfg 属性后面跟 mod 或 fn
  const pat = /#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:mod|fn)\s+\w+\s*(?:\{|[\(<])/g;
  let m;
  while ((m = pat.exec(blanked))) {
    const brace = blanked.indexOf('{', m.index);
    if (brace < 0) continue;
    // fn 的体在 `)` 之后的 `{}`；mod 的体直接在 `{}`
    const open = blanked.slice(m.index, brace).includes('fn') ? brace : brace;
    out.push([m.index, skipBraces(blanked, open)]);
  }
  // ③ 整文件测试模块（按命名约定）
  if (/_tests\.rs$/.test(rel)) out.push([0, code.length]);
  return out;
}

/**
 * 逐函数建立索引。判定一律作用在 `blankNonCode` 之后的文本上。
 * `guards` = 体内出现禁删面判据；`treeRemoves` = 体内出现删树原语调用。
 */
function build(code, rel = '') {
  const blanked = blankNonCode(code, 'rs');
  const tests = testRanges(code, rel);
  const fns = splitFunctions(code, 'rs')
    .filter((f) => !tests.some(([a, b]) => f.start >= a && f.start < b))
    .map((f) => {
      const body = blanked.slice(f.bodyStart, f.end - 1);
      return {
        ...f,
        body,
        line: lineAt(code, f.start),
        denyFace: DENY_FACE.some((d) => body.includes(d)),
        denyFaceWrap: DENY_FACE_WRAP.some((d) => body.includes(d)),
        treeRemoves: body.includes(TREE_REMOVE),
        nameGuard: body.includes(NAME_GUARD),
        shapeGuard: body.includes(SHAPE_GUARD),
        calls: null,
      };
    });
  const names = new Set(fns.map((f) => f.name));
  for (const f of fns) {
    f.calls = [...names].filter((n) => n !== f.name && new RegExp(`\\b${n}\\s*\\(`).test(f.body));
  }
  return fns;
}

/**
 * 删树调用点的「已过禁删面」判定。
 *
 * 为什么允许**跨文件 1 跳**：`reg_import_apply_sections`（engine/reg_backup.rs）的删树
 * 调用点，其禁删面在 `reg_backup_restore_guards_with`（同文件、上游函数）里判 ——
 * 那道闸在 `reg_backup_restore_guards` 入口处跑完才把 sections 交给执行臂。
 * 同文件 1 跳（callee 方向）能覆盖 `cleanup_execute_with_backup_root`。
 *
 * 判定口径（与 `check-delete-root-guard` 同族，差别只在方向）：
 * - 本函数体内有禁删面判据 ⇒ 过；
 * - 本函数**调用**的某个函数（同文件）体内有禁删面判据 ⇒ 过（1 跳 callee）；
 * - 都没有 ⇒ 不过（判红）。
 */
function denyFaceReached(fns, byName, f) {
  if (f.denyFace || f.denyFaceWrap) return true;
  return f.calls.some((c) => byName.get(c)?.denyFace || byName.get(c)?.denyFaceWrap);
}

const g = gate(import.meta.url);
const exemptKey = (rel, fn) => `${rel}#${fn}`;
const exempt = new Map(TRANSITION.map((t) => [exemptKey(t.file, t.fn), t]));

let treeExitCount = 0;
let guardedCount = 0;
const found = new Set();

if (!g.skipUnlessPresent(join(SRC, 'engine', 'protect.rs'), 'src-tauri/src（本门禁的判定对象）')) {
  g.finish();
}

for (const abs of walk(SRC)) {
  const rel = relative(ROOT, abs).split('\\').join('/');
  const code = readFileSync(abs, 'utf8');
  if (!code.includes(TREE_REMOVE)) continue;
  const fns = build(code, rel);
  const byName = new Map(fns.map((f) => [f.name, f]));
  for (const f of fns) {
    if (!f.treeRemoves) continue;
    treeExitCount++;
    const key = exemptKey(rel, f.name);
    const reached = denyFaceReached(fns, byName, f);
    if (reached) {
      guardedCount++;
      if (exempt.has(key)) {
        g.fail(`${rel}:${f.line} ${f.name}() 已调用禁删面判据，但 TRANSITION 仍挂着它（豁免未回收 = 第二类假绿）`);
      }
      continue;
    }
    found.add(key);
    if (!exempt.has(key)) {
      g.fail(
        `${rel}:${f.line} ${f.name}() 调用了注册表删树原语（${TREE_REMOVE}），但本函数与同文件 1 跳内都没有禁删面判据（${DENY_FACE.join(' / ')}），也不在过渡豁免里`,
      );
    }
  }
}

// 已登记但盘上找不到的豁免（改名/搬文件/删函数都会走到这里）
for (const [k, t] of exempt) {
  if (!found.has(k)) g.fail(`TRANSITION 条目已失效（盘上找不到同名函数）：${t.file}:${t.fn}（${t.batch}）`);
}
for (const t of TRANSITION) {
  if (!t.reason || t.reason.length < 8) g.fail(`TRANSITION 条目缺理由：${t.file}#${t.fn}`);
  if (!t.batch) g.fail(`TRANSITION 条目缺批次：${t.file}#${t.fn}`);
}

if (treeExitCount < MIN_TREE_EXITS) {
  g.fail(
    `断言对象地板不成立：只认出 ${treeExitCount} 个删树出口（地板 ${MIN_TREE_EXITS}）⇒ 识别正则或目录根失效，不是仓库变安全`,
  );
}
g.ok(
  `注册表删树出口对账：识别 ${treeExitCount} 个删树调用点，其中已过禁删面 ${guardedCount} 个、未过 ${treeExitCount - guardedCount} 个（未过的全部在过渡豁免里，逐条见 TRANSITION）`,
);

// ── 原语自身的两道闸（R5c-M02 形态闸 + R5c-M01 名字形态闸）─────────────────────
//
// 为什么单独钉：上面那节管的是**调用点**有没有过禁删面；这一节管**原语自己**有没有
// 形态闸。两者是不同的失效方向：调用点全对但原语没有形态闸 ⇒ 空子键 / 含 NUL 的
// 目标照样直达 `RegDeleteTreeW`。
const REGISTRY_RS = join(SRC, 'engine', 'native', 'registry.rs');
if (g.skipUnlessPresent(REGISTRY_RS, 'src-tauri/src/engine/native/registry.rs')) {
  const regText = blankNonCode(readFileSync(REGISTRY_RS, 'utf8'), 'rs');
  if (!regText.includes(SHAPE_GUARD)) {
    g.fail(
      `注册表删树原语缺少空子键形态闸（${SHAPE_GUARD.replace('(', '')}）—— 空/仅空白/仅反斜杠的 subkey 会直达 RegDeleteTreeW（该 API 的空路径口径 = 以 hKey 本身为根，目标变成整棵子树）`,
    );
  } else {
    g.ok(`注册表删树原语带空子键形态闸（${SHAPE_GUARD.replace('(', '')}）`);
  }
  if (!regText.includes(NAME_GUARD)) {
    g.fail(
      `注册表原生层缺少名字形态闸（${NAME_GUARD.replace('(', '')}）—— 值名/键路径含 NUL 时交给 Win32 的是 NUL 之前的前缀（判定的字节 ≠ 执行的字节）`,
    );
  } else {
    g.ok(`注册表原生层带名字形态闸（${NAME_GUARD.replace('(', '')}）`);
  }
}

// ── 合成样本正向对照：每次运行都跑（判红能力必须被看见）────────────────────────
//
// 判据本体：`build()` + `denyFaceReached()`，与真仓扫描共用同一实现 ——
// 对照样本与真仓样本走同一条路，不存在「对照用自己的实现、真仓用另一套」。
const CONTROLS = [
  {
    label: 'C1 删树调用 + 同函数内无禁删面 ⇒ 必须判红',
    code: 'fn a(h: u32, s: &str) { let _ = reg_key_remove_checked(h, s, true); }',
    expectViolation: true,
  },
  {
    label: 'C2 同形状但本函数内已有禁删面判据 ⇒ 不判红',
    code:
      'fn a(h: u32, s: &str) { if crate::engine::protect::reg_target_block_reason(s).is_some() { return; } let _ = reg_key_remove_checked(h, s, true); }',
    expectViolation: false,
  },
  {
    label: 'C3 只在注释里写禁删面 ⇒ 必须仍判红（文本命中不算通过）',
    code:
      '// 这里本来该调 reg_target_block_reason( 但没调\nfn a(h: u32, s: &str) { let _ = reg_key_remove_checked(h, s, true); }',
    expectViolation: true,
  },
  {
    label: 'C4 禁删面在同文件 1 跳被调函数里 ⇒ 不判红（判据认 1 跳 callee）',
    code:
      'fn guard(s: &str) -> bool { crate::engine::protect::reg_target_block_reason(s).is_some() }\nfn a(h: u32, s: &str) { if guard(s) { return; } let _ = reg_key_remove_checked(h, s, true); }',
    expectViolation: false,
  },
  {
    label: 'C5 只删树、无任何禁删面 ⇒ 必须判红',
    code: 'fn a(h: u32, s: &str) { let _ = reg_key_remove(h, s, true); }',
    expectViolation: true,
  },
  {
    label: 'C6 不含删树原语的函数 ⇒ 不判红（防把无关函数算成删树出口）',
    code: 'fn a(s: &str) { let _ = s.len(); }',
    expectViolation: false,
  },
];
{
  let ctrlBad = 0;
  for (const c of CONTROLS) {
    const fns = build(c.code);
    const byName = new Map(fns.map((f) => [f.name, f]));
    const viol = fns.some((f) => f.treeRemoves && !denyFaceReached(fns, byName, f));
    if (viol !== c.expectViolation) {
      ctrlBad++;
      // T1a-M12：对照失败走 g.fail（failed++ ⇒ exit 1），不冒充通过。
      g.fail(`正向对照失败：${c.label}（实得 viol=${viol}）`);
    }
  }
  if (ctrlBad === 0) {
    g.ok(`正向对照 ${CONTROLS.length} 组通过（含「注释里写判定不算通过」与「1 跳 callee 认账」两组）`);
  }
}

// ── pssteps 注册表出口专项（R5c-M02 ②：pssteps 全链没有一处禁删面）─────────────────
//
// 为什么单独钉：pssteps 是本轮实锤的**无闸可达形态**所在（R5c-M02 的现算证据：
// `rg "reg_target_block_reason|is_reg_target_protected|canonical_reg_key"
// src-tauri/src/engine/pssteps.rs`）。它的问题不是「某个函数忘了判」，而是
// **整条链一道都没有** —— 所以门禁必须对这条链单独断言「有」，否则将来有人把
// pssteps 里的那道判定删掉，上面的逐函数扫描要等到**下一个**删树出口才报出来。
const PSSTEPS_RS = join(SRC, 'engine', 'pssteps.rs');
if (g.skipUnlessPresent(PSSTEPS_RS, 'src-tauri/src/engine/pssteps.rs')) {
  const psText = blankNonCode(readFileSync(PSSTEPS_RS, 'utf8'), 'rs');
  const hasDeny = DENY_FACE.some((d) => psText.includes(d));
  if (!hasDeny) {
    g.fail(
      `pssteps 注册表出口没有任何禁删面判据（${DENY_FACE.join(' / ')}）—— 该链曾整条无闸（R5c-M02 实锤），必须有一道`,
    );
  } else {
    g.ok('pssteps 注册表出口带禁删面判据');
  }
  // 合成对照：把判据摘掉 ⇒ 必须判红（否则这条专项断言是恒真的装饰）
  const stripped = psText.replace(/reg_target_block_reason\s*\(/g, 'removed_fn(');
  if (stripped.includes('reg_target_block_reason(') || stripped.includes('is_reg_target_protected(')) {
    g.fail('pssteps 专项判据失效：摘掉禁删面调用后仍被判为「有」');
  } else {
    g.ok('pssteps 专项判据可判红（摘掉禁删面调用即被抓）');
  }
}

g.finish(
  'check-registry-delete-guard: 全部通过（TRANSITION 剩 ' +
    exempt.size +
    ' 条，均为已裁定的「不补」并附书面理由，非待办）',
);

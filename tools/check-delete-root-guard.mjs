'use strict';
// tools/check-delete-root-guard.mjs —— 递归删除/裁剪的**根**必须过根级 reparse 判定（B0 门禁）
//
// 出处：2026-10-24 全仓重审 R7-K01（🔴）与族 F-1（reparse 校验面不全，7 个实例）。
// 根因形状：清扫根 `dirs.push(std::env::temp_dir().join("Trim"))` 之后逐**子项**判 reparse，
// 根自身没人判 ⇒ 根被换成 junction 时 `read_dir` 直接穿透，旧文件被 `remove_file` 永久删，
// 不经回收站、不经 `is_path_protected`。写侧原语 `engine::paths::temp_script_dir()` 恰恰是对
// **根**拒 reparse 的（`src-tauri/src/engine/paths.rs:431-445`）⇒ 同族两套口径，本门禁把它钉成一条。
//
// 判据为什么不是「文件里出现过 inspect_root 就算过」（v2 §4 A-7「文本命中不算」）：
//   ① 判定作用在 `blankNonCode` 之后的文本上 ⇒ 注释/字符串里写 `inspect_root(` 不顶账；
//   ② 作用在**函数体**上 ⇒ 同文件另一个函数里判过不算这个函数判过；
//   ③ 破坏性枚举允许跨一层调用（`prune_temp_scripts_in` → `collect_temp_files` 才是真 read_dir），
//      所以做同文件 2 跳可达。
//
// G0.2（2026-11-01 重审）：旧实现的覆盖判据是「本函数 / 删除链任一中间层 / **同文件任一 caller**
// 判过 ⇒ 整条根算绿」——最后一条是「任一即洗白」：`realtime_report_save` 自己没判根，只因同文件
// 另一个入口 `prune_reports` 判过就被算绿（R1d-K01）。现在改为**逐调用点**：
//   · 自判点 `file#fn`：根在 f 体内取用/删除，且 f 的调用方不全带实参 —— 体内必须判；
//   · 调用点 `file#fn@caller`：caller 带实参把根交给 f、f 在 2 跳内到达删除原语 ——
//     每个 caller 各自成立：caller 体内判过，或 f 向下到删除原语之前每一条删除路径都判过
//     （C7 中间层放行；some/any 式「有一条判过」会漏掉同层另一条未判删除路径）；
//     共享执行体不再被「某一个 caller 判过」代表，**每个带参调用方各算一条**；
//   · 调用方直接删的采集器（R7-K01 形状）同样按 caller 拆点，不再「任一 caller 判过即可」。
// 「判过」仍是 T1e-L05 口径：同一函数体内 `inspect_root(` 与 `is_trusted()` 都出现。
// 粒度声明：「调用点所在分支」按**函数体**判定（text-level，不做控制流/语句序分析）——
// 与既有 T1e-L05 同粒度；守卫写在 call 之后同函数体也算过，这是本门禁已知的精度上限。
//
// 过渡基线：本门禁随 B0 落地、随 B2 兑现。B2（2026-10-25）已把 15 条里的 14 条接进
// `protect::inspect_root`。G0.2（2026-11-01）后盘上只剩一条：已裁定不补的枚举工具
// （附书面理由）；`realtime_report_save`（R1d-K01）的守卫已于 P0 补上，对应条目已回收。
// `TRANSITION` 里每条都要 `{file, fn, batch, reason}`，
// 且**双向咬合**：代码补上判定后若豁免表还留着 ⇒ 判红（防「修完了台账还挂着」的第二类假绿）。
//
// 用法：node tools/check-delete-root-guard.mjs [--verbose]

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gate } from './lib/gate.mjs';
import { blankNonCode, splitFunctions, skipBraces, lineAt } from './lib/src-scan.mjs';

// 仓根由本文件位置推出，不用 `process.cwd()`：在 src-tauri/ 下单跑时判定对象会变成
// 「不在本机」而打 SKIP + exit 0，门禁静默变成未校验（T1b-L01）。
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = join(ROOT, 'src-tauri', 'src');
const NATIVE = join(ROOT, 'native-scanner', 'src');
const GUARD = 'inspect_root(';
const READ = 'read_dir(';
// T1e-L04：增 `remove_dir(` / `recycle_one(` 两类删除原语；`delete_file_with_panic(` 在仓内零命中（已退役），
// 删掉以免掩耳盗铃。任何「read_dir + 2 跳内出现下列原语」的站点未判根即红。
const DESTRUCTIVE = ['remove_file(', 'remove_dir_all(', 'remove_dir(', 'send_to_trash_os(', 'recycle_one('];
const MIN_DESTRUCTIVE_ROOTS = 5; // 对象地板：低于此数说明判定正则失明，不说明仓库变安全

// B2（2026-10-25）清零：原 15 条已逐条接入 `protect::inspect_root`。G0.2（2026-11-01）把判据
// 收到逐调用点后，盘上只剩两条：① 已裁定不补的枚举工具（key 由函数名改为它唯一删除调用点）；
// ② `realtime_report_save` 未判根（R1d-K01），**带明确回收条件**——P0-4 补守卫后必须删条目，
// 双向咬合会当场判红。除此之外新根入口/新调用点漏判即红，不许再往本表塞新条目 ——
// 要塞必须先答「为什么不接判据」，答不出就接判据。
const TRANSITION = [
  { file: 'src-tauri/src/engine/native/cleanup.rs', fn: 'expand_glob_dirs@cleanup_execute_with_backup_root', batch: 'B2/已裁定不补', reason: '通配展开的**枚举工具**，不是删除根：`expand_glob_dirs` 自己只 read_dir 拼候选，真正的删除发生在 `cleanup_execute_with_backup_root`（`cleanup_execute` 的实现体，本调用点所在函数）的逐 victim 段——对每个 victim 调 `reparse_ancestor_memoized` → `trim_finder::scan::reparse_ancestor`，命中即 `reparse_blocked += 1` 并在回执汇总处计数点名。根是 junction 时该祖先链判定当场就拒 ⇒ 在展开器或入口补根判定只会把「可见的逐项拒因 + 计数」换成「静默 0 命中」，正撞方案 P1-6「失败不得伪装成空结果」。活性由 native-scanner 的 `p0_2c_祖先复检深度到文件系统根不设第二上限` 与 `s2_*` 删除链用例（断言 mode=reparse-ancestor 且真实内容完好）钉住，不是靠这条理由自证。坐标按函数/段落锚定，不写行号（T1e-L04：旧理由里的行号已漂移，且门禁不校验它）' },
];

const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? walk(join(dir, e.name)) : (e.name.endsWith('.rs') ? [join(dir, e.name)] : []));

/** `#[cfg(test)]` 模块的字符区间：测试体内构造真目录再删是本仓标准夹具，不是生产删除根。 */
function testModRanges(code) {
  const blanked = blankNonCode(code, 'rs');
  const out = [];
  const pat = /#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*mod\s+\w+\s*\{/g;
  let m;
  while ((m = pat.exec(blanked))) out.push([m.index, skipBraces(blanked, blanked.indexOf('{', m.index))]);
  return out;
}

/**
 * 同文件可达性 + 根判定覆盖（T1e-L03/L05 抽成唯一实现，真仓与合成对照共用）。
 *
 * 删除侧允许 2 跳（`read_dir` 所在函数 → 中间层 → 真正 remove_*）：
 * 旧实现只算「本函数 / 1 跳 callee / 1 跳 caller」，`f → g → h(remove_file)` 整条链
 * 不进射程（现盘唯一实例 `realtime_report_list → prune_reports → prune_reports_in`
 * 的中间层自带判定，是安全形状；但判据看不见它就无法在下一处重演时报警）。
 *
 * 覆盖改为**逐调用点**（G0.2）：每个「把根交进删除链」的调用点各出一条记录，
 * 键 = `file#fn`（自判点）或 `file#fn@caller`（带参调用点），任一未判即整条根判红。
 * 旧实现的 `callerGuarded = 同文件任一 caller 判过` 已删除 —— 它就是「sibling caller 洗白」。
 */
function judgeRoots(fns) {
  const byName = new Map(fns.map((f) => [f.name, f]));
  // f 自身或 2 跳带参调用链上是否真有删除原语。零参调用不算「把根传下去」
  // （`app_data_dir()` 这类零参路径取用不是「把根交给删除方」，现盘反例见
  // migrate_legacy_once → app_data_dir → 测试夹具 lib_test_data_root 的 remove_dir_all）。
  const reachesDelete = (f, depth) => {
    if (f.deletes) return true;
    if (depth <= 0) return false;
    for (const c of f.argCalls) {
      const callee = byName.get(c);
      if (callee && reachesDelete(callee, depth - 1)) return true;
    }
    return false;
  };
  // 从 f 往下到删除原语之前，**每一条**会真的删的路径上是否都有人判过根。
  // 用 every 而不是 some：f 同时有「判过的删除路径」和「没判的删除路径」时，
  // 后者照样能把根带进 remove_*，some 会把它洗白（「任一即洗白」的另一个面）。
  // C7 的「守卫可落在中间层」仍然是 every 的特例（只有一条删除路径）。
  const chainGuarded = (f, depth) => {
    if (f.guards) return true;
    if (f.deletes || depth <= 0) return false;
    const next = f.argCalls.map((n) => byName.get(n)).filter((g) => g && reachesDelete(g, depth - 1));
    return next.length > 0 && next.every((g) => chainGuarded(g, depth - 1));
  };
  const out = [];
  for (const f of fns) {
    if (!f.reads) continue;
    const callers = fns.filter((c) => c.calls.includes(f.name));
    const argCallers = callers.filter((c) => c.argCalls.includes(f.name));
    const deletingCallers = callers.filter((c) => c.deletes);
    const delReachable = reachesDelete(f, 2);
    const sites = [];
    // 自判点：根在 f 体内被取用。所有调用方都带实参时根来自调用方（共享执行体），
    // 自判点让位给逐调用方 —— 执行体自身不必重复判，但每个调用方**各自**要判。
    // 只要存在零参调用方，根也可能在 f 内自取，自判点保留。
    const allCallersPassArgs = callers.length > 0 && callers.every((c) => c.argCalls.includes(f.name));
    if (delReachable && !allCallersPassArgs) {
      sites.push({ key: 'self', line: f.line, guarded: chainGuarded(f, 2) });
    }
    if (delReachable) {
      for (const c of argCallers) {
        sites.push({ key: c.name, line: c.line, guarded: c.guards || chainGuarded(f, 2) });
      }
    }
    // 调用方直接删也算（`collect_temp_files` 只枚举、`prune_temp_scripts_in` 才 remove_file
    // —— R7-K01 的真实形状），这一腿不属于「往下传根」，不受 argCalls 限制。
    // 逐调用方：每个「调用 f 且自己删」的 caller 各自要判（c.guards 或采集器 f 判过）。
    for (const c of deletingCallers) {
      sites.push({ key: c.name, line: c.line, guarded: c.guards || f.guards });
    }
    if (sites.length === 0) continue; // 只 read_dir、本文件不删 ⇒ 不是删除根，不判红
    // 同一 caller 可能两条腿都命中：同键取「与」—— 一个调用点只允许一条成立路径，
    // 两条腿的判据都以 c.guards 为主，取「与」不会互相洗白。
    const merged = new Map();
    for (const s of sites) {
      const prev = merged.get(s.key);
      merged.set(s.key, { key: s.key, line: s.line, guarded: prev ? prev.guarded && s.guarded : s.guarded });
    }
    const list = [...merged.values()];
    out.push({ fn: f, sites: list, guarded: list.every((s) => s.guarded) });
  }
  return out;
}

function build(code) {
  const blanked = blankNonCode(code, 'rs');
  const tests = testModRanges(code);
  const fns = splitFunctions(code, 'rs').filter((f) => !tests.some(([a, b]) => f.start >= a && f.start < b)).map((f) => {
    const body = blanked.slice(f.bodyStart, f.end - 1);
    return {
      ...f,
      body,
      line: lineAt(code, f.start),
      reads: body.includes(READ),
      deletes: DESTRUCTIVE.some((d) => body.includes(d)),
      // T1e-L05：只出现 `inspect_root(` 不算判过 —— 返回值必须真被读（`is_trusted()`），
      // 否则「调了一下、没看结果」也能把根入口洗白。
      // T1e-M04：native-scanner 没有 inspect_root，根/目标闸是
      // `is_protected_path` 与 N1c-Y01 的「直接子目录 + Trim-DiskBench 名字」双判据。
      guards: (body.includes(GUARD) && body.includes('is_trusted()'))
        || body.includes('is_protected_path(')
        || (body.includes('direct_child') && body.includes('bench_name_ok')),
      calls: null,
      argCalls: null,
    };
  });
  const names = new Set(fns.map((f) => f.name));
  for (const f of fns) {
    f.calls = [...names].filter((n) => n !== f.name && new RegExp(`\\b${n}\\s*\\(`).test(f.body));
    // 带实参的调用（`name(` 后不是空串/右括号）：跨函数传根至少得把东西传下去。
    f.argCalls = [...names].filter((n) => n !== f.name && new RegExp(`\\b${n}\\s*\\(\\s*[^)\\s]`).test(f.body));
  }
  return fns;
}

const g = gate(import.meta.url);
const exemptKey = (rel, fn) => `${rel}#${fn}`;
const exempt = new Map(TRANSITION.map((t) => [exemptKey(t.file, t.fn), t]));

let hitCount = 0; // 根入口（根读取函数）个数：地板按对象算，防止「站点拆分后地板自适应」
let siteCount = 0;
let guardedCount = 0;
let unregistered = 0; // 未判且未登记的调用点：>0 时 summary 不许写成「未判的全部在豁免里」
const found = new Set();
const VERBOSE = process.argv.includes('--verbose');

// T1e-L09：SKIP 必须短路（`g.finish()` 在 0 失败时不退出，随后 walk 会 ENOENT 崩栈）。
if (!g.skipUnlessPresent(join(SRC, 'engine', 'protect.rs'), 'src-tauri/src（本门禁的判定对象）')) {
  g.finish();
  process.exit(0);
}

for (const abs of [...walk(SRC), ...walk(NATIVE)]) {
  const rel = relative(ROOT, abs).split('\\').join('/');
  const code = readFileSync(abs, 'utf8');
  if (!code.includes(READ)) continue;
  const fns = build(code);
  for (const { fn: f, sites } of judgeRoots(fns)) {
    hitCount++;
    for (const s of sites) {
      siteCount++;
      const key = s.key === 'self' ? exemptKey(rel, f.name) : exemptKey(rel, `${f.name}@${s.key}`);
      found.add(key);
      const siteLabel = s.key === 'self' ? '自判点' : `调用点 ← ${s.key}()`;
      if (VERBOSE) console.log(`${s.guarded ? '✓' : '✗'} ${key}（${rel}:${s.line}）`);
      if (s.guarded) {
        guardedCount++;
        if (exempt.has(key)) {
          g.fail(`${rel}:${s.line} ${f.name}() 的${siteLabel} 已调用 ${GUARD.replace('(', '')}，但 TRANSITION 仍挂着它（豁免未回收 = 第二类假绿）`);
        }
        continue;
      }
      if (!exempt.has(key)) {
        unregistered++;
        g.fail(`${rel}:${s.line} ${f.name}() 的${siteLabel} 是「read_dir + 2 跳内删除」的根入口/移交点，该调用点所在函数与删除链上游都没有 ${GUARD} 判定，也不在过渡豁免里`);
      }
    }
  }
}

// 已登记但盘上找不到的豁免（改名/搬文件/删函数/调用点消失都会走到这里）
for (const [k, t] of exempt) {
  if (!found.has(k)) g.fail(`TRANSITION 条目已失效（盘上找不到同名函数或调用点）：${t.file}:${t.fn}（${t.batch}）`);
}
for (const t of TRANSITION) {
  if (!t.reason || t.reason.length < 8) g.fail(`TRANSITION 条目缺理由：${t.file}#${t.fn}`);
  if (!t.batch) g.fail(`TRANSITION 条目缺批次：${t.file}#${t.fn}`);
  // T1e-L04：理由里不许写 `xxx.rs:行号` —— 插一行就漂，而门禁不校验坐标内容。
  // 改写成函数名 / 段落名（本门禁只判「有没有行号」，不猜语义）。
  if (/\.rs:\d+/.test(t.reason)) {
    g.fail(`TRANSITION 理由里带行号（${t.file}#${t.fn}）—— 会随插行漂移，改用函数/段落锚点`);
  }
}

if (hitCount < MIN_DESTRUCTIVE_ROOTS) {
  g.fail(`断言对象地板不成立：只认出 ${hitCount} 个「枚举+删除」根入口（地板 ${MIN_DESTRUCTIVE_ROOTS}）⇒ 判定正则或目录根失效，不是仓库变安全`);
}
g.ok(`删除根守卫对账（逐调用点）：根入口 ${hitCount} 个、调用点 ${siteCount} 个，已判 ${guardedCount} 个、未判 ${siteCount - guardedCount} 个（其中未登记 ${unregistered} 个；其余在过渡豁免里，逐条见 TRANSITION；--verbose 列全部键）`);

// ── 合成样本正向对照：每次运行都跑（判红能力必须被看见，`check-pending-batch-limit` 先例）──
const CONTROLS = [
  {
    label: 'C1 read_dir + remove_file 且无判定 ⇒ 必须判红',
    code: 'fn a(p: &Path) { let _ = std::fs::read_dir(p); let _ = std::fs::remove_file(p); }',
    expectViolation: true,
  },
  {
    label: 'C2 同形状但 caller 先判根 ⇒ 不判红（判据认 caller）',
    code: 'fn top(p: &Path) { if crate::engine::protect::inspect_root(p, None).is_trusted() { a(p); } }\nfn a(p: &Path) { let _ = std::fs::read_dir(p); let _ = std::fs::remove_file(p); }',
    expectViolation: false,
  },
  {
    // 这一条是本门禁存在的理由：只看文本命中就会在这里放行
    label: 'C3 只在注释里写 inspect_root ⇒ 必须仍判红（文本命中不算通过）',
    code: '// 这里本来该调 inspect_root( 但没调\nfn a(p: &Path) { let _ = std::fs::read_dir(p); let _ = std::fs::remove_dir_all(p); }',
    expectViolation: true,
  },
  {
    label: 'C4 自己 read_dir、删除在 1 跳被调函数 ⇒ 必须判红',
    code: 'fn prune(p: &Path) { collect(p); }\nfn collect(p: &Path) { let _ = std::fs::read_dir(p); kick(p); }\nfn kick(_p: &Path) { let _ = std::fs::remove_file(p_as()); }',
    expectViolation: true,
  },
  {
    label: 'C5 只 read_dir、本文件任何地方都不删 ⇒ 不判红（防把枚举工具函数算成删除根）',
    code: 'fn list_dirs(p: &Path) { let _ = std::fs::read_dir(p); }\nfn unrelated() { let _ = 1; }',
    expectViolation: false,
  },
  {
    label: 'C6 read_dir → 中间层 → remove_file（2 跳）且无判定 ⇒ 必须判红（T1e-L03）',
    code: 'fn top(p: &Path) { let _ = std::fs::read_dir(p); mid(p); }\nfn mid(p: &Path) { leaf(p); }\nfn leaf(p: &Path) { let _ = std::fs::remove_file(p); }',
    expectViolation: true,
  },
  {
    label: 'C7 同 2 跳链，但中间层判过根 ⇒ 不判红（守卫可在链上任一层）',
    code: 'fn top(p: &Path) { let _ = std::fs::read_dir(p); mid(p); }\nfn mid(p: &Path) { if crate::engine::protect::inspect_root(p, None).is_trusted() { leaf(p); } }\nfn leaf(p: &Path) { let _ = std::fs::remove_file(p); }',
    expectViolation: false,
  },
  {
    label: 'C8 调了 inspect_root 但没读 is_trusted() ⇒ 仍判红（T1e-L05）',
    code: 'fn top(p: &Path) { let _ = crate::engine::protect::inspect_root(p, None); let _ = std::fs::read_dir(p); let _ = std::fs::remove_file(p); }',
    expectViolation: true,
  },
  {
    // G0.2 的存在理由：旧判据 `some(caller.guards)` 在这一条上会放行（兄弟入口判过即洗白）
    label: 'C9 共享执行体两个 caller，一个判过、另一个没判 ⇒ 必须判红（逐调用点，任一洗白不算）',
    code: 'fn a(p: &Path) { let _ = std::fs::read_dir(p); let _ = std::fs::remove_file(p); }\nfn good(p: &Path) { if crate::engine::protect::inspect_root(p, None).is_trusted() { a(p); } }\nfn bad(p: &Path) { a(p); }',
    expectViolation: true,
  },
  {
    // 防「过紧」假红：每个调用方都判过时，共享执行体体内不重复判也必须放行。
    label: 'C10 同形状但两个 caller 都判过 ⇒ 不判红（逐调用点全部成立即可，不要求执行体自判）',
    code: 'fn a(p: &Path) { let _ = std::fs::read_dir(p); let _ = std::fs::remove_file(p); }\nfn good1(p: &Path) { if crate::engine::protect::inspect_root(p, None).is_trusted() { a(p); } }\nfn good2(p: &Path) { if crate::engine::protect::inspect_root(p, None).is_trusted() { a(p); } }',
    expectViolation: false,
  },
  {
    // T1e-L04：新增的 `remove_dir(` 原语必须同样被「read_dir + 2 跳内删除」判据捕获。
    label: 'C11 read_dir + remove_dir( 未判根 ⇒ 必须判红（新增原语对照）',
    code: 'fn top(p: &Path) { let _ = std::fs::read_dir(p); let _ = std::fs::remove_dir(p); }',
    expectViolation: true,
  },
  {
    // T1e-L04：recycle_one( 作为回收站封装同样算删除原语，未判根必红。
    label: 'C12 read_dir + recycle_one( 未判根 ⇒ 必须判红（新增原语对照）',
    code: 'fn top(p: &Path) { let _ = std::fs::read_dir(p); let _ = recycle_one(p); }',
    expectViolation: true,
  },
];
let ctrlBad = 0;
for (const c of CONTROLS) {
  const viol = judgeRoots(build(c.code)).some((r) => !r.guarded);
  // G0.2：对照失败必须进 g.fail（旧写法只 console.error ⇒ 真仓干净时 exit 仍是 0，
  // 「判红能力坏掉」被冒充成通过 —— 对照组必须自己也能把门禁判红）。
  if (viol !== c.expectViolation) { ctrlBad++; g.fail(`正向对照失败：${c.label}（实得 viol=${viol}）`); }
}
if (ctrlBad === 0) g.ok(`正向对照 ${CONTROLS.length} 组通过（含「注释里写判定不算通过」「1/2 跳穿透必判红」「2 跳链中间层判过放行」「调了不读判定仍红」）`);

// ── P0-4 写回链的复检面地板（B2 加）──────────────────────────────────────────
// 方案原文要的是「所有 create_dir_all 的还原写入口必须复用同一判据」。实测那条判据在本仓
// **不能这样钉**：`create_dir_all` 在还原链里还用于**应用自己的包目录**（`Pack::begin` 的
// zip 目录、registry 目录），那些位置若也要求祖先复检，便携盘挂在 junction 上的合法用户
// 会被整片拒写 —— 判据从「防穿链」变成「防自己的数据根」。
// 因此这里钉的是可判红的**下限**：还原写回链（restore_pack.rs）的 `ancestor_reparse_block_reason`
// 调用点不得少于 3 处（目录趟 / 文件趟 / 临时件自身观测），掉一处即红。
// 三处各自的**行为**活性由 `engine::restore_pack::tests` 的 4 条单测与真机 #[ignore] 探针
// `还原写回链拒绝junction父目录的新建目标` 钉住，不靠本条计数自证。
const WRITE_CHAIN_FILE = join(ROOT, 'src-tauri', 'src', 'engine', 'restore_pack.rs');
const WRITE_GUARD = 'ancestor_reparse_block_reason(';
const WRITE_FLOOR = 3;
if (existsSync(WRITE_CHAIN_FILE)) {
  const text = blankNonCode(readFileSync(WRITE_CHAIN_FILE, 'utf8'), 'rs');
  const n = [...text.matchAll(new RegExp(WRITE_GUARD.replace('(', '\\('), 'g'))].length;
  if (n < WRITE_FLOOR) {
    g.fail(`还原写回链的祖先复检调用点 ${n} < 下限 ${WRITE_FLOOR} ⇒ 有一处写点被摘掉判据（目录趟/文件趟/临时件观测三处缺一）`);
  } else {
    g.ok(`还原写回链祖先复检查调用点 ${n} 处（≥ 下限 ${WRITE_FLOOR}）`);
  }
  // 合成对照：两处写点的样本必须被同一条判据抓到（把地板降到 3 后本样本必然不达标）
  const thin = 'fn a() { std::fs::create_dir_all(x); }\nfn b() { std::fs::create_dir_all(y); }';
  const thinCount = [...blankNonCode(thin, 'rs').matchAll(new RegExp(WRITE_GUARD.replace('(', '\\('), 'g'))].length;
  if (thinCount >= WRITE_FLOOR) {
    g.fail('W 组判据失效：无复检调用的合成样本竟达到地板（这条断言永远不会红）');
  }
} else {
  g.warn(`未校验：${relative(ROOT, WRITE_CHAIN_FILE).split('\\').join('/')} 不在盘上，W 组本节未验证（不算通过）`);
}

const pendingTransition = TRANSITION.filter((t) => /^P\d/.test(t.batch)).length;
g.finish(`check-delete-root-guard: 全部通过（TRANSITION 剩 ${exempt.size} 条：已裁定不补 ${exempt.size - pendingTransition} 条 + 待修复 ${pendingTransition} 条（守卫补齐后必须回收条目），无其它待办）`);

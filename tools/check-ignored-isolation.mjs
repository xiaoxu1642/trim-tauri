'use strict';
// tools/check-ignored-isolation.mjs —— `#[ignore]` 真机探针必须先定隔离数据根（B0 门禁）
//
// 出处：2026-10-24 全仓重审 X1-K01（🔴）。`engine::paths::DATA_DIR` 是 `OnceLock` ——
// **谁先取根谁定死**。真机探针若不先调 `tests/common/mod.rs::ensure_test_data_root()`，
// 一旦它先跑到，同一测试二进制里所有用例的数据根就退回真实 `%APPDATA%\com.xiaoxu.trim`，
// 同批写型探针（settings / appearance / 注册表备份）随之落进用户目录。
//
// 为什么不是「扫函数前 40 行」（v2 §0.3 E7 指出这正是 v1 取数器的缺陷）：
// 本门禁按 `splitFunctions` 取**完整函数体**，隔离调用写在第 45 行也算数、也算位置。
// 「首句必须定根」是施工要求，不是机检要求；机检只保证「这个探针不会把根定错」。
//
// 用法：node tools/check-ignored-isolation.mjs

import { readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';
import { gate } from './lib/gate.mjs';
import { blankNonCode, splitFunctions, lineAt } from './lib/src-scan.mjs';

const ROOT = process.cwd();
const TESTS = join(ROOT, 'src-tauri', 'tests');
// 幂等放行：这些写法本身就会先定根（`common/mod.rs` 的 runtime 构造路径）。
// ⚠ 不要用 `rt(` 当判据：它是 `alert(` / `insert(` / `sort(` 的子串，会把一切探针都放行
//   （首版就因此把 `startup_scan_real_count_vs_writer_cap_probe` 误判成「已隔离」）。
const ISOLATED = ['ensure_test_data_root(', 'probe_guard(', 'MockRuntime', 'mock_builder'];
// 判据口径：**#[ignore] 即真机探针 ⇒ 一律必须先定根**。
// v1 曾用「函数体是否出现 `trim_tauri_lib::`」当筛选，但 tests 里普遍是 `use trim_tauri_lib::x;`
// 之后调短名 ⇒ 该启发式会把一堆真探针判成「不需要隔离」（首版实测 6 条被漏）。
// 定根本身是一行且幂等，代价远低于「根被并行测试定死到真实 %APPDATA%」。
const LIB_REF = /trim_tauri_lib\s*::|app_data_dir\s*\(/;
const MIN_IGNORED = 15; // 对象地板：低于此数说明属性解析失效，不是仓库变干净

// 过渡基线：X1-K01 扩面结果（v1 只报了 1 条，M3 现算 + 本门禁给出 11 条）。B3 逐条清零。
const TRANSITION = [
  'paths_file_icon_still_serves_local_system_dll_icon',
  'settings_set_pref_accepts_only_boolean_for_restore_point_key',
  'appearance_set_pref_accepts_legal_values_roundtrip',
  'residue_scan_on_real_apps_keeps_uninstall_key_candidate',
  'uninstall_list_rows_carry_resolvable_shortcuts',
  'reg_backup_restore_writes_registry_end_to_end',
  'cleanup_scan_l1_l2_probe',
  'optimizer_restore_frequency_main_window_passes_with_deterministic_reply',
  'startup_scan_real_count_vs_writer_cap_probe',
  'cleanup_query_locked_probe_names_locking_process',
  'u_r1d_diskbench_leaves_no_residue_on_success',
  // 以下 7 条由本门禁在 135301c 上现算补出（v1 与 X1 只看了 module_smoke，漏了另两个测试文件）
  'memory_info_reports_total',
  'memory_processes_non_empty',
  'memory_kill_requires_recent_scan',
  'finder_scan_bigfiles_small_dir',
  'runtimes_collect_shape',
  'netcheck_collect_shape',
  'decrypts_electron44_oscrypt_and_dotnet_dpapi',
].map((fn) => ({ fn, batch: 'B3/P1-4', reason: '探针未先定隔离根，并行时可把 DATA_DIR 定到真实 %APPDATA%（X1-K01）' }));

const g = gate(import.meta.url);
const exempt = new Map(TRANSITION.map((t) => [t.fn, t]));
if (!g.skipUnlessPresent(TESTS, 'src-tauri/tests（本门禁的判定对象）')) g.finish();

const files = readdirSync(TESTS, { withFileTypes: true }).flatMap((e) =>
  e.isFile() && e.name.endsWith('.rs') ? [join(TESTS, e.name)]
    : e.isDirectory() ? readdirSync(join(TESTS, e.name)).filter((x) => x.endsWith('.rs')).map((x) => join(TESTS, e.name, x)) : []);

const ignored = [];
for (const abs of files) {
  const code = readFileSync(abs, 'utf8');
  if (!code.includes('#[ignore')) continue;
  const blanked = blankNonCode(code, 'rs');
  for (const f of splitFunctions(code, 'rs')) {
    const head = blanked.slice(Math.max(0, f.start - 400), f.start);
    if (!/#\[ignore/.test(head)) continue;
    const body = blanked.slice(f.bodyStart, f.end - 1);
    const isoAt = Math.min(...ISOLATED.map((s) => { const i = body.indexOf(s); return i < 0 ? Infinity : i; }));
    const libAt = body.search(LIB_REF);
    ignored.push({
      name: f.name,
      rel: relative(ROOT, abs).split('\\').join('/'),
      line: lineAt(code, f.start),
      isolated: Number.isFinite(isoAt),
      ordered: libAt < 0 || (Number.isFinite(isoAt) && isoAt < libAt),
    });
  }
}

let bad = 0;
const seen = new Set();
for (const t of ignored) {
  seen.add(t.name);
  if (t.isolated && t.ordered) {
    if (exempt.has(t.name)) {
      g.fail(`${t.rel}:${t.line} ${t.name} 已先定隔离根，但 TRANSITION 还挂着它（豁免未回收 = 第二类假绿）`);
    }
    continue;
  }
  bad++;
  const why = !t.isolated ? `没有 ${ISOLATED[1]} / ${ISOLATED[0]} 等定根动作` : '定根动作出现在触库之后（OnceLock 已被前一个调用定死）';
  if (!exempt.has(t.name)) {
    g.fail(`${t.rel}:${t.line} ${t.name} 是 #[ignore] 真机探针，${why}，也不在过渡豁免里`);
  }
}
for (const [fn, t] of exempt) {
  if (!seen.has(fn)) g.fail(`TRANSITION 条目失效（盘上已无同名 #[ignore] 探针，或它已不再触库）：${fn}（${t.batch}）`);
  if (!t.batch || !t.reason || t.reason.length < 8) g.fail(`TRANSITION 条目缺批次或理由：${fn}`);
}

if (ignored.length < MIN_IGNORED) {
  g.fail(`断言对象地板不成立：只认出 ${ignored.length} 条 #[ignore] 探针（地板 ${MIN_IGNORED}）⇒ 属性解析或目录根失效，不是仓库变干净`);
}
g.ok(`ignored 探针隔离对账：#[ignore] ${ignored.length} 条 / 未先定根 ${bad} 条（全部在过渡豁免内，B3 清零）`);

// 合成样本正向对照（每次都跑）
const CONTROLS = [
  {
    label: 'K1 定根动作出现在触库之后 ⇒ 必须判「不合格」（OnceLock 已被前一个调用定死）',
    code: '#[ignore = "t"]\nfn a() {\n' + '  let _ = trim_tauri_lib::x();\n'.repeat(45) + '  ensure_test_data_root();\n}',
    want: 'bad-order',
  },
  {
    label: 'K2 首句即定根 ⇒ 合格',
    code: '#[ignore = "t"]\nfn b() {\n  let _g = ensure_test_data_root();\n  let _ = trim_tauri_lib::y();\n}',
    want: 'ok',
  },
  {
    label: 'K3 全程无定根动作 ⇒ 必须判「不合格」（不再用「是否触库」当豁免口子）',
    code: '#[ignore = "t"]\nfn c() { assert_eq!(1 + 1, 2); }',
    want: 'not-isolated',
  },
  {
    label: 'K4 注释里写 #[ignore] 不算真探针（防文本命中假绿）',
    code: '// #[ignore]\nfn d() { let _ = trim_tauri_lib::z(); }',
    want: 'not-a-probe',
  },
];
let ctrlBad = 0;
for (const c of CONTROLS) {
  const blanked = blankNonCode(c.code, 'rs');
  let got = 'not-a-probe';
  for (const f of splitFunctions(c.code, 'rs')) {
    const head = blanked.slice(Math.max(0, f.start - 400), f.start);
    if (!/#\[ignore/.test(head)) continue;
    const body = blanked.slice(f.bodyStart, f.end - 1);
    const isoAt = Math.min(...ISOLATED.map((s) => { const i = body.indexOf(s); return i < 0 ? Infinity : i; }));
    const libAt = body.search(LIB_REF);
    if (!Number.isFinite(isoAt)) got = 'not-isolated';
    else if (!(libAt < 0 || isoAt < libAt)) got = 'bad-order';
    else got = 'ok';
  }
  if (got !== c.want) { ctrlBad++; console.error(`✗ 正向对照失败：${c.label}（实得 ${got}，应为 ${c.want}）`); }
}
if (ctrlBad === 0) g.ok(`正向对照 ${CONTROLS.length} 组通过（含「定根太晚必判红」「注释里的属性不算属性」两组）`);

g.finish('check-ignored-isolation: 全部通过（过渡豁免 ' + exempt.size + ' 条待 B3 清零）');

// check-guard-tiers.mjs —— IPC 来源校验档位门禁（审查 v2-F5）
//
// 为什么需要它：`capabilities/*.json` **不约束命令**（审查 v2-L1 实测 0/139 条应用命令
// 受其约束），命令级的唯一闸门就是每个命令体内那一次 `guard::guard*` 调用。而在本门禁
// 出现之前，15 条 Node 门禁 + `ipc_smoke` 里**没有一条**断言档位 —— 现场实跑全绿时
// F4（`settings_save` 写密钥却挂最宽档）与 F6（`open-in-regedit` 会写注册表 + 弹 UAC
// 却挂最宽档）两个错档完全隐形。
//
// 三组断言：
//   A. 覆盖率：每个 `#[tauri::command]` 都必须有来源校验调用； exempt 清单里的
//      （`app_first_paint`，见 F15）必须逐条登记理由。
//   B. 主窗档双向棘轮：`MUST_MAIN` 与实际判出的 MAIN 集合必须**完全相等** ——
//      只升不降或只降不升都会红，任何档位变动都必须同步改这张表并被 review 看见。
//   C. MAIN 档的调用形态必须是 `guard(&window, guard::MAIN)`（不允许出现
//      `guard_readonly` 与 MAIN 意图混写）。
//
// 用法：node tools/check-guard-tiers.mjs [--update]
//   --update：把当前实际判出的 MAIN 集合打印成可直接粘回本文件的清单（维护用，不判红）

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

const CMD_DIR = join(REPO_ROOT, 'src-tauri', 'src', 'commands');
const UPDATE = process.argv.includes('--update');

/**
 * 显式允许「不走统一 guard」的命令。
 *
 * 每条都必须写明理由与审查编号 —— 这张表是 A 组断言的唯一豁免口，
 * 空理由等于给自己留后门（审查 v1 M13「假绿」的前车）。
 */
const EXEMPT = {
  // 审查 v2-F15：139 条里唯一手写 `label() != "main"` 的命令，无高危副作用
  // （仅触发提前显窗）。留痕不一致已单独记 F15，此处只豁免「必须有 guard 调用」这一条。
  app_first_paint: 'v2-F15：手写 label 判定，无高危副作用；缺口是**留痕**不是档位',
};

/**
 * 必须是主窗档（guard::MAIN）的命令清单。
 *
 * 维护约定：改任何一条命令的档位，都必须同步改这张表 —— B 组断言是双向的，
 * 只改代码或只改表都会红。新增 MAIN 档命令时把名字加进来并写明理由。
 * 由 v2 审查现场枚举（138 条走 guard，其中 guard(MAIN) 35 条）+ 本轮 F4/F6 升档得出。
 */
const MUST_MAIN = [
  'appearance_bg_delete',
  'appearance_bg_import',
  'appearance_bg_list',
  'appearance_bg_open_dir',
  'cleanup_execute',
  'cleanup_kill_locked_processes',
  'cleanup_retry_failed_delete',
  'cleanup_update_rules',
  'contextmenu_open_in_regedit', // v2-F6：会写 HKCU（Regedit\LastKey）且失败时 runas 弹 UAC
  'contextmenu_remove',
  'contextmenu_restart_explorer',
  'contextmenu_restore',
  'contextmenu_toggle',
  'contextmenu_win11_classic',
  'diskbench_run',
  'elevate_request', // AGENTS §3：提权入口只认主窗口 label
  'fileclean_execute',
  'finder_delete',
  'maintenance_run',
  'memory_clean',
  'netcheck_repair',
  'optimizer_backup_reg',
  'optimizer_create_restore',
  'optimizer_restore_reg',
  'optimizer_run',
  // 'pwsh_prepare' 已于 B11（2026-09-26）整链摘除，不再是一条命令
  'runtimes_install',
  // 'settings_save' 已于 v2-F4 整链摘除（2026-09-26），不再是一条命令
  'startup_add',
  'startup_delete',
  'startup_toggle',
  'updater_cancel_download',
  'updater_check',
  'updater_download',
  'updater_get_mirror',
  'updater_install',
  'updater_set_mirror',
];

// ---- 枚举所有 #[tauri::command] 及其档位 ----
const files = readdirSync(CMD_DIR).filter((f) => f.endsWith('.rs'));
/** @type {Map<string, {file:string, tier:string|null, line:number}>} */
const tiers = new Map();

for (const f of files) {
  const text = readFileSync(join(CMD_DIR, f), 'utf8');
  const lines = text.split('\n');
  const marks = [];
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes('#[tauri::command]')) marks.push(i);
  }
  for (let k = 0; k < marks.length; k++) {
    const start = marks[k];
    const end = k + 1 < marks.length ? marks[k + 1] : lines.length;
    let name = null;
    for (let j = start + 1; j < Math.min(start + 8, end); j++) {
      const m = lines[j].match(/pub\s+(?:async\s+)?fn\s+(\w+)/);
      if (m) { name = m[1]; break; }
    }
    if (!name) continue;

    let tier = null;
    for (let j = start; j < end && tier === null; j++) {
      const line = lines[j];
      if (/guard::guard\(\s*&window,\s*guard::MAIN\s*\)/.test(line)) tier = 'MAIN';
      else if (/guard::guard_readonly\(/.test(line)) tier = 'READONLY';
      else if (/guard::guard\(\s*&window,\s*guard::APP_WINDOWS\s*\)/.test(line)) tier = 'APP_WINDOWS';
      else if (/guard::guard\(/.test(line)) tier = 'GUARD_OTHER';
      // 手写 label 判定：`window.label() != "main"` 之外，也可能先取出 label 再比较
      // （`app_first_paint` 为写日志就是这样）。认 `.label()` 调用，避免改个写法就漏判。
      else if (/window\.label\(\)/.test(line)) tier = 'HANDWRITTEN';
    }
    tiers.set(name, { file: f, tier, line: start + 1 });
  }
}

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== IPC 来源校验档位门禁 ===\n');

if (UPDATE) {
  const actual = [...tiers.entries()].filter(([, v]) => v.tier === 'MAIN').map(([k]) => k).sort();
  console.log('--update：当前实际 MAIN 档命令（共 ' + actual.length + ' 条）\n');
  for (const n of actual) console.log(`  '${n}',`);
  console.log('\n（把上面这份替换进 MUST_MAIN；本模式不判红）\n');
  process.exit(0);
}

// ---- A1. 覆盖率：每条命令都必须做来源校验（手写 label 判定也算，但受 A2 约束） ----
const noGuard = [...tiers.entries()].filter(([, v]) => v.tier === null);
check(
  noGuard.length === 0,
  `A1. 全部 ${tiers.size} 条命令均有来源校验`,
  noGuard.length ? `缺校验 ${JSON.stringify(noGuard.map(([n, v]) => `${v.file}:${v.line} ${n}`))}` : '',
);

// ---- A2. 手写判定豁免双向棘轮 ----
// 统一 guard 会在拒绝时写日志（`guard.rs:29-32`），手写 `label() != "main"` 不会 ——
// 静默拒绝会掩盖注入尝试，所以「不走统一 guard」必须是有意为之且被登记。
const handwritten = [...tiers.entries()].filter(([, v]) => v.tier === 'HANDWRITTEN').map(([k]) => k);
const unregistered = handwritten.filter((n) => !EXEMPT[n]); // 代码里手写了但清单没登记
const staleExempt = Object.keys(EXEMPT).filter(
  (n) => !tiers.has(n) || !['HANDWRITTEN', null].includes(tiers.get(n).tier),
); // 清单登记了但代码已改用统一 guard
check(
  unregistered.length === 0 && staleExempt.length === 0,
  `A2. 不走统一 guard 的命令逐条登记（豁免 ${Object.keys(EXEMPT).length} / 实际 ${handwritten.length}）`,
  unregistered.length
    ? `手写判定未登记 ${JSON.stringify(unregistered)}`
    : staleExempt.length
      ? `豁免清单已失效（已改用统一 guard，请移除）${JSON.stringify(staleExempt)}`
      : '',
);

// ---- B. 主窗档双向棘轮 ----
const actualMain = [...tiers.entries()].filter(([, v]) => v.tier === 'MAIN').map(([k]) => k).sort();
const wantMain = [...MUST_MAIN].sort();
const missing = wantMain.filter((n) => !actualMain.includes(n)); // 登记了但代码里不是 MAIN
const extra = actualMain.filter((n) => !wantMain.includes(n)); // 代码里是 MAIN 但没登记
const unknown = wantMain.filter((n) => !tiers.has(n)); // 清单里写了不存在的命令名
check(
  missing.length === 0 && extra.length === 0 && unknown.length === 0,
  `B. 主窗档清单与实际完全一致（清单 ${wantMain.length} / 实际 ${actualMain.length}）`,
  unknown.length
    ? `清单里有不存在的命令 ${JSON.stringify(unknown)}`
    : missing.length
      ? `应为 MAIN 实际不是 ${JSON.stringify(missing.map((n) => `${tiers.get(n)?.file}:${tiers.get(n)?.line} ${n}(${tiers.get(n)?.tier})`))}`
      : extra.length
        ? `实际是 MAIN 但清单未登记 ${JSON.stringify(extra)}`
        : '',
);

// ---- C. MAIN 档不能有 guard_readonly 混写 ----
const mixed = [...tiers.entries()].filter(([n, v]) => {
  if (!MUST_MAIN.includes(n) || v.tier !== 'MAIN') return false;
  const text = readFileSync(join(CMD_DIR, v.file), 'utf8').split('\n');
  const end = text.findIndex((l, i) => i > v.line && l.includes('#[tauri::command]'));
  const body = text.slice(v.line - 1, end < 0 ? text.length : end);
  return body.some((l) => /guard_readonly\(/.test(l));
});
check(
  mixed.length === 0,
  'C. MAIN 档命令体内无 guard_readonly 混写',
  mixed.length ? JSON.stringify(mixed.map(([n, v]) => `${v.file}:${v.line} ${n}`)) : '',
);

// ---- 统计报告（不判红） ----
const byTier = {};
for (const [, v] of tiers) byTier[v.tier ?? 'NONE'] = (byTier[v.tier ?? 'NONE'] ?? 0) + 1;
console.log('\n档位分布：' + Object.entries(byTier).map(([k, v]) => `${k}=${v}`).join('  '));

console.log('');
if (fail > 0) {
  console.error(`门禁失败：${fail} 组断言未通过`);
  process.exit(1);
}
console.log('档位门禁全部通过');

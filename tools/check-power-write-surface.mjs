#!/usr/bin/env node
// check-power-write-surface.mjs —— 电源写面收敛门禁（P0-1，2026-10-16）
//
// 抓什么：优化数据层（vendor OPTIONS ⇄ optimizer-runtime.json 双源）、永劫面板侧表、
// 电源面板后端（engine/native/syspanel.rs、commands/syspanel.rs）与 PS 执行层
// （pssteps.rs / systembin.rs）里出现的「电源配置写入」。
//
// 背景一句话：2026-10-10 裁定「整个产品只保留唯一的开启卓越性能写入口」——5 个旧优化项
// 与永劫两条 powercfg 写入同批清零；2026-10-16 用户裁定电源计划编辑器（0.8.2）整体保留
// 为**已授权写面**。本门禁就是这条裁定的机检形态：漫游式电源写入（优化项/数据层偷偷改
// 用户电源配置）是本域最大的「静默改系统」面，靠人眼守不住。
//
// 允许的写面只有 ALLOW 表里的显式登记（三张清单）：
//   ① 电源计划编辑器：duplicate/rename/delete/import/export/逐设置 apply（已登记）
//   ② 开启卓越性能：创建/激活 —— P1-2 落地时在 ALLOW 表补登记
//   ③ 隐藏高性能：导出/删除/恢复 —— P1-2 落地时在 ALLOW 表补登记
// 其余任何 powercfg 写命令、Control\Power / Session Manager\Power / GraphicsDrivers\Power
// 等电源命名空间注册表写入、ASPM/休眠/节流/现代待机相关值，一律判红。
//
// 判据纪律（§5.16 N6）：vendor 与 runtime 走**同一个 judgeItem**，不许两套实现；
// 只读查询（/getactivescheme、-lastwake、/q 等）刻意不在写命令集内 —— 全量禁会把
// 健康检查与排查入口一起误伤（本机 overview-scripts.js 的 /getactivescheme 是合法读）。
// 双棘轮：命中未登记 ⇒ 红；ALLOW 登记了却一次都不命中（白名单腐烂）⇒ 红。
// 假绿防线（§4.1）：内置 POSITIVE_CONTROLS 自检（写命令/电源命名空间必判红、
// 只读查询与普通步骤必须放行），由 check-positive-controls 管辖其真实执行。
//
// 用法：node tools/check-power-write-surface.mjs   （退出码 0 = 全绿，1 = 任一不符）
'use strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { gate } from './lib/gate.mjs';
import { ORIGIN, REPO_ROOT } from './ps-origin.mjs';

const require = createRequire(import.meta.url);
const g = gate(import.meta.url);
const R = (rel) => readFileSync(join(REPO_ROOT, ...rel.split('/')), 'utf8');

let fail = 0;
const check = (ok, name, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${name}${detail ? ' —— ' + detail : ''}`);
  if (!ok) fail++;
};

// ===========================================================================
// 判定器（唯一实现）
// ===========================================================================

// powercfg 的「写」动词全集。读侧（/query -q、/list -l、/getactivescheme、-lastwake、
// -devicequery、-sleepstudy 报告类、-systemsleepdiagnostics、-energy、-batteryreport 等）
// 刻意不在表内。
const PC_WRITE_SWITCHES = new Set([
  'h', 'hibernate', 's', 'setactive', 'setacvalueindex', 'setdcvalueindex',
  'x', 'change', 'delete', 'import', 'export', 'duplicatescheme',
  'restoredefaultschemes', 'rename', 'setsecuritydescriptor', 'requestsoverride',
  'deviceenable', 'devicedisable',
]);

// 电源命名空间（注册表侧）。`\\{1,2}`：兼容「解析后的单反斜杠」与「源码原文的双反斜杠」
// 两种形态（前者来自 JSON.parse 的 reg 文本，后者来自 .rs/.js 原文扫描）。
const POWER_NS = /(Control|Session Manager|GraphicsDrivers)\\{1,2}Power|\\{1,2}SleepStudy|\\{1,2}SleepReliability/i;

// 命中即判红的电源值名（覆盖设备级 ASPM 这类不挂在 \Control\Power 下的旁路写法）。
const POWER_VALUE_NAMES =
  /^(HibernateEnabledDefault|HibernateEnabled|HiberbootEnabled|PowerThrottlingOff|PlatformAoAcOverride|CsEnabled|EnergyEstimationEnabled|EventProcessorEnabled|SleepStudyDisabled|SleepReliabilityDetailedDiagnostics|EnableASPM)$/i;

/** powercfg 写命令命中（返回 [{rule, detail}]）。 */
function powercfgHits(text) {
  const out = [];
  for (const m of String(text || '').matchAll(/powercfg(?:\.exe)?\b/gi)) {
    const after = String(text).slice(m.index + m[0].length, m.index + m[0].length + 160);
    // 允许中间夹引号/括号/逗号/换行（真实调用形态：system_tool("powercfg.exe"), 换行 &["/export", …]）
    const sw = after.match(/^[\s"'(),;&=\[]{0,30}(?:\/|-)\s*([a-z_]+)/i);
    if (sw && PC_WRITE_SWITCHES.has(sw[1].toLowerCase())) {
      out.push({ rule: 'powercfg-write', detail: `powercfg ${sw[1].toLowerCase()}` });
    }
  }
  return out;
}

/** 电源命名空间命中：reg 段落 / reg 值名 / 文本三路（返回 [{rule, detail, anchor}]）。 */
function powerNsHits({ regText = '', text = '' }) {
  const out = [];
  for (const sec of String(regText).matchAll(/\[([^\]\r\n]+)\]/g)) {
    if (POWER_NS.test(sec[1])) out.push({ rule: 'power-ns', detail: `注册表段 ${sec[1]}` });
  }
  for (const v of String(regText).matchAll(/^\s*"([^"]+)"\s*=/gm)) {
    if (POWER_VALUE_NAMES.test(v[1])) out.push({ rule: 'power-ns', detail: `电源值名 ${v[1]}` });
  }
  const m = String(text || '').match(POWER_NS);
  if (m) {
    const i = m.index ?? 0;
    out.push({
      rule: 'power-ns',
      detail: `文本含电源命名空间 ${m[0]}`,
      anchor: String(text).slice(Math.max(0, i - 80), i + 80),
    });
  }
  return out;
}

/** 对一条优化项做结构化判定（vendor OPTIONS 与 runtime 走同一函数，§5.16）。 */
function judgeItem(o) {
  const hits = [];
  for (const [where, arr] of [['steps', o.steps], ['restore', o.restore]]) {
    for (const [i, s] of (arr || []).entries()) {
      if (!s || typeof s !== 'object') continue;
      const reg = typeof s.reg === 'string' ? s.reg : '';
      const text = [s.pwsh, s.cmd].filter((x) => typeof x === 'string').join('\n');
      const at = `${where}[${i}]`;
      for (const h of powercfgHits(text)) hits.push({ ...h, where: at });
      for (const h of powerNsHits({ regText: reg, text })) hits.push({ ...h, where: at });
    }
  }
  return hits.map((h) => ({ ...h, id: o.id }));
}

/** 剥注释（// 与 /* *​/ 两种）：注释里的提及不是可执行写面。 */
function stripComments(text) {
  return String(text).replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/[^\n]*/g, ' ');
}

// ===========================================================================
// 允许写面登记表（双棘轮：命中未登记 ⇒ 红；登记不命中 ⇒ 红）
// ===========================================================================
const ALLOW = [
  {
    file: 'src-tauri/src/engine/native/syspanel.rs',
    match: (h) => h.rule === 'powercfg-write' && h.detail === 'powercfg export',
    why: '电源计划编辑器·导出 .powrplan（v5 P0 走 systembin::quiet_cmd_timeout；2026-10-16 用户裁定编辑器整体保留为已授权写面）',
  },
  {
    file: 'src-tauri/src/engine/native/syspanel.rs',
    match: (h) => h.rule === 'power-ns' && /PowerSettings/.test(h.anchor || ''),
    why: '编辑器「在注册表中查看」的 regedit 只读导航串（把编辑器定位到该设置键，不写注册表）',
  },
  // ---- P1-2（开启卓越性能 / 隐藏高性能）落地时在下方逐条补登记（用户 2026-10-16 裁定）：
  // { file: 'src-tauri/src/engine/native/syspanel.rs', match: h => h.detail === 'powercfg duplicatescheme', why: '开启卓越性能·创建（P1-2）' },
  // { file: 'src-tauri/src/engine/native/syspanel.rs', match: h => h.detail === 'powercfg setactive', why: '开启卓越性能/隐藏流程·激活（P1-2）' },
  // { file: 'src-tauri/src/engine/native/syspanel.rs', match: h => h.detail === 'powercfg delete', why: '隐藏高性能·删除（P1-2，导出在前、失败回滚）' },
  // { file: 'src-tauri/src/engine/native/syspanel.rs', match: h => h.detail === 'powercfg import', why: '隐藏高性能·恢复导入（P1-2）' },
];

// ===========================================================================
// 扫描面
// ===========================================================================
const hits = []; // {file, rule, detail, id?, where?, anchor?}
const stats = { runtime: 0, vendorOpts: 0, vendorJs: 0, nara: 0, src: 0 };

// 1) optimizer-runtime.json（数据层真源产物）
{
  const arr = JSON.parse(R('src-tauri/data/optimizer-runtime.json'));
  stats.runtime = Array.isArray(arr) ? arr.length : 0;
  if (Array.isArray(arr)) {
    for (const o of arr) for (const h of judgeItem(o)) hits.push({ file: 'src-tauri/data/optimizer-runtime.json', ...h });
  }
}

// 2) vendor OPTIONS（上游真源，与 runtime 同一判定函数）
try {
  const { OPTIONS } = require(join(ORIGIN, 'src/scripts-powershell/optimizer-scripts.js'));
  stats.vendorOpts = Array.isArray(OPTIONS) ? OPTIONS.length : 0;
  if (Array.isArray(OPTIONS)) {
    for (const o of OPTIONS) for (const h of judgeItem(o)) hits.push({ file: 'vendor/upstream-js/src/scripts-powershell/optimizer-scripts.js#OPTIONS', ...h });
  }
} catch (e) {
  check(false, 'vendor OPTIONS 不可读', String(e).slice(0, 120));
}

// 3) vendor 全量 js 文本（scripts-powershell/*.js + main.js），剥注释后扫
{
  const dir = join(REPO_ROOT, 'vendor', 'upstream-js', 'src', 'scripts-powershell');
  const files = readdirSync(dir).filter((f) => f.endsWith('.js')).map((f) => join(dir, f));
  const mainJs = join(REPO_ROOT, 'vendor', 'upstream-js', 'main.js');
  if (existsSync(mainJs)) files.push(mainJs);
  for (const abs of files) {
    const rel = abs.slice(REPO_ROOT.length + 1).replace(/\\/g, '/');
    const text = stripComments(readFileSync(abs, 'utf8'));
    const hs = [...powercfgHits(text), ...powerNsHits({ text })];
    stats.vendorJs++;
    for (const h of hs) hits.push({ file: rel, ...h });
  }
}

// 4) 永劫面板侧表（JSON 原文）
{
  const text = R('src-tauri/data/optimizer-nara-panel.json');
  stats.nara = 1;
  for (const h of [...powercfgHits(text), ...powerNsHits({ text })]) {
    hits.push({ file: 'src-tauri/data/optimizer-nara-panel.json', ...h });
  }
}

// 5) 源码文本（剥注释）：电源面板后端 + PS 执行层
{
  const SRC_FILES = [
    'src-tauri/src/engine/native/syspanel.rs',
    'src-tauri/src/commands/syspanel.rs',
    'src-tauri/src/engine/pssteps.rs',
    'src-tauri/src/engine/systembin.rs',
  ];
  for (const rel of SRC_FILES) {
    const text = stripComments(R(rel));
    stats.src++;
    for (const h of [...powercfgHits(text), ...powerNsHits({ text })]) hits.push({ file: rel, ...h });
  }
}

// ===========================================================================
// 断言
// ===========================================================================

// A1. 扫描面地板：任何一路塌缩（目录改名/数组读空）都会让下面的「0 命中」变成假绿
check(
  stats.runtime >= 100 && stats.vendorOpts >= 100 && stats.vendorJs >= 15 && stats.nara === 1 && stats.src === 4,
  `A1. 扫描面完整（runtime ${stats.runtime} 项 / vendor OPTIONS ${stats.vendorOpts} 项 / vendor js ${stats.vendorJs} 个 / 面板 1 / 源码 4）`,
  stats.runtime < 100 || stats.vendorOpts < 100 ? '数据层读空 —— 判定器在读错对象，先修本门禁' : '',
);

// A2. 命中 ⇄ ALLOW 逐条对拍（双棘轮）
const consumed = ALLOW.map(() => 0);
const unregistered = [];
for (const h of hits) {
  const idx = ALLOW.findIndex((a) => a.file === h.file && a.match(h));
  if (idx >= 0) consumed[idx]++;
  else unregistered.push(h);
}
const fmt = (h) => `${h.file}${h.id ? ` [${h.id}]` : ''} ${h.where ? h.where + ' ' : ''}(${h.detail})`;
check(
  unregistered.length === 0,
  `A2. 未登记的电源写入面（${unregistered.length} 处）`,
  unregistered.length
    ? unregistered.slice(0, 12).map(fmt).join('；') +
      ' —— 若属新授权写面（如 P1-2 两能力），在 ALLOW 表逐条登记后转绿；其余一律改掉，不许放宽判据'
    : '',
);
const rotten = ALLOW.map((a, i) => (consumed[i] === 0 ? `${a.file} · ${a.why}` : null)).filter(Boolean);
check(
  rotten.length === 0,
  `A3. ALLOW 白名单无空转（${ALLOW.length} 条登记，${consumed.join('/')} 次命中）`,
  rotten.length ? `登记了却一次不命中（白名单腐烂比没有更危险）：${rotten.join('；')}` : '',
);

// 打印扫描账（报告引用数字从这里抄）
console.log(
  `   · 命中账：${hits.length} 处 = 已登记 ${consumed.reduce((a, b) => a + b, 0)} + 未登记 ${unregistered.length}` +
    `（powercfg 写 ${hits.filter((h) => h.rule === 'powercfg-write').length} / 电源命名空间 ${hits.filter((h) => h.rule === 'power-ns').length}）`,
);

// ===========================================================================
// POSITIVE_CONTROLS：判定器自检（原缺陷形态必须判红、合法形态必须放行）
// ===========================================================================
{
  const cases = [
    {
      label: '原旧写面：powercfg /h off（tf_hibern_off 退役形态）',
      run: () => powercfgHits('powercfg /h off').some((h) => h.rule === 'powercfg-write'),
      want: true,
    },
    {
      label: '原旧写面：powercfg -setacvalueindex（ASPM/节流形态）',
      run: () => powercfgHits('powercfg /setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0').some((h) => h.rule === 'powercfg-write'),
      want: true,
    },
    {
      label: '跨行调用形态：system_tool("powercfg.exe") 与 &["/export" 分行仍须命中',
      run: () => powercfgHits('quiet_cmd_timeout(\n  system_tool("powercfg.exe"),\n  &["/export", tmp, guid],\n)').some((h) => h.detail === 'powercfg export'),
      want: true,
    },
    {
      label: '电源命名空间：Control\\Power 注册表段',
      run: () => powerNsHits({ regText: '[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Power]\r\n"HibernateEnabledDefault"=dword:00000000\r\n' }).some((h) => h.rule === 'power-ns'),
      want: true,
    },
    {
      label: '旁路值名：设备级 EnableASPM（不在 Control\\Power 下）',
      run: () => powerNsHits({ regText: '[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968}]\\r\n"EnableASPM"=dword:00000000\r\n' }).some((h) => h.rule === 'power-ns'),
      want: true,
    },
    {
      label: '合法只读：powercfg /getactivescheme 必须放行',
      run: () => powercfgHits('$planLine = (powercfg /getactivescheme 2>$null) | Select-Object -First 1').length === 0,
      want: true,
    },
    {
      label: '合法只读：cmd /k powercfg -lastwake 必须放行',
      run: () => powercfgHits('cmd /k powercfg -lastwake').length === 0,
      want: true,
    },
    {
      label: '合法步骤：fsutil 行为设置必须放行',
      run: () => powercfgHits('fsutil behavior set disabledeletenotify 0').length === 0 && powerNsHits({ text: 'fsutil behavior set disabledeletenotify 0' }).length === 0,
      want: true,
    },
    {
      label: '合法步骤：Session Manager\\Memory Management（页面文件）不得误伤',
      run: () => powerNsHits({ regText: '[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management]\r\n"ClearPageFileAtShutdown"=dword:00000000\r\n' }).length === 0,
      want: true,
    },
  ];
  const bad = cases.filter((c) => c.run() !== c.want).map((c) => c.label);
  check(bad.length === 0, `正向对照：${cases.length} 条判定器样本（判红 ${cases.filter((c) => c.want).length} / 放行 ${cases.filter((c) => !c.want).length}）`, bad.join('；') || '');
}

if (fail > 0) {
  console.error(`check-power-write-surface: ${fail} 组断言未通过`);
  process.exit(1);
}
console.log(
  `判断通过：电源写面只剩已登记的 ${ALLOW.length} 条（编辑器导出/只读导航）；` +
    '其余 powercfg 写与电源命名空间写入全零（runtime/vendor/面板/源码五路扫描）',
);

// check-ps-extraction.mjs —— PS 脚本「逐字搬运」门禁（Phase 1 起生效）
//
// 背景：Tauri 侧把 `src/scripts-powershell/*.js` 里的 PowerShell 脚本外置为
// `src-tauri/ps/*.ps1`（编译期 include_str! 嵌入）。这是**纯搬运**，任何字符漂移
// 都等于悄悄改了清理/采集行为，且不会报错——必须机器校验。
//
// 校验两层：
//   ① 文本层：JS 模板字面量（运行时取值，故 \n \\ \uFEFF 等转义由 JS 引擎还原）
//      与 .ps1 正文逐字一致（剥离 .ps1 顶部的 PROVENANCE 说明块后比较）；
//   ② 行为层：同一台机器上分别用 pwsh 跑「JS 原脚本」与「.ps1」，JSON 输出深比对
//      （只对确定性字段比对，抖动字段见 TOLERANT 说明）。
//
// 审查 v2-M18（本文件默认语义的反转）：行为层要**真起 PowerShell**，66 条映射里 15 条
// 不带 noRun（sysdisk/overview_*/memory_*/netcheck_*/runtimes_*/netspeed_*/cm_*/
// startup_scan/peripheral_query 等采集类），每条还要跑两遍（JS 版 + .ps1 版）。
// 本门禁在 AGENTS.md §4 里是「改完必做」的静态门禁，默认真跑等于让每次验收都扫盘+发网络探测；
// 更要紧的是旧实现「找不到 pwsh 只打一句 ⚠ 跳过」后照样输出「全部门禁通过」= 静默判绿。
// 现在：默认**只做文本层**，行为层必须显式 `--run`；`--run` 而 pwsh 缺席 → 判红（不许降级成跳过）；
// 未跑行为层时结尾不再宣称「全部通过」，而是「文本层通过 / 行为层未验证」，
// 需要把「未验证」也当失败的场景（发布前验收）加 `--strict`。
//
// 用法：node tools/check-ps-extraction.mjs [--run [--only a,b]] [--strict] [--no-run]
//   --run         执行行为层（真起 pwsh，只跑不带 noRun 的 15 条）；缺 pwsh 即判红
//   --only        配合 --run，只跑名字匹配的映射（排障用）
//   --strict      把「行为层未验证」也算作失败（退出码 1）——发布前验收用这条
//   --no-run      历史姿势，现为默认行为的显式写法（保留兼容，不判错）
// 退出码：0 = 文本层全一致（--strict 时还须行为层已覆盖）；1 = 有不一致或未按要求执行

import { createRequire } from 'node:module';
import { readFileSync, writeFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { MAPPING, stripProvenance, loadBody } from './ps-mapping.mjs';

const require = createRequire(import.meta.url);
const PSDIR = join(new URL('..', import.meta.url).pathname.replace(/^\//, '').replace(/\//g, '\\'), 'src-tauri', 'ps');

// 行为层比对中允许差异的字段（运行期天然抖动）
// cache：内存「系统缓存」逐秒变动；collectedAt：netcheck 采集时刻；
// jitter/min/max/samples：netspeed ping 的逐次采样值（网络抖动，无法复现）。
const VOLATILE = new Set(['cpu', 'memory', 'uptime', 'processes', 'free', 'used', 'percent', 'at', 'timestamp', 'refresh', 'width', 'height',
  'cache', 'pageUsed', 'pageTotal', 'collectedAt', 'jitter', 'min', 'max', 'avg', 'samples',
  // load：内存占用百分比（memory_info），两次运行间天然浮动 ±1~2 个百分点
  'load']);
// 但 overview 的 disks[].total 等结构字段必须一致

const runCompare = process.argv.includes('--run');
// --no-run 现在只是默认行为的显式写法；仍接受，避免让既有脚本/肌肉记忆报错。
if (process.argv.includes('--no-run') && !runCompare) { /* 与新默认等价 */ }
const STRICT = process.argv.includes('--strict');
const ONLY = (() => {
  const i = process.argv.indexOf('--only');
  return i >= 0 && process.argv[i + 1] ? new Set(process.argv[i + 1].split(',')) : null;
})();

function resolvePwsh() {
  const candidates = [];
  if (process.env.PWSH7_PATH) candidates.push(process.env.PWSH7_PATH);
  if (process.env.ProgramFiles) candidates.push(join(process.env.ProgramFiles, 'PowerShell', '7', 'pwsh.exe'));
  try {
    const out = execFileSync('where.exe', ['pwsh.exe'], { encoding: 'utf8' });
    candidates.push(...out.split(/\r?\n/).map(s => s.trim()).filter(Boolean));
  } catch { /* where 不可用则忽略 */ }
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return null;
}

function runPs(pwsh, scriptText, workDir, tag) {
  const file = join(workDir, `${tag}.ps1`);
  writeFileSync(file, Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]), Buffer.from(scriptText, 'utf8')]));
  const r = spawnSync(pwsh, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', file], {
    encoding: 'utf8', timeout: 120000, env: { ...process.env, TRIM_TMP: workDir },
  });
  if (r.status !== 0) return { error: `退出码 ${r.status}: ${(r.stderr || '').trim().slice(0, 300)}` };
  const line = (r.stdout || '').split(/\r?\n/).filter(l => l.trim().startsWith('{')).pop();
  if (!line) return { error: 'stdout 无 JSON 行' };
  try { return { value: JSON.parse(line) }; } catch (e) { return { error: `JSON 解析失败: ${e.message}` }; }
}

function deepDiff(a, b, path = '', out = []) {
  if (out.length > 25) return out;
  if (typeof a !== typeof b) { out.push(`${path}: 类型不同 (${typeof a} vs ${typeof b})`); return out; }
  if (a === null || b === null || typeof a !== 'object') {
    if (a !== b) out.push(`${path}: ${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
    return out;
  }
  if (Array.isArray(a) !== Array.isArray(b)) { out.push(`${path}: 数组性不同`); return out; }
  if (Array.isArray(a)) {
    if (a.length !== b.length) out.push(`${path}: 长度 ${a.length} vs ${b.length}`);
    for (let i = 0; i < Math.min(a.length, b.length); i++) deepDiff(a[i], b[i], `${path}[${i}]`, out);
    return out;
  }
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const k of keys) {
    if (VOLATILE.has(k)) continue;
    if (!(k in a)) { out.push(`${path}.${k}: 仅新版有`); continue; }
    if (!(k in b)) { out.push(`${path}.${k}: 仅旧版有`); continue; }
    deepDiff(a[k], b[k], path ? `${path}.${k}` : k, out);
  }
  return out;
}

let fail = 0;
// 行为层三个计数：应跑 / 真跑成功 / 跑不起来 —— 没有它们就区分不了「验过且一致」与「压根没验」
let behRun = 0;
let behRunnable = 0;
let behError = 0;
const pwsh = runCompare ? resolvePwsh() : null;
if (runCompare && !pwsh) {
  // 判红而不是跳过：显式要求了行为层，机器上却没有 pwsh，那就是「没验」，
  // 让它沉默地走过去正是 v2-M18 要根除的形态。
  console.error('✗ 指定了 --run，但未找到 pwsh（设 PWSH7_PATH 或把 pwsh.exe 放进 PATH）——行为层无法执行，判失败');
  process.exit(1);
}
const work = runCompare ? mkdtempSync(join(tmpdir(), 'trim-ps-check-')) : null;

console.log('=== PS 脚本搬运一致性门禁 ===');
console.log(runCompare
  ? `行为层：开启（--run，pwsh=${pwsh}；真起 PowerShell 执行不带 noRun 的映射，有扫盘/网络副作用）`
  : `行为层：未验证（默认不执行真实 .ps1；需要时用 --run）`);
console.log('');
for (const m of MAPPING) {
  if (ONLY && !ONLY.has(m.name)) continue;
  const jsText = loadBody(m, require, readFileSync);
  const psPath = join(PSDIR, m.ps1);
  const { body, provenance } = stripProvenance(readFileSync(psPath, 'utf8'));

  const textOk = jsText.trim() === body.trim();
  console.log(`${textOk ? '✓' : '✗'} ${m.ps1} 文本层（PROVENANCE 块${provenance ? '有' : '缺失!'}）`);
  if (!textOk) {
    fail++;
    const a = jsText.trim().split('\n');
    const b = body.trim().split('\n');
    const n = Math.max(a.length, b.length);
    for (let i = 0; i < n; i++) {
      if ((a[i] ?? '') !== (b[i] ?? '')) {
        console.log(`   首个差异 @行 ${i + 1}`);
        console.log(`   JS: ${JSON.stringify((a[i] ?? '').slice(0, 160))}`);
        console.log(`   PS: ${JSON.stringify((b[i] ?? '').slice(0, 160))}`);
        break;
      }
    }
  }

  if (!m.noRun) behRunnable++;
  if (runCompare && !m.noRun) {
    const jsRun = runPs(pwsh, jsText, work, `${m.name}-js`);
    const psRun = runPs(pwsh, body, work, `${m.name}-ps`);
    if (jsRun.error || psRun.error) {
      // 跑不起来 ≠ 一致：计入 fail，避免旧的「⚠ 行为层跳过」把该条清零后照样判绿
      fail++;
      behError++;
      console.log(`  ✗ 行为层无法执行：JS=${jsRun.error || 'ok'} PS=${psRun.error || 'ok'}`);
    } else {
      behRun++;
      const diff = deepDiff(jsRun.value, psRun.value);
      if (diff.length === 0) console.log(`  ✓ 行为层：JSON 深比对一致（抖动字段已豁免：${[...VOLATILE].slice(0, 6).join('/')}…）`);
      else { fail++; console.log(`  ✗ 行为层差异 ${diff.length} 处：${diff.slice(0, 6).join(' | ')}`); }
    }
  } else if (m.noRun) {
    console.log(`  – 行为层豁免：${m.noRun}`);
  }
}

if (work) rmSync(work, { recursive: true, force: true });
// 「行为层已验证」= 该跑的每条都真跑了、且没有一条以「跑不起来」告终
const behCovered = runCompare && behRunnable > 0 && behRun === behRunnable && behError === 0;
console.log(`\n行为层覆盖：${runCompare ? `${behRun}/${behRunnable}` : '未执行（0/0）'}`);
if (!runCompare) {
  console.log(STRICT
    ? '✗ --strict 要求行为层已验证，本次未执行（发布前验收：加 --run 真跑，或去掉 --strict 只当静态门禁）'
    : '※ 本次只做了文本层对拍：行为层未验证，不代表 .ps1 与 JS 在真实 pwsh 下等价。');
}
const textFail = fail;
const ok = textFail === 0 && (!STRICT || behCovered);
const verdict = ok
  ? (behCovered ? '✓ 全部门禁通过（文本层 + 行为层均已验证）' : '✓ 文本层门禁通过（行为层未验证，见上）')
  : `✗ ${textFail} 项未通过${STRICT && !behCovered ? '（另：--strict 要求行为层已验证，本次未达成）' : ''}`;
console.log(`\n${verdict}`);
process.exit(ok ? 0 : 1);

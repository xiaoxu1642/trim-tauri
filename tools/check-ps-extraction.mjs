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
// 用法：node tools/check-ps-extraction.mjs [--no-run]

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

const runCompare = !process.argv.includes('--no-run');

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
const pwsh = runCompare ? resolvePwsh() : null;
if (runCompare && !pwsh) console.log('⚠ 未找到 pwsh，跳过行为层比对（仅做文本层）');
const work = mkdtempSync(join(tmpdir(), 'trim-ps-check-'));

console.log('=== PS 脚本搬运一致性门禁 ===\n');
for (const m of MAPPING) {
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

  if (runCompare && pwsh && !m.noRun) {
    const jsRun = runPs(pwsh, jsText, work, `${m.name}-js`);
    const psRun = runPs(pwsh, body, work, `${m.name}-ps`);
    if (jsRun.error || psRun.error) {
      console.log(`  ⚠ 行为层跳过：JS=${jsRun.error || 'ok'} PS=${psRun.error || 'ok'}`);
    } else {
      const diff = deepDiff(jsRun.value, psRun.value);
      if (diff.length === 0) console.log(`  ✓ 行为层：JSON 深比对一致（抖动字段已豁免：${[...VOLATILE].slice(0, 6).join('/')}…）`);
      else { fail++; console.log(`  ✗ 行为层差异 ${diff.length} 处：${diff.slice(0, 6).join(' | ')}`); }
    }
  } else if (m.noRun) {
    console.log(`  – 行为层豁免：${m.noRun}`);
  }
}

rmSync(work, { recursive: true, force: true });
console.log(`\n${fail === 0 ? '全部门禁通过' : `${fail} 项未通过`}`);
process.exit(fail === 0 ? 0 : 1);
#!/usr/bin/env node
// check-artifact-size.mjs —— 发版产物体积棘轮（性能审计 v3 P2-I）
//
// 为什么需要它（v3 §10.2 缺口 2 的实测结论）：`build-release/` 里三个产物的字节数
// 此前**没有被任何门禁读过**——`check-release-freshness` 是 OPTIONAL 且管"新鲜度"不管尺寸，
// `check-asset-size` 管的是 `src/` 源码侧资源。于是"安装包悄悄变大"只能发版前人肉发现；
// 而安装包体积对本仓尤其敏感：单是一支 MiSansVF.ttf 就占 setup 约六成（20,093,424 B，
// 2026-10-14 已整链移除）。
//
// 三条纪律：
//   ① 缺失即 SKIP，不是通过。`build-release/` 与产物都是**未跟踪**文件（AGENTS §2 / §7），
//      干净克隆后本机可能根本没有；缺输入时打 ✓ 就是假绿。
//   ② 只减不增的棘轮：超登记 cap ⇒ 红；小于 cap ⇒ 只提示跑 `--write` 收紧（缩小是合法方向，
//      但基线不自动跟随，否则"这次小了"会变成下次"变大一点也没事"的暗口子）。
//   ③ 正向对照内置：违例样本（超 cap）与合规样本（未超）都必须命中，否则本门禁断言不可信。
//
// 用法：node tools/check-artifact-size.mjs         校验
//       node tools/check-artifact-size.mjs --write 重算并落基线（产物必须已在盘上）
'use strict';
import { existsSync, readdirSync, statSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPO_ROOT } from './ps-origin.mjs';
import { gate } from './lib/gate.mjs';

const DIR = join(REPO_ROOT, 'build-release');
const BASELINE_PATH = join(REPO_ROOT, 'tools', 'fixtures', 'artifact-size-baseline.json');
const WRITE = process.argv.includes('--write');

const g = gate(import.meta.url);

/** 产物角色识别：一条 pattern 一个角色，避免把调试件混进来 */
const ROLES = [
  { role: 'setup', re: /^Trim_.+_x64-setup\.exe$/ },
  { role: 'portableZip', re: /^Trim_.+_x64-portable\.zip$/ },
  { role: 'exe', re: /^Trim\.exe$/ },
];

/** 纯判定器：给定当前尺寸与基线，返回违例列表（可被合成样本喂） */
export function judgeSizes(current, baseline) {
  const problems = [];
  const shrink = [];
  for (const { role } of ROLES) {
    const cur = current[role];
    if (cur == null) continue; // 缺失由调用方按 SKIP 处理，不算违例
    const cap = baseline[role];
    if (cap == null) {
      problems.push(`${role} 在盘上（${cur} B）但未登记进基线 —— 新产物角色必须显式登记`);
      continue;
    }
    if (cur > cap) problems.push(`${role} ${cur} B > 登记 cap ${cap} B（+${cur - cap} B）：确需变大请带理由跑 --write`);
    else if (cur < cap) shrink.push(`${role} ${cap}→${cur}（−${cap - cur} B，确认无误后 --write 收紧）`);
  }
  // T1b-M04（v7.2 C09）：反向也棘轮——基线登记了、盘上没有的角色不许 continue 掉。
  // 旧实现三个角色少一个不报（构建不完整/角色改名时「0 命中」照样绿）。
  for (const role of Object.keys(baseline)) {
    if (!(role in current)) {
      problems.push(`基线登记了 ${role}（cap ${baseline[role]} B）但盘上没有该产物 —— 产物缺失不许静默（发版不完整或角色改名，--write 前先查因）`);
    }
  }
  return { problems, shrink };
}

function scanArtifacts() {
  const out = {};
  for (const f of readdirSync(DIR)) {
    for (const { role, re } of ROLES) {
      if (re.test(f)) out[role] = statSync(join(DIR, f)).size;
    }
  }
  return out;
}

console.log('=== 发版产物体积门禁 ===\n');

// 正向对照自检（违例必红 / 合规必放行）——先跑，失效即整条门禁不可信
{
  const problems = [];
  const bad = judgeSizes({ setup: 101 }, { setup: 100 });
  if (bad.problems.length !== 1) problems.push(`超 cap 样本未判红：得 ${JSON.stringify(bad.problems)}`);
  const good = judgeSizes({ setup: 100 }, { setup: 100 });
  if (good.problems.length !== 0) problems.push(`等值合规样本误报：${JSON.stringify(good.problems)}`);
  const shrinkCase = judgeSizes({ setup: 50 }, { setup: 100 });
  if (shrinkCase.problems.length !== 0 || shrinkCase.shrink.length !== 1) {
    problems.push(`缩小样本应只提示不红：得 ${JSON.stringify(shrinkCase)}`);
  }
  const unregistered = judgeSizes({ exe: 7, setup: 100 }, { setup: 100 });
  if (unregistered.problems.length !== 1) problems.push(`未登记角色漏判：${JSON.stringify(unregistered.problems)}`);
  // T1b-M04：反向缺失（基线有、盘上无）必须判红
  const missingRole = judgeSizes({ setup: 100 }, { setup: 100, exe: 5 });
  if (missingRole.problems.length !== 1) problems.push(`基线有盘上无漏判：${JSON.stringify(missingRole.problems)}`);
  const complete = judgeSizes({ setup: 100, exe: 5 }, { setup: 100, exe: 5 });
  if (complete.problems.length !== 0) problems.push(`角色齐全样本误报：${JSON.stringify(complete.problems)}`);
  if (problems.length) {
    g.fail(`正向对照自检失效：\n  ${problems.join('\n  ')}`);
    g.finish();
    process.exit(1);
  }
  g.ok('正向对照自检 6 组全部命中（超 cap 必红 / 等值放行 / 缩小只提示 / 未登记必红 / 基线有盘上无必红 / 角色齐全放行）');
}

if (!g.skipUnlessPresent(DIR, 'build-release/（发版产物目录，未跟踪）')) {
  console.warn('⚠ 产物不在本机：体积对拍**未执行**（SKIP，不是通过；只有产物已落盘时才会判红/判绿）');
  g.finish();
  process.exit(0);
}
const current = scanArtifacts();
if (!Object.keys(current).length) {
  console.warn('⚠ build-release/ 存在但没有可识别的产物（setup / portable / Trim.exe 三种角色均未命中）：本节**未校验**');
  g.finish();
  process.exit(0);
}

if (WRITE) {
  writeFileSync(BASELINE_PATH, JSON.stringify(current, null, 2) + '\n', 'utf8');
  g.ok(`基线已落盘：${BASELINE_PATH} —— ${JSON.stringify(current)}`);
  g.finish('产物基线重算完成');
  process.exit(0);
}

if (!existsSync(BASELINE_PATH)) {
  console.warn(
    `⚠ 基线文件不存在（tools/fixtures/artifact-size-baseline.json）：本节**未校验**。` +
      `产物已在盘上时可跑 \`node tools/check-artifact-size.mjs --write\` 建立基线（建立后本门禁才有判红能力）`,
  );
  g.finish();
  process.exit(0);
}
const baseline = JSON.parse(readFileSync(BASELINE_PATH, 'utf8'));
for (const [role, size] of Object.entries(current)) {
  console.log(`  ${role.padEnd(12)} ${size.toLocaleString('en-US').padStart(12)} B  （基线 ${String(baseline[role] ?? '未登记').padStart(12)} B）`);
}
const { problems, shrink } = judgeSizes(current, baseline);
if (problems.length) g.fail(`产物体积超登记基线：\n  ${problems.join('\n  ')}`);
// T1b-M04：「三个产物」是写死词——角色数是动态值，写死词与动态数并存就是 K02/M08 那类口径病
else g.ok(`产物体积均未超登记 cap（${Object.keys(current).length} 个角色在盘上）`);
if (shrink.length) g.warn(`收敛提示：${shrink.join('；')}`);

g.finish('产物体积门禁全部通过');

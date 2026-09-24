// tools/check-origin-drift.mjs —— 上游基线快照 vs 活源仓库的**可选**漂移复核
//
// 为什么需要它：审查 K2 把门禁的源坐标从「本机上的 Electron 仓库」改成仓库内的
// `vendor/upstream-js/` 快照，门禁从此自足（干净克隆能跑）。代价是快照会随上游演进而**腐烂**
// —— 上游改了 `.ps1` 模板或受保护路径清单，本仓看不出来。
// 本工具就是那把「防腐烂」的尺子：**只在源仓库在位时才有效，缺席即跳过（退出码 0）**，
// 因此不属 AGENTS.md §4 的必做门禁，也不允许被任何必做门禁 import。
//
// 用法：node tools/check-origin-drift.mjs        # 自动按 TRIM_ORIGIN 或默认路径找源仓库
// 退出码：0 = 无漂移 / 源仓库缺席（跳过）；1 = 有漂移（列出文件与差异字节数）
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';

import { ORIGIN, UPSTREAM_REPO } from './ps-origin.mjs';

if (!existsSync(UPSTREAM_REPO)) {
  console.log(`· 源仓库不在位（${UPSTREAM_REPO}），跳过漂移复核（不算失败）`);
  process.exit(0);
}

/** 快照里要核对的文件：源仓库根的几个入口 + src 下两个目录 */
function snapshotFiles(root) {
  const out = [];
  for (const f of ['main.js', 'preload.js']) {
    if (existsSync(join(root, f))) out.push(f);
  }
  for (const dir of ['src/main', 'src/scripts-powershell']) {
    const abs = join(root, dir);
    if (!existsSync(abs)) continue;
    for (const name of readdirSync(abs)) {
      if (name.endsWith('.js')) out.push(`${dir}/${name}`);
    }
  }
  return out;
}

let drift = 0;
let checked = 0;
for (const rel of snapshotFiles(ORIGIN)) {
  const snap = join(ORIGIN, rel);
  const live = join(UPSTREAM_REPO, rel);
  checked++;
  if (!existsSync(live)) {
    console.log(`✗ ${rel}：快照里有、源仓库已无（上游删除或改名）`);
    drift++;
    continue;
  }
  const a = readFileSync(snap);
  const b = readFileSync(live);
  if (!a.equals(b)) {
    console.log(`✗ ${rel}：快照 ${a.length} B ⇄ 源仓库 ${b.length} B，已漂移`);
    drift++;
  }
}
console.log(
  drift
    ? `${drift}/${checked} 个基线文件与源仓库不一致：整文件重新复制回 vendor/upstream-js/ 后重跑 sync-ps-from-js.mjs 与三套门禁`
    : `✓ ${checked} 个基线文件与源仓库逐字节一致`,
);
process.exit(drift ? 1 : 0);

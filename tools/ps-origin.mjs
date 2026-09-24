// tools/ps-origin.mjs —— 「上游基线」根坐标（PS 脚本搬运的唯一真源）
//
// 批次：审查 K2（2026-09-24）。此前这里是硬编码绝对路径 `C:/KaiFa/Trim`，
// 且在模块顶层就读盘——换机器、干净克隆、CI 上四套门禁与 `.ps1` 生成器**加载即抛**，
// 与提交 `6535847` 修掉的 `trim-finder = path = "../../Trim/native-scanner"` 是同一种病。
// 现在基线已逐字节 vendor 进 `vendor/upstream-js/`（目录形状与源仓库一致，
// 所以 `${ORIGIN}/src/main/…`、`${ORIGIN}/main.js` 这些既有拼法全部保持有效），
// 门禁在仓库自足的前提下不再依赖外部目录。
//
// 单独成文件的原因：ps-mapping.mjs 会 import 各域映射文件，若域文件反过来 import
// ps-mapping 的 ORIGIN 就构成循环依赖——ESM 下域模块顶层求值时会踩 TDZ
// （ReferenceError: Cannot access 'ORIGIN' before initialization）。
//
// ⚠️ 这份快照是**只读基线**：要改逻辑改源仓库后整文件重拷（勿手工编辑，
// 也勿给 `vendor/upstream-js/**` 加行尾转换——.gitattributes 里已 `-text` 钉死）。
// 快照与源仓库是否已漂，用 `node tools/check-origin-drift.mjs` 复核（可选，非门禁）。
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

/** 本仓库根（tools/ 的上一级） */
export const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** 上游基线根：目录形状 = 源仓库根（src/main、src/scripts-powershell、main.js、preload.js） */
export const ORIGIN = join(REPO_ROOT, 'vendor', 'upstream-js');

/**
 * 源仓库（Electron 轨）在本机的位置，仅 `check-origin-drift.mjs` 用来做「快照 vs 活源」
 * 复核。默认取环境变量 TRIM_ORIGIN；缺省时按 vendor 之前的老路径猜一次。
 * **任何门禁都不得依赖它存在**——读不到就跳过，不作为失败。
 */
export const UPSTREAM_REPO = process.env.TRIM_ORIGIN || 'C:/KaiFa/Trim';

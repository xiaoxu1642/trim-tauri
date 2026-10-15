// gen-finder-delete-modes.mjs —— 生成「原生删除结果分档」跨 crate 对拍夹具（R4，2026-10-15）
//
// 为什么需要：产出侧 `native-scanner/src/scan.rs`（delete() 写的 MODE_* 字面量）与消费侧
// `src-tauri/src/commands/finder.rs`（classify_delete_result_mode 的档位映射）分属两个
// crate —— 不能共享代码（§4.1「形似不合」：跨边界只许共享夹具字节，不许共享/抄判定结论）。
// 两侧各自的测试独立对拍本夹具：
//   · 产出侧（scan.rs::mod tests）：夹具登记的每个 mode 字面量都必须在（改 mode 不同步即红）；
//   · 消费侧（finder.rs::mod tests）：每个 mode 的档位映射必须与夹具一致（改映射即红）；
//   · 渲染层消费面（finder.rs::mod tests 同条）：三个分档字段被 finder.js 真的读走。
//
// 用法：node tools/gen-finder-delete-modes.mjs        # 重算并落盘夹具
// 退出码：0 = 已落盘；1 = 失败

import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'tools', 'fixtures', 'finder-delete-modes.json');

// mode 字面量（scan.rs 的 MODE_* 常量）→ 分档（finder.rs 的档位值）。
// 档位语义：ok = 已移入回收站；busy = 回收站失败/占用族；refused = 受保护或链接目标拒绝；
// name = 文件名无法无损处理（保护判定不可靠而拒）。
const MODES = [
  ['recycled', 'ok'],
  ['rejected', 'refused'],
  ['unrecoverable-name', 'name'],
  ['trash-failed', 'busy'],
];

const doc = {
  _comment:
    '原生删除结果行分档对拍夹具（R4 2026-10-15）。产出侧 native-scanner/src/scan.rs 的 MODE 常量；'
    + '消费侧 src-tauri/src/commands/finder.rs 的分档函数。跨 crate 只共享本夹具字节，'
    + '两侧各自独立对拍；本文件由 tools/gen-finder-delete-modes.mjs 生成，不手改。',
  modes: Object.fromEntries(MODES),
};

writeFileSync(OUT, JSON.stringify(doc, null, 2) + '\n', 'utf8');
console.log(`✓ 已落盘 ${OUT}（${MODES.length} 个 mode）`);

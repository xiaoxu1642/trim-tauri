// tools/ps-origin.mjs —— 源仓库根（PS 脚本搬运的唯一坐标）
//
// 单独成文件的原因：ps-mapping.mjs 会 import 各域映射文件，若域文件反过来 import
// ps-mapping 的 ORIGIN 就构成循环依赖——ESM 下域模块顶层求值时会踩 TDZ
// （ReferenceError: Cannot access 'ORIGIN' before initialization）。
export const ORIGIN = 'C:/KaiFa/Trim';
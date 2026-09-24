// tools/ps-map/models.mjs —— models 域（C 批）的 PS 脚本搬运映射
//
// 条目形状与哨兵约定见 tools/ps-mapping.mjs 头部注释。
// 现阶段 models 域（大模型管理）脚本来自 main.js 内联常量或纯 JS 逻辑；
// 若迁移中发现需要外置的 PS 脚本，在此登记（禁止在命令实现里手写 PS 文本）。
export const MAP = [];
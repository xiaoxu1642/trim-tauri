// tools/ps-map/cleanup.mjs —— cleanup 域（C 批）的 PS 脚本搬运映射
//
// 条目形状与哨兵约定见 tools/ps-mapping.mjs 头部注释。
//
// 本域三个脚本都是**多占位符模板**（分类/路径/规则/DLL/条目/布尔开关/防护清单），
// 且 JS 对每个占位符的变换不同（布尔→`$true/$false`、JSON→序列化+单引号转义），
// 用哨兵调用会同时破坏多处语义 —— 故一律走**模板模式**：把带 `\${X_PLACEHOLDER}`
// 的模板原样搬出，Rust 侧按 JS 同口径逐项替换。
// 真实插值（模板里 `${DIAG.PS_PREAMBLE}` / `${RULE_PATH_EVAL_PS}` / `${PROTECT.PROTECT_PATH_PS}`）
// 由 deps 登记后在生成期求值，Rust 拿到的模板里不再有未解析插值。
import { ORIGIN } from '../ps-origin.mjs';

const JS = `${ORIGIN}/src/scripts-powershell/cleanup-scripts.js`;

// 模板真实插值的来源模块（与 cleanup-scripts.js 顶部 require 一致）
const DEPS = {
  DIAG: `${ORIGIN}/src/main/diag.js`,
  RULE_PATH_EVAL_PS: `${ORIGIN}/src/main/ps-rule-path-eval.js`,
  PROTECT: `${ORIGIN}/src/main/ps-protect-path.js`,
};

export const MAP = [
  {
    name: 'cleanup_scan',
    template: { file: JS, varName: 'SCAN_SCRIPT', deps: DEPS },
    ps1: 'cleanup_scan.ps1',
    note: '磁盘清理扫描（模板：CATEGORIES / CONFIGURED_PATHS / RULES_JSON / FASTSIZE_DLL 占位符）',
    noRun: '模板含未替换占位符，行为层不适用（替换正确性由 tools/check-ps-substitution.mjs 对拍）',
  },
  {
    name: 'cleanup_execute',
    template: { file: JS, varName: 'EXECUTE_SCRIPT', deps: DEPS },
    ps1: 'cleanup_execute.ps1',
    note: '磁盘清理执行（模板：ITEMS / FORCE / RECYCLE / AUTO_REBUILD / RULES_JSON / PROTECTED_JSON / FASTSIZE_DLL 占位符）',
    noRun: '模板含未替换占位符，且会真删文件，行为层豁免',
  },
  {
    name: 'cleanup_detail',
    template: { file: JS, varName: 'DETAIL_SCRIPT', deps: DEPS },
    ps1: 'cleanup_detail.ps1',
    note: '条目明细枚举（模板：DETAIL_ID / DETAIL_PATH / DETAIL_RULES_JSON 占位符）',
    noRun: '模板含未替换占位符，行为层不适用',
  },
];
// ps-mapping.mjs —— PS 脚本搬运映射（门禁与生成器共用，单一真源）
//
// 每项：JS 模块路径 + 取脚本的方式 → 目标 .ps1 文件名。三种取法：
//   { call: 'fn' }            零参调用导出函数，取运行时字符串（最常见）
//   { call: 'fn', args: [...] } 带**字面量**参数调用（参数含运行期变量时见下）
//   { const: 'NAME' }         直接取模块导出的字符串常量
//
// 搬运为**纯搬运**：正文直接取自 JS 模块的**运行时字符串值**（不是源码字面量），
// 因此 JS 模板字面量的转义折叠（如 `\*` → `*`、`\\` → `\`、`\uFEFF` 等）由 JS 引擎
// 处理，Rust 侧拿到的就是 Electron 当时真正执行的那份脚本。
//
// 教训（Phase 1，门禁抓出）：手工搬运 device_info 时按「`\\` → `\`」的直觉还原，
// 却把源码里本就只有一个反斜杠的 `'\*'` 保留成 `\*`——而 JS 运行时会把它折叠成 `*`，
// 两者在 PowerShell 中语义不同，直接导致显卡匹配走错分支、显示器信息取错。
// **结论：一律用 tools/sync-ps-from-js.mjs 生成，禁止手工誊抄。**
//
// ---- 参数化脚本（args + 哨兵）----
// 某些脚本的正文里要嵌入运行期才确定的值（PID、安装包路径、规则库 JSON…）。
// 处理方式：生成时用**不会与真实内容碰撞的哨兵字面量**调用一次，得到「模板 .ps1」；
// Rust 侧在运行前把哨兵替换为真实值。哨兵必须满足：
//   · 独特性：形如 __TRIM_XXX__（或 987654321 这类正常数据里不会出现的数字）；
//   · 无变换：JS 对参数只做单引号转义/字符串化时，哨兵原样落入正文（否则见下）；
//   · 标记 noRun：模板跑不出有意义结果（甚至可能改系统），行为层必须豁免。
// 若 JS 对参数做了 JSON 序列化等多步变换，禁止硬凑哨兵——改用「每个变体一条映射」
// （不同 actionId 各生成一份 .ps1），把变化收敛到生成期。
// 
// ---- 分域文件（并行迁移防冲突）----
// 域专属映射放在 tools/ps-map/<域>.mjs，各导出 `MAP` 数组；本文件只做汇总。
// 新增/修改脚本只需要动自己那个域文件，避免多人同时改本文件互相覆盖。

export { ORIGIN } from './ps-origin.mjs';
import { ORIGIN } from './ps-origin.mjs';

// S3 后仅保留 2 个 PS 脚本：cm_icons（GDI+ 图标提取）和 optimizer_build（WMI 还原点）
export const MAPPING = [
  { name: 'cm_icons', js: `${ORIGIN}/src/scripts-powershell/contextmenu-scripts.js`, call: 'icons', args: [['__TRIM_ITEMS_JSON__']], ps1: 'cm_icons.ps1', note: '右键菜单图标修复（哨兵 items）', noRun: '带哨兵参数，行为层豁免' },
  // 审查 v2-F14：旧 note 写「40 个优化项共用一份模板」，实测含 pwsh 步骤的优化项是 44/115
  { name: 'optimizer_build', js: `${ORIGIN}/src/scripts-powershell/optimizer-scripts.js`, call: 'buildScript', args: [[{ __trim_sentinel__: true }]], ps1: 'optimizer_build.ps1', note: '优化项执行脚本（哨兵 steps；44 个含 pwsh 步骤的优化项共用一份模板）', noRun: '会改注册表/服务/系统设置，行为层豁免' },
];

export const PROVENANCE_BEGIN = '# <<<PROVENANCE';
export const PROVENANCE_END = '# PROVENANCE>>>';

/**
 * 取映射项的脚本正文。
 * - 模块项：require 后按 call/args 或 const 取运行时字符串；
 * - 内联项：从源文件切出模板字面量，用 JS 引擎求值（转义折叠与运行期一致）。
 */
export function loadBody(entry, requireFn, readFileFn) {
  if (entry.inline) {
    const text = readFileFn(entry.inline.file, 'utf8');
    const marker = `${entry.inline.varName} = \``;
    const start = text.indexOf(marker);
    if (start < 0) throw new Error(`${entry.inline.file} 未找到 ${entry.inline.varName}`);
    const bodyStart = start + marker.length;
    const end = text.indexOf('`', bodyStart);
    if (end < 0) throw new Error(`${entry.inline.varName} 模板字面量未闭合`);
    // eslint-disable-next-line no-new-func
    return new Function('return `' + text.slice(bodyStart, end) + '`')();
  }
  if (entry.template) {
    return loadTemplate(entry.template, requireFn, readFileFn);
  }
  const mod = requireFn(entry.js);
  if (entry.const) {
    const v = mod[entry.const];
    if (typeof v !== 'string') throw new Error(`${entry.js} 导出 ${entry.const} 不是字符串`);
    return v;
  }
  const fn = mod[entry.call];
  if (typeof fn !== 'function') throw new Error(`${entry.js} 未导出函数 ${entry.call}`);
  const out = fn(...(entry.args || []));
  if (typeof out !== 'string') throw new Error(`${entry.js}.${entry.call}() 未返回字符串`);
  // 审查 M22：安装型脚本的「安装包路径」是运行期才已知的，上游 repair() 用
  // `fs.existsSync` 做存在性校验，所以生成期**只能传一个真实存在的路径**当占位符——
  // 后果是把开发者机器上的绝对路径烧进 .ps1、烧进发布的二进制，且坐标（ORIGIN）一变
  // 文本层对拍就红。故在此统一换成唯一 token，Rust 侧运行前再替换成真实缓存包路径。
  if (entry.sentinelPath) {
    if (!out.includes(entry.sentinelPath)) {
      throw new Error(`${entry.js}.${entry.call}() 产物里没有哨兵 ${entry.sentinelPath}（上游改了模板？）`);
    }
    return out.split(entry.sentinelPath).join(INSTALLER_PATH_TOKEN);
  }
  return out;
}

/** 安装型脚本里的「安装包路径」占位符：必须全局唯一、且不是任何真实路径 */
export const INSTALLER_PATH_TOKEN = '@@TRIM_INSTALLER_PATH@@';

/**
 * 把源坐标写成**仓库内相对路径**再进 PROVENANCE 头。
 * 绝对路径进跟踪文件 = 泄露开发环境布局（M22），且换机器/换 clone 位置就产生无意义 diff。
 */
function relSource(absolute) {
  const norm = String(absolute).replace(/\\/g, '/');
  const i = norm.indexOf('/vendor/upstream-js/');
  if (i >= 0) return norm.slice(i + 1);
  if (norm.startsWith(REPO_ROOT.replace(/\\/g, '/'))) {
    return norm.slice(REPO_ROOT.length + 1);
  }
  return norm;
}

/**
 * 模板模式：取「带占位符的模板常量」而不是调用生成函数。
 *
 * 适用场景：一个脚本里有**多个**运行期占位符，且 JS 对每个占位符的变换各不相同
 * （布尔→`$true/$false`、JSON→序列化+单引号转义…）。此时用哨兵调用会同时破坏
 * 多处语义，改为把模板连同 `\${X_PLACEHOLDER}` 原样搬出，Rust 侧按 JS 的同口径
 * 逐项替换——替换规则少且可见，且可被「同输入双生成对拍」验证（见 tools/check-ps-substitution.mjs）。
 *
 * 模板里的**真实插值**（`${DIAG.PS_PREAMBLE}` 这类，非占位符）必须在此求值：
 * 由 `deps` 登记「插值根标识符 → 模块路径」，模块 exports 即为该值。
 */
export function loadTemplate(tpl, requireFn, readFileFn) {
  const { file, varName, deps = {} } = tpl;
  const text = readFileFn(file, 'utf8');
  const marker = `${varName} = \``;
  const start = text.indexOf(marker);
  if (start < 0) throw new Error(`${file} 未找到 ${varName}`);
  const bodyStart = start + marker.length;
  const end = text.indexOf('`', bodyStart);
  if (end < 0) throw new Error(`${varName} 模板字面量未闭合`);
  const src = text.slice(bodyStart, end);
  // 收集真实插值（跳过 \${X_PLACEHOLDER} 这类占位符）
  const roots = new Set();
  for (const m of src.matchAll(/\$\{([A-Za-z_$][\w$]*)/g)) {
    const root = m[1];
    if (root.endsWith('_PLACEHOLDER') || root === '__trimPlaceholder__') continue;
    roots.add(root);
  }
  const names = [];
  const values = [];
  for (const r of roots) {
    const dep = deps[r];
    if (!dep) throw new Error(`${varName} 模板引用了未登记的插值 ${r}（请在 deps 中给出模块路径）`);
    names.push(r);
    // 两种用法都要支持：
    //   · `${PROTECT.PROTECT_PATH_PS}` —— 值是**整个模块**（供 X.Y 取属性）
    //   · `${RULE_PATH_EVAL_PS}`       —— 值是**模块的同名字符串导出**
    //     （等价 JS 的 `const { RULE_PATH_EVAL_PS } = require(...)` 解构）。
    // 同名导出优先，且仅认字符串——否则整体交模块（避免误把模块对象当插值值，
    // 那会把 `[object Object]` 当脚本正文写进 .ps1：本条注释即该缺陷的修复记录）。
    const m = requireFn(dep);
    const sameName = m && typeof m === 'object' && typeof m[r] === 'string' ? m[r] : null;
    values.push(sameName !== null ? sameName : m);
  }
  // eslint-disable-next-line no-new-func
  return new Function(...names, 'return `' + src + '`')(...values);
}

/** 生成带来源标记的 .ps1 全文 */
export function withProvenance(entry, body) {
  // 源坐标一律走 relSource()：绝对路径不得进跟踪文件（审查 M22）
  const argsText = (entry.args || [])
    .map((a) => (entry.sentinelPath && a === entry.sentinelPath ? JSON.stringify(INSTALLER_PATH_TOKEN) : JSON.stringify(a)))
    .join(', ');
  const source = entry.inline
    ? `${relSource(entry.inline.file)} → 常量 ${entry.inline.varName}（内联模板字面量）`
    : entry.template
      ? `${relSource(entry.template.file)} → 常量 ${entry.template.varName}（模板模式：占位符保留，运行前由 Rust 同口径替换）`
      : entry.const
      ? `${relSource(entry.js)} → 常量 ${entry.const}`
      : `${relSource(entry.js)} → ${entry.call}(${argsText})`;
  const header = [
    PROVENANCE_BEGIN,
    `# 来源：${source}`,
    `# 生成：tools/sync-ps-from-js.mjs 直接取 JS **运行时字符串值**写入，无任何字符替换；`,
    `#       改动本文件必须在源仓库改 JS 后重跑生成器（校验见 tools/check-ps-extraction.mjs）。`,
    ...(entry.note ? [`# 说明：${entry.note}`] : []),
    PROVENANCE_END,
  ].join('\n');
  return `${header}\n${body}`;
}

/** 剥离来源标记块，返回正文（供门禁比对） */
export function stripProvenance(text) {
  const idx = text.indexOf(PROVENANCE_END);
  if (idx < 0) return { body: text, provenance: null };
  return { body: text.slice(idx + PROVENANCE_END.length), provenance: text.slice(0, idx + PROVENANCE_END.length) };
}
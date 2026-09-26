// check-system-bin.mjs —— 系统工具裸进程名门禁（审查 v2-F7）
//
// 为什么判红：`Command::new("reg.exe")` 落到 `CreateProcessW(lpApplicationName = NULL)`，
// 搜索顺序是「**调用方 exe 所在目录** → **父进程 CWD** → System32」——前两位优先于
// System32。便携版放在用户可写目录时，同目录植入同名 exe 即被优先加载；提权实例的
// 工作目录又被设为 `exe.parent()`（elevate.rs），等于把第一与第二搜索位都送给那个目录。
//
// 修法是让这些调用点统一走 `engine::systembin::system_tool()`（解析到 System32）。
// 本门禁保证**之后**不会再有人抄回裸名 —— 只靠 code review 记不住这条。
//
// 断言：
//   A. 生产代码里 `Command::new(<字符串字面量>)` 必须经 `system_tool(...)` 包裹，
//      或在 `ALLOW_BARE` 里逐条登记理由（可选工具 / 非系统目录程序）。
//   B. 白名单外的名字若被 `system_tool` 包裹，必须是 `systembin::PINNED` 里的
//      （防止把用户安装包路径也送去 System32 解析，那是另一种错）。
//   C. 两跳别名（审查 v3-M1）：`Command::new(<变量>)` 这种变量形态旧版按设计跳过，
//      而真实违规（netfx35 的 dism.exe）恰恰藏在「字面量 → 元组解构 → 变量 spawn」
//      的第二跳里。现在要求：spawn 表达式自带 system_tool → 通过；绑定 RHS 是
//      PINNED 字面量且未解析 → 判红；既非字面量也非解析（参数/复杂表达式）→
//      必须在 SITE_EXEMPT 逐条登记理由，漏登记即红（fail-loud 注册制）。
//
// 用法：node tools/check-system-bin.mjs

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

const SRC = join(REPO_ROOT, 'src-tauri', 'src');

/**
 * 允许裸名的例外，逐条写明理由。
 * 判据：该程序**不随 Windows 分发**，硬解析到 System32 只会把它弄坏。
 */
const ALLOW_BARE = {
  git: '可选工具，位置由用户环境决定（cleanup.rs 规则库拉取）；随系统分发的工具不在此列',
};

/** 与 `engine/systembin.rs` 的 PINNED 保持一致（顺序无关） */
const PINNED = [
  'cmd.exe', 'dism.exe', 'explorer.exe', 'ipconfig.exe', 'lodctr.exe',
  'netsh.exe', 'netsh', 'powercfg.exe', 'powershell.exe', 'reg.exe', 'reg',
  'sc.exe', 'sc', 'schtasks.exe', 'schtasks', 'sfc.exe', 'tasklist.exe',
  'where.exe', 'wsreset.exe',
];

function walk(dir, out = []) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith('.rs')) out.push(p);
  }
  return out;
}

const files = walk(SRC);

/**
 * 命中：`Command::new(` 之后（允许跨行空白）紧跟的实参。
 * 审查 F3：旧实现按单行正则匹配，`Command::new(\n  "reg.exe",\n)` 这种跨行字面量
 * 会整段漏检（裸名静默绕过门禁）。改为全文扫描：定位每个 `Command::new(`，
 * 跳过空白/换行后再判实参形态；行号由偏移量反推。
 */
const CMD_NEW = 'Command::new(';

/** @type {{file:string,line:number,raw:string,name:string|null,wrapped:boolean,ident:string|null}[]} */
const hits = [];
/** 文件全文缓存（断言 C 的绑定扫描用） */
const fileTexts = new Map();
for (const f of files) {
  const text = readFileSync(f, 'utf8');
  fileTexts.set(relative(REPO_ROOT, f).replace(/\\/g, '/'), text);
  // 每行起始偏移，用于反推行号与「行首是否注释」
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\n') starts.push(i + 1);
  }
  const lineOf = (off) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= off) lo = mid; else hi = mid - 1;
    }
    return lo;
  };
  let idx = text.indexOf(CMD_NEW);
  while (idx >= 0) {
    const ln = lineOf(idx);
    const lineStart = starts[ln];
    const lineEnd = text.indexOf('\n', lineStart);
    const lineText = text.slice(lineStart, lineEnd < 0 ? undefined : lineEnd);
    // 注释里出现 `Command::new("reg.exe")` 是在讲原理（systembin.rs 的模块头就是这么写的），
    // 不是调用点 —— 不排除会把文档示例判成违规。
    if (!lineText.trimStart().startsWith('//')) {
      // 跳过空白与换行后取实参（跨行实参由此覆盖）
      let p = idx + CMD_NEW.length;
      while (p < text.length && /\s/.test(text[p])) p++;
      const rest = text.slice(p);
      const lit = rest.match(/^"((?:[^"\\]|\\.)*)"/);
      const wrapped = /^system_tool\(/.test(rest) || /^crate::engine::systembin::system_tool\(/.test(rest);
      // 变量参数（`Command::new(program)` / `(&exe)`）：捕获标识符，交由断言 C 做两跳别名判定
      let ident = null;
      if (!lit && !wrapped) {
        const idm = rest.match(/^&?\s*(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)/);
        if (idm) ident = idm[1];
      }
      if (lit || wrapped || ident) {
        hits.push({
          file: relative(REPO_ROOT, f).replace(/\\/g, '/'),
          line: ln + 1,
          raw: lineText.trim(),
          name: lit ? lit[1] : null,
          wrapped,
          ident,
        });
      }
    }
    idx = text.indexOf(CMD_NEW, idx + CMD_NEW.length);
  }
}

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== 系统工具裸进程名门禁 ===\n');

// ---- A. 字面量必须经 system_tool 包裹或登记豁免 ----
const bare = hits.filter((h) => !h.wrapped && h.name !== null && !ALLOW_BARE[h.name]);
const staleAllow = Object.keys(ALLOW_BARE).filter((n) => !hits.some((h) => h.name === n));
check(
  bare.length === 0 && staleAllow.length === 0,
  `A. ${hits.length} 个 Command::new 调用点均走绝对路径或已登记豁免`,
  bare.length
    ? `裸进程名 ${JSON.stringify(bare.map((h) => `${h.file}:${h.line} ${h.name}`))}`
    : staleAllow.length
      ? `豁免清单已失效（无对应调用点）${JSON.stringify(staleAllow)}`
      : '',
);

// ---- B. system_tool 只用于 PINNED 白名单 ----
const misPinned = hits.filter((h) => h.wrapped && h.name !== null && !PINNED.includes(h.name));
check(
  misPinned.length === 0,
  'B. system_tool 只用于随系统分发的工具（白名单内）',
  misPinned.length
    ? `不在白名单 ${JSON.stringify(misPinned.map((h) => `${h.file}:${h.line} ${h.name}`))}`
    : '',
);

// ---- C. 两跳别名：字面量 → 变量 → 裸 spawn（审查 v3-M1） ----
//
// 旧版对变量形态整类跳过，而真实违规（netfx35 的 dism.exe）正是
// `("dism.exe", …)` 解构进 `program` 后再 `Command::new(program)` 的第二跳。
// 判定顺序：
//   1) spawn 表达式自带 system_tool( → 已归入 wrapped，不进本断言；
//   2) 同文件存在 `let <id> =`（含元组解构）绑定：RHS 含 system_tool( → 通过；
//      RHS 含 PINNED 精确字面量且未解析 → 判红；
//   3) 绑定不可静态收敛（函数参数 / 复杂表达式）→ 必须在 SITE_EXEMPT 登记
//      file:line 与理由，漏登记即红 —— 注册制保证每个盲区都被「有意识放过」。
const SITE_EXEMPT = {
  'src-tauri/src/commands/quickcmds.rs:267': '用户自定义快捷指令令牌（spawn_detached 参数），来源为用户配置且已过滤元字符，静态无法收敛到固定程序名',
  'src-tauri/src/engine/native.rs:1184': 'p 来自注册表 Run 键回读的绝对路径列表（:1167 构造），非 PINNED 裸名',
  'src-tauri/src/engine/native.rs:1190': 'fp 由 SystemRoot 拼接的 explorer.exe 绝对路径兜底，非裸名',
  'src-tauri/src/pwsh/mod.rs:307': 'is_pwsh7_executable 的探测候选（绝对路径 &Path）',
  'src-tauri/src/pwsh/mod.rs:475': 'exe 参数（resolve_pwsh()/system_tool 解析出的绝对路径，v3-K1 重构后 run_with_exe）',
};

/** 绑定扫描：返回 ident 的绑定判定 'resolved' | 'literal-unwrapped' | 'unknown' */
function resolveBinding(file, ident) {
  const text = fileTexts.get(file);
  if (!text) return 'unknown';
  let verdict = 'unknown';
  const letRe = /\blet\b([^=;]{0,160}?)=/g;
  let m;
  while ((m = letRe.exec(text)) !== null) {
    const pattern = m[1];
    if (!new RegExp(`\\b${ident}\\b`).test(pattern)) continue;
    const rhs = text.slice(m.index + m[0].length, text.indexOf(';', m.index + m[0].length));
    if (/system_tool\(/.test(rhs)) return 'resolved';
    if (PINNED.some((p) => rhs.includes(`"${p}"`))) verdict = 'literal-unwrapped';
  }
  return verdict;
}

const identSites = hits.filter((h) => !h.wrapped && h.ident);
const cFailures = [];
for (const h of identSites) {
  const key = `${h.file}:${h.line}`;
  const verdict = resolveBinding(h.file, h.ident);
  if (verdict === 'literal-unwrapped') {
    cFailures.push(`${key} 绑定到 PINNED 字面量且未经 system_tool 解析（ident=${h.ident}）`);
  } else if (verdict === 'unknown' && !SITE_EXEMPT[key]) {
    cFailures.push(`${key} 变量形态无法静态收敛（ident=${h.ident}），必须在 SITE_EXEMPT 登记理由`);
  }
}
const staleSites = Object.keys(SITE_EXEMPT).filter(
  (k) => !identSites.some((h) => `${h.file}:${h.line}` === k),
);
check(
  cFailures.length === 0 && staleSites.length === 0,
  `C. ${identSites.length} 个变量形态调用点均解析或已登记（两跳别名闭合）`,
  cFailures.length
    ? cFailures.join('；')
    : staleSites.length
      ? `SITE_EXEMPT 已失效（无对应调用点）${JSON.stringify(staleSites)}`
      : '',
);

console.log('\n调用点分布：' + hits.map((h) => `${h.name ?? h.ident ?? '变量'}${h.wrapped ? '(已解析)' : ''}`).length + ' 处');
const wrappedCount = hits.filter((h) => h.wrapped).length;
console.log(`  已走 system_tool: ${wrappedCount} ／ 登记豁免: ${hits.length - wrappedCount}`);

console.log('');
if (fail > 0) {
  console.error(`门禁失败：${fail} 组断言未通过`);
  process.exit(1);
}
console.log('系统工具门禁全部通过');

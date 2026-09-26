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
  'netsh.exe', 'netsh', 'powercfg.exe', 'reg.exe', 'reg', 'sc.exe', 'sc',
  'schtasks.exe', 'schtasks', 'sfc.exe', 'tasklist.exe', 'where.exe', 'wsreset.exe',
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
/** 命中：`Command::new(` 之后紧跟的参数（取到本行末的括号平衡片段，够用） */
const re = /Command::new\(\s*&?([A-Za-z_][\w:]*)?\(?\s*("(?:[^"\\]|\\.)*")?/g;

/** @type {{file:string,line:number,raw:string,name:string|null,wrapped:boolean}[]} */
const hits = [];
for (const f of files) {
  const text = readFileSync(f, 'utf8');
  const lines = text.split('\n');
  lines.forEach((line, i) => {
    if (!line.includes('Command::new(')) return;
    // 注释里出现 `Command::new("reg.exe")` 是在讲原理（systembin.rs 的模块头就是这么写的），
    // 不是调用点 —— 不排除会把文档示例判成违规。
    if (line.trimStart().startsWith('//')) return;
    const idx = line.indexOf('Command::new(');
    const after = line.slice(idx + 'Command::new('.length).trim();
    // 变量参数（`Command::new(program)` / `(&exe)`）：静态判不了，跳过
    const lit = after.match(/^"((?:[^"\\]|\\.)*)"/);
    const wrapped = /^system_tool\(/.test(after) || /^crate::engine::systembin::system_tool\(/.test(after);
    if (!lit && !wrapped) return; // 变量，交由 code review
    hits.push({
      file: relative(REPO_ROOT, f).replace(/\\/g, '/'),
      line: i + 1,
      raw: line.trim(),
      name: lit ? lit[1] : null,
      wrapped,
    });
  });
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

console.log('\n调用点分布：' + hits.map((h) => `${h.name ?? '变量'}${h.wrapped ? '(已解析)' : ''}`).length + ' 处');
const wrappedCount = hits.filter((h) => h.wrapped).length;
console.log(`  已走 system_tool: ${wrappedCount} ／ 登记豁免: ${hits.length - wrappedCount}`);

console.log('');
if (fail > 0) {
  console.error(`门禁失败：${fail} 组断言未通过`);
  process.exit(1);
}
console.log('系统工具门禁全部通过');

// check-system-bin.mjs —— 系统工具裸进程名门禁（审查 v2-F7；v0.1.6 静默收敛扩展）
//
// 为什么判红：`Command::new("reg.exe")` 落到 `CreateProcessW(lpApplicationName = NULL)`，
// 搜索顺序是「**调用方 exe 所在目录** → **父进程 CWD** → System32」——前两位优先于
// System32。便携版放在用户可写目录时，同目录植入同名 exe 即被优先加载；提权实例的
// 工作目录又被设为 `exe.parent()`（elevate.rs），等于把第一与第二搜索位都送给那个目录。
//
// v0.1.6 真机反馈新增第二道约束：GUI 进程拉起控制台程序（schtasks/reg/sc/cmd）若不
// 带 CREATE_NO_WINDOW 会弹出可见 cmd 窗。因此后台 spawn 统一收敛到
// `engine::systembin::quiet_cmd()`（内部 = 直接构造 + CREATE_NO_WINDOW；调用方先把
// 程序名过 system_tool 解析）：
//   A. `quiet_cmd(<字符串字面量>)` 必须登记 ALLOW_BARE（可选工具）。
//      `quiet_cmd(system_tool("x"))` 是标准形态，B 断言管白名单。
//   C. `quiet_cmd(<变量>)` 两跳别名：绑定到 PINNED 字面量且未解析 → 红；
//      不可静态收敛 → SITE_EXEMPT 登记制。
//   D. 裸 `Command::new(` 在生产代码默认违规，必须登记 RAW_EXEMPT
//      （自带非默认 creation flags 的合法场景：pwsh 执行层、quickcmds 可见控制台）。
//
// 用法：node tools/check-system-bin.mjs

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

const SRC = join(REPO_ROOT, 'src-tauri', 'src');

/**
 * 允许 `quiet_cmd(<裸名字面量>)` 的例外，逐条写明理由。
 * 判据：该程序**不随 Windows 分发**，硬解析到 System32 只会把它弄坏。
 */
const ALLOW_BARE = {
  git: '可选工具，位置由用户环境决定（cleanup.rs 规则库拉取）；随系统分发的工具不在此列',
};

/** 与 `engine/systembin.rs` 的 PINNED 保持一致（顺序无关） */
const PINNED = [
  'cmd.exe', 'dism.exe', 'explorer.exe', 'fltmc.exe', 'ipconfig.exe', 'lodctr.exe',
  'netsh.exe', 'netsh', 'powercfg.exe', 'powershell.exe', 'reg.exe', 'reg',
  'sc.exe', 'sc', 'schtasks.exe', 'schtasks', 'sfc.exe', 'tasklist.exe',
  'where.exe', 'wsreset.exe',
];

/**
 * 允许裸 `Command::new(` 的场景（v0.1.6 静默收敛）：只放行**自带非默认 creation
 * flags** 的合法产品功能。
 *
 * V2 P1-C2（2026-09-30）：登记键从 `file:行号` 改成 `file + anchor`（调用点那一行的
 * 判别性子串）。原因：AGENTS §5.19 记了两次「在被豁免调用点上方增删一行 ⇒ 行号错位、
 * 豁免指到别处或失效」，而本门禁此前是"看行号"而不是"看内容"。锚点式登记让豁免跟着
 * 代码走；同时**不做模糊匹配**：锚点在文件里匹配到 0 处判红（失效）、匹配到 2 处以上
 * 也判红（歧义，必须加长锚文本），所以既不会被增删行蒙掉，也不会被改名悄悄绕过。
 */
const RAW_EXEMPT = [
  {
    file: 'src-tauri/src/pwsh/mod.rs',
    anchor: 'let mut child = Command::new(exe)',
    reason: 'run_with_exe：收件箱 PowerShell 5.1 执行层（自带 CREATE_NO_WINDOW flags + Job Object）',
  },
  {
    file: 'src-tauri/src/commands/quickcmds.rs',
    anchor: 'Command::new(exe)',
    reason: '用户自定义快捷指令的可见控制台（CREATE_NEW_CONSOLE 是产品功能，禁静默）',
  },
  {
    file: 'src-tauri/src/engine/systembin.rs',
    anchor: 'std::process::Command::new(program)',
    reason: 'quiet_cmd 自身的实现体',
  },
  {
    file: 'src-tauri/src/engine/native/cleanup.rs',
    anchor: 'Command::new("cmd")',
    reason: '2026-10-04 审计 §4.5 测试夹具：mklink /J 造 junction 验证备份裁剪包含性核验（cfg(test) 专用，native-scanner/tests 同款；junction 无稳定 Rust API，symlink_dir 需特权）',
  },
];

/**
 * 变量形态豁免（anchor 式登记，理由同上）：绑定无法静态收敛的 quiet_cmd 调用。
 * 目标是保持最小集；新增豁免必须写明为什么不违反 systembin 口径。
 */
const SITE_EXEMPT = [
  {
    file: 'src-tauri/src/engine/systembin.rs',
    anchor: 'pub fn quiet_cmd(program: impl AsRef',
    reason: 'quiet_cmd 函数定义本身（token 命中函数名，非调用点）',
  },
  {
    file: 'src-tauri/src/engine/systembin.rs',
    anchor: 'let mut child = quiet_cmd(program)',
    reason: 'quiet_cmd_timeout（v2-L4P-29）函数体内的透传：program 由调用方经 system_tool 或已登记豁免解析，本函数只补超时收口',
  },
  {
    file: 'src-tauri/src/engine/native/contextmenu.rs',
    anchor: 'quiet_cmd(p).spawn()',
    reason: 'p 来自注册表 Run 键回读的绝对路径列表，非 PINNED 裸名',
  },
  {
    file: 'src-tauri/src/engine/native/contextmenu.rs',
    anchor: 'quiet_cmd(&fp).spawn()',
    reason: 'fp 由 SystemRoot 拼接的 explorer.exe 绝对路径兜底，非裸名',
  },
];

/**
 * 按锚点解析一条登记项 → 它覆盖的调用点。
 * 返回 `{ ok, hits, why }`：0 命中 = 登记已失效；>1 命中 = 锚文本不够判别。
 */
function resolveExemption(entry, pool) {
  const matched = pool.filter((h) => h.file === entry.file && h.raw.includes(entry.anchor));
  if (matched.length === 0) {
    return {
      ok: false,
      hits: [],
      why: `${entry.file}#${entry.anchor.slice(0, 40)} 找不到对应调用点（登记失效：代码改名/删调用点后必须同步本表）`,
    };
  }
  if (matched.length > 1) {
    return {
      ok: false,
      hits: matched,
      why: `${entry.file}#${entry.anchor.slice(0, 40)} 匹配到 ${matched.length} 处调用点（锚文本不判别，请加长到唯一）`,
    };
  }
  return { ok: true, hits: matched, why: '' };
}

function walk(dir, out = []) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith('.rs')) out.push(p);
  }
  return out;
}

const files = walk(SRC);

/** 文件全文缓存（断言 C 的绑定扫描用） */
const fileTexts = new Map();

/**
 * 命中：spawn token 之后（允许跨行空白）紧跟的实参。
 * 全文扫描：定位每个 token，跳过空白/换行后再判实参形态；行号由偏移量反推。
 * 注释里出现的是在讲原理，不是调用点。
 */
const CALL_TOKENS = ['quiet_cmd(', 'Command::new('];

/** @type {{file:string,line:number,raw:string,name:string|null,wrapped:boolean,ident:string|null,kind:string}[]} */
const hits = [];
for (const f of files) {
  const text = readFileSync(f, 'utf8');
  fileTexts.set(relative(REPO_ROOT, f).replace(/\\/g, '/'), text);
  // 每行起始偏移，用于反推行号
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
  for (const token of CALL_TOKENS) {
    let idx = text.indexOf(token);
    while (idx >= 0) {
      const ln = lineOf(idx);
      const lineStart = starts[ln];
      const lineEnd = text.indexOf('\n', lineStart);
      const lineText = text.slice(lineStart, lineEnd < 0 ? undefined : lineEnd);
      if (!lineText.trimStart().startsWith('//')) {
        // 跳过空白与换行后取实参（跨行实参由此覆盖）
        let p = idx + token.length;
        while (p < text.length && /\s/.test(text[p])) p++;
        const rest = text.slice(p);
        const lit = rest.match(/^"((?:[^"\\]|\\.)*)"/);
        const wrapped = /^system_tool\(/.test(rest) || /^crate::engine::systembin::system_tool\(/.test(rest);
        // 变量实参：捕获标识符（剥掉 & 与空白），交由断言 C 做两跳别名判定
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
            kind: token,
          });
        }
      }
      idx = text.indexOf(token, idx + token.length);
    }
  }
}

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== 系统工具裸进程名门禁 ===\n');

const quiet = hits.filter((h) => h.kind === 'quiet_cmd(');
const raw = hits.filter((h) => h.kind === 'Command::new(');

// ---- A. 字面量必须经 system_tool 包裹或登记豁免 ----
const bare = quiet.filter((h) => !h.wrapped && h.name !== null && !ALLOW_BARE[h.name]);
const staleAllow = Object.keys(ALLOW_BARE).filter((n) => !quiet.some((h) => h.name === n));
check(
  bare.length === 0 && staleAllow.length === 0,
  `A. ${quiet.length} 个 quiet_cmd 调用点均走绝对路径或已登记豁免`,
  bare.length
    ? `裸进程名 ${JSON.stringify(bare.map((h) => `${h.file}:${h.line} ${h.name}`))}`
    : staleAllow.length
      ? `豁免清单已失效（无对应调用点）${JSON.stringify(staleAllow)}`
      : '',
);

// ---- B. system_tool 只用于 PINNED 白名单 ----
const misPinned = quiet.filter((h) => h.wrapped && h.name !== null && !PINNED.includes(h.name));
check(
  misPinned.length === 0,
  'B. system_tool 只用于随系统分发的工具（白名单内）',
  misPinned.length
    ? `不在白名单 ${JSON.stringify(misPinned.map((h) => `${h.file}:${h.line} ${h.name}`))}`
    : '',
);

// ---- C. 两跳别名：字面量 → 变量 → spawn（审查 v3-M1） ----
//
// 判定顺序：
//   1) spawn 表达式自带 system_tool( → 已归入 wrapped，不进本断言；
//   2) 同文件存在 `let <id> =`（含元组解构）绑定：RHS 含 system_tool( → 通过；
//      RHS 含 PINNED 精确字面量且未解析 → 判红；
//   3) 绑定不可静态收敛（函数参数 / 复杂表达式）→ 必须在 SITE_EXEMPT 登记
//      file:line 与理由，漏登记即红 —— 注册制保证每个盲区都被「有意识放过」。

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

const identSites = quiet.filter((h) => !h.wrapped && h.ident);
// 先把锚点解析成"覆盖了哪个调用点"，再做双向核对：
//   登记侧失效/歧义 → 红；调用点侧没被任何登记覆盖 → 红
const siteResolutions = SITE_EXEMPT.map((e) => ({ entry: e, ...resolveExemption(e, identSites) }));
const siteCovered = new Set(
  siteResolutions.filter((r) => r.ok).flatMap((r) => r.hits.map((h) => `${h.file}:${h.line}`)),
);
const cFailures = [];
for (const h of identSites) {
  const key = `${h.file}:${h.line}`;
  const verdict = resolveBinding(h.file, h.ident);
  if (verdict === 'literal-unwrapped') {
    cFailures.push(`${key} 绑定到 PINNED 字面量且未经 system_tool 解析（ident=${h.ident}）`);
  } else if (verdict === 'unknown' && !siteCovered.has(key)) {
    cFailures.push(`${key} 变量形态无法静态收敛（ident=${h.ident}），必须在 SITE_EXEMPT 用唯一锚文本登记理由`);
  }
}
const siteBroken = siteResolutions.filter((r) => !r.ok);
check(
  cFailures.length === 0 && siteBroken.length === 0,
  `C. ${identSites.length} 个变量形态调用点均解析或已按锚点登记（两跳别名闭合）`,
  // 先看登记侧是否坏掉（失效/歧义），再看调用侧未覆盖 —— 后者往往是前者的症状，
  // 报"你没登记"会让人去补一条本来就在表里的登记
  siteBroken.length
    ? siteBroken.map((r) => r.why).join('；')
    : cFailures.join('；'),
);

// ---- D. 裸 Command::new 必须按锚点登记（v0.1.6 静默收敛） ----
const rawResolutions = RAW_EXEMPT.map((e) => ({ entry: e, ...resolveExemption(e, raw) }));
const rawCovered = new Set(
  rawResolutions.filter((r) => r.ok).flatMap((r) => r.hits.map((h) => `${h.file}:${h.line}`)),
);
const rawViolations = raw.filter((h) => !rawCovered.has(`${h.file}:${h.line}`));
const rawBroken = rawResolutions.filter((r) => !r.ok);
check(
  rawViolations.length === 0 && rawBroken.length === 0,
  `D. ${raw.length} 处裸 Command::new 均已按锚点登记（后台 spawn 必须走 quiet_cmd）`,
  // 登记侧坏掉（失效/歧义）优先报：它通常是"某处调用点没被覆盖"的根因
  rawBroken.length
    ? rawBroken.map((r) => r.why).join('；')
    : `未登记 ${JSON.stringify(rawViolations.map((h) => `${h.file}:${h.line} ${h.raw.slice(0, 60)}`))}`,
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

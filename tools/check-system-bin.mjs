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

import { readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';
import { walkRs } from './lib/fs-walk.mjs';
import { gate } from './lib/gate.mjs';

const SRC = join(REPO_ROOT, 'src-tauri', 'src');

/**
 * 允许 `quiet_cmd(<裸名字面量>)` 的例外，逐条写明理由。
 * 判据：该程序**不随 Windows 分发**，硬解析到 System32 只会把它弄坏。
 */
const ALLOW_BARE = {
};

/** 与 `engine/systembin.rs` 的 PINNED 保持一致（顺序无关） */
const PINNED = [
  'appwiz.cpl', 'bcdedit.exe', 'calc.exe', 'charmap.exe', 'cleanmgr.exe', 'cmd.exe',
  'compmgmt.msc', 'control.exe', 'desk.cpl', 'devmgmt.msc', 'dfrgui.exe', 'dism.exe',
  'diskmgmt.msc', 'dxdiag.exe', 'eventvwr.msc', 'explorer.exe', 'fltmc.exe',
  'intl.cpl', 'ipconfig.exe', 'lodctr.exe', 'main.cpl', 'mmsys.cpl', 'msconfig.exe',
  'msiexec.exe', 'msinfo32.exe', 'mspaint.exe', 'msra.exe', 'mstsc.exe', 'narrator.exe', 'ncpa.cpl',
  'netsh.exe', 'netsh', 'notepad.exe', 'optionalfeatures.exe', 'osk.exe', 'perfmon.exe',
  'perfmon.msc', 'powercfg.exe', 'powercfg.cpl', 'powershell.exe', 'psr.exe', 'reg.exe',
  'reg', 'regedit.exe', 'resmon.exe', 'rstrui.exe', 'rundll32.exe', 'sc.exe', 'sc',
  'schtasks.exe', 'schtasks', 'sdclt.exe', 'services.msc', 'sfc.exe', 'snippingtool.exe',
  'sysdm.cpl', 'tasklist.exe', 'taskmgr.exe', 'taskschd.msc', 'timedate.cpl', 'typeperf.exe',
  'utilman.exe', 'where.exe', 'wf.msc', 'winmgmt.exe', 'winver.exe', 'wscui.cpl', 'wsreset.exe',
];

/**
 * v6-K01（P0-2）生产实参地板：生产代码实际传入 system_tool 的关键名单（与
 * systembin.rs 的 `pinned_covers_production_callers` 单测同名单、互为两道防线——
 * Rust 运行时 + Node 静态）。任何一个从 PINNED 掉表（人为删项/整理漏项）即红。
 */
const PRODUCTION_PINNED_FLOOR = [
  'cmd.exe',        // optimizer/apply.rs（quiet_cmd_timeout_raw）
  'bcdedit.exe',    // optimizer/bcd.rs
  'dism.exe',       // cleanup.rs / runtimes_net.rs / maintenance.rs
  'powershell.exe', // pwsh 执行层唯一入口
  'reg.exe',        // cleanup/peripheral/startup/process/residue
  'regedit.exe',    // systembin::open_regedit_at
  'explorer.exe',   // systembin::shell_select_in_explorer + contextmenu 重启臂（v6-K03）
  'schtasks.exe',   // maintenance/startup/process/misc
  'netsh.exe',      // runtimes_net
  'tasklist.exe',   // misc
  'fltmc.exe',      // minifilter_orphan
  'powercfg.exe',   // syspanel
  'msiexec.exe',    // uninstall/list_run.rs（卸载执行面的裸名准入解析）
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
    anchor: 'Command::new(program)',
    reason: '快捷指令的可见控制台（CREATE_NEW_CONSOLE 是产品功能，禁静默）；program 已由 system_tool 解析，非裸名',
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
  {
    file: 'src-tauri/src/commands/fileclean.rs',
    anchor: 'std::process::Command::new("cmd")',
    reason: '2026-10-14 P2-E §5.3 第三条的真机 #[ignore] 探针：mklink /J 造 junction（与上面 cleanup.rs 夹具同口径，cfg(test) 专用、非生产执行面；junction 无稳定 Rust API，symlink_dir 需特权）',
  },
  {
    file: 'src-tauri/src/commands/elevate.rs',
    anchor: 'std::process::Command::new("cmd")',
    reason: '提权交接 #[ignore] 真机探针：ping 起一个有寿命的真实子进程，用来证明 wait_predecessor_exit 真的等（cfg(test) 专用、非生产执行面）',
  },
  {
    file: 'src-tauri/src/commands/uninstall/residue_trace_tests.rs',
    anchor: 'let st = Command::new("cmd")',
    reason: 'J12（2026-10-16）双向咬合用例：mklink /J 造（活/断）junction 验证「断链放行、活链仍拒」（cfg(test) 专用、非生产执行面；junction 无稳定 Rust API，symlink_dir 需特权）',
  },
  {
    file: 'src-tauri/src/engine/protect.rs',
    anchor: 'let ok = std::process::Command::new("cmd")',
    reason: 'Kudu S2（5073673）别名解析真机用例①：mklink /J 造指向受保护子树的 junction，验证解析后命中保护（cfg(test) 专用、非生产执行面；与 cleanup.rs/fileclean.rs 夹具同口径，P0-B 全量跑时补登记）',
  },
  {
    file: 'src-tauri/src/engine/protect.rs',
    anchor: 'let ok2 = std::process::Command::new("cmd")',
    reason: '同上用例③对照组：mklink /J 造指向普通目录的 junction，验证不得误判受保护（锚点带 ok2 前缀与上一条区分，避免 0/2 歧义判红）',
  },
  {
    file: 'src-tauri/src/commands/uninstall/pending_delete.rs',
    anchor: 'std::process::Command::new("cmd")',
    reason: 'v6-K05（P0-3）别名复检用例：mklink /J 造指向受保护子树（System32\\config）的 junction，验证 PFRO 登记闸的 final_path_protected 分支（cfg(test) 专用、非生产执行面；junction 无稳定 Rust API，symlink_dir 需特权）',
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
    anchor: 'spawn_and_wait_with_timeout(quiet_cmd(program).args(args), timeout)',
    reason: 'quiet_cmd_timeout（v2-L4P-29）函数体内的透传：program 由调用方经 system_tool 或已登记豁免解析，本函数只补超时收口',
  },
  {
    file: 'src-tauri/src/engine/systembin.rs',
    anchor: 'spawn_and_wait_with_timeout(quiet_cmd(program).raw_arg(raw_arg), timeout)',
    reason: 'quiet_cmd_timeout_raw（P3-5）：同 args 版的透传形态，raw_arg 逐字保留命令行走同一等待实现',
  },
  {
    file: 'src-tauri/src/engine/systembin.rs',
    anchor: 'pub fn quiet_cmd_timeout(',
    reason: 'quiet_cmd_timeout 函数定义本身（v6-K01 补 CALL_TOKENS 后 raw/args 版定义体被 token 命中，非调用点）',
  },
  {
    file: 'src-tauri/src/engine/systembin.rs',
    anchor: 'pub fn quiet_cmd_timeout_raw(',
    reason: 'quiet_cmd_timeout_raw 函数定义本身（同上，v6-K01 补 token 后被命中，非调用点）',
  },
  {
    file: 'src-tauri/src/engine/native/maintenance.rs',
    anchor: 'quiet_cmd_timeout(&wow',
    reason: 'P1-01 计数器链②：SysWOW64\\lodctr.exe 由 SystemRoot 拼接的绝对路径（32 位计数器重建需要 32 位 lodctr，system_tool 只在 System32/root 两目录找，第三目录不覆盖——绝对路径不经搜索顺序，非裸名）',
  },
  // v6-K03（P0-3）：contextmenu.rs 原两条登记（quiet_cmd(p).spawn() 按被杀进程
  // 自己的 image path 重启、quiet_cmd(&fp).spawn() SystemRoot 兜底）随重启臂重写
  // 一起消失——新调用点是 `if let Ok(exe) = system_tool("explorer.exe")` 后
  // quiet_cmd(&exe)，由 C 组两跳别名判定解析，无需登记。
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

const files = walkRs(SRC);

/** 文件全文缓存（断言 C 的绑定扫描用） */
const fileTexts = new Map();

/**
 * 命中：spawn token 之后（允许跨行空白）紧跟的实参。
 * 全文扫描：定位每个 token，跳过空白/换行后再判实参形态；行号由偏移量反推。
 * 注释里出现的是在讲原理，不是调用点。
 */
// v5 批次 9 门禁候选 1：CALL_TOKENS 补 `quiet_cmd_timeout(`——它是超时 spawn 的
// 实际入口（39 处调用点，check-ps-callsites 登记表同源），缺它则这批调用点的
// 实参形态完全失明（T1a 实测 39 处 0 对象）。
// v6-K01（P0-2）：补 `quiet_cmd_timeout_raw(`——apply.rs 的 cmd 步骤走 raw 版，
// 缺它则该调用点对 A/B 组失明（实为 K01 病灶之一）。
const CALL_TOKENS = ['quiet_cmd(', 'quiet_cmd_timeout(', 'quiet_cmd_timeout_raw(', 'Command::new('];

/**
 * 从一段 Rust 源码文本提取 spawn 实参命中（v6-K01 / P0-2 抽出）：
 * 主扫描（真实源码）与 H 组正向对照自检（合成样本）共用同一实现——
 * 判据真源唯一，改判定器时自检样本当场红，不再有「机检失明」的静默漂移。
 * 返回条目带行号（函数内自算，不依赖调用方环境）。
 */
function extractHitsFromText(text) {
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
  /** @type {{line:number,raw:string,name:string|null,wrapped:boolean,ident:string|null,kind:string,argHead:string}[]} */
  const out = [];
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
        // wrapped 判定覆盖三种调用前缀：全路径 / systembin 短前缀（bcd.rs 风格）/ 裸名
        const wrapped =
          /^system_tool\(/.test(rest)
          || /^crate::engine::systembin::system_tool\(/.test(rest)
          || /^systembin::system_tool\(/.test(rest);
        // 变量实参：捕获标识符（剥掉 & 与空白），交由断言 C 做两跳别名判定
        let ident = null;
        if (!lit && !wrapped) {
          const idm = rest.match(/^&?\s*(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)/);
          if (idm) ident = idm[1];
        }
        if (lit || wrapped || ident) {
          out.push({
            line: ln + 1,
            raw: lineText.trim(),
            name: lit ? lit[1] : null,
            wrapped,
            ident,
            kind: token,
            // G 组用：wrapped 实参的头部形态（截前 120 字符压平换行），路径形态检测用
            argHead: rest.slice(0, 120).replace(/\s+/g, ' '),
          });
        }
      }
      idx = text.indexOf(token, idx + token.length);
    }
  }
  return out;
}

/** @type {{file:string,line:number,raw:string,name:string|null,wrapped:boolean,ident:string|null,kind:string,argHead:string}[]} */
const hits = [];
for (const f of files) {
  const text = readFileSync(f, 'utf8');
  fileTexts.set(relative(REPO_ROOT, f).replace(/\\/g, '/'), text);
  for (const h of extractHitsFromText(text)) {
    hits.push({
      file: relative(REPO_ROOT, f).replace(/\\/g, '/'),
      ...h,
    });
  }
}

const g = gate(import.meta.url);
const check = (ok, label, detail = '') => {
  const line = `${label}${detail ? ' — ' + detail : ''}`;
  if (ok) g.ok(line); else g.fail(line);
};

console.log('=== 系统工具裸进程名门禁 ===\n');

// v6-K01（P0-2）：quiet 组从「仅 quiet_cmd(」扩到全部三个 spawn 入口——
// quiet_cmd_timeout / quiet_cmd_timeout_raw 与 quiet_cmd 是同一实参判定语义的三个
// 门面（超时版/raw 版只是等待与命令行形状差异），旧过滤让 39+ 处超时调用点对
// A/B 组失明（裸字面量与误塞实参都看不见），正是 K01 想堵的缝。
const quiet = hits.filter((h) => h.kind !== 'Command::new(');
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

/**
 * 闭包参数链判定（v6-K01 / P0-2 新增）：`system_tool("x").map_err(...).and_then(|exe| …exe…)`
 * 是拆 API 后的标准形态——exe 是闭包参数不是 let 绑定，resolveBinding 找不到；
 * 判据 = 该 ident 是某个 `.and_then(|ident|` 的参数，且链头上游 400 字符内含 system_tool(。
 */
function resolveClosureBinding(file, ident) {
  const text = fileTexts.get(file);
  if (!text) return false;
  const re = new RegExp(`\\.and_then\\(\\s*\\|&?\\s*${ident}\\b`);
  let m;
  while ((m = re.exec(text)) !== null) {
    const head = text.slice(Math.max(0, m.index - 400), m.index);
    if (/system_tool\(/.test(head)) return true;
  }
  return false;
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
  } else if (verdict === 'unknown' && !resolveClosureBinding(h.file, h.ident) && !siteCovered.has(key)) {
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

// ---- E. Rust PINNED ⇄ 本文件 PINNED 双向同步（本清单决定 B/C 组判据） ----
const systembinSrc = readFileSync(join(REPO_ROOT, 'src-tauri', 'src', 'engine', 'systembin.rs'), 'utf8');
const pinnedBlock = systembinSrc.match(/const PINNED: &\[&str\] = &\[([\s\S]*?)\n\];/);
const rustPinned = pinnedBlock
  ? [...pinnedBlock[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]).sort()
  : [];
const jsPinned = [...PINNED].sort();
const pinnedSame = rustPinned.length > 0 && JSON.stringify(rustPinned) === JSON.stringify(jsPinned);
check(
  pinnedSame,
  `E. Rust PINNED ⇄ 门禁 PINNED 双向同步（${rustPinned.length} / ${jsPinned.length}）`,
  pinnedSame
    ? ''
    : `Rust=[${rustPinned.join(', ')}] / 门禁=[${jsPinned.join(', ')}]`,
);

// ---- F. PINNED 生产实参地板（v6-K01 / P0-2） ----
// 「从 PINNED 删掉 cmd.exe 后 system_tool("cmd") 必须判红」的静态机械化之一：
// 生产在用的工具名从白名单掉表（删项/整理漏项）即红，不等运行时 Err 才暴露。
// 另一道防线在 systembin.rs 单测 pinned_covers_production_callers（Rust 运行时侧）。
const floorMissing = PRODUCTION_PINNED_FLOOR.filter((n) => !jsPinned.includes(n));
check(
  floorMissing.length === 0,
  `F. PINNED 生产实参地板（${PRODUCTION_PINNED_FLOOR.length} 个生产在用名全在表）`,
  floorMissing.length ? `掉表 ${JSON.stringify(floorMissing)}——恢复表项或同步调用方` : '',
);

// ---- G. system_tool 实参不得是路径形态（v6-K01 / P0-2） ----
// 「把合法安装包路径误塞系统工具入口也必须判红」的静态机械化：system_tool 的
// 辖域是 PINNED **工具名**；含盘符/UNC 的实参是外部工具，必须走 explicit_tool_path
// （旧实现原样返回侥幸可用，拆 API 后它直接 Err，运行时才暴露 → 这里前移到门禁）。
// raw 字符串 r"D:\..." 形态 lit 正则提不到 name，用 argHead 判路径特征。
const gOffenders = hits.filter((h) => {
  if (!h.wrapped) return false;
  // 抠出 system_tool( 的第一个实参字面量（含 r"..." raw 形态）
  const m = h.argHead.match(/^crate::engine::systembin::system_tool\(\s*(r?)"((?:[^"\\]|\\.)*)"/)
    ?? h.argHead.match(/^system_tool\(\s*(r?)"((?:[^"\\]|\\.)*)"/);
  if (!m) return false;
  const arg = m[2];
  // 盘符（X:\）或 UNC（\\开头）= 路径形态，不属于系统工具名
  return /^[A-Za-z]:[\\/]/.test(arg) || arg.startsWith('\\\\');
});
check(
  gOffenders.length === 0,
  `G. ${hits.filter((h) => h.wrapped).length} 个 system_tool 实参均无路径形态（安装包走 explicit_tool_path）`,
  gOffenders.length
    ? `路径形态实参 ${JSON.stringify(gOffenders.map((h) => `${h.file}:${h.line} ${h.argHead.slice(0, 60)}`))}`
    : '',
);

// ---- I. shell_run_wait 生产调用点必须消费准入函数的返回值（R2b-K01/M02，v7.2 C05） ----
// 卸载器路径必须先过 `admit_uninstaller_exec`（解析绝对路径 + 宿主/注入闸）再进
// ShellExecuteEx 咽喉。判据：生产段首个实参必须是 `&admitted` —— 字面量（重新产裸名）
// 与 `&exe`/`&original.0`（直接吃注册表原文）都判红。探针/负向样本在 `#[cfg(test)]`
// 段内，不参与生产判定。判定器抽成纯函数，与 I2 合成样本共用同一实现。
function shellWaitViolations(text) {
  const prod = text.split('#[cfg(test)]')[0];
  const out = [];
  for (const line of prod.split('\n')) {
    if (line.trimStart().startsWith('//')) continue;
    if (line.includes('fn shell_run_wait(')) continue; // 函数定义不是调用点
    const m = line.match(/shell_run_wait\(\s*([^,)]*)/);
    if (!m) continue;
    if (m[1].trim() !== '&admitted') out.push(line.trim());
  }
  return out;
}

const shellViolations = [];
for (const f of files) {
  const rel = relative(REPO_ROOT, f).replace(/\\/g, '/');
  for (const line of shellWaitViolations(readFileSync(f, 'utf8'))) {
    shellViolations.push(`${rel}: ${line.slice(0, 80)}`);
  }
}
check(
  shellViolations.length === 0,
  'I. shell_run_wait 生产调用点均消费准入函数返回值（首参 &admitted）',
  shellViolations.length ? JSON.stringify(shellViolations) : '',
);

const SHELL_SELF_SAMPLES = [
  { code: 'let w = unsafe { shell_run_wait("msiexec.exe", &args) };', expect: 'fail', why: '字面量绕过准入（K01 回归形态）' },
  { code: 'let w = unsafe { shell_run_wait(&exe, &args) };', expect: 'fail', why: '直接吃注册表原文变量（未过准入）' },
  { code: 'let w = unsafe { shell_run_wait(&admitted, &args) };', expect: 'ok', why: '准入函数返回值（标准形态）' },
  { code: '// 注释里提到 shell_run_wait("x") 不是调用点', expect: 'ok', why: '注释不参与判定' },
  { code: 'pub(super) unsafe fn shell_run_wait(exe: &str, args: &str)', expect: 'ok', why: '函数定义不是调用点' },
];
const shellSelfFailures = SHELL_SELF_SAMPLES.filter(
  (s) => (shellWaitViolations(s.code).length > 0) !== (s.expect === 'fail'),
);
check(
  shellSelfFailures.length === 0,
  `I2. shell_run_wait 判定器正向对照（${SHELL_SELF_SAMPLES.length} 个合成样本）`,
  shellSelfFailures.length ? shellSelfFailures.map((s) => s.why).join('；') : '',
);

// ---- H. 判定器正向对照自检（v6-K01 / P0-2，PENDING_CONTROLS 缺口收口） ----
// 合成样本走与主扫描同一 extractHitsFromText 实现 + A/G 组同源判据：
// 违规样本必须被判红、合规样本必须放行——判定器改动导致失明时这里当场红。
const SELF_SAMPLES = [
  {
    code: 'let out = quiet_cmd("schtasks");',
    expect: 'fail', why: '裸字面量直接 spawn（A 组违规形态）',
  },
  {
    code: 'let out = quiet_cmd_timeout_raw("schtasks", &raw, T);',
    expect: 'fail', why: 'raw 版裸字面量（CALL_TOKENS 补 token 前的盲区形态）',
  },
  {
    code: 'let out = quiet_cmd_timeout(system_tool(r"D:\\dl\\vc_redist.x64.exe"), &args, T);',
    expect: 'fail', why: '安装包路径误塞系统工具入口（G 组违规形态）',
  },
  {
    code: 'let out = quiet_cmd_timeout(system_tool("schtasks.exe"), &args, T);',
    expect: 'ok', why: '标准形态：PINNED 名经 system_tool 解析（放行）',
  },
  {
    code: 'let out = quiet_cmd_timeout(exe, &args, T);',
    expect: 'ok', why: '变量形态（ident 提取，交 C 组两跳别名判定——本样本自身不判红）',
  },
];
const selfFailures = [];
for (const s of SELF_SAMPLES) {
  const found = extractHitsFromText(s.code);
  if (found.length === 0) {
    selfFailures.push(`自检样本提取为空（token 未命中）: ${s.why}`);
    continue;
  }
  const h = found[0];
  if (s.expect === 'fail') {
    // 违规判定：裸字面量（非 wrapped、非豁免名单）或 wrapped 路径形态
    const isBareLit = h.name !== null && !h.wrapped;
    const isPathShaped = h.wrapped
      && (() => {
        const m = h.argHead.match(/^system_tool\(\s*(r?)"((?:[^"\\]|\\.)*)"/);
        if (!m) return false;
        return /^[A-Za-z]:[\\/]/.test(m[2]) || m[2].startsWith('\\\\');
      })();
    if (!isBareLit && !isPathShaped) {
      selfFailures.push(`违规样本未被判定为违规: ${s.why}（argHead=${h.argHead.slice(0, 60)}）`);
    }
  } else if (h.name !== null && !h.wrapped && !ALLOW_BARE[h.name]) {
    // 合规样本被误判红 = 判定器过紧（会制造假红）
    selfFailures.push(`合规样本被误判违规: ${s.why}`);
  }
}
check(
  selfFailures.length === 0,
  `H. 判定器正向对照自检（${SELF_SAMPLES.length} 个合成样本同源判定）`,
  selfFailures.length ? selfFailures.join('；') : '',
);

console.log('');
g.finish('系统工具门禁全部通过');

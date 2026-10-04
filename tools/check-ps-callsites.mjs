// check-ps-callsites.mjs —— PowerShell 调用点门禁（v2 方案 R0，2026-10-01）
//
// 为什么要有这条：`PS_INLINE_ALLOW`（engine/pssteps.rs）管的是**数据层语法白名单**——
// 「哪串 PowerShell 允许逐字交给收件箱 PS 跑」。它从来不是「命令层调用点已登记」的证据，
// 而 v1 方案正是把它当成了证据，于是 `tf_restore_point` 的创建链
// （commands/optimizer/restore_point.rs 的 run_inline_ps）绕开 `pssteps::compile` 也一直被算成"受棘轮管"。
// 同类漏网的还有 commands/uninstall.rs 的两处 Appx 调用：`quiet_cmd(...).output()`
// 连超时都没有，子孙进程占住管道即整条 IPC 永久挂住（R0 已改走统一入口）。
//
// 本门禁把「谁可以启动 PowerShell」收成一张表：
//   A. 裸 PS 进程构造（spawn 实参链里出现 powershell.exe / pwsh.exe）→ 咽喉文件外零容忍；
//   B. 低层执行器（run_inbox_ps / run_file / run_file_streaming）调用点 → 登记制；
//   C. 统一入口 run_inbox_script 调用点 → 登记制，且**登记的秒数必须与源码实参一致**
//      （防「登记 30s、代码改成 3600s」这种静默漂移）；
//   D. optimizer.rs 的 run_inline_ps 生产调用点 → 逐条登记秒数，新增一例不登记即红；
//   E. PS_INLINE_ALLOW 条数现算打印 —— 台账数字只能从这里抄，不许文档手写（v2 V2-06）。
//
// 登记格式沿用 check-system-bin 的 `{file, anchor, reason}`：anchor 是调用点那一行的判别性
// 子串，匹配 0 处=登记失效红、≥2 处=锚不判别红（AGENTS §5.19）。因为同一个函数体里会出现
// **文本完全相同**的两行调用（optimizer.rs 的 check-restore 与 list-restore 都是
// `run_inline_ps(ps, 30, None) else {`），锚必须带**所在函数名**才判别得开，故比对串是
// `fn <所在函数> | <该行文本>`。
//
// 用法：node tools/check-ps-callsites.mjs

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

const SRC = join(REPO_ROOT, 'src-tauri', 'src');
/// PS 执行层本体：`system_tool("powershell.exe")` 与低层 `run_*` 的唯一归属地。
const THROAT = 'src-tauri/src/pwsh/mod.rs';

/**
 * B. 低层执行器调用点（已经带 Job Object 与超时，但临时脚本的生命周期在调用方手里）。
 * `run_inbox_ps` 自 R0 起是 pwsh 模块私有、编译器已经挡住外部调用；列在这里是为了它哪天
 * 被重新 `pub` 出来时门禁先响，而不是留给下一个人靠肉眼发现。
 */
const PS_EXEC_SITES = [];
// 表空不等于断言空：R1 之后全仓**不允许**有任何咽喉外的低层执行器调用点，
// 上面 contextmenu.rs 那条（右键图标走 PowerShell 7）已随原生 ExtractIconExW 落地删除。
// 谁重新 `pub` 出 run_file* 并调用，pool 就会非空而登记表为空 → B 红。

/**
 * C. 统一入口 `pwsh::run_inbox_script` 的生产调用点。
 * timeout 单位秒；写 'caller' 表示这一处只是薄封装、秒数由更上层的 D 表登记。
 */
const PS_CALL_SITES = [
  {
    file: 'src-tauri/src/commands/actions.rs',
    anchor: 'crate::pwsh::run_inbox_script(&body, std::time::Duration::from_secs(120), Some("actions:run-script"))',
    reason: 'v0.7.0 B7：用户自写 PowerShell 直调。超时是固定 120 秒且用户不可配 —— 能配超时等于关掉「超时收树」这道护栏；不代提权（elevate:request 未下放给 actions 副窗）',
    owner: 'commands/actions.rs',
    timeout: 120,
  },
  {
    file: 'src-tauri/src/engine/pssteps.rs',
    anchor: 'run_inbox_script(script, std::time::Duration::from_secs(300)',
    reason: '数据层 PsInline 算子：原生解释器表达不了的构造逐字交给收件箱 PS',
    owner: 'engine/pssteps.rs',
    timeout: 300,
  },
  {
    file: 'src-tauri/src/commands/optimizer/restore_point.rs',
    anchor: 'fn run_inline_ps | crate::pwsh::run_inbox_script(ps, std::time::Duration::from_secs(timeout_secs), diag)',
    reason: '命令层薄封装：不自己定超时，秒数见 D 表逐调用点',
    owner: 'commands/optimizer/restore_point.rs',
    timeout: 'caller',
  },
  {
    file: 'src-tauri/src/commands/uninstall/appx.rs',
    anchor: 'fn enum_appx_packages | let out = crate::pwsh::run_inbox_script(script, APPX_ENUM_TIMEOUT, None)',
    reason: 'Appx 枚举（Get-AppxPackage）。R0 前是无超时的 quiet_cmd(...).output()',
    owner: 'commands/uninstall/appx.rs',
    timeout: 120,
  },
  {
    file: 'src-tauri/src/commands/uninstall/appx.rs',
    anchor: 'fn remove_appx | let out = crate::pwsh::run_inbox_script(&script, APPX_REMOVE_TIMEOUT, None)',
    reason: 'Appx 移除（Remove-AppxPackage），卸载动作本身可长。R0 前同样无超时',
    owner: 'commands/uninstall/appx.rs',
    timeout: 300,
  },
];

/**
 * D. `run_inline_ps` 的生产调用点（还原点查询 / 计数 / 预检 / 创建 / 列表）。
 * 这张表的意义是**计数棘轮**：命令层再加第六处直调就必须在这里留名 ——
 * 「还剩几个 PS 点」由本门禁打印，文档不再允许手写数字。
 */
const RUN_INLINE_PS_SITES = [
  { anchor: 'fn optimizer_check_restore | let Some(out) = run_inline_ps(ps, 30, None) else', reason: 'optimizer:check-restore 最近还原点', timeout: 30 },
  { anchor: 'fn count_restore_points | let out = run_inline_ps(ps, 30, None)?;', reason: '创建前后计数（含回读轮询）', timeout: 30 },
  { anchor: 'fn create_restore_inner | if let Some(out) = run_inline_ps(pre, 20, None)', reason: '创建前系统保护预检', timeout: 20 },
  { anchor: 'fn create_restore_inner | let Some(out) = run_inline_ps(&script, 120', reason: '创建还原点脚本本体', timeout: 120 },
  { anchor: 'fn optimizer_list_restore | let Some(out) = run_inline_ps(ps, 30, None) else', reason: 'optimizer:list-restore 列表', timeout: 30 },
];

/// 白名单条数的真源：只从这里读，别抄进文档
const PS_INLINE_ALLOW_FILE = 'src-tauri/src/engine/pssteps.rs';

function walk(dir, out = []) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith('.rs')) out.push(p);
  }
  return out;
}

const rel = (p) => relative(REPO_ROOT, p).replace(/\\/g, '/');
const cut = (s) => (s.length > 52 ? s.slice(0, 52) + '…' : s);

/** 调用点所属函数：取该偏移之前最后一个 `fn 名字`（Rust 里足以定位到最近的函数头） */
function enclosingFn(text, off) {
  const head = text.slice(0, off);
  let last = null;
  for (const m of head.matchAll(/\bfn\s+([A-Za-z_][A-Za-z0-9_]*)/g)) last = m[1];
  return last ?? '?';
}

/**
 * 取出 `<token>(` 之后平衡括号内的实参文本（跳过字符串字面量里的括号）。
 * token 自带左括号，故 `run_file(` 不会误配 `run_file_impl(`。
 */
function argsOf(text, openIdx) {
  let depth = 0;
  let inStr = null;
  for (let i = openIdx; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      if (c === '\\') i++;
      else if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'") inStr = c;
    else if (c === '(') depth++;
    else if (c === ')') {
      depth--;
      if (depth === 0) return text.slice(openIdx + 1, i);
    }
  }
  return '';
}

/** 按顶层逗号切实参（括号与字符串内的逗号不算分隔） */
function splitArgs(args) {
  const out = [];
  let depth = 0;
  let inStr = null;
  let cur = '';
  for (let i = 0; i < args.length; i++) {
    const c = args[i];
    if (inStr) {
      cur += c;
      if (c === '\\') { cur += args[++i] ?? ''; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'") { inStr = c; cur += c; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    if (c === ')' || c === ']' || c === '}') depth--;
    if (c === ',' && depth === 0) { out.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/** 扫一个调用 token → 命中清单（注释行、函数定义行不算调用点） */
function collect(text, file, token) {
  const hits = [];
  // 定义行不算调用点：这里的 defRe 历史上就够不到函数名（before 截到 token 前为止），
  // 真正生效的是 D/F 组各自的 isDefLine 过滤；保留本正则只为兼容旧形态，
  // 但可见性分支已放宽到 pub(...)，避免以后有人把它当唯一出口来改。
  const defRe = new RegExp(`(pub(\\(\\w+\\))?\\s+)?(async\\s+)?(unsafe\\s+)?fn\\s+${token.slice(0, -1).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`);
  let idx = text.indexOf(token);
  while (idx >= 0) {
    const lineStart = text.lastIndexOf('\n', idx - 1) + 1;
    const lineEnd = text.indexOf('\n', lineStart);
    const lineText = text.slice(lineStart, lineEnd < 0 ? undefined : lineEnd);
    const before = text.slice(lineStart, idx);
    if (!before.trimStart().startsWith('//') && !defRe.test(before.replace(/\s+/g, ' ').replace('fn ', 'fn'))) {
      const args = argsOf(text, idx + token.length - 1);
      hits.push({
        file,
        line: text.slice(0, idx).split('\n').length,
        raw: lineText.trim(),
        args,
        desc: `fn ${enclosingFn(text, idx)} | ${lineText.trim()}`,
      });
    }
    idx = text.indexOf(token, idx + token.length);
  }
  return hits;
}

/** 把登记表解析成「覆盖了哪个调用点」 */
function resolve(entries, pool) {
  const problems = [];
  const used = new Map();
  for (const e of entries) {
    const matched = pool.filter((h) => (!e.file || h.file === e.file) && h.desc.includes(e.anchor));
    if (matched.length === 0) {
      problems.push(`登记失效：${e.file ?? ''} # ${cut(e.anchor)} 在代码里找不到对应调用点`);
    } else if (matched.length > 1) {
      problems.push(`锚不判别：${e.file ?? ''} # ${cut(e.anchor)} 匹配到 ${matched.length} 处，请加长`);
    } else if (used.has(matched[0])) {
      problems.push(`一处调用点被两条登记同时覆盖：${matched[0].desc}`);
    } else {
      used.set(matched[0], e);
      e._site = matched[0];
    }
  }
  return { problems, uncovered: pool.filter((h) => !used.has(h)) };
}

/** 从实参文本解析秒数：`from_secs(N)` 直接命中；`from_secs(ID)` / 裸 `ID` 回同文件查 const */
function resolveSecs(entry, argsText) {
  const direct = argsText.match(/from_secs\(\s*(\d+)\s*\)/);
  if (direct) return Number(direct[1]);
  const fileText = texts.get(entry.file) ?? '';
  for (const a of splitArgs(argsText)) {
    const id = a.match(/^([A-Z][A-Z0-9_]+)$/) ?? a.match(/^std::time::Duration::from_secs\(\s*([A-Z][A-Z0-9_]+)\s*\)$/);
    if (!id) continue;
    const def = fileText.match(new RegExp(`const\\s+${id[1]}\\s*:[^=;]*?=\\s*std::time::Duration::from_secs\\(\\s*(\\d+)\\s*\\)`));
    if (def) return Number(def[1]);
  }
  return null;
}

const files = walk(SRC);
const texts = new Map();
for (const f of files) texts.set(rel(f), readFileSync(f, 'utf8'));

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== PowerShell 调用点门禁（v2 R0）===\n');

// ---- A. 裸 PS 进程构造（零容忍，不配登记表）----
let spawnScanned = 0;
const bareHits = [];
for (const [file, text] of texts) {
  for (const token of ['Command::new(', 'quiet_cmd(', 'system_tool(']) {
    for (const h of collect(text, file, token)) {
      spawnScanned++;
      if (/"(?:r#)?"?(powershell|pwsh)\.exe/i.test(`${h.args} ${h.raw}`)) {
        bareHits.push(`${file}:${h.line} ${cut(h.raw)}`);
      }
    }
  }
}
const bareOutsideThroat = bareHits.filter((s) => !s.startsWith(`${THROAT}:`));
check(
  bareOutsideThroat.length === 0,
  `A. 扫描 ${spawnScanned} 处 spawn 实参链，咽喉（${THROAT}）外零裸 PS 进程构造`,
  bareOutsideThroat.join('；'),
);

// ---- B / C / D 三张登记表 ----
const execPool = [];
const callPool = [];
const inlinePool = [];
for (const [file, text] of texts) {
  if (file === THROAT) continue; // 执行层内部自调不是「调用点」
  for (const t of ['run_inbox_ps(', 'run_file(', 'run_file_streaming(']) execPool.push(...collect(text, file, t));
  callPool.push(...collect(text, file, 'run_inbox_script('));
  if (file.endsWith('commands/optimizer/restore_point.rs')) inlinePool.push(...collect(text, file, 'run_inline_ps('));
}
// 定义行不是调用点。可见性前缀要一并剥掉再看 `fn`：D 批拆模块后跨文件 helper 降成
// `pub(super) fn`，只判 `startsWith('fn ')` 会把定义数成第 N 个调用点（登记表随之假红）。
const isDefLine = (raw) => /^(?:(?:pub|crate|use)(?:\(\w+\))?\s+)*(?:async\s+)?(?:unsafe\s+)?fn\s/.test(raw.trim());
const inlineCalls = inlinePool.filter((h) => !isDefLine(h.raw));

const rB = resolve(PS_EXEC_SITES, execPool);
const rC = resolve(PS_CALL_SITES, callPool);
const rD = resolve(RUN_INLINE_PS_SITES.map((e) => ({ ...e, file: 'src-tauri/src/commands/optimizer/restore_point.rs' })), inlineCalls);

check(
  rB.problems.length === 0 && rB.uncovered.length === 0,
  `B. ${execPool.length} 处低层执行器调用点均已登记（登记表 ${PS_EXEC_SITES.length} 条）`,
  [...rB.problems, ...rB.uncovered.map((h) => `未登记：${h.file}:${h.line} ${h.desc}`)].join('；'),
);

const timeoutProblems = [];
for (const e of PS_CALL_SITES) {
  if (!e._site) continue;
  if (e.timeout === 'caller') {
    if (/from_secs\(\s*\d+\s*\)/.test(e._site.args)) {
      timeoutProblems.push(`${e.file}:${e._site.line} 登记为 'caller'（秒数归上层），代码却写死了字面量`);
    }
    continue;
  }
  const secs = resolveSecs(e, e._site.args);
  if (secs === null) timeoutProblems.push(`${e.file}:${e._site.line} 超时无法静态核对（登记 ${e.timeout}s）`);
  else if (secs !== e.timeout) timeoutProblems.push(`${e.file}:${e._site.line} 超时漂移：登记 ${e.timeout}s，代码 ${secs}s`);
}
check(
  rC.problems.length === 0 && rC.uncovered.length === 0 && timeoutProblems.length === 0,
  `C. ${callPool.length} 处统一入口调用点均已登记，且超时秒数与源码实参一致`,
  [...rC.problems, ...rC.uncovered.map((h) => `未登记：${h.file}:${h.line} ${h.desc}`), ...timeoutProblems].join('；'),
);

const inlineProblems = [];
for (const e of RUN_INLINE_PS_SITES) {
  if (!e._site) continue;
  const secs = Number((splitArgs(e._site.args)[1] ?? '').match(/\d+/)?.[0] ?? NaN);
  if (!Number.isFinite(secs)) inlineProblems.push(`optimizer.rs:${e._site.line} 第二实参不是字面量秒数（锚 ${cut(e.anchor)}）`);
  else if (secs !== e.timeout) inlineProblems.push(`optimizer.rs:${e._site.line} 超时漂移：登记 ${e.timeout}s，代码 ${secs}s`);
}
check(
  rD.problems.length === 0 && rD.uncovered.length === 0 && inlineProblems.length === 0,
  `D. run_inline_ps 生产调用点 ${inlineCalls.length} 处全部登记（表 ${RUN_INLINE_PS_SITES.length} 条）`,
  [...rD.problems, ...rD.uncovered.map((h) => `未登记：${h.file}:${h.line} ${h.desc}`), ...inlineProblems].join('；'),
);

// ---- F. 带超时静默子进程（quiet_cmd_timeout）调用点（v2-L4P-29 / B-7） ----
// 6 处 reg.exe export 备份点统一走带超时入口；秒数真源 = systembin::REG_EXPORT_TIMEOUT。
// 这张表抓两件事：① 新增 quiet_cmd_timeout 调用点不登记即红（登记制）；
// ② 谁把 REG_EXPORT_TIMEOUT 常量改掉（换字面量/换时长）即红（超时一致性）。
const TIMEOUT_SPAWN_SITES = [
  { file: 'src-tauri/src/engine/native/startup.rs', anchor: '&["export", &export_path, reg_file_str, "/y"]', reason: '启动项禁用台账：删值前整键备份' },
  { file: 'src-tauri/src/engine/native/contextmenu.rs', anchor: '&["export", &write_path, reg_file_str, "/y"]', reason: '右键菜单删除前整键备份' },
  { file: 'src-tauri/src/engine/native/peripheral.rs', anchor: '&["export", &reg_path, backup_file_str, "/y"]', reason: '外设优化写值前逐键备份' },
  { file: 'src-tauri/src/engine/native/cleanup.rs', anchor: '&["export", &export_path, file_str, "/y"]', reason: 'cleanup regKeys 删除前逐键备份' },
  { file: 'src-tauri/src/commands/uninstall/residue.rs', anchor: '&["export", &export_path, file_str, "/y"]', reason: '残留 reg_key 删除前整键备份' },
  { file: 'src-tauri/src/commands/uninstall/residue.rs', anchor: '&["export", key_part, file_str, "/y"]', reason: '残留 reg_value 删值前父键备份' },
  // 顽固软件治理的 schtasks 三点（v5 M-1）：备份不判成败就无条件 /Delete 是"删了且没凭据"，
  // 裸 .output() 又会让挂死的 schtasks 永久锁住这条 IPC。超时复用 REG_EXPORT_TIMEOUT（同为
  // 备份类短命令：平时毫秒级，15s 已是宽限上界）。
  { file: 'src-tauri/src/engine/native/process.rs', anchor: '&["/Query", "/TN", task, "/NH"],', reason: '顽固软件治理：判任务是否存在' },
  { file: 'src-tauri/src/engine/native/process.rs', anchor: '&["/Query", "/TN", task, "/XML"],', reason: '顽固软件治理：删任务前导出 XML（唯一还原凭据）' },
  { file: 'src-tauri/src/engine/native/process.rs', anchor: '&["/Delete", "/TN", task, "/F"],', reason: '顽固软件治理：删除计划任务' },
  // 维护任务（v2-L4P-37/F-6）：sfc/DISM/sc，30 分钟上限
  { file: 'src-tauri/src/engine/native/maintenance.rs', anchor: 'exe, args, MAINT_CMD_TIMEOUT', reason: '维护任务 run_cmd：sfc/DISM/sc 长耗时子进程', timeoutConst: 'MAINT_CMD_TIMEOUT', secs: 1800 },
  { file: 'src-tauri/src/engine/native/maintenance.rs', anchor: '&sc, &["stop", name], MAINT_CMD_TIMEOUT', reason: 'stop_service_wait 的 sc stop（restart_service / search / wu 三条链共用）', timeoutConst: 'MAINT_CMD_TIMEOUT', secs: 1800 },
  // v5 S-1：store 任务从「spawn 不管结果」改成等退出码，于是它进入超时登记表
  { file: 'src-tauri/src/engine/native/maintenance.rs', anchor: 'system_tool("wsreset.exe"),', reason: '维护：wsreset 清 Store 缓存（等退出码，非 fire-and-forget）', timeoutConst: 'WSRESET_TIMEOUT', secs: 60 },
  // v5 R-3：运行库装包/DISM 从裸 .output() 改成带超时 —— 挂住时这条 IPC 永不返回，
  // 前端按钮卡在「安装中…」。上游 Electron 轨本来就带 600s，迁移时丢了。
  { file: 'src-tauri/src/engine/native/runtimes_net.rs', anchor: 'REDIST_INSTALL_TIMEOUT', reason: '运行库修复：vc_redist / netfx48 静默安装与 DISM 启用 NetFx3', timeoutConst: 'REDIST_INSTALL_TIMEOUT', secs: 600 },
  // v0.5.0 残留扫描（只读）：fltmc 是 minifilter 挂载态的唯一权威来源。它挂在扫描线程的
  // 同步链上，一旦被杀软钩住不退出，整轮报告就永远不返回 —— 与 reg export 同族，必须带超时。
  { file: 'src-tauri/src/commands/uninstall/minifilter_orphan.rs', anchor: 'system_tool("fltmc.exe"), &["filters"], FLTMC_TIMEOUT', reason: '残留扫描：读过滤管理器挂载清单（只读，失败即整组不产候选）', timeoutConst: 'FLTMC_TIMEOUT', secs: 10 },
  // 2026-10-04 审计 §4.4：清理页 special=dism 的 /ResetBase 是漏改的同类裸 .output()，
  // /ResetBase 合法就要跑几十分钟，后代 TiWorker 占住管道即永久挂住整条清理链。
  // 1800s 对齐 MAINT_CMD_TIMEOUT（sfc/DISM/sc 同级长耗时）；到点杀的是 DISM 前端
  // 进程，CBS/TiWorker 事务自回滚，中断安全。
  { file: 'src-tauri/src/engine/native/cleanup.rs', anchor: 'DISM_CLEANUP_TIMEOUT', reason: '清理页 DISM /StartComponentCleanup /ResetBase（审计 §4.4）', timeoutConst: 'DISM_CLEANUP_TIMEOUT', secs: 1800 },
];
const TIMEOUT_SECS = 15;

// ---- G. QUICKCMDS 两条 PS 启动项登记（v2-L4P-26 / B-4） ----
// quickcmds 的 powershell 启动是**产品功能**（可见控制台，CREATE_NEW_CONSOLE），
// 不走 quiet_cmd、不受 A 组正则约束——正因为 A 组看不见它，必须在这里显式留名：
// 新增第三条 PS 启动项不登记即红；摘掉这两条任何一条，锚失效同样红。
const QUICKCMD_PS_SITES = [
  { anchor: '("sys-cmd-admin", "管理员CMD", "powershell -Command \\"Start-Process cmd -Verb RunAs\\"")', reason: '产品功能：管理员 CMD 快捷启动（经可见控制台）' },
  { anchor: '("sys-powershell", "PowerShell", "powershell")', reason: '产品功能：PowerShell 快捷启动' },
];

// ---- E. PS_INLINE_ALLOW 条数现算 + 台账打印 ----
const allowText = texts.get(PS_INLINE_ALLOW_FILE) ?? '';
const allowBlock = allowText.match(/const PS_INLINE_ALLOW: &\[&str\] = &\[([\s\S]*?)\n\];/);
const allowItems = allowBlock ? [...allowBlock[1].matchAll(/^\s+"([^"]+)"/gm)].map((m) => m[1]) : [];
const allowDup = allowItems.length - new Set(allowItems).size;
check(
  allowItems.length > 0 && allowDup === 0,
  `E. PS_INLINE_ALLOW ${allowItems.length} 条（只管数据层语法白名单，不构成命令层登记证据）`,
  allowItems.length === 0
    ? '解析不到数组，本门禁该跟着 pssteps.rs 的声明形态一起改'
    : allowDup > 0
      ? `有 ${allowDup} 条重入条目，白名单必须逐项唯一（否则条数不再等于实际放行面）`
      : '',
);

// ---- F/G 组执行（登记制 + 超时常量核对）----
const timeoutPool = [];
for (const [file, text] of texts) {
  // 定义行本身不是调用点（collect 的 defRe 归一化对此函数名失效，这里显式剔除）
  timeoutPool.push(...collect(text, file, 'quiet_cmd_timeout(').filter((h) => !h.raw.includes('fn quiet_cmd_timeout')));
}
const tUsed = new Set();
const tProblems = [];
for (const e of TIMEOUT_SPAWN_SITES) {
  const matched = timeoutPool.filter((h) => (!e.file || h.file === e.file) && h.args.includes(e.anchor));
  if (matched.length === 0) tProblems.push(`登记失效：${e.file} # ${cut(e.anchor)}`);
  else if (matched.length > 1) tProblems.push(`锚不判别：${e.file} # ${cut(e.anchor)} 命中 ${matched.length} 处`);
  else {
    tUsed.add(matched[0]);
    e._site = matched[0];
    if (!e.reason) tProblems.push(`${e.file} 登记缺理由`);
    // 超时常量核对：调用点实参必须引用登记的常量名，且常量定义值 = 登记秒数
    const tc = e.timeoutConst ?? 'REG_EXPORT_TIMEOUT';
    const secs = e.secs ?? TIMEOUT_SECS;
    {
      if (!e._site.args.includes(tc)) {
        tProblems.push(`${e.file}:${e._site.line} 实参未引用登记的 ${tc}`);
      }
      const sysbin = texts.get('src-tauri/src/engine/systembin.rs') ?? '';
      // v3 D1：native.rs 已按功能域拆成 native/ 目录，超时常量的定义处散在各域文件里
      const nativeOf = (f) => f.startsWith('src-tauri/src/engine/native/');
      const native = [...texts.entries()].filter(([f]) => nativeOf(f)).map(([, x]) => x).join('\n');
      const allSrc = sysbin + native;
      const defRe = new RegExp(`const\\s+${tc}\\s*:[^=;]*?=\\s*std::time::Duration::from_secs\\(([^)]*)\\)`);
      const def = allSrc.match(defRe);
      if (!def) tProblems.push(`${tc} 常量定义找不到（native.rs / systembin.rs）`);
      else {
        const expr = def[1].replace(/\s/g, '');
        const val = /^\d+$/.test(expr) ? Number(expr) : expr.split('*').reduce((a, b) => a * Number(b), 1);
        if (val !== secs) tProblems.push(`${tc} 漂移：登记 ${secs}s，代码 ${val}s`);
      }
    }
  }
}
const tUncovered = timeoutPool.filter((h) => !tUsed.has(h));
const sysbinText = texts.get('src-tauri/src/engine/systembin.rs') ?? '';
const tConstOk = new RegExp(`pub const REG_EXPORT_TIMEOUT[^=]*=\\s*std::time::Duration::from_secs\\(\\s*${TIMEOUT_SECS}\\s*\\)`).test(sysbinText);
check(
  tProblems.length === 0 && tUncovered.length === 0 && tConstOk,
  `F. quiet_cmd_timeout 调用点 ${timeoutPool.length} 处全部登记，REG_EXPORT_TIMEOUT=${TIMEOUT_SECS}s 与源码一致`,
  [...tProblems, ...tUncovered.map((h) => `未登记：${h.file}:${h.line} ${h.desc}`), tConstOk ? '' : 'systembin.rs 的 REG_EXPORT_TIMEOUT 定义漂移'].filter(Boolean).join('；'),
);

let gProblems = [];
for (const e of QUICKCMD_PS_SITES) {
  const text = [...texts.entries()].filter(([f]) => f.endsWith('quickcmds.rs')).map(([, t]) => t).join('\n');
  const n = text.split(e.anchor).length - 1;
  if (n !== 1) gProblems.push(`锚期望恰好 1 处、实际 ${n} 处：${cut(e.anchor)}`);
  else if (!e.reason) gProblems.push('登记缺理由');
}
check(
  gProblems.length === 0,
  `G. QUICKCMDS 的 ${QUICKCMD_PS_SITES.length} 条 PS 启动项均已登记（产品功能，可见控制台，不进 A 组正则）`,
  gProblems.join('；'),
);

console.log('');
console.log('PS 调用点台账（现算，引用这些数字的地方必须重跑本门禁）：');
console.log(`  数据层 PsInline 执行器 : ${callPool.filter((h) => h.file.endsWith('pssteps.rs')).length} 处`);
console.log(`  命令层直调 inbox PS    : ${inlineCalls.length} 处 → 收敛到薄封装 ${callPool.filter((h) => h.file.endsWith('optimizer.rs')).length} 处`);
console.log(`  Appx 命令层直调        : ${callPool.filter((h) => h.file.includes('commands/uninstall/')).length} 处`);
console.log(`  外部 PowerShell 7 通道 : ${execPool.filter((h) => h.raw.includes('run_file')).length} 处（R1 归零目标）`);
console.log(`  合计 inbox PS 生产入口 : ${callPool.length} 处（登记表 ${PS_CALL_SITES.length} 条）`);

console.log('');
if (fail > 0) {
  console.error(`门禁失败：${fail} 组断言未通过`);
  process.exit(1);
}
console.log('PowerShell 调用点门禁全部通过');

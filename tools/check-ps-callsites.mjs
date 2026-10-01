// check-ps-callsites.mjs —— PowerShell 调用点门禁（v2 方案 R0，2026-10-01）
//
// 为什么要有这条：`PS_INLINE_ALLOW`（engine/pssteps.rs）管的是**数据层语法白名单**——
// 「哪串 PowerShell 允许逐字交给收件箱 PS 跑」。它从来不是「命令层调用点已登记」的证据，
// 而 v1 方案正是把它当成了证据，于是 `tf_restore_point` 的创建链
// （commands/optimizer.rs 的 run_inline_ps）绕开 `pssteps::compile` 也一直被算成"受棘轮管"。
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
    file: 'src-tauri/src/engine/pssteps.rs',
    anchor: 'run_inbox_script(script, std::time::Duration::from_secs(300)',
    reason: '数据层 PsInline 算子：原生解释器表达不了的构造逐字交给收件箱 PS',
    owner: 'engine/pssteps.rs',
    timeout: 300,
  },
  {
    file: 'src-tauri/src/commands/optimizer.rs',
    anchor: 'fn run_inline_ps | crate::pwsh::run_inbox_script(ps, std::time::Duration::from_secs(timeout_secs), diag)',
    reason: '命令层薄封装：不自己定超时，秒数见 D 表逐调用点',
    owner: 'commands/optimizer.rs',
    timeout: 'caller',
  },
  {
    file: 'src-tauri/src/commands/uninstall.rs',
    anchor: 'fn enum_appx_packages | let out = crate::pwsh::run_inbox_script(script, APPX_ENUM_TIMEOUT, None)',
    reason: 'Appx 枚举（Get-AppxPackage）。R0 前是无超时的 quiet_cmd(...).output()',
    owner: 'commands/uninstall.rs',
    timeout: 120,
  },
  {
    file: 'src-tauri/src/commands/uninstall.rs',
    anchor: 'fn remove_appx | let out = crate::pwsh::run_inbox_script(&script, APPX_REMOVE_TIMEOUT, None)',
    reason: 'Appx 移除（Remove-AppxPackage），卸载动作本身可长。R0 前同样无超时',
    owner: 'commands/uninstall.rs',
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
  const defRe = new RegExp(`(pub(\\(crate\\))?\\s+)?(async\\s+)?fn\\s+${token.slice(0, -1).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`);
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
  if (file.endsWith('commands/optimizer.rs')) inlinePool.push(...collect(text, file, 'run_inline_ps('));
}
const inlineCalls = inlinePool.filter((h) => !h.raw.trimStart().startsWith('fn '));

const rB = resolve(PS_EXEC_SITES, execPool);
const rC = resolve(PS_CALL_SITES, callPool);
const rD = resolve(RUN_INLINE_PS_SITES.map((e) => ({ ...e, file: 'src-tauri/src/commands/optimizer.rs' })), inlineCalls);

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

console.log('');
console.log('PS 调用点台账（现算，引用这些数字的地方必须重跑本门禁）：');
console.log(`  数据层 PsInline 执行器 : ${callPool.filter((h) => h.file.endsWith('pssteps.rs')).length} 处`);
console.log(`  命令层直调 inbox PS    : ${inlineCalls.length} 处 → 收敛到薄封装 ${callPool.filter((h) => h.file.endsWith('optimizer.rs')).length} 处`);
console.log(`  Appx 命令层直调        : ${callPool.filter((h) => h.file.endsWith('uninstall.rs')).length} 处`);
console.log(`  外部 PowerShell 7 通道 : ${execPool.filter((h) => h.raw.includes('run_file')).length} 处（R1 归零目标）`);
console.log(`  合计 inbox PS 生产入口 : ${callPool.length} 处（登记表 ${PS_CALL_SITES.length} 条）`);

console.log('');
if (fail > 0) {
  console.error(`门禁失败：${fail} 组断言未通过`);
  process.exit(1);
}
console.log('PowerShell 调用点门禁全部通过');

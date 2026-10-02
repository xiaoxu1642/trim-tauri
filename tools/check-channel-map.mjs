// check-channel-map.mjs —— IPC 通道映射一致性门禁（D2，Phase 1 起生效）
//
// 迁移方案 D2 的硬要求：**映射表键集合必须等于 preload.js 的通道集合**，
// 且新增通道必须同表登记，防止「Rust 有了、前端没接」或反向的静默断裂
// （R18：141 条通道中任一漏迁，表现为按钮没反应而非报错，最难发现）。
//
// 五组断言：
//   A. preload 的 invoke 通道集合 == tauri-api.js 的 CHANNEL_MAP 键集合
//   B. preload 的 send 通道集合 == SEND_MAP 键 ∪ 窗口插件桥接通道 ∪ app:first-paint 直连
//   C. 已登记且已在 Rust 注册的命令，名字必须一一对应（snake_case 且无重复映射）
//   D. lib.rs 中每个 #[tauri::command] 函数（探针除外）都必须被映射表引用
//      ——这是本门禁最有价值的一条：抓 Rust 侧写完却忘了接前端的裂缝
//   D4. 反向的第二层：映射到的命令还得**真有渲染层调用点**（审查 v2-M15）。
//       D1~D3 只保证「三张表互相对得上」，对「表里有、没人调」是瞎的 ——
//       settings:save 就是这么带着约 250 行密钥/内网 URL 校验逻辑零调用方存活至今。
//
// 未迁移通道（Rust 尚未注册）只做**统计报告**不判失败，以支持 Phase 1 增量迁移。
//
// 用法：node tools/check-channel-map.mjs [--strict]
//   --strict：要求全部通道均已迁移（Phase 5 收尾门禁用）

import { readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';

import { ORIGIN, REPO_ROOT } from './ps-origin.mjs';

const STRICT = process.argv.includes('--strict');
const TAURI_ROOT = REPO_ROOT;

// 通道契约基线：读**仓库内**的上游快照（审查 K2）。原先这里是硬编码的本机源仓库绝对路径，
// 干净克隆上加载即抛；快照与活源仓库是否已漂，由 tools/check-origin-drift.mjs 复核。
const preload = readFileSync(join(ORIGIN, 'preload.js'), 'utf8');
const adapter = readFileSync(join(TAURI_ROOT, 'src', 'scripts', 'tauri-api.js'), 'utf8');
const libRs = readFileSync(join(TAURI_ROOT, 'src-tauri', 'src', 'lib.rs'), 'utf8');

// 窗口插件桥接的 send 通道（不经过 sendChannel，走 plugin:window|*）
const WINDOW_BRIDGED = ['window:minimize', 'window:maximize', 'window:close'];
// 直连命令的生命周期通道（send 语义，但走专用命令而非映射表）
const DIRECT = ['app:first-paint'];
/** DIRECT 对应的 Rust 命令名（D1 断言要看命令名而非通道名） */
const DIRECT_COMMANDS = ['app_first_paint'];
/** 不面向渲染层契约的排障探针（D1 要豁免，否则会误报「Rust 有了、前端没接」）。
 *  Phase 0 的 spike_ping / spike_apply_material 已连命令带注册一并删除（CDP 退役后
 *  探针无主，且其渲染层入口 raw: invokeCore 会绕过 window.api 白名单直调任意命令）。
 *  debug_data_dirs 保留：数据目录/搬迁/写入探针仍是排障必需。 */
const PROBES = ['debug_data_dirs'];

/**
 * 上游 preload.js 里声明、但**本仓库已刻意摘除**的通道（A 组断言要豁免）。
 *
 * 判据：上游基线 `vendor/upstream-js/preload.js` 是只读快照（AGENTS.md §5.12），
 * 改它等于改契约锚点；而 Tauri 轨确实不再需要这条通道时，就在这里登记「已退役」，
 * 与 `DIRECT` 同类 —— 都是「preload 有、映射表没有」的合法形态。
 * 每条必须写明退役理由与日期，否则这条豁免会变成随意删通道的后门。
 */
const RETIRED = {
  'settings:save': 'v2-F4（2026-09-26）：零调用方 + 无 UI 面 + 写入面在 models:save，整链摘除',
  'pwsh:prepare': 'v2-M15/B11（2026-09-26）：D4 孤儿，且 Tauri 轨无内置运行时可准备，与 pwsh:status 完全重复',
  'pwsh:status': 'v2-R1（2026-10-01）：右键图标改原生 ExtractIconExW 后，PS7 候选链与 pwshruntime.rs 整条退役，本应用不再启动 pwsh.exe',
  // D4 基线清零（2026-09-28，用户拍板「零引用功能全部清除」）：六条孤儿整链摘除
  // （命令 fn + lib.rs 注册 + CHANNEL_MAP + api 包装器一并删除；shutdown:begin/complete
  // 保留为刻意登记的扩展点，见 D4_ORPHANS）
  'app:get-theme': 'D4 清零（2026-09-28）：主题只走本地 theme.js，零调用方整链摘除',
  'window:update-overlay': 'D4 清零（2026-09-28）：自绘标题栏改由 CSS/body.win-maximized 承担，no-op 命令已无意义',
  'netspeed:ping': 'D4 清零（2026-09-28）：零调用方，netcheck 域已覆盖连通性探测，整链摘除',
  'netspeed:throughput': 'D4 清零（2026-09-28）：同上（回环吞吐测速无 UI 面）',
  'elevate:status': 'D4 清零（2026-09-28）：提权状态走事件 elevate:notice，状态查询零调用方',
  'paths:validate': 'D4 清零（2026-09-28）：纯死通道（Rust 侧亦无内部调用，v2-F19 订正过错误理由）',
  // J3（2026-09-29）D4 基线清零：两条 shutdown 通道整链摘除（命令体 + lib.rs 注册 +
  // SEND_MAP + api 包装器一并删除），理由见 D4_ORPHANS 注释。
  'shutdown:begin': 'J3 清零（2026-09-29）：空函数 no-op，零调用方；关闭编排在主进程 RunEvent::Exit',
  'shutdown:complete': 'J3 清零（2026-09-29）：渲染层零调用，且 readonly 档可 app.exit(0) 是多余退出面',
};

/**
 * Tauri 轨**正向新增**通道（上游 Electron preload.js 快照里没有的）。
 * 上游快照是只读契约锚点（AGENTS §5.12），不回填；Tauri 时代新增能力在这里登记，
 * 每条写明来源批次与理由。与 RETIRED 对称的反向豁免：不登记会被 A 组断言当
 * 「map 独有」判红；通道摘除后此处的残留条目同样判红（防豁免清单腐化）。
 */
const TAURI_ADDED = {
  'uninstall:modify': 'P1-D6（2026-10-01）：修改/修复入口，执行 ModifyPath（主窗档）',
  'uninstall:pending-add': 'P1-B3（2026-10-01）：回收站失败项登记重启后删（主窗档）',
  'uninstall:pending-list': 'P1-B3（2026-10-01）：重启后删待删清单（主窗档，只读）',
  'uninstall:pending-revoke': 'P1-B3（2026-10-01）：撤回重启后删登记（主窗档）',
  'uninstall:report-list': 'U-6（2026-09-28）：批次报告列表（上游只写报告无查看面）',
  'uninstall:report-get': 'U-6（2026-09-28）：批次报告明细读取（同上）',
  'uninstall:dead-scan': 'M6（2026-09-28）：失效残留扫描（不依赖卸载事实的无主残留，上游无此能力）',
  'uninstall:dir-size': 'B6（2026-09-29）：EstimatedSize 缺失时的安装目录体积兜底估算（上游无此能力）',
  'realtime:report-get': 'v2-L4P-35（2026-10-02）：网速报告列表瘦身后按需取单份明细（上游无此能力）',
  'uninstall:appx-logo': 'U-3（2026-09-28）：Appx Logo 懒加载（上游无此能力）',
  'cleanup:reg-backup-list': 'C-4（2026-09-28）：注册表备份列表（上游只写备份无还原面）',
  'cleanup:reg-backup-restore': 'C-4（2026-09-28）：注册表备份还原（reg import，主窗档）',
  'uninstall:batch-list': 'H1（2026-09-29）：卸载还原包列表（上游只有 .reg 备份，无内容级还原包）',
  'uninstall:batch-restore': 'H1（2026-09-29）：整批还原文件内容（往磁盘写，主窗档）',
  'cleanup:file-backup-list': 'C-4（2026-09-28）：永久删批次文件备份清单（2026-09-28 拍板补删前备份）',
  'cleanup:file-backup-restore': 'C-4（2026-09-28）：文件备份拷回原路径（主窗档）',
  'uninstall:check-residue-version': 'A3/M3（2026-09-28）：残留规则库版本检查（上游无残留库热更新能力）',
  'uninstall:update-residue-rules': 'A3/M3（2026-09-28）：残留规则库在线更新（主窗档，显式动作不做定时）',
  'uninstall:orphan-scan': 'C2/M4（2026-09-28）：孤儿应用数据扫描（上游无所有权历史这一层）',
  'uninstall:orphan-ignore': 'C2/M4（2026-09-28）：把某历史 owner 记入忽略清单（同上）',
  'uninstall:reg-backup-list': 'D1/M5（2026-09-28）：卸载域注册表备份列表（此前备份只写不读）',
  'uninstall:reg-backup-restore': 'D1/M5（2026-09-28）：单个备份 reg import 还原（主窗档 + 危险确认）',
  'syspanel:power-plan-get': 'P2 §3.6（2026-10-03）：电源方案读侧（RAINZ 对标系统面板）',
  'syspanel:power-plan-apply': 'P2 §3.6（2026-10-03）：电源方案三档切换 + 400ms 回读校验（主窗档，白名单 GUID）',
  'syspanel:pagefile-state': 'P2 §3.6（2026-10-03）：虚拟内存只读展示（写侧同批落地）',
  'syspanel:pagefile-apply': 'P2 §3.6（2026-10-03）：虚拟内存写侧（AutomaticManagedPagefile + PagingFiles；主窗档 + 高危确认 + 需重启）',
  'optimizer:batch-preflight': 'M1（2026-10-03）：批量执行前整批准入预检（纯只读，上游 Electron 无此面）',
};

function collect(set, re, text) {
  for (const m of text.matchAll(re)) set.add(m[1]);
  return set;
}

const preloadInvoke = collect(new Set(), /ipcRenderer\.invoke\(\s*['"]([^'"]+)['"]/g, preload);
const preloadSend = collect(new Set(), /ipcRenderer\.send\(\s*['"]([^'"]+)['"]/g, preload);

// 解析适配层两张表：形如 'channel': 'command',
function parseMap(name, text) {
  const start = text.indexOf(`var ${name} = {`);
  if (start < 0) throw new Error(`未找到 ${name}`);
  const end = text.indexOf('\n  };', start);
  const block = text.slice(start, end < 0 ? text.length : end);
  const map = new Map();
  for (const m of block.matchAll(/'([^']+)':\s*'([^']+)'/g)) map.set(m[1], m[2]);
  return map;
}
const channelMap = parseMap('CHANNEL_MAP', adapter);
const sendMap = parseMap('SEND_MAP', adapter);

// 解析 lib.rs generate_handler! 注册表
const handlerBlock = libRs.slice(libRs.indexOf('generate_handler!['), libRs.indexOf('])', libRs.indexOf('generate_handler![')));
const registered = new Set();
for (const m of handlerBlock.matchAll(/commands::\w+::(\w+)/g)) registered.add(m[1]);

// 解析 commands/**.rs 中声明的 #[tauri::command] 函数
// v3 D2：递归扫——命令下沉到子目录（commands/uninstall/*.rs）时，只扫一层会让 D3
// 「注册了但找不到声明」集体判红，反过来若改成静默跳过就是把注入面台账掏空。
const cmdDir = join(TAURI_ROOT, 'src-tauri', 'src', 'commands');
const cmdFiles = [];
(() => {
  const walk = (dir, prefix = '') => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.isDirectory()) walk(join(dir, e.name), `${prefix}${e.name}/`);
      else if (e.name.endsWith('.rs')) cmdFiles.push({ rel: prefix + e.name, abs: join(dir, e.name) });
    }
  };
  walk(cmdDir);
})();
const declared = new Map(); // fn -> file
for (const { rel, abs } of cmdFiles) {
  const text = readFileSync(abs, 'utf8');
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].includes('#[tauri::command]')) continue;
    for (let j = i + 1; j < Math.min(i + 6, lines.length); j++) {
      const m = lines[j].match(/pub\s+(?:async\s+)?fn\s+(\w+)/);
      if (m) { declared.set(m[1], rel); break; }
    }
  }
}

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== IPC 通道映射一致性门禁 ===\n');

// ---- A. invoke 集合 ----
const retiredKeys = Object.keys(RETIRED);
const staleRetired = retiredKeys.filter(c => channelMap.has(c)); // 退役清单里又冒出来了 → 红
const onlyPreload = [...preloadInvoke].filter(c => !channelMap.has(c) && !RETIRED[c]);
const onlyMap = [...channelMap.keys()].filter(c => !preloadInvoke.has(c) && !TAURI_ADDED[c]);
const staleAdded = Object.keys(TAURI_ADDED).filter(c => !channelMap.has(c)); // 登记了但映射表没有 → 豁免失效
check(onlyPreload.length === 0 && onlyMap.length === 0 && staleRetired.length === 0 && staleAdded.length === 0,
  `A. invoke 通道集合一致（preload ${preloadInvoke.size} / CHANNEL_MAP ${channelMap.size} / 已退役 ${retiredKeys.length} / 正向新增 ${Object.keys(TAURI_ADDED).length}）`,
  staleRetired.length
    ? `已退役通道又出现在映射表里（请删条目或撤退役登记）${JSON.stringify(staleRetired)}`
    : staleAdded.length
      ? `正向新增登记已失效（映射表里没有这些通道）${JSON.stringify(staleAdded)}`
      : onlyPreload.length || onlyMap.length
        ? `preload 独有 ${JSON.stringify(onlyPreload)} / map 独有 ${JSON.stringify(onlyMap)}`
        : '');

// ---- B. send 集合 ----
const expectedSend = new Set([...sendMap.keys(), ...WINDOW_BRIDGED, ...DIRECT]);
// 退役豁免对 send 同样适用：RETIRED 的语义是「Tauri 轨不再需要这条通道」，
// 与它挂在 invoke 还是 send 方向无关（A 组早就这么处理了，B 组此前漏掉）。
const sendMissing = [...preloadSend].filter(c => !expectedSend.has(c) && !RETIRED[c]);
const sendExtra = [...expectedSend].filter(c => !preloadSend.has(c));
check(sendMissing.length === 0 && sendExtra.length === 0,
  `B. send 通道集合一致（preload ${preloadSend.size} / 映射+桥接 ${expectedSend.size}）`,
  sendMissing.length || sendExtra.length ? `缺 ${JSON.stringify(sendMissing)} / 多 ${JSON.stringify(sendExtra)}` : '');

// ---- C. 命令名规范与唯一性 ----
const values = [...channelMap.values(), ...sendMap.values()];
const badName = values.filter(v => !/^[a-z][a-z0-9_]*$/.test(v));
check(badName.length === 0, 'C1. 命令名全部 snake_case', badName.length ? JSON.stringify(badName) : '');
const dupes = values.filter((v, i) => values.indexOf(v) !== i);
check(dupes.length === 0, 'C2. 无重复映射（一个命令被两个通道指向）', dupes.length ? JSON.stringify([...new Set(dupes)]) : '');

// ---- D. Rust 命令 ↔ 映射表 双向一致 ----
const mapped = new Set([...values, ...DIRECT_COMMANDS]);
const unmappedDeclared = [...declared.keys()].filter(f => !mapped.has(f) && !PROBES.includes(f));
check(unmappedDeclared.length === 0,
  'D1. 每个 Rust 命令都被映射表引用（防「Rust 有了、前端没接」）',
  unmappedDeclared.length ? unmappedDeclared.map(f => `${f}@${declared.get(f)}`).join(', ') : '');

const notRegistered = [...mapped].filter(v => !registered.has(v));
const declaredNotRegistered = [...declared.keys()].filter(f => !registered.has(f));
check(declaredNotRegistered.length === 0,
  'D2. 声明的命令都进了 generate_handler!（防「写了没注册」）',
  declaredNotRegistered.length ? JSON.stringify(declaredNotRegistered) : '');

const registeredNoDecl = [...registered].filter(f => !declared.has(f));
check(registeredNoDecl.length === 0,
  'D3. 注册的命令都有 #[tauri::command] 声明（防注册名拼错）',
  registeredNoDecl.length ? JSON.stringify(registeredNoDecl) : '');

// ---- D4. 每条映射命令都要真有渲染层调用点（审查 v2-M15 的「加门禁断言」那半）----
// 为什么要单独一条：D1~D3 核的是「Rust 声明 ⇄ generate_handler! ⇄ CHANNEL_MAP」三张表互相对得上，
// 「表里有条目、前端没人调」在三张表里都是自洽的，于是一条孤儿写通道可以带着约 250 行
// 密钥掩码/内网 URL 校验逻辑长期存活（settings:save），并让下一轮把「注册」读成「已覆盖」。
// 判据取「适配层里该通道的 window.api 路径是否在渲染层出现」，而不是命令名文本 ——
// 渲染层只写 `window.api.<域>.<方法>()`，命令名压根不出现在 src/ 里。
//
// 三种合法写法都要认出来，否则会把「用了」误判成「孤儿」（假红同样是债）：
//   ① 直接点调用：`window.api?.appearance?.getMaterial()`（先把 `?.` 归一成 `.`）
//   ② 局部别名：`const api = window.api?.pwsh;` 之后的 `api.getStatus()`
//   ③ 动态派发：`window.api?.modal?.[method]()` —— 静态面认不出方法名，整域按「已派发」放行，
//      但会在输出里点名，避免它变成「想绕过 D4 就加个方括号」的后门。
const D4_ORPHANS = new Map([
  // 现状基线：v2-M15 实测的零调用方通道。基线是**双向棘轮**——
  // 新增孤儿判红（不许再往表里加不接线的条目），基线里的条目一旦有了调用点也判红
  // （白名单不许留死条目，否则下一次没人记得它其实早就接上了）。摘除或接线后从这里删掉。
  // 2026-09-28 清到 2 条，2026-09-29（J3）**清零**：shutdown:begin / shutdown:complete
  // 整链摘除并登记 RETIRED。它们不是「扩展点」而是两个真实风险面：begin 是空函数，
  // complete 会 app.exit(0) 且档位是 guard_readonly（五个窗都能强制退出应用），
  // 而关闭编排早已全在主进程（RunEvent::Exit → on_app_exit），这条 IPC 入口纯属重复。
]);

/** 递归取 src/ 下的渲染层源码（适配层自身除外：它定义包装器，不是调用点） */
function rendererSources(dir, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) rendererSources(p, out);
    else if (/\.(?:js|html)$/.test(e.name) && !p.endsWith(`tauri-api.js`)) {
      // `?.` 归一：渲染层大量写 `window.api?.x?.y()`，不归一会把在用通道判成孤儿
      out.push([relative(TAURI_ROOT, p), readFileSync(p, 'utf8').replace(/\?\./g, '.')]);
    }
  }
  return out;
}

/** 从适配层的 `var api = {…}` 里解析「通道 → window.api 点路径」 */
function parseApiPaths(text) {
  const lines = text.split('\n');
  const start = lines.findIndex(l => l.startsWith('  var api = {'));
  if (start < 0) throw new Error('适配层里没找到 `var api = {`，D4 无从解析');
  let end = -1;
  for (let i = start + 1; i < lines.length; i++) if (/^  \};/.test(lines[i])) { end = i; break; }
  if (end < 0) throw new Error('`var api = {` 块收尾没找到（缩进变了？）');
  const stack = [];
  const map = new Map();
  for (let i = start + 1; i < end; i++) {
    const l = lines[i];
    if (/^\s*\/[/*]/.test(l)) continue;            // 注释行不参与结构判定
    const ind = l.match(/^\s*/)[0].length;
    const open = l.match(/^\s*([A-Za-z_$][\w$]*)\s*:\s*\{/);
    if (open) {
      while (stack.length && stack[stack.length - 1].ind >= ind) stack.pop();
      stack.push({ key: open[1], ind });
      continue;
    }
    const key = l.match(/^\s*([A-Za-z_$][\w$]*)\s*:/);
    if (!key) continue;
    while (stack.length && stack[stack.length - 1].ind >= ind) stack.pop();
    // 函数体可能跨行（如 overview:hardware 要先整形 options），向后找通道字面量，
    // 但绝不越过下一个方法键——否则会把邻居的通道记到本键头上。
    for (let k = i; k < Math.min(i + 14, end); k++) {
      const ch = lines[k].match(/(?:invokeChannel|sendChannel)\(\s*'([^']+)'/);
      if (ch) { map.set(ch[1], [...stack.map(s => s.key), key[1]].join('.')); break; }
      if (k !== i && /^\s*[A-Za-z_$][\w$]*\s*:\s*(?:async\s+)?function/.test(lines[k])) break;
    }
  }
  return map;
}

{
  const apiPaths = parseApiPaths(adapter);
  const allChannels = new Map([...channelMap, ...sendMap]);
  const sources = rendererSources(join(TAURI_ROOT, 'src'));
  // 局部别名表：域名 → 变量名集合
  const aliases = new Map();
  const dynamic = new Set();
  for (const [, text] of sources) {
    for (const m of text.matchAll(/(?:const|let|var)\s+(\w+)\s*=\s*window\.api\.(\w+)\b/g)) {
      if (!aliases.has(m[2])) aliases.set(m[2], new Set());
      aliases.get(m[2]).add(m[1]);
    }
    // 注意 `?.` 归一后形态是 `window.api.modal.[method](...)` —— 点号还留在方括号前，
    // 所以这里的方括号前缀是可选的（写死 `api.x[` 会漏认，把在用的 modal 域误判成孤儿）。
    for (const m of text.matchAll(/window\.api\.(\w+)\s*\.?\s*\[/g)) dynamic.add(m[1]);
  }
  const used = (ch) => {
    const path = apiPaths.get(ch);
    if (!path) return false;
    const [domain, ...rest] = path.split('.');
    const method = rest.join('.');
    const needle = `.${path}`;
    for (const [, text] of sources) {
      if (text.includes(needle)) return true;
      if (dynamic.has(domain) && new RegExp(`window\\.api\\.${domain}\\s*\\.?\\s*\\[`).test(text)) return true;
      for (const v of aliases.get(domain) ?? []) {
        if (new RegExp(`\\b${v}\\.${method}\\b`).test(text)) return true;
      }
    }
    return false;
  };
  const unmappedPath = [...allChannels.keys()].filter(c => !apiPaths.has(c));
  const orphans = [...allChannels.keys()].filter(c => apiPaths.has(c) && !used(c)).sort();
  const dead = [...orphans].filter(o => !D4_ORPHANS.has(o));
  const stale = [...D4_ORPHANS.keys()].filter(o => !orphans.includes(o));
  check(
    unmappedPath.length === 0 && dead.length === 0 && stale.length === 0,
    `D4. 每条映射命令都有渲染层调用点（通道 ${allChannels.size} / 已接线 ${allChannels.size - orphans.length} / 基线内孤儿 ${orphans.length}）`,
    unmappedPath.length
      ? `这些通道在 window.api 里找不到对应方法，适配层形状变了？${JSON.stringify(unmappedPath)}`
      : dead.length
        ? `新增孤儿通道（要么接线要么整链摘除，并同步 D4 基线）${JSON.stringify(dead)}`
        : stale.length
          ? `基线里的孤儿已有调用点，请从 D4_ORPHANS 删除：${JSON.stringify(stale)}`
          : '',
  );
  if (dynamic.size) console.log(`  · D4 按「动态派发」放行的域：${[...dynamic].join(', ')}（静态面认不出方法名）`);
  if (orphans.length) {
    console.log(`  · D4 现状孤儿 ${orphans.length} 条（v2-M15 遗留，摘除或接线后要同步删基线条目）：`);
    for (const o of orphans) console.log(`      ${o} → ${apiPaths.get(o)}（命令 ${allChannels.get(o)}）：${D4_ORPHANS.get(o) ?? '未登记原因'}`);
  }

/**
 * D5 基线（2026-10-03 R1-1.2b 登记）：只读档却**只有主窗在用**的命令。
 *
 * 语义：这些命令挂 `guard_readonly`（放行全部五个窗口 label），但四个子窗没有任何一个
 * 在调它们 —— 那份放宽当前没有任何消费方在用，却把命令暴露给了全部窗口。
 *
 * **为什么是「登记基线」而不是「一条条改档」**：
 * - 改档方向会锁死功能。`modal`/`ds` 那一类公共脚本未来完全可能加上对这些命令的调用，
 *   现在锁回 MAIN 就等于提前把那条路堵死（AGENTS §3 的 M1~M3 教训）。
 * - 是否有可利用性取决于「子窗脚本有没有消费方」，静态面认不出来的那部分
 *   （如 `modal` 域的动态派发）必须靠人工判，不能靠门禁猜。
 * - 本批交付物是**棘轮**：让「新增一条白给的放宽」变红，以及「已登记的条目不再白给」
 * 也变红（豁免清单烂掉比没有更危险）。
 *
 * **棘轮方向**：本表只许**变短**。新增一条 readonly 而无子窗消费方 ⇒ 判红；
 * 表里某条后来有了子窗调用点（应当从表里删掉）⇒ 也判红。
 */
const D5_READONLY_WITHOUT_SUB_CONSUMER = new Set([
  'aidesc_get',
  'app_open_external',
  'app_read_usage',
  'appearance_set_material',
  'appearance_set_material_enabled',
  'bench_history_add',
  'bench_history_clear',
  'bench_history_delete',
  'bench_history_list',
  'cleanup_check_locked',
  'cleanup_check_rules_version',
  'cleanup_file_backup_list',
  'cleanup_item_detail',
  'cleanup_reg_backup_list',
  'cleanup_rules',
  'cleanup_scan',
  'contextmenu_backup',
  'contextmenu_blocked_list',
  'contextmenu_icons',
  'contextmenu_scan',
  'device_scan',
  'diag_dwm_conflict',
  'fileclean_scan',
  'finder_delete_manifest',
  'finder_open_backup_dir',
  'finder_scan',
  'fonts_import',
  'fonts_list',
  'fonts_remove_imported',
  'fonts_save_config',
  'intro_load',
  'log_export',
  'log_read',
  'maintenance_tasks',
  'memory_info',
  'models_open_window',
  'models_set_scope',
  'netcheck_collect',
  'optimizer_batch_preflight',
  'optimizer_check_optimized',
  'optimizer_check_restore',
  'optimizer_genadvice',
  'optimizer_list',
  'optimizer_list_restore',
  'optimizer_state_overview',
  'optimizer_svc_mem_current',
  'overview_checkup',
  'overview_hardware',
  'overview_metrics',
  'paths_app_icon',
  'paths_browse',
  'paths_load',
  'paths_save',
  'paths_scan',
  'peripheral_open_window',
  'preview_open_window',
  'process_manager_open_window',
  'quickcmds_run',
  'realtime_adapters',
  'realtime_loss',
  'realtime_report_clear',
  'realtime_report_delete',
  'realtime_report_get',
  'realtime_report_list',
  'realtime_report_save',
  'realtime_sample',
  'runtimes_collect',
  'startup_openlocation',
  'startup_scan',
  'system_disk_list',
  'system_disk_type',
  'uninstall_appx_logo',
]);

  // ---- D5. 只读档必须真有子窗消费方（R1-1.2b 补，独立真源） ----
  //
  // 为什么需要这一组（判红实验实测出来的缺陷，不是我预想的）：
  // D 组是「代码档位 ⇄ MUST_READONLY 清单」双向对拍，而**清单是人维护的**。
  // 实测把某readonly 命令改成 MAIN、并同步把登记从 MUST_READONLY 挪进 MUST_MAIN
  // 后，A/B/C/D/E **五组全部绿** —— 两边一起改，双向对拍永远自洽。
  // 只在 D 组里加断言治不了这个，因为改档的人会顺手改清单。
  //
  // 独立真源 = **子窗 HTML 实际加载的脚本里的调用点**。清单改不动 HTML：
  // 想把一条只有主窗消费的 readonly 命令留在 readonly 档，就必须让某个子窗真的调它，
  // 否则这里红。按 AGENTS §3「档位以谁真的需要调它为准」—— readonly 档的价值就是
  // 「四个子窗也放行」，**没有一个子窗消费方，那份放宽就是白给的攻击面**。
  //
  // 口径与 D4 同源（复用 apiPaths / aliases / dynamic 推导，不另造一套匹配）：
  //   - readonly 档命令 ⇒ 至少一个**子窗专属**脚本里有调用点；
  //   - MAIN 档命令 ⇒ 不许有子窗调用点（有的话说明档位写松了，应下放而不是锁死）。
  const SRC_DIR = join(TAURI_ROOT, 'src');
  const htmlFiles = readdirSync(SRC_DIR).filter((f) => f.endsWith('.html'));
  const MAIN_HTML = 'index.html';
  // 子窗加载的脚本基名集合（tauri-api.js 被所有窗口加载，是适配层不是业务面，排除）
  const subScriptNames = new Set(['tauri-api.js']);
  for (const h of htmlFiles) {
    if (h === MAIN_HTML) continue;
    const txt = readFileSync(join(SRC_DIR, h), 'utf8').replace(/\?\./g, '.');
    for (const m of txt.matchAll(/src="([^"]*\.js)"/g)) {
      subScriptNames.add(m[1].split('/').pop());
    }
  }
  const subSources = sources.filter(([rel]) => {
    const base = rel.split(/[\\/]/).pop();
    // *.html 只认子窗那四个；js 按脚本基名
    return rel.endsWith('.html') ? !rel.endsWith(MAIN_HTML) : subScriptNames.has(base);
  });
  const usedIn = (ch, pool) => {
    const path_ = apiPaths.get(ch);
    if (!path_) return false;
    const [domain, ...rest] = path_.split('.');
    const method = rest.join('.');
    const needle = `.${path_}`;
    for (const [, text] of pool) {
      if (text.includes(needle)) return true;
      if (dynamic.has(domain) && new RegExp(`window\\.api\\.${domain}\\s*\\.?\\s*\\[`).test(text)) return true;
      for (const v of aliases.get(domain) ?? []) {
        if (new RegExp(`\\b${v}\\.${method}\\b`).test(text)) return true;
      }
    }
    return false;
  };

  // 档位由 guard-tiers 门禁管；这里从 Rust 侧现算 readonly / MAIN 两条命令集合。
  // 不读 check-guard-tiers.mjs 的清单（那就是 D 组，被本组取代的原因）。
  const CMD_DIR = join(TAURI_ROOT, 'src-tauri', 'src', 'commands');
  const readAllRs = (dir) => {
    const acc = [];
    const walk = (d) => {
      for (const e of readdirSync(d, { withFileTypes: true })) {
        const p = join(d, e.name);
        if (e.isDirectory()) walk(p);
        else if (e.name.endsWith('.rs')) acc.push(readFileSync(p, 'utf8'));
      }
    };
    walk(dir);
    return acc.join('\n');
  };
  const allCmdSrc = readAllRs(CMD_DIR);
  const tierOf = () => {
    const out = { MAIN: new Set(), READONLY: new Set() };
    // 必须按 `#[tauri::command]` **切段**（段尾 =下一个 `#[tauri::command]`），
    // 不能只取到 `pub fn` 为止 —— guard 调用在函数体内，取到签名就截断了。
    // 这与 check-guard-tiers.mjs 的枚举口径一致（单向依赖它反而会引入「那边改了这边跟着红」）。
    const marks = [...allCmdSrc.matchAll(/#\[tauri::command\]/g)].map((m) => m.index);
    marks.push(allCmdSrc.length);
    for (let i = 0; i < marks.length - 1; i++) {
      const seg = allCmdSrc.slice(marks[i], marks[i + 1]);
      const nm = seg.match(/pub\s+(?:async\s+)?fn\s+(\w+)/);
      if (!nm) continue;
      if (/guard::guard\(\s*&window,\s*guard::MAIN\s*\)/.test(seg)) out.MAIN.add(nm[1]);
      else if (/guard::guard_readonly\(/.test(seg)) out.READONLY.add(nm[1]);
    }
    return out;
  };
  const tiers = tierOf();
  // 命令名 → 通道名（反查 CHANNEL_MAP）
  const chanOf = new Map([...channelMap].map(([ch, cmd]) => [cmd, ch]));
  const readonlyNoSubConsumer = [];
  const readonlyGrantsNoOne = [];
  for (const cmd of [...tiers.READONLY].sort()) {
    const ch = chanOf.get(cmd);
    if (!ch) continue; // 无渲染层通道（如纯事件源）不在本组范围
    if (!usedIn(ch, subSources)) {
      // 主窗也在用 = 放宽白给（须登记）；主窗也不用 = 纯孤儿，归 D4 组管
      if (usedIn(ch, sources)) readonlyGrantsNoOne.push(cmd);
      readonlyNoSubConsumer.push(cmd);
    }
  }
  const mainWithSubConsumer = [...tiers.MAIN].filter((cmd) => {
    const ch = chanOf.get(cmd);
    return ch && usedIn(ch, subSources);
  });
  // 棘轮①：新增一条「只读却无子窗消费方」即红（表只许变短）
  const newGrants = readonlyGrantsNoOne.filter((n) => !D5_READONLY_WITHOUT_SUB_CONSUMER.has(n));
  // 棘轮②：表里的条目后来有了子窗调用点 → 豁免失效，同样红（白名单烂掉比没有更危险）
  const staleGrants = [...D5_READONLY_WITHOUT_SUB_CONSUMER].filter(
    (n) => !readonlyGrantsNoOne.includes(n),
  );
  check(
    newGrants.length === 0 && staleGrants.length === 0 && mainWithSubConsumer.length === 0,
    `D5. 只读档的放宽有子窗消费方支撑（只读 ${tiers.READONLY.size} / 已登记豁免 ${D5_READONLY_WITHOUT_SUB_CONSUMER.size} / 主窗 ${tiers.MAIN.size}）`,
    newGrants.length
      ? `新增「只读档却无子窗调用点」的白给放宽 ${JSON.stringify(newGrants)}—— 确需只读档（子窗真会调它）请先接线；确无消费方请改 MAIN 档`
      : staleGrants.length
        ? `豁免清单已失效（这些命令现在有子窗调用点了，请从 D5_READONLY_WITHOUT_SUB_CONSUMER 删除）${JSON.stringify(staleGrants)}`
        : mainWithSubConsumer.length
          ? `MAIN 档却有子窗调用点（档位写松了，应下放）${JSON.stringify(mainWithSubConsumer)}`
          : '',
  );
  if (readonlyGrantsNoOne.length) {
    console.log(`  · D5 只读档「放宽给子窗但只有主窗在用」${readonlyGrantsNoOne.length} 条（已登记豁免，逐条理由见 D5_READONLY_WITHOUT_SUB_CONSUMER）`);
  }
  if (readonlyNoSubConsumer.length > readonlyGrantsNoOne.length) {
    console.log(`  · D5 另有 ${readonlyNoSubConsumer.length - readonlyGrantsNoOne.length} 条只读命令主窗也没调用点（纯孤儿，归 D4 组管）`);
  }
}


// ---- F. 高危优化清单双源对拍（审查 L6） ----
// 后端 `HAZARD_IDS` 是「必须拿到 confirmedHighRisk 才放行」的闸门集合，前端
// `HAZARD_OPTION_IDS` 是「弹红色警示」的集合。两边各写一份、无机器校验时，漂移方向是
// **后端闸门失效**（前端不再弹警示、后端也不再要求确认），所以这里取交集差集判红。
const idsIn = (text, marker) => {
  const at = text.indexOf(marker);
  if (at < 0) return null;
  // 从 marker **末尾**起找收尾括号：Rust 的 `const HAZARD_IDS: &[&str] = &[` 中，
  // 类型标注 `&[&str]` 自带一个 `]`，从 marker 起点找会停在那儿、解析出空集合（本条 F
  // 第一次跑就是这么抓到自己的 bug 的）。
  const from = at + marker.length;
  const end = text.indexOf(']', from);
  if (end < 0) return null;
  return new Set([...text.slice(from, end).matchAll(/['"]([a-z0-9_]+)['"]/g)].map((m) => m[1]));
};
// 注意 marker 必须**吃到数组起始括号**：`const HAZARD_IDS: &[&str] = &[` 里的 `&[&str]`
// 也含 `]`，marker 截短会让下面的 indexOf(']') 在类型标注处就收尾、解析出空集合。
// v3 D4：optimizer.rs 拆成 commands/optimizer/ 目录，高危清单落在 catalog.rs。
// 读整个目录而不是点名某个文件——坐标再搬家也不用回来改这里，同时保留
// 「一个都找不到就判红」的 fail-closed 方向（idsIn 返回 null 即红）。
const readDirRs = (dir) =>
  readdirSync(dir)
    .filter((f) => f.endsWith('.rs'))
    .map((f) => readFileSync(join(dir, f), 'utf8'))
    .join('\n');
const rustOptSrc = readDirRs(join(cmdDir, 'optimizer'));
const jsOptSrc = readFileSync(join(TAURI_ROOT, 'src', 'scripts', 'optimizer.js'), 'utf8');
const rustHazard = idsIn(rustOptSrc, 'const HAZARD_IDS: &[&str] = &[');
const jsHazard = idsIn(jsOptSrc, 'const HAZARD_OPTION_IDS = new Set([');
if (!rustHazard || !jsHazard) {
  check(false, 'F. 高危清单双源对拍', '没找到 HAZARD_IDS / HAZARD_OPTION_IDS，清单被改名或删掉？');
} else {
  const onlyRust = [...rustHazard].filter((i) => !jsHazard.has(i));
  const onlyJs = [...jsHazard].filter((i) => !rustHazard.has(i));
  check(
    rustHazard.size > 0 && onlyRust.length === 0 && onlyJs.length === 0,
    `F. 高危清单双源一致（Rust ${rustHazard.size} / JS ${jsHazard.size}）`,
    onlyRust.length || onlyJs.length ? `Rust 独有 ${JSON.stringify(onlyRust)} / JS 独有 ${JSON.stringify(onlyJs)}` : '',
  );

  // ---- F2. 第三条腿：手写清单 ⇄ 数据层 risk=high（审查 v2-K3）----
  // F 只比两份手写清单，抓不到「数据层自认 high、两份清单都没登记」的漂移——v2-K3 漏的
  // 正是那 7 项（tf_appx 移除 25 个内置 UWP、tf_onedrive 彻底卸载 OneDrive，均
  // restoreAvailable:false 不可逆）。现在判据是「清单 ∪ risk==high」，于是清单侧要钉三件事：
  //   ① 清单里每个 id 都真在数据层存在（死条目会让这份清单看起来「已核对」，反向掩盖漂移）；
  //   ② 两侧的判据函数都没被退回成「只认清单」（文本锚点钉住，改回去即红）；
  //   ③ 数据层 high 的数量没有塌方（把 risk 批量降级成 medium 是绕开这条闸门的捷径）。
  const HIGH_FLOOR = 5;
  const optPath = join(TAURI_ROOT, 'src-tauri', 'data', 'optimizer-runtime.json');
  let optIds = null;
  let highIds = null;
  try {
    const arr = JSON.parse(readFileSync(optPath, 'utf8'));
    if (Array.isArray(arr)) {
      optIds = new Set(arr.map((o) => o && o.id));
      highIds = new Set(arr.filter((o) => o && o.risk === 'high').map((o) => o.id));
    }
  } catch { /* 读不到即下面判红 */ }
  if (!optIds || !highIds) {
    check(false, 'F2. 高危判据 ⇄ 数据层对拍', `读不到或不是数组：${optPath}`);
  } else {
    const dead = [...rustHazard].filter((i) => !optIds.has(i));
    // 判据②（Rust 侧）：union 公式必须仍在**执行链的判定路径上**被调用。
    // M1（2026-10-03）之后调用点从 `optimizer_run` 内联搬进了 `preflight_reason`
    // （批量预检与单条执行同源），所以锚点不再只认 `&opt, &option_id` 那一种写法——
    // 但**必须**同时钉住两件事，否则这条断言会被「把 union 判据删掉」骗过：
    //   ① `preflight_reason` 函数体里真的有 union 调用，且带 restore 方向豁免；
    //   ② `optimizer_run` 走的是 `preflight_reason`，没有自己另判一份。
    const pfAt = rustOptSrc.indexOf('fn preflight_reason');
    const preflightFn = pfAt >= 0 ? rustOptSrc.slice(pfAt, pfAt + 2000) : '';
    const preflightCallsUnion =
      preflightFn !== '' &&
      /needs_high_risk_confirm\(\s*&?opt\s*,\s*&?option_id\s*\)/.test(preflightFn) &&
      /if\s*!restore\s*&&\s*needs_high_risk_confirm\(/.test(preflightFn);
    const runDelegates = /match\s+preflight_reason\(&opt,\s*&option_id,\s*p\.restore\)/.test(rustOptSrc);
    const rustUnion = rustOptSrc.includes('fn needs_high_risk_confirm') && preflightCallsUnion && runDelegates;
    const jsUnion = jsOptSrc.includes('function needsHazardConfirm(opt)')
      && jsOptSrc.includes('needsHazardConfirm(opt)) runParams.confirmedHighRisk');
    check(
      dead.length === 0 && rustUnion && jsUnion && highIds.size >= HIGH_FLOOR,
      `F2. 高危判据三条对拍（清单 ${rustHazard.size} ∪ 数据层 high ${highIds.size}）`,
      !rustUnion || !jsUnion
        ? '判据被退回「只认手写清单」：缺 union 公式锚点（Rust：preflight_reason 内须调 needs_high_risk_confirm 且带 restore 方向豁免，optimizer_run 须委托它；JS：needsHazardConfirm）'
        : dead.length
          ? `清单里有数据层不存在的死条目 ${JSON.stringify(dead)}`
          : highIds.size < HIGH_FLOOR
            ? `数据层 risk=high 只剩 ${highIds.size} 项（下限 ${HIGH_FLOOR}）——是否有人批量降级绕过闸门`
            : ''
    );
  }
}

// ---- 迁移进度报告 ----
const migrated = [...mapped].filter(v => registered.has(v));
const total = channelMap.size + sendMap.size;
console.log(`\n迁移进度：Rust 已注册命令 ${registered.size} 条；` +
  `invoke 通道 ${channelMap.size} 中已迁 ${[...channelMap.values()].filter(v => registered.has(v)).length}，` +
  `send 通道 ${sendMap.size} 中已迁 ${[...sendMap.values()].filter(v => registered.has(v)).length}`);
console.log(`未迁移 invoke 通道（前 20）：${[...channelMap.entries()].filter(([, v]) => !registered.has(v)).slice(0, 20).map(([k]) => k).join(', ')}`);

if (STRICT) {
  const pending = [...channelMap.values(), ...sendMap.values()].filter(v => !registered.has(v));
  check(pending.length === 0 && notRegistered.length === 0, `E. --strict：全部 ${total} 条通道均已迁移`, pending.length ? `仍缺 ${pending.length} 条` : '');
}

console.log(`\n${fail === 0 ? '门禁通过' : `${fail} 项未通过`}`);
process.exit(fail === 0 ? 0 : 1);
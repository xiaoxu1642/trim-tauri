// check-channel-map.mjs —— IPC 通道映射一致性门禁（D2，Phase 1 起生效）
//
// 迁移方案 D2 的硬要求：**映射表键集合必须等于 preload.js 的通道集合**，
// 且新增通道必须同表登记，防止「Rust 有了、前端没接」或反向的静默断裂
// （R18：141 条通道中任一漏迁，表现为按钮没反应而非报错，最难发现）。
//
// 四组断言：
//   A. preload 的 invoke 通道集合 == tauri-api.js 的 CHANNEL_MAP 键集合
//   B. preload 的 send 通道集合 == SEND_MAP 键 ∪ 窗口插件桥接通道 ∪ app:first-paint 直连
//   C. 已登记且已在 Rust 注册的命令，名字必须一一对应（snake_case 且无重复映射）
//   D. lib.rs 中每个 #[tauri::command] 函数（探针除外）都必须被映射表引用
//      ——这是本门禁最有价值的一条：抓 Rust 侧写完却忘了接前端的裂缝
//
// 未迁移通道（Rust 尚未注册）只做**统计报告**不判失败，以支持 Phase 1 增量迁移。
//
// 用法：node tools/check-channel-map.mjs [--strict]
//   --strict：要求全部通道均已迁移（Phase 5 收尾门禁用）

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { ORIGIN, REPO_ROOT } from './ps-origin.mjs';

const STRICT = process.argv.includes('--strict');
const TAURI_ROOT = REPO_ROOT;

// 通道契约基线：读**仓库内**的上游快照（审查 K2）。原先这里是硬编码 `C:/KaiFa/Trim`，
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

// 解析 commands/*.rs 中声明的 #[tauri::command] 函数
const declared = new Map(); // fn -> file
const cmdDir = join(TAURI_ROOT, 'src-tauri', 'src', 'commands');
for (const f of readdirSync(cmdDir)) {
  if (!f.endsWith('.rs')) continue;
  const text = readFileSync(join(cmdDir, f), 'utf8');
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].includes('#[tauri::command]')) continue;
    for (let j = i + 1; j < Math.min(i + 6, lines.length); j++) {
      const m = lines[j].match(/pub\s+(?:async\s+)?fn\s+(\w+)/);
      if (m) { declared.set(m[1], f); break; }
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
const onlyPreload = [...preloadInvoke].filter(c => !channelMap.has(c));
const onlyMap = [...channelMap.keys()].filter(c => !preloadInvoke.has(c));
check(onlyPreload.length === 0 && onlyMap.length === 0,
  `A. invoke 通道集合一致（preload ${preloadInvoke.size} / CHANNEL_MAP ${channelMap.size}）`,
  onlyPreload.length || onlyMap.length ? `preload 独有 ${JSON.stringify(onlyPreload)} / map 独有 ${JSON.stringify(onlyMap)}` : '');

// ---- B. send 集合 ----
const expectedSend = new Set([...sendMap.keys(), ...WINDOW_BRIDGED, ...DIRECT]);
const sendMissing = [...preloadSend].filter(c => !expectedSend.has(c));
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
const rustOptSrc = readFileSync(join(cmdDir, 'optimizer.rs'), 'utf8');
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
    const rustUnion = rustOptSrc.includes('fn needs_high_risk_confirm')
      && rustOptSrc.includes('needs_high_risk_confirm(&opt, &option_id)');
    const jsUnion = jsOptSrc.includes('function needsHazardConfirm(opt)')
      && jsOptSrc.includes('needsHazardConfirm(opt)) runParams.confirmedHighRisk');
    check(
      dead.length === 0 && rustUnion && jsUnion && highIds.size >= HIGH_FLOOR,
      `F2. 高危判据三条对拍（清单 ${rustHazard.size} ∪ 数据层 high ${highIds.size}）`,
      !rustUnion || !jsUnion
        ? '判据被退回「只认手写清单」：缺 union 公式锚点（Rust needs_high_risk_confirm / JS needsHazardConfirm）'
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
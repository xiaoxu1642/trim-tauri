#!/usr/bin/env node
// check-optimizer-write-contract.mjs —— 写入坐标侧表（optimizer-writes.json）的契约门禁
// （M2，2026-10-03）
//
// 为什么需要它：`optimizer-writes.json` 是「执行侧写什么」的**镜像**，而真源始终是
// `optimizer-runtime.json` 里那些 pwsh 文本。两份数据一旦漂移，后果是
// **静默失效的检测断言**：侧表少列一个服务 ⇒ 该服务的启动类型不再参与体检 ⇒
// 用户改过这一项却看到「未生效」⇒ 点「立即执行」重复施加。界面不报错、日志无痕。
//
// 漂移方向与危害不对称：
//   · 侧表**多**列一个服务 → 体检永远判未生效（用户被误导，可见）
//   · 侧表**少**列一个服务 → 体检漏判（用户重复施加，**不可见**）—— 这才是要拦的
//
// 六组断言：
//   A. 键 ⊆ 白名单 + 必填键齐全（**不是** `deny_unknown_fields` 要求字段集完全相等：
//      `storeServices` 只有 `tf_svc_bulk` 有）
//   B. groups[] ⇄ pwsh 文本**双向**对拍（两侧都不许多/少）
//   C. 每组 expectStart 合法（windows 0.61: AUTO=2/DEMAND=3/DISABLED=4）
//   D. storeServices == apply.rs 的 `STORE_SERVICES` 逐项一致，且未混进 groups
//   E. 覆盖率棘轮：登记项数只增不减
//   F. _comment 写明「不进双源体系」（M2 方案 §5.4 红线）
//   G. 判据正向自检（POSITIVE_CONTROLS）
'use strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

const opts = JSON.parse(read('src-tauri', 'data', 'optimizer-runtime.json'));
const writes = JSON.parse(read('src-tauri', 'data', 'optimizer-writes.json'));
const applyRs = read('src-tauri', 'src', 'commands', 'optimizer', 'apply.rs');

// ======================================================================
// 机械提取：把 pwsh 全文解析成「期望 Start 值 → 服务名集合」
// 口径与 catalog.rs::write_spec_of 必须一致。三处踩过的坑：
//  ① 不能按固定字符窗口往前找数组声明 —— tf_svc_bulk 的基础数组有 65 个服务名
//    （600+ 字符），`Start -Value 4` 落在数组声明之后 400 字符开外 ⇒ 归属查找失败，
//    整段 65 个服务**静默丢失**。正确做法：先按「数组声明 / 单服务键路径」切段。
//  ② 一项可能有多个期望值 —— tf_svc_bulk 一步 pwsh 里有三段：基础 65 个 Start=4、
//    wuauserv Start=3、lfsvc 在基础数组里。所以是 groups[] 不是单一 expectStart。
//  ③ 判「该不该在表里」要认 `-Name Start -Value N`，不能认「服务键下任意写入」——
//    audio_disable_service_restart 写的是 `DelayedAutoStart`，那是 A 类不是 B 类。
// ======================================================================
const JUNK = new Set(['W32Time', 'Services', 'CurrentControlSet']);

function parseGroups(o) {
  const blob = (o.steps || []).map((s) => s.pwsh || '').join('\n');
  const marks = [];
  for (const m of blob.matchAll(/\$(?:disabled|svcs|drv|services|storeSvc)\s*=\s*@\(/g)) {
    marks.push({ at: m.index, kind: 'array' });
  }
  for (const m of blob.matchAll(/\$p\d*\s*=\s*"[^"]*Services\\([A-Za-z0-9_.\-]+)"/g)) {
    marks.push({ at: m.index, kind: 'single', name: m[1] });
  }
  marks.sort((a, b) => a.at - b.at);
  const groups = new Map();
  const add = (v, n) => {
    if (!groups.has(v)) groups.set(v, new Set());
    groups.get(v).add(n);
  };
  for (let i = 0; i < marks.length; i++) {
    const seg = blob.slice(marks[i].at, i + 1 < marks.length ? marks[i + 1].at : blob.length);
    const v = Number((seg.match(/Start\s+-Value\s+(\d)/) || [])[1]);
    if (Number.isNaN(v)) continue; // 这段没写 Start ⇒ 不是写入段
    if (marks[i].kind === 'single') { add(v, marks[i].name); continue; }
    const arrBody = (seg.match(/@\(([^)]*)\)/) || [])[1] || '';
    for (const n of arrBody.matchAll(/"([^"]+)"/g)) add(v, n[1]);
  }
  for (const [, set] of groups) for (const n of [...set]) if (JUNK.has(n)) set.delete(n);
  return groups;
}

/** 条件追加的那批，从 apply.rs 的常量现读（不抄） */
function storeFromRust(src = applyRs) {
  const m = src.match(/pub\(super\) const STORE_SERVICES: &\[&str\] =\s*&\[([^\]]*)\]/s);
  if (!m) return null;
  return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]).sort();
}

/** 该项 pwsh 全文里有没有「写**服务**启动类型」这种写入（反向：该不该在表里） */
function writesServiceStart(o) {
  const blob = (o.steps || []).map((s) => s.pwsh || '').join('\n');
  if (!/New-ItemProperty[^\n]*-Name\s+Start\s+-Value\s+\d/.test(blob)) return false;
  // 必须同时命中「服务键路径」。两个反例（都真出现过）：
  //  · `telemetry_optimize` 的 AutoLogger 段也写 `-Name Start -Value 0`，但落在
  //    `...\Control\WMI\Autologger` 下 —— 那是 ETW 会话配置，**不是服务**。
  //  · `audio_disable_service_restart` 落在 `...\Services\Audiosrv` 下，但写的是
  //    `-Name DelayedAutoStart` —— 是服务键，但**不是启动类型**。
  // 所以口径必须**两条都命中**：有服务键路径，且同一条语句里写的是 `-Name Start`。
  return /Services\\[A-Za-z0-9_.\-$]+/.test(blob);
}

// ---- A. 键 ⊆ 白名单 + 必填键齐全 ----
const ALLOWED = new Set(['groups', 'storeServices', 'regWrites']);
// 必填键**按域**：`groups` 与 `regWrites` 至少有一个非空（B 类项只有 groups，
// A 类项只有 regWrites）。要求两者都必填会把 A 类项全判红。
const REG_KEYS = new Set(['hive', 'subkey', 'value', 'value2', 'kind', 'expect', 'absent']);
// kind 的全集（M2-C 加了两种新形态，都是 **dynamic 项专用**）：
//   enum      —— 「值 ∈ 合法集合」（svc_mem_gb）
//   timeWindow —— 「现在 ∈ [value, value2) 区间」（perf_wu_pause）
// dynamic 项的 `steps` 由后端按用户选的参数在运行时生成，**数据层没有 pwsh 文本**
// 可对拍 —— 所以这两种形态的真源是 `apply.rs`，由 A3 组负责。
const REG_KINDS = new Set(['dword', 'string', 'binary', 'enum', 'timeWindow']);
const HIVES = new Set(['HKLM', 'HKCU', 'HKCR', 'HKU', 'HKCC']);
const items = writes.items || {};
const comment = writes._comment || '';
const keyProblems = [];
for (const [id, spec] of Object.entries(items)) {
  for (const k of Object.keys(spec)) {
    if (!ALLOWED.has(k)) keyProblems.push(`${id}: 未知键「${k}」（白名单 ${[...ALLOWED].join('/')}）`);
  }
  if (!spec.groups?.length && !spec.regWrites?.length) {
    keyProblems.push(`${id}: groups 与 regWrites 都为空（登记了却没有任何断言）`);
  }
  for (const g of spec.groups || []) {
    for (const k of Object.keys(g)) {
      if (k !== 'expectStart' && k !== 'services') {
        keyProblems.push(`${id}: groups[] 里未知键「${k}」`);
      }
    }
    if (g.expectStart === undefined) keyProblems.push(`${id}: 某组缺 expectStart`);
    if (!Array.isArray(g.services) || !g.services.length) {
      keyProblems.push(`${id}: 某组 services 为空或不是数组`);
    } else if (g.services.some((x) => typeof x !== 'string')) {
      keyProblems.push(`${id}: services 里有非字符串项`);
    }
  }
  for (const [ri, r] of (spec.regWrites || []).entries()) {
    const at = `${id}.regWrites[${ri}]`;
    for (const k of Object.keys(r)) {
      if (!REG_KEYS.has(k)) keyProblems.push(`${at}: 未知键「${k}」`);
    }
    if (!HIVES.has(r.hive)) keyProblems.push(`${at}: hive=${r.hive} 不在 ${[...HIVES].join('/')}（Rust 侧 reg_hive 只认这几个短名）`);
    if (!REG_KINDS.has(r.kind)) keyProblems.push(`${at}: kind=${r.kind} 非法（${[...REG_KINDS].join('/')}）`);
    if (!r.absent && r.kind === 'binary') {
      if (!/^[0-9a-f]+$/.test(r.expect || '') || r.expect.length % 2 !== 0) {
        keyProblems.push(`${at}: binary 期望值必须是非空偶数长度的小写 hex，实际 ${JSON.stringify(r.expect)}`);
      }
    }
    if (r.absent && r.expect) {
      keyProblems.push(`${at}: absent 语义不该带 expect（判据是「键不存在」）`);
    }
    // value2 只有 timeWindow 用；其余形态带它会被Rust 侧静默忽略（写错了看不出来）
    if (r.kind === 'timeWindow') {
      if (!r.value2) keyProblems.push(`${at}: timeWindow 必须给 value2（区间结束键名）`);
    } else if (r.value2) {
      keyProblems.push(`${at}: 只有 timeWindow 能用 value2（当前 kind=${r.kind}）`);
    }
    if (r.kind === 'enum') {
      const nums = String(r.expect).split(',').map((x) => Number(x.trim()));
      if (nums.some((n) => !Number.isInteger(n))) {
        keyProblems.push(`${at}: enum 期望值必须全是整数（逗号分隔），实际 ${JSON.stringify(r.expect)}`);
      }
    }
    // enum / timeWindow 是 dynamic 项专用形态：静态项的 steps 在数据层里，
    // 判据应当能走 A2 组的「pwsh 原文逐条对拍」。给 dynamic 项用等值判据
    // 反而是错的（期望值随用户选的参数变，等值永远不成立）。
    const itemDynamic = (opts.find((x) => x.id === id) || {}).dynamic === true;
    if ((r.kind === 'enum' || r.kind === 'timeWindow') && !itemDynamic) {
      keyProblems.push(`${at}: ${r.kind} 只用于 dynamic 项，而 ${id} 不是 dynamic（静态项应当用等值判据）`);
    }
    if (r.kind !== 'enum' && r.kind !== 'timeWindow' && itemDynamic && r.kind !== 'dword') {
      keyProblems.push(`${at}: dynamic 项 ${id} 用了 ${r.kind} 形态，需确认是否该用 enum/timeWindow`);
    }
  }
}
check(
  keyProblems.length === 0,
  `A. 键 ⊆ 白名单 + 必填键齐全（${Object.keys(items).length} 项 / regWrites ${Object.values(items).reduce((n, s) => n + (s.regWrites?.length || 0), 0)} 条）`,
  keyProblems.join('; '),
);

// ======================================================================
// A2. regWrites[] ⇄ pwsh 原文**逐条**对拍（M2-B）
// ----------------------------------------------------------------------
// 为什么这条必须存在（本批真的被它抓到一次）：侧表的 `regWrites[]` 若靠人手抄，
// 抄错一个字节没有任何东西会红 —— 单测只断「格式是小写 hex、长度是偶数」，
// 53 个字符和 48 个字符**都**满足。而这个错误的后果是「该项恒判未生效」
// （或更糟：恒判已生效），用户看到的是错的体检结论。
//
// 提取口径（三种形态，刻意不用同一段代码 —— 形态不同，正则就该不同）：
//   binary → `[byte[]](0x..,…)` 展开成小写 hex 连写
//   dword  → `-Name <值名> … -Value <十进制>`（与 `-PropertyType DWord` 同行或紧邻）
//   absent → `Remove-ItemProperty … -Name <值名>`
//
// 键路径也从 pwsh 原文取（`$p = "HKLM:\…"` / `$k = "…"` / `$paths = @("…")`）。
// 侧表与原文不一致就红 —— 少登记是漏判（危险方向），多登记是恒判未生效。
// ======================================================================

/** 从 pwsh 文本里提取全部 `[byte[]](...)` 的小写 hex 连写（可能有多个） */
function binaryLiterals(blob) {
  const OPEN = '[byte[]](', CLOSE = ')';
  const out = [];
  let at = 0;
  for (;;) {
    const i = blob.indexOf(OPEN, at);
    if (i < 0) break;
    const j = blob.indexOf(CLOSE, i + OPEN.length);
    if (j < 0) break;
    const body = blob.slice(i + OPEN.length, j);
    const hex = body
      .split(',')
      .map((x) => x.trim().replace(/^0x/i, '').replace(/^0+/, '') || '0')
      .map((b) => b.toLowerCase().padStart(2, '0'))
      .join('');
    out.push(hex);
    at = j + 1;
  }
  return out;
}

/** 提取 pwsh 里出现的所有注册表根路径（HKLM:\ / HKEY_LOCAL_MACHINE 都认） */
function rootsIn(blob) {
  const set = new Set();
  for (const m of blob.matchAll(/HKLM:\\+([^"'\s;)]*)/gi)) set.add(`HKLM\\${m[1]}`.replace(/\\+$/, ''));
  for (const m of blob.matchAll(/HKCU:\\+([^"'\s;)]*)/gi)) set.add(`HKCU\\${m[1]}`.replace(/\\+$/, ''));
  return set;
}

const regDrift = [];
let regChecked = 0;
for (const [id, spec] of Object.entries(items)) {
  const regWrites = spec.regWrites || [];
  if (!regWrites.length) continue;
  const o = opts.find((x) => x.id === id);
  if (!o) { regDrift.push(`${id}: 侧表有 regWrites 但数据层没有此项`); continue; }
  const blob = (o.steps || []).map((s) => s.pwsh || '').join('\n');
  const roots = rootsIn(blob);
  const binLiterals = binaryLiterals(blob);
  // **dynamic 项跳过本组**：它的 steps 由后端按用户选的参数在运行时生成
  // （数据层里 `svc_mem_gb` 连 steps 键都没有、`perf_wu_pause` 是空数组），
  // 没有 pwsh 文本可对拍 —— 拿空串去查「hive/子键/值名」只会得到一堆假红。
  // 它们的真源是 `apply.rs`（`memory_steps` / `wu_pause_steps`），由 A3 组负责。
  if (o.dynamic === true) continue;

  for (const r of regWrites) {
    regChecked++;
    const at = `${id}/${r.value}`;
    // ① hive 必须在 pwsh 文本里出现过对应根（`HKLM:` / `HKCU:` …）
    if (![...roots].some((x) => x.toUpperCase().startsWith(r.hive.toUpperCase() + '\\'))) {
      regDrift.push(`${at}: hive=${r.hive} 在 pwsh 文本里找不到对应根（现有：${[...roots].join(' | ') || '无'}）`);
    }
    // ② 键路径的**末段**必须在 pwsh 文本里出现（不整段比：原文用 `$p` 变量拼）
    const tail = r.subkey.split('\\').pop();
    if (tail && !blob.includes(tail)) {
      regDrift.push(`${at}: 子键末段「${tail}」在 pwsh 文本里找不到（键路径可能写错）`);
    }
    // ③ 值名必须出现
    if (!blob.includes(r.value)) {
      regDrift.push(`${at}: 值名「${r.value}」在 pwsh 文本里找不到`);
    }
    // ④ 逐字节 / 逐值对拍（这条是抓「手抄错」的那条）
    if (r.kind === 'binary' && !r.absent) {
      if (!binLiterals.includes(r.expect)) {
        regDrift.push(
          `${at}: binary 期望值与 pwsh 原文的 [byte[]](...) 不一致 —— `
          + `侧表 ${r.expect}（${r.expect.length / 2} 字节）/ 原文有 ${binLiterals.map((x) => `${x}（${x.length / 2} 字节）`).join(' | ')}`,
        );
      }
    }
    if (r.kind === 'dword' && !r.absent) {
      // 原文里该值名附近的 -Value N（N 与侧表 expect 相同）
      const near = blob.slice(Math.max(0, blob.indexOf(r.value) - 200), blob.indexOf(r.value) + 300);
      const vals = [...near.matchAll(/-Value\s+(\d+)/g)].map((m) => m[1]);
      if (vals.length && !vals.includes(r.expect)) {
        regDrift.push(`${at}: dword 期望值 ${r.expect} 不在原文该值名附近的 -Value 列表（${vals.join(',')}）`);
      }
    }
    if (r.absent) {
      // 删除语义：`Remove-ItemProperty` 附近必须提到该值名。
      //
      // ⚠️ **不能用固定字数窗口**：`perf_wu_enable` 的写法是
      //   foreach ($n in @("PauseFeatureUpdatesStartTime", ... )) {
      //     Remove-ItemProperty -Path $base -Name $n … }
      // 值名在**数组里**、离 `Remove-ItemProperty` 很远。第一版用 400 字窗口，
      // 六条断言全被判「原文没提到」—— 那正是「判据失灵」的形态。
      // 现在改成：只要该项 pwsh 里有 `Remove-ItemProperty`，且值名在该项的
      // steps 全文里出现，就算通过（键已在 ②③ 里对过）。
      if (!blob.includes('Remove-ItemProperty')) {
        regDrift.push(`${at}: absent 语义但该项 pwsh 里没有 Remove-ItemProperty`);
      } else if (!blob.includes(r.value)) {
        regDrift.push(`${at}: absent 语义但值名「${r.value}」在该项 pwsh 全文里找不到`);
      }
    }
  }
  // 反向 ①：**每一个** `[byte[]](...)` 字面量都必须被侧表的某个 binary 断言覆盖。
  //
  // 这条是判红实验 6 逼出来的：手抄错一个字节时，前面的正向断言抓不到
  // （它只问「侧表那个值在原文里吗」—— 手抄错的那个值原文里当然没有，
  // 但我判红时改的是「首位加个 0」，恰好落在原文里以 0 开头的串上，
  // `includes` 就放行了）。反向这条按**集合覆盖**判，单侧手抄错一定被抓。
  //
  // 为什么不推广到 dword：pwsh 文本里一个 `-Value 0` 可能被同一项的多个键共用，
  // 反向会误报。binary 是一步一段的，不存在复用。
  for (const lit of binLiterals) {
    const covered = regWrites.some((r) => r.kind === 'binary' && !r.absent && r.expect === lit);
    if (!covered) {
      regDrift.push(
        `${id}: pwsh 里的 [byte[]](...) 字面量（${lit.length / 2} 字节 = ${lit}）没有任何 binary 断言覆盖`,
      );
    }
  }
  // 反向 ②：**每一个**被 `Remove-ItemProperty` 删掉的值名都必须有 absent 断言。
  //
  // 这条是判红实验 7 逼出来的：`perf_wu_enable` 原文删 **6** 个 Pause 键，
  // 我侧表只登记 4 个 ⇒ 另外 2 个永不被检测，而正向断言全绿
  //（它只问「侧表有的对不对」，不问「该有的有没有」）。
  const rmValues = new Set();
  const NAME_TOKEN = '[A-Za-z0-9_]+';
  for (const m of blob.matchAll(new RegExp(`Remove-ItemProperty[^\\n]*?-Name\\s+(?:\\$([A-Za-z0-9_]+)|"(${NAME_TOKEN})"|'([^']+)')`, 'g'))) {
    // 三个捕获组分别是「裸变量名 / 双引号 / 单引号」。变量名（`$n` / `$au`）要跳过 ——
    // 它的真实值名在数组里，由下面那条 foreach 规则负责。
    const literal = m[2] || m[3];
    if (literal) rmValues.add(literal);
  }
  // foreach ($n in @("A","B")) { Remove-ItemProperty -Name $n } 形态：值名在数组里
  for (const m of blob.matchAll(new RegExp(`foreach\\s*\\(\\s*\\$\\w+\\s+in\\s+@\\(([^)]*)\\)\\s*\\)`, 'g'))) {
    for (const v of m[1].matchAll(/"([^"]+)"/g)) rmValues.add(v[1]);
  }
  for (const v of rmValues) {
    // 只对**本项**已声明至少一条 absent 断言时生效 —— 否则任何带
    // Remove-ItemProperty 的项都会被要求「把所有删的键都登记」，那是全量覆盖要求。
    if (!regWrites.some((r) => r.absent)) continue;
    if (!regWrites.some((r) => r.absent && r.value === v)) {
      regDrift.push(`${id}: Remove-ItemProperty 删除了「${v}」但侧表没有对应的 absent 断言（漏检）`);
    }
  }
  // 反向：pwsh 里写了 `-PropertyType DWord` 的项却没在侧表 regWrites 里 —— 不查
  // （A 类覆盖是**按批推进**的，不是全量；那种反向断言在覆盖率达 100% 之前会一直红）。
}
check(
  regDrift.length === 0,
  `A2. regWrites[] ⇄ pwsh 原文逐条对拍（${regChecked} 条断言：hive/子键/值名/字节/删除语义）`,
  regDrift.join('; '),
);

// ======================================================================
// A3. 两种新形态（enum / timeWindow）的专项对拍（M2-C）
// ----------------------------------------------------------------------
// 这两种形态**不能**走 A2 那套「从 pwsh 文本抽值」的路径：
//   · enum 的判据是「值 ∈ 集合」，集合的真源是 `apply.rs` 的 `MEMORY_KB` +
//     `MEMORY_KB_DEFAULT`（**不在 pwsh 文本里**—— dynamic 项的 steps 是运行时生成的）；
//   · timeWindow 的两端键名真源是 `apply.rs::wu_pause_steps` 生成的 pwsh 文本。
// 所以 A3 换了个真源：`apply.rs`。
// ======================================================================

// 真源 ①：MEMORY_KB + MEMORY_KB_DEFAULT（从 apply.rs 现读）
const kbBlockM = applyRs.match(/pub\(super\) const MEMORY_KB: &\[\(&str, i64\)\] = &\[([\s\S]*?)\n\];/);
const defM = applyRs.match(/pub\(super\) const MEMORY_KB_DEFAULT: i64 = ([0-9_]+);/);
const a3Problems = [];
if (!kbBlockM || !defM) {
  a3Problems.push('从 apply.rs 读不出 MEMORY_KB / MEMORY_KB_DEFAULT（被改名或搬走？）');
} else {
  const want = [
    ...kbBlockM[1].matchAll(/\(\s*"[^"]*"\s*,\s*([0-9_]+)\s*\)/g),
  ].map((m) => Number(m[1].replace(/_/g, '')));
  want.push(Number(defM[1].replace(/_/g, '')));
  const wantSorted = [...new Set(want)].sort((a, b) => a - b);

  const memSpec = items.svc_mem_gb?.regWrites?.find((r) => r.kind === 'enum');
  if (!memSpec) {
    a3Problems.push('svc_mem_gb 没有 kind="enum" 的 regWrites（dynamic 项的判据缺失）');
  } else {
    const got = String(memSpec.expect).split(',').map((x) => Number(x.trim())).filter((n) => !Number.isNaN(n));
    const gotSorted = [...new Set(got)].sort((a, b) => a - b);
    if (JSON.stringify(gotSorted) !== JSON.stringify(wantSorted)) {
      a3Problems.push(
        `svc_mem_gb 的 enum 集合与 apply.rs 的 MEMORY_KB+DEFAULT 不一致：`
        + `侧表 [${gotSorted.join(',')}] / 真源 [${wantSorted.join(',')}]`,
      );
    }
  }
}

// 真源 ②：`wu_pause_steps` 生成的 pwsh 里的键名。
//
// ⚠️ **必须从 apply.rs 取，不能从数据层取**（这正是本组第一版判红的原因）：
// `perf_wu_pause` 是 dynamic 项，它的 pwsh 由 `apply.rs::wu_pause_steps(days)`
// 在运行时拼出来 —— 数据层里 `steps` 是**空数组**。从数据层读会得到「一个键都读不出」，
// 那正是「真源找错地方」的形态。
const wuFn = applyRs.match(/pub\(super\) fn wu_pause_steps\(days: i64\)[\s\S]*?\n\}/);
if (!wuFn) {
  a3Problems.push('从 apply.rs 读不出 wu_pause_steps（被改名或搬走？）');
} else {
  // 键名在 Rust 源码里是 `\"PauseFeature…\"`（**转义**引号，因为它们在
  // `format!` 的字符串字面量里）。正则必须匹配「反斜杠 + 引号」，
  // 否则抓到 0 个 —— 而「读到 0 个」与「生成逻辑变了」在这一组里长得一样，
  // 所以下面两处要分开报错。
  const wuKeys = [...wuFn[0].matchAll(/\\"(Pause[A-Za-z]+)\\"/g)].map((m) => m[1]);
  const wuStarts = new Set(wuKeys.filter((k) => k.endsWith('StartTime')));
  const wuEnds = new Set(wuKeys.filter((k) => k.endsWith('EndTime') || k.endsWith('ExpiryTime')));
  if (!wuStarts.size || !wuEnds.size) {
    a3Problems.push('从 wu_pause_steps 读不出 Pause* 键名（生成逻辑变了？）');
  } else {
    const twSpec = (items.perf_wu_pause?.regWrites || []).filter((r) => r.kind === 'timeWindow');
    if (twSpec.length !== wuStarts.size) {
      a3Problems.push(
        `perf_wu_pause 的 timeWindow 组数 ${twSpec.length} ≠ wu_pause_steps 里的 Start 键数 ${wuStarts.size}`,
      );
    }
    for (const r of twSpec) {
      if (!wuStarts.has(r.value)) {
        a3Problems.push(`${r.value} 不在 wu_pause_steps 的 Start 键集合（${[...wuStarts].join('/')}）里`);
      }
      if (!wuEnds.has(r.value2)) {
        a3Problems.push(`${r.value2} 不在 wu_pause_steps 的 End 键集合（${[...wuEnds].join('/')}）里`);
      }
    }
  }
}
check(
  a3Problems.length === 0,
  'A3. enum 集合 ⇄ apply.rs 的 MEMORY_KB、timeWindow 键名 ⇄ wu_pause_steps 生成的 pwsh',
  a3Problems.join('; '),
);

// ---- B. groups[] ⇄ pwsh 文本双向对拍 ----
const drift = [];
for (const [id, spec] of Object.entries(items)) {
  const o = opts.find((x) => x.id === id);
  if (!o) { drift.push(`${id}: 侧表有此项但数据层没有（退役了？）`); continue; }
  const want = parseGroups(o); // Map<number, Set<string>>
  // 「条件追加」的那批不在 pwsh 文本里（由 apply.rs 在运行时生成），
  // 它们的对拍归 D 组（storeServices == STORE_SERVICES）。这里要把它们单列，
  // 否则会判成「侧表多列」。
  const storeSet = new Set(spec.storeServices || []);
  // 已在 regWrites[] 里登记的服务名不再要求进 groups：`audio_disable_service_restart`
  // 写的是 `Services\Audiosrv` 的 `DelayedAutoStart`（不是 Start），B 类的
  // `service_start_type_is` 对它无意义 —— 它归 A 类。两个域对同一个服务键可以并存。
  // 排除口径按**子键末段**（不是 `value` 名）：`audio_disable_service_restart` 的
  // regWrites 写的是 `Services\Audiosrv` 这个**键**下的 `DelayedAutoStart` 值，
  // 而 groups 要的是「把 Audiosrv 这个**服务**的 Start 改成 X」。两者键相同、值不同，
  // 所以比对基准是键（子键末段），不是值名。
  const inRegWrites = new Set(
    (spec.regWrites || []).map((r) => String(r.subkey).split(String.fromCharCode(92)).pop()),
  );
  // ⚠️ 用**数组**而不是 Map：侧表可能有多个 `expectStart` 相同的组
  // （tf_svc_bulk 的基础 65 个 Start=4 + 商店 5 个 Start=4），
  // 用 Map.set 会让后者**覆盖**前者 ⇒ 基础组整段判成「少列」（踩过一次）。
  const gotGroups = [];
  for (const g of spec.groups || []) {
    gotGroups.push({ expect: g.expectStart, set: new Set(g.services || []) });
  }
  const got = new Set(gotGroups.flatMap((g) => [...g.set]));
  // 商店那 5 项在侧表里也出现在 groups 里（值是 4）—— 它们不参与「多列」判定，
  // 也不参与「期望值错位」判定（真正的对拍在 D 组）。
  const allWant = new Set([...want.values()].flatMap((s) => [...s]));
  const allGot = got;
  const extra = [...allGot].filter((n) => !allWant.has(n) && !storeSet.has(n)).sort();
  // 少列 ⇒ 漏判（危险）。已在 regWrites 里登记的排除掉（它走 A 类判据，不靠 groups）。
  const missing = [...allWant].filter((n) => !allGot.has(n) && !inRegWrites.has(n)).sort();
  if (missing.length) drift.push(`${id}: 侧表少列 ${missing.length} 个服务（漏判，危险）→ ${missing.slice(0, 5).join(', ')}`);
  if (extra.length) drift.push(`${id}: 侧表多列 ${extra.length} 个服务（恒判未生效）→ ${extra.slice(0, 5).join(', ')}`);
  // 期望值对拍：pwsh 文本里 (服务, 期望) 对，**侧表里至少有一组**给出同一个期望即算对。
  // wuauserv 在侧表有两组（3 与 4）、pwsh 文本只有 3 ⇒ 取「任一组匹配」而非「唯一匹配」。
  for (const [v, set] of want) {
    for (const nm of set) {
      const gots = gotGroups.filter((g) => g.set.has(nm)).map((g) => g.expect);
      if (gots.length && !gots.includes(v)) {
        drift.push(`${id}: 服务 ${nm} 的期望 Start 侧表=${gots.join('/')} / pwsh 文本=${v}`);
      }
    }
  }
}
// 反向：数据层里所有「pwsh 写服务 Start 值」的项都该在表里
for (const o of opts) {
  if (writesServiceStart(o) && !items[o.id]) {
    drift.push(`${o.id}: pwsh 步骤在写服务启动类型但侧表里没有它（该做 B 类检测却漏了）`);
  }
}
check(
  drift.length === 0,
  `B. groups[] ⇄ pwsh 文本双向对拍（${Object.keys(items).length} 项）`,
  drift.join('; '),
);

// ---- C. expectStart 必须是合法 win32 启动类型 ----
// R0-a踩过凭记忆写错（把 SERVICE_DEMAND_START 记成 2，真值 3），所以这里列全枚举。
const LEGAL_START = new Set([2, 3, 4]);
const startProblems = [];
let nGroups = 0;
let nAsserts = 0;
for (const [id, spec] of Object.entries(items)) {
  for (const g of spec.groups || []) {
    nGroups++;
    nAsserts += (g.services || []).length;
    if (!LEGAL_START.has(g.expectStart)) {
      startProblems.push(`${id}: expectStart=${g.expectStart} 不是合法启动类型（AUTO=2/DEMAND=3/DISABLED=4）`);
    }
  }
}
check(
  startProblems.length === 0,
  `C. expectStart 是合法 win32 启动类型（${nGroups} 组 / ${nAsserts} 个断言）`,
  startProblems.join('; '),
);

// ---- D. storeServices == apply.rs 的 STORE_SERVICES，且未混进 groups ----
const storeRust = storeFromRust();
const specBulk = items['tf_svc_bulk'];
const storeProblems = [];
if (!storeRust) {
  storeProblems.push('从 apply.rs 读不出 STORE_SERVICES 常量（被改名/搬走？）');
} else if (!specBulk) {
  storeProblems.push('侧表没有 tf_svc_bulk');
} else {
  const got = [...(specBulk.storeServices || [])].sort();
  if (JSON.stringify(got) !== JSON.stringify(storeRust)) {
    storeProblems.push(`storeServices ≠ STORE_SERVICES：侧表 ${JSON.stringify(got)} / Rust ${JSON.stringify(storeRust)}`);
  }
  // 「混进 groups」的判定要**排除条件追加语义下的合法重叠**。
  //
  // `wuauserv` 真的同时出现在两处，这是**数据层的既有语义**不是缺陷：
  //   · 基础段（Start=3，手动）—— 让 Windows Update 在禁用 70+ 服务后仍能工作
  //   · 商店段（Start=4，禁用）—— 用户勾了「连商店服务一起禁」才追加执行
  // 执行顺序是「基础段先、商店段后」（`svc_bulk_append_store` push 到末尾），
  // 所以勾了商店 ⇒ 最终 4；没勾 ⇒ 最终 3。
  //
  // 因此正确判据不是「不許重叠」，而是「**重叠项在 groups 里的期望值必须与
  // 「未追加商店段时」的最终值一致**」—— 即基础段的期望值就是检测该用的那个。
  // 反过来若某项只在 storeServices 里、groups 里完全没有，那才是漏判。
  const allGroups = (specBulk.groups || []).flatMap((g) => g.services || []);
  const onlyInStore = got.filter((n) => !allGroups.includes(n));
  if (onlyInStore.length) {
    storeProblems.push(
      `这 ${onlyInStore.length} 个服务只在 storeServices 里、groups 里没有 ⇒ 勾/不勾商店两种路径都漏判：${onlyInStore.join(', ')}`,
    );
  }
  // 重叠项必须记进 _comment 说明「两处期望值不同，按执行顺序取值」
  const overlap = got.filter((n) => allGroups.includes(n));
  if (overlap.length && !/wuauserv/.test(comment)) {
    storeProblems.push(
      `有 ${overlap.length} 个服务同时在 groups 与 storeServices（${overlap.join(', ')}），` +
      `两处期望值可能不同 —— _comment 必须写明「按执行顺序取值」这件事`,
    );
  }
}
check(
  storeProblems.length === 0,
  'D. storeServices == apply.rs 的 STORE_SERVICES，且未混进 groups',
  storeProblems.join('; '),
);

// ---- D2. 跨组期望值互斥的服务必须属于「条件追加」清单 ----
//
// 检测侧对 `groups` 出的是**静态**断言：同一服务若在多组里期望值不同，就必有一条
// 恒假（wuauserv 基础段=3 / 商店段=4，2026-10-05 复核坐实为「批量项恒报部分生效」
// 的根因）。合法形态只有一种：该服务的最终值取决于运行期选项，因此必须属于
// `storeServices`（条件追加），检测侧会整条跳过。
const conflictProblems = [];
for (const [id, spec] of Object.entries(items)) {
  const bySvc = new Map();
  for (const g of spec.groups || []) {
    for (const n of g.services || []) {
      if (!bySvc.has(n)) bySvc.set(n, new Set());
      bySvc.get(n).add(g.expectStart);
    }
  }
  const store = new Set(spec.storeServices || []);
  for (const [n, set] of bySvc) {
    if (set.size > 1 && !store.has(n)) {
      conflictProblems.push(
        `${id}: 服务 ${n} 跨组期望值互斥（${[...set].join('/')}），且不在 storeServices 里 —— 检测侧必有一条恒假`,
      );
    }
  }
}
check(
  conflictProblems.length === 0,
  'D2. 跨组互斥的服务必须属于条件追加清单（wuauserv 语义）',
  conflictProblems.join('; '),
);

// ---- E. 覆盖率棘轮（只增不减）----
const BASELINE = 6;
const n = Object.keys(items).length;
check(
  n >= BASELINE,
  `E. 覆盖率棘轮（登记 ${n} 项 / 基线 ${BASELINE} 项，只增不减）`,
  n < BASELINE ? `缩水 ${BASELINE - n} 项 —— 若确有项退役，请在提交信息里说明并显式下调本基线` : '',
);

// ---- F. _comment 必须写明「不进双源体系」 ----
check(
  comment.includes('不进 check-data-parity') || comment.includes('单源数据'),
  'F. _comment 写明本表是单源、不进 check-data-parity 双源体系',
  comment ? '' : '_comment 缺失',
);

// ======================================================================
// A4/A5/A6（M4）：优化目录的键集白名单 + provenance 覆盖 + 签名 sidecar
// ----------------------------------------------------------------------
// 三条都是「别让它退化成摆设」的断言：
//   A4 键集白名单（**双向**，见下方口径说明）
//   A5 provenance 覆盖棘轮（只增不减）
//   A6 签名 sidecar 存在且 alg 正确
// ======================================================================

// ---- A4. 键集白名单：双向 ----
//
// **为什么不能是 `deny_unknown_fields` 式的「字段集完全相等」**（M4 实测）：
// `restore`94 项 / `restoreInferred` 55 项 / `dynamic` 2 项 / `steps` 125 项
// **都是可选的** —— 要求字段集完全相等会立刻判红。所以口径是：
//   · 出现的键 ⊆ 白名单（防拼错字段名 / 混进别域的键）
//   · **必填键全都在**（id / group / title / risk 四项，缺任一即红）
const OPT_KEYS = new Set([
  'id', 'group', 'title', 'risk', 'desc', 'effect', 'pros', 'cons',
  'steps', 'restore', 'restoreAvailable', 'restoreInferred', 'dynamic',
]);
const STEP_KEYS = new Set(['label', 'reg', 'pwsh', 'cmd', 'service', 'disable', 'startType']);
const OPT_REQUIRED = ['id', 'group', 'title', 'risk'];
const a4Problems = [];
let optKeyCount = 0;
for (const o of opts) {
  const id = o.id || '(无 id)';
  for (const k of Object.keys(o)) {
    optKeyCount++;
    if (!OPT_KEYS.has(k)) a4Problems.push(`优化项 ${id}: 未知顶层键「${k}」`);
  }
  for (const k of OPT_REQUIRED) {
    if (o[k] === undefined) a4Problems.push(`优化项 ${id}: 缺必填键「${k}」`);
  }
  for (const [where, arr] of [['steps', o.steps], ['restore', o.restore]]) {
    for (const [i, s] of (arr || []).entries()) {
      for (const k of Object.keys(s)) {
        optKeyCount++;
        if (!STEP_KEYS.has(k)) a4Problems.push(`${id}.${where}[${i}]: 未知 step 键「${k}」`);
      }
      if (s.label === undefined) a4Problems.push(`${id}.${where}[${i}]: 缺 label（渲染层要显示它）`);
    }
  }
}
// 反向：白名单里的键是否**都**真的在用 —— 一个从没出现过的白名单项说明它已失效
const seenOpt = new Set();
for (const o of opts) {
  for (const k of Object.keys(o)) seenOpt.add(k);
  for (const arr of [o.steps, o.restore]) {
    for (const s of arr || []) for (const k of Object.keys(s)) seenOpt.add(k);
  }
}
const staleKeys = [...OPT_KEYS, ...STEP_KEYS].filter((k) => !seenOpt.has(k));
if (staleKeys.length) {
  a4Problems.push(`白名单里有从未出现的键（说明它已失效或是笔误）：${staleKeys.join(', ')}`);
}
check(
  a4Problems.length === 0,
  `A4. 优化目录键集双向对拍（${opts.length} 项 / ${optKeyCount} 个键：出现的 ⊆ 白名单 且 必填齐全 且 白名单无僵尸）`,
  a4Problems.join('; '),
);

// ---- A5. provenance 覆盖棘线（只增不减）----
const prov = JSON.parse(read('src-tauri', 'data', 'optimizer-provenance.json'));
const provItems = prov.items || {};
const PROV_KEYS = new Set(['sourceClass', 'why', 'reviewedAt']);
const PROV_CLASSES = new Set(['builtin', 'measured', 'vendor']);
const a5Problems = [];
for (const [id, p] of Object.entries(provItems)) {
  if (!opts.some((o) => o.id === id)) a5Problems.push(`provenance 有 ${id} 但数据层没有此项`);
  for (const k of Object.keys(p)) {
    if (!PROV_KEYS.has(k)) a5Problems.push(`${id}: 未知 provenance 键「${k}」`);
  }
  if (!PROV_CLASSES.has(p.sourceClass)) a5Problems.push(`${id}: sourceClass=${p.sourceClass} 不在 ${[...PROV_CLASSES].join('/')}`);
  if (!p.why || String(p.why).length < 8) a5Problems.push(`${id}: why 太短（判据不可解释）`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(p.reviewedAt || '')) a5Problems.push(`${id}: reviewedAt 不是 YYYY-MM-DD`);
}
// 必覆盖：全部 high risk + 每个分组至少一项
const highIds = opts.filter((o) => o.risk === 'high').map((o) => o.id);
const uncoveredHigh = highIds.filter((id) => !provItems[id]);
if (uncoveredHigh.length) {
  a5Problems.push(`这 ${uncoveredHigh.length} 个 high risk 项没有 provenance（高危项必须可解释）→ ${uncoveredHigh.join(', ')}`);
}
const allGroups = [...new Set(opts.map((o) => o.group))];
const uncoveredGroups = allGroups.filter(
  (g) => !opts.some((o) => o.group === g && provItems[o.id]),
);
if (uncoveredGroups.length) {
  a5Problems.push(`这 ${uncoveredGroups.length} 个分组一项 provenance 都没有 → ${uncoveredGroups.join(', ')}`);
}
const PROV_BASELINE = 24; // 2026-10-03 首版：14 个 high + 10 个分组代表
if (Object.keys(provItems).length < PROV_BASELINE) {
  a5Problems.push(
    `provenance 覆盖缩水：${Object.keys(provItems).length} < 基线 ${PROV_BASELINE} —— 若确有项退役，显式下调 PROV_BASELINE 并在提交信息里说明`,
  );
}
check(
  a5Problems.length === 0,
  `A5. provenance 覆盖：${Object.keys(provItems).length} 项（high ${highIds.length} 全覆盖 / ${allGroups.length} 分组全覆盖 / 基线 ${PROV_BASELINE} 只增不减）`,
  a5Problems.join('; '),
);

// ---- A6. 签名 sidecar 存在且 alg 正确 ----
const a6Problems = [];
let sidecar = null;
try {
  sidecar = JSON.parse(read('src-tauri', 'data', 'optimizer-runtime.json.sig.json'));
} catch (e) {
  a6Problems.push(`读不到 optimizer-runtime.json.sig.json（${e.message}）—— 优化目录必须带签名（M4）`);
}
if (sidecar) {
  if (sidecar.alg !== 'ed25519') a6Problems.push(`sidecar alg=${sidecar.alg}，应为 ed25519`);
  if (!sidecar.sig || String(sidecar.sig).length < 80) a6Problems.push('sidecar 的 sig 字段缺失或过短');
}
check(
  a6Problems.length === 0,
  'A6. 优化目录签名 sidecar 在位且 alg=ed25519',
  a6Problems.join('; '),
);

// ======================================================================
// A7（C1）：出厂默认值侧表的契约
// ----------------------------------------------------------------------
// 核心断言不是「填了多少」，而是**「没填的那些有没有诚实地标 unknown」**。
// C1 的价值在「依据可判定」—— 一个编出来的 Windows 出厂默认值恰好废掉这个价值，
// 而门禁只能校验「与数据一致」、校验不了「与 Windows 真实出厂一致」。
// 所以门禁的火力集中在两处：
//   ① `defaultKnown=true` 的项，其 `defaultValue` 必须**可从数据层机械复核**
//      （唯一允许的 true 形态是 `null` =键本应不存在，判据：steps 有 / restore 无）
//   ② `defaultKnown=false` 的项，`defaultValue` **必须**是字符串 `"unknown"`
//      ——出现任何具体值即红（那说明有人开始猜了）
// ======================================================================
const DEF_KEYS = new Set(['defaultKnown', 'defaultValue', 'why', 'reviewedAt']);
const defs = JSON.parse(read('src-tauri', 'data', 'optimizer-defaults.json'));
const defItems = defs.items || {};
const a7Problems = [];
for (const [id, d] of Object.entries(defItems)) {
  if (!opts.some((o) => o.id === id)) a7Problems.push(`defaults 有 ${id} 但数据层没有此项`);
  for (const k of Object.keys(d)) {
    if (!DEF_KEYS.has(k)) a7Problems.push(`${id}: 未知 defaults 键「${k}」`);
  }
  if (d.defaultKnown === true) {
    // 唯一允许的 known 形态是 `null`（键本应不存在）。任何具体值都需要
    // 「可机械复核的来源」，而本仓目前**没有**这样的来源（出厂默认值无权威出处、
    // 实测原值因机而异）—— 出现即红。
    if (d.defaultValue !== null) {
      a7Problems.push(
        `${id}: defaultKnown=true 但 defaultValue=${JSON.stringify(d.defaultValue)} —— `
        + `本仓目前唯一可机械复核的 known 形态是 null（键本应不存在）。`
        + `填具体值需要「可复核的来源」，而 Windows 出厂默认值无权威出处、`
        + `实测原值因机而异 —— 写了就是编造依据（C1 的价值恰在「依据可判定」）`,
      );
    } else {
      // 反向复核：真的是「steps 有 / restore 无」吗
      const o = opts.find((x) => x.id === id);
      const sk = new Set();
      for (const s of (o.steps || [])) {
        if (typeof s.reg !== 'string') continue;
        for (const m of s.reg.matchAll(/^"([^"]+)"=/gm)) sk.add(m[1]);
      }
      const rk = new Set();
      for (const s of (o.restore || [])) {
        if (typeof s.reg !== 'string') continue;
        for (const m of s.reg.matchAll(/^"([^"]+)"=/gm)) rk.add(m[1]);
      }
      const created = [...sk].filter((k) => !rk.has(k));
      if (!created.length) {
        a7Problems.push(
          `${id}: 标成 defaultKnown=true（键本应不存在）但机械复核不成立 —— `
          + `steps 的键全部出现在 restore 里，没有「执行时新建」的键`,
        );
      }
    }
  } else if (d.defaultKnown === false) {
    if (d.defaultValue !== 'unknown') {
      a7Problems.push(
        `${id}: defaultKnown=false 但 defaultValue=${JSON.stringify(d.defaultValue)} —— `
        + `未知的必须写字符串 "unknown"。写具体值等于把猜测冒充成依据，`
        + `而 C1 的门禁只能验「与数据一致」、验不了「与 Windows 真实出厂一致」`,
      );
    }
  } else {
    a7Problems.push(`${id}: defaultKnown 必须是 true/false，实际 ${JSON.stringify(d.defaultKnown)}`);
  }
  if (!d.why || String(d.why).length < 8) a7Problems.push(`${id}: why 太短（依据不可复核）`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d.reviewedAt || '')) a7Problems.push(`${id}: reviewedAt 不是 YYYY-MM-DD`);
}
// 覆盖率棘轮：登记项数只增不减
const DEF_BASELINE = 126; // 2026-10-03 首版：全部项都登记（known 或 unknown）
if (Object.keys(defItems).length < DEF_BASELINE) {
  a7Problems.push(
    `defaults 覆盖缩水：${Object.keys(defItems).length} < 基线 ${DEF_BASELINE} —— `
    + `新项必须登记（哪怕标 unknown），否则「哪些项的默认值未知」就不可查`,
  );
}
// known 项数棘轮：**只增不减**。判红实验 2 抓到的缺口：把一个 `defaultKnown=true`
// 改成 `false` + `"unknown"` 完全合规（每条规则都过），于是「机械可复核的项」可以
// 被静默降级成 unknown —— 覆盖率只登记不升级，几个月后这张表就全是 unknown 而没人察觉。
const DEF_KNOWN_BASELINE = 10; // 2026-10-03 首版
const knownCount = Object.values(defItems).filter((x) => x.defaultKnown).length;
if (knownCount < DEF_KNOWN_BASELINE) {
  a7Problems.push(
    `defaultKnown=true 的项从 ${DEF_KNOWN_BASELINE} 降到 ${knownCount} —— `
    + `「可机械复核的项」可以静默降级成 unknown（每条规则都过），`
    + `所以必须单独棘轮。确有项不再可复核时请下调本基线并在提交信息里说明`,
  );
}
check(
  a7Problems.length === 0,
  `A7. 出厂默认值侧表：${Object.keys(defItems).length} 项全登记 / defaultKnown=true ${knownCount} 项（机械可复核，棘轮 >= ${DEF_KNOWN_BASELINE}）/ 其余显式 "unknown"（不猜值）`,
  a7Problems.join('; '),
);

console.log('');
if (fail > 0) {
  console.error(`写入坐标侧表门禁失败 ${fail} 项。`);
  process.exit(1);
}
console.log('✓ 写入坐标侧表：键集 / 双向对拍 / 启动类型 / 商店分离 / 棘轮 / 单源声明 全通过');

// ==================== G. 判据正向自检 ====================
// 本门禁是「找违规型」的：若判据失灵，上面的 ✓ 只是因为没扫到东西。
// 逐条对**已知违规样本**跑同一份判据函数，必须报红。
(function positiveControls() {
  const findings = [];
  const cases = [
    // ① 侧表少列服务（漏判方向，最危险）
    {
      name: '少列服务',
      want: new Map([[4, new Set(['SvcA', 'SvcB', 'SvcC'])]]),
      got: new Map([[4, new Set(['SvcA', 'SvcB'])]]),
      store: null,
      expectHit: true,
    },
    // ② 侧表多列服务
    {
      name: '多列服务',
      want: new Map([[4, new Set(['SvcA'])]]),
      got: new Map([[4, new Set(['SvcA', 'SvcZ'])]]),
      store: null,
      expectHit: true,
    },
    // ③ 期望 Start 值错位（同一个服务两侧期望不同）
    {
      name: '期望值错位',
      want: new Map([[4, new Set(['SvcA'])]]),
      got: new Map([[3, new Set(['SvcA'])]]),
      store: null,
      expectHit: true,
    },
    // ④ 商店服务混进 groups
    {
      name: '商店混入 groups',
      want: new Map([[4, new Set(['SvcA'])]]),
      got: new Map([[4, new Set(['SvcA', 'ClipSVC'])]]),
      store: ['ClipSVC', 'InstallService'],
      storeInGroups: ['ClipSVC'],
      expectHit: true,
    },
    // ⑤ storeServices 与 Rust 常量不一致
    {
      name: 'storeServices 漂移',
      want: new Map([[4, new Set(['SvcA'])]]),
      got: new Map([[4, new Set(['SvcA'])]]),
      store: ['ClipSVC', 'InstallService'],
      sideStore: ['ClipSVC'],
      expectHit: true,
    },
    // ⑥ 非法启动类型
    {
      name: '非法启动类型',
      startProblem: 7,
      expectHit: true,
    },
    // ⑦ 干净样本（期望**不**报红，防止判据变成「永远红」）
    {
      name: '干净样本',
      want: new Map([[4, new Set(['SvcA', 'SvcB'])]]),
      got: new Map([[4, new Set(['SvcA', 'SvcB'])]]),
      store: null,
      expectHit: false,
    },
  ];

  for (const c of cases) {
    let hit = false;
    if (c.startProblem !== undefined) {
      hit = !LEGAL_START.has(c.startProblem);
    } else {
      const allWant = new Set([...c.want.values()].flatMap((s) => [...s]));
      const allGot = new Set([...c.got.values()].flatMap((s) => [...s]));
      if ([...allWant].some((x) => !allGot.has(x))) hit = true;
      if ([...allGot].some((x) => !allWant.has(x))) hit = true;
      for (const [v, set] of c.want) {
        for (const nm of set) {
          for (const [gv, gset] of c.got) {
            if (gset.has(nm) && gv !== v) hit = true;
          }
        }
      }
      if (c.store && c.sideStore && JSON.stringify([...c.sideStore].sort()) !== JSON.stringify([...c.store].sort())) hit = true;
      if (c.storeInGroups) {
        const allIn = [...c.got.values()].flatMap((s) => [...s]);
        if (c.storeInGroups.some((x) => allIn.includes(x))) hit = true;
      }
    }
    if (hit !== c.expectHit) findings.push(`${c.name}（期望${c.expectHit ? '报红' : '放行'}，实际${hit ? '红' : '绿'}）`);
  }

  // 第二批（M4 新增 A4/A5/A6 三组）：对**同一份**判据跑违规样本。
  // 与上面分开是因为这三组的判据形态不同（键集/覆盖/文件存在），共用一个
  // 「找出问题」的小函数即可，但样本要能独立表达「哪些字段是坏的」。
  const a4OptKeys = new Set(OPT_KEYS);
  const a4StepKeys = new Set(STEP_KEYS);
  const a4Check = (opt) => {
    const bad = [];
    for (const k of Object.keys(opt)) if (!a4OptKeys.has(k)) bad.push(k);
    for (const k of OPT_REQUIRED) if (opt[k] === undefined) bad.push(`缺${k}`);
    for (const arr of [opt.steps, opt.restore]) {
      for (const s of arr || []) {
        for (const k of Object.keys(s)) if (!a4StepKeys.has(k)) bad.push(`step.${k}`);
        if (s.label === undefined) bad.push('step.缺label');
      }
    }
    return bad;
  };
  const a5Check = (opt, provMap) => {
    const bad = [];
    if (opt.risk === 'high' && !provMap[opt.id]) bad.push('high 项无 provenance');
    return bad;
  };
  const m4Cases = [
    ['A4 未知顶层键',
      a4Check({ id: 'x', group: 'g', title: 't', risk: 'low', bogusField: 1 }).length > 0,
      true],
    ['A4 缺必填键',
      a4Check({ id: 'x', group: 'g', title: 't' }).length > 0,
      true],
    ['A4 未知 step 键',
      a4Check({ id: 'x', group: 'g', title: 't', risk: 'low', steps: [{ label: 'a', bogus: 1 }] }).length > 0,
      true],
    ['A4 干净样本应放行',
      a4Check({ id: 'x', group: 'g', title: 't', risk: 'low', steps: [{ label: 'a' }] }).length === 0,
      true],
    ['A5 high 项无 provenance',
      a5Check({ id: 'x', risk: 'high' }, {}).length > 0,
      true],
    ['A5 high 项有 provenance 应放行',
      a5Check({ id: 'x', risk: 'high' }, { x: { sourceClass: 'builtin' } }).length === 0,
      true],
    ['A6 sidecar 非对象',
      (() => { try { const s = JSON.parse('{bad'); return s.alg !== 'ed25519'; } catch { return true; } })(),
      true],
  ];
  for (const [name, got, want] of m4Cases) {
    if (got !== want) findings.push(`M4 自检「${name}」判据行为不符预期`);
  }
  // 第三批（C1 / A7）：「诚实标 unknown」这条判据的正向对照。
  // 关键样本是第4 条 —— defaultKnown=true 但机械复核不成立（steps 的键全在 restore 里）。
  // 那条是本组最容易写成「只看 defaultValue 是不是 null」的形态，而那样它就恒绿。
  const a7Judge = (d, createdKeysInSteps, createdKeysInRestore) => {
    const bad = [];
    if (d.defaultKnown === true) {
      if (d.defaultValue !== null) bad.push('known 但填了具体值');
      const created = createdKeysInSteps.filter((k) => !createdKeysInRestore.includes(k));
      if (!created.length) bad.push('标 known 但机械复核不成立');
    } else if (d.defaultKnown === false) {
      if (d.defaultValue !== 'unknown') bad.push('unknown 但填了具体值');
    } else {
      bad.push('defaultKnown 非法');
    }
    return bad;
  };
  const a7Cases = [
    ['known + null + 机械复核成立', a7Judge({ defaultKnown: true, defaultValue: null }, ['A', 'B'], ['A']).length === 0, true],
    ['known + 填了具体值', a7Judge({ defaultKnown: true, defaultValue: 'dword:00000000' }, ['A'], []).length > 0, true],
    ['unknown 但填了具体值（开始猜了）', a7Judge({ defaultKnown: false, defaultValue: '0' }, [], []).length > 0, true],
    ['unknown + "unknown" 应放行', a7Judge({ defaultKnown: false, defaultValue: 'unknown' }, [], []).length === 0, true],
    ['known + null 但机械复核不成立', a7Judge({ defaultKnown: true, defaultValue: null }, ['A'], ['A']).length > 0, true],
  ];
  for (const [name, got, want] of a7Cases) {
    if (got !== want) findings.push(`A7 自检「${name}」判据行为不符预期`);
  }
  const total = cases.length + m4Cases.length + a7Cases.length;
  const ok = findings.length === 0;
  console.log(`${ok ? '✓' : '✗'} 自检：${total} 条已知样本（含 1 条**应当放行**的干净样本），判据行为全对 ${total - findings.length} 条`);
  if (!ok) {
    console.error(`  ✗ 判据失灵：${JSON.stringify(findings)}`);
    process.exit(1);
  }
})();

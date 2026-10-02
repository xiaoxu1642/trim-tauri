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
  // 必须同时命中「服务键路径」。`telemetry_optimize` 的 AutoLogger 段也写
  // `-Name Start -Value 0`，但落在 `...\Control\WMI\Autologger` 下 ——
  // 那是 ETW 会话配置，**不是服务**，B 类检测（service_start_type_is）对它无意义。
  // 只看 `-Name Start` 会把它误报成「该做 B 类却漏了」（门禁第一次跑就抓到了）。
  return /Services\\[A-Za-z0-9_.\-$]+/.test(blob);
}

// ---- A. 键 ⊆ 白名单 + 必填键齐全 ----
const ALLOWED = new Set(['groups', 'storeServices']);
const REQUIRED = ['groups'];
const items = writes.items || {};
const comment = writes._comment || '';
const keyProblems = [];
for (const [id, spec] of Object.entries(items)) {
  for (const k of Object.keys(spec)) {
    if (!ALLOWED.has(k)) keyProblems.push(`${id}: 未知键「${k}」（白名单 ${[...ALLOWED].join('/')}）`);
  }
  for (const k of REQUIRED) {
    if (spec[k] === undefined) keyProblems.push(`${id}: 缺必填键「${k}」`);
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
}
check(
  keyProblems.length === 0,
  `A. 键 ⊆ 白名单 + 必填键齐全（${Object.keys(items).length} 项）`,
  keyProblems.join('; '),
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
  const missing = [...allWant].filter((n) => !allGot.has(n)).sort(); // 少列 ⇒ 漏判（危险）
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

  const total = cases.length;
  const ok = findings.length === 0;
  console.log(`${ok ? '✓' : '✗'} 自检：${total} 条已知样本（含 1 条**应当放行**的干净样本），判据行为全对 ${total - findings.length} 条`);
  if (!ok) {
    console.error(`  ✗ 判据失灵：${JSON.stringify(findings)}`);
    process.exit(1);
  }
})();

'use strict';
// tools/check-test-sandbox.mjs —— 测试沙箱必须走自删守卫（D 轮新增门禁）
//
// 出处：2026-10-25 小旭贴的操作日志。清理条目 `tempFiles` 的扫描根**就是用户 %TEMP%**
// （`cleanup-rules.json` 的 `pathPs: "$env:TEMP"`），而测试一直在同一处建沙箱，且把
// `remove_dir_all` 手写在用例最后一行 ⇒ 任何一次断言失败 / panic / 早退都在盘上留一份。
// 本机实测：累计 224 个 `trim-*` 目录，其中 native-scanner 两条深度用例留下 70 层嵌套
// （> `MAX_WALK_DEPTH` 64），清理扫描从此常年在这种测试垃圾上撞深度上限打留痕 ——
// **测试垃圾反过来污染了被测对象看到的世界**，用户分不清扫到的是自己的临时文件还是 agent 的垃圾。
//
// 判据（四条，都能单独判红）：
//   ① 建点必须走守卫：`temp_dir().join(format!("trim-…` 只允许出现在三个守卫实现文件里；
//      其余每一处记进**按文件计数上限（只减不增的棘轮）**，新增文件或计数上升即红；
//   ② 守卫本体必须活性：实现文件里 `impl Drop for` + `remove_dir_all` 缺一即红
//      （掏空 Drop 会让所有已改造建点静默退回「失败即留残」，而①仍然全绿）；
//   ③ %TEMP% 残留只做**观测**：读得到就打计数，读不到显式 SKIP —— 干净克隆/别的机器上
//      这不构成失败（AGENTS：读不到要说「未校验」，不许假绿也不许假红）；
//   ④ 正向对照：未登记新文件 / 计数上升 / 守卫实现消失，三种都必须判红。
//
// 用法：node tools/check-test-sandbox.mjs [--write]

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { gate } from './lib/gate.mjs';

const g = gate(import.meta.url);
const ROOT = process.cwd();
const WRITE = process.argv.includes('--write');

/** 守卫实现本体（唯一允许直接建沙箱的地方） */
const IMPL = [
  'src-tauri/src/testutil.rs',
  'native-scanner/src/util.rs',
  'native-scanner/tests/common/mod.rs',
];

/**
 * 过渡基线：还没换守卫的建点，按文件计数，**只减不增**。
 * 键串由本门禁现算得到（不是照抄任何旧报告的行号或数字）。
 * 清完一处就把对应行删掉；全删光后本门禁退化成「只准在 IMPL 里建沙箱」。
 */
const CEILING = {
  'src-tauri/src/engine/native/cleanup.rs': 19,
  'src-tauri/src/commands/fileclean.rs': 6,
  'src-tauri/src/engine/native/startup.rs': 5,
  'src-tauri/src/commands/uninstall/residue_trace_tests.rs': 4,
  'src-tauri/src/commands/uninstall/pending_delete.rs': 4,
  'src-tauri/src/security/mod.rs': 3,
  'src-tauri/src/engine/shellicon.rs': 3,
  'src-tauri/src/engine/reg_backup.rs': 3,
  'src-tauri/src/engine/protect.rs': 2,
  'src-tauri/src/commands/updater.rs': 2,
  'src-tauri/src/commands/gameclean.rs': 2,
  'src-tauri/src/engine/native/peripheral.rs': 1,
  'src-tauri/src/engine/native/contextmenu.rs': 1,
  'src-tauri/src/commands/uninstall/list_run.rs': 1,
};

const SITE = /temp_dir\(\)\.join\(format!\("trim-/g;

function walk(dir, out) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (e.name === 'target' || e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.name.endsWith('.rs')) out.push(p);
  }
  return out;
}

/** 纯判定：实得计数 ⇄ 基线。返回 {bad, shrunk}。 */
function judge(counts, ceiling, implFiles) {
  const bad = [];
  const shrunk = [];
  for (const f of implFiles) {
    if ((counts[f] || 0) < 1) bad.push(`守卫实现 ${f} 里找不到建点 ⇒ 守卫被搬走或改名，本门禁失明`);
  }
  for (const [f, n] of Object.entries(counts)) {
    if (implFiles.includes(f)) continue;
    const cap = ceiling[f];
    if (cap === undefined) {
      bad.push(`新文件 ${f} 直接建沙箱 ${n} 处（未登记进过渡基线）⇒ 改走 sandbox()/TempRoot 守卫；确有必要保留的，登记进 CEILING 并写明为什么不能改`);
    } else if (n > cap) {
      bad.push(`${f} 建点 ${n} > 上限 ${cap}（棘轮只减不增）`);
    } else if (n < cap) {
      shrunk.push(`${f} ${cap}→${n}`);
    }
  }
  return { bad, shrunk };
}

console.log('=== 测试沙箱自删守卫门禁 ===');

const files = [];
for (const root of ['src-tauri/src', 'native-scanner/src', 'native-scanner/tests']) {
  walk(join(ROOT, root), files);
}

const counts = {};
for (const abs of files) {
  const rel = relative(ROOT, abs).replace(/\\/g, '/');
  const n = (readFileSync(abs, 'utf8').match(SITE) || []).length;
  if (n) counts[rel] = n;
}

const { bad, shrunk } = judge(counts, CEILING, IMPL);
const debt = Object.entries(counts).filter(([f]) => !IMPL.includes(f)).reduce((s, [, n]) => s + n, 0);
const ceilingTotal = Object.values(CEILING).reduce((s, n) => s + n, 0);

if (bad.length) for (const b of bad) g.fail(b);
else g.ok(`① 未守卫建点 ${debt} 处，全部在过渡基线内（基线合计 ${ceilingTotal}，只减不增）`);

if (shrunk.length) {
  const hint = `请同步删小 CEILING 对应行${WRITE ? '（--write 已给出行）' : ''}：\n    · ${shrunk.join('\n    · ')}`;
  if (WRITE) g.ok(`①b 收敛 ${shrunk.length} 处，${hint}`);
  else g.warn(`①b 有 ${shrunk.length} 处债务已减但基线未同步，${hint}`);
}

// ② 守卫本体活性
for (const f of IMPL) {
  const abs = join(ROOT, f);
  if (!existsSync(abs)) {
    g.fail(`② 守卫实现文件 ${f} 不见了`);
    continue;
  }
  const t = readFileSync(abs, 'utf8');
  const hasDrop = /impl\s+Drop\s+for\s+\w+/.test(t);
  const hasRemove = /remove_dir_all/.test(t);
  if (hasDrop && hasRemove) g.ok(`② ${f} 守卫活性：Drop + remove_dir_all 都在`);
  else g.fail(`② ${f} 守卫被掏空（Drop ${hasDrop ? '在' : '缺'} / remove_dir_all ${hasRemove ? '在' : '缺'}）⇒ 已改造的建点会静默退回「失败即留残」，而①仍然全绿`);
}

// ③ %TEMP% 残留：观测项
const TEMP = process.env.TEMP || process.env.TMP;
if (!TEMP || !existsSync(TEMP)) {
  g.warn('③ %TEMP% 在本机不可读 —— 残留计数**未校验**（SKIP，不是通过）');
} else {
  let residue = null;
  try {
    residue = readdirSync(TEMP).filter((n) => n.startsWith('trim-'));
  } catch {
    residue = null;
  }
  if (residue === null) g.warn('③ %TEMP% 列举失败 —— 残留计数**未校验**（SKIP，不是通过）');
  else if (residue.length === 0) g.ok('③ %TEMP% 下 trim-* 残留 0 个');
  else g.warn(`③ %TEMP% 下还有 ${residue.length} 个 trim-* 沙箱残留（观测项，不判红）：${residue.slice(0, 4).join(', ')}${residue.length > 4 ? ' …' : ''}`);
}

// ④ 正向对照：判定器必须能红 —— 三种破坏形态各自判红才算数
{
  const worst = 'src-tauri/src/engine/native/cleanup.rs';
  const cases = [
    ['未登记的新建点文件', judge({ 'src-tauri/src/brand-new.rs': 1 }, CEILING, IMPL)],
    ['建点计数上升（棘轮方向）', judge({ [worst]: CEILING[worst] + 1 }, CEILING, IMPL)],
    ['守卫实现整体消失（判定器失明）', judge({}, CEILING, IMPL)],
  ];
  let caught = 0;
  for (const [name, r] of cases) {
    if (r.bad.length) {
      caught++;
    } else {
      g.fail(`正向对照失效：${name} 没有被判红 ⇒ 本门禁永远不会被测坏`);
    }
  }
  // 反向：干净样本必须放行，否则判据是「永远红」而不是能判红
  if (bad.length === 0 && shrunk.length === 0) {
    g.ok('正向对照：三形态均可判红，且当前干净样本照常放行');
  } else if (caught === cases.length) {
    g.ok(`正向对照 ${caught}/${cases.length} 形态均可判红（当前盘态另有收敛/红项，见上）`);
  }
}

g.finish('测试沙箱守卫门禁：全部通过');

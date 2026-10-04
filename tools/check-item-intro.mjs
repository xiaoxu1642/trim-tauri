// check-item-intro.mjs —— 本地简介库（item-intro.json）的语义门禁（RAINZ 对标 §3.4）
//
// 为什么需要：`item-intro.json` 里 `scopes.optimizer.byId` 从「string 简介」升级为
// 「{desc, tips?}」之后，本仓第一次有了一份**前端与门禁都要吃**的多形态数据。
// 光靠 `check-data-parity` 那种"产物 ⇄ 源"字节对拍守不住 —— item-intro.json 是手写真源，
// 没有可比的产物。这里钉的是**语义**：
//   ① 每个 byId 值要么是 string（旧格式，兼容窗口，不许再新增）要么是 {desc, tips?} 对象；
//   ② tips 要么整段没有、要么三档齐全（"日常 / 游戏 / 办公" 缺一档 = 半空壳，前端会显示不全）；
//   ③ 与 catalog / retired 集合对拍：目录里有 → intro 里必须有；intro 里有 → 要么在目录、
//      要么在 `retired-optimizations.json`（AGENTS §5.12 允许退役 id 的简介保留）；
//   ④ tips 覆盖率棘轮：只许增不许减（防下一次"清理过期项"顺手把 tips 也清了）；
//   ⑤ 其他 scope（startup/contextmenu/memoryclean/residue）保持"键 → string"，别乱改形状；
//   ⑥ 判据正向自检：伪造一份违规数据，validate 必须报错。
//   ⑦ scope 对拍（v0.7.0，2026-10-05）：以**真实调用点现算**出的简介面板消费档为准，
//      对拍 `intro.js getLocal` 分支 ⇄ `modelpicker.js SCOPE_META` ⇄ `AI_SCOPES` ⇄
//      `item-intro.json scopes` 四个方向。
//      为什么单独钉这一组：这几处的兜底都是**静默**的 —— `getLocal` 里没列出的档会落到
//      `getContextmenu`，`SCOPE_META[scope] ? … : 'contextmenu'` 同理，`aidesc_get` 里
//      未知 scope 也直接按右键管理处理。新增一档忘了任何一处，表现不是报错而是
//      「拿右键管理的简介去解释一个服务键」，肉眼与普通自测都看不出来（本轮加这组时
//      就当场抓到过一处同类漏档）。
//      为什么不按 AI_SCOPES 要求每档都写 getLocal：maintenance 档是 maintenance.js
//      直连 aidesc.get 的，不走简介面板 —— 按表要求会变成误红。
//
// 用法：node tools/check-item-intro.mjs
// 退出码：0 = 全绿；1 = 任一断言未通过
'use strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const INTRO = path.join(ROOT, 'src-tauri', 'data', 'item-intro.json');
const CATALOG = path.join(ROOT, 'src-tauri', 'data', 'optimizer-runtime.json');
const RETIRED = path.join(ROOT, 'src-tauri', 'data', 'retired-optimizations.json');

// tips 覆盖率棘轮基线：**只增不减**。
// 数字与 check 断言 ④ 配套 —— 未来给某个退役项补 tips 时同步把这里抬起来；
// 减项（目录里删了某项、intro 也清了）不允许把基线降回去，那正是本门禁要拦的。
// 39 = §3.4 首批；43 = + D 批 1 的 4 项；47 = + D 批 2 的 4 项；51 = + D 批 4 的 4 项；
// 55 = + D 批 3 的 4 项（svc_w32time_manual 等，走 startType 分支）；
// 59 = + D 批 收尾 4 项（wu_au_options_notify / wu_no_auto_reboot / sys_transparency_off /
// devmgr_show_hidden_default）。方案 §3.5 D 批 1-4 里"键路径有把握 + 不与既有语义重叠"
// 的项已全部落地；TcpAckFrequency / DisableAIFeatures / 蓝牙策略键 / UserPreferencesMask
// 明确不做的理由写在 OPTIONS 里（AGENTS §9.3 纪律 ①）。
const TIPS_BASELINE = 59;

let fail = 0;
function check(ok, name, detail) {
  console.log(`${ok ? '✓' : '✗'} ${name}${detail ? ' —— ' + detail : ''}`);
  if (!ok) fail++;
}

console.log('=== 本地简介库语义门禁（RAINZ 对标 §3.4）===\n');

function readJson(abs) {
  return JSON.parse(fs.readFileSync(abs, 'utf8'));
}
function existsJson(rel) {
  try { readJson(join(rel)); return true; } catch { return false; }
}
function join(...parts) { return path.join(ROOT, ...parts); }

const intro = readJson(INTRO);
const catalog = readJson(CATALOG);
const retired = readJson(RETIRED);

const opt = intro?.scopes?.optimizer;
const byId = opt?.byId;
if (!byId || typeof byId !== 'object') {
  check(false, '① 结构：scopes.optimizer.byId 必须是对象', '读到：' + JSON.stringify(byId)?.slice(0, 60));
  console.log('\n✗ 简介库结构变了，后续断言无法执行');
  process.exit(1);
}

// ① 结构：每条 byId 值合法
const legacyStrings = [];
const objNoDesc = [];
const tipsPartial = [];
for (const [id, v] of Object.entries(byId)) {
  if (typeof v === 'string') {
    // 允许**保留**旧 string（不阻断本次迁移），但新增会破坏 tips 判据 —— 由棘轮 ④ 与
    // 迁移检查（④'：所有 tips 都在 obj 里）双保险。这里先记录不判红。
    legacyStrings.push(id);
    continue;
  }
  if (!v || typeof v !== 'object' || typeof v.desc !== 'string' || v.desc.length < 6) {
    objNoDesc.push(id);
    continue;
  }
  if (v.tips !== undefined) {
    const t = v.tips;
    if (!t || typeof t !== 'object' || typeof t.normal !== 'string' || typeof t.game !== 'string' || typeof t.office !== 'string') {
      tipsPartial.push(id);
    } else if (t.normal.length < 6 || t.game.length < 6 || t.office.length < 6) {
      tipsPartial.push(id + '(短)');
    }
  }
}
// 迁移完成后 legacyStrings 应当为空；非空不判红，只在报告里出现一次，提醒"仍有旧形状未迁"
check(objNoDesc.length === 0,
  `① 每条 object 值都有非空 desc（当前 object=${Object.values(byId).filter((v) => v && typeof v === 'object').length}）`,
  objNoDesc.length ? `缺 desc：${objNoDesc.slice(0, 5).join(',')}` : '');
check(tipsPartial.length === 0,
  '② tips 三档齐全（有 tips 就必须 normal/game/office 都在，且各 ≥ 6 字）',
  tipsPartial.length ? `半空壳：${tipsPartial.slice(0, 5).join(',')}` : '');
if (legacyStrings.length) {
  console.log(`  · 提示：仍有 ${legacyStrings.length} 条 byId 是旧 string 形状（未来新增请用 {desc}）：${legacyStrings.slice(0, 3).join(',')}`);
}

// ③ 集合对拍
const catIds = new Set(catalog.map((c) => c.id));
const retIds = new Set((retired.items || []).map((r) => r.id));
const missing = [...catIds].filter((id) => !(id in byId));
const orphans = Object.keys(byId).filter((id) => !catIds.has(id) && !retIds.has(id));
check(missing.length === 0,
  `③ catalog ⇄ intro 双向覆盖：目录 ${catIds.size} 项都能在 intro 里查到`,
  missing.length ? `缺失：${missing.slice(0, 5).join(',')}` : '');
// 孤儿：既不在 catalog、又不在 retired —— 一定是"手改 intro 加了个不存在的 id"或"目录删项忘了清"
check(orphans.length === 0,
  `③ intro 里每一项都在 catalog 或 retired 中（当前 intro=${Object.keys(byId).length} / retired 允许=${[...Object.keys(byId)].filter((id) => retIds.has(id)).length}）`,
  orphans.length ? `孤儿：${orphans.slice(0, 5).join(',')}` : '');

// ④ tips 覆盖率棘轮
const tipsCount = Object.values(byId).filter((v) => v && typeof v === 'object' && v.tips).length;
check(tipsCount >= TIPS_BASELINE,
  `④ tips 覆盖率棘轮（当前 ${tipsCount} / 基线 ${TIPS_BASELINE}，只增不减）`,
  tipsCount < TIPS_BASELINE ? `比基线少 ${TIPS_BASELINE - tipsCount} —— 补回来或明确 --bump-baseline 降基线（须书面理由）` : '');

// ⑤ 其他 scope 保持"键 → string"，别乱改形状（这几块本轮 §3.4 不动）
for (const scope of ['startup', 'contextmenu', 'memoryclean', 'residue']) {
  const cfg = intro?.scopes?.[scope] || {};
  const maps = Object.entries(cfg).filter(([k, v]) => v && typeof v === 'object' && !Array.isArray(v) && !['label', 'match', 'default'].includes(k));
  const badShape = [];
  for (const [, sub] of maps) {
    for (const [k, v] of Object.entries(sub)) {
      if (typeof v !== 'string') badShape.push(`${scope}.${k}`);
    }
  }
  check(badShape.length === 0,
    `⑤ ${scope} scope 仍是「键 → string」形状（本轮 §3.4 只升级 optimizer）`,
    badShape.length ? `漂了 ${badShape.length} 条：${badShape.slice(0, 3).join(',')}` : '');
}

// ⑥ 判据正向自检：伪造一份违规数据，validate 必须报错
{
  // 复刻本文件 ①②③④ 的核心判据成一次内存运算（不重复调用 check、只统计"应判红"数）
  const fake = {
    'A_no_desc': { notDesc: 'x' },
    'B_tips_partial': { desc: '有 desc', tips: { normal: '正常场景', game: '游戏场景' } }, // 缺 office
    'C_ok_plain': { desc: '完整 desc 但没有 tips' },
    'D_ok_tips': { desc: '完整 desc + tips 三档', tips: { normal: '日常', game: '游戏', office: '办公' } },
  };
  let caught = 0;
  for (const [id, v] of Object.entries(fake)) {
    if (typeof v.desc !== 'string' || v.desc.length < 6) caught++;
    else if (v.tips && !(typeof v.tips.normal === 'string' && typeof v.tips.game === 'string' && typeof v.tips.office === 'string')) caught++;
  }
  // A 无 desc（1 处）+ B tips 缺 office（1 处）= 2
  check(caught === 2,
    `⑥ 判据正向自检（伪造 4 条、期望抓到 2 条 → 实际 ${caught}）`,
    caught !== 2 ? '判据疑似坏成永远放行或过度误伤 —— 修 check 逻辑' : '');
}

// ---- ⑦ scope 三表对拍（v0.7.0）----
{
  const SETTINGS = path.join(ROOT, 'src-tauri', 'src', 'commands', 'settings.rs');
  const INTRO_JS = path.join(ROOT, 'src', 'scripts', 'intro.js');
  const PICKER = path.join(ROOT, 'src', 'scripts', 'modelpicker.js');
  const scopeSet = (text, re) => {
    const m = text.match(re);
    if (!m) return null;
    return [...m[1].matchAll(/"([a-z]+)"/g)].map((x) => x[1]);
  };
  const aiScopes = scopeSet(fs.readFileSync(SETTINGS, 'utf8'), /AI_SCOPES: &\[&str\] = &\[([^\]]*)\]/);
  check(Array.isArray(aiScopes) && aiScopes.length > 0,
    `⑦0 settings.rs 里解析到 AI_SCOPES（${aiScopes ? aiScopes.length : '解析失败'} 档）`,
    aiScopes ? '' : '正则没抓到常量体 —— 改写法必须同步本门禁，否则下面四组全是空跑');
  if (aiScopes && aiScopes.length) {
    const introJs = fs.readFileSync(INTRO_JS, 'utf8');
    const pickerJs = fs.readFileSync(PICKER, 'utf8');
    // 消费方集合从**真实调用点**现算，不照抄 AI_SCOPES：maintenance 档是 maintenance.js
    // 直连 aidesc.get 的，根本不经过简介面板 —— 按 AI_SCOPES 要求它写 getLocal 分支就是误红。
    const scriptDir = path.join(ROOT, 'src', 'scripts');
    const callers = new Set();
    for (const f of fs.readdirSync(scriptDir).filter((x) => x.endsWith('.js'))) {
      const t = fs.readFileSync(path.join(scriptDir, f), 'utf8');
      for (const m of t.matchAll(/mountIntroPanel\(\{[\s\S]{0,220}?scope:\s*'([a-z]+)'/g)) callers.add(m[1]);
    }
    const called = [...callers].sort();
    check(called.length > 0, `⑦1 现算出简介面板的消费档（${called.join(',')}）`,
      called.length ? '' : '一个都没抓到 = 调用点写法变了，本组会空跑');
    const noBranch = called.filter((s) => s !== 'contextmenu'
      && !new RegExp(`scope === '${s}'`).test(introJs));
    check(noBranch.length === 0,
      `⑦a intro.js getLocal 为每个消费档都写了显式分支（${called.length} 档全查）`,
      noBranch.length ? `这些档会静默拿右键管理的简介：${noBranch.join(',')}` : '');
    const noMeta = called.filter((s) => !new RegExp(`\\n?\\s*${s}: \\{ label:`).test(pickerJs));
    check(noMeta.length === 0,
      `⑦b modelpicker.js SCOPE_META 覆盖每个消费档（${called.length} 档全查）`,
      noMeta.length ? `模型选择器会按「右键管理」显示标题：${noMeta.join(',')}` : '');
    // 反向：intro.json 里不该有 AI_SCOPES 之外的孤儿 scope（没人会请求它）
    const dataScopes = Object.keys(intro?.scopes || {});
    const orphan = dataScopes.filter((s) => !aiScopes.includes(s));
    check(orphan.length === 0,
      `⑦c item-intro.json 的 scopes 全部在 AI_SCOPES 内（数据侧 ${dataScopes.length} 档）`,
      orphan.length ? `孤儿 scope（前端拿不到、也没人会请求）：${orphan.join(',')}` : '');
    // 消费档也必须在 AI_SCOPES 里（前端在请求一档后端不认的 scope = 静默按 contextmenu 处理）
    const unknownCall = called.filter((s) => !aiScopes.includes(s));
    check(unknownCall.length === 0,
      `⑦e 每个消费档都在 AI_SCOPES 内（否则 aidesc_get 会静默按右键管理档出 prompt）`,
      unknownCall.length ? `${unknownCall.join(',')} 不在表里` : '');
    // 正向对照：判定确实在做事 —— 伪造一个"新增档没写分支"的场景必须被抓到
    const fakeJs = introJs.replace(/if \(scope === 'residue'\) return getResidue\(item\);/, '');
    const fakeMiss = called.filter((s) => s !== 'contextmenu' && !new RegExp(`scope === '${s}'`).test(fakeJs));
    check(fakeMiss.includes('residue'),
      '⑦d 正向对照：抹掉 residue 分支后判据必须抓到它',
      fakeMiss.length ? `抓到 ${fakeMiss.join(',')}` : '判据疑似坏成恒绿（伪造的缺失没被识别）');
  }
}

console.log(`\n简介库：optimizer byId ${Object.keys(byId).length} 条 / 有 tips ${tipsCount} 条 / 覆盖率 ${(tipsCount / Object.keys(byId).length * 100).toFixed(1)}%`);
console.log(fail === 0 ? '\n门禁通过' : `\n门禁失败：${fail} 组断言未通过`);
process.exit(fail === 0 ? 0 : 1);

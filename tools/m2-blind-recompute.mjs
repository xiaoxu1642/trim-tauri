// M2/M3 前置：35 项检测盲区的机械现算（R1 之后的代码口径）
//
// 口径说明（为什么不用方案 §1.3 抄来的数字）：
//   方案里「盲区 35 项（27.8%）」是 v0.5.0 时点的现算，此后 R0 补了 startType 检测
//   （R0-b），R1 动了 overview.rs / apply.rs。数字会漂移，这里按当前源码重算。
//   盲区定义 = collect_checks 消费了步骤、但产不出任何 Check 的项
//   —— 与「体检显示未生效」是同一种形态（collect_checks 空 ⇒ 上游 if !checks.is_empty() 跳过）。
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const data = JSON.parse(fs.readFileSync(path.join(ROOT, 'src-tauri', 'data', 'optimizer-runtime.json'), 'utf8'));
const overview = fs.readFileSync(path.join(ROOT, 'src-tauri', 'src', 'commands', 'optimizer', 'overview.rs'), 'utf8');

// ---- 从 overview.rs 源码抽collect_checks 真正消费的字段（不靠手抄清单）----
const body = overview.slice(overview.indexOf('pub(super) fn collect_checks'), overview.indexOf('/// 切分 .reg 文本'));
const consumed = new Set();
for (const m of body.matchAll(/s\.get\("(\w+)"\)/g)) consumed.add(m[1]);
console.log(`collect_checks 实际消费的字段：${[...consumed].sort().join(', ')}`);

// 与 v2-M1 笔记里那份已知白名单一致吗（label 纯展示 / pwsh·cmd 靠脚本语义）
const KNOWN_WHITELIST = new Set(['label', 'pwsh', 'cmd']);
const stepFields = new Set();
for (const o of data) for (const s of o.steps || []) for (const k of Object.keys(s)) stepFields.add(k);
console.log(`数据层 steps 里出现的全部字段：${[...stepFields].sort().join(', ')}`);
const uncovered = [...stepFields].filter((f) => !consumed.has(f) && !KNOWN_WHITELIST.has(f));
console.log(`未被消费且不在白名单：${uncovered.length ? uncovered.join(', ') : '（无）'}\n`);

// ---- 逐项判定：能不能产出 Check ----
//规则与 collect_checks 一致：
//   reg → 解析 .reg 段与值行，值为 `-` 的占位跳过；有值才有 Check
//   service + disable===true → 一条 svc
//   service + startType存在 → 一条 svcStart
const parseRegSections = (block) => {
  const out = [];
  let cur = null, buf = '';
  for (const raw of String(block).split('\n')) {
    const t = raw.trimEnd();
    const tt = t.trim();
    if (tt.startsWith('[') && tt.endsWith(']') && tt.length >= 2) {
      if (cur !== null) out.push([cur, buf]);
      cur = tt.slice(1, -1).trim(); buf = '';
    } else if (cur !== null) buf += t + '\n';
  }
  if (cur !== null) out.push([cur, buf]);
  return out;
};
const parseRegValues = (bodyText) => {
  const out = [];
  for (const line of String(bodyText).split('\n')) {
    const t = line.trim();
    if (!t.startsWith('"')) continue;
    const rest = t.slice(1);
    const q = rest.indexOf('"');
    if (q < 0) continue;
    const eq = rest.slice(q + 1);
    if (!eq.startsWith('=')) continue;
    out.push([rest.slice(0, q), eq.slice(1).trim()]);
  }
  return out;
};

const blind = [];
const detectable = [];
for (const o of data) {
  const steps = o.steps || [];
  let nChecks = 0;
  const kinds = new Set();
  for (const s of steps) {
    if (typeof s.reg === 'string') {
      for (const [, segBody] of parseRegSections(s.reg)) {
        for (const [, raw] of parseRegValues(segBody)) {
          if (raw.trim() === '-') continue; // 还原占位
          nChecks++; kinds.add('reg');
        }
      }
    }
    if (s.service && s.disable === true) { nChecks++; kinds.add('svc'); }
    if (s.service && typeof s.startType === 'string') { nChecks++; kinds.add('svcStart'); }
  }
  const row = { id: o.id, title: o.title, group: o.group, risk: o.risk, nChecks, kinds: [...kinds], steps };
  if (nChecks === 0) blind.push(row); else detectable.push(row);
}

console.log(`可检测 ${detectable.length} / 盲区 ${blind.length}（共 ${data.length}）\n`);
const byRisk = {};
for (const b of blind) (byRisk[b.risk] ??= []).push(b);
for (const r of ['high', 'medium', 'low']) {
  const list = byRisk[r] || [];
  console.log(`—— risk=${r}：${list.length} 项 ——`);
  for (const b of list) {
    const stepKinds = [...new Set(b.steps.map((s) => s.reg ? 'reg' : s.pwsh ? 'pwsh' : s.cmd ? 'cmd' : s.service ? 'service' : Object.keys(s)[0]).filter(Boolean))];
    console.log(`  ${b.id}｜${b.title}｜group=${b.group}｜步形态=${stepKinds.join('+')}`);
  }
  console.log('');
}
const shape = {};
for (const b of blind) for (const s of b.steps) {
  const k = s.reg ? 'reg' : s.pwsh ? 'pwsh' : s.cmd ? 'cmd' : s.service ? 'service' : 'other';
  shape[k] = (shape[k] || 0) + 1;
}
console.log(`盲区 step 形态分布：${Object.entries(shape).map(([k, v]) => `${k}=${v}`).join('  ')}`);

// 顺带算 293 个 =- 占位（方案 §1.3-B的说法待验）
let dash = 0, dashItems = new Set();
for (const o of data) for (const s of o.restore || []) {
  if (typeof s.reg === 'string') for (const [, b] of parseRegSections(s.reg)) {
    for (const [, raw] of parseRegValues(b)) if (raw.trim() === '-') { dash++; dashItems.add(o.id); }
  }
}
console.log(`restore 里 =- 占位：${dash} 个，涉 ${dashItems.size} 项`);

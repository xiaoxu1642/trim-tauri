// D4 门控重算（R1-4b / 决策 D4）：126 项里到底有几项存在**真实硬件差异**？
//
// 为什么必须先算这个：十四项目对标方案 §5.8 估「硬件条件门控 2 人日」，
// 但那个估计没有回答「哪些项真的有硬件差异」。若结论是空集 ⇒ C3 直接废弃，
// 省下的是一整轮实现 + 一条要长期维护的门控侧表。
//
// 口径（必须可复现，R1-4b.2）：纯读数据层 + 规则文本，**不探测本机硬件**
// （探测会把「本机是什么」混进「设计上有没有差异」，而门控要的是后者）。
//
// 硬件差异的**判据**（四条，每条都能在数据层里机械找到证据）：
//   H1 步骤里出现 GPU 厂商分判（NVIDIA / AMD / Intel 的驱动名或注册表路径）
//   H2 步骤里出现电池 / 电源状态判据（Battery / 电池 / AC 电源 / 充电）
//   H3 步骤里出现硬件能力存在性判据（某个设备/处理器能力是否存在才生效）
//   H4 步骤里出现混合睡眠 / 现代待机 / S0 低功耗待机这类**电源状态机**分档
//
// 每条命中都要给出**具体证据**（哪一项、哪一步、命中哪条），不接受「大概有」。
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const data = JSON.parse(fs.readFileSync(path.join(ROOT, 'src-tauri', 'data', 'optimizer-runtime.json'), 'utf8'));

const H = {
  H1_GPU_VENDOR: /nvidia|nvapi|nv_|amd|radeon|amdk|ati\.?\s?i|intel|igdlv?c|igfx/i,
  H2_BATTERY: /battery|电池|充电|ac\s?power|on\s?battery|mains|ups\b/i,
  H3_CAPABILITY: /getpwrscheme|deviceexists|hasdevice|getdevice|capability|feature\s?present|isntdefender|presence/i,
  H4_POWER_STATE: /modern standby|modernstandby|混合睡眠|hybrid ?sleep|s0 ?low ?power|s3|suspend|低功耗待机|connected ?standby/i,
};

const rows = [];
for (const o of data) {
  const steps = [...(o.steps || []), ...(o.restore || [])];
  const hits = [];
  steps.forEach((s, idx) => {
    const label = s.label || `step${idx + 1}`;
    const blob = [s.cmd, s.pwsh, s.reg].filter(Boolean).join('\n');
    if (!blob) return;
    for (const [code, rx] of Object.entries(H)) {
      const m = blob.match(rx);
      if (m) hits.push({ code, label, evidence: m[0].slice(0, 60) });
    }
  });
  if (hits.length) {
    rows.push({ id: o.id, title: o.title, group: o.group, risk: o.risk, hits });
  }
}

console.log('=== D4 门控重算：126 项里存在真实硬件差异的项 ===\n');
console.log(`数据源：src-tauri/data/optimizer-runtime.json（${data.length} 项，活动清单）`);
console.log('口径：纯静态读数据层，不探测本机硬件\n');

const byCode = {};
for (const r of rows) for (const h of r.hits) (byCode[h.code] ??= []).push({ id: r.id, ...h });

for (const code of Object.keys(H)) {
  const list = byCode[code] || [];
  console.log(`${code}（${Object.keys(H).find((k) => k === code).match(/H\d_[A-Z_]+/)[0]}）：${list.length} 处命中`);
  for (const h of list.slice(0, 8)) console.log(`    ${h.id} / ${h.label} ← 「${h.evidence}」`);
  if (list.length > 8) console.log(`    …另 ${list.length - 8} 处`);
  console.log('');
}

const ids = [...new Set(rows.map((r) => r.id))];
console.log(`结论：命中硬件差异判据的项共 ${ids.length} 个 / ${data.length}`);
if (ids.length) {
  console.log('这些项：' + ids.join(', '));
  console.log('\n⚠️ 命中不等于「需要硬件门控」—— 还要逐条判断该条件是不是**该项生效的前提**。');
  console.log('   例如「关电池续航优化」这种项，写电池关键词只是描述对象，不是前置条件。');
} else {
  console.log('⇒ 空集。**C3 硬件条件门控（方案 §5.8，估 2 人日）直接废弃**。');
}

// 确定性自检：连跑两次结果必须一致（R1-4b.2）
const snapshot = JSON.stringify(rows);
if (process.argv.includes('--twice')) {
  const again = [];
  for (const o of data) {
    const steps = [...(o.steps || []), ...(o.restore || [])];
    const hits = [];
    steps.forEach((s, idx) => {
      const blob = [s.cmd, s.pwsh, s.reg].filter(Boolean).join('\n');
      if (!blob) return;
      for (const [code, rx] of Object.entries(H)) {
        const m = blob.match(rx);
        if (m) hits.push({ code, label: s.label || `step${idx + 1}`, evidence: m[0].slice(0, 60) });
      }
    });
    if (hits.length) again.push({ id: o.id, title: o.title, group: o.group, risk: o.risk, hits });
  }
  console.log('\n确定性自检：' + (JSON.stringify(again) === snapshot ? '两次一致 ✓' : '两次不一致 ✗'));
}

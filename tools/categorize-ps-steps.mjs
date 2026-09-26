// categorize-ps-steps.mjs —— 统计数据层 pwsh 步骤的指令模式，评估原生化覆盖面
import { readFileSync } from 'node:fs';
const d = JSON.parse(readFileSync('src-tauri/data/optimizer-runtime.json', 'utf8'));

const buckets = new Map();
const push = (k, v) => {
  if (!buckets.has(k)) buckets.set(k, []);
  buckets.get(k).push(v);
};

for (const o of d) {
  const id = o.id;
  for (const [phase, arr] of [['steps', o.steps || []], ['restore', o.restore || []]]) {
    for (const s of arr) {
      const code = s.pwsh;
      if (!code) continue;
      const lines = code.split('\n').map((l) => l.trim()).filter(Boolean);
      const kind = [];
      if (/New-ItemProperty|Set-ItemProperty/.test(code)) kind.push('New/Set-ItemProperty');
      if (/Remove-ItemProperty/.test(code)) kind.push('Remove-ItemProperty');
      if (/Stop-Service/.test(code)) kind.push('Stop-Service');
      if (/sc\.exe config|sc config/.test(code)) kind.push('sc config');
      if (/Get-ScheduledTask|Disable-ScheduledTask|Enable-ScheduledTask|Unregister-ScheduledTask|Register-ScheduledTask/.test(code)) kind.push('ScheduledTask');
      if (/New-Item|Remove-Item/.test(code)) kind.push('New/Remove-Item');
      if (/Start-Process/.test(code)) kind.push('Start-Process');
      if (/Get-ChildItem|Get-Item/.test(code)) kind.push('Get-Item');
      if (/foreach|ForEach-Object/.test(code)) kind.push('foreach');
      if (/Get-AppxPackage/.test(code)) kind.push('AppxPackage');
      if (/powercfg/.test(code)) kind.push('powercfg');
      if (/netsh/.test(code)) kind.push('netsh');
      if (/reg\.exe|reg add|reg delete/.test(code)) kind.push('reg.exe');
      if (kind.length === 0) kind.push('OTHER');
      push(kind.join('+'), `${id}:${phase}:${lines.length}L`);
    }
  }
}

const rows = [...buckets.entries()].sort((a, b) => b[1].length - a[1].length);
let total = 0;
for (const [k, v] of rows) {
  total += v.length;
  console.log(`${String(v.length).padStart(3)}  ${k}`);
  console.log(`      ${v.slice(0, 4).join(' | ')}${v.length > 4 ? ` …+${v.length - 4}` : ''}`);
}
console.log(`\nTOTAL pwsh steps: ${total}`);

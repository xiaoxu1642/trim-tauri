// count-pwsh-steps.mjs —— 临时统计：数据层里含 pwsh 步骤的优化项数量
import { readFileSync } from 'node:fs';
const d = JSON.parse(readFileSync('src-tauri/data/optimizer-runtime.json', 'utf8'));
let pwshItems = 0, pwshSteps = 0, total = 0, rItems = 0;
for (const o of d) {
  total++;
  const steps = o.steps || [];
  if (steps.some((s) => s.pwsh)) pwshItems++;
  pwshSteps += steps.filter((s) => s.pwsh).length;
  if ((o.restore || []).some((s) => s.pwsh)) rItems++;
}
console.log(`total items: ${total}`);
console.log(`items with pwsh in steps: ${pwshItems}`);
console.log(`pwsh steps total: ${pwshSteps}`);
console.log(`items with pwsh in restore: ${rItems}`);

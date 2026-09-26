// dump-ps-steps.mjs —— 打印 pwsh 步骤原文，用于设计原生化解析器
import { readFileSync } from 'node:fs';
const d = JSON.parse(readFileSync('src-tauri/data/optimizer-runtime.json', 'utf8'));
const ids = process.argv.slice(2);
for (const o of d) {
  if (ids.length && !ids.includes(o.id)) continue;
  for (const [phase, arr] of [['steps', o.steps || []], ['restore', o.restore || []]]) {
    arr.forEach((s, i) => {
      if (!s.pwsh) return;
      console.log(`\n===== ${o.id} [${phase}#${i}] =====`);
      console.log(s.pwsh);
    });
  }
}

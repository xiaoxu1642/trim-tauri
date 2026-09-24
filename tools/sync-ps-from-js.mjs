// sync-ps-from-js.mjs —— 从 JS 模块生成 src-tauri/ps/*.ps1（搬运唯一正确路径）
//
// 为什么不手工誊抄：JS 模板字面量有转义折叠（`\\`→`\`、`\*`→`*`、`\n`→换行…），
// 手工「还原」必然与 Electron 实际执行的脚本文本产生偏差，且偏差表现为**功能走错分支
// 而不报错**（Phase 1 已真实踩中一次，见 ps-mapping.mjs 注释）。
// 本生成器直接取 JS 运行时值，天然等价。
//
// 用法：node tools/sync-ps-from-js.mjs [--check]
//   --check：只比对不写盘（差异即退出码 1，可用于门禁）

import { createRequire } from 'node:module';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

import { MAPPING, withProvenance, stripProvenance, loadBody } from './ps-mapping.mjs';

const require = createRequire(import.meta.url);
const PSDIR = join(new URL('..', import.meta.url).pathname.replace(/^\//, '').replace(/\//g, '\\'), 'src-tauri', 'ps');
const CHECK_ONLY = process.argv.includes('--check');

let changed = 0;
for (const entry of MAPPING) {
  const body = loadBody(entry, require, readFileSync);
  const target = join(PSDIR, entry.ps1);
  const desired = withProvenance(entry, body);
  const current = existsSync(target) ? readFileSync(target, 'utf8') : null;
  // 只比较正文与来源行（来源说明文案改动不必重写文件）
  const same = current !== null && stripProvenance(current).body === stripProvenance(desired).body;
  if (same) {
    console.log(`✓ ${entry.ps1} 已同步（正文一致，${body.length} 字符）`);
    continue;
  }
  changed++;
  if (CHECK_ONLY) {
    console.log(`✗ ${entry.ps1} 与 JS 运行时值不一致`);
  } else {
    writeFileSync(target, desired, 'utf8');
    console.log(`↻ ${entry.ps1} 已按 JS 运行时值重写（${body.length} 字符）`);
  }
}

console.log(CHECK_ONLY ? `\n${changed === 0 ? '全部已同步' : `${changed} 个文件不一致`}` : `\n重写 ${changed} 个文件`);
process.exit(CHECK_ONLY && changed > 0 ? 1 : 0);
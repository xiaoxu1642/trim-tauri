// gen-optimizer-runtime.mjs —— 把 vendor 基线的 OPTIONS 序列化成
// `src-tauri/data/optimizer-runtime.json`（方案 v2 P0-1，2026-10-05）
//
// 为什么需要它：AGENTS §6 明写「优化项运行时数据」是生成器产物、**禁手改**，
// 但 tools/ 里从来没有这个生成器 —— 每次改优化项都在手改一个禁手改的文件，
// 并手工复刻 pros/cons/effect/restore/restoreInferred/restoreAvailable 等派生字段。
// 真源 = vendor/upstream-js/src/scripts-powershell/optimizer-scripts.js 的 OPTIONS
// （§5.12 只读基线；改条目按例外②姿势文本定位，别整文件换）。
//
// **字节格式是契约，不是审美**：单行、`,` 与 `: ` 后各一个空格（历史生成的 Python 口径，
// 全文件 17 万字节）。换成 JSON.stringify 的紧凑形会让整文件 byte diff、且破 §5.21
// 「数组原样 JSON.stringify」的复核前提。序列化后先 round-trip（parse 回来与源深等）
// 再允许写盘 —— 序列化器自身写坏时应当当场炸，而不是把坏字节写进产物。
//
// 改完数据必重签（§5.21 三坑：裸数组走 sidecar、别给数组挂 _sig、别重排格式）：
//   node tools/sign-cleanup-rules.mjs sign --file src-tauri/data/optimizer-runtime.json
//
// 用法：
//   node tools/gen-optimizer-runtime.mjs          只检查（不写盘），与产物不一致即非 0 退出
//   node tools/gen-optimizer-runtime.mjs --write  生成/覆盖 src-tauri/data/optimizer-runtime.json
'use strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { REPO_ROOT, ORIGIN } from './ps-origin.mjs';

const OUT = path.join(REPO_ROOT, 'src-tauri', 'data', 'optimizer-runtime.json');
const SRC = path.join(ORIGIN, 'src', 'scripts-powershell', 'optimizer-scripts.js');
const WRITE = process.argv.slice(2).includes('--write');

const require = createRequire(import.meta.url);
const { OPTIONS } = require(SRC);

if (!Array.isArray(OPTIONS) || OPTIONS.length === 0) {
  console.error(`✗ ${path.relative(REPO_ROOT, SRC)} 的 OPTIONS 不是非空数组（源形状变了？）`);
  process.exit(1);
}

// Python json.dumps 默认分隔符（', ' / ': '）的同形序列化器。
// 显式拒绝 undefined/function/symbol/bigint 与非有限数：JSON.stringify 会**静默丢弃/写坏**
// 这些值，那样产物与源「看起来对上了」其实缺字段 —— 这里必须炸。
function serialize(v) {
  if (v === null) return 'null';
  const t = typeof v;
  if (t === 'string') return JSON.stringify(v);
  if (t === 'boolean') return v ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isFinite(v)) throw new Error(`OPTIONS 里出现非有限数字：${v}`);
    return String(v);
  }
  if (Array.isArray(v)) return '[' + v.map(serialize).join(', ') + ']';
  if (t === 'object') {
    return '{' + Object.entries(v).map(([k, x]) => JSON.stringify(k) + ': ' + serialize(x)).join(', ') + '}';
  }
  throw new Error(`OPTIONS 里出现不可序列化类型 ${t}（JSON.stringify 会静默丢弃，这里显式拒）`);
}

const want = serialize(OPTIONS);
if (JSON.stringify(JSON.parse(want)) !== JSON.stringify(OPTIONS)) {
  console.error('✗ 序列化 round-trip 结果与源深等失败（序列化器坏了，拒绝写盘）');
  process.exit(1);
}

const rel = path.relative(REPO_ROOT, OUT).replace(/\\/g, '/');

if (WRITE) {
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, want, 'utf8');
  console.log(`✓ 已生成 ${rel}（${OPTIONS.length} 项）`);
  console.log('  下一步（§5.21）：node tools/sign-cleanup-rules.mjs sign --file src-tauri/data/optimizer-runtime.json');
  process.exit(0);
}

if (!fs.existsSync(OUT)) {
  console.error(`✗ ${rel} 不存在。跑：node tools/gen-optimizer-runtime.mjs --write`);
  process.exit(1);
}
const got = fs.readFileSync(OUT, 'utf8');
if (got !== want) {
  console.error(`✗ ${rel} 与 vendor OPTIONS 不一致（改了源忘重出，或手改了 data/*.json）`);
  console.error('  修法：node tools/gen-optimizer-runtime.mjs --write 然后重签（§5.21）');
  let i = 0;
  while (i < Math.min(got.length, want.length) && got[i] === want[i]) i++;
  console.error(`  首个差异在第 ${i} 字节：产物 "${got.slice(i, i + 40)}" vs 源 "${want.slice(i, i + 40)}"`);
  process.exit(1);
}
console.log(`✓ ${rel} 与 vendor OPTIONS 逐字节一致（${OPTIONS.length} 项）`);

// gen-bugcheck-codes.mjs —— 把 tools/bugcheck-codes.source.mjs 序列化成
// `src-tauri/data/bugcheck-codes.json`（Rainz 对标 §3.1，2026-10-03）
//
// 为什么单独一个生成器而不"直接手写 JSON"：AGENTS §6「生成器产出的数据文件不要手改」——
// 反过来也成立：**能被生成的东西就不该在 data/ 里被手工编辑**，否则下一位作者看到
// JSON 会以为它就是真源，改动直接落到派生物上、下次重跑生成器又没了。
// 蓝屏码库的真源在 source.mjs（那里能带注释解释「为什么这条归到这个 cat」），
// JSON 只是 Rust include_str! 要读的字节。
//
// 用法：
//   node tools/gen-bugcheck-codes.mjs           只检查（不写盘），源与产物不一致即非 0 退出
//   node tools/gen-bugcheck-codes.mjs --write   生成/覆盖 src-tauri/data/bugcheck-codes.json
'use strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  BUGCHECK_CODES,
  CATS,
  FALLBACK_DEFAULT,
  FALLBACK_RULES,
  validateEntries,
} from './bugcheck-codes.source.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'src-tauri', 'data', 'bugcheck-codes.json');

const argv = process.argv.slice(2);
const WRITE = argv.includes('--write');

// 排序按 code 升序：diff 稳定、门禁「code 不重复」判据线性扫一遍即可
const sorted = [...BUGCHECK_CODES].sort((a, b) => a.code - b.code);

const errors = validateEntries(sorted);
if (errors.length) {
  console.error(`✗ 源结构校验失败（${errors.length} 处）：`);
  for (const e of errors.slice(0, 20)) console.error('  ' + e);
  process.exit(1);
}

const pkg = {
  // code 字段用 0x 十六进制字符串：JSON 里放 u32 数字，读的人看不出 0x116 vs 278
  // 到底是不是同一码；字符串反而更贴近微软 Learn 上的写法。
  // 数字型 `code` 保留，让 Rust 侧 include_str! + serde 直接反序列化到 u32。
  _meta: {
    schema: 'trim.bugcheck-codes.v1',
    total: sorted.length,
    cats: [...CATS],
    source: 'tools/bugcheck-codes.source.mjs',
    note: '派生物：改动请回到 source.mjs，跑 node tools/gen-bugcheck-codes.mjs --write 重出',
  },
  entries: sorted.map((e) => ({
    code: e.code,
    hex: '0x' + e.code.toString(16).padStart(8, '0').toUpperCase(),
    name: e.name,
    cat: e.cat,
    meaning: e.meaning,
    causes: e.causes,
    solution: e.solution,
  })),
  fallbackRules: FALLBACK_RULES.map((r) => ({ id: r.id, cat: r.cat, why: r.why })),
  fallbackDefault: { ...FALLBACK_DEFAULT },
};

const want = JSON.stringify(pkg, null, 2) + '\n';

function exists() {
  try {
    return fs.statSync(OUT).isFile();
  } catch {
    return false;
  }
}

if (WRITE) {
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, want, 'utf8');
  console.log(`✓ 已生成 ${path.relative(ROOT, OUT)}（${sorted.length} 条 / ${CATS.length} 分类）`);
  process.exit(0);
}

if (!exists()) {
  console.error(`✗ ${path.relative(ROOT, OUT)} 不存在。跑：node tools/gen-bugcheck-codes.mjs --write`);
  process.exit(1);
}
const got = fs.readFileSync(OUT, 'utf8');
if (got !== want) {
  console.error('✗ 产物与源不一致（多半是改了 source.mjs 忘了重出，或手改了 data/*.json）');
  console.error('  修法：node tools/gen-bugcheck-codes.mjs --write');
  // 打一个粗略的字节差位置，方便人定位
  let i = 0;
  while (i < Math.min(got.length, want.length) && got[i] === want[i]) i++;
  console.error(`  首个差异在第 ${i} 字节：产物 "${got.slice(i, i + 40).replace(/\n/g, '\\n')}" vs 源 "${want.slice(i, i + 40).replace(/\n/g, '\\n')}"`);
  process.exit(1);
}
console.log(`✓ 产物与源一致：${sorted.length} 条 / ${CATS.length} 分类 / ${FALLBACK_RULES.length} 条兜底归类`);

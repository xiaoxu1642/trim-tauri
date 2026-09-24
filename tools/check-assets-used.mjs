// check-assets-used.mjs —— 「frontendDist 里不许躺无人引用的资源」门禁（审查 v2-L8）
//
// 为什么需要它：`tauri.conf.json` 的 build.frontendDist = `../src`，**src/ 下的每个字节都会进产物**。
// v2-L8 实测 `src/assets/ico/` 11 个文件里 9 个零引用、共 3,414,696 B（母版 source_squared.png
// 2,713,043 + source.png 670,086 + 7 个 icon_NxNxN.png 31,567），另 douyin.ico 29,801 B 也只被
// `pathbinding.js:2` 的内联 base64 顶替、运行期无人加载。这类件不会报错、只会一直躺在安装包里。
//
// 判据（刻意保守，宁可不判红也不误判）：
//   ① 枚举 `src/` 全部文件；
//   ② 在**引用语料**里找它的 basename（全名匹配，不做模糊）；
//   ③ 语料不含文件自身 —— 自己提自己的名字不算被引用；
//   ④ 语料**排除 `vendor/` 与 `docs/`**：前者是只读上游基线（它的注释里写着
//      「如 src/assets/ico/douyin.ico」，算进来就等于让一个死文件自我证明活着），
//      后者不入库。真正会加载它们的只有前端代码与 Rust 侧（建窗 URL / bundle 清单）。
//
// 用法：node tools/check-assets-used.mjs [--verbose]
//   --verbose  逐条打印每个资源的命中处
// 退出码：0 = 全部资源都有引用（或在白名单里登记了理由）；1 = 有零引用资源

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, basename, relative } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

const VERBOSE = process.argv.includes('--verbose');
const DIST = join(REPO_ROOT, 'src');            // = tauri.conf.json 的 build.frontendDist
const KB = (n) => `${(n / 1024).toFixed(1)} KB`;

/**
 * 已登记例外：零引用但**刻意**留在产物里的资源，必须写清为什么。
 * 判红时先看这里有没有；加条目的门槛是「说得出运行期为什么需要它在包里」。
 */
const WHITELIST = new Map([
  // 例：'src/assets/ico/foo.png' → '由 <某处> 以 <方式> 加载'
]);

/** 引用语料：会真的加载资源的那些地方（前端源码 + Rust 侧 + 打包清单 + 能力面） */
const CORPUS_DIRS = [
  join(REPO_ROOT, 'src'),
  join(REPO_ROOT, 'src-tauri', 'src'),
];
const CORPUS_FILES = [
  join(REPO_ROOT, 'src-tauri', 'tauri.conf.json'),
  join(REPO_ROOT, 'src-tauri', 'Cargo.toml'),   // bundle/resources 之类的清单也可能点名
];

function walk(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

// 语料只收文本件（图片/字体当语料既慢又会误命中字节序列）
const isCorpusText = (f) => /\.(?:js|mjs|cjs|css|html|json|toml|rs|md|txt)$/i.test(f);
const corpus = [];
for (const d of CORPUS_DIRS) for (const f of walk(d)) if (isCorpusText(f)) corpus.push(f);
for (const f of CORPUS_FILES) if (existsSync(f) && isCorpusText(f)) corpus.push(f);

const texts = corpus.map((f) => [f, readFileSync(f, 'utf8')]);
const assets = walk(DIST);

let unused = 0;
let unusedBytes = 0;
console.log('=== frontendDist 资源引用门禁（v2-L8）===');
console.log(`产物目录 src/ = ${assets.length} 个文件；引用语料 ${texts.length} 个文本件（不含 vendor/、docs/）\n`);
for (const f of assets) {
  const rel = relative(REPO_ROOT, f).replace(/\\/g, '/');
  const size = statSync(f).size;
  const name = basename(f);
  const hits = [];
  for (const [cf, text] of texts) {
    if (cf === f) continue;                      // 自引用不算被引用
    if (text.includes(name)) hits.push(relative(REPO_ROOT, cf).replace(/\\/g, '/'));
  }
  if (hits.length || WHITELIST.has(rel)) {
    if (VERBOSE) console.log(`✓ ${rel} (${KB(size)})  ←  ${hits.length ? hits.slice(0, 3).join(', ') : WHITELIST.get(rel)}`);
    continue;
  }
  unused++;
  unusedBytes += size;
  console.log(`✗ ${rel} (${KB(size)}) 无人引用 —— 它仍会随 frontendDist 进产物`);
}

if (unused) {
  console.log(`\n※ 零引用资源 ${unused} 个、共 ${(unusedBytes / 1024 / 1024).toFixed(2)} MB。`
    + `确认运行期不需要就搬出 src/（母版/未打包资产放仓库根的 assets-src/，它不在 frontendDist 里），`
    + `确实要在包里但靠动态拼名加载的，进本文件 WHITELIST 并写明理由。`);
}
console.log(`\n${unused === 0 ? '✓ 产物里没有零引用资源' : `✗ ${unused} 个零引用资源待处理`}`);
process.exit(unused === 0 ? 0 : 1);

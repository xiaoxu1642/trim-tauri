// check-assets-used.mjs —— 「frontendDist 里不许躺无人引用的资源」门禁（审查 v2-L8）
//
// 为什么需要它：`tauri.conf.json` 的 build.frontendDist = `../src`，**src/ 下的每个字节都会进产物**。
// v2-L8 实测 `src/assets/ico/` 11 个文件里 9 个零引用、共 3,414,696 B（母版 source_squared.png
// 2,713,043 + source.png 670,086 + 7 个 icon_NxNxN.png 31,567），另 douyin.ico 29,801 B 也只被
// `src/scripts/pathbinding.js` 的内联 base64 顶替、运行期无人加载。这类件不会报错、只会一直躺在安装包里。
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

import { readFileSync, statSync, existsSync } from 'node:fs';
import { join, basename, relative } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';
import { walkFiles } from './lib/fs-walk.mjs';
import { blankNonCode } from './lib/src-scan.mjs';

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
// T1d-M06：头注一直声称排除 vendor/，但 walkFiles 没传 ignoreDir——上游基线的注释
// 里写一句文件名就能让死资源自我证明。这里把排除真正落实。
const CORPUS_DIRS = [
  { dir: join(REPO_ROOT, 'src'), ignoreDir: (n) => n === 'vendor' },
  { dir: join(REPO_ROOT, 'src-tauri', 'src') },
];
const CORPUS_FILES = [
  join(REPO_ROOT, 'src-tauri', 'tauri.conf.json'),
  join(REPO_ROOT, 'src-tauri', 'Cargo.toml'),   // bundle/resources 之类的清单也可能点名
];

// 语料只收文本件（图片/字体当语料既慢又会误命中字节序列）
const isCorpusText = (f) => /\.(?:js|mjs|cjs|css|html|json|toml|rs|md|txt)$/i.test(f);
const corpus = [];
for (const d of CORPUS_DIRS) {
  for (const f of walkFiles(d.dir, null, d.ignoreDir ? { ignoreDir: d.ignoreDir } : {})) {
    if (isCorpusText(f)) corpus.push(f);
  }
}
for (const f of CORPUS_FILES) if (existsSync(f) && isCorpusText(f)) corpus.push(f);

/** 只剥注释、保留字符串：资源名通常写在字符串字面量里（url()/src=/include_bytes!）。 */
function stripCommentsForRefs(file, text) {
  if (/\.(?:js|mjs|cjs)$/i.test(file)) return blankNonCode(text, 'js', { keepStrings: true });
  if (/\.rs$/i.test(file)) return blankNonCode(text, 'rs', { keepStrings: true });
  if (/\.css$/i.test(file)) return text.replace(/\/\*[\s\S]*?\*\//g, ' ');
  if (/\.html$/i.test(file)) return text.replace(/<!--[\s\S]*?-->/g, ' ');
  return text;
}
const texts = corpus.map((f) => [f, stripCommentsForRefs(f, readFileSync(f, 'utf8'))]);
const assets = walkFiles(DIST);

/** 引用命中 = basename 出现在「剥注释后」的语料代码里；文件自身不算。 */
function referenceHits(name, self, corpusTexts) {
  return corpusTexts
    .filter(([cf, code]) => cf !== self && code.includes(name))
    .map(([cf]) => relative(REPO_ROOT, cf).replace(/\\/g, '/'));
}

let unused = 0;
let unusedBytes = 0;
console.log('=== frontendDist 资源引用门禁（v2-L8）===');
console.log(`产物目录 src/ = ${assets.length} 个文件；引用语料 ${texts.length} 个文本件（不含 vendor/、docs/）\n`);
// v2-L4P-16（E-1）：0 对象即红——目录名改错/扫描器失效时「0 个资源全通过」是假绿。
// 正向对照：src/ 下 JS 文件数必须 > 0（前端目录存在的前提）。
if (assets.length === 0 || !texts.length) {
  console.error(`✗ 扫描对象为空（assets=${assets.length}, corpus=${texts.length}）——门禁失效方向判红，请检查 DIST/语料配置`);
  process.exit(1);
}
for (const f of assets) {
  const rel = relative(REPO_ROOT, f).replace(/\\/g, '/');
  const size = statSync(f).size;
  const name = basename(f);
  const hits = referenceHits(name, f, texts);   // 自引用不算被引用
  if (hits.length || WHITELIST.has(rel)) {
    if (VERBOSE) console.log(`✓ ${rel} (${KB(size)})  ←  ${hits.length ? hits.slice(0, 3).join(', ') : WHITELIST.get(rel)}`);
    continue;
  }
  unused++;
  unusedBytes += size;
  console.log(`✗ ${rel} (${KB(size)}) 无人引用 —— 它仍会随 frontendDist 进产物`);
}

// ---- T1d-M06 正向对照：注释提及不算引用、vendor/ 不在语料 ----
{
  const commentOnly = '// 见 src/assets/ico/Trim.ico\nconst x = 1;\n';
  const commentHits = referenceHits('Trim.ico', '(self)', [['sample.js', stripCommentsForRefs('sample.js', commentOnly)]]);
  if (commentHits.length !== 0) {
    console.error('✗ T1d-M06 正向对照失败：注释里的资源名仍被当成引用（剥注释失效）');
    process.exit(1);
  }
  const realRef = "const icon = 'src/assets/ico/Trim.ico';";
  const realHits = referenceHits('Trim.ico', '(self)', [['sample.js', stripCommentsForRefs('sample.js', realRef)]]);
  if (realHits.length !== 1) {
    console.error('✗ T1d-M06 正向对照失败：字符串里的真实引用未被识别（剥注释过严）');
    process.exit(1);
  }
  const vendorLeak = corpus
    .map((f) => relative(REPO_ROOT, f).replace(/\\/g, '/'))
    .filter((f) => /(^|\/)src\/vendor(\/|$)/.test(f));
  if (vendorLeak.length !== 0) {
    console.error(`✗ T1d-M06：语料仍包含 vendor/（${vendorLeak.slice(0, 3).join('、')}）—— 上游基线不得替资源作证`);
    process.exit(1);
  }
  console.log('✓ T1d-M06 参照对照：注释提及不计、真实字符串引用命中、vendor/ 已排除');
}

if (unused) {
  console.log(`\n※ 零引用资源 ${unused} 个、共 ${(unusedBytes / 1024 / 1024).toFixed(2)} MB。`
    + `确认运行期不需要就搬出 src/（母版/未打包资产放仓库根的 assets-src/，它不在 frontendDist 里），`
    + `确实要在包里但靠动态拼名加载的，进本文件 WHITELIST 并写明理由。`);
}

// ---- v2-L4P-45（F-11）：src-tauri/icons 只读枚举台账 ----
// 此前门禁只扫 frontendDist（src/），看不见 src-tauri/icons：那里 17 个
// Square*/StoreLogo 等 Windows 打包位图不在 bundle.icon 清单里、语料也零引用，
// 但它们由 Tauri bundler 按 targets 隐式消费，**不可删**。这里做双向台账：
// 盘上→清单（orphan 打印）、清单→盘上（missing 判红）——bundle.icon 指向缺失文件时，
// 打包会失败/缺图标，不能让 check-asset-size 那个只扫 src/ 的门禁背锅。
const ICONS_DIR = join(REPO_ROOT, 'src-tauri', 'icons');
if (existsSync(ICONS_DIR)) {
  const conf = JSON.parse(readFileSync(join(REPO_ROOT, 'src-tauri', 'tauri.conf.json'), 'utf8'));
  const bundled = new Set((conf.bundle?.icon ?? []).map((s) => s.replace(/^icons\//, '')));
  const icons = walkFiles(ICONS_DIR);
  const missingBundle = [...bundled].filter((n) => !icons.some((f) => basename(f) === n));
  if (missingBundle.length) {
    console.error(`✗ bundle.icon 指向不存在的文件：${missingBundle.join('、')}`);
    process.exit(1);
  }
  const orphan = [];
  for (const f of icons) {
    const name = basename(f);
    if (bundled.has(name)) continue;
    const referenced = texts.some(([cf, text]) => cf !== f && text.includes(name));
    if (!referenced) orphan.push(name);
  }
  console.log(`\nsrc-tauri/icons 台账：共 ${icons.length} 个，bundle.icon 点名 ${bundled.size} 个，` +
    `语料引用后零引用 ${orphan.length} 个（bundler 按 targets 隐式消费，刻意保留）：`);
  if (orphan.length) console.log('  ' + orphan.join(', '));
  if (icons.length === 0) {
    console.error('✗ icons 目录为空——图标枚举失效方向判红');
    process.exit(1);
  }
}
console.log(`\n${unused === 0 ? '✓ 产物里没有零引用资源' : `✗ ${unused} 个零引用资源待处理`}`);
process.exit(unused === 0 ? 0 : 1);

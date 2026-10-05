#!/usr/bin/env node
// check-release-freshness.mjs —— 产物新鲜度门禁（审查 K5 彻底方案 / §8 技术债第 1 条）
//
// 抓什么：`build-release/` 里当前版本的四件套 mtime，必须**晚于**全部参与构建的源文件。
// 抓的缺陷形态：源码改了、产物没重发。K5 就是这个形态 —— 上一轮审查发现「v0.5.6 的
// 产物里不含已修的漏洞」，而当时没有任何东西会红：产物比源码旧是发版流程的**正常**
// 中间态（改完代码还没到发版），把它判红会让门禁天天红、于是被忽略。
//
// 所以本门禁是 **OPTIONAL（不进 AGENTS §4 必跑）**，只在两种时刻有意义：
//   ① 发版前，人工触发确认「我要发的这批产物确实包含当前全部源码」；
//   ② 审查/复核时，确认线上产物不是上一版代码打的包。
// 日常迭代不跑它 —— 那正是它可选的原因，不是它没用。
//
// 为什么仍然值得写（而不是继续靠人肉 `ls -la`）：
//   · 人肉比的是「产物 mtime vs 我记得的某个文件 mtime」，记不住就会漏；
//   · K5 复核时用了**两条独立证据**（mtime + 产物字节扫描 + 线上实拉）才敢下结论，
//     说明单靠一条证据自己也不够 —— 这里把「mtime 比对」固化成脚本，
//     字节扫描那类重手段留给需要时的人工复核。
//
// 判定口径（为什么用 mtime 而不是内容哈希）：
//   mtime 判不出「改了又改回」，但那种情况**产物内容本来就是对的**（内容一致），
//   危害为零；mtime 判不出的是「源码新、产物旧」—— 正是 K5 那类真缺陷。
//   哈希能判得更准，但要求每次跑门禁都解包/读 22MB 的 exe，成本与收益不成比例。
//
// 用法：
//   node tools/check-release-freshness.mjs            # 用 tauri.conf.json 的当前版本
//   node tools/check-release-freshness.mjs 0.5.7     # 指定版本号
//   node tools/check-release-freshness.mjs --list     # 只列产物与最新源文件时间，不判定
//
// 退出码：0 全绿或 SKIP（有产物缺失 / 显式 SKIP）/ 1 产物陈旧或台账异常。
// **无产物时 SKIP 而非判红**：新克隆的仓库没有 build-release/，那是正常状态。
// 但「有 setup.exe 却缺 .sig / 缺清单」判红 —— 那是资产不齐（v0.3.5/0.3.6 同型事故）。

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'build-release');

let failed = 0;
const fail = (msg) => { console.error(`✗ ${msg}`); failed++; };
const ok = (msg) => console.log(`✓ ${msg}`);
const skip = (msg) => console.log(`○ ${msg}`);

const args = process.argv.slice(2);
const LIST_ONLY = args.includes('--list');
const VERSION = args.find((a) => !a.startsWith('--')) || '';

/** 取 mtime（ms），文件/目录都在时返回；不存在返回 null（**不抛**，让调用方决定判红还是 SKIP） */
function mtime(p) {
  try {
    return statSync(p).mtimeMs;
  } catch {
    return null;
  }
}

/**
 * 收集「参与构建的源文件」清单。
 *
 * 口径与理由：
 *   · `src/`、`src-tauri/src`、`src-tauri/*.toml`、`src-tauri/data`、`src-tauri/ps`、
 *     `native-scanner/src`、`vendor/`、`tools/`（含门禁与生成器）—— 凡是能进包的
 *     都要算，漏一个方向就漏一类陈旧产物。
 *   · **排除** `target/`（构建目录本身，mtime 永远最新，会把一切判成新鲜）、
 *     `node_modules`、`docs/`（不入库的分析资料）、`build-release` 自身。
 *   · 只认文件，不认目录（目录 mtime 会被「新建/删除文件」改动，与内容无关）。
 */
const SRC_ROOTS = [
  'src',
  'src-tauri/src',
  'src-tauri/data',
  'src-tauri/ps',
  'src-tauri/tauri.conf.json',
  'src-tauri/Cargo.toml',
  'src-tauri/Cargo.lock',
  'src-tauri/build.rs',
  'native-scanner/src',
  'native-scanner/Cargo.toml',
  'vendor',
  'tools',
];
const EXCLUDE_DIRS = new Set(['target', 'node_modules', '.git', 'build-release', 'docs']);

function walk(dir, out) {
  let ents;
  try {
    ents = readdirSync(dir, { withFileTypes: true });
  } catch {
    return; // 目录不存在 = 该路径没进包，跳过（不是缺陷）
  }
  for (const e of ents) {
    if (EXCLUDE_DIRS.has(e.name)) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (e.isFile()) out.push(p);
  }
}

const srcFiles = [];
for (const r of SRC_ROOTS) {
  const p = join(ROOT, r);
  if (existsSync(p) && statSync(p).isFile()) srcFiles.push(p);
  else walk(p, srcFiles);
}

console.log('=== 产物新鲜度门禁（源码 mtime vs build-release 产物 mtime）===\n');

// ── 0. 版本号：显式实参优先，否则取 conf（清单/产物名都按这个版本号拼） ──
let ver = VERSION;
if (!ver) {
  try {
    ver = String(JSON.parse(readFileSync(join(ROOT, 'src-tauri/tauri.conf.json'), 'utf8')).version ?? '');
  } catch (e) {
    fail(`读 tauri.conf.json 失败：${e.message}`);
  }
}
if (!ver) {
  fail('拿不到版本号（显式实参没给，conf 也没读到）——本门禁无法判定，判红');
} else if (!/^\d+\.\d+\.\d+$/.test(ver)) {
  fail(`版本号不是 x.y.z 三段：${ver}（产物名与清单名都按三段拼，写错会静默找不到产物）`);
}

console.log(`版本：${ver || '?'}    源文件：${srcFiles.length} 个\n`);

// ── 1. 没产物 = SKIP，不判红（新克隆仓库的正常状态） ──
if (!existsSync(OUT)) {
  skip(`build-release/ 不存在 —— 无产物可比对，SKIP（日常迭代态；发版前请先 cargo tauri build）`);
  console.log('\ncheck-release-freshness: SKIP（无产物）');
  process.exit(0);
}

// 产物四件套。**清单也参与判定**：清单的 version/url/signature 由 make-latest-json.py
// 从产物字节生成，清单独独旧于源码同样是发布事故（客户端被钉死上一版）。
const artifacts = [
  { name: `Trim_${ver}_x64-setup.exe`, why: 'NSIS 安装包' },
  { name: `Trim_${ver}_x64-setup.exe.sig`, why: 'minisign 签名（requireSignedVersion 硬要求）' },
  { name: `Trim_${ver}_x64-portable.zip`, why: '便携包' },
  { name: 'latest.json', why: 'GitHub 线路清单（Release 资产）' },
  { name: 'latest-gitee.json', why: 'Gitee 线路清单（raw/main 托管，同时是仓根那份的源）' },
];

if (LIST_ONLY) {
  console.log('产物：');
  for (const a of artifacts) {
    const t = mtime(join(OUT, a.name));
    console.log(`  ${t === null ? '（缺失）' : new Date(t).toISOString().slice(0, 19).replace('T', ' ')}  ${a.name}`);
  }
  let newest = -1, newestF = '';
  for (const f of srcFiles) {
    const t = mtime(f) || 0;
    if (t > newest) { newest = t; newestF = f; }
  }
  console.log(`\n最新源文件：${newestF ? `${relative(ROOT, newestF).split(sep).join('/')}  ${new Date(newest).toISOString().slice(0, 19).replace('T', ' ')}` : '（无）'}`);
  console.log('\ncheck-release-freshness: --list 模式不做判定');
  process.exit(0);
}

// 资产不齐判红（不 SKIP）：有 setup.exe 却缺 sig/清单 = v0.3.5/0.3.6「资产缺一无人发现」同型
const missing = artifacts.filter((a) => !existsSync(join(OUT, a.name)));
const present = artifacts.filter((a) => existsSync(join(OUT, a.name)));
if (present.length === 0) {
  skip(`build-release/ 里没有版本 ${ver} 的任何产物 —— SKIP（尚未构建该版本）`);
  console.log('\ncheck-release-freshness: SKIP（该版本无产物）');
  process.exit(0);
}
for (const a of missing) fail(`产物缺失：${a.name}（${a.why}）—— 资产不齐，发版会让客户端拉不到或验签失败`);

// ── 2. 产物 vs 源文件：最旧产物必须比最新源文件新 ──
let newestSrc = -1;
let newestSrcRel = '';
for (const f of srcFiles) {
  const t = mtime(f);
  if (t !== null && t > newestSrc) { newestSrc = t; newestSrcRel = relative(ROOT, f).split(sep).join('/'); }
}
if (newestSrc < 0) {
  fail('源文件清单为空 —— 扫描口径失效（src/ 与 src-tauri/ 都不存在？），本门禁此刻什么都证明不了');
}

let oldestArt = Infinity;
let oldestArtName = '';
for (const a of present) {
  const t = mtime(join(OUT, a.name));
  if (t !== null && t < oldestArt) { oldestArt = t; oldestArtName = a.name; }
}

const fmt = (t) => new Date(t).toISOString().slice(0, 19).replace('T', ' ');
console.log(`最新源文件：${newestSrcRel}  ${fmt(newestSrc)}`);
console.log(`最旧产物　：${oldestArtName}  ${fmt(oldestArt)}\n`);

if (oldestArt <= newestSrc) {
  fail(
    `产物陈旧：${oldestArtName}（${fmt(oldestArt)}）早于源码 ${newestSrcRel}（${fmt(newestSrc)}）`,
  );
  console.error('   ⇒ 当前 build-release/ 里的包不包含最近这批源码改动。若要发布，必须重跑');
  console.error('     cargo tauri build → 重签 → 重打 zip → 重出两份清单（顺序见 AGENTS §7）。');
  console.error('   ⇒ 若你只是改了代码、还没到发版时刻：本门禁是 OPTIONAL，忽略即可，不必改产物。');
} else {
  ok(`产物新鲜：最旧产物比最新源文件晚 ${Math.round((oldestArt - newestSrc) / 1000)} 秒`);
}

// ── 3. 清单 version 自洽（产物区两份清单必须指向当前版本） ──
for (const name of ['latest.json', 'latest-gitee.json']) {
  const p = join(OUT, name);
  if (!existsSync(p)) continue;
  try {
    const j = JSON.parse(readFileSync(p, 'utf8'));
    const v = String(j.version ?? '');
    if (v !== ver) fail(`${name} 的 version=${v} ≠ 当前版本 ${ver} —— 该清单会把客户端钉在旧版`);
    else ok(`${name} version 与当前版本一致（${v}）`);

    // 3b. signature 必须是「一层 base64 的四行 minisign 文本」。
    //     多套一层就是 2026-10-05 那次事故：客户端下载完报 Invalid encoding in minisign data，
    //     而检查更新一路正常 —— 只有真跑一遍下载才暴露，所以这条必须在发版前静态拦住。
    const sig = String(j.signature ?? '');
    const platSig = String(j?.platforms?.['windows-x86_64']?.signature ?? '');
    if (!sig) {
      fail(`${name} 缺 signature 字段`);
    } else {
      const inner = Buffer.from(sig, 'base64').toString('utf8').split(/\r?\n/).filter((l) => l.length);
      const shapeOk = inner.length === 4
        && inner[0].startsWith('untrusted comment: ')
        && inner[2].startsWith('trusted comment: ')
        && Buffer.from(inner[1], 'base64').length === 74
        && Buffer.from(inner[3], 'base64').length === 64;
      if (!shapeOk) {
        fail(`${name} 的 signature 不是「一层 base64 的四行 minisign 文本」（解出 ${inner.length} 行，长度 ${sig.length}）`
          + ' —— 插件 verify_signature 只做一次 base64 解码，多套一层会让全部客户端验签失败');
      } else if (!new RegExp(`version:${ver.replace(/\./g, '\\.')}`).test(inner[2])) {
        fail(`${name} 的 signature trusted comment 里没有 version:${ver} —— requireSignedVersion 会判 MissingSignedVersion`);
      } else {
        ok(`${name} signature 形状与 version:${ver} 正确`);
      }
      if (platSig !== sig) fail(`${name} 顶层 signature 与 platforms.windows-x86_64.signature 不一致（客户端按平台位取，两处不同必有一处验不过）`);
    }

    // 3c. 清单声明的 sha256 必须等于**实际安装包**的哈希（没声明就 SKIP，不判红：
    //     清单可以不写这个字段，客户端只把它当交叉核对值）
    const exe = join(OUT, `Trim_${ver}_x64-setup.exe`);
    const declared = String(j?.platforms?.['windows-x86_64']?.sha256 ?? j.sha256 ?? '');
    if (!declared) {
      skip(`${name} 未声明 sha256 —— 客户端只做 minisign 验签，哈希交叉核对**未启用**`);
    } else if (!existsSync(exe)) {
      skip(`${name} 声明了 sha256，但本机没有 Trim_${ver}_x64-setup.exe 可比对`);
    } else {
      const actual = createHash('sha256').update(readFileSync(exe)).digest('hex');
      if (actual !== declared.toLowerCase()) {
        fail(`${name} 的 sha256=${declared} ≠ 实际安装包 ${actual} —— 客户端会拒绝安装（清单与产物不是同一份）`);
      } else {
        ok(`${name} 的 sha256 与实际安装包一致（${actual.slice(0, 12)}…）`);
      }
    }
  } catch (e) {
    fail(`${name} 解析失败：${e.message}`);
  }
}

console.log('');
if (failed > 0) {
  console.error(`check-release-freshness: ${failed} 处不一致`);
  process.exit(1);
}
console.log('check-release-freshness: 全部通过');

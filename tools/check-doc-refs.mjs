#!/usr/bin/env node
// check-doc-refs.mjs —— 本地文档互引路径存在性 + 禁第二真源私钥路径
// （v2-L4P-42 / D-3、C-7、A-7，2026-10-02）
//
// 抓什么：
//   1. AGENTS.md 与 src-tauri/src/** 注释里引用的本地文档路径必须真实存在——
//      「红线指向虚无的文件」是流程性缺陷（L4 D-3 实例：依赖登记处指向一份磁盘上
//      不存在的迁移方案文档，导致「新 feature 是否登记」永远无法判红）。
//   2. 源码注释不得再写死签名私钥的第二真源路径（A-7：updater.rs 曾维护一份
//      私钥路径 + CI 流程，与 AGENTS §7.4 互相漂移）。
// 口径：只检查「看起来像本仓路径」的引用（docs/... 或 `docs\xxx`），排除 URL、
// 代码目录（src/、src-tauri/、tools/ 等由既有门禁管）、Cargo/registry 路径。
'use strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, relative, dirname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

import { walkFiles } from './lib/fs-walk.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = join(ROOT, 'src-tauri', 'src');
const FRONTEND = join(ROOT, 'src');

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

// docs/ 下的真实文件集合（相对小写路径，供快速命中）
//
// `docs/` 与 `AGENTS.md` 都是**未跟踪**的本机资料区（.gitignore 第 8/10 行），干净克隆里
// 根本不存在。必做门禁读它们之前必须先问在不在：
// - 直接 readdirSync 会 ENOENT 崩（2026-10-04 实测）；
// - 把「对照集为空」当成判定基础更糟 —— 空集会让每一条 docs/ 引用都判「不存在」，
//   于是缺文件被渲染成满屏假红。两种都改成显式 SKIP 并声明未校验。
const DOCS_DIR = join(ROOT, 'docs');
const AGENTS_MD = join(ROOT, 'AGENTS.md');
const docsPresent = existsSync(DOCS_DIR);
const agentsPresent = existsSync(AGENTS_MD);
const docsFiles = new Set(
  docsPresent
    ? walkFiles(DOCS_DIR).map((p) => relative(ROOT, p).replace(/\\/g, '/').toLowerCase())
    : [],
);
if (!docsPresent) console.log('⚠ docs/ 不在本机（未跟踪的本机资料区）：docs 引用存在性**未校验**');
if (!agentsPresent) console.log('⚠ AGENTS.md 不在本机（未跟踪）：1b 未执行');

// 引用形态：`docs/xxx.md` / `docs\xxx.md`（词边界内，排除 https:// 等 URL）
const REF_RE = /(?<![:\w/\\])(docs[\\/][A-Za-z0-9\u4e00-\u9fa5._\-\\/\s]+?\.(?:md|json|mjs|js|ps1))(?![\w\\/])/g;
// 1a. 源码 + 前端注释里引用的 docs/ 路径必须存在（docs/ 缺席时跳过，见上方说明）
const refHits = [];
const scanRoots = [SRC, FRONTEND];
if (docsPresent) {
  for (const base of scanRoots) {
    for (const fAbs of walkFiles(base)) {
      const text = readFileSync(fAbs, 'utf8');
      const rel = relative(ROOT, fAbs).replace(/\\/g, '/');
      for (const m of text.matchAll(REF_RE)) {
        const norm = normalize(m[1].replace(/\\/g, '/')).replace(/\\/g, '/').toLowerCase();
        if (!docsFiles.has(norm)) {
          refHits.push(`${rel}: ${m[1].trim()}`);
        }
      }
    }
  }
}
check(
  !docsPresent || refHits.length === 0,
  docsPresent
    ? '1a. 源码注释引用的 docs/ 路径全部真实存在（D-3：红线不许指向虚无）'
    : '1a. docs/ 引用检查 SKIP（本机未跟踪资料区不存在）',
  refHits.length ? refHits.join('；') : `${docsFiles.size} 个 docs 文件作为对照集`,
);

// 1b. AGENTS.md 自身引用的 docs/ 路径必须存在
if (agentsPresent && docsPresent) {
  const text = readFileSync(AGENTS_MD, 'utf8');
  const bad = [];
  for (const m of text.matchAll(REF_RE)) {
    const norm = normalize(m[1].replace(/\\/g, '/')).replace(/\\/g, '/').toLowerCase();
    if (!docsFiles.has(norm)) bad.push(m[1].trim());
  }
  check(bad.length === 0, '1b. AGENTS.md 引用的 docs/ 路径全部真实存在', bad.join('；'));
}

// 2. 源码注释禁止第二真源私钥路径（签发流程唯一真源 = AGENTS §7.4）
//
// v5-K04 批次 7（2026-10-13）修补「三重失明」（T1c 实测）：
//   ① 令牌黑名单收编 `~/.trim-signing` 变体（`trim-signing` 单词覆盖全部含它的写法）；
//   ② 语料扩面：tools/ 与 vendor/ 也扫，且 **全行扫**（Rust 的 panic!/assert 文案是
//      字符串字面量不是注释行，contract_tests.rs:2011 型漏报就在这）；
//   ③ 受控例外按 {file, anchor} 白名单（§5.19 键形，禁行号），且每条必须真的命中
//      ≥1 次（白名单不命中 = 腐烂，判红——正向对照）。
// 受控例外的位置/理由/范围登记在发版手册 §7.3「受控例外」小节。
const KEY_TOKENS = [
  'trim-updater.key',
  '~/.tauri-signer',
  'TAURI_SIGNING_PRIVATE_KEY',
  'trim-signing', // v5-K04：私钥目录名（~/.trim-signing 及一切变体）
];
const KEY_SCAN_ROOTS = [SRC, FRONTEND, join(ROOT, 'tools'), join(ROOT, 'vendor')];
const KEY_PATH_WHITELIST = [
  {
    file: 'tools/sign-cleanup-rules.mjs',
    anchor: "path.join(os.homedir(), '.trim-signing'",
    why: '签名工具自身必须知道钥匙在哪（功能必需）',
  },
  {
    file: 'vendor/upstream-js/src/main/rules-signature.js',
    anchor: '默认 ~/.trim-signing/',
    why: 'vendor 只读基线禁改',
  },
  {
    file: 'vendor/upstream-js/src/main/update-signature.js',
    anchor: '默认 ~/.trim-signing/',
    why: 'vendor 只读基线禁改',
  },
];
const keyHits = [];
const whitelistHits = new Set();
for (const base of KEY_SCAN_ROOTS) {
  for (const fAbs of walkFiles(base)) {
    const rel = relative(ROOT, fAbs).replace(/\\/g, '/');
    // 判据定义文件自身必须排除：KEY_TOKENS/白名单的字面量写在这里，扫它会自举命中。
    // 它不是泄漏面（令牌是判据，不是私钥落点）；真正要盯的是**其他任何文件**。
    if (rel === 'tools/check-doc-refs.mjs') continue;
    const lines = readFileSync(fAbs, 'utf8').split(/\r?\n/);
    lines.forEach((line, i) => {
      for (const t of KEY_TOKENS) {
        if (!line.includes(t)) continue;
        const wl = KEY_PATH_WHITELIST.find((w) => w.file === rel && line.includes(w.anchor));
        if (wl) {
          whitelistHits.add(wl.file);
          continue;
        }
        keyHits.push(`${rel}:${i + 1} 含 ${t}`);
      }
    });
  }
}
check(
  keyHits.length === 0,
  '2. 私钥第二真源路径零暴露（注释与字符串字面量全行扫：src/src 前端/tools/vendor）',
  keyHits.join('；'),
);
const missingWhitelist = KEY_PATH_WHITELIST.filter((w) => !whitelistHits.has(w.file));
check(
  missingWhitelist.length === 0,
  `2b. 受控例外白名单 ${KEY_PATH_WHITELIST.length} 条全部真实命中（不命中 = 白名单腐烂）`,
  missingWhitelist.map((w) => `${w.file}（${w.why}）`).join('；'),
);

// ---- 3. 白名单坐标存在性（P3-7，2026-10-09） ----
// AGENTS.md 反引号点名的**仓内具体坐标**（tools//src//src-tauri//native-scanner//vendor/
// 开头的路径）必须落盘 —— 已删的双跑工具 `tools/dual-run-batchA.mjs` 此前仍被白名单
// 点名，就是这条缺口的实例（v4 §1.3）。带 * ? { } | 的 glob/占位形态不判。
// AGENTS.md 缺席（干净克隆）⇒ 显式 SKIP，声明本节未校验。
if (agentsPresent) {
  const CODE_REF_RE = /`((?:tools|src|src-tauri|native-scanner|vendor)\/[\w./\u4e00-\u9fa5-]+)`/g;
  const named = [];
  const ghost = [];
  for (const m of readFileSync(AGENTS_MD, 'utf8').matchAll(CODE_REF_RE)) {
    const p = m[1];
    if (/[*?{}|]/.test(p)) continue;
    named.push(p);
    if (!existsSync(join(ROOT, p))) ghost.push(p);
  }
  check(
    named.length >= 8,
    `3. AGENTS.md 点名的仓内坐标 ${named.length} 处（≥8 地板，防解析失明）`,
    named.length < 8 ? '命中趋零 ⇒ 语料或正则失明' : '',
  );
  check(
    ghost.length === 0,
    '3b. 点名的仓内坐标全部落盘（白名单不许指向已删除的文件）',
    ghost.join('；'),
  );
} else {
  console.log('⚠ AGENTS.md 不在本机（未跟踪）：3 白名单坐标存在性**未校验**（SKIP，不是通过）');
}

// ---- 4. U8（v5 批次 9 门禁候选 9）：本机审查文档的表值必须带可重跑取数命令 ----
// 《方法论》等 docs/ 文档的表格数字是下一轮审查的派单依据；表值旁没有取数命令，
// 数字漂移就无人能发现（X0-3 现算 14+12 处过期）。docs/ 是未跟踪本机资料区：
// 缺席时显式 SKIP，**不是通过**。本批落地骨架（标记存在性 + 地板）；过期值全量
// 修复按修复方案 §4 归后续批次，不冒充已修。
{
  const METH = join(DOCS_DIR, '本仓库审查规范', '本仓库审查方法论.md');
  if (existsSync(METH)) {
    const text = readFileSync(METH, 'utf8');
    // 表值行（| 开头且含两位以上数字）粗数，作扫描面地板
    const tableRows = text.split('\n').filter((l) => /^\s*\|/.test(l) && /\d{2,}/.test(l)).length;
    check(
      tableRows >= 50,
      `4. U8 语料自检：《方法论》表格行 ${tableRows}（≥ 50 地板，防解析失明）`,
      tableRows < 50 ? '表格行趋零 ⇒ 文件被搬/改名或解析失明' : '',
    );
    const withCmd = (text.match(/现算|取数命令|命令：/g) || []).length;
    check(
      withCmd >= 10,
      `4b. U8 骨架：取数标记 ${withCmd} 处（≥ 10；**骨架版**——26 处过期值全量修复归后续批次，修复方案 §4）`,
      withCmd < 10 ? '取数标记趋零 ⇒ U8 判据失明' : '',
    );
  } else {
    console.log('⚠ U8：《方法论》不在本机（未跟踪资料区）——表值取数命令检查**未校验**（SKIP，不是通过）');
  }
}

if (fail > 0) {
  console.error('check-doc-refs: 存在漂移');
  process.exit(1);
}
console.log('check-doc-refs: 全部通过');

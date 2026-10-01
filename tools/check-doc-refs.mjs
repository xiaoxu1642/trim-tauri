#!/usr/bin/env node
// check-doc-refs.mjs —— 本地文档互引路径存在性 + 禁第二真源私钥路径
// （v2-L4P-42 / D-3、C-7、A-7，2026-10-02）
//
// 抓什么：
//   1. AGENTS.md 与 src-tauri/src/** 注释里引用的本地文档路径必须真实存在——
//      「红线指向虚无的文件」是流程性缺陷（L4 D-3：依赖登记处指向不存在的
//      `docs/Tauri迁移方案-可执行版.md`，导致「新 feature 是否登记」永远无法判红）。
//   2. 源码注释不得再写死签名私钥的第二真源路径（A-7：updater.rs 曾维护一份
//      私钥路径 + CI 流程，与 AGENTS §7.4 互相漂移）。
// 口径：只检查「看起来像本仓路径」的引用（docs/... 或 `docs\xxx`），排除 URL、
// 代码目录（src/、src-tauri/、tools/ 等由既有门禁管）、Cargo/registry 路径。
'use strict';
import { readdirSync, statSync, readFileSync, existsSync } from 'node:fs';
import { join, relative, dirname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = join(ROOT, 'src-tauri', 'src');
const FRONTEND = join(ROOT, 'src');

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

// docs/ 下的真实文件集合（相对小写路径，供快速命中）
function walkDocs(dir, out = []) {
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walkDocs(p, out);
    else out.push(relative(ROOT, p).replace(/\\/g, '/').toLowerCase());
  }
  return out;
}
const docsFiles = new Set(walkDocs(join(ROOT, 'docs')));

// 引用形态：`docs/xxx.md` / `docs\xxx.md`（词边界内，排除 https:// 等 URL）
const REF_RE = /(?<![:\w/\\])(docs[\\/][A-Za-z0-9\u4e00-\u9fa5._\-\\/\s]+?\.(?:md|json|mjs|js|ps1))(?![\w\\/])/g;
// 1a. 源码 + 前端注释里引用的 docs/ 路径必须存在
const refHits = [];
const scanRoots = [SRC, FRONTEND];
for (const base of scanRoots) {
  for (const f of walkDocs(base)) {
    const text = readFileSync(join(ROOT, f), 'utf8');
    for (const m of text.matchAll(REF_RE)) {
      const norm = normalize(m[1].replace(/\\/g, '/')).replace(/\\/g, '/').toLowerCase();
      if (!docsFiles.has(norm)) {
        refHits.push(`${relative(ROOT, f).replace(/\\/g, '/')}: ${m[1].trim()}`);
      }
    }
  }
}
check(
  refHits.length === 0,
  '1a. 源码注释引用的 docs/ 路径全部真实存在（D-3：红线不许指向虚无）',
  refHits.length ? refHits.join('；') : `${docsFiles.size} 个 docs 文件作为对照集`,
);

// 1b. AGENTS.md 自身引用的 docs/ 路径必须存在
{
  const text = readFileSync(join(ROOT, 'AGENTS.md'), 'utf8');
  const bad = [];
  for (const m of text.matchAll(REF_RE)) {
    const norm = normalize(m[1].replace(/\\/g, '/')).replace(/\\/g, '/').toLowerCase();
    if (!docsFiles.has(norm)) bad.push(m[1].trim());
  }
  check(bad.length === 0, '1b. AGENTS.md 引用的 docs/ 路径全部真实存在', bad.join('；'));
}

// 2. 源码注释禁止第二真源私钥路径（签发流程唯一真源 = AGENTS §7.4）
const KEY_TOKENS = ['trim-updater.key', '~/.tauri-signer', 'TAURI_SIGNING_PRIVATE_KEY'];
const keyHits = [];
for (const f of walkDocs(SRC)) {
  const lines = readFileSync(join(ROOT, f), 'utf8').split(/\r?\n/);
  lines.forEach((line, i) => {
    if (!line.trimStart().startsWith('//') && !line.trimStart().startsWith('//!')) return;
    for (const t of KEY_TOKENS) {
      if (line.includes(t)) keyHits.push(`${relative(SRC, f).replace(/\\/g, '/')}:${i + 1} 含 ${t}`);
    }
  });
}
check(
  keyHits.length === 0,
  '2. 源码注释零第二真源私钥路径（A-7：签发流程只看 AGENTS §7.4）',
  keyHits.join('；'),
);

if (fail > 0) {
  console.error('check-doc-refs: 存在漂移');
  process.exit(1);
}
console.log('check-doc-refs: 全部通过');

#!/usr/bin/env node
// check-pending-batch-limit.mjs —— 「后端单批登记上限 ⇄ 前端唯一导出值」跨语言对拍（v7.2 P1 · F4a1-L09）
//
// 来源：P1-W3 单元代理交付片段 uF4a1c-gate.snippet.mjs，主 agent 2026-10-22 落成真门禁。
// 片段原本建议并入 check-data-parity 的组结构以「不增门禁条数」，这里刻意**单独成条**：
// 判据 §4.1「形似不合」的问句是「合并后若其一被放宽，另一条还能不能独立判红」——
// 本条钉的是 IPC 载荷上限（数值 + 锚点唯一性 + 消费面命中），与 check-data-parity 钉的
// 「data JSON ⇄ vendor 上游逐字段」不是同一件事，合进一个文件会让「关掉 parity 复算」
// 顺手把这条也关掉。条数由 check-gate-roster 现算，不靠手工守恒。
//
// 抓什么：`PENDING_ADD_MAX_ITEMS` 的真源只有一处（Rust `pending_delete.rs`）。前端由
// `tauri-api.js` 导出 `window.ipcLimits.pendingAddMaxItems`，`cleanup.js` / `residue-window.js`
// 读它切片。此前两文件各抄一份同名不同形的字面量、注释都自称「与后端一致」却无对拍
// ⇒ 后端下调即前端整批被拒「请分批登记」，正是 AGENTS §5.16「判据与数值表不许两套实现」
// 的跨语言那一支。
//
// 四条断言：
//   A 两侧锚点各命中**且只命中一次**（命中 0 或 ≥2 都判红，防判定正则失效冒充绿）；
//   B 数值相等，ok 文案点名两侧实际值；
//   C `src/scripts/**` 全量不得再出现批量字面量副本（找违规型，先剥注释再扫，§4.1②）；
//   D 正向对照：两个消费文件必须真的在读导出，`reached` 集合逐个点名。
//
// 合成样本对照（CONTROLS 8 组）**每次运行都跑**，不再是 `--selftest` 才跑：判红能力必须
// 随每轮验收一起被看见，否则「对照块坏了」这件事没有腿会报（`check-positive-controls`
// 因此才能把本条登记成「内置正向对照」而不是欠账）。`--selftest` 保留为只跑对照的调试档。
//
// 新增别的 IPC 载荷上限时：把它加进同一张锚点表（值仍只许在 Rust 侧），别再往 src/ 抄字面量。
//
// 用法：node tools/check-pending-batch-limit.mjs
//      node tools/check-pending-batch-limit.mjs --selftest   只跑合成样本对照
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';

const RS_REL = ['src-tauri', 'src', 'commands', 'uninstall', 'pending_delete.rs'].join('/');
const API_REL = ['src', 'scripts', 'tauri-api.js'].join('/');
const SCRIPTS_REL = ['src', 'scripts'].join('/');
// 消费面点名：正向对照要求这两个文件恰好都在读导出（少了就是漏改，多了不用管）
const CONSUMERS = ['cleanup.js', 'residue-window.js'];
const EXPORT_USE = 'ipcLimits.pendingAddMaxItems';

const RE_RS = /pub\(super\)\s+const\s+PENDING_ADD_MAX_ITEMS\s*:\s*usize\s*=\s*(\d+)\s*;/g;
const RE_API = /pendingAddMaxItems\s*:\s*(\d+)/g;
// 批量字面量副本：前端一旦写回 `PENDING_ADD_BATCH = 32` / `PENDING_BATCH = 32` 即红
const RE_LITERAL = /\bPENDING(?:_ADD)?_BATCH\s*=\s*\d+/g;

const hits = (text, re) => { re.lastIndex = 0; return [...text.matchAll(re)]; };
// 判定面先剥注释：门禁自己（和被改过）的注释也算语料，注释里举例写一份字面量会自判红
function stripComments(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/^\s*(\/\/|\/\/\/|\/\*).*$|^\s*\/\/.*$/gm, (m) => ' '.repeat(m.length))
    .replace(/([^:])\/\/[^\n]*/g, '$1');
}

/** 核心判据：纯函数，返回违规清单（空数组 = 全绿）；ok 文案由调用方用第 3 个返回值拼 */
function judge(rsText, apiText, consumerTexts, otherTexts = {}) {
  const bad = [];
  const rsHits = hits(rsText, RE_RS);
  const apiHits = hits(apiText, RE_API);
  if (rsHits.length !== 1) bad.push(`后端锚点 PENDING_ADD_MAX_ITEMS 命中 ${rsHits.length} 处（须恰好 1 处，0=常量改名/删除时本门禁没跟着改，≥2=判定面已不可辨）`);
  if (apiHits.length !== 1) bad.push(`前端锚点 pendingAddMaxItems 命中 ${apiHits.length} 处（须恰好 1 处）`);
  let pair = null;
  if (rsHits.length === 1 && apiHits.length === 1) {
    pair = { backend: Number(rsHits[0][1]), frontend: Number(apiHits[0][1]) };
    if (pair.backend !== pair.frontend) {
      bad.push(`数值分叉：后端 ${pair.backend} ≠ 前端导出 ${pair.frontend}（真源只许在 Rust，前端值由本门禁对拍，不许再抄第三遍）`);
    }
  }
  const dup = [];
  for (const [name, text] of Object.entries(consumerTexts)) {
    const l = hits(stripComments(text), RE_LITERAL);
    if (l.length) dup.push(`${name}:${JSON.stringify(l.map((m) => m[0]))}`);
  }
  for (const [name, text] of Object.entries(otherTexts)) {
    const l = hits(stripComments(text), RE_LITERAL);
    if (l.length) dup.push(`${name}:${JSON.stringify(l.map((m) => m[0]))}`);
  }
  if (dup.length) bad.push(`src/scripts 里存在批量字面量副本 ${dup.join('；')}（第三抄：值必须读 tauri-api.js 的导出）`);
  const reached = CONSUMERS.filter((n) => (consumerTexts[n] || '').includes(EXPORT_USE));
  if (reached.length !== CONSUMERS.length) {
    bad.push(`消费面未全部读导出（应 ${CONSUMERS.length} 个，实到 ${reached.length}：${reached.join(', ') || '无'}）`);
  }
  return { bad, pair, reached };
}

// ---------- P2 合成样本：证明每条断言既能判红、又不在干净样本上假红 ----------
const CLEAN_API = `Object.defineProperty(window, 'ipcLimits', { value: { pendingAddMaxItems: 32 } });`;
const CLEAN_RS = `pub(super) const PENDING_ADD_MAX_ITEMS: usize = 32;`;
const CLEAN_CONSUMERS = {
  'cleanup.js': `const PENDING_ADD_BATCH = window.${EXPORT_USE};`,
  'residue-window.js': `const PENDING_BATCH = window.${EXPORT_USE};`,
};
const CONTROLS = [
  ['干净样本不假红', judge(CLEAN_RS, CLEAN_API, CLEAN_CONSUMERS).bad.length === 0],
  ['前端导出值改 33 必红', judge(CLEAN_RS, CLEAN_API.replace('32', '33'), CLEAN_CONSUMERS).bad.length > 0],
  ['后端锚点消失必红', judge('// 常量已改名', CLEAN_API, CLEAN_CONSUMERS).bad.length > 0],
  ['前端锚点重复必红', judge(CLEAN_RS, CLEAN_API + CLEAN_API, CLEAN_CONSUMERS).bad.length > 0],
  ['消费面字面量副本回归必红', judge(CLEAN_RS, CLEAN_API,
    { ...CLEAN_CONSUMERS, 'cleanup.js': CLEAN_CONSUMERS['cleanup.js'] + ' const PENDING_ADD_BATCH = 32;' }).bad.length > 0],
  ['消费面漏读导出必红（reached 只 1 个）', judge(CLEAN_RS, CLEAN_API,
    { ...CLEAN_CONSUMERS, 'residue-window.js': 'const PENDING_BATCH = 32;' }).bad.length > 0],
  ['非消费文件偷抄字面量必红', judge(CLEAN_RS, CLEAN_API, CLEAN_CONSUMERS,
    { 'uninstall.js': 'const PENDING_BATCH = 32;' }).bad.length > 0],
  ['注释里的举例不判红（§4.1②）', judge(CLEAN_RS, CLEAN_API,
    { ...CLEAN_CONSUMERS, 'cleanup.js': CLEAN_CONSUMERS['cleanup.js'] + '\n// 旧写法 const PENDING_ADD_BATCH = 32; ' }).bad.length === 0],
];

/** 合成样本对照：违例必须判红、干净样本不得假红。返回失效组数。 */
function runControls() {
  let bad = 0;
  for (const [label, got] of CONTROLS) {
    if (!got) { console.log(`✗ 正向对照失败：${label}`); bad++; }
    else console.log(`✓ 合成样本 ${label}`);
  }
  console.log(bad
    ? `自检 ${bad} 组失效（对照块坏了 ⇒ 本门禁的判红能力不可信）`
    : `自检 ${CONTROLS.length} 组全部命中（违例必红 + 干净不假红）`);
  return bad;
}

function main() {
  // 对照块先跑且**恒跑**：它坏了，后面那条「现盘一致」的绿就没有意义。
  const controlBad = runControls();
  if (process.argv.includes('--selftest')) return controlBad ? 1 : 0;
  {
    let d = process.argv[2] && !process.argv[2].startsWith('-') ? process.argv[2] : process.cwd();
    while (!existsSync(join(d, 'src-tauri', 'Cargo.toml')) && d !== join(d, '..')) d = join(d, '..');
    const pick = (p) => join(d, p);
    const [rsPath, apiPath, scriptsDir] = [pick(RS_REL), pick(API_REL), pick(SCRIPTS_REL)];
    for (const [p, label] of [[rsPath, RS_REL], [apiPath, API_REL], [scriptsDir, SCRIPTS_REL]]) {
      if (!existsSync(p)) {
        console.log(`SKIP：${label} 不在本机 ⇒ 本节**未校验**（不是通过；文件齐全时才会判红/判绿）`);
        return controlBad ? 1 : 0;
      }
    }
    const rsText = readFileSync(rsPath, 'utf8');
    const apiText = readFileSync(apiPath, 'utf8');
    const consumerTexts = {};
    for (const n of CONSUMERS) {
      const p = join(scriptsDir, n);
      if (!existsSync(p)) { console.log(`SKIP 消费面：${n} 不在，D 组未校验`); continue; }
      consumerTexts[n] = readFileSync(p, 'utf8');
    }
    const otherTexts = {};
    for (const n of readdirSync(scriptsDir).filter((n) => n.endsWith('.js') && !CONSUMERS.includes(n))) {
      otherTexts[n] = readFileSync(join(scriptsDir, n), 'utf8');
    }
    const r = judge(rsText, apiText, consumerTexts, otherTexts);
    if (r.bad.length) {
      for (const b of r.bad) console.log(`✗ ${b}`);
      console.log(`check-pending-batch-limit: ${r.bad.length} 处不一致`);
      return 1;
    }
    console.log(`✓ 后端 PENDING_ADD_MAX_ITEMS=${r.pair.backend} ⇄ 前端 ipcLimits.pendingAddMaxItems=${r.pair.frontend}，`
      + `锚点各 1 处、src/scripts 全量无字面量副本、消费面命中 ${r.reached.map((n) => relative(d, join(scriptsDir, n)).replace(/\\/g, '/')).join(' + ')}`);
    return controlBad ? 1 : 0;
  }
}
process.exit(main());

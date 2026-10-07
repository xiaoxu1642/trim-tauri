#!/usr/bin/env node
// check-rule-schema-sync.mjs —— 规则契约表 ⇄ Rust 装载侧同步门禁（v3 审查 C-4，2026-10-07）
//
// 抓什么（`engine/rule_schema.rs` 用 include_str! 编译期嵌入 `tools/rule-schema.json`，
// 是契约表的运行期消费侧；两边字节同源，但「引用姿势」与「查询键」没有东西守着）：
//   1. include_str! 路径必须逐字钉在 tools/rule-schema.json —— 路径被换掉后 Rust 单测
//      仍可能全绿（读得到另一份文件），只有文本对拍能发现；
//   2. rule_schema.rs 非测试区不得出现契约表 token 词汇的字面量（第二真源回潮即红）；
//   3. 两域**实际被查询**的键（req_list/req_number/rs::list/rs::number 调用点字面量）必须
//      都在表里 —— 键被删/改名时访问器静默拿到 None；Rust 侧有手抄清单测试，本门禁
//      从调用点现算，两处互相独立（§4.1「形似不合」：不抄判定结论，只共享口径）；
//   4. crossTrack 被消费的三个键、两域 tokens 结构必须齐备。
//
// 与既有门禁的分工：check-cleanup-rule-contract / check-residue-rule-contract 看的是
// 「库 ⇄ 表」一致；Rust 单测看的是「手抄清单 ⇄ 表」存在性；本门禁补的是「Rust 文本 ⇄ 表」。
// 用法：node tools/check-rule-schema-sync.mjs
'use strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SCHEMA_FILE = join(ROOT, 'tools', 'rule-schema.json');
const RUST_SCHEMA = join(ROOT, 'src-tauri', 'src', 'engine', 'rule_schema.rs');
const RULES_RS = join(ROOT, 'src-tauri', 'src', 'commands', 'cleanup', 'rules.rs');
const RESIDUE_RS = join(ROOT, 'src-tauri', 'src', 'commands', 'uninstall', 'residue_update.rs');

const INCLUDE_PIN = 'include_str!("../../../tools/rule-schema.json")';

// ---------- 判定器（纯函数：真扫描与正向对照共用同一份实现） ----------

function stripTestSection(rustText) {
  const at = rustText.indexOf('#[cfg(test)]');
  return { hadTestSection: at >= 0, text: at >= 0 ? rustText.slice(0, at) : rustText };
}

function checkIncludePath(rustText) {
  return rustText.includes(INCLUDE_PIN);
}

function vocabViolations(rustText, schema) {
  const { hadTestSection, text } = stripTestSection(rustText);
  const bad = [];
  if (!hadTestSection) bad.push('rule_schema.rs 找不到 #[cfg(test)] 区 —— 剥离失败，词汇检查口径已失效，先修门禁');
  const tokens = [
    ...(schema.cleanup?.tokens?.allowed ?? []),
    ...(schema.residue?.tokens?.allowed ?? []),
  ];
  for (const t of tokens) {
    if (text.includes(t)) bad.push(`rule_schema.rs 非测试区出现契约表 token 字面量「${t}」（第二真源回潮）`);
  }
  return { bad, tokenCount: tokens.length };
}

const keysFrom = (text, re) => [...new Set([...text.matchAll(re)].map((m) => m[1]))];

/// floors=true 时对「现算出的键数量」施加地板：抓取口径失效（正则过时/代码改写）与
/// 「真的没有查询」都会让本门禁退化成恒绿 —— 用地板把前者钉红（§4.1 找违规型门禁纪律）。
function queryKeyViolations(rulesText, residueText, schema, { floors = true } = {}) {
  const bad = [];
  const counts = [];
  const cases = [
    [
      'cleanup req_list',
      keysFrom(rulesText, /req_list\("cleanup",\s*"(\w+)"\)/g),
      (k) => Array.isArray(schema.cleanup?.[k]) && schema.cleanup[k].length > 0,
      20,
    ],
    [
      'cleanup req_number',
      keysFrom(rulesText, /req_number\("cleanup",\s*"(\w+)"\)/g),
      (k) => typeof (schema.cleanup?.limits?.[k] ?? schema.cleanup?.[k]) === 'number',
      8,
    ],
    [
      'residue rs::list',
      keysFrom(residueText, /rs::list\("residue",\s*"(\w+)"\)/g),
      (k) => Array.isArray(schema.residue?.[k]) && schema.residue[k].length > 0,
      5,
    ],
    [
      'residue rs::number',
      keysFrom(residueText, /rs::number\("residue",\s*"(\w+)"\)/g),
      (k) => typeof (schema.residue?.limits?.[k] ?? schema.residue?.[k]) === 'number',
      5,
    ],
  ];
  for (const [label, keys, okFn, floor] of cases) {
    if (floors && keys.length < floor) {
      bad.push(`${label} 只现算出 ${keys.length} 个查询键（地板 ${floor}）—— 抓取口径或代码形态变了，核对后再改地板`);
    }
    for (const k of keys) {
      if (!okFn(k)) bad.push(`${label} 查询的键「${k}」在 tools/rule-schema.json 里不存在或形态不符（装载侧会静默取到 None）`);
    }
    counts.push(`${label}=${keys.length}`);
  }
  const crossKeys = keysFrom(rulesText, /rule_schema::cross\("(\w+)"\)/g);
  if (floors && crossKeys.length < 3) bad.push(`rule_schema::cross 只现算出 ${crossKeys.length} 个键（地板 3）`);
  for (const k of crossKeys) {
    if (!Array.isArray(schema.crossTrack?.[k])) bad.push(`crossTrack.${k} 不存在或非数组（A13 活来源/分流登记会静默为空）`);
  }
  counts.push(`cross=${crossKeys.length}`);
  for (const dom of ['cleanup', 'residue']) {
    const t = schema[dom]?.tokens;
    if (!Array.isArray(t?.allowed) || t.allowed.length === 0 || typeof t?.caseInsensitive !== 'boolean') {
      bad.push(`${dom}.tokens 结构不符（需要非空 allowed[] + caseInsensitive bool）`);
    }
  }
  const tokenCount = (schema.cleanup?.tokens?.allowed?.length ?? 0) + (schema.residue?.tokens?.allowed?.length ?? 0);
  return { bad, counts, tokenCount };
}

// ---------- 正向对照：判定器必须先能对已知违规判红，才允许看真仓 ----------

const MINI_SCHEMA = {
  cleanup: { topFields: ['id'], limits: { maxItems: 10 }, tokens: { allowed: ['%WINDIR%'], caseInsensitive: false } },
  residue: { ruleKinds: ['kind'], limits: { maxRules: 5 }, tokens: { allowed: ['%TEMP%'], caseInsensitive: true } },
  crossTrack: { liveSourceKeys: [], deadSourceKeys: [], specialHandlers: [] },
};
const CLEAN_RUST_HEAD = `const CONTRACT_JSON: &str = ${INCLUDE_PIN};`;
const CLEAN_RUST = `${CLEAN_RUST_HEAD}\n#[cfg(test)]\nmod tests {}`;
const CLEAN_RULES = 'req_list("cleanup", "topFields");\nreq_number("cleanup", "maxItems");\nrule_schema::cross("liveSourceKeys");';
const CLEAN_RESIDUE = 'rs::list("residue", "ruleKinds");\nrs::number("residue", "maxRules");';

const POSITIVE_CONTROLS = [
  ['干净样本应全过', () => [
    ...(checkIncludePath(CLEAN_RUST) ? [] : ['include 路径判定器误红']),
    ...vocabViolations(CLEAN_RUST, MINI_SCHEMA).bad,
    ...queryKeyViolations(CLEAN_RULES, CLEAN_RESIDUE, MINI_SCHEMA, { floors: false }).bad,
  ].join('；')],
  ['注入 token 字面量应判红', () => {
    const leak = `${CLEAN_RUST_HEAD}\nconst LEAK: &str = "%WINDIR%";\n#[cfg(test)]\nmod tests {}`;
    const bad = vocabViolations(leak, MINI_SCHEMA).bad;
    return bad.some((x) => x.includes('%WINDIR%')) ? '' : '词汇判定器没抓住已知的 token 字面量注入';
  }],
  ['查询到表里没有的键应判红', () => {
    const bad = queryKeyViolations(`${CLEAN_RULES}\nreq_list("cleanup", "nope");`, CLEAN_RESIDUE, MINI_SCHEMA, { floors: false }).bad;
    return bad.some((x) => x.includes('nope')) ? '' : '键存在性判定器没抓住已知的缺键查询';
  }],
  ['include 路径漂移应判红', () =>
    checkIncludePath(CLEAN_RUST.replace('tools/rule-schema.json', 'tools/rule-schema-old.json'))
      ? '路径钉判定器没抓住已知的路径漂移'
      : ''],
  ['丢掉 #[cfg(test)] 标记（剥离失败）应判红', () => {
    const nomark = `${CLEAN_RUST_HEAD}\nconst X: &str = "%TEMP%";`;
    const bad = vocabViolations(nomark, MINI_SCHEMA).bad;
    return bad.some((x) => x.includes('找不到 #[cfg(test)]')) ? '' : '剥离失败没有被点名';
  }],
];

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== 判定器正向对照（先判红，再扫真仓）===');
let controlsOk = true;
for (const [label, run] of POSITIVE_CONTROLS) {
  const problem = run();
  if (problem) controlsOk = false;
  console.log(`${problem ? '✗' : '✓'} 对照 ${label}${problem ? ' — ' + problem : ''}`);
}
if (!controlsOk) fail++;

console.log('\n=== 真仓对拍 ===');
const rustText = readFileSync(RUST_SCHEMA, 'utf8');
const rulesText = readFileSync(RULES_RS, 'utf8');
const residueText = readFileSync(RESIDUE_RS, 'utf8');
let schema;
try {
  schema = JSON.parse(readFileSync(SCHEMA_FILE, 'utf8'));
} catch (e) {
  console.error(`✗ tools/rule-schema.json 解析失败：${e.message}`);
  process.exit(1);
}

check(
  checkIncludePath(rustText),
  `1. rule_schema.rs 嵌入路径逐字钉在 tools/rule-schema.json`,
  checkIncludePath(rustText) ? INCLUDE_PIN : '现有文本里找不到该携带句',
);
const vocab = vocabViolations(rustText, schema);
check(
  vocab.tokenCount >= 20 && vocab.bad.length === 0,
  `2. 词汇零重复：两域 token 集 ${vocab.tokenCount} 个词均未在 rule_schema.rs 非测试区落字面量`,
  vocab.bad.join('；'),
);
const q = queryKeyViolations(rulesText, residueText, schema);
check(q.bad.length === 0, `3. 查询键存在性（${q.counts.join(' / ')}）`, q.bad.join('；'));
check(q.tokenCount >= 20, `4. tokens 结构齐备（两域合计 ${q.tokenCount} 个登记词）`);

if (fail > 0) {
  console.error('check-rule-schema-sync: 存在漂移');
  process.exit(1);
}
console.log('check-rule-schema-sync: 全部通过');

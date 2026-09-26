// check-csp-consistency.mjs —— 5 份 CSP meta 共同前缀一致性门禁（审查 v3-L4）
//
// 为什么判红：CSP 唯一真源在 index.html 的 meta 标签（AGENTS §5.9），4 个子窗 HTML
// 各带一份逐字拷贝（历史上靠人肉同步）。改 index.html 的 CSP 而忘了子窗 → 叠加取严
// 之下子窗行为漂移，且没有任何报错。
//
// 判定：去掉 index.html 独有的 `frame-src`（网速页内嵌测速 iframe 必需，属**收窄**，
// 白名单候选③）之后，5 份 meta 的 content 必须逐字相等。
//
// 用法：node tools/check-csp-consistency.mjs

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

const SRC = join(REPO_ROOT, 'src');
const htmls = readdirSync(SRC).filter((f) => f.endsWith('.html'));

const cspOf = (file) => {
  const text = readFileSync(join(SRC, file), 'utf8');
  const m = text.match(/http-equiv="Content-Security-Policy"\s+content="([^"]*)"/);
  if (!m) return null;
  // 去 frame-src 指令（含尾随分号）—— 只有 index.html 有，属登记过的收窄差异
  return m[1].replace(/\s*frame-src[^;]*;/, '').trim();
};

const csps = new Map();
for (const f of htmls) csps.set(f, cspOf(f));

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== CSP meta 一致性门禁 ===\n');

const missing = [...csps.entries()].filter(([, v]) => v === null).map(([k]) => k);
check(missing.length === 0, `${htmls.length} 份 HTML 均带 CSP meta`, missing.length ? `缺失 ${JSON.stringify(missing)}` : '');

const values = [...csps.values()].filter((v) => v !== null);
const allSame = values.length > 0 && values.every((v) => v === values[0]);
check(
  allSame,
  '去掉 frame-src 收窄差异后 5 份 CSP 逐字相等',
  allSame ? '' : `不一致：${JSON.stringify([...csps.entries()].filter(([, v]) => v !== null))}`,
);

console.log('');
if (fail > 0) {
  console.error('门禁失败：有断言未通过');
  process.exit(1);
}
console.log('CSP 一致性门禁全部通过');

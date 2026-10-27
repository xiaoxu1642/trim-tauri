// check-csp-consistency.mjs —— 5 份 CSP meta 共同前缀一致性门禁（审查 v3-L4）
//
// 为什么判红：CSP 唯一真源在 index.html 的 meta 标签（AGENTS §5.9），3 个子窗 HTML
// 各带一份逐字拷贝（历史上靠人肉同步）。改 index.html 的 CSP 而忘了子窗 → 叠加取严
// 之下子窗行为漂移，且没有任何报错。
//
// 判定：去掉 index.html 独有的 `frame-src`（网速页内嵌测速 iframe 必需，属**收窄**，
// 白名单候选③）之后，5 份 meta 的 content 必须逐字相等。
//
// 审查 L-2（2026-10-03）补：frame-src 剥离是「去掉再比」，一份子窗若**新增**自己的
// frame-src（放宽 iframe 来源）也会被一起剥掉 ⇒ 漏判。故对 frame-src 出现次数另立
// 基线棘轮：只有 index.html 允许恰好 1 处，其余每份（含未来新增子窗）必须为 0。
//
// 审查 L-3（2026-10-03）补：AGENTS §5.9「conf 的 app.security.csp 保持 null」此前只有
// 人工核对 —— conf 里一旦写了 CSP 就变成双份维护，这里补一条机检断言。
//
// 用法：node tools/check-csp-consistency.mjs

import { readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';
import { walkFiles } from './lib/fs-walk.mjs';

const SRC = join(REPO_ROOT, 'src');
// T1a-L04：递归（子目录里的 HTML 也必须有 CSP）。
const htmls = walkFiles(SRC, (n) => n.endsWith('.html'))
  .map((p) => relative(SRC, p).replace(/\\/g, '/'));

// frame-src 基线：唯一豁免是 index.html（网速页测速 iframe）。新子窗默认 0，
// 想加 frame-src 必须先改这份登记 —— 让「放宽 iframe 来源」变成显式动作。
const FRAME_SRC_BASELINE = { 'index.html': 1 };

const cspOf = (file) => {
  const text = readFileSync(join(SRC, file), 'utf8');
  const m = text.match(/http-equiv="Content-Security-Policy"\s+content="([^"]*)"/);
  if (!m) return null;
  // 去 frame-src 指令（含尾随分号）—— 只有 index.html 有，属登记过的收窄差异
  return {
    stripped: m[1].replace(/\s*frame-src[^;]*;/, '').trim(),
    // 剥离只处理一处，计数看的是全文：第二处 frame-src 不会进剥离、但逃不过棘轮
    frameSrcCount: (m[1].match(/(?:^|[\s;])frame-src[\s:]/g) ?? []).length,
  };
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

// L-2：frame-src 出现次数基线棘轮（index.html 1 处、其余 0 处）
const fsBad = [...csps.entries()]
  .filter(([, v]) => v !== null)
  .filter(([f, v]) => v.frameSrcCount !== (FRAME_SRC_BASELINE[f] ?? 0));
check(
  fsBad.length === 0,
  'frame-src 出现次数 = 基线（index.html 恰 1，其余恰 0）',
  fsBad.length === 0
    ? ''
    : `漂移：${fsBad.map(([f, v]) => `${f}=${v.frameSrcCount}（基线 ${FRAME_SRC_BASELINE[f] ?? 0}）`).join('、')}`,
);

const values = [...csps.values()].filter((v) => v !== null);
const allSame = values.length > 0 && values.every((v) => v.stripped === values[0].stripped);
// v2-L4P-44（E-14）：份数不再硬编码在断言文案里，随 htmls 现算（新增子窗自动纳入）
check(
  allSame,
  `去掉 frame-src 收窄差异后 ${values.length} 份 CSP 逐字相等`,
  allSame ? '' : `不一致：${JSON.stringify([...csps.entries()].filter(([, v]) => v !== null).map(([f, v]) => [f, v.stripped]))}`,
);

// T1a-M24：指令内容地板 —— 「N 份逐字相等」的基准取 values[0]，**五份同步放宽照样绿**
//（探针实测：没有一条断言在读指令内容）。关键指令的最小集合在此钉死；确需放宽必须
// 逐条来本表改（放宽=显式动作，与 FRAME_SRC_BASELINE 同纪律）。
const CSP_INSTRUCTION_FLOOR = [
  ["script-src 'self'", 'script-src 只认同源（内联脚本与外线全禁）'],
  ["object-src 'none'", 'object-src 全禁（插件面归零）'],
  ["base-uri 'self'", 'base-uri 只认同源（防 base 标签劫持相对路径）'],
  ["style-src 'self' 'unsafe-inline'", 'style-src 现状形态（token 化样式表需要内联样式）'],
  ['default-src \'self\'', 'default-src 在场（未列指令的兜底必须显式）'],
  ['connect-src \'self\' ipc: http://ipc.localhost', 'connect-src 的 IPC 通道形状'],
];
{
  const baseline = values[0]?.stripped ?? '';
  const floorBad = CSP_INSTRUCTION_FLOOR.filter(([expr]) => !baseline.includes(expr));
  check(
    floorBad.length === 0,
    `CSP 指令内容地板（关键指令 ${CSP_INSTRUCTION_FLOOR.length} 条在场；T1a-M24）`,
    floorBad.length ? `同步放宽被抓：${floorBad.map(([e, why]) => `${e}（${why}）`).join('；')}` : '',
  );
}

// L-3：conf 的 app.security.csp 必须显式 null（CSP 唯一真源在 index.html meta）
const conf = JSON.parse(readFileSync(join(REPO_ROOT, 'src-tauri', 'tauri.conf.json'), 'utf8'));
check(
  conf.app?.security?.csp === null,
  'tauri.conf.json 的 app.security.csp 保持 null（唯一真源在 meta）',
  conf.app?.security?.csp === null ? '' : `实际值：${JSON.stringify(conf.app?.security?.csp ?? '<键缺失>')} —— 写了即双份维护，删键也应恢复显式 null`,
);

console.log('');
if (fail > 0) {
  console.error('门禁失败：有断言未通过');
  process.exit(1);
}
console.log('CSP 一致性门禁全部通过');

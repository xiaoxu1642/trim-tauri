// check-asset-size.mjs —— 前端产物体积门禁（审查 v3-F6）
//
// 为什么判红：打包体积回归（误拷大文件、字体换成未子集化的全量版、壁纸换成原图）此前没有任何
// 门禁拦得住，只能靠发版前人肉发现。本门禁的直接起因是 `MiSansVF.ttf` 单文件 20,093,424 B
// —— 占 src/ 的 84.8%、安装包约六成。它已于 2026-10-14 整链移除，但**三条护栏照留**：
// 「资源悄悄变大」这个风险与那一次具体移除无关。
// 本门禁给三条护栏：
//   A. 单文件超过 PER_FILE_LIMIT 且未在 BASELINE 登记 → 红（新重资源必须显式登记）；
//   B. BASELINE 登记项超过登记 cap、或条目指向已不存在的文件 → 红（体积只许变小；
//      真要变大必须带着理由调 cap —— 与 check-guard-tiers 的双向棘轮同思路）；
//   C. src/ 全量超过 TOTAL_LIMIT → 红（总量兜底，防「每个文件都不大但攒了一堆」）。
//
// 用法：node tools/check-asset-size.mjs

import { statSync } from 'node:fs';
import { join, relative } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';
import { walkFiles } from './lib/fs-walk.mjs';
import { gate } from './lib/gate.mjs';

const SRC = join(REPO_ROOT, 'src');
// 1 MiB：未登记单文件超限线（现算 src/ 最大单文件是 wp-anime.jpg 593,077 B = 579 KiB，
// 离线还有 464 KiB；第二、三是 wp-gaming.jpg 443,724 与 cleanup-fallback.generated.js 330,545）
const PER_FILE_LIMIT = 1024 * 1024;
// 24 MiB 总量兜底：防「每个文件都不大但攒了一堆」。MiSans 移除后现算 src/ 全量仅 3,590,588 B
// （62 文件）= 3.42 MiB，本条余量因此变大 —— **刻意不收紧**：它是绝对兜底而不是棘轮，
// 收紧反而会把「总量护栏」误当成「体积预算」来讨价还价。
const TOTAL_LIMIT = 24 * 1024 * 1024;

/**
 * 已知重资源基线（登记 = 接受该体积；cap 为登记时的实测字节数）。
 * 新增条目必须写明「为什么大」。
 */
const BASELINE = {
  // 2026-10-14：原唯一登记项 `assets/fonts/MiSansVF.ttf`（20,093,424 B）已整链移除，本表随之清空。
  // ⚠️ 顺带纠正一条误导：该条目原本的登记理由写的是「应用默认字体（--app-font-family 首选）」，
  //    而自 2026-09-28 八轮拍板起默认字体栈就是 Segoe UI / 微软雅黑、MiSans 只是设置页一个可选项
  //    —— 也就是说这条理由当时已经不成立了。以后登记重资源时**必须现算核对理由**，别照抄本行。
};

const files = walkFiles(SRC).map((p) => {
  const st = statSync(p);
  return { rel: relative(SRC, p).replace(/\\/g, '/'), size: st.size };
});

const g = gate(import.meta.url);
const check = (ok, label, detail = '') => {
  const line = `${label}${detail ? ' — ' + detail : ''}`;
  if (ok) g.ok(line); else g.fail(line);
};

const fmt = (n) => (n / 1024 / 1024).toFixed(2) + ' MiB';

/**
 * 三段判据的唯一实现（v3 P2-I 从主流程里抽出）。
 *
 * 为什么必须抽出来：抽之前 A/B/C 的判据是内联在主流程里的表达式，要配「人为塞大文件必须红」
 * 的正向对照就只能**在别处再抄一遍同样的表达式** —— 那正是 §5.16 禁止的第二套实现
 *（抄的那份一旦与真源漂移，对照就变成"验证了一个已经不存在的判据"，比没有对照更危险）。
 * 现在真实扫描与自检共用这一个函数，判据只有一份。
 */
function judgeAssets(files, baseline, perFileLimit, totalLimit) {
  return {
    unlisted: files.filter((f) => f.size > perFileLimit && !(f.rel in baseline)),
    missing: Object.keys(baseline).filter((rel) => !files.some((f) => f.rel === rel)),
    grown: files.filter((f) => f.rel in baseline && f.size > baseline[f.rel]),
    total: files.reduce((s, f) => s + f.size, 0),
    totalLimit,
  };
}

console.log('=== 前端产物体积门禁 ===\n');

// ---- 正向对照自检：违例必红 + 合规必放行（§4.1「无对照的恒绿断言视同没写」）----
{
  const problems = [];
  const L = 1000, T = 10_000;
  const a = judgeAssets([{ rel: 'big.bin', size: 1500 }], {}, L, T);
  if (a.unlisted.length !== 1) problems.push(`对照①未命中：塞未登记超大文件应被 A 抓到，得 ${JSON.stringify(a.unlisted)}`);
  const b = judgeAssets([{ rel: 'ok.js', size: 10 }], { 'gone.ttf': 999 }, L, T);
  if (b.missing.length !== 1) problems.push(`对照②未命中：登记条目指向的文件消失应被 B 抓到，得 ${JSON.stringify(b.missing)}`);
  const c = judgeAssets([{ rel: 'a.ttf', size: 2000 }], { 'a.ttf': 1000 }, L, T);
  if (c.grown.length !== 1) problems.push(`对照③未命中：登记项超 cap 应被 B 抓到，得 ${JSON.stringify(c.grown)}`);
  // ④ 等值合规样本（size 恰好 == cap）必须放行 —— 防判据退化成「永远红」
  const d = judgeAssets([{ rel: 'a.ttf', size: 1000 }, { rel: 'b.js', size: 5 }], { 'a.ttf': 1000 }, L, T);
  if (d.unlisted.length || d.missing.length || d.grown.length) {
    problems.push(`对照④误报：等值合规样本被判违规 ${JSON.stringify({ u: d.unlisted, m: d.missing, g: d.grown })}`);
  }
  // ⑤ 总量护栏可算（不是恒 0），否则 C 组是假绿
  const e = judgeAssets([{ rel: 'x', size: 20_000 }], { x: 20_000 }, L, T);
  if (e.total <= e.totalLimit) problems.push(`对照⑤失效：超总量样本没算出超限，total=${e.total} / 上限 ${e.totalLimit}`);
  if (problems.length) {
    g.fail(`正向对照自检失效（本门禁三段判据不可信）：\n  ${problems.join('\n  ')}`);
    g.finish();
    process.exit(1);
  }
  g.ok('正向对照自检 5 组全部命中（塞未登记大文件必红 / 条目失踪必红 / 超 cap 必红 / 等值放行 / 总量护栏可算）');
}

const r = judgeAssets(files, BASELINE, PER_FILE_LIMIT, TOTAL_LIMIT);

// T1d-M10：扫描面为空不能三段全绿（walkFiles 对不存在目录返回 []）。
if (files.length === 0) {
  g.fail('扫描面 0 个文件 ⇒ src/ 目录配置失效（不是体积合规）');
}

// ---- A. 未登记的超大单文件 ----
check(
  r.unlisted.length === 0,
  `A. 单文件 > ${fmt(PER_FILE_LIMIT)} 的资源均已登记（现登记 ${Object.keys(BASELINE).length} 项）`,
  r.unlisted.length
    ? `未登记超大文件 ${JSON.stringify(r.unlisted.map((f) => `${f.rel} ${fmt(f.size)}`))} —— 若确属必要，请连同理由登记进 BASELINE`
    : '',
);

// ---- B. 登记项棘轮（超 cap / 失踪条目）----
if (Object.keys(BASELINE).length === 0) {
  // T1d-M10：空基线时 B 段没有断言对象——显式 SKIP，不拿 ✓ 冒充判过。
  console.log('– SKIP B. 0 项基线资源，本节未校验（新增重资源时先登记进 BASELINE）');
} else {
  check(
    r.missing.length === 0 && r.grown.length === 0,
    `B. ${Object.keys(BASELINE).length} 项基线资源均未超登记体积`,
    [
      r.missing.length ? `条目指向的文件已不存在 ${JSON.stringify(r.missing)}（请从 BASELINE 移除）` : '',
      r.grown.length
        ? `超过登记体积 ${JSON.stringify(r.grown.map((f) => `${f.rel} ${fmt(f.size)} > cap ${fmt(BASELINE[f.rel])}`))}（确需变大请带理由调 cap）`
        : '',
    ]
      .filter(Boolean)
      .join('；'),
  );
}

// ---- C. 全量兜底 ----
check(
  r.total <= TOTAL_LIMIT,
  `C. src/ 全量 ${fmt(r.total)} ≤ 上限 ${fmt(TOTAL_LIMIT)}（${files.length} 个文件）`,
  r.total > TOTAL_LIMIT
    ? '超过总量护栏：新增资源请先做子集化/压缩，或调整 TOTAL_LIMIT 并说明理由'
    : '',
);

console.log('');
g.finish('体积门禁全部通过');

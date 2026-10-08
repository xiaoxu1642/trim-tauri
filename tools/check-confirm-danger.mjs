// check-confirm-danger.mjs —— app 确认入口「调用形态」门禁（审查 L3 2026-10-01 NEW-1）
//
// 为什么判红：window.app.confirmDanger / confirmWarning / confirm 是**位置参数**契约
// （app.js：confirm(title, message, confirmText, cancelText, options)）。cleanup.js 的
// offerTrashRetry 曾以「单对象」形态调用 confirmDanger（L3 NEW-1）：对象被当 title
// 渲染成 "[object Object]"，正文空白、「永久删除不可恢复」危险警示整段丢失——
// 而这条链是绕过回收站的不可逆永久删除确认。check-channel-map 只对通道名，
// 抓不到「通道对、参数形态错」这类回归，故单独立门禁。
//
// 判定：src/scripts/*.js 中以下调用形态即红（首参为对象字面量 `{`）：
//   · 裸标识符 confirmDanger( / confirmWarning(
//   · app.confirmDanger / app.confirmWarning / app.confirm（含 ?. 可选链）
// 注意：window.modal.confirm({…}) 是合法契约（modal 层本就收对象参数），不在判定范围。
// 注释剥离：块注释整块剥离（等长替换保行号）；命中行若其前缀含 `//` 视为注释跳过。
// 模板字符串里的形似文本理论上可能误红——出现时改措辞即可，不要为此放松匹配。
// 运行时最后防线：app.js confirmDanger/confirmWarning 内置对象归一兜底（NEW-1 修复），
// 但兜底不豁免本门禁——调用点必须在源头上写对。
//
// 判红验证：任一 src/scripts/*.js 临时加 `window.app?.confirmDanger({ title: 'x' });`
// → 本门禁必须红（exit 1）；移除后恢复绿。
//
// 用法：node tools/check-confirm-danger.mjs

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

const dir = join(REPO_ROOT, 'src', 'scripts');
const files = readdirSync(dir).filter((f) => f.endsWith('.js')).sort();

// 扫描面地板（P0-4）：目录塌陷/改名 ⇒ files=[]，末尾「✓ 0 个脚本无对象形态调用」是空集假绿。
// 下限 10 是现算值（48 个 .js）的明显下界——只拦整目录消失/几近塌陷，不拦正常增删。
if (files.length < 10) {
  console.error(`✗ src/scripts 只剩 ${files.length} 个 .js ⇒ 扫描面塌陷（现算 48），拒绝判绿`);
  process.exit(1);
}

// 剥离块注释（等长替换保偏移量与行号），行注释在命中处按行前缀判定
function stripBlockComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '));
}

// 注意必须带 g 标志：exec 循环依赖 lastIndex 推进，无 g 时同一首匹配永远返回 → 死循环
// （判红验证实测抓出：无匹配时毫秒级绿跑，一旦有匹配即挂死）
const RE_BARE = /(?:^|[^\w.$])(?:confirmDanger|confirmWarning)\s*\(\s*\{/g;
const RE_APP = /\bapp\s*\??\.confirm(?:Danger|Warning)?\s*\(\s*\{/g;
// P3-5（v4-K05）：高危确认凭据不得硬编码 —— `confirmedHighRisk: true` 字面量出现在
// 渲染层（含桥接层）即红：凭据必须由调用点从确认结果派生（变量 / `!!x`）传入，
// 硬编码 true 等于把安全门拆掉（v2-F4 历史形态）。局部对象赋值（`= true`，且上游
// 刚 await 过确认）不在判定面。
const RE_HARDCODED_CRED = /confirmedHighRisk\s*:\s*true\b/g;
// 正向对照自检（合成样本，见文末）
function hardcodedCredViolations(text) {
  return [...text.matchAll(RE_HARDCODED_CRED)].map((m) => m[0]);
}

const bad = [];
const hardcoded = [];
for (const f of files) {
  const text = stripBlockComments(readFileSync(join(dir, f), 'utf8'));
  for (const re of [RE_BARE, RE_APP]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const lineStart = text.lastIndexOf('\n', m.index - 1) + 1;
      const before = text.slice(lineStart, m.index);
      if (before.includes('//')) {
        // 行注释里的形似文本（整行注释或行尾注释），跳过
        re.lastIndex = m.index + m[0].length;
        continue;
      }
      const line = text.slice(0, m.index).split('\n').length;
      bad.push(`${f}:${line}`);
      re.lastIndex = m.index + m[0].length;
    }
  }
  // P3-5：凭据字面量检查（行注释跳过，注释里的提及不算数）
  RE_HARDCODED_CRED.lastIndex = 0;
  let h;
  while ((h = RE_HARDCODED_CRED.exec(text)) !== null) {
    const lineStart = text.lastIndexOf('\n', h.index - 1) + 1;
    if (text.slice(lineStart, h.index).includes('//')) continue;
    hardcoded.push(`${f}:${text.slice(0, h.index).split('\n').length}`);
  }
}

// 正向对照自检（合成样本）
{
  const POSITIVE_CONTROLS = {
    bad: 'window.api.syspanel.pagefileApply(true, [], { confirmedHighRisk: true });',
    good: 'window.api.syspanel.pagefileApply(true, [], { confirmedHighRisk: !!ok });\nrunParams.confirmedHighRisk = true;',
  };
  const b = hardcodedCredViolations(POSITIVE_CONTROLS.bad).length;
  const g2 = hardcodedCredViolations(POSITIVE_CONTROLS.good).length;
  if (b !== 1 || g2 !== 0) {
    console.error(`✗ 正向对照失败：字面量样本命中 ${b}（应 1）/ 合规样本命中 ${g2}（应 0）`);
    process.exit(1);
  }
  console.log('✓ 正向对照自检通过（凭据字面量判定器可判红、合规样本放行）');
}

console.log('=== app 确认入口调用形态门禁（confirmDanger/confirmWarning/confirm 位置参数契约）===\n');
if (bad.length) {
  for (const b of bad) {
    console.error(`✗ src/scripts/${b} — 确认入口首参传对象字面量（会被当 title 渲染成 "[object Object]"，危险警示整段丢失；NEW-1 回归形态）`);
  }
} else {
  console.log(`✓ ${files.length} 个 src/scripts 脚本无「对象形态调用 app 确认入口」`);
}
if (hardcoded.length) {
  for (const h of hardcoded) {
    console.error(`✗ src/scripts/${h} — confirmedHighRisk 被字面量为 true（高危确认凭据硬编码 = 绕过安全门；v4-K05 回归形态）`);
  }
} else {
  console.log('✓ 渲染层无 confirmedHighRisk 字面量（凭据均由调用点从确认结果派生）');
}

console.log('');
if (bad.length > 0 || hardcoded.length > 0) {
  console.error('门禁失败：确认入口调用形态/凭据回归（见上）');
  process.exit(1);
}
console.log('确认入口调用形态门禁通过');

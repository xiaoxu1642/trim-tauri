// check-idle-scripts.mjs —— 延迟加载脚本的 DOMContentLoaded 守卫门禁（审查 v3-M3）
//
// 为什么判红：`IDLE_SCRIPTS` 与 `PAGE_SCRIPTS` 里的脚本由 app.js 在**首帧空闲后**
// 或**进页时**动态注入，届时 DOMContentLoaded 早已发生——顶层注册该事件等于
// init 永不执行，功能静默失效（真实案例：mouse-trail.js 的鼠标拖尾开关点了没反应）。
//
// 正确姿势（与 updater-ui.js 同款）：
//   if (document.readyState === 'loading') {
//     document.addEventListener('DOMContentLoaded', init);
//   } else { init(); }
//
// 判定：脚本若注册了顶层 `DOMContentLoaded` 监听，就必须同文件带
// `document.readyState` 守卫；二者缺一即红。
//
// 用法：node tools/check-idle-scripts.mjs

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

const appJs = readFileSync(join(REPO_ROOT, 'src', 'scripts', 'app.js'), 'utf8');

// 从 app.js 现场提取延迟加载清单（新增文件自动纳入，不用回来改本门禁）
function extractIdle() {
  const m = appJs.match(/const IDLE_SCRIPTS = \[([^\]]*)\]/);
  if (!m) throw new Error('app.js 里找不到 IDLE_SCRIPTS 清单');
  return [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]);
}

function extractPages() {
  const m = appJs.match(/const PAGE_SCRIPTS = \{([\s\S]*?)\n  \};/);
  if (!m) throw new Error('app.js 里找不到 PAGE_SCRIPTS 清单');
  // 只取脚本路径（块里混有页面 key 等非路径字符串）
  return [...m[1].matchAll(/'([^']+)'/g)]
    .map((x) => x[1])
    .filter((s) => s.startsWith('scripts/') && s.endsWith('.js'));
}

const files = [...new Set([...extractIdle(), ...extractPages()])];

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== 延迟加载脚本 DOMContentLoaded 守卫门禁 ===\n');

const bad = [];
for (const rel of files) {
  const text = readFileSync(join(REPO_ROOT, 'src', rel.replace(/^src\//, '')), 'utf8');
  const lines = text.split('\n');
  // 结构判定：注册点必须 ① 在含 readyState 的 if 块内（花括号深度 > 0 且向上
  // 能找到守卫 if 行），或 ② 该行自带 readyState，或 ③ 紧随 readyState 行的 else。
  // 其余（顶层裸注册）= M3 的静默失效形态，红。
  const re = /addEventListener\(\s*['"]DOMContentLoaded['"]/;
  for (let idx = 0; idx < lines.length; idx++) {
    if (!re.test(lines[idx])) continue;
    if (/document\.readyState/.test(lines[idx])) continue; // 单行守卫形态
    const prev = idx > 0 ? lines[idx - 1] : '';
    if (/document\.readyState/.test(prev) && /\belse\b/.test(lines[idx])) continue;
    // 向上找所属块的开括号行（右→左扫字符：`}` 计入未进块，`{` 在深度 0 处
    // 即所属块的开括号），开括号行必须含 readyState 守卫
    let depth = 0;
    let guarded = false;
    outer: for (let i = idx - 1; i >= 0; i--) {
      const l = lines[i];
      for (let j = l.length - 1; j >= 0; j--) {
        const c = l[j];
        if (c === '}') depth++;
        else if (c === '{') {
          if (depth === 0) {
            guarded = /document\.readyState\s*(===?|!==)\s*['"]loading['"]/.test(l);
            break outer;
          }
          depth--;
        }
      }
    }
    if (!guarded) {
      bad.push(`${rel}:${idx + 1}`);
      break;
    }
  }
}
check(
  bad.length === 0,
  `${files.length} 个延迟/按页加载脚本均带 readyState 守卫（或未注册 DOMContentLoaded）`,
  bad.length ? `缺守卫 ${JSON.stringify(bad)} —— 注入时 DOMContentLoaded 已过，init 永不执行` : '',
);

console.log('');
if (fail > 0) {
  console.error('门禁失败：有断言未通过');
  process.exit(1);
}
console.log('延迟加载脚本门禁全部通过');

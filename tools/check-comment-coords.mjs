'use strict';
// tools/check-comment-coords.mjs —— 注释里的「文件:行号」坐标必须能在干净克隆里按图索骥
//
// 出处：A4-M03 / A4-M06 / A4-Z01…Z17（坐标漂移族）+ D1-M06（capabilities 描述写死行号）。
//
// 为什么单独立一条：既有 `check-comment-rot` 的坐标判据（R3c/R3e）只吃「反引号 + 仓内目录
// 前缀」这一种形态，而本轮实锤的坐标引用里**绝大多数落在射程外** —— 裸文件名
// （`mod.rs:211`）、无反引号（`perf.rs:369`）、`vendor/` 前缀各占一片。射程外的坐标一样
// 会漂：D1-M06 里 `lib.rs:435` 已漂到 736，A4-Z15 的 `lib.rs:439` 修过一次又漂 —— 
// 这是「无入口必然复烂」的直接证据，也说明**只加判据不改措辞等于没修**。
//
// 抓什么（作用在注释行本身 —— 本门禁判的正是「注释里写的坐标」）：
//   C1 坐标指向的文件必须能解析到**唯一**一个跟踪文件。裸文件名若是仓内同名多份 ⇒ 判红，
//      因为读者没法按图索骥（这正是 Z 族里 `mod.rs` / `contextmenu.rs` 那一批的形态）。
//   C2 行号不得越界。
//
// 只判「坐标能不能定位到」，不判行内容对不对 —— 内容正确性由 R3e 的符号命中判据守，
// 两条不重叠、不互抄结论（§4.1）。
//
// 用法：node tools/check-comment-coords.mjs

import { readFileSync } from 'node:fs';
import { join, relative, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

import { gate } from './lib/gate.mjs';
import { walkFiles } from './lib/fs-walk.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SCAN_ROOTS = [
  join(ROOT, 'src-tauri', 'src'),
  join(ROOT, 'src-tauri', 'tests'),
  join(ROOT, 'native-scanner', 'src'),
  join(ROOT, 'src', 'scripts'),
  join(ROOT, 'src', 'styles'),
  join(ROOT, 'tools'),
  // D1-M06：capabilities 的 `description` 里也写了仓内坐标（`lib.rs:435` 已漂到 736），
  // 而 `.json` 既没有 `//` 注释行、也不在既有坐标判据的射程内 ⇒ 单列一个根收进来。
  join(ROOT, 'src-tauri', 'capabilities'),
];
const EXTS = (n) => /\.(rs|js|mjs|css|html|json)$/.test(n);
// 语料面（扫谁的注释）：跳过 `vendor/` —— 那是只读基线，它内部怎么写不归本门禁评。
const IGNORE_DIR = (n) => n === 'target' || n === 'node_modules' || n === 'vendor' || n === '.git';
// 目标面（坐标可以指向谁）：**包含** `vendor/` —— 本仓注释引用 vendor 的行号是本仓
// 自己的行为，豁免不到；指向它却解析不出，正是「干净克隆里按图索骥不到」。
const IGNORE_DIR_FOR_TARGETS = (n) =>
  n === 'target' || n === 'node_modules' || n === 'docs' || n === 'build-release' || n === '.git';
const IGNORE_FILES = ['tools/check-comment-coords.mjs'];

const RE_TARGET = /([A-Za-z_][\w./-]*\.(?:rs|js|mjs|ps1|json|css|html)):(\d+)(?:-(\d+))?/g;

/** 从注释行里抽出 `<文件>:<行号>` 引用 */
function coordRefs(text, anyLine = false) {
  const out = [];
  text.split('\n').forEach((t, i) => {
    const s = t.trim();
    // json 的描述字段里没有 `//` 前缀，故整行都当语料扫。
    if (!anyLine && !s.startsWith('//') && !s.startsWith('*')) return;
    let m;
    RE_TARGET.lastIndex = 0;
    while ((m = RE_TARGET.exec(s)) !== null) {
      out.push({ fromLine: i + 1, target: m[1], ln: Number(m[2]) });
    }
  });
  return out;
}

const cache = new Map();
function linesOf(rel) {
  if (!cache.has(rel)) cache.set(rel, readFileSync(join(ROOT, rel), 'utf8').split('\n'));
  return cache.get(rel);
}

const g = gate(import.meta.url);

const files = [];
for (const base of SCAN_ROOTS) {
  for (const fAbs of walkFiles(base, EXTS, { ignoreDir: IGNORE_DIR })) {
    const rel = relative(ROOT, fAbs).replace(/\\/g, '/');
    if (IGNORE_FILES.includes(rel)) continue;
    // .json 只收 capabilities 描述；规则库那份是生成物，坐标由各自契约门禁管，不重复扫。
    if (rel.endsWith('.json') && !rel.startsWith('src-tauri/capabilities/')) continue;
    files.push(rel);
  }
}
const targets = [];
// 目标面额外含 `src/` 根（`index.html` 等页面骨架）与 `vendor/`（只读基线也是合法坐标目标）。
for (const base of [...SCAN_ROOTS, join(ROOT, 'vendor'), join(ROOT, 'src')]) {
  for (const fAbs of walkFiles(base, EXTS, { ignoreDir: IGNORE_DIR_FOR_TARGETS })) {
    targets.push(relative(ROOT, fAbs).replace(/\\/g, '/'));
  }
}
const tracked = new Set(targets);
const byBase = new Map();
for (const f of targets) {
  const b = basename(f);
  if (!byBase.has(b)) byBase.set(b, []);
  byBase.get(b).push(f);
}
/** 坐标里的文件名 ⇒ 唯一跟踪文件；同名多份或解析不出返回 null */
function resolveTarget(t) {
  if (tracked.has(t)) return t;
  const c = byBase.get(basename(t)) || [];
  return c.length === 1 ? c[0] : null;
}

// 合成样本自检（正反向都要：能判红 + 真样本不假红）
const CONTROLS = [
  {
    label: 'C1 对照a：裸文件名且仓内同名多份 ⇒ 必须判红',
    code: '// 见 `mod.rs:211` 的写法\nfn a() {}',
    expect: 1,
  },
  {
    label: 'C1 对照b：带仓内前缀且文件在 ⇒ 不判红',
    code: '// 见 `src-tauri/src/engine/protect.rs:1` 的写法\nfn a() {}',
    expect: 0,
  },
  {
    label: 'C2 对照：行号越界 ⇒ 必须判红',
    code: '// 见 `src-tauri/src/engine/protect.rs:999999`\nfn a() {}',
    expect: 1,
  },
];
{
  let bad = 0;
  for (const c of CONTROLS) {
    const n = coordRefs(c.code).filter((r) => !resolveTarget(r.target)).length;
    // 越界判定需要真行数，这里直接对可解析目标再查一次
    let total = 0;
    for (const r of coordRefs(c.code)) {
      const t = resolveTarget(r.target);
      if (!t || r.ln < 1 || r.ln > linesOf(t).length) total++;
    }
    if (total !== c.expect) {
      bad++;
      console.error(`✗ 正向对照失败：${c.label}（实得 ${total}，应为 ${c.expect}）`);
    }
  }
  if (bad === 0) g.ok(`正向对照 ${CONTROLS.length} 组通过（含「歧义路径判红」与「有效坐标放行」两组）`);
}

// ── 真仓扫描 ──
const bad = [];
let refs = 0;
for (const rel of files) {
  for (const r of coordRefs(linesOf(rel).join('\n'), rel.endsWith('.json'))) {
    refs++;
    const resolved = resolveTarget(r.target);
    if (!resolved) {
      bad.push({
        from: `${rel}:${r.fromLine}`,
        to: r.target,
        why: '坐标里的文件名在仓内同名多份或解析不出 ⇒ 干净克隆按图索骥不到（Z 族形态）',
      });
      continue;
    }
    const tl = linesOf(resolved);
    if (r.ln < 1 || r.ln > tl.length) {
      bad.push({
        from: `${rel}:${r.fromLine}`,
        to: `${r.target}:${r.ln}`,
        why: `行号越界（${resolved} 现共 ${tl.length} 行）`,
      });
    }
  }
}
for (const b of bad) g.fail(`坐标漂移：${b.from} → ${b.to} —— ${b.why}`);

// 语料地板：坐标引用整片消失 = 识别正则失明，那种「无违例」毫无意义
if (refs < 20) g.fail(`坐标引用只认出 ${refs} 处（地板 20）⇒ 识别正则或扫描面已漂移`);
else g.ok(`注释坐标引用 ${refs} 处，全部能在跟踪面内唯一定位`);

// ---- D1-M10 措辞棘轮：maintenance-tasks.json 不得再被宣称「由生成器保证」----
//
// 实盘现算：仓内没有任何写盘器产出该件（D1.md probeO O3）⇒ 「由生成器保证合法」
// 是一句假话；三处声明已改为「手维护」口径（D-5 裁定：改措辞，不补生成器）。
// 这里钉住：凡提及该件的行不得再出现「生成器」——否则这句假话随时会回来。
{
  const bad = [];
  let sites = 0;
  for (const f of files) {
    const rel = relative(ROOT, f).replace(/\\/g, '/');
    linesOf(rel).forEach((t, i) => {
      if (!t.includes('maintenance-tasks.json')) return;
      sites++;
      if (t.includes('生成器')) bad.push(`${rel}:${i + 1}`);
    });
  }
  if (sites === 0) g.fail('D1-M10：语料失明 —— 全仓找不到 maintenance-tasks.json 的提及');
  else if (bad.length) g.fail(`D1-M10：${bad.join('；')} 仍宣称「生成器」—— 实盘无写盘器，必须改为「手维护」口径`);
  else g.ok(`D1-M10：maintenance-tasks.json 相关文案已全部为手维护口径（提及 ${sites} 处）`);
}

g.finish('check-comment-coords: 全部通过');

// check-data-parity.mjs —— 「派生数据 ⇄ 上游真源」双源对拍门禁（审查 v2-M17）
//
// 为什么需要它：本仓有 6 个 `src-tauri/data/*.json` 与 1 个 `src/scripts/*.generated.js`，
// 全部是**派生物**，但仓库里既没有再生成脚本、也没有任何一条断言（v2-M17 实测
// `grep -rn "data/" tools/*.mjs` = 0 命中）。附录 G 当时逐条深比对是「零漂移」——
// 可「一致」和「有断言守着」是两件事：前者会漂，且漂移的表现是**静默**：
//   · 规则库只改了 JSON ⇒ 兜底副本停在旧 71 项，IPC 异常时界面展示过期分类且不报错
//     （`cleanup.js:55` 直接吃 FALLBACK）；
//   · 优化项只改了前端 OPTIONS ⇒ JSON 停在旧字段，Rust 侧按旧值下发步骤；
//   · 受保护路径基线重拷了 vendor 却没重跑夹具 ⇒ Rust 测的是过期期望值，看着绿其实在测旧口径。
// 本门禁把附录 G 的四条对拍固化下来，四条都是**纯内存重算**（不写盘、不起 pwsh、不开窗口）。
//
// 用法：node tools/check-data-parity.mjs [--strict] [--verbose]
//   --strict   与默认行为等价（本门禁没有「可选层」，四项源全在仓库内，读不到即判红）；
//              接受该 flag 只为和 §4 其它门禁统一写法
//   --verbose  额外打印每条漂移的字段名（默认只打印前若干条）
// 退出码：0 = 四组逐条一致；1 = 任一组漂移或源不可读

import { readFileSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';

import { ORIGIN, REPO_ROOT } from './ps-origin.mjs';
import { buildParityFixture, FIXTURE_PATH } from './gen-protect-parity.mjs';

const VERBOSE = process.argv.includes('--verbose');
const require = createRequire(import.meta.url);

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
  return ok;
};

/** 读 JSON；读不到/解析失败直接判红（绝不「跳过即通过」） */
function readJson(rel) {
  const abs = join(REPO_ROOT, rel);
  if (!existsSync(abs)) { check(false, `读取 ${rel}`, '文件不存在'); return null; }
  try { return JSON.parse(readFileSync(abs, 'utf8')); }
  catch (e) { check(false, `读取 ${rel}`, e.message.slice(0, 120)); return null; }
}

/** 逐条目、逐字段的深比对（顺序敏感：JSON 里条目顺序本身是要钉的语义） */
function diffArrays(a, b, labelA, labelB) {
  const out = [];
  if (!Array.isArray(a) || !Array.isArray(b)) {
    return [`${labelA}/${labelB} 不是数组（结构变了？labelA=${Array.isArray(a)} labelB=${Array.isArray(b)}）`];
  }
  if (a.length !== b.length) {
    out.push(`条目数不同：${labelA} ${a.length} / ${labelB} ${b.length}`);
  }
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const ai = a[i] ?? {};
    const bi = b[i] ?? {};
    const id = ai.id ?? bi.id ?? `#${i}`;
    if (ai.id !== bi.id) out.push(`第 ${i} 位 id 不同（顺序漂移）：${labelA}=${ai.id} / ${labelB}=${bi.id}`);
    const keys = new Set([...Object.keys(ai), ...Object.keys(bi)]);
    for (const k of keys) {
      if (JSON.stringify(ai[k]) !== JSON.stringify(bi[k])) {
        const va = VERBOSE ? JSON.stringify(ai[k]) : JSON.stringify(ai[k] ?? null).slice(0, 40);
        const vb = VERBOSE ? JSON.stringify(bi[k]) : JSON.stringify(bi[k] ?? null).slice(0, 40);
        out.push(`${id}.${k}: ${labelA}=${va} / ${labelB}=${vb}`);
      }
    }
  }
  return out;
}
const show = (drift) => drift.length ? `${drift.length} 处漂移：${drift.slice(0, VERBOSE ? 99 : 5).join(' | ')}` : '';

console.log('=== 派生数据 ⇄ 上游真源 双源对拍门禁（v2-M17）===\n');

// ---------------------------------------------------------------------------
// P1 `data/cleanup-rules.json` ⇄ `src/scripts/cleanup-fallback.generated.js`
// 兜底副本是 IPC 异常时界面唯一能看到的数据，漂了就是「静默展示过期分类」。
// 比对取 JSON.stringify 全等：键序、`_sig`、`rulesVersion` 一并钉住
// （`_sig` 是规则库验签摘要，副本里停着旧签名等于把「签名对不上」也一起过期掉）。
// ---------------------------------------------------------------------------
const RULES_REL = join('src-tauri', 'data', 'cleanup-rules.json');
const FALLBACK_REL = join('src', 'scripts', 'cleanup-fallback.generated.js');
{
  const rules = readJson(RULES_REL);
  const fbPath = join(REPO_ROOT, FALLBACK_REL);
  let parsed = null;
  let why = '';
  if (rules && existsSync(fbPath)) {
    const text = readFileSync(fbPath, 'utf8');
    // 生成物的形状是 root.CLEANUP_RULES_FALLBACK = JSON.parse("<转义后的 JSON 文本>")；
    // 那段字面量是合法的 JSON 字符串字面量，所以可以「先解字面量、再解其中的 JSON」，
    // 不必复刻生成器的转义规则（复刻一份转义规则本身就是下一个漂移点）。
    const at = text.indexOf('JSON.parse("');
    const lit = at >= 0 ? text.slice(at + 'JSON.parse('.length).match(/^"(?:[^"\\]|\\.)*"/) : null;
    if (!lit) why = '没找到 JSON.parse("<字面量>") 形状，生成方式变了？';
    else {
      try { parsed = JSON.parse(JSON.parse(lit[0])); } catch (e) { why = `字面量解析失败：${e.message.slice(0, 80)}`; }
    }
  } else if (!existsSync(fbPath)) why = '兜底副本文件不存在';

  if (!rules || !parsed) {
    check(false, 'P1 cleanup-rules.json ⇄ cleanup-fallback.generated.js', why || '源不可读');
  } else {
    const same = JSON.stringify(parsed) === JSON.stringify(rules);
    let items = 0;
    for (const g of (rules.groups || [])) for (const sg of (g.subGroups || [])) items += (sg.items || []).length;
    check(same && items > 0,
      `P1 清理规则库 ⇄ 前端兜底副本（组 ${rules.groups?.length ?? '?'} / 项 ${items}，含 _sig 与 rulesVersion ${rules.rulesVersion}）`,
      same ? '' : 'JSON.stringify 不等（内容或键序已漂移；改规则 JSON 后需重新生成副本）');
  }
}

// ---------------------------------------------------------------------------
// P2 `vendor/…/optimizer-scripts.js OPTIONS` ⇄ `data/optimizer-runtime.json`
// 上游真源在 vendor 基线里（§5.12：只读基线）。这里是「基线重拷了、派生 JSON 没重出」
// 的唯一机器拦截点。字段级 + 顺序级都要钉：Rust 侧按 id 取项，但前端分组展示按数组序。
// ---------------------------------------------------------------------------
{
  const optSrc = require(`${ORIGIN}/src/scripts-powershell/optimizer-scripts.js`);
  const json = readJson(join('src-tauri', 'data', 'optimizer-runtime.json'));
  const srcArr = Array.isArray(optSrc?.OPTIONS) ? optSrc.OPTIONS : null;
  if (!srcArr || !json) {
    check(false, 'P2 optimizer OPTIONS ⇄ optimizer-runtime.json', `源不可读（OPTIONS=${!!srcArr}）`);
  } else {
    const drift = diffArrays(srcArr, json, 'OPTIONS', 'JSON');
    const groups = new Set(srcArr.map(o => o.group)).size;
    check(drift.length === 0,
      `P2 优化项 OPTIONS ⇄ 运行时 JSON（${srcArr.length} 项 / ${groups} 组，逐字段）`,
      show(drift));
  }
}

// ---------------------------------------------------------------------------
// P3 `vendor/…/maintenance-scripts.js list()` ⇄ `data/maintenance-tasks.json`
// 任务表还带 categories：它必须与上游 CATEGORY_ORDER 同序（界面按它分组）。
// ---------------------------------------------------------------------------
{
  const mm = require(`${ORIGIN}/src/scripts-powershell/maintenance-scripts.js`);
  const json = readJson(join('src-tauri', 'data', 'maintenance-tasks.json'));
  const srcArr = typeof mm?.list === 'function' ? mm.list() : null;
  if (!Array.isArray(srcArr) || !json) {
    check(false, 'P3 maintenance list() ⇄ maintenance-tasks.json', '源不可读');
  } else {
    const drift = diffArrays(srcArr, json.tasks, 'list()', 'JSON');
    check(drift.length === 0, `P3 维护任务 list() ⇄ 任务表 JSON（${srcArr.length} 项）`, show(drift));
    const catSame = JSON.stringify(mm.CATEGORY_ORDER) === JSON.stringify(json.categories);
    check(catSame, `P3b 维护任务分组顺序 ⇄ CATEGORY_ORDER（${mm.CATEGORY_ORDER?.length ?? '?'} 组）`,
      catSame ? '' : `上游 ${JSON.stringify(mm.CATEGORY_ORDER)} / JSON ${JSON.stringify(json.categories)}`);
  }
}

// ---------------------------------------------------------------------------
// P4 `tools/fixtures/protect-parity.json` ⇄ `vendor/…/ps-protect-path.js`
// 附录 G 已注明：`protect.rs` 那条 `matches_js_authority` 抓的是 **Rust 侧口径漂移**，
// 抓不到「基线重拷了、夹具没重跑」——夹具是入库快照，期望值本身过期时 Rust 测的是旧口径。
// 这里用生成器的同一个函数在内存里重算一遍与落盘夹具比（就是那条缺的腿）；
// 分档理由见块内注释（夹具冻的是出生机的用户目录）。
// ---------------------------------------------------------------------------
{
  let committed = null;
  try { committed = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')); }
  catch (e) { check(false, 'P4 protect-parity 夹具 ⇄ JS 权威实现', `读不到：${e.message.slice(0, 80)}`); }
  if (committed) {
    const fresh = buildParityFixture();
    // 夹具冻的是**出生机**的用户目录（JS 权威实现的默认清单读 process.env，
    // `protect.rs` 那条用例也读自己进程的 env）—— 实测把 USERPROFILE 换成别的值，
    // `cargo test --lib protect::` 立刻红。所以这里分两档，既不放纵漂移也不误报：
    //   · 本机就是出生机 ⇒ 整串逐字节比（最强，基线重拷没重跑夹具必红）
    //   · 本机不是出生机 ⇒ 只比「机器中立那半」（不含 C:\Users\ 的条目与向量判定），
    //     并把用户目录那一半显式标为未比对（不静默、不判绿充数）
    const homeOf = (o) => {
      const m = JSON.stringify(o).match(/users[\\/]+([^\s"'\\/]+)/i);
      return m ? m[1].toLowerCase() : '';
    };
    const localHome = homeOf({ p: process.env.USERPROFILE || '' });
    const fixtureHome = homeOf(committed);
    const isBirthMachine = !!localHome && localHome === fixtureHome;
    // 「机器中立」判据：路径里不含用户目录段（users\<name> 之后的部分也可能带用户相关目录名，
    // 所以整条一起排除，宁可少判也不误判）
    const neutral = (v) => !/users[\\/]/i.test(typeof v === 'string' ? v : JSON.stringify(v));
    const detail = [];
    if (isBirthMachine) {
      if (JSON.stringify(fresh) !== JSON.stringify(committed)) detail.push('整串不一致 ⇒ 基线被重拷过或夹具被手改');
    } else {
      const pick = (f) => ({
        roots: Object.fromEntries(Object.entries(f.roots).map(([k, v]) => [k, v.filter(neutral)])),
        vectors: f.vectors.filter(v => neutral(v.p)).map(v => `${v.p}=${v.protected}`).sort(),
      });
      const a = JSON.stringify(pick(fresh));
      const b = JSON.stringify(pick(committed));
      if (a !== b) detail.push('机器中立部分不一致 ⇒ 基线口径变了');
    }
    const denied = fresh.vectors.filter(v => v.protected).length;
    check(detail.length === 0,
      `P4 受保护路径夹具 ⇄ JS 权威现算（向量 ${fresh.vectors.length}：判拒 ${denied} / 放行 ${fresh.vectors.length - denied}；`
      + `${isBirthMachine ? `本机即夹具出生机，整串比对` : `出生机=${fixtureHome || '?'} ≠ 本机=${localHome || '?'}，只比机器中立部分`}）`,
      detail.join('；') || (isBirthMachine ? '' :
        '※ 用户目录相关条目未比对（换机后 `cargo test --lib protect::` 同样会红，需先重跑生成器）'),
    );
    if (!isBirthMachine) {
      console.log('  · 想让夹具机器中立，得先让 protect.rs 那条用例把「默认段」也吃夹具输入（见 gen-protect-parity.mjs 顶部说明）。');
    }
  }
}


// ---------------------------------------------------------------------------
// 报告项（不参与判定）：附录 G 里「本仓无再生成路径 / 无消费者」的两个数据文件。
// 它们没有可对拍的上游真源，判红无意义，但「无人守护」这件事必须每次都被看见。
// ---------------------------------------------------------------------------
console.log('\n※ 无对拍对象（本仓既无再生成路径、也无门禁，改动只能靠人肉核对）：');
for (const rel of [join('src-tauri', 'data', 'reg-ownership.json'), join('src-tauri', 'data', 'retired-optimizations.json')]) {
  const abs = join(REPO_ROOT, rel);
  let extra = '';
  try {
    const j = JSON.parse(readFileSync(abs, 'utf8'));
    extra = Array.isArray(j) ? `（${j.length} 条）` : `（键 ${Object.keys(j).slice(0, 4).join(',')}）`;
  } catch { extra = '（读不到）'; }
  console.log(`  · ${rel.replace(/\\/g, '/')} ${existsSync(abs) ? extra : '缺失'}`);
}

console.log(`\n${fail === 0 ? '✓ 四组数据对拍全部一致' : `${fail} 项未通过`}`);
process.exit(fail === 0 ? 0 : 1);

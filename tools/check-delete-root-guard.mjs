'use strict';
// tools/check-delete-root-guard.mjs —— 递归删除/裁剪的**根**必须过根级 reparse 判定（B0 门禁）
//
// 出处：2026-10-24 全仓重审 R7-K01（🔴）与族 F-1（reparse 校验面不全，7 个实例）。
// 根因形状：清扫根 `dirs.push(std::env::temp_dir().join("Trim"))` 之后逐**子项**判 reparse，
// 根自身没人判 ⇒ 根被换成 junction 时 `read_dir` 直接穿透，旧文件被 `remove_file` 永久删，
// 不经回收站、不经 `is_path_protected`。写侧原语 `engine::paths::temp_script_dir()` 恰恰是对
// **根**拒 reparse 的（`paths.rs:431-445`）⇒ 同族两套口径，本门禁把它钉成一条。
//
// 判据为什么不是「文件里出现过 inspect_root 就算过」（v2 §4 A-7「文本命中不算」）：
//   ① 判定作用在 `blankNonCode` 之后的文本上 ⇒ 注释/字符串里写 `inspect_root(` 不顶账；
//   ② 作用在**函数体**上 ⇒ 同文件另一个函数里判过不算这个函数判过；
//   ③ 破坏性枚举允许跨一层调用（`prune_temp_scripts_in` → `collect_temp_files` 才是真 read_dir），
//      所以做同文件 1 跳可达；调用方在把根传下去之前判过也算（guard 必须在根上，位置不限函数）。
//
// 过渡基线：本门禁随 B0 落地、随 B2 兑现。B2（2026-10-25）已把 15 条里的 14 条接进
// `protect::inspect_root`，剩下的 1 条是**已裁定不补**并写明理由的枚举工具（不是待办）。
// `TRANSITION` 里每条都要 `{file, fn, batch, reason}`，
// 且**双向咬合**：代码补上判定后若豁免表还留着 ⇒ 判红（防「修完了台账还挂着」的第二类假绿）。
//
// 用法：node tools/check-delete-root-guard.mjs [--verbose]

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { gate } from './lib/gate.mjs';
import { blankNonCode, splitFunctions, skipBraces, lineAt } from './lib/src-scan.mjs';

const ROOT = process.cwd();
const SRC = join(ROOT, 'src-tauri', 'src');
const GUARD = 'inspect_root(';
const READ = 'read_dir(';
const DESTRUCTIVE = ['remove_file(', 'remove_dir_all(', 'send_to_trash_os(', 'delete_file_with_panic('];
const MIN_DESTRUCTIVE_ROOTS = 5; // 对象地板：低于此数说明判定正则失明，不说明仓库变安全

// B2（2026-10-25）清零：原 15 条已逐条接入 `protect::inspect_root`，本表只留**裁定为不补**
// 的那一条（有书面理由，不是「还没做」）。新根入口漏判即红，不许再往本表塞新条目 ——
// 要塞必须先答「为什么不接判据」，答不出就接判据。
const TRANSITION = [
  { file: 'src-tauri/src/engine/native/cleanup.rs', fn: 'expand_glob_dirs', batch: 'B2/已裁定不补', reason: '通配展开的**枚举工具**，不是删除根：真正的删除发生在执行链，而 `engine/native/cleanup.rs:1430` 对每个 victim 调 `reparse_ancestor_memoized` → `trim_finder::scan::reparse_ancestor`，命中即 `reparse_blocked += 1` 并在回执里计数点名（`cleanup.rs:672`）。根是 junction 时该祖先链判定当场就拒 ⇒ 在这里补根判定只会把「可见的逐项拒因 + 计数」换成「静默 0 命中」，正撞方案 P1-6「失败不得伪装成空结果」。活性由 native-scanner 的 `p0_2c_祖先复检深度到文件系统根不设第二上限` 与 `s2_*` 删除链用例（断言 mode=reparse-ancestor 且真实内容完好）钉住，不是靠这条理由自证' },
];

const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? walk(join(dir, e.name)) : (e.name.endsWith('.rs') ? [join(dir, e.name)] : []));

/** `#[cfg(test)]` 模块的字符区间：测试体内构造真目录再删是本仓标准夹具，不是生产删除根。 */
function testModRanges(code) {
  const blanked = blankNonCode(code, 'rs');
  const out = [];
  const pat = /#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*mod\s+\w+\s*\{/g;
  let m;
  while ((m = pat.exec(blanked))) out.push([m.index, skipBraces(blanked, blanked.indexOf('{', m.index))]);
  return out;
}

/**
 * 同文件 1 跳可达：fn 体内出现的其它 fn 名（按 `名字(` 粗配，已剥注释与字符串）。
 * 删除侧允许 1 跳（`prune_*` → `collect_*` 才是真 read_dir 的反向形态），
 * 枚举侧**不允许**跳：判定单位就是「自己 read_dir 的那个函数」，否则会把
 * 「顺手调了个带 read_dir 的工具函数」误算成删除根（首版就因此假红了 `expand_glob_dirs`）。
 */
function build(code) {
  const blanked = blankNonCode(code, 'rs');
  const tests = testModRanges(code);
  const fns = splitFunctions(code, 'rs').filter((f) => !tests.some(([a, b]) => f.start >= a && f.start < b)).map((f) => {
    const body = blanked.slice(f.bodyStart, f.end - 1);
    return {
      ...f,
      body,
      line: lineAt(code, f.start),
      reads: body.includes(READ),
      deletes: DESTRUCTIVE.some((d) => body.includes(d)),
      guards: body.includes(GUARD),
      calls: null,
    };
  });
  const names = new Set(fns.map((f) => f.name));
  for (const f of fns) {
    f.calls = [...names].filter((n) => n !== f.name && new RegExp(`\\b${n}\\s*\\(`).test(f.body));
  }
  return fns;
}

const g = gate(import.meta.url);
const exemptKey = (rel, fn) => `${rel}#${fn}`;
const exempt = new Map(TRANSITION.map((t) => [exemptKey(t.file, t.fn), t]));

let hitCount = 0;
let guardedCount = 0;
const found = new Set();

if (!g.skipUnlessPresent(join(SRC, 'engine', 'protect.rs'), 'src-tauri/src（本门禁的判定对象）')) {
  g.finish();
}

for (const abs of walk(SRC)) {
  const rel = relative(ROOT, abs).split('\\').join('/');
  const code = readFileSync(abs, 'utf8');
  if (!code.includes(READ)) continue;
  const fns = build(code);
  const byName = new Map(fns.map((f) => [f.name, f]));
  for (const f of fns) {
    if (!f.reads) continue;
    // 删除可以在被调函数里（prune → collect 的反向），也可以在**调用它的**函数里
    // （`collect_temp_files` 只枚举、`prune_temp_scripts_in` 才 remove_file —— R7-K01 的真实形状）
    const deletesSomewhere = f.deletes
      || f.calls.some((c) => byName.get(c)?.deletes)
      || fns.some((c) => c.calls.includes(f.name) && c.deletes);
    if (!deletesSomewhere) continue;
    // 自身判过，或任一 caller 判过（根在传下来之前被校验）
    const guarded = f.guards || fns.some((c) => c.calls.includes(f.name) && c.guards);
    hitCount++;
    const key = exemptKey(rel, f.name);
    if (guarded) {
      guardedCount++;
      if (exempt.has(key)) {
        g.fail(`${rel}:${f.line} ${f.name}() 已调用 ${GUARD.replace('(', '')}，但 TRANSITION 仍挂着它（豁免未回收 = 第二类假绿）`);
      }
      continue;
    }
    found.add(key);
    if (!exempt.has(key)) {
      g.fail(`${rel}:${f.line} ${f.name}() 是「自己 read_dir + 本函数或 1 跳内删除」的根入口，体内与 caller 都没有 ${GUARD} 判定，也不在过渡豁免里`);
    }
  }
}

// 已登记但盘上找不到的豁免（改名/搬文件/删函数都会走到这里）
for (const [k, t] of exempt) {
  if (!found.has(k)) g.fail(`TRANSITION 条目已失效（盘上找不到同名函数）：${t.file}:${t.fn}（${t.batch}）`);
}
for (const t of TRANSITION) {
  if (!t.reason || t.reason.length < 8) g.fail(`TRANSITION 条目缺理由：${t.file}#${t.fn}`);
  if (!t.batch) g.fail(`TRANSITION 条目缺批次：${t.file}#${t.fn}`);
}

if (hitCount < MIN_DESTRUCTIVE_ROOTS) {
  g.fail(`断言对象地板不成立：只认出 ${hitCount} 个「枚举+删除」根入口（地板 ${MIN_DESTRUCTIVE_ROOTS}）⇒ 判定正则或目录根失效，不是仓库变安全`);
}
g.ok(`删除根守卫对账：识别「自己 read_dir + 本函数或 1 跳内删除」的根入口 ${hitCount} 个，其中已判根 ${guardedCount} 个、未判 ${hitCount - guardedCount} 个（未判的全部在过渡豁免里，逐条见 TRANSITION）`);

// ── 合成样本正向对照：每次运行都跑（判红能力必须被看见，`check-pending-batch-limit` 先例）──
const CONTROLS = [
  {
    label: 'C1 read_dir + remove_file 且无判定 ⇒ 必须判红',
    code: 'fn a(p: &Path) { let _ = std::fs::read_dir(p); let _ = std::fs::remove_file(p); }',
    expectViolation: true,
  },
  {
    label: 'C2 同形状但 caller 先判根 ⇒ 不判红（判据认 caller）',
    code: 'fn top(p: &Path) { crate::engine::protect::inspect_root(p, None); a(p); }\nfn a(p: &Path) { let _ = std::fs::read_dir(p); let _ = std::fs::remove_file(p); }',
    expectViolation: false,
  },
  {
    // 这一条是本门禁存在的理由：只看文本命中就会在这里放行
    label: 'C3 只在注释里写 inspect_root ⇒ 必须仍判红（文本命中不算通过）',
    code: '// 这里本来该调 inspect_root( 但没调\nfn a(p: &Path) { let _ = std::fs::read_dir(p); let _ = std::fs::remove_dir_all(p); }',
    expectViolation: true,
  },
  {
    label: 'C4 自己 read_dir、删除在 1 跳被调函数 ⇒ 必须判红',
    code: 'fn prune(p: &Path) { collect(p); }\nfn collect(p: &Path) { let _ = std::fs::read_dir(p); kick(p); }\nfn kick(_p: &Path) { let _ = std::fs::remove_file(p_as()); }',
    expectViolation: true,
  },
  {
    label: 'C5 只 read_dir、本文件任何地方都不删 ⇒ 不判红（防把枚举工具函数算成删除根）',
    code: 'fn list_dirs(p: &Path) { let _ = std::fs::read_dir(p); }\nfn unrelated() { let _ = 1; }',
    expectViolation: false,
  },
];
let ctrlBad = 0;
for (const c of CONTROLS) {
  const fns = build(c.code);
  const byName = new Map(fns.map((f) => [f.name, f]));
  const viol = fns.some((f) => {
    if (!f.reads) return false;
    const del = f.deletes || f.calls.some((x) => byName.get(x)?.deletes)
      || fns.some((c) => c.calls.includes(f.name) && c.deletes);
    return del && !f.guards && !fns.some((ca) => ca.calls.includes(f.name) && ca.guards);
  });
  if (viol !== c.expectViolation) { ctrlBad++; console.error(`✗ 正向对照失败：${c.label}（实得 viol=${viol}）`); }
}
if (ctrlBad === 0) g.ok(`正向对照 ${CONTROLS.length} 组通过（含「注释里写判定不算通过」与「1 跳穿透必判红」两组）`);

// ── P0-4 写回链的复检面地板（B2 加）──────────────────────────────────────────
// 方案原文要的是「所有 create_dir_all 的还原写入口必须复用同一判据」。实测那条判据在本仓
// **不能这样钉**：`create_dir_all` 在还原链里还用于**应用自己的包目录**（`Pack::begin` 的
// zip 目录、registry 目录），那些位置若也要求祖先复检，便携盘挂在 junction 上的合法用户
// 会被整片拒写 —— 判据从「防穿链」变成「防自己的数据根」。
// 因此这里钉的是可判红的**下限**：还原写回链（restore_pack.rs）的 `ancestor_reparse_block_reason`
// 调用点不得少于 3 处（目录趟 / 文件趟 / 临时件自身观测），掉一处即红。
// 三处各自的**行为**活性由 `engine::restore_pack::tests` 的 4 条单测与真机 #[ignore] 探针
// `还原写回链拒绝junction父目录的新建目标` 钉住，不靠本条计数自证。
const WRITE_CHAIN_FILE = join(ROOT, 'src-tauri', 'src', 'engine', 'restore_pack.rs');
const WRITE_GUARD = 'ancestor_reparse_block_reason(';
const WRITE_FLOOR = 3;
if (existsSync(WRITE_CHAIN_FILE)) {
  const text = blankNonCode(readFileSync(WRITE_CHAIN_FILE, 'utf8'), 'rs');
  const n = [...text.matchAll(new RegExp(WRITE_GUARD.replace('(', '\\('), 'g'))].length;
  if (n < WRITE_FLOOR) {
    g.fail(`还原写回链的祖先复检调用点 ${n} < 下限 ${WRITE_FLOOR} ⇒ 有一处写点被摘掉判据（目录趟/文件趟/临时件观测三处缺一）`);
  } else {
    g.ok(`还原写回链祖先复检查调用点 ${n} 处（≥ 下限 ${WRITE_FLOOR}）`);
  }
  // 合成对照：两处写点的样本必须被同一条判据抓到（把地板降到 3 后本样本必然不达标）
  const thin = 'fn a() { std::fs::create_dir_all(x); }\nfn b() { std::fs::create_dir_all(y); }';
  const thinCount = [...blankNonCode(thin, 'rs').matchAll(new RegExp(WRITE_GUARD.replace('(', '\\('), 'g'))].length;
  if (thinCount >= WRITE_FLOOR) {
    g.fail('W 组判据失效：无复检调用的合成样本竟达到地板（这条断言永远不会红）');
  }
} else {
  g.warn(`未校验：${relative(ROOT, WRITE_CHAIN_FILE).split('\\').join('/')} 不在盘上，W 组本节未验证（不算通过）`);
}

g.finish('check-delete-root-guard: 全部通过（TRANSITION 剩 ' + exempt.size + ' 条，均为已裁定的「不补」并附书面理由，非待办）');

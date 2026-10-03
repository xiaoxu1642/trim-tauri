#!/usr/bin/env node
// check-scan-rule-diff.mjs —— 扫描器「规则改动 → 命中集差分」门禁（V2 P1-C5，2026-09-30）
//
// 为什么需要这层包装：`native-scanner/` 是 path 依赖、**不并 workspace**（AGENTS §5.11），
// 主仓 `cd src-tauri && cargo test` 不会跑它的 `tests/` —— 用例写完没人跑就是死门禁
// （`check-ps-substitution` 恒 SKIP 被摘出清单是前车之鉴）。挂进 Node 门禁清单后，
// 它和其他 check-*.mjs 同一入口、同一退出码语义。
//
// 它守的是契约门禁守不到的那层：`check-cleanup-rule-contract` 对拍的是规则库文本与结构，
// 而「pattern 放宽一格到底多命中哪些文件」只有真跑一遍扫描器才知道（CRS 语料差分的价值
// 正在此：静态全绿 ≠ 行为没变）。同一条用例里还有 D19 死键的**双向**桩：引擎只读
// `candidates`、库里写的是 `candidatesPs`；哪天有人把键名对齐，那侧立刻判红，逼他同步
// 契约表 crossTrack 登记表与覆盖基线，而不是悄悄把枚举面扩大。
//
// 本门禁只读：用例只在 %TEMP% 造自己的样本树、只跑扫描（用例内有一条「扫描是只读的」
// 前提检查），本文件自身不写仓库任何文件。
//
// 用法：node tools/check-scan-rule-diff.mjs

import { readFileSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

const CRATE = join(REPO_ROOT, 'native-scanner');
const SRC = join(CRATE, 'src');

/**
 * 现算 `src/` 下的 `#[test]` 条数（审查 L-31，2026-10-03 L4）。
 *
 * 为什么不能写死数字：上一版注释写「21 个」，实测 25 个 —— 而 M-3 恰好就是把这些
 * 单测接进本门禁的那次修复。**注释里的数字与实际数量漂移，本身没有任何东西会红**，
 * 于是「门禁守着多少条钉桩」这件事在文档层面失明了。改成现算：注释里只说「全部」，
 * 数量打在门禁输出里（随代码变，不会漂）。
 *
 * 口径：只数 `src/*.rs`（`tests/` 由 `cargo test` 另跑，那侧不归这条注释管）。
 */
function countUnitTests() {
  let n = 0;
  let files;
  try {
    files = readdirSync(SRC, { withFileTypes: true });
  } catch {
    // 目录不存在/不可读**不能让门禁崩掉**：崩掉虽然也是非零退出码，但输出是一段
    // node 堆栈，判红原因（路径写错了 or src 被搬走）被埋在栈里，人要反推。
    // fail-closed 的正确形态是「明确判红并说清为什么」，不是「以异常的形式失败」。
    return -1;
  }
  for (const f of files) {
    if (!f.isFile() || !f.name.endsWith('.rs')) continue;
    const src = readFileSync(join(SRC, f.name), 'utf8');
    n += (src.match(/^[ \t]*#\[test\][ \t]*$/gm) || []).length;
  }
  return n;
}

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== 扫描器规则行为差分门禁 ===\n');
// M-3（2026-10-03 L3）：`cargo test --test cleanup_scan_rule_diff` 只跑 tests/，
// native-scanner/src/ 下的 #[cfg(test)] 单测（全局上限、锁中毒口径、控制字符
// 转义等关键钉桩）不在任何门禁内 —— 靠人不主动跑就无人跑。改为 `cargo test`
// 一次接入全部：集成测试（cleanup_scan_rule_diff 等）+ src 单测。
// 审查 L-31（2026-10-03 L4）：单测数量**现算**（见 countUnitTests 的注释），
// 不在注释里写死数字 —— 写死的那个「21」与真实值分叉了很久，无人报警。
// 判红点很实：把 src 下所有 #[test] 删光即红（门禁必须还挂着东西）。
const UNIT_TESTS = countUnitTests();
check(
  UNIT_TESTS > 0,
  `0. src/ 下 #[test] 单测已纳入本门禁（现算 ${UNIT_TESTS < 0 ? '读不到 src 目录' : `${UNIT_TESTS} 条`}，由 cargo test 全包执行）`,
  UNIT_TESTS < 0
    ? `native-scanner/src 不可读（路径写错、或 crate 被搬走）——本门禁此刻什么都守不住，判红`
    : UNIT_TESTS === 0
      ? 'src/ 下数不到任何 #[test]：要么全被删了，要么单测被挪到了 tests/（那侧本门禁也跑，但要改注释口径）'
      : '',
);
console.log(`  cargo test  （cwd=${CRATE}）\n`);

const r = spawnSync('cargo', ['test'], {
  cwd: CRATE,
  stdio: 'inherit',
});

// fail-closed：拿不到 cargo 不算通过（断网/环境坏掉时不许打绿）
if (r.error) {
  console.error(`\n✗ 无法启动 cargo：${r.error.message}`);
  console.error('  本门禁 fail-closed：cargo 不可用即判红，不许把"跑不起来"当"没发现问题"。');
  process.exit(1);
}
if (r.status !== 0) {
  console.error(`\n✗ 行为差分未通过（退出码 ${r.status}）—— 规则逻辑改动改变了命中集，或钉桩失效。`);
  console.error('  ↳ 若是有意改扫描行为：先确认用例断言该不该同步改，再核对契约表');
  console.error('    `tools/rule-schema.json` 的 crossTrack 登记表与 `tools/fixtures/rule-coverage-baseline.json`。');
  process.exit(1);
}
console.log('\n✓ 通过：差分断言 / D19 死键双向桩 / 扫描只读前提');

// ==================== R1-2 重解析点留痕的静态断言 ====================
// 为什么静态面也要钉：上面的行为用例只在 `cleanup_scan_rule_diff` 这一个入口跑，
// 而 `is_reparse` 在两个文件里有 **14 处**调用。将来新增一处「跳过 + continue」形态的
// 站点而忘了留痕，行为用例碰不到那个入口 ⇒ 静默丢目录又回来了。
//
// ⚠️ **口径只覆盖「跳过 + continue」形态，不覆盖 `&& !is_reparse(...)` 条件过滤**。
// 两者语义不同：
//   · 跳过形态 = 「枚举到但主动丢弃」，用户会看到结果偏少，**必须留痕**；
//   · 过滤形态 = 「按条件筛选」（如只要真目录、`rec` 为假时不递归），是枚举口径的一部分，
//     记成「跳过」会把这个计数变成一个含义混乱的混合值。
// 条件过滤那几处（scan.rs 的 dir_size / analyze / expand_tasks / topk 等）**当前无留痕**，
// 它们的跳过量未被任何字段呈现 —— 这是已知缺口，已在下方显式登记（EXPECTED_UNTRACED），
// 不靠「判据看不见」蒙混过去。补齐它们需要给每个域加累加器，属另一轮工作。
//
// 用「跳过分支的紧邻块」而不是「文件里出现过这个词」，是因为后者会把注释、
// helper 定义（is_reparse_target）、条件过滤全部算进去 —— 判据必须能区分「哪一处被改」。
const scanRs = readFileSync(join(SRC, 'scan.rs'), 'utf8');
const cleanRs = readFileSync(join(SRC, 'cleanup_scan.rs'), 'utf8');

/** 逐行判定：这一行是不是「命中即丢弃」的 reparse 跳过分支 */
function isSkipBranch(line) {
  if (/^\s*\/\//.test(line)) return false;
  if (!/is_reparse\s*\(/.test(line)) return false;
  // 条件过滤形态：`&& !is_reparse(...)` / `|| is_reparse(...)` 包在枚举条件里 —— 不算站点
  if (/&&\s*!is_reparse\s*\(/.test(line)) return false;
  if (/\|\|\s*is_reparse\s*\(/.test(line)) return false;
  return true;
}

/** 找每处跳过站点，并检查其后续 3 行内是否有计数自增 */
function reparseSkipSites(src, label) {
  const lines = src.split('\n');
  const bare = [];
  let counted = 0;
  for (let i = 0; i < lines.length; i++) {
    if (!isSkipBranch(lines[i])) continue;
    const win = lines.slice(i, i + 4).join('\n');
    if (/skipped_reparse\s*\+=\s*1|note_reparse_skip\(\)/.test(win)) counted++;
    else bare.push(`${label}:${i + 1} ${lines[i].trim()}`);
  }
  return { bare, counted };
}

const scanSites = reparseSkipSites(scanRs, 'scan.rs');
const cleanSites = reparseSkipSites(cleanRs, 'cleanup_scan.rs');
check(
  scanSites.bare.length === 0 && cleanSites.bare.length === 0,
  `R1-2a. 每处「命中即丢弃」的重解析点跳过都有留痕计数（scan.rs ${scanSites.counted} 处 / cleanup_scan.rs ${cleanSites.counted} 处）`,
  [...scanSites.bare, ...cleanSites.bare].join(' | '),
);

/**
 * 已知未留痕的**条件过滤**站点（枚举口径的一部分，不是「丢弃」）。
 * 每条登记是为了让「没留痕」这件事在门禁输出里可见，而不是靠判据失明蒙混。
 *
 * ⚠️ **匹配用「内容 needle + 唯一性」，不用行号**：行号会因任意一次插删而漂移，
 * 判红信息会变成「8 条全过期」这种没法用的噪音（实测踩过：删掉 scan.rs:275 的一行计数
 * 后，本组把其余 8 条全报成过期，而真正的问题在上一组已经点名了）。
 * 现在口径是「needle 在该文件里**恰好出现一次**」，出现多次说明登记表写糊了，也判红。
 */
const EXPECTED_UNTRACED = [
  ['scan.rs', 't.is_dir() && !is_reparse(ent)', 'analyze 的子目录枚举：只要真目录'],
  ['scan.rs', 'stack.push(fp)', 'dir_size：只要真目录，防跨卷联接点重复计入'],
  ['scan.rs', 'dirs += 1;\n                    stack.push', 'analyze_dir_deep：只要真目录'],
  ['scan.rs', 'is_reparse(&ent) => subdirs.push', 'analyze：只要真目录'],
  ['scan.rs', 'ft.is_dir() && !is_reparse(&ent)', 'expand_tasks：只要真目录'],
  ['scan.rs', 'if rec && !is_reparse(&ent)', 'topk_in：非递归档或非真目录不下钻'],
  ['scan.rs', '|| is_reparse(&ent)', 'empty 根下候选筛选：reparse 不作候选'],
  ['scan.rs', 'if is_reparse_target(p)', 'delete 链的目标保护：reparse 目标直接拒绝删除'],
];
const untracked = EXPECTED_UNTRACED.filter(([f, needle]) => {
  const src = f === 'scan.rs' ? scanRs : cleanRs;
  return src.split(needle).length - 1 !== 1; // 恰好一次
});
check(
  untracked.length === 0,
  `R1-2a2. 条件过滤站点登记表仍对得上（${EXPECTED_UNTRACED.length} 条，均未留痕、已登记为已知缺口）`,
  untracked.length
    ? `这些登记项在磁盘上找不到或出现多次（代码改了或 needle 写得不够唯一）：${untracked.map((u) => `${u[0]} «${u[1]}»`).join(', ')}`
    : '',
);
if (EXPECTED_UNTRACED.length) {
  console.log(`  · R1-2 已知缺口：${EXPECTED_UNTRACED.length} 处「条件过滤」站点的跳过量未留痕（枚举口径的一部分，非丢弃；补齐需给各域加累加器）`);
}

// 反向判据（R1-2.2 的静态面）：**reparse 跳过块内不许改任何判定累加器**。
//
// 为什么不用「计数自增不许出现在判定字段的算式里」那种写法：判红实验 7 实测过——
// 在跳过块里加一句 `acc.total_count += 1`，那个判据**抓不到**（它查的是
// 「`skipped_reparse` 有没有出现在判定算式里」，而实验里加的是反向：判定字段被
// 偷偷塞进了跳过分支）。扫全文件的 `X += 1` 也不成立：判定字段本来就有合法的自增。
//
// 现在的口径是**以站点为圆心**：跳过块内（往后 3 行）除计数自增外不许出现任何
// `+= ` / `-= ` 形式的累加。这才是「留痕不许改变判定」的可判形态。
const judgeAdds = [];
for (const [src, label] of [[scanRs, 'scan.rs'], [cleanRs, 'cleanup_scan.rs']]) {
  const lines = src.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (!isSkipBranch(lines[i])) continue;
    const win = lines.slice(i, i + 4);
    win.forEach((l, k) => {
      if (/skipped_reparse\s*\+=\s*1|note_reparse_skip\(\)/.test(l)) return;
      if (/\w+\s*\+=\s*[0-9]/.test(l) || /\w+\s*-=\s*[0-9]/.test(l)) {
        judgeAdds.push(`${label}:${i + k + 1} ${l.trim()}`);
      }
    });
  }
}
check(
  judgeAdds.length === 0,
  'R1-2b. 重解析点跳过块内不许改判定累加器（留痕只许记 skipped_reparse，不许动判定）',
  judgeAdds.join(' | '),
);

// 透出断言：留痕必须真的到达输出行，否则只是「记了个没人看的数」。
check(
  (cleanRs.match(/\("skippedReparse"/g) || []).length >= 2,
  'R1-2c. 留痕计数已透出到行协议（fileKeys 与 path 两处 emit 都要有）',
  `实际找到 ${(cleanRs.match(/\("skippedReparse"/g) || []).length} 处`,
);

// ==================== E9 excludePaths 分类的静态断言（2026-10-04 审计 §4.9） ====================
// 带点目录（`Vendor.Tool`）曾被 `extension().is_some()` 误 routed 进文件表，
// 而 path_excluded 对文件只做精确相等 ⇒ 排除静默失效、子树照删（安全特性被静默
// 关掉，且扫描/执行两侧同款、没有分叉可查）。修复后两侧都走 classify_exclude_entry
// （按磁盘实况分类）。行为用例钉住扫描侧接线（tests/cleanup_scan_rule_diff.rs）
// 与执行侧行为（engine/native/cleanup.rs），这里钉**双侧接线 + 旧形态绝迹**：
// 行为用例碰不到「有人把调用换回扩展名推断但没删测试」的组合，静态面补上。
const execCleanupRs = readFileSync(join(REPO_ROOT, 'src-tauri/src/engine/native/cleanup.rs'), 'utf8');
check(
  /pub fn classify_exclude_entry\(/.test(cleanRs) &&
    /fn classify_exclude_entry[\s\S]{0,700}?symlink_metadata/.test(cleanRs),
  'E9a. excludePaths 分类器存在且按磁盘实况（symlink_metadata）判',
);
const e9b = (cleanRs.match(/classify_exclude_entry\(&ep/g) || []).length;
check(
  e9b === 1,
  'E9b. 扫描侧 excludePaths 循环走分类器（恰好 1 处接线）',
  `实际 ${e9b} 处`,
);
const e9c = (execCleanupRs.match(/classify_exclude_entry\(&ep/g) || []).length;
check(
  e9c === 1,
  'E9c. 执行侧 excludePaths 循环走分类器（恰好 1 处接线）',
  `实际 ${e9c} 处`,
);
check(
  !cleanRs.includes('if Path::new(&ep).extension().is_some()') &&
    !execCleanupRs.includes('if std::path::Path::new(&ep).extension().is_some()'),
  'E9d. 「按扩展名分类 excludePaths」的旧形态在两侧均已绝迹',
);

console.log('');
if (fail > 0) {
  console.error(`静态留痕断言失败 ${fail} 项。`);
  process.exit(1);
}
console.log('✓ 静态留痕断言全部通过');

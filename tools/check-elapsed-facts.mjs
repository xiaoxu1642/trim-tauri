#!/usr/bin/env node
// check-elapsed-facts.mjs —— E4「区域耗时统计」的门禁（R1-3，2026-10-03）
//
// 为什么需要它：方案 §3.5 E4 写「`results[]` 加 `elapsedMs`，零风险」。但「零风险」
// 有前提 —— **只加字段，不碰任何判定**。这个前提没有机器能替你保证：某天有人在
// 判定里写了一句 `if ms > 1000 { retry() }`，或者把耗时混进 ok_count 的算式，
// 那就不再是 E4 了，而这类改动在 review 里极容易混过去（多一个字段而已）。
//
// 本门禁三条断言：
//   A. 两个域的每条结果都带 `elapsedMs`（漏一条 = 留痕有缺口，正是 v2-M1 那个形态）
//   B. 耗时**不参与任何判定**（反向判据，见下）
//   C. 失败路径同样计时（只测成功路径等于把「慢的失败」藏起来）
//
// 2026-10-09（D3）：contextmenu 域随右键菜单删除链整链退役（载体 remove + 嵌套 push_result
// 已删）——本门禁如实在两个域（startup / perf）上继续生效；将来谁的 results 加回耗时字段，
// 按本文件同口径把它登记进 DOMAINS。
//
// B 与 C 都是反向判据，也是本门禁最容易做坏的地方。已实测踩过两个坑：
//   ① B 的窗口正则若只查「`.elapsed()` 附近有没有比较符」，会漏掉**最常见**的
//      「赋值给中间变量再比较」形态（`let ms = t.elapsed().as_millis(); if ms > …`）——
//      链式调用把比较符推出了窗口。现在改为「先收集计时派生变量名，再看有无消费」。
//   ② C 若在全文件范围比「计时起点」与「第一个 error 分支」的行序，会恒红
//      （别的函数的 error 分支被算进来）。现在限定在本域区间内比。
//
// 正向自检（POSITIVE_CONTROLS）：本门禁是「找违规型」的，必须能对已知违规样本判红，
// 否则「全绿」只是判据失灵。自检与断言**共用同一份判据函数**（不另写副本）。
'use strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

const read = (...p) => readFileSync(join(ROOT, ...p), 'utf8');
const startupRs = read('src-tauri', 'src', 'commands', 'startup.rs');
const perfRs = read('native-scanner', 'src', 'perf.rs');

// ============================================================
// 判据①（反向）：耗时参与判定
// ============================================================

/** 直接形态：`.elapsed()` 链式调用后紧跟比较符/跳转（同一表达式内） */
const DIRECT_JUDGE = [
  /\.elapsed\([^)]*\)[\w:.]*(?:\(\))*\s*(?:>|>=|<|<=|==|!=)\s*\d/,
  /(?:>|>=|<|<=)\s*\d\s*(?:ms\b|毫秒)[^;\n]*\.elapsed\(/,
  /(?:ok_count|failed|success|total|retried)\w*\s*[+\-]=?[^;\n]*\.elapsed\(/i,
  /\.elapsed\([^)]*\)[\w:.]*(?:\(\))*\s*;?\s*(?:retry|skip|abort|break|continue)\b/i,
];

/** 计时派生变量的兜底命名（覆盖多种，避免「换个变量名就绕过」） */
const TIMER_VARS = [
  'ms', 'elapsed_ms', 'elapsed_us', 'elapsed', 'cost',
  'dur', 'duration', 'taken', 'spent', 't_ms',
];

/** 变量 name 是否被消费（进了比较 / 跳转 / 判定算式） */
function consumedIn(win, name) {
  const v = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const patterns = [
    'if\\s*\\([^)]*\\b' + v + '\\b[^)]*\\)',
    '\\b' + v + '\\b\\s*(?:>|>=|<|<=|==|!=)',
    '(?:>|>=|<|<=)\\s*' + v + '\\b',
    '(?:ok_count|failed|success|total|retried)\\w*\\s*[+\\-]=?[^\\n]*\\b' + v + '\\b',
    '(?:retry|skip|abort|break|continue)\\b[^\\n]*\\b' + v + '\\b',
  ];
  return patterns.some((p) => new RegExp(p).test(win));
}

/**
 * 扫出「耗时参与判定」的点。
 *
 * 锚点是**计时机制**（`Instant::now` / `.elapsed`）而不是字段名 —— 违规可以写成
 * 「先算耗时 → 拿它判定 → 最后才写字段」，按字段名扫描会漏掉。
 *
 * 窗口取「本行起 12 行」：足以覆盖「赋值 → 下一段消费」，又不会跨到别的域。
 *
 * @param {string} src 源码全文
 * @returns {string[]} 违规点描述，空数组 = 干净
 */
function scanJudgement(src) {
  const lines = src.split('\n');
  const hits = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!/Instant::now\(\)/.test(line) && !/\.elapsed\(/.test(line)) continue;
    const win = lines.slice(i, Math.min(lines.length, i + 12)).join('\n');
    if (DIRECT_JUDGE.some((re) => re.test(win))) {
      hits.push(`第 ${i + 1} 行 ${line.trim()}`);
      continue;
    }
    // 派生变量形态：收集窗口内由计时派生的变量名，再看有没有被消费
    const derived = new Set();
    const assignRe = /\b(?:let|const)\s+(?:mut\s+)?(\w+)\s*(?::[^=]*)?=[^;\n]*\.elapsed\(/g;
    for (const m of win.matchAll(assignRe)) derived.add(m[1]);
    const names = derived.size ? [...derived] : TIMER_VARS;
    if (names.some((n) => consumedIn(win, n))) hits.push(`第 ${i + 1} 行 ${line.trim()}`);
  }
  return hits;
}

// ============================================================
// 判据②：失败路径同样计时
// ============================================================

/**
 * 「失败路径同样计时」：以**失败分支为圆心**反向找该分支所属循环体里的计时起点。
 *
 * ⚠️ 三个坑都是实测踩出来的：
 *  ① 不能全文件比「计时起点 vs 第一个 error」的行序 —— 别的函数的 error 分支会
 *     被算进来，恒红（首版）；
 *  ② 只比行序也不够 —— 起点仍在 error 之前但隔了十几行，说明计时器落在判定内部，
 *     失败路径没被包住（判红实验 10b 抓不到）；
 *  ③ 也不能「取区间内第一个 Instant::now()」—— 区间起点往往落在函数中段，
 *     前面那些 unrelated 的 now() 会被误当成本域的（实测抓到 273 行 /1935 行的假阳性）。
 *
 * 现在的口径：从**每个失败分支**出发，向**前**找最近的一个 `Instant::now()`。
 *  ③ 也不能「取区间内第一个 Instant::now()」—— 区间起点往往落在函数中段，
 *     前面那些 unrelated 的 now() 会被误当成本域的（实测抓到 273 行/ 1935 行的假阳性）。
 *
 * 阈值 `MAX_GAP` 的来历：真实代码里「循环头的计时器」到「循环体末尾的失败分支」
 * 实测可到44 行（contextmenu 37 / startup 44，两处都带 3~4 层嵌套判定），
 * 所以 50 是「能覆盖真实代码又不至于把判据放空」的上界。**真正的判据是
 * 「前 MAX_GAP 行内找得到起点」**—— 行距超限只是附带提示，不是判红条件：
 * 刻意把两种情况分开报，避免「行距超了但计时起点确实在同一循环体」被误判。
 *
 * @param {string} src 源码全文
 * @param {RegExp} failRe 失败分支的特征（出现多次即逐个检查）
 * @returns {string[]} 问题描述，空数组 = 干净
 */
const MAX_GAP = 50;
function scanFailPathTimer(src, failRe) {
  const lines = src.split('\n');
  const hits = [];
  lines.forEach((l, i) => {
    if (!failRe.test(l)) return;
    // 限定在同一顶层函数体内（坑④：别处函数里的Instant::now() 不算）
    let fnStart = 0;
    for (let k = i; k >= 0; k--) {
      if (/^(?:pub(?:\(\w+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+\w+/.test(lines[k])) { fnStart = k; break; }
    }
    let nearest = -1;
    for (let k = i; k >= fnStart && i - k <= MAX_GAP; k--) {
      if (/Instant::now\(\)/.test(lines[k])) { nearest = k; break; }
    }
    if (nearest < 0) {
      hits.push(
        `第 ${i + 1} 行失败分支：所在函数体（自第 ${fnStart + 1} 行起）内前 ${MAX_GAP} 行找不到计时起点` +
        `（函数体共 ${i - fnStart} 行）⇒ 失败路径没计时`,
      );
    }
  });
  return hits;
}

// ============================================================
// A. 每个域都有耗时字段
// ============================================================
// 口径：字段名必须出现在「产出该域 results 的文件」里，且至少有 1 处**真在计算**
// （`elapsed()` 调用）。只写字段名不计算 = 假绿（`"elapsedMs": 0` 恒成立）。
//
// ⚠️ **per-domain needle，不能只查字段名**：`perf.rs` 的 diskbench 早就有
// `elapsedMs`（`:369`），只查 `"elapsedMs"` 的话，mem-clean 那处被删掉时
// 断言依然会绿 —— 这就是「同一个文件里另一处同名字段顶包」的假绿。
// 所以每个域登记**它自己那处**的精确形态。
const DOMAINS = [
  {
    label: 'startup（启动项删除）',
    src: startupRs,
    needle: '"elapsedMs".into(),',
  },
  {
    label: 'perf（内存清理分区）',
    src: perfRs,
    needle: '\\"elapsedMs\\":{elapsed_ms}',
  },
];
for (const d of DOMAINS) {
  const hasField = d.src.includes(d.needle);
  const hasCalc = /\.elapsed\(\)/.test(d.src);
  check(
    hasField && hasCalc,
    `A. ${d.label} 的 results 带耗时且真在计算`,
    !hasField
      ? `本域的耗时写入点不见了（needle=${d.needle}）—— 注意不能只查字段名，` +
        '同文件里 diskbench 等别处早就有同名字段，会顶包造成假绿'
      : hasCalc ? '' : '字段名在但没有任何 elapsed() 计算 ⇒ 恒为 0 的假绿',
  );
}

// ============================================================
// B. 耗时不得参与判定
// ============================================================
const judgeSites = [];
for (const [label, src] of [['startup.rs', startupRs], ['perf.rs', perfRs]]) {
  for (const hit of scanJudgement(src)) judgeSites.push(`${label}:${hit}`);
}
check(
  judgeSites.length === 0,
  'B. 耗时字段不参与任何判定（E4 的「零风险」前提就在这条）',
  judgeSites.join(' | '),
);

// ==================== C 组的已知边界（必须留在文件里） ====================
// C 组能抓「所在函数体内完全没有计时起点」，**抓不到**「计时起点落在判定内部」——
// 即 `let allowed = check(); …十几行… if !allowed { let t = now(); … }` 这种形态。
// 判红实验 10b 实测：此时起点仍在同一函数体内、距失败分支 < MAX_GAP，C 组放行。
// 抓它需要真正的支配树分析（计时器是否支配该分支），静态正则做不到。
// 本仓的选择：如实登记边界，而不是把 MAX_GAP 收紧到能抓住它 —— 收紧会误红真实代码
// （实测真实代码的起点到失败分支可达 44 行）。当前真实代码里计时器都在循环头、
// 失败分支都在同一循环体内，所以这条边界暂不构成实际风险；但它是**已知缺口**，
// 不是「已覆盖」。

// ============================================================
// C. 失败路径同样计时
// ============================================================
const DOMAIN_FAIL = [
  // startup：set_result_entry 的 error 写入
  ['startup.rs', startupRs, /set_result_entry\(&mut data, id, "error"/],
  // perf：mem_clean 的 items 循环（成功/失败共用一个 push 点，`ok` 由 status==0 派生）
  ['perf.rs', perfRs, /let status: i32 = if/],
];
const failPath = [];
for (const [label, src, failRe] of DOMAIN_FAIL) {
  for (const hit of scanFailPathTimer(src, failRe)) failPath.push(`${label}: ${hit}`);
}
check(
  failPath.length === 0,
  'C. 失败路径同样计时（计时起点必须早于本域第一个失败分支）',
  failPath.join(' | '),
);

console.log('');
if (fail > 0) {
  console.error(`E4 耗时字段门禁失败 ${fail} 项。`);
  process.exit(1);
}
console.log('✓ E4 耗时字段：两个域都带、都不参与判定、失败路径都计时');

// ============================================================
// POSITIVE_CONTROLS（正向自检）
// ============================================================
// 本门禁是「找违规型」的：若判据失灵（全绿只是因为什么都没扫到），上面的 ✓ 是假的。
// 这里对**已知违规样本**跑一遍**同一份判据函数**，必须报红 —— 报绿说明判据坏了。
// ⚠️ 自检必须复用断言用的 scanJudgement / scanFailPathTimer，不能各写一份：
// 首版就是自检里塞了旧副本，于是「上面抓 1 条、自检说抓 3 条」自相矛盾而没人发现。
(function positiveControls() {
  const judgeViolations = [
    ['直接比阈值', 'let t = Instant::now();\ndo_it();\nif t.elapsed().as_millis() > 1000 { retry(); }'],
    ['中间变量比阈值', 'let t = Instant::now();\ndo_it();\nlet ms = t.elapsed().as_millis();\nif ms > 1000 {\n    retry();\n}'],
    ['中间变量驱动控制流', 'let t = Instant::now();\nlet ms = t.elapsed();\nif ms > 500 { skip(); }'],
    ['耗时混进成功计数', 'let t = Instant::now();\nlet ms = t.elapsed().as_millis();\nok_count += 1 + ms as usize;'],
    ['耗时驱动 break', 'let t = Instant::now();\nlet ms = t.elapsed().as_millis();\nif ms > 100 { break; }'],
  ];
  const missedJudge = judgeViolations.filter(([, src]) => scanJudgement(src).length === 0).map(([n]) => n);

  const ANY = /for x in items/;
  const ERR = /"status":\s*"error"/;
  const timerViolations = [
    // 形态一：失败分支之前**完全没有**计时起点
    ['失败分支前没有计时起点', 'for x in items {\n  let r = json!({"status":"error"});\n  results.push(r);\n}', ERR],
    // 形态二：计时器落在**另一个函数**里（正向自检抓出来的真盲区）——
    // 文件别处有个 `Instant::now()`，若只按行距限定就会把它当成本域的计时起点。
    ['计时器落在另一个函数', [
      'fn other_helper() {',
      '    let t = std::time::Instant::now();',
      '    do_something();',
      '}',
      'fn target() {',
      '    let r = json!({"status":"error"});',
      '    results.push(r);',
      '}',
    ].join('\n'), ERR],
  ];
  const missedTimer = timerViolations
    .filter(([, src, re]) => scanFailPathTimer(src, re).length === 0)
    .map(([n]) => n);

  const total = judgeViolations.length + timerViolations.length;
  const caught = total - missedJudge.length - missedTimer.length;
  const ok = missedJudge.length === 0 && missedTimer.length === 0;
  console.log(`${ok ? '✓' : '✗'} 自检：${total} 条已知违规样本，判据能抓住 ${caught} 条`);
  if (!ok) {
    console.error(`  ✗ 判据失灵：抓不住 ${JSON.stringify([...missedJudge, ...missedTimer])} —— 上面的 ✓ 不可信，请修判据`);
    process.exit(1);
  }
})();
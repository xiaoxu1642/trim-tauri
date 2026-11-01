'use strict';
// tools/lib/next-rules-version.mjs —— 写库工具 rulesVersion 的单一口径（T1c-L05）
//
// 两个写库工具曾各写一份：import-winapp2 用 toISOString（UTC），new-residue-rule
// 用本地日期 + 「当前+1」。北京时间 0:00–8:00 内 UTC 日期还是前一天 ⇒ 同一台机器
// 先后跑两个工具会得到倒序版本号；而 rulesVersion 只被当作「这包是哪一版」的标签，
// 没有门禁验单调，倒序会静默通过。这里只做一件事：本地日期与「当前+1」取大，
// 保证严格递增且不会倒退成 UTC 前一天。

/**
 * 本地日期 YYYYMMDD。刻意不用 toISOString：那是 UTC（见头注）。
 * @param {Date} [now]
 * @returns {number}
 */
export function rulesVersionToday(now = new Date()) {
  const pad = (n) => String(n).padStart(2, '0');
  return Number(`${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}`);
}

/**
 * @param {number} curVer 当前库的 rulesVersion（可缺省/非数字，一律按零处理）
 * @param {Date} [now] 注入时钟（自检用）
 * @returns {number} 严格大于 curVer 的 YYYYMMDD 式版本号
 */
export function nextRulesVersion(curVer, now = new Date()) {
  const cur = Number(curVer) || 0;
  return Math.max(rulesVersionToday(now), cur + 1);
}

#!/usr/bin/env node
// stamp-rule-ver.mjs —— 把条目级版本戳 `ver` 重刷成顶层 rulesVersion（V2 P2-A1，2026-09-30）
//
// 为什么要单独一个脚本而不是"手写 82 处"：`ver` 的语义是**这一版包**（不是该条目的引入版本），
// 所以它必须与顶层 `rulesVersion` 逐条相等；两侧契约门禁（Node + Rust）都会断言这一点。
// 手写就会出「改了 rulesVersion 忘了刷 ver ⇒ 装载侧整包拒绝」这种自伤，而且两份库结构不同
// （清理是 groups→subGroups→items，残留是 rules[]），人肉更容易漏一边。
//
// 用法：
//   node tools/stamp-rule-ver.mjs            只检查（不写盘），不一致即非 0 退出
//   node tools/stamp-rule-ver.mjs --write    重刷两份库的 ver（**不签名**）
//   node tools/stamp-rule-ver.mjs --bump 20261005   先把 rulesVersion 抬到该值再重刷
//
// 为什么本脚本刻意不签名：私钥只在发布机（AGENTS §5.20），且"改内容"与"签内容"是两步——
// 合成一步会让人以为写完就直接能发。写完后必须自己跑：
//   node tools/sign-cleanup-rules.mjs sign + gen-fallback
//   node tools/sign-cleanup-rules.mjs sign --file src-tauri/data/uninstall-residue-rules.json
//
// 缩进/键序保持原样（2 空格 + CRLF 无关，两份库现有风格由 JSON.stringify(…,2) 决定）；
// 写盘走"整文件重写"而不是补丁，因为签名覆盖的是紧凑 JSON 文本，格式化差异不影响验签、
// 但会影响 diff 可读性 —— 这里只动 ver 一处，其余字段原样保留。
'use strict';
import fs from 'node:fs';
import path from 'node:path';

const ROOT = path.join(path.dirname(new URL(import.meta.url).pathname.replace(/^\//, '')).replace(/\\/g, '/'), '..');
const CLEANUP = path.join(ROOT, 'src-tauri', 'data', 'cleanup-rules.json');
const RESIDUE = path.join(ROOT, 'src-tauri', 'data', 'uninstall-residue-rules.json');

const argv = process.argv.slice(2);
const WRITE = argv.includes('--write');
const bumpIdx = argv.indexOf('--bump');
const BUMP = bumpIdx >= 0 ? Number(argv[bumpIdx + 1]) : 0;
if (bumpIdx >= 0 && (!Number.isInteger(BUMP) || BUMP < 20260928)) {
  console.error(`✗ --bump 需要一个不小于 20260928 的整数（日期式版本号），得到 ${argv[bumpIdx + 1]}`);
  process.exit(2);
}

function itemsOf(rules) {
  const out = [];
  for (const g of rules.groups ?? []) {
    for (const it of g.items ?? []) out.push(it);
    for (const sg of g.subGroups ?? []) for (const it of sg.items ?? []) out.push(it);
  }
  return out;
}

/** 返回 { file, label, total, stale, target } */
function survey(file, label, collect) {
  const pkg = JSON.parse(fs.readFileSync(file, 'utf8'));
  const target = BUMP || pkg.rulesVersion;
  if (!Number.isInteger(target) || target <= 0) {
    console.error(`✗ ${label}: rulesVersion 不是正整数（${pkg.rulesVersion}）`);
    process.exit(2);
  }
  const items = collect(pkg);
  const stale = items.filter((it) => it.ver !== target);
  return { file, label, pkg, items, target, stale, collect };
}

function apply(r) {
  if (!r.stale.length && r.pkg.rulesVersion === r.target) return false;
  if (BUMP) r.pkg.rulesVersion = BUMP;
  for (const it of r.items) it.ver = r.target;
  fs.writeFileSync(r.file, JSON.stringify(r.pkg, null, 2) + '\n', 'utf8');
  return true;
}

const targets = [
  survey(CLEANUP, '清理库', (p) => itemsOf(p)),
  survey(RESIDUE, '残留库', (p) => (Array.isArray(p.rules) ? p.rules : [])),
];

let changed = false;
for (const r of targets) {
  const head = `${r.label}：${r.items.length} 条，顶层 rulesVersion=${r.pkg.rulesVersion}，目标 ver=${r.target}`;
  if (!r.stale.length && r.pkg.rulesVersion === r.target) {
    console.log(`✓ ${head} —— 全部一致`);
    continue;
  }
  const missing = r.stale.filter((it) => it.ver === undefined).length;
  console.log(`${WRITE ? '↻' : '✗'} ${head} —— 不一致 ${r.stale.length} 条（其中缺 ver ${missing} 条）`);
  if (WRITE) {
    apply(r);
    changed = true;
  }
}

if (!WRITE) {
  if (changed) process.exit(1);
  const anyStale = targets.some((r) => r.stale.length || r.pkg.rulesVersion !== r.target);
  if (anyStale) {
    console.error('\n✗ 条目级 ver 与 rulesVersion 不一致，跑：node tools/stamp-rule-ver.mjs --write（随后必须重签）');
    process.exit(1);
  }
  process.exit(0);
}

console.log('\n已重刷。下一步（顺序不能倒）：');
console.log('  node tools/sign-cleanup-rules.mjs sign');
console.log('  node tools/sign-cleanup-rules.mjs gen-fallback');
console.log('  node tools/sign-cleanup-rules.mjs sign --file src-tauri/data/uninstall-residue-rules.json');
console.log('  node tools/check-data-parity.mjs && node tools/check-cleanup-rule-contract.mjs && node tools/check-residue-rule-contract.mjs');

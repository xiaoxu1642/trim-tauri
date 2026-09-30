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

import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

const CRATE = join(REPO_ROOT, 'native-scanner');

console.log('=== 扫描器规则行为差分门禁 ===\n');
console.log(`  cargo test --test cleanup_scan_rule_diff  （cwd=${CRATE}）\n`);

const r = spawnSync('cargo', ['test', '--test', 'cleanup_scan_rule_diff'], {
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

#!/usr/bin/env node
// check-headless-cli.mjs —— P2-B 无头扫描 CLI 冒烟（OPTIONAL：发版前 / CLI 链路改动时跑）
//
// 为什么要它：`examples/scan.rs` 是「不启 UI 也能拿清理候选」的对外通道，其价值在
// 结构契约（JSON 形状 + 只读语义）；但它的构建依赖 cargo（重）、执行要扫真实系统
// （机器状态相关）——不适合进日常 MUST_RUN，登记为 OPTIONAL 发版项。
//
// 检查内容：
//   1. `cargo build --example scan`（增量；已构建则秒级）
//   2. 跑 `scan --item tempFiles --json`（tempFiles 在任何 Windows 上恒存在；只读）
//   3. 断言：exit 0、success=true、counts 七键数值齐、data 含候选且首条 id=tempFiles、
//      malformedLines=0（行协议干净）
// 判红自证：开发时把 3a 断言取反跑红一次，恢复后转绿。
'use strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

// 1. 构建 example
try {
  execFileSync('cargo', ['build', '--manifest-path', path.join(ROOT, 'src-tauri', 'Cargo.toml'), '--example', 'scan'], { stdio: 'pipe', timeout: 300000 });
  check(true, '1. cargo build --example scan');
} catch (e) {
  check(false, '1. cargo build --example scan', String(e.message || e).slice(0, 300));
  console.error('\ncheck-headless-cli: 构建失败，后续检查跳过（exit 1）');
  process.exit(1);
}

// 2. 跑 CLI（只读；tempFiles 恒存在）
const exe = path.join(ROOT, 'src-tauri', 'target', 'debug', 'examples', process.platform === 'win32' ? 'scan.exe' : 'scan');
let out = '';
let code = 0;
try {
  out = execFileSync(exe, ['--item', 'tempFiles', '--json'], { encoding: 'utf8', timeout: 180000, maxBuffer: 64 * 1024 * 1024 });
} catch (e) {
  code = e.status ?? -1;
  out = String(e.stdout || '');
}
check(code === 0, `2. scan --item tempFiles --json 退出码 0`, `实得 ${code}`);

// 3. JSON 形状断言
let j = null;
try {
  j = JSON.parse(out);
  check(true, '3. 输出为合法 JSON');
} catch (e) {
  check(false, '3. 输出为合法 JSON', String(e.message).slice(0, 200));
}
if (j) {
  check(j.success === true, '3a. success = true', `实得 ${j.success}`);
  const counts = j.counts || {};
  const keys = ['entries', 'filesTotal', 'lockedFiles', 'lockedEntries', 'truncatedEntries', 'skippedReparseTotal', 'malformedLines'];
  const missing = keys.filter((k) => typeof counts[k] !== 'number');
  check(missing.length === 0, '3b. counts 七键数值齐', missing.length ? `缺/非数值: ${missing.join(', ')}` : keys.join(','));
  check(Array.isArray(j.data) && j.data.length >= 1, '3c. data 为数组且含候选', `实得 ${Array.isArray(j.data) ? j.data.length : 'n/a'}`);
  const tid = j.data && j.data[0] && j.data[0].id;
  check(tid === 'tempFiles', '3d. 首条候选 id = tempFiles', `实得 ${tid}`);
  check(counts.malformedLines === 0, '3e. 行协议畸形行 = 0', `实得 ${counts.malformedLines}`);
}

if (fail > 0) {
  console.error(`\ncheck-headless-cli: ${fail} 项失败`);
  process.exit(1);
}
console.log('\ncheck-headless-cli: 全部通过');

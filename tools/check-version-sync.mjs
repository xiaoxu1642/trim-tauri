#!/usr/bin/env node
// check-version-sync.mjs — 版本号四处一致门禁（J1，2026-09-29）
//
// 为什么要有这条：AGENTS §7.1 一直要求「三处同步」，但那是人工纪律——发版时我手工 grep
// 三处确认，改漏一处不会有任何东西报警。竞品分析里正好有一个现成的事故形态：
// 杰瑞调机助手 asar 内 package.json 是 3.1.75、exe 文件版本是 3.1.54，于是「检查更新按
// 3.1.75 比对、卸载列表显示 3.1.54」，产物与安装器不再一一对应。
//
// 第四处是 Cargo.lock 里 `name = "trim-tauri"` 那一段：它通常由 cargo 自动同步，
// 但自动的前提是有人真跑过一次 cargo 命令。发版链上「只改 conf 忘了 readme」
// 与「lock 停留在旧版本」是两类不同的漏法，都要钉住。
//
// 用法：node tools/check-version-sync.mjs
'use strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== 版本号一致性门禁 ===\n');

// 1) tauri.conf.json
let confVer = '';
try {
  confVer = String(JSON.parse(read('src-tauri/tauri.conf.json')).version ?? '');
} catch (e) {
  check(false, '1. tauri.conf.json 可读且含 version', e.message);
}

// 2) Cargo.toml 的 [package] 段（不能全局找 version，依赖段里也有一堆）
const cargo = read('src-tauri/Cargo.toml');
const pkgSection = cargo.split(/^\[.*\]$/m)[0] + (cargo.match(/^\[package\]$/m) ? cargo.split(/^\[package\]$/m)[1].split(/^\[.*\]$/m)[0] : '');
const cargoVer = (pkgSection.match(/^version\s*=\s*"([^"]+)"/m) || [])[1] ?? '';

// 3) Cargo.lock 里本包那一段
const lock = read('src-tauri/Cargo.lock');
const lockBlk = lock.split(/\n\[\[package\]\]\n/).find((b) => /^name = "trim-tauri"$/m.test(b)) ?? '';
const lockVer = (lockBlk.match(/^version = "([^"]+)"/m) || [])[1] ?? '';

// 4) readme 顶部引用块
const readme = read('readme.md');
const readmeVer = (readme.match(/版本 \*\*([0-9][0-9.]*)\*\*/) || [])[1] ?? '';

const found = { conf: confVer, cargo: cargoVer, lock: lockVer, readme: readmeVer };
console.log(`读到的值：conf=${confVer || '?'} Cargo.toml=${cargoVer || '?'} Cargo.lock=${lockVer || '?'} readme=${readmeVer || '?'}`);

check(!!confVer, '1. tauri.conf.json 有 version', confVer ? confVer : '字段缺失');
check(!!cargoVer, '2. Cargo.toml [package] 有 version（只认 [package] 段，依赖段的 version 不算）', cargoVer || '未找到');
check(!!lockVer, '3. Cargo.lock 有 name="trim-tauri" 包段及其 version', lockVer || '未找到该包段（lock 未同步？）');
check(!!readmeVer, '4. readme.md 顶部有「版本 **x.y.z**」', readmeVer || '未找到');

const values = Object.entries(found).filter(([, v]) => v);
const distinct = [...new Set(values.map(([, v]) => v))];
check(distinct.length === 1, '5. 四处版本号完全一致',
  distinct.length === 1 ? `全部为 ${distinct[0]}` : `分叉：${values.map(([k, v]) => `${k}=${v}`).join(' / ')}`);

const semver = /^\d+\.\d+\.\d+$/;
check(semver.test(confVer), '6. 版本号是 x.y.z 三段（updater 与 NSIS 产物名都按这个形状拼）', confVer);

// 7) 审查 L-1（2026-10-03）：conf 的 updater endpoints ⇄ updater.rs FEEDS 字面对拍。
// 运行时以代码为准（每个 builder 都 .endpoints(vec![endpoint]) 覆盖 conf），conf 那份
// 是「读配置的人看到的线路清单」——漂了不产生漏洞，但会让人得出错误结论（K5 的
// 教训：清单侧与产物侧各改各的，没有任何东西会红）。字面双向包含：URL 改任何
// 一段（协议/基址/清单名）都会红，不解析 Rust 元组表、不做 URL 归一化。
const updaterSrc = read('src-tauri/src/commands/updater.rs');
let endpoints = [];
try {
  endpoints = JSON.parse(read('src-tauri/tauri.conf.json')).plugins?.updater?.endpoints ?? [];
} catch { /* conf 解析失败时 endpoints 保持空，走下方判红 */ }
const feedUrls = [];
{
  // FEEDS 元组里的 (基址, 清单名) 对：清单名按 *.json 识别，拼成完整 URL
  const re = /"(https:\/\/[^"]+)",\s*\n\s*"([^"]*\.json)"/g;
  let m;
  while ((m = re.exec(updaterSrc))) feedUrls.push(m[1] + m[2]);
}
const missingInSrc = endpoints.filter((u) => !feedUrls.includes(u));
const missingInConf = feedUrls.filter((u) => !endpoints.includes(u));
check(
  endpoints.length > 0 && missingInSrc.length === 0 && missingInConf.length === 0,
  '7. conf updater endpoints ⇄ updater.rs FEEDS 一致（L-1：死配置也要自洽）',
  endpoints.length === 0 ? 'conf endpoints 为空或 conf 不可读'
    : feedUrls.length === 0 ? 'FEEDS 里没解析出任何 线路基址+清单.json 对（线路表形态变了？）'
      : [missingInSrc.length ? `conf 有而 FEEDS 无：${missingInSrc.join('、')}` : '',
        missingInConf.length ? `FEEDS 有而 conf 无：${missingInConf.join('、')}` : '']
        .filter(Boolean).join('；') || `双方 ${endpoints.length} 条一致`,
);

console.log('');
if (fail > 0) {
  console.error('门禁失败：有断言未通过');
  process.exit(1);
}
console.log('版本号一致性门禁全部通过');

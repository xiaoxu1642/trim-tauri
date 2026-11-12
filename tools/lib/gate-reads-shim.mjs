'use strict';
// tools/lib/gate-reads-shim.mjs —— `--emit-reads` 专用的 fs 记录层
//
// 为什么需要它：按模块跑门禁的前提是「这条门禁到底读哪些文件」。靠人读源码猜会漏
// （真实例：check-desktop-entry 走 lstat/readlink 读桌面链接，check-desc-vs-writes
// 经 createRequire 读 PS 生成物，静态 grep 都看不见）。这里在**真跑一遍**的时候
// 记录每一次 stat/read，再用认领表折算成模块集合 —— 结论来自行为，不来自猜测。
//
// 输出走 stdout 的固定前缀行（不落临时文件）：门禁自己的输出照常透传，
// 调用方按前缀过滤。前缀必须够独特，避免和门禁正文撞行。
import * as real from 'node:fs';
import { fileURLToPath } from 'node:url';

export * from 'node:fs';

const MARK = '@@TRIM_READ@@ ';
const seen = new Set();
const log = (p) => {
  let s = null;
  if (typeof p === 'string') s = p;
  else if (p instanceof URL && p.protocol === 'file:') s = fileURLToPath(p);
  if (!s || seen.has(s)) return;
  seen.add(s);
  // 写 fd 2 而不是 stdout：门禁自己的 stdout 会被调用方判读（✗ / SKIP / 0 对象计数），
  // 混进上千行追踪会污染判定；而且 spawnSync 的 maxBuffer 会先把 stdout 撑爆。
  // 走 stderr 时调用方只过滤 @@TRIM_READ@@ 前缀行，其余 stderr 仍按原样判读。
  real.writeSync(2, `${MARK}${s.replace(/\\/g, '/')}\n`);
};

const wrap = (name) => {
  const orig = real[name];
  return function (p, ...rest) {
    log(p);
    return orig.call(this, p, ...rest);
  };
};

export const readFileSync = wrap('readFileSync');
export const readdirSync = wrap('readdirSync');
export const statSync = wrap('statSync');
export const existsSync = wrap('existsSync');
export const lstatSync = wrap('lstatSync');
export const readlinkSync = wrap('readlinkSync');
export const openSync = wrap('openSync');
export const accessSync = wrap('accessSync');

export default {
  ...real,
  readFileSync,
  readdirSync,
  statSync,
  existsSync,
  lstatSync,
  readlinkSync,
  openSync,
  accessSync,
};

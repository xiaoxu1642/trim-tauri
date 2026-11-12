'use strict';
// tools/lib/gate-reads-hooks.mjs —— 把 node:fs 重定向到 gate-reads-shim.mjs 的加载钩子
//
// 用法（只在 --emit-reads 里，由 check-gate-roster spawn 子进程时挂上）：
//   node --experimental-loader tools/lib/gate-reads-hooks.mjs tools/check-xxx.mjs
//
// 注意：钩子自身对 `node:fs` 的 import 必须放行（否则 shim 自己也被换成 shim，
// 递归到栈溢出）。判据用 parentURL 是否就是 shim 本体。
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const SHIM = pathToFileURL(join(dirname(fileURLToPath(import.meta.url)), 'gate-reads-shim.mjs')).href;

export async function resolve(specifier, context, next) {
  const fromShim = (context.parentURL || '').includes('gate-reads-shim.mjs');
  if (!fromShim && (specifier === 'node:fs' || specifier === 'fs')) {
    return { url: SHIM, shortCircuit: true };
  }
  return next(specifier, context);
}

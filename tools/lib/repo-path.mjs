'use strict';
// tools/lib/repo-path.mjs —— 命令行路径参数的仓内 containment（T1c-L08）
//
// `--file` / `--out` 经 path.join/path.resolve 会把 `..` 折叠掉：`--file ../x.json`
// 能写穿到仓库外，而这类工具写的都是规则库的近亲（签它、合并它）。JSON 写出成功
// 不等于可恢复——仓库外的写面没有 git、没有验签链，回来时没人知道它被改过。
// 判据：解析后相对 ROOT 不得以 `..` 开头；不同盘符时 path.relative 直接返回绝对
// 路径，同样拦下。调用方决定错误怎么呈现（die / console.error + exit）。
import path from 'node:path';

/**
 * @param {string} root 仓库根（绝对路径）
 * @param {string} p 用户传入的路径（相对仓根，或绝对路径）
 * @param {string} flag 报错里点名是哪个开关
 * @returns {string} 解析后的绝对路径
 */
export function resolveInsideRepo(root, p, flag) {
  const abs = path.resolve(root, p);
  const back = path.relative(root, abs);
  if (back.startsWith('..') || path.isAbsolute(back)) {
    throw new Error(`${flag} 必须指向仓库内的路径（仓库外的写入没有 git 恢复面）：${p}`);
  }
  return abs;
}

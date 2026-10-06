'use strict';
// tools/lib/fs-walk.mjs —— 门禁共享：递归目录遍历
//
// 为什么单独成模块：此前 12 条门禁各自手抄一份 walk（共 13 处实现，形状各异：
// statSync/withFileTypes 两派、缺目录有崩有跳过、相对路径各映射各的），新增门禁
// 复制旧版时把「缺目录容错」这类细节抄漏就会 ENOENT 崩整轮（docs 测试框架报告 §3.5）。
// 这里做单一真源，判据只有一份实现。
import { readdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * 递归收集目录下的文件（绝对路径，readdir 原生顺序，不排序）。
 *
 * 缺目录/不可读目录返回该支空数组而不是抛 ENOENT：门禁对缺失输入的纪律是
 * 「显式 SKIP 并声明本节未校验」（AGENTS §2），是否 SKIP 由调用方先 existsSync
 * 自行声明——本函数只负责遍历，不替调用方决定「缺失算不算通过」。
 *
 * @param {string} dir 起点目录（传文件路径等同空支）
 * @param {(name: string) => boolean} [accept] 文件名谓词；缺省收全部文件
 * @param {{ ignoreDir?: (name: string) => boolean }} [opts] 目录排除（如 target/node_modules）
 * @returns {string[]}
 */
export function walkFiles(dir, accept = null, opts = {}) {
  const ignoreDir = opts.ignoreDir ?? null;
  const out = [];
  const go = (d) => {
    let ents;
    try {
      ents = readdirSync(d, { withFileTypes: true });
    } catch {
      return; // 目录不存在/不可读 = 该支无文件（与历史各 walk 的容错口径一致）
    }
    for (const e of ents) {
      const p = join(d, e.name);
      if (e.isDirectory()) {
        if (!ignoreDir || !ignoreDir(e.name)) go(p);
      } else if (e.isFile() && (!accept || accept(e.name))) {
        out.push(p);
      }
    }
  };
  go(dir);
  return out;
}

/** 递归收集 .rs 文件（绝对路径）。命令面门禁的统一口径。 */
export const walkRs = (dir) => walkFiles(dir, (n) => n.endsWith('.rs'));

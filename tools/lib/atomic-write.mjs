'use strict';
// tools/lib/atomic-write.mjs —— 写库/生成器整文件落盘的单一实现（T1c-L06）
//
// 就地 writeFileSync 在崩溃/断电/磁盘满时会把跟踪文件留成截断的半个 JSON，
// 只能靠 git 恢复；而生成器与签名器写的是「下一跑会被当作权威输入」的文件。
// 做法与 Rust 侧 security::atomic_write 同语义：同目录临时件写满 → rename 覆盖。
// 同卷 rename 是原子的；失败时清掉临时件，目标文件保持旧字节。
import { renameSync, rmSync, writeFileSync } from 'node:fs';

/**
 * 原子写整文件。临时件与目标同目录（跨卷 rename 不是原子操作）。
 * @param {string} file 目标绝对路径
 * @param {string} text 完整内容
 * @param {BufferEncoding} [encoding]
 */
export function writeFileAtomic(file, text, encoding = 'utf8') {
  const tmp = `${file}.tmp-${process.pid}`;
  try {
    writeFileSync(tmp, text, encoding);
    renameSync(tmp, file);
  } catch (e) {
    try {
      rmSync(tmp, { force: true });
    } catch {
      /* 清理失败不掩盖原始错误 */
    }
    throw e;
  }
}

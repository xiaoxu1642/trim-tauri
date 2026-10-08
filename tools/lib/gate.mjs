'use strict';
// tools/lib/gate.mjs —— 门禁共享：判红计数 / 收尾退出 / 缺输入显式 SKIP
//
// 为什么单独成模块：抽取前各门禁长期并存三种判红写法（fail++ 计数 / fail(msg) helper /
// throw new Error），「缺文件即 SKIP」也曾各自实现（docs 测试框架报告 §3.5）。
// 抽这层把两条固定纪律做成单点：
//   ① 找违规型判定累计计数、结尾一次性退出码（中途 throw 会让首个红后面的断言全部不跑）；
//   ② 读未跟踪/可能缺失的输入前先判存在，缺失时显式 SKIP 并声明「本节未校验」——
//      不 ENOENT 崩整轮，也不打 ✓ 冒充通过（AGENTS §2，check-gate-roster 先例）。
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { basename } from 'node:path';

/**
 * 创建一条门禁的判红/收尾器。
 *
 * @param {string|URL} self 本门禁标识（传 import.meta.url 即可，自动取文件名）
 */
export function gate(self) {
  const name = basename(typeof self === 'string' && self.endsWith('.mjs') ? self : fileURLToPath(self));
  let failed = 0;
  const fail = (msg) => {
    failed++;
    console.error(`✗ ${msg}`);
  };
  const ok = (msg) => console.log(`✓ ${msg}`);
  const warn = (msg) => console.warn(`⚠ ${msg}`);

  /**
   * 缺失输入守卫：文件/目录存在返回 true；不存在打印显式 SKIP 声明并返回 false。
   * 典型用法：`if (!skipUnlessPresent(AGENTS, 'AGENTS.md（未跟踪）')) return;`
   *
   * @param {string} file 待读路径
   * @param {string} label SKIP 文案里的名称（含「为什么会缺」的说明）
   */
  const skipUnlessPresent = (file, label) => {
    if (existsSync(file)) return true;
    console.warn(
      `⚠ ${label} 不在本机：对应校验**未执行**（SKIP，不是通过；文件齐全时才会判红/判绿）`,
    );
    return false;
  };

  /**
   * 收尾：有判红则汇总条数并退出码 1；全绿时打印成功语（可选）。
   * @param {string} [successMsg]
   */
  const finish = (successMsg) => {
    if (failed > 0) {
      console.error(`${name}: ${failed} 处不一致`);
      process.exit(1);
    }
    if (successMsg) console.log(successMsg);
  };

  return { fail, ok, warn, skipUnlessPresent, finish, get failed() { return failed; } };
}

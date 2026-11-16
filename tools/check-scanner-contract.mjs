#!/usr/bin/env node
// check-scanner-contract.mjs —— 扫描器公共契约门禁（架构优化 P3，2026-11-17）
//
// 为什么需要这层包装：`native-scanner/` 是主仓 path 依赖、**非 workspace 成员**
// （src-tauri/Cargo.toml 注释），主仓 `cd src-tauri && cargo test` 跑不到它自带的
// `tests/`。扫描器公共行为（重复分组 / 空文件时效闸 / 年龄护栏 / 回收站原语）的
// 主仓可执行契约落在 `src-tauri/tests/scanner_contract.rs`（trim_finder 公共 API 直调）；
// 用例会随 `cargo test` 一起跑，但「随跑」不等于「有人跑」——不挂门禁就是
// `check-scan-rule-diff` 头注释点名的「用例写完没人跑就是死门禁」。挂进 Node 门禁
// 清单后，它与 check-scan-rule-diff 同一入口、同一退出码语义。
//
// 它与 check-scan-rule-diff 的分工：那条门禁跑 native-scanner 自带 tests/ 的规则差分
// （CRS 语料命中集），这条门禁跑主仓侧的公共 API 契约（四类用例，见测试文件头注释）。
// 两边都不跑，扫描器的行为面就只剩 src/ 单测。
//
// 本门禁只读：用例样本全部建在测试自带的自删守卫沙箱（仓库 target 下，不进 %TEMP%），
// 回收站用例只测不存在路径的 fail-closed 形态，不真删任何文件、不动真实回收站。
//
// 用法：node tools/check-scanner-contract.mjs

import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SRC_TAURI = join(ROOT, 'src-tauri');
const CONTRACT = join(SRC_TAURI, 'tests', 'scanner_contract.rs');

// 下限 = 四类契约各至少一条（重复/空文件/年龄护栏/回收站）。现算不写死具体条数：
// 注释里的数字与实际漂移时没有任何东西会红（L-31 的教训），数量只打在输出里。
const MIN_TESTS = 4;

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== 扫描器公共契约门禁 ===\n');

// 0. 契约用例点名在位。cargo test --test scanner_contract 的目标名来自文件名：
// 文件被删/改名时 cargo 直接报错（判红），但条数塌缩到 < 4 时 cargo 照样绿——
// 四类契约被裁掉三类后门禁仍显示通过，正是这条要堵的「静默摘网」。
let cnt = 0;
let readable = false;
try {
  const t = readFileSync(CONTRACT, 'utf8');
  readable = true;
  cnt = (t.match(/^[ \t]*#\[test\][ \t]*$/gm) || []).length;
} catch {
  readable = false;
}
check(
  readable && cnt >= MIN_TESTS,
  `0. 契约用例点名在位（tests/scanner_contract.rs：${readable ? `${cnt} 条 #[test]` : '文件不存在/不可读'}）`,
  !readable
    ? '契约用例文件缺失——本门禁此刻守不住任何扫描器公共行为，判红'
    : cnt < MIN_TESTS
      ? `只有 ${cnt} 条 #[test]（< ${MIN_TESTS}）：四类契约（重复/空文件/年龄护栏/回收站）至少一类被裁剪或挪走`
      : '',
);

// 1. cargo 判据。10 分钟而不是 check-scan-rule-diff 的 5 分钟：集成测试要链接整个
// trim_tauri_lib（tauri 依赖面），冷缓存下比 native-scanner 全 crate 重得多。
// check-gate-roster --run 的单条 5 分钟上限意味着走验收序列时缓存已被前面的
// cargo check/test 烤热；冷缓存单独跑本门禁请先手动跑一次构建。
const CARGO_TIMEOUT_MS = 10 * 60 * 1000;
const r = spawnSync('cargo', ['test', '--test', 'scanner_contract'], {
  cwd: SRC_TAURI,
  stdio: 'inherit',
  timeout: CARGO_TIMEOUT_MS,
});

// cargo 判定是显式三元组，判据只有一条 —— `!r.error && r.status === 0`（照
// check-scan-rule-diff 的 P0-08 口径）：「被信号杀死」（status=null）与「非零退出码」
// 不许混成同一句「退出码 null」；超时（spawnSync 置 error.code=ETIMEDOUT）也不许被
// 读成「跑不起来」。三种失败形态统一判红，并把 status/signal/error 全打出来。
const CARGO = {
  status: r.status,
  signal: r.signal ?? null,
  error: r.error ? { code: r.error.code ?? null, message: r.error.message } : null,
};
const CARGO_OK = !CARGO.error && CARGO.status === 0;
const CARGO_OUTCOME =
  `status=${CARGO.status === null ? 'null' : CARGO.status} ` +
  `signal=${CARGO.signal ?? 'none'} ` +
  `error=${CARGO.error ? `${CARGO.error.code ?? 'ERR'}: ${CARGO.error.message}` : 'none'}`;
const CARGO_WHY = (() => {
  if (CARGO.error) {
    return CARGO.error.code === 'ETIMEDOUT'
      ? `cargo test 超时（${Math.round(CARGO_TIMEOUT_MS / 60000)} 分钟上限内没跑完；冷缓存先手动烤一次构建再跑）`
      : 'cargo test 跑不起来（fail-closed：跑不起来不等于没发现问题）';
  }
  if (CARGO.signal) return `cargo test 被信号 ${CARGO.signal} 终止`;
  return 'cargo test 退出码非零 —— 扫描器公共行为契约被改，或用例断言需要同步';
})();
check(
  CARGO_OK,
  '1. 公共契约用例通过（cargo test --test scanner_contract；判据 = !error && status === 0）',
  CARGO_OK ? '' : `${CARGO_WHY}｜${CARGO_OUTCOME}`,
);
console.log(`  cargo test 结局三元组：${CARGO_OUTCOME}`);
if (!CARGO_OK) {
  console.error('  ↳ 若是有意改扫描器公共行为：先确认用例断言该不该同步改，再核对本门禁登记');
}

console.log('');
if (fail > 0) {
  console.error(`扫描器公共契约门禁失败 ${fail} 项。`);
  process.exit(1);
}
console.log('✓ 扫描器公共契约门禁通过');

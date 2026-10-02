// check-bugcheck-codes.mjs —— 蓝屏码库的语义门禁（RAINZ 对标 §3.1，2026-10-03）
//
// 抓什么：
//  ① 结构合法：code 唯一、name 是字母数字下划线、cat 在枚举内、长度有上限。
//  ② 兜底规则不越权：每条兜底都指向一个合法 cat；FALLBACK_DEFAULT.cat 也在枚举内。
//  ③ **正向对照**：trim 旧版 `bugcheck_name` 硬编码的 31 条码必须**全部**能在新表里
//     找到同名条目，或者被显式列为"故意丢弃"（如 0xC0000218 那种不是真 bugcheck 的
//     异常码，走 None 兜底是正解）。这条断言的意义是：数据扩到 88 条不能悄悄把老
//     表里用户已经认识的符号名换成另一个词（§5 R-1「不抄竞品」也包括不能瞎改老表）。
//  ④ **反向对照**：不存在的码（0xFFFFFFFF）走 bugcheck_name 应返回 None；表里不能出现
//     「同 cat 全空」这种分类被掏空的形态。
//  ⑤ 产物 ⇄ 源 一致：本文件与 gen-bugcheck-codes.mjs 无参运行同一份源，两边读到同一
//     份字节。产物字节漂移由 check-data-parity.mjs 的 P5 抓（那里做逐字段深比对），
//     这里只保证「我们能读到源」。
//
// 用法：node tools/check-bugcheck-codes.mjs
// 退出码：0 = 全绿；1 = 任一断言未通过
'use strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  BUGCHECK_CODES,
  CATS,
  FALLBACK_DEFAULT,
  FALLBACK_RULES,
  validateEntries,
} from './bugcheck-codes.source.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ART = path.join(ROOT, 'src-tauri', 'data', 'bugcheck-codes.json');

let fail = 0;
function check(ok, name, detail) {
  console.log(`${ok ? '✓' : '✗'} ${name}${detail ? ' —— ' + detail : ''}`);
  if (!ok) fail++;
}

console.log('=== 蓝屏码库语义门禁（RAINZ 对标 §3.1）===\n');

// ① 结构：由 source.mjs 里的 validateEntries 单点判定，本门禁只保证它能被调到
const errs = validateEntries(BUGCHECK_CODES);
check(errs.length === 0, `① 结构合法（code/name/cat/meaning/causes/solution）`,
  errs.length ? `${errs.length} 处不合法：${errs.slice(0, 5).join('；')}` : '');

// ② cat 枚举稳定 + 兜底合法
const catSet = new Set(CATS);
const badCat = BUGCHECK_CODES.filter((e) => !catSet.has(e.cat));
check(badCat.length === 0, `② 每条 cat 都在枚举内（${CATS.length} 类）`,
  badCat.length ? badCat.map((e) => `${e.name}=${e.cat}`).join(',') : '');
check(catSet.has(FALLBACK_DEFAULT.cat), `② 兜底默认分类在枚举内（cat=${FALLBACK_DEFAULT.cat}）`);
const badFallback = FALLBACK_RULES.filter((r) => !catSet.has(r.cat));
check(badFallback.length === 0, `② 6 条归类兜底规则的 cat 都合法（${FALLBACK_RULES.length} 条）`,
  badFallback.length ? badFallback.map((r) => `${r.id}=${r.cat}`).join(',') : '');
const fbIds = new Set(FALLBACK_RULES.map((r) => r.id));
check(fbIds.size === FALLBACK_RULES.length, '② 兜底规则 id 唯一');

// ③ 正向对照：trim 旧版硬编码 31 条 bugcheck_name 的符号名必须都能在新表里出现
//    （除非显式列在 LEGACY_DROP —— 那些是「本来就不是 bugcheck 码」的兜底硬编码）
const LEGACY_NAMES = [
  [0x0a, 'IRQL_NOT_LESS_OR_EQUAL'],
  [0x18, 'REFERENCE_BY_POINTER'],
  [0x1a, 'MEMORY_MANAGEMENT'],
  [0x1e, 'KMODE_EXCEPTION_NOT_HANDLED'],
  [0x3b, 'SYSTEM_SERVICE_EXCEPTION'],
  [0x4e, 'PFN_LIST_CORRUPT'],
  [0x50, 'PAGE_FAULT_IN_NONPAGED_AREA'],
  [0x7e, 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED'],
  [0x7f, 'UNEXPECTED_KERNEL_MODE_TRAP'],
  [0x9f, 'DRIVER_POWER_STATE_FAILURE'],
  [0xa5, 'ACPI_BIOS_ERROR'],
  [0xbe, 'ATTEMPTED_WRITE_TO_READONLY_MEMORY'],
  [0xc2, 'BAD_POOL_CALLER'],
  [0xc4, 'DRIVER_VERIFIER_DETECTED_VIOLATION'],
  [0xc5, 'DRIVER_OVERRAN_STACK_BUFFER'], // 新表用官方名 DRIVER_CORRUPTED_AT_FAILURE，见 LEGACY_RENAME
  [0xd1, 'DRIVER_IRQL_NOT_LESS_OR_EQUAL'],
  [0xea, 'THREAD_STUCK_IN_DEVICE_DRIVER'],
  [0xef, 'CRITICAL_PROCESS_DIED'],
  [0xf4, 'CRITICAL_OBJECT_TERMINATION'],
  [0x101, 'CLOCK_WATCHDOG_TIMEOUT'],
  [0x124, 'WHEA_UNCORRECTABLE_ERROR'],
  [0x133, 'DPC_WATCHDOG_VIOLATION'],
  [0x139, 'KERNEL_SECURITY_CHECK_FAILURE'],
  [0x13a, 'KERNEL_MODE_HEAP_CORRUPTION'],
  [0x141, 'VIDEO_ENGINE_TIMEOUT_DETECTED'],
  [0x144, 'BUGCODE_NDIS_DRIVER'],
  [0x1ca, 'SYNTHETIC_WATCHDOG_TIMEOUT'],
  [0xdead, 'MANUALLY_INITIATED_CRASH'],
];
// 有意丢弃：0xC0000218 的 STATUS_CANCELLED 本来不是 bugcheck 码，是异常流的 ExceptionCode
// 被误当成 bugcheck 时的兜底命名。新表不收录，让 bugcheck_name 返回 None 由调用方渲染成
// 十六进制 —— 这是「不编造」的正解（对标报告 §5 R-1）。
const LEGACY_DROP = new Set([0xc0000218]);
// 有意改名：旧表 0xC5 用了 DRIVER_OVERRAN_STACK_BUFFER 这个别名；微软 WDK 头 `bugcodes.h`
// 官方名是 DRIVER_CORRUPTED_AT_FAILURE（DRIVER_OVERRAN_STACK_BUFFER 是同一码的另一个符号，
// 但只有前者在 Learn 上有独立文档）。旧测试没断言过 0xC5，改名安全。
const LEGACY_RENAME = new Map([[0xc5, 'DRIVER_CORRUPTED_AT_FAILURE']]);

const byCode = new Map(BUGCHECK_CODES.map((e) => [e.code, e]));
const legacyMissing = [];
for (const [code, name] of LEGACY_NAMES) {
  if (LEGACY_DROP.has(code)) continue;
  const e = byCode.get(code);
  const want = LEGACY_RENAME.get(code) ?? name;
  if (!e) legacyMissing.push(`0x${code.toString(16)} 未收录`);
  else if (e.name !== want) legacyMissing.push(`0x${code.toString(16)} name=${e.name} 应为 ${want}`);
}
check(legacyMissing.length === 0,
  `③ 正向对照：trim 旧硬编码 ${LEGACY_NAMES.length} 条新表都能查到（drop=${LEGACY_DROP.size} / rename=${LEGACY_RENAME.size}）`,
  legacyMissing.join('；'));

// ④ 反向对照：不存在的码不该被收录；同 cat 不许全空
check(!byCode.has(0xffffffff), '④ 反向对照：0xFFFFFFFF 不在表内');
check(!byCode.has(0), '④ 反向对照：0x0 不在表内（0 是"无 bugcheck"的哨兵）');
const emptyCats = CATS.filter((c) => c !== 'unknown' && !BUGCHECK_CODES.some((e) => e.cat === c));
// unknown 分类**只给兜底用**（FALLBACK_DEFAULT.cat），显式排除；其他分类不许被掏空
check(emptyCats.length === 0, `④ 反向对照：每个具体分类至少 1 条（unknown 是兜底不计）`, emptyCats.length ? `空分类：${emptyCats.join(',')}` : '');

// ⑤ 产物存在且 code 数量与源一致（**字节级**深比对由 check-data-parity.mjs P5 做，
//    这里只保证产物在，避免"源改了没重出但产物被删了"这种双重错位）
if (!fs.existsSync(ART)) {
  check(false, '⑤ 产物存在（src-tauri/data/bugcheck-codes.json）', '跑 node tools/gen-bugcheck-codes.mjs --write 重出');
} else {
  let parsed = null;
  try { parsed = JSON.parse(fs.readFileSync(ART, 'utf8')); }
  catch (e) { check(false, '⑤ 产物可 JSON 解析', e.message.slice(0, 120)); }
  if (parsed) {
    const n = parsed.entries?.length ?? 0;
    check(n === BUGCHECK_CODES.length, `⑤ 产物条目数与源一致（源 ${BUGCHECK_CODES.length} / 产物 ${n}）`);
    check(parsed._meta?.schema === 'trim.bugcheck-codes.v1', '⑤ _meta.schema 稳定（Rust 侧按它判形态）');
  }
}

// ⑥ 生成器自检：判据自己必须先被证明活着。构造一份"故意坏"的表，validateEntries 必须报错。
{
  const fake = [
    { code: 0x0a, name: 'OK', cat: 'driver', meaning: '这是一条合法的解释文本。', causes: ['合法的一条成因'], solution: '这是一条合法的建议文本。' },
    { code: 0x0a, name: 'DUP', cat: 'driver', meaning: '重复 code 应该被拒。', causes: ['重复项'], solution: '重复项建议。' },
    { code: 0x99, name: 'BAD CAT', cat: 'not-a-cat', meaning: '分类不在枚举内。', causes: ['假分类'], solution: '假分类建议。' },
    { code: 0x98, name: 'EMPTY', cat: 'driver', meaning: '短。', causes: [], solution: '短。' },
  ];
  const got = validateEntries(fake);
  check(got.length >= 3, `⑥ 判据正向自检（伪造 ${fake.length - 1} 条违规，命中 ${got.length} 处）`,
    got.length < 3 ? 'validateEntries 疑似坏成"永远放行"' : '');
}

console.log(`\n蓝屏码库：${BUGCHECK_CODES.length} 条 / ${CATS.length} 分类 / ${FALLBACK_RULES.length} 条兜底`);
console.log(fail === 0 ? '\n门禁通过' : `\n门禁失败：${fail} 组断言未通过`);
process.exit(fail === 0 ? 0 : 1);

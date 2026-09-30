// rule-schema.mjs —— 规则库契约表的 Node 侧读取器（V2 P0-A2，2026-09-30）
//
// 真源是 `tools/rule-schema.json`，同一份字节也被 Rust 装载侧编译期嵌入
// （`src-tauri/src/engine/rule_schema.rs`）。之所以两份消费者读同一个文件而不是
// 各自抄一遍清单：本仓已经因为「更新侧与装载侧各写一套字段规则」出过事故
// （AGENTS §5.16 / N6，残留库向导因此把判定完全交给门禁）。
//
// 本模块**只提供词汇与数值**（字段白名单 / 枚举 / 上限 / token 登记集）。
// 判定逻辑一律留在调用方：注册表禁删面、target 形态、residue 三条件组≥2、
// excludePaths 的 `::` 约束 —— 把它们塞进数据文件等于造通用规则引擎，
// 82 条库的规模不需要（AGENTS §2 零新增依赖）。
//
// 两域的同名条目**刻意不同值**（token 集、大小写口径、字段面都不一样）：
// 这里不提供任何"取交集/并集/合并"的便捷函数，防止造出假一致。
'use strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
export const SCHEMA_FILE = path.join(ROOT, 'tools', 'rule-schema.json');

let cached = null;

/** 读契约表（进程内缓存一次；解析失败直接抛，不静默返回空表 —— 空表会让门禁全绿） */
export function loadSchema() {
  if (cached) return cached;
  const text = fs.readFileSync(SCHEMA_FILE, 'utf8');
  const obj = JSON.parse(text);
  for (const dom of ['cleanup', 'residue']) {
    if (!obj[dom] || typeof obj[dom] !== 'object') {
      throw new Error(`契约表缺 ${dom} 段（tools/rule-schema.json）`);
    }
  }
  cached = obj;
  return obj;
}

/** 域内字符串数组：缺失或为空即抛 —— 静默给空数组等于把白名单关掉 */
export function list(domain, key) {
  const v = loadSchema()[domain][key];
  if (!Array.isArray(v) || v.length === 0) {
    throw new Error(`契约表 ${domain}.${key} 缺失或为空`);
  }
  if (v.some((x) => typeof x !== 'string')) {
    throw new Error(`契约表 ${domain}.${key} 含非字符串项`);
  }
  return v;
}

/** 数值：先 limits.<key> 再域顶层 <key>；缺失或为 0 即抛（0 上限会让所有包被拒或全放行） */
export function number(domain, key) {
  const d = loadSchema()[domain];
  const v = d?.limits?.[key] ?? d?.[key];
  if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0) {
    throw new Error(`契约表 ${domain}.${key} 缺失或非正数`);
  }
  return v;
}

/** token 登记集 + 大小写口径（两域不同值，调用方各取自己那份） */
export function tokens(domain) {
  const t = loadSchema()[domain].tokens;
  if (!t || !Array.isArray(t.allowed) || typeof t.caseInsensitive !== 'boolean') {
    throw new Error(`契约表 ${domain}.tokens 形态异常`);
  }
  return { allowed: t.allowed, caseInsensitive: t.caseInsensitive };
}

/** crossTrack 登记表（V2 P2-D7 实测不等价点）；缺失即抛，不静默当空表 */
export function crossTrack(key) {
  const v = loadSchema().crossTrack?.[key];
  if (v === undefined || v === null) throw new Error(`契约表缺 crossTrack.${key}`);
  return v;
}

/** 供门禁做"表没被合并成一份等价清单"的反向断言 */
export function schemaVersion() {
  const v = loadSchema().schemaVersion;
  if (typeof v !== 'number') throw new Error('契约表缺 schemaVersion');
  return v;
}

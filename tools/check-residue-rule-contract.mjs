#!/usr/bin/env node
// check-residue-rule-contract.mjs — 卸载残留规则库契约门禁（U-1，2026-09-28；A1/A2 收口 2026-09-28）
//
// 对 src-tauri/data/uninstall-residue-rules.json 做四层断言：
//   A. 根结构：rulesVersion（≥ 20260928 棘轮，只升不降）/ prov / rules 数组
//   B. 规则条目：id 唯一非空且字符集受限；displayName / publisher / uninstallKey 三条件组
//      **至少两组非空**（与 Rust 侧 residue_rules_hits 的「双条件命中」拍板口径对齐，单侧维护即红）
//   C. residue 条目：kind ∈ {folder, file, reg_key, reg_value, shortcut}（Q8 于 2026-10-06
//      重拍放开后两类：执行侧早已支持、无新删除面；边界：reg_value 删值+整父键 export 兜底，
//      shortcut 走回收站）；
//      target 过文件形状与**注册表硬否决**判定；note 非空（面板 reason 要展示）；未知字段整包拒
//   D. 签名：Ed25519 验签通过（与 sign-cleanup-rules.mjs 同密钥同规范化）
//   E. 内置副本接线：commands/uninstall/ 目录（装载侧在 residue_update.rs）必须 include_str! 本文件
//      （E4-E6 更新链接线断言已随在线更新链退役 —— 2026-10-06 用户裁定：规则只随包体更新）
//   F. 夹具对拍（A1/A2）：tools/fixtures/residue-contract.json 的 regVectors 与 packages
//      两侧各自独立实现同一套判定 —— 本文件**不调用** Rust，靠夹具钉口径（方案 §4.3 第三步）。
//      任一侧口径漂移，夹具立刻判红；新增保护类别必须同时补夹具反例。
//
// 用法：node tools/check-residue-rule-contract.mjs            （全套门禁）
//       node tools/check-residue-rule-contract.mjs --preview x.json （A8 候选包干跑）
'use strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const RULES = path.join(ROOT, 'src-tauri', 'data', 'uninstall-residue-rules.json');
// v3 D2：卸载域按命令契约拆成 commands/uninstall/ 目录，装载/校验/更新链集中在
// residue_update.rs。这里读整目录而不是单文件——坐标再搬家时断言仍然有效，
// 不会退化成「文件不在了就跳过」的假绿。
const UNINSTALL_DIR = path.join(ROOT, 'src-tauri', 'src', 'commands', 'uninstall');
import { leadingToken, makeTokenChecker } from './rule-tokens.mjs';
import { list as schemaList, number as schemaNumber, tokens as schemaTokens } from './rule-schema.mjs';
const FIXTURE = path.join(ROOT, 'tools', 'fixtures', 'residue-contract.json');
// 词汇与上限取自 `tools/rule-schema.json`（V2 P0-A2，2026-09-30）：同一份字节也被 Rust 装载侧
// 编译期嵌入（engine/rule_schema.rs），本文件不再抄第二份清单 —— 抄了就会出现"改了表没改门禁"
// 或反过来的分叉（本仓 A7/N6 记过同源化的边界：只共享查法与报错，**不共享允许集**）。
const { allowed: RESIDUE_RULE_TOKENS, caseInsensitive: TOKEN_CI } = schemaTokens('residue');
if (!TOKEN_CI) {
  console.error('✗ 契约表 residue.tokens.caseInsensitive 必须是 true（大小写口径要改得单独拍板）');
  process.exit(1);
}
// token 判定器（大小写不敏感，保持既有行为）
const checkToken = makeTokenChecker(RESIDUE_RULE_TOKENS, { caseInsensitive: true });

const MIN_VERSION = schemaNumber('residue', 'versionRatchetMin');
const ALLOWED_KINDS = schemaList('residue', 'ruleKinds');
const TOP_FIELDS = schemaList('residue', 'topFields');
const PROV_FIELDS = schemaList('residue', 'provFields');
const RULE_FIELDS = schemaList('residue', 'ruleFields');
const ENTRY_FIELDS = schemaList('residue', 'entryFields');
const MATCH_GROUPS = schemaList('residue', 'matchGroups');
const MIN_MATCH_GROUPS = schemaNumber('residue', 'matchGroupsMinNonEmpty');
const MAX_RULES = schemaNumber('residue', 'maxRules');
const MAX_RESIDUE = schemaNumber('residue', 'maxResiduePerRule');
const MAX_GROUP_ITEMS = schemaNumber('residue', 'maxGroupItems');
const MAX_TARGET_LEN = schemaNumber('residue', 'maxTargetLen'); // MAX_PATH
const MAX_TEXT_LEN = schemaNumber('residue', 'maxTextLen');
const MAX_SEGMENTS = schemaNumber('residue', 'maxSegments');

// ==================== 注册表禁删面（与 engine/protect.rs 同口径的独立实现） ====================

const REG_SUBTREE_DENY = [
  'HKLM\\SYSTEM', 'HKLM\\SAM', 'HKLM\\SECURITY', 'HKLM\\BCD00000000',
  'HKLM\\COMPONENTS', 'HKLM\\DRIVERS', 'HKLM\\HARDWARE',
  'HKLM\\SOFTWARE\\CLASSES', 'HKCU\\SOFTWARE\\CLASSES',
  'HKLM\\SOFTWARE\\POLICIES', 'HKCU\\SOFTWARE\\POLICIES', 'HKLM\\SOFTWARE\\WOW6432NODE\\POLICIES',
  'HKLM\\SOFTWARE\\CLIENTS', 'HKCU\\SOFTWARE\\CLIENTS', 'HKLM\\SOFTWARE\\REGISTEREDAPPLICATIONS',
  'HKLM\\SOFTWARE\\ODBC', 'HKLM\\SOFTWARE\\KHRONOS', 'HKLM\\SOFTWARE\\OPENGL',
  'HKCU\\ENVIRONMENT', 'HKCU\\NETWORK', 'HKCU\\VOLATILE ENVIRONMENT',
];
const REG_MICROSOFT_ROOTS = [
  'HKLM\\SOFTWARE\\MICROSOFT',
  'HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT',
  'HKCU\\SOFTWARE\\MICROSOFT',
];
const REG_MICROSOFT_LEAF_ALLOW = [
  'HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\UNINSTALL',
  'HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\UNINSTALL',
  'HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\UNINSTALL',
  'HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\APP PATHS',
  'HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\APP PATHS',
  'HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\APP PATHS',
  'HKLM\\SOFTWARE\\MICROSOFT\\TRACING',
  'HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\TRACING',
];
const REG_CONTAINER_DENY = ['HKLM\\SOFTWARE', 'HKLM\\SOFTWARE\\WOW6432NODE', 'HKCU\\SOFTWARE'];
const REG_GENERIC_LEAF = [
  'SOFTWARE', 'CLASSES', 'MICROSOFT', 'WINDOWS', 'WINDOWSNT', 'CURRENTVERSION', 'UNINSTALL',
  'WOW6432NODE', 'POLICIES', 'RUN', 'RUNONCE', 'RUNONCEEX', 'RUNSERVICES', 'INSTALLER',
  'SHELL', 'EXPLORER', 'SHELLEXTENSIONS', 'CONTEXTMENUHANDLERS', 'BROWSERHELPEROBJECTS',
  'FILEEXTS', 'AUTOPLAYHANDLERS', 'MOUNTPOINTS2', 'USERASSOCIATIONS', 'WINLOGON', 'TRACING',
  'FONTS', 'FONTLINKS', 'FONTSUBSTITUTES', 'PROFILELIST', 'SHAREDLLS',
  'IMAGEFILEEXECUTIONOPTIONS', 'APPCOMPATFLAGS', 'CLIENTS', 'REGISTEREDAPPLICATIONS',
  'ENVIRONMENT', 'NETWORK', 'SHELLFOLDERS', 'USERSHELLFOLDERS', 'MUICACHE',
  'LOCALSETTINGS', 'APPPATHS',
];

/** 归一化注册表目标 → { hive, canon, segs } 或 null（判不出来 = 调用方按拒绝处理） */
function normalizeRegTarget(target) {
  const t = String(target ?? '').trim();
  if (!t || /[\0\r\n]/.test(t)) return null;
  const segs = t.replace(/\//g, '\\').split('\\').map((s) => s.trim().toUpperCase());
  if (segs.some((s) => !s || s === '.' || s === '..')) return null;
  const first = segs[0];
  const hive =
    first === 'HKLM' || first === 'HKEY_LOCAL_MACHINE' ? 'HKLM'
      : first === 'HKCU' || first === 'HKEY_CURRENT_USER' ? 'HKCU'
        : null;
  if (!hive) return null;
  const rest = segs.slice(1);
  return { hive, segs: rest, canon: rest.length ? `${hive}\\${rest.join('\\')}` : hive };
}

/** 返回拒绝原因字符串 = 禁删；返回 null = 放行。判定顺序与 protect.rs 逐条对齐。 */
function regTargetBlockReason(target) {
  const n = normalizeRegTarget(target);
  if (!n) return '注册表目标无法判定（hive 只支持 HKLM/HKCU，且不允许空段或 . / ..）';
  if (!n.segs.length) return '注册表根单元（hive）整体禁止删除';
  const { canon } = n;
  const under = (root) => canon === root || canon.startsWith(root + '\\');
  for (const root of REG_SUBTREE_DENY) {
    if (under(root)) return `${canon} 位于系统级注册表单元 ${root} 之下（整棵禁删）`;
  }
  const mroot = REG_MICROSOFT_ROOTS.find((m) => under(m));
  if (mroot && !REG_MICROSOFT_LEAF_ALLOW.some((a) => canon.startsWith(a + '\\'))) {
    return `${canon} 落在 ${mroot} 系统命名空间内（该树默认整棵禁删，只有 Uninstall / App Paths / Tracing 下的产品键放行）`;
  }
  for (const deny of [...REG_SUBTREE_DENY, ...REG_CONTAINER_DENY]) {
    if (canon === deny) return `${canon} 本身是系统级容器键，不得整棵删除`;
    if (deny.startsWith(canon + '\\')) return `${canon} 是受保护容器 ${deny} 的祖先，删除会端掉整个容器`;
  }
  const leaf = String(n.segs[n.segs.length - 1]).replace(/ /g, '');
  if (REG_GENERIC_LEAF.includes(leaf)) {
    return `${canon} 的末段「${n.segs[n.segs.length - 1]}」是 Windows 命名空间，不是某个产品的专属键`;
  }
  return null;
}

// ==================== R-2 启动项删值窄口子（与 run_keys::reg_value_gate 同口径的独立实现） ====================
//
// 这是本仓第二处「A1 让路」（第一处是服务键窄口子），而且它开的是**系统命名空间**
// （`…\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`）的删除面。方案 §2.3 R-2 明确要求
// 「Rust 判定与 Node 门禁读同一份夹具字节」——所以两侧刻意各写一份实现，谁也不调谁，
// 靠 `tools/fixtures/residue-contract.json` 的 `runValueVectors` 钉住。
// Rust 侧真源：`src-tauri/src/commands/uninstall/run_keys.rs::reg_value_gate`。
// 任一侧放宽（尤其把「Microsoft 树内、但不是那六条根」从拒绝改成放行）F5 立刻红。
const RUN_VALUE_ROOTS = [
  'HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN',
  'HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCE',
  'HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN',
  'HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCE',
  'HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN',
  'HKCU\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCE',
];

/** 三态：'allowed' | 'denied' | 'not-governed'（语义见 run_keys.rs 的 RegValueGate） */
function runValueGate(target) {
  const t = String(target ?? '');
  const at = t.lastIndexOf('::');
  if (at < 0) return 'not-governed'; // 不是「键::值名」形态 ⇒ 不在管辖内
  const keyPart = t.slice(0, at);
  const valueName = t.slice(at + 2);
  const n = normalizeRegTarget(keyPart);
  if (!n) return 'denied'; // 父键归一化失败 ⇒ fail-closed
  const parent = n.canon;
  const inMsTree = REG_MICROSOFT_ROOTS.some((m) => parent === m || parent.startsWith(m + '\\'));
  if (!RUN_VALUE_ROOTS.includes(parent)) return inMsTree ? 'denied' : 'not-governed';
  if (!valueName || valueName !== valueName.trim()) return 'denied';
  if (valueName === '*') return 'denied';
  if (valueName.includes('\\') || valueName.includes('::')) return 'denied';
  if (/[\u0000-\u001f\u007f]/.test(valueName)) return 'denied';
  if ([...valueName].length > 260) return 'denied';
  return 'allowed';
}

// ==================== 规则包语义校验（与 uninstall.rs::validate_residue_package 同口径） ====================

function fileTargetProblem(target) {
  if ([...target].length > MAX_TARGET_LEN) return '目标长度超过 260（MAX_PATH）';
  if (target.includes('*') || target.includes('?')) return '目标含通配符（残留规则只允许精确路径）';
  // 形态与 token 查法走 rule-tokens.mjs；允许集合仍是本文件那份（与清理库刻意不同集、
  // 且这一侧大小写不敏感 —— 同源化不等于把两份清单合并）
  const lead = leadingToken(target);
  if (lead.error) return lead.error;
  let body;
  if (lead.token) {
    const why = checkToken(lead.token);
    if (why) return why;
    body = lead.body;
  } else {
    const driveAbs = /^[A-Za-z]:[\\/]./.test(target);
    const uncAbs = target.startsWith('\\\\') && target.replace(/^\\+/, '').includes('\\');
    if (!driveAbs && !uncAbs) return '既不是登记变量的子路径，也不是绝对路径';
    body = target;
  }
  const segs = body.split(/[\\/]/);
  if (segs.some((s) => !s || s === '.' || s === '..')) return '含空段、`.` 或 `..`（尾随分隔符同样命中）';
  if (segs.length > MAX_SEGMENTS) return `路径段数 ${segs.length} 超上限 ${MAX_SEGMENTS}`;
  return null;
}

function regTargetProblem(target) {
  if ([...target].length > MAX_TARGET_LEN) return '目标长度超过 260（MAX_PATH）';
  if (target.includes('*') || target.includes('?')) return '目标含通配符（残留规则只允许精确路径）';
  if (/[\0\r\n\t]/.test(target)) return '目标含控制字符';
  if (target.includes('::') || target.includes('%')) return '注册表目标不允许 `::值名` 或变量形态';
  if (regTargetBlockReason(target)) return regTargetBlockReason(target);
  const n = normalizeRegTarget(target);
  if (!n) return 'hive 只支持 HKCU / HKLM';
  if (n.segs.length > MAX_SEGMENTS) return `注册表深度 ${n.segs.length} 超上限 ${MAX_SEGMENTS}`;
  return null;
}

/** reg_value 目标 =「键路径::值名」（执行侧 residue.rs::classify_residue_op 按 rsplit_once("::") 拆）。
 *  硬否决判据**按键路径、不按值名**（§2.1 第 7 步）：先拆开，再对键路径部分走与 reg_key
 *  完全同一套判定 —— Run 等系统命名空间下的值照样进不来，kind 放开不放松否决面。 */
function regValueTargetProblem(target) {
  if ([...target].length > MAX_TARGET_LEN) return '目标长度超过 260（MAX_PATH）';
  if (target.includes('*') || target.includes('?')) return '目标含通配符（残留规则只允许精确路径）';
  if (/[\0\r\n\t]/.test(target)) return '目标含控制字符';
  if (target.includes('%')) return '注册表目标不允许变量形态';
  const parts = target.split('::');
  if (parts.length !== 2) return 'reg_value 目标必须是「键路径::值名」形态（恰好一个 :: 分隔）';
  const [keyPart, valueName] = parts;
  if (!keyPart.trim()) return 'reg_value 的键路径为空';
  if (!valueName.trim()) return 'reg_value 的值名为空';
  if (valueName !== valueName.trim()) return 'reg_value 值名首尾含空白';
  return regTargetProblem(keyPart);
}

/** shortcut 目标 = 文件形状 + 必须 .lnk 后缀（防拿快捷方式 kind 写任意路径）。 */
function shortcutTargetProblem(target) {
  const base = fileTargetProblem(target);
  if (base) return base;
  if (!/\.lnk$/i.test(target)) return 'shortcut 目标必须是 .lnk 快捷方式文件';
  return null;
}

/** 返回 null = 通过；返回字符串 = 整包拒绝原因 */
function validateResiduePackage(pkg) {
  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) return '规则包不是 JSON 对象';
  const unknownTop = Object.keys(pkg).find((k) => !TOP_FIELDS.includes(k));
  if (unknownTop) return `顶层 未知字段 ${unknownTop}`;
  if (typeof pkg.rulesVersion !== 'number' || !Number.isFinite(pkg.rulesVersion) || pkg.rulesVersion <= 0) {
    return 'rulesVersion 缺失、非数字或非正数';
  }
  if (!Array.isArray(pkg.prov) || !pkg.prov.length) return 'prov 缺失或为空（来源登记是审核链的一环）';
  for (const p of pkg.prov) {
    if (!p || typeof p !== 'object' || Array.isArray(p)) return 'prov 条目不是对象';
    const unk = Object.keys(p).find((k) => !PROV_FIELDS.includes(k));
    if (unk) return `prov 未知字段 ${unk}`;
    for (const f of PROV_FIELDS) {
      const v = p[f];
      if (typeof v !== 'string' || !v.trim() || [...v].length > MAX_TEXT_LEN) return `prov.${f} 缺失、非字符串或为空白`;
    }
  }
  if (!Array.isArray(pkg.rules) || !pkg.rules.length) return 'rules 缺失或为空数组';
  if (pkg.rules.length > MAX_RULES) return `规则条数 ${pkg.rules.length} 超上限 ${MAX_RULES}`;
  const seen = new Set();
  for (const rule of pkg.rules) {
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return '规则条目不是对象';
    const id = rule.id;
    if (typeof id !== 'string' || !id || [...id].length > MAX_TEXT_LEN || !/^[A-Za-z0-9._-]+$/.test(id)) {
      return '规则 id 缺失、为空或含非 [A-Za-z0-9._-] 字符';
    }
    if (seen.has(id)) return `规则 id 重复: ${id}`;
    seen.add(id);
    const unk = Object.keys(rule).find((k) => !RULE_FIELDS.includes(k));
    if (unk) return `规则 ${id}: 未知字段 ${unk}`;
    let groups = 0;
    for (const g of MATCH_GROUPS) {
      const arr = rule[g];
      if (arr === undefined) continue;
      if (!Array.isArray(arr)) return `规则 ${id}: ${g} 不是数组`;
      if (arr.length > MAX_GROUP_ITEMS) return `规则 ${id}: ${g} 条目数 ${arr.length} 超上限 ${MAX_GROUP_ITEMS}`;
      for (const s of arr) {
        if (typeof s !== 'string' || !s.trim() || [...s].length > MAX_TEXT_LEN) {
          return `规则 ${id}: ${g} 含空白或超长条目`;
        }
      }
      if (arr.length) groups += 1;
    }
    if (!('ver' in rule)) return `规则 ${id}: 缺条目级版本戳 ver（跑 node tools/stamp-rule-ver.mjs --write 后重签）`;
    if (typeof rule.ver !== 'number' || rule.ver !== pkg.rulesVersion) {
      return `规则 ${id}: ver=${JSON.stringify(rule.ver)} 与顶层 rulesVersion=${JSON.stringify(pkg.rulesVersion)} 不一致`;
    }
    if (groups < MIN_MATCH_GROUPS) return `规则 ${id}: 三条件组只有 ${groups} 组非空，双条件命中是 U-1 拍板口径（阈值取自契约表 matchGroupsMinNonEmpty）`;
    if (!Array.isArray(rule.residue) || !rule.residue.length) return `规则 ${id}: residue 缺失、不是数组或为空`;
    if (rule.residue.length > MAX_RESIDUE) {
      return `规则 ${id}: residue 条数 ${rule.residue.length} 超上限 ${MAX_RESIDUE}`;
    }
    for (const e of rule.residue) {
      if (!e || typeof e !== 'object' || Array.isArray(e)) return `规则 ${id}: residue 条目不是对象`;
      const unkE = Object.keys(e).find((k) => !ENTRY_FIELDS.includes(k));
      if (unkE) return `规则 ${id}: residue 未知字段 ${unkE}`;
      if (!ALLOWED_KINDS.includes(e.kind)) {
        return `规则 ${id}: 未知 kind ${String(e.kind)}（允许集 [${ALLOWED_KINDS.join(', ')}]）`;
      }
      if (typeof e.target !== 'string' || !e.target.trim() || e.target !== e.target.trim()) {
        return `规则 ${id}: residue.target 为空白或首尾含空白`;
      }
      const problem =
        e.kind === 'reg_key' ? regTargetProblem(e.target)
          : e.kind === 'reg_value' ? regValueTargetProblem(e.target)
            : e.kind === 'shortcut' ? shortcutTargetProblem(e.target)
              : fileTargetProblem(e.target);
      if (problem) return `规则 ${id}: ${e.kind} 目标 ${e.target} 不合规 — ${problem}`;
      if (typeof e.note !== 'string' || !e.note.trim() || [...e.note].length > MAX_TEXT_LEN) {
        return `规则 ${id}: residue.note 缺失或为空白（面板 reason 要展示）`;
      }
    }
  }
  return null;
}

// ==================== 断言执行 ====================

const argv = process.argv.slice(2);
const pvIdx = argv.indexOf('--preview');

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

// ---- A8 干跑预览：只回答「这条规则装上后会不会被装载侧拒」 ----
// 用法：node tools/check-residue-rule-contract.mjs --preview <候选json>
// 只做 validateResiduePackage 一件事（注册表禁删面在它内部）：不读真实规则库、不验签、不落盘。
// 不验签是有意的——私钥只在发布机，干跑阶段拿不到；而装载侧的真闸门就是同一个
// validateResiduePackage（与 Rust 侧同名同口径），过了它就等于过了运行期装载。
if (pvIdx >= 0) {
  const target = argv[pvIdx + 1];
  if (!target) {
    console.log('✗ --preview 需要候选 JSON 路径');
    process.exit(2);
  }
  let cand = null;
  try {
    cand = JSON.parse(fs.readFileSync(target, 'utf8'));
  } catch (e) {
    console.log(`✗ 候选文件读取或 JSON 解析失败: ${e.message}`);
    process.exit(1);
  }
  const pkgErr = validateResiduePackage(cand);
  if (pkgErr) {
    console.log(`✗ 语义校验未通过: ${pkgErr}`);
    process.exit(1);
  }
  const n = (Array.isArray(cand.rules) ? cand.rules : []).length;
  console.log(`✓ 候选包通过装载侧同口径校验（${n} 条规则，含注册表禁删面）`);
  console.log('干跑不验签、不落盘。合并进规则库后必须重签，否则验签断言与 Rust 装载都会判红:');
  console.log('  node tools/sign-cleanup-rules.mjs sign --file src-tauri/data/uninstall-residue-rules.json');
  process.exit(0);
}

console.log('=== 卸载残留规则库契约门禁 ===\n');

let raw = '';
let parsed = null;
try {
  raw = fs.readFileSync(RULES, 'utf8');
  parsed = JSON.parse(raw);
  check(true, '0. 规则文件可读且为合法 JSON');
} catch (e) {
  check(false, '0. 规则文件可读且为合法 JSON', e.message);
  console.log('\n存在未通过断言，门禁不通过');
  process.exit(1);
}

// ---- A. 根结构棘轮 ----
const ver = typeof parsed.rulesVersion === 'number' ? parsed.rulesVersion : 0;
check(ver >= MIN_VERSION, `A1. rulesVersion 棘轮 ≥ ${MIN_VERSION}（当前 ${ver}）`);

// ---- A2/A5/B/C. 整包语义校验（与 Rust 运行期同一套断言） ----
const pkgErr = validateResiduePackage(parsed);
check(pkgErr === null, 'A2. 整包语义校验通过（字段白名单 / kind / 匹配组 / 目标形状 / 上限）', pkgErr || '');

// ---- B1. 匹配组双条件（语义校验里也有，这里单独出账便于定位） ----
const rules = Array.isArray(parsed.rules) ? parsed.rules : [];
const badCond = rules.filter((r) => MATCH_GROUPS.filter((g) => Array.isArray(r?.[g]) && r[g].length > 0).length < 2);
check(badCond.length === 0, 'B1. 三条件组至少两组非空（双条件拍板口径）',
  badCond.length ? `不达标: ${badCond.map((r) => r.id).join(', ')}` : '');

// ---- B2. 落点条目数棘轮（只许增，不许悄悄抽空） ----
//
// 为什么 `gen-rule-coverage.mjs` 的覆盖棘轮不够：它记的是**规则 id 集合**，
// 不是每条规则的 `residue` 落点数。于是「把 residue-wechat 的 3 条落点全删掉、
// 规则 id 留着」在那一层是完全绿的 —— 而这正是 2026-10-04 实测到的腐坏形态：
// 微信 4.x 把落点从 `Tencent\WeChat` 改名成 `Tencent\Weixin`、数据目录改成
// `Tencent\xwechat`，旧规则**一条都命中不了**，但规则本身「看起来」完好无损。
// 删光落点比改错落点更难被发现（前者连一条 warn 日志都没有），所以单开一条棘轮。
//
// 基线 = 2026-10-06 HiBit 借鉴 v2 §2.2 扩容实测（78 条规则 / 209 条落点；此前 2026-10-04
// 基线为 12 规则 / 41 落点）。有意收缩请改这里的数字并在审核记录里写明为什么那批落点
// 不再需要（而不是顺手删掉）。
const RESIDUE_ENTRY_BASELINE = 209;
const entryCount = rules.reduce((n, r) => n + (Array.isArray(r.residue) ? r.residue.length : 0), 0);
check(entryCount >= RESIDUE_ENTRY_BASELINE, `B2. 落点条目数 ${entryCount} ≥ 基线 ${RESIDUE_ENTRY_BASELINE}`,
  entryCount < RESIDUE_ENTRY_BASELINE
    ? `落点被抽空 ${RESIDUE_ENTRY_BASELINE - entryCount} 条。规则 id 还在但落点没了 = 规则永远命中不到，\
且不会有任何运行期日志（比对条件组还过）。有意收缩请显式下调基线并写明原因。`
    : '');

// ---- C1. 现存合法规则必须继续放行（收紧不许把功能打死） ----
const LEGIT_REG_KEYS = [
  'HKLM\\SOFTWARE\\ESET', 'HKLM\\SOFTWARE\\360Safe', 'HKLM\\SOFTWARE\\Piriform',
  'HKCU\\Software\\360Safe', 'HKCU\\Software\\RoboForm',
  'HKCU\\Software\\Tencent\\WeChat', 'HKCU\\Software\\Tencent\\QQ',
];
const falseBlocked = LEGIT_REG_KEYS.filter((t) => regTargetBlockReason(t));
check(falseBlocked.length === 0, 'C1. 合法产品键放行回测', falseBlocked.length ? `被误拒: ${falseBlocked.join(', ')}` : '');
const inLibRegKeys = rules.flatMap((r) => (r.residue || []).filter((e) => e.kind === 'reg_key').map((e) => e.target));
// reg_value 的否决判据按键路径不按值名（§2.1 第 7 步）：入库面检查同样只取键路径部分
const inLibRegValues = rules.flatMap((r) =>
  (r.residue || []).filter((e) => e.kind === 'reg_value').map((e) => String(e.target).split('::')[0]));
const libBlocked = [...inLibRegKeys, ...inLibRegValues].filter((t) => regTargetBlockReason(t));
check(libBlocked.length === 0, 'C2. 当前库内 reg_key/reg_value 键路径全部通过保护判定',
  libBlocked.length ? `被拒: ${libBlocked.join(', ')}` : '');

// ---- D. 签名验签 ----
const body = {};
for (const [k, v] of Object.entries(parsed)) {
  if (k === '_sig') continue;
  body[k] = v;
}
const sigB64 = parsed._sig && parsed._sig.sig;
let sigOk = false;
let sigDetail = '';
if (!sigB64) {
  sigDetail = '缺少 _sig（先跑 node tools/sign-cleanup-rules.mjs sign --file src-tauri/data/uninstall-residue-rules.json）';
}
// 公钥验签（不依赖本机私钥）。0.6.6 密钥轮换后为**双钥**：legacy（历史签发钥）+ v2（轮换新钥），
// 任一通过即放行——清理 / 残留库存量内容仍是旧钥签名，只认新钥会把合法存量判红。
// 两把公钥与 src-tauri/src/engine/rules_signature.rs 的 RULES_PUBKEY_PEM / RULES_PUBKEY_V2_PEM 逐字一致；
// 轮换背景（2026-10-04 重装丢钥 + 双钥兼容）见该文件注释。
const PUBKEY_PEMS = {
  legacy: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAQehWbhuKKCxcWOje/8AZXYN192Z3Ryi8+cQ6ENwXAtY=\n-----END PUBLIC KEY-----',
  v2: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcfi1pq5dJY2x3/d+sDdLmj1N6eGIqOmttQh5rTbKCro=\n-----END PUBLIC KEY-----',
};
try {
  const msg = Buffer.from(JSON.stringify(body), 'utf8');
  for (const tag of Object.keys(PUBKEY_PEMS)) {
    const pubKey = crypto.createPublicKey(PUBKEY_PEMS[tag]);
    if (crypto.verify(null, msg, pubKey, Buffer.from(sigB64 || '', 'base64'))) {
      sigOk = true;
      sigDetail = `（${tag} 钥验签通过）`;
      break;
    }
  }
  if (!sigOk) sigDetail = '验签失败：内容与两把内置公钥均不匹配（篡改或未重新签名）';
} catch (e) {
  sigOk = false;
  sigDetail = `验签异常: ${e.message}`;
}
check(sigOk, 'D. Ed25519 验签通过', sigDetail);

// ---- E. Rust 侧接线 ----
const rsText = fs
  .readdirSync(UNINSTALL_DIR)
  .filter((f) => f.endsWith('.rs') && !f.includes('_tests'))
  .map((f) => fs.readFileSync(path.join(UNINSTALL_DIR, f), 'utf8'))
  .join('\n');
check(
  /include_str!\("[^"]*uninstall-residue-rules\.json"\)/.test(rsText),
  'E1. 卸载域内置副本已接线（include_str!，路径相对 commands/uninstall/ 子目录）',
);
// 装载链两处都必须过校验：数据目录那份 + 内置那份（只校验其一等于留豁免通道）
const loadFn = rsText.slice(rsText.indexOf('fn load_residue_rules()'));
check(
  /validate_residue_package\(&v\)/.test(loadFn) && /validate_residue_package\(&builtin\)/.test(loadFn),
  'E2. load_residue_rules 对数据目录与内置库都调用语义校验',
);
check(
  /quarantine_file\(&file/.test(loadFn),
  'E3. 数据目录坏文件走隔离流程（Q2 拍板：整包拒绝 + 保留上一份 + 隔离现场）',
);

/// 取某个零缩进函数体（内部块的收尾带缩进，所以 `\n}\n` 只会命中函数尾）
function fnBody(text, header) {
  const i = text.indexOf(header);
  if (i < 0) return '';
  const j = text.indexOf('\n}\n', i);
  return j < 0 ? '' : text.slice(i, j);
}

// ---- F. 夹具对拍：与 Rust 运行期校验器共用同一组正反例 ----
let fixture = null;
try {
  fixture = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
  check(true, 'F0. 夹具可读且为合法 JSON');
} catch (e) {
  check(false, 'F0. 夹具可读且为合法 JSON', e.message);
}
if (fixture) {
  const regBad = (fixture.regVectors || []).filter((v) => {
    const got = regTargetBlockReason(v.target) !== null;
    return got !== Boolean(v.blocked);
  });
  check(regBad.length === 0, `F1. 注册表保护判定与夹具一致（${(fixture.regVectors || []).length} 条向量）`,
    regBad.length ? `${regBad.length} 处不一致：${regBad.map((v) => `${v.target}(${v.cls})`).join('；')}` : '');
  const pkgBad = (fixture.packages || []).filter((c) => {
    const got = validateResiduePackage(c.pkg) === null;
    return got !== Boolean(c.ok);
  });
  check(pkgBad.length === 0, `F2. 语义校验与夹具一致（${(fixture.packages || []).length} 条用例）`,
    pkgBad.length ? `${pkgBad.length} 处不一致：${pkgBad.map((c) => `${c.label} 期望 ${c.ok ? '放行' : '拒绝'}`).join('；')}` : '');
  const negCount = (fixture.packages || []).filter((c) => !c.ok).length;
  check(negCount >= 20, `F3. 夹具判红用例数量充足（当前 ${negCount} 条，方案 §7 要求每类保护都有反例）`);

  // F4 双向覆盖（V2 P0-C1）：拒绝侧与放行侧都必须有足量样本，且数量是棘轮。
  // 只测拒绝方向时，判定器会一路收紧到把合法产品键打死而门禁照绿 —— 放行方向
  // 才是"收紧不许误伤功能"的证据（本仓 C1/C2 的放行回测就是这个用途的结构化版本）。
  // 数量下限写在下面常量里：删反例必须同时改下限，等于逼人来写明理由。
  const REG_DENY_MIN = 25;
  const REG_ALLOW_MIN = 8;
  let regDeny = 0;
  let regAllow = 0;
  for (const v of fixture.regVectors || []) {
    if (v.blocked) regDeny += 1; else regAllow += 1;
  }
  check(
    regDeny >= REG_DENY_MIN && regAllow >= REG_ALLOW_MIN,
    `F4a. 注册表向量双向足量（拒 ${regDeny}/${REG_DENY_MIN}，放 ${regAllow}/${REG_ALLOW_MIN}）`,
    regDeny < REG_DENY_MIN || regAllow < REG_ALLOW_MIN
      ? `放行侧只有 ${regAllow} 条时，判定器可以随意收紧而无人报警；要删反例必须同时改上面的下限并写明理由`
      : '',
  );
  const noCls = (fixture.regVectors || []).filter((v) => !v.cls).length;
  check(noCls === 0, `F4b. 注册表向量都归了类（未分类 ${noCls} 条）`);
  const okPkg = (fixture.packages || []).filter((c) => c.ok).length;
  check(okPkg >= 5, `F4c. 语义校验至少有 5 条"合法包"用例（当前 ${okPkg}）—— 只有反例就等于没测过放行方向`, '');
  const dupLabel = (fixture.packages || []).map((c) => c.label).filter((l, i, a) => a.indexOf(l) !== i);
  check(dupLabel.length === 0, 'F4d. 夹具用例 label 唯一（重名会让"缺样本"看不出来）', dupLabel.join('；'));
  const badLabelled = (fixture.packages || []).filter((c) => typeof c.label !== 'string' || !c.label.trim());
  check(badLabelled.length === 0, `F4e. 夹具用例都有名字（无名 ${badLabelled.length} 条）`);

  // ---- F5~F7. R-2 启动项删值窄口子（与 run_keys::reg_value_gate 共用同一份夹具字节） ----
  const rvVectors = fixture.runValueVectors || [];
  const gateBad = rvVectors.filter((v) => runValueGate(v.target) !== v.gate);
  check(
    gateBad.length === 0,
    `F5. R-2 启动项删值窄口子与夹具一致（${rvVectors.length} 条向量）`,
    gateBad.length
      ? `${gateBad.length} 处不一致：${gateBad.map((v) => `${v.cls || v.target} 期望 ${v.gate} 实得 ${runValueGate(v.target)}`).join('；')}`
      : '',
  );
  // 三态各自的下限是**棘轮**：只留放行向（或只留拒绝向）时，把判定实现成常量也能过。
  // 删向量必须同时改这里的下限，等于逼人来写明理由。
  const RV_MIN = { allowed: 5, denied: 10, 'not-governed': 5 };
  const rvCount = { allowed: 0, denied: 0, 'not-governed': 0 };
  for (const v of rvVectors) if (v.gate in rvCount) rvCount[v.gate] += 1;
  check(
    Object.keys(RV_MIN).every((k) => rvCount[k] >= RV_MIN[k]),
    `F6. R-2 向量三态足量（放 ${rvCount.allowed}/${RV_MIN.allowed}，拒 ${rvCount.denied}/${RV_MIN.denied}，不管辖 ${rvCount['not-governed']}/${RV_MIN['not-governed']}）`,
    Object.keys(RV_MIN).filter((k) => rvCount[k] < RV_MIN[k]).length
      ? '三态缺一时，把判据实现成常量（全放行 / 全拒绝）也能一路绿'
      : '',
  );
  const rvNoCls = rvVectors.filter((v) => !v.cls).length;
  check(rvNoCls === 0, `F7. R-2 向量都归了类（未分类 ${rvNoCls} 条）`);
}

console.log(fail === 0 ? '\n门禁通过' : `\n${fail} 项未通过`);
process.exit(fail === 0 ? 0 : 1);

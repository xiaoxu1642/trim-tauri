#!/usr/bin/env node
// check-residue-rule-contract.mjs — 卸载残留规则库契约门禁（U-1，2026-09-28；A1/A2 收口 2026-09-28）
//
// 对 src-tauri/data/uninstall-residue-rules.json 做四层断言：
//   A. 根结构：rulesVersion（≥ 20260928 棘轮，只升不降）/ prov / rules 数组
//   B. 规则条目：id 唯一非空且字符集受限；displayName / publisher / uninstallKey 三条件组
//      **至少两组非空**（与 Rust 侧 residue_rules_hits 的「双条件命中」拍板口径对齐，单侧维护即红）
//   C. residue 条目：kind ∈ {folder, file, reg_key}（Q8：reg_value / shortcut 不放行）；
//      target 过文件形状与**注册表硬否决**判定；note 非空（面板 reason 要展示）；未知字段整包拒
//   D. 签名：Ed25519 验签通过（与 sign-cleanup-rules.mjs 同密钥同规范化）
//   E. 内置副本接线：src-tauri/src/commands/uninstall.rs 必须 include_str! 本文件
//   F. 夹具对拍（A1/A2）：tools/fixtures/residue-contract.json 的 regVectors 与 packages
//      两侧各自独立实现同一套判定 —— 本文件**不调用** Rust，靠夹具钉口径（方案 §4.3 第三步）。
//      任一侧口径漂移，夹具立刻判红；新增保护类别必须同时补夹具反例。
//
// 用法：node tools/check-residue-rule-contract.mjs            （全套门禁）
//       node tools/check-residue-rule-contract.mjs --preview x.json （A8 候选包干跑）
'use strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const RULES = path.join(ROOT, 'src-tauri', 'data', 'uninstall-residue-rules.json');
const UNINSTALL_RS = path.join(ROOT, 'src-tauri', 'src', 'commands', 'uninstall.rs');
const FIXTURE = path.join(ROOT, 'tools', 'fixtures', 'residue-contract.json');
const PRIV_KEY = path.join(os.homedir(), '.trim-signing', 'rules-ed25519-private.pem');
// token 登记表：新 token 必须先在这里登记、Rust 侧 RESIDUE_RULE_TOKENS 同步、
// 且 expand_env_path 能展开才放行（两侧清单必须同集，夹具 packages 钉住）
const RESOLVABLE_TOKENS = [
  'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA', 'PROGRAMFILES',
  'PROGRAMFILES(X86)', 'PROGRAMW6432', 'COMMONPROGRAMFILES', 'USERPROFILE',
  'WINDIR', 'SYSTEMROOT',
];
const MIN_VERSION = 20260928;
const ALLOWED_KINDS = ['folder', 'file', 'reg_key'];
const TOP_FIELDS = ['rulesVersion', 'prov', 'rules', '_sig'];
const PROV_FIELDS = ['sourceClass', 'reviewedAt'];
const RULE_FIELDS = ['id', 'displayName', 'publisher', 'uninstallKey', 'residue'];
const ENTRY_FIELDS = ['kind', 'target', 'note'];
const MATCH_GROUPS = ['displayName', 'publisher', 'uninstallKey'];
const MAX_RULES = 400;
const MAX_RESIDUE = 64;
const MAX_GROUP_ITEMS = 32;
const MAX_TARGET_LEN = 260; // MAX_PATH
const MAX_TEXT_LEN = 200;
const MAX_SEGMENTS = 32;

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

// ==================== 规则包语义校验（与 uninstall.rs::validate_residue_package 同口径） ====================

function fileTargetProblem(target) {
  if ([...target].length > MAX_TARGET_LEN) return '目标长度超过 260（MAX_PATH）';
  if (target.includes('*') || target.includes('?')) return '目标含通配符（残留规则只允许精确路径）';
  if (/[\0\r\n\t]/.test(target)) return '目标含控制字符';
  let body;
  if (target.startsWith('%')) {
    const rest = target.slice(1);
    const end = rest.indexOf('%');
    if (end < 0) return '变量名未闭合';
    const token = rest.slice(0, end);
    if (!token || !RESOLVABLE_TOKENS.some((t) => t.toLowerCase() === token.toLowerCase())) {
      return `变量 %${token}% 未登记（先确认展开器可解析再入白名单）`;
    }
    const tail = rest.slice(end + 1);
    if (tail.includes('%')) return '路径中不允许出现第二个变量替换';
    if (!tail.startsWith('\\') && !tail.startsWith('/')) return '变量后必须有分隔符与非空子段（禁止 token 根）';
    body = tail.slice(1);
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
    if (groups < 2) return `规则 ${id}: 三条件组只有 ${groups} 组非空，双条件命中是 U-1 拍板口径`;
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
      const problem = e.kind === 'reg_key' ? regTargetProblem(e.target) : fileTargetProblem(e.target);
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

// ---- C1. 现存合法规则必须继续放行（收紧不许把功能打死） ----
const LEGIT_REG_KEYS = [
  'HKLM\\SOFTWARE\\ESET', 'HKLM\\SOFTWARE\\360Safe', 'HKLM\\SOFTWARE\\Piriform',
  'HKCU\\Software\\360Safe', 'HKCU\\Software\\RoboForm',
  'HKCU\\Software\\Tencent\\WeChat', 'HKCU\\Software\\Tencent\\QQ',
];
const falseBlocked = LEGIT_REG_KEYS.filter((t) => regTargetBlockReason(t));
check(falseBlocked.length === 0, 'C1. 合法产品键放行回测', falseBlocked.length ? `被误拒: ${falseBlocked.join(', ')}` : '');
const inLibRegKeys = rules.flatMap((r) => (r.residue || []).filter((e) => e.kind === 'reg_key').map((e) => e.target));
const libBlocked = inLibRegKeys.filter((t) => regTargetBlockReason(t));
check(libBlocked.length === 0, 'C2. 当前库内 reg_key 目标全部通过保护判定',
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
} else if (!fs.existsSync(PRIV_KEY)) {
  sigDetail = '本机无私钥，无法做存在性对拍；改用公钥验签（见下）';
}
// 公钥验签（不依赖本机私钥）：内置公钥与 rules_signature.rs::RULES_PUBKEY_PEM 一致
const PUBKEY_PEM = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAQehWbhuKKCxcWOje/8AZXYN192Z3Ryi8+cQ6ENwXAtY=\n-----END PUBLIC KEY-----';
try {
  const pubKey = crypto.createPublicKey(PUBKEY_PEM);
  sigOk = crypto.verify(null, Buffer.from(JSON.stringify(body), 'utf8'), pubKey, Buffer.from(sigB64 || '', 'base64'));
  if (!sigOk) sigDetail = '验签失败：内容与签名不匹配（篡改或未重新签名）';
} catch (e) {
  sigOk = false;
  sigDetail = `验签异常: ${e.message}`;
}
check(sigOk, 'D. Ed25519 验签通过', sigDetail);

// ---- E. Rust 侧接线 ----
const rsText = fs.readFileSync(UNINSTALL_RS, 'utf8');
check(
  rsText.includes('include_str!("../../data/uninstall-residue-rules.json")'),
  'E1. uninstall.rs 内置副本已接线（include_str!）',
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

// A3 更新链的接线断言：远程包校验必须复用装载侧那个语义校验器。
// 「更新放行、装载拒绝」这种分叉两边都觉得自己对，只有钉住调用关系才发现得了。
const verifyFn = fnBody(rsText, 'fn verify_residue_remote_text');
check(verifyFn.length > 200, 'E4a. 更新链的远程校验函数存在且非空');
check(
  /validate_residue_package\(&parsed\)/.test(verifyFn),
  'E4b. 远程包校验调用同一个语义校验器（不许在更新侧另写一套字段规则）',
);
check(
  /verify_rules_text/.test(verifyFn) && /rulesVersion/.test(verifyFn),
  'E4c. 远程包校验序里验签与版本防降级都在',
);
const updateFn = fnBody(rsText, 'pub async fn uninstall_update_residue_rules');
check(
  /atomic_write_file\(&target, text\.as_bytes\(\)\)/.test(updateFn),
  'E5a. 更新落盘走字节级原子写（重序列化 JSON 会让 _sig 验的不是签的那份字节，审查 M10）',
);
check(
  !/serde_json::to_string|to_string_pretty/.test(updateFn),
  'E5b. 更新落盘禁止重新序列化规则文本',
);
check(
  /set_residue_watermark\(/.test(updateFn),
  'E5c. 更新成功后必须抬升水位线（防回滚链不能只读不写）',
);
const checkFn = fnBody(rsText, 'pub async fn uninstall_check_residue_version');
check(
  checkFn.length > 100 && !/atomic_write_file/.test(checkFn),
  'E6. 「检查版本」命令不得写盘（只读语义，别顺手改成静默自动更新）',
);

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
}

console.log(fail === 0 ? '\n门禁通过' : `\n${fail} 项未通过`);
process.exit(fail === 0 ? 0 : 1);

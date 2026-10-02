// check-optimizer-security.mjs —— 优化目录的「安全降级」门禁（RAINZ 对标 §4 R2）
//
// 抓什么：扩库时把「关内核签名强制 / 关 Defender / 关 VBS·内存完整性 / 关系统还原 /
//         关 UAC / 关 SmartScreen / 关防火墙 / 永久关 Windows 更新 / 禁用安全服务」
//         这类项悄悄加进目录。Trim 现有目录里已经有 4 条（disable_uac / tf_defender /
//         perf_windows_update_off / perf_vbs_off），所以这不是空谈：靠人眼守不住，
//         得有机器判据。
//
// 判据是**机械的**：(段路径, 键名, 写入值) 三元组 + 命令面正则，规则只有这一份实现，
// 侧表 `src-tauri/data/optimizer-security.json` 必须与重算结果**逐条相等** ——
// 手工增删侧表条目不能改变判定，只能改变「是否被登记」。
//
// ⚠ 看值不看名：`perf_wu_enable`（恢复自动更新）的 pwsh 里出现了 `NoAutoUpdate`，但它是
//    **删除**该键；把「键名出现过」当降级会造出误报（第一版判据就踩了这个，见 §正向对照）。
//    同理 `"EnableLUA"=dword:00000001` 是**开**UAC。
//
// 用法：node tools/check-optimizer-security.mjs   （退出码 0 = 全绿，1 = 任一不符）
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';

const R = (rel) => readFileSync(join(REPO_ROOT, ...rel.split('/')), 'utf8');
const CATALOG = 'src-tauri/data/optimizer-runtime.json';
const SIDE = 'src-tauri/data/optimizer-security.json';

let fail = 0;
function check(ok, name, detail) {
  console.log(`${ok ? '✓' : '✗'} ${name}${detail ? ' —— ' + detail : ''}`);
  if (!ok) fail++;
}

// ---------------------------------------------------------------------------
// 判定器（唯一实现）
// ---------------------------------------------------------------------------

/** `.reg` 段落 → 段落名；键值对 → 名字与原始值 */
function regSections(text) {
  const out = [];
  let cur = null;
  for (const line of String(text).split(/\r?\n/)) {
    const t = line.trim();
    if (t.startsWith('[') && t.endsWith(']')) {
      cur = { section: t.slice(1, -1), pairs: [] };
      out.push(cur);
    } else if (cur) {
      const m = t.match(/^"([^"]+)"\s*=\s*(.*)$/);
      if (m) cur.pairs.push({ name: m[1], raw: m[2].trim() });
    }
  }
  return out;
}

/** `dword:xxxxxxxx` / `"0"` → 数值；`-`（删除）与无法判定 → null */
function numericValue(raw) {
  const d = raw.match(/^dword:([0-9a-fA-F]{1,8})$/);
  if (d) return parseInt(d[1], 16);
  const s = raw.match(/^"(.*)"$/);
  if (s && /^-?\d+$/.test(s[1])) return Number(s[1]);
  return null; // `-`（删除）或字符串：不参与分类
}

/** 键值层规则：段路径可选，when 指「写入值满足什么条件才叫降级」 */
const VALUE_RULES = [
  { id: 'uac-off', sectionRe: /\\Policies\\System$/i, nameRe: /^EnableLUA$/i, when: 'zero', why: '关闭 UAC（用户账户控制）' },
  { id: 'vbs-off', nameRe: /^EnableVirtualizationBasedSecurity$/i, when: 'zero', why: '关闭基于虚拟化的安全（VBS）' },
  { id: 'hvci-off', sectionRe: /HypervisorEnforcedCodeIntegrity/i, nameRe: /^Enabled$/i, when: 'zero', why: '关闭内存完整性（HVCI）' },
  { id: 'driver-blocklist-off', nameRe: /^VulnerableDriverBlocklistEnable$/i, when: 'zero', why: '关闭易受攻击驱动阻止列表' },
  { id: 'defender-off', nameRe: /^Disable(AntiSpyware|AntiVirus|RealtimeMonitoring|BehaviorMonitoring|TamperProtection|IOAVProtection|ScriptScanning|BlockAtFirstSeen|EnhancedNotifications|GenericRePorts|RealtimeMonitoring)$/i, when: 'nonzero', why: '关闭 Defender 防护面' },
  { id: 'smartscreen-off', nameRe: /^EnableSmartScreen$/i, when: 'zero', why: '关闭 SmartScreen' },
  { id: 'firewall-off', nameRe: /^EnableFirewall$/i, when: 'zero', why: '关闭防火墙' },
  { id: 'wu-off', nameRe: /^NoAutoUpdate$/i, when: 'nonzero', why: '永久关闭 Windows Update 自动更新' },
  { id: 'restore-off', sectionRe: /SystemRestore|SR\b/i, nameRe: /^DisableSR$/i, when: 'nonzero', why: '关闭系统还原' },
];

/** 命令面规则（pwsh / cmd 文本；这些没有「值」可比，按形态判） */
const CMD_RULES = [
  { id: 'bcdedit-integrity', re: /bcdedit[^\r\n]{0,80}\b(nointegritychecks|testsigning|disableelamdrivers)\b[^\r\n]{0,20}\b(on|yes|1)\b/i, why: '关闭内核驱动签名强制 / 测试签名' },
  { id: 'sec-svc-disable', re: /\bsc(\.exe)?\s+config\s+(WinDefend|WdNisSvc|SecurityHealthService|wscsvc|Sense|MsSense|SgrmBroker)\b[^\r\n]{0,60}start=\s*4\b/i, why: '禁用安全类服务的启动' },
  { id: 'restore-off-cmd', re: /Disable-ComputerRestore\b/i, why: '关闭系统还原' },
  { id: 'defender-cmd', re: /Set-MpPreference[^\r\n]{0,120}-Disable\w+\s+\$?true\b/i, why: '关闭 Defender 防护（Set-MpPreference）' },
];

/** 对一个优化项分类，返回命中的规则 id 列表（去重、稳定序） */
function classify(opt) {
  const hit = new Set();
  for (const step of opt.steps || []) {
    if (typeof step.reg === 'string') {
      for (const sec of regSections(step.reg)) {
        for (const p of sec.pairs) {
          const v = numericValue(p.raw);
          if (v === null) continue;
          for (const r of VALUE_RULES) {
            if (!r.nameRe.test(p.name)) continue;
            if (r.sectionRe && !r.sectionRe.test(sec.section)) continue;
            if (r.when === 'zero' && v !== 0) continue;
            if (r.when === 'nonzero' && v === 0) continue;
            hit.add(r.id);
          }
        }
      }
    }
    const cmdText = [step.pwsh, step.cmd].filter((x) => typeof x === 'string').join('\n');
    for (const r of CMD_RULES) if (cmdText && r.re.test(cmdText)) hit.add(r.id);
  }
  return [...hit].sort();
}

// ---------------------------------------------------------------------------
// 正向/反向对照自检：判据自己必须先被证明活着，且不许误报
// ---------------------------------------------------------------------------
{
  // 每条对照都带**该规则真实的段落形状**（如 uac-off 要求段尾是 `\Policies\System`）——
  // 用通用段落做对照会验证不了收窄条件，第一版就是这么假红的。
  const DG = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard';
  const POL_SYS = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System';
  const WU_AU = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU';
  const DEF = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender';
  const fake = (section, line) =>
    classify({ steps: [{ reg: `Windows Registry Editor Version 5.00\r\n\r\n[${section}]\r\n${line}\r\n` }] });

  const fire = [
    [POL_SYS, '"EnableLUA"=dword:00000000', 'uac-off'],
    [DG, '"EnableVirtualizationBasedSecurity"=dword:00000000', 'vbs-off'],
    [WU_AU, '"NoAutoUpdate"=dword:00000001', 'wu-off'],
    [DEF, '"DisableAntiSpyware"=dword:00000001', 'defender-off'],
  ];
  const silent = [
    // 反向：**写成「开」不许报** —— 第一版判据只比键名，把 perf_wu_enable（恢复自动更新）
    // 误判成了降级项；下面四条各钉一个方向。
    [POL_SYS, '"EnableLUA"=dword:00000001', 'uac-off'],
    [DG, '"EnableVirtualizationBasedSecurity"=dword:00000001', 'vbs-off'],
    [WU_AU, '"NoAutoUpdate"=dword:00000000', 'wu-off'],
    [DEF, '"DisableAntiSpyware"=dword:00000000', 'defender-off'],
    [POL_SYS, '"EnableLUA"=-', 'uac-off'], // 删除键 ≠ 降级
  ];
  const badFire = fire
    .filter(([sec, line, id]) => !fake(sec, line).includes(id))
    .map(([, line, id]) => `${id} 未命中「${line}」`);
  const badSilent = silent
    .filter(([sec, line, id]) => fake(sec, line).includes(id))
    .map(([, line, id]) => `${id} 误报「${line}」`);
  check(
    badFire.length === 0 && badSilent.length === 0,
    `正向/反向对照自检（${fire.length} 命中 + ${silent.length} 静默）`,
    [...badFire, ...badSilent].join('；'),
  );
}

// ---------------------------------------------------------------------------
// 侧表 ⇄ 重算 逐条对拍
// ---------------------------------------------------------------------------
const catalog = JSON.parse(R(CATALOG));
const side = JSON.parse(R(SIDE));
const byId = new Map(catalog.map((o) => [o.id, o]));

const classified = new Map();
for (const o of catalog) {
  const kinds = classify(o);
  if (kinds.length) classified.set(o.id, kinds);
}

const table = side.items && typeof side.items === 'object' ? side.items : null;
if (!table) {
  check(false, '侧表结构（items 对象）', '读不到 items');
} else {
  const tableIds = Object.keys(table).sort();
  const calcIds = [...classified.keys()].sort();

  // ① 侧表里的 id 必须还在目录里（项退役没清表 = 标签挂在空气上）
  const stale = tableIds.filter((id) => !byId.has(id));
  check(stale.length === 0, `① 侧表 id 都在目录里（${tableIds.length} 条）`, stale.length ? `已不在目录：${stale.join(', ')}` : '');

  // ② 逐条相等：少登记（新项混入未登记）与多登记（标签与判定不符）都要红
  const missing = calcIds.filter((id) => !tableIds.includes(id));
  const extra = tableIds.filter((id) => !calcIds.includes(id));
  check(
    missing.length === 0 && extra.length === 0,
    `② 侧表 ⇄ 机械重算逐条相等（命中 ${calcIds.length} 条：${calcIds.join(', ')}）`,
    [missing.length ? `未登记：${missing.join(', ')}` : '', extra.length ? `多登记/判定不符：${extra.join(', ')}` : ''].filter(Boolean).join('；'),
  );

  // ③ 每条要带档位与理由（空理由 = 没写清楚为什么它算降级）
  const bad = [];
  for (const [id, meta] of Object.entries(table)) {
    if (!meta || typeof meta !== 'object') { bad.push(`${id} 不是对象`); continue; }
    if (!['high', 'medium'].includes(meta.level)) bad.push(`${id} level 非法`);
    if (typeof meta.why !== 'string' || meta.why.trim().length < 6) bad.push(`${id} 缺 why`);
    if (!Array.isArray(meta.writes) || !meta.writes.length) bad.push(`${id} 缺 writes`);
  }
  check(bad.length === 0, '③ 每条带 level(high|medium) / why / writes', bad.join('；'));

  // ④ 侧表声明的命中规则必须与重算一致（防止「写了条目的 why 但判据已经改了」）
  const ruleDrift = [];
  for (const [id, meta] of Object.entries(table)) {
    const got = classified.get(id) || [];
    const want = Array.isArray(meta.rules) ? [...meta.rules].sort() : [];
    if (JSON.stringify(got) !== JSON.stringify(want)) ruleDrift.push(`${id}: 重算 [${got.join(',')}] ≠ 表 [${want.join(',')}]`);
  }
  check(ruleDrift.length === 0, '④ 每条的 rules 与重算命中的规则 id 一致', ruleDrift.join('；'));
}

console.log(`\n安全降级项：${classified.size} / 目录 ${catalog.length} 项`);
console.log(fail === 0 ? '\n门禁通过' : '\n门禁失败：' + fail + ' 组断言未通过');
process.exit(fail === 0 ? 0 : 1);

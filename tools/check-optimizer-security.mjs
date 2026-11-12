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
// 安全类服务白名单（T1f-M02）：禁用这些服务才算「禁用安全服务」。
// 不含 CryptSvc/SENS 等基础服务——那条属于「批量禁用」风险，不是本规则的概念。
const SECURITY_SERVICES = /^(WinDefend|WdNisSvc|SecurityHealthService|wscsvc|Sense|MsSense|SgrmBroker)$/i;
const VALUE_RULES = [
  { id: 'uac-off', sectionRe: /\\Policies\\System$/i, nameRe: /^EnableLUA$/i, when: 'zero', why: '关闭 UAC（用户账户控制）' },
  // T1f-M02：reg `Services\<安全服务> "Start"=4` 与 cmd 形态同语义。
  { id: 'sec-svc-disable', sectionRe: /\\Services\\(WinDefend|WdNisSvc|SecurityHealthService|wscsvc|Sense|MsSense|SgrmBroker)$/i, nameRe: /^Start$/i, equals: 4, why: '停用安全服务（WinDefend / Sense 等）的启动' },
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

/** 服务被改成禁用/启动值 4 的步骤 + 文本里出现的服务名（含变量数组形态）。 */
function securityServiceDisableHit(step, text) {
  const disable = /start\s*=\s*(?:4\b|disabled\b)|-StartupType\s+Disabled|\.StartupType\s*=\s*['"]?Disabled/i.test(text)
    // T1f-M01：PowerShell/reg.exe 的三类注册表写形态。
    // 注意 `Stop-Service` 单独出现**不算**永久禁用——它只停当前进程，启动类型没变。
    || /(?:New-ItemProperty|Set-ItemProperty)[^\n]{0,240}-Name\s+["']?Start["']?[^\n]{0,120}-Value\s+["']?(?:4|Disabled)\b/i.test(text)
    || /\breg(?:\.exe)?\s+add[^\n]{0,240}\/v\s+["']?Start["']?[^\n]{0,120}\/d\s+["']?(?:4|Disabled)\b/i.test(text)
    || step.disable === true
    || /^disabled$/i.test(String(step.startType ?? ''));
  if (!disable) return false;
  const names = new Set();
  // T1f-M01：只从「写入型构造」采集服务名，三种等价写法都要覆盖 ——
  // `-Name`、位置参数、`Get-Service X | Set-Service` 管道。
  // 不能再把文本里所有引号串当服务名：`Get-Service "WinDefend"` 只是查询条件，
  // 与另一个普通服务的 `-StartupType Disabled` 同处一段文本时会拼出误报。
  for (const m of text.matchAll(/\bsc(?:\.exe)?\s+config\s+(?:"([^"]+)"|([^\s]+))/gi)) {
    names.add((m[1] || m[2] || '').replace(/^["']|["']$/g, ''));
  }
  for (const m of text.matchAll(/\bSet-Service[^\n]*?-Name\s+(?:"([^"]+)"|'([^']+)'|([\w.$-]+))/gi)) {
    names.add(m[1] || m[2] || m[3]);
  }
  // 位置参数：`Set-Service WinDefend -StartupType Disabled`（首参不能是另一个开关）。
  for (const m of text.matchAll(/\bSet-Service\s+(?!-)(?:"([^"]+)"|'([^']+)'|([\w.$-]+))/gi)) {
    names.add(m[1] || m[2] || m[3]);
  }
  // 管道：只认「取服务 → 交给 Set-Service」这一种形态。
  for (const m of text.matchAll(/\bGet-Service\s+(?:-Name\s+)?(?:"([^"]+)"|'([^']+)'|([\w.$-]+))[^\n|]*\|\s*Set-Service\b/gi)) {
    names.add(m[1] || m[2] || m[3]);
  }
  for (const m of text.matchAll(/\\Services\\([^\\\]"'\s]+)/gi)) names.add(m[1]);
  // 变量形态：`$services = @("DiagTrack","Sense")` + 循环里统一禁；只解析显式数组载体，
  // 元素必须是引号串（真实服务名形态）。
  for (const m of text.matchAll(/\$\w+\s*=\s*@\(([^)]*)\)/g)) {
    for (const s of m[1].matchAll(/["']([^"']+)["']/g)) names.add(s[1]);
  }
  if (typeof step.service === 'string') names.add(step.service);
  return [...names].some((n) => SECURITY_SERVICES.test(String(n).replace(/^["']|["']$/g, '')));
}

/** 对一个优化项分类，返回命中的规则 id 列表（去重、稳定序） */
function classify(opt) {
  const hit = new Set();
  // T1f-M02：restore 步同样可能写入降级值（同文件 BCD 白名单块早就包含 restore）。
  for (const step of [...(opt.steps || []), ...(opt.restore || [])]) {
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
            if (r.equals !== undefined && v !== r.equals) continue;
            hit.add(r.id);
          }
        }
      }
    }
    const cmdText = [step.pwsh, step.cmd].filter((x) => typeof x === 'string').join('\n');
    for (const r of CMD_RULES) if (cmdText && r.re.test(cmdText)) hit.add(r.id);
    // T1f-M02：sc disabled / Set-Service / 变量数组 / 结构化 service 步的统一判据。
    // 结构化步没有 cmd 文本，仍须判（service/startType/disable 字段本身就是证据）。
    if (securityServiceDisableHit(step, cmdText)) hit.add('sec-svc-disable');
  }
  return [...hit].sort();
}

// ---------------------------------------------------------------------------
// 侧表条目正文的判据（T1f-L03：旧实现只查「非空 / 长度 ≥ 6」，`why: '为什么'`、
// `writes: [123]`、`writes: ['']` 全都能过）。这里把「写得对不对」压成两条机械判据。
// ---------------------------------------------------------------------------

/**
 * `writes` 元素：形态是「目标 :: 键=值」（目标可省）—— 必须能看出改了哪个键、改成什么值。
 * 只写一段路径、或只写键名不带值，都不算把写入面说清楚。
 */
function writesProblem(w) {
  if (typeof w !== 'string' || !w.trim()) return '不是非空字符串';
  if (!w.includes('=')) return '没有「键=值」：看不出改成什么值';
  const at = w.lastIndexOf('::');
  const tail = (at >= 0 ? w.slice(at + 2) : w).trim();
  if (!/^[^=\s][^=]*=\S+$/.test(tail)) return `「::」后半段不是「键=值」：${tail}`;
  return '';
}

/** 概念词元：中文/英文/数字连续段，取长度 ≥ 3 的（`UAC`/`Defender`/`内存完整性` 这类是概念名） */
function conceptTokens(text) {
  return new Set(
    String(text).toLowerCase().split(/[^a-z0-9\u4e00-\u9fff]+/).filter((t) => t.length >= 3),
  );
}

// T1f-M03：同义词组。中文同义改写（「用户账户控制」↔「UAC」）必须能过，
// 但不能放宽到「任意安全词都算」——只有登记组内的词才算同一概念。
const SYNONYM_GROUPS = [
  ['uac', '用户账户控制', 'user account control'],
  ['vbs', '基于虚拟化的安全', '虚拟化安全', 'virtualization based security'],
  ['defender', 'windows defender', '杀毒', '防病毒', '实时保护', 'antivirus', 'antispyware'],
  ['windows update', '自动更新', '系统更新', 'wu'],
  ['smartscreen', '智能屏幕', 'smart screen'],
  ['firewall', '防火墙'],
  ['system restore', '系统还原'],
  ['hvci', '内存完整性', 'hypervisor enforced code integrity'],
  ['driver blocklist', '驱动阻止列表', '易受攻击驱动'],
];
function hasConceptOverlap(mineText, ruleText) {
  const mine = conceptTokens(mineText);
  const rule = conceptTokens(ruleText);
  if ([...rule].some((t) => mine.has(t))) return true;
  const lowerMine = String(mineText).toLowerCase();
  const lowerRule = String(ruleText).toLowerCase();
  for (const group of SYNONYM_GROUPS) {
    if (group.some((w) => lowerMine.includes(w)) && group.some((w) => lowerRule.includes(w))) return true;
  }
  return false;
}

/**
 * `why` 元素：它是高危确认框正文（`optimizer.js` 原样展示给用户），必须说的是这条项
 * **为什么**降安全面。机器判「名副其实」需要词表 —— 这里拿规则表自己的 `why` 当概念
 * 词源：该条声明的每条规则，至少要有一个概念词元与本条 `why` 有交集。
 * 对不上基本等于复制了别条的理由或写成了宣传语（`这条能释放更多磁盘空间` 正是这种）。
 */
function whyOffTopic(meta) {
  const out = [];
  for (const rid of Array.isArray(meta.rules) ? meta.rules : []) {
    const rule = [...VALUE_RULES, ...CMD_RULES].find((r) => r.id === rid);
    if (!rule) { out.push(`${rid}（规则表里没有这条规则 id）`); continue; }
    if (!hasConceptOverlap(meta.why, rule.why)) out.push(rid);
  }
  return out;
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
  const fakeCmd = (text) => classify({ steps: [{ pwsh: text }] });

  // T1b-M09：13 条规则逐条配「命中 + 静默」，不再只覆盖其中 4 条。
  const cases = [
    { id: 'uac-off', hit: () => fake(POL_SYS, '"EnableLUA"=dword:00000000'), miss: () => fake(POL_SYS, '"EnableLUA"=dword:00000001') },
    { id: 'vbs-off', hit: () => fake(DG, '"EnableVirtualizationBasedSecurity"=dword:00000000'), miss: () => fake(DG, '"EnableVirtualizationBasedSecurity"=dword:00000001') },
    { id: 'hvci-off', hit: () => fake('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity', '"Enabled"=dword:00000000'), miss: () => fake('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity', '"Enabled"=dword:00000001') },
    { id: 'driver-blocklist-off', hit: () => fake('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config', '"VulnerableDriverBlocklistEnable"=dword:00000000'), miss: () => fake('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config', '"VulnerableDriverBlocklistEnable"=dword:00000001') },
    { id: 'defender-off', hit: () => fake(DEF, '"DisableAntiSpyware"=dword:00000001'), miss: () => fake(DEF, '"DisableAntiSpyware"=dword:00000000') },
    { id: 'smartscreen-off', hit: () => fake('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System', '"EnableSmartScreen"=dword:00000000'), miss: () => fake('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System', '"EnableSmartScreen"=dword:00000001') },
    { id: 'firewall-off', hit: () => fake('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile', '"EnableFirewall"=dword:00000000'), miss: () => fake('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile', '"EnableFirewall"=dword:00000001') },
    { id: 'wu-off', hit: () => fake(WU_AU, '"NoAutoUpdate"=dword:00000001'), miss: () => fake(WU_AU, '"NoAutoUpdate"=dword:00000000') },
    { id: 'restore-off', hit: () => fake('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore', '"DisableSR"=dword:00000001'), miss: () => fake('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore', '"DisableSR"=dword:00000000') },
    { id: 'bcdedit-integrity', hit: () => fakeCmd('bcdedit /set nointegritychecks on'), miss: () => fakeCmd('bcdedit /set nointegritychecks off') },
    { id: 'sec-svc-disable', hit: () => fakeCmd('sc config WinDefend start= 4'), miss: () => fakeCmd('sc config WinDefend start= 2') },
    // T1f-M02：其余同语义形态逐条给正反样本（探针的全部形态收成对照）。
    { id: 'sec-svc-disable', hit: () => fake('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinDefend', '"Start"=dword:00000004'), miss: () => fake('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinDefend', '"Start"=dword:00000002') },
    { id: 'sec-svc-disable', hit: () => fakeCmd('sc.exe config $s start= disabled\n$svc = @("DiagTrack","Sense")'), miss: () => fakeCmd('sc.exe config $s start= disabled\n$svc = @("DiagTrack","WpnService")') },
    { id: 'sec-svc-disable', hit: () => fakeCmd('Set-Service -Name Sense -StartupType Disabled'), miss: () => fakeCmd('Set-Service -Name Sense -StartupType Manual') },
    // T1f-M01：位置参数与管道是 `Set-Service -Name` 的等价写法，必须同判。
    { id: 'sec-svc-disable', hit: () => fakeCmd('Set-Service WinDefend -StartupType Disabled'), miss: () => fakeCmd('Set-Service WinDefend -StartupType Manual') },
    { id: 'sec-svc-disable', hit: () => fakeCmd('Get-Service Sense | Set-Service -StartupType Disabled'), miss: () => fakeCmd('Get-Service Sense | Set-Service -StartupType Manual') },
    // T1f-M01：查询条件里的安全服务名不是写入目标 —— 禁用普通服务时不得误报。
    { id: 'sec-svc-disable', hit: () => fakeCmd('Set-Service -Name Sense -StartupType Disabled'), miss: () => fakeCmd('Set-Service -Name DiagTrack -StartupType Disabled\nGet-Service "WinDefend"') },
    { id: 'sec-svc-disable', hit: () => fakeCmd('Set-Service WinDefend -StartupType Disabled'), miss: () => fakeCmd('Get-Service -Name "Sense" -ErrorAction SilentlyContinue\nSet-Service -Name DiagTrack -StartupType Disabled') },
    { id: 'sec-svc-disable', hit: () => fakeCmd('New-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\WinDefend" -Name Start -Value 4'), miss: () => fakeCmd('Stop-Service -Name WinDefend') },
    { id: 'sec-svc-disable', hit: () => fakeCmd('Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Sense" -Name Start -Value 4'), miss: () => fakeCmd('Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Sense" -Name Start -Value 2') },
    { id: 'sec-svc-disable', hit: () => fakeCmd('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\wscsvc" /v Start /d 4 /f'), miss: () => fakeCmd('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\wscsvc" /v Start /d 2 /f') },
    { id: 'sec-svc-disable', hit: () => classify({ steps: [{ service: 'WinDefend', startType: 'Disabled' }] }), miss: () => classify({ steps: [{ service: 'WinDefend', startType: 'Manual' }] }) },
    { id: 'sec-svc-disable', hit: () => classify({ restore: [{ service: 'Sense', disable: true }] }), miss: () => classify({ restore: [{ service: 'Sense', startType: 'Manual' }] }) },
    { id: 'restore-off-cmd', hit: () => fakeCmd('Disable-ComputerRestore -Drive C:\\'), miss: () => fakeCmd('Enable-ComputerRestore -Drive C:\\') },
    { id: 'defender-cmd', hit: () => fakeCmd('Set-MpPreference -DisableRealtimeMonitoring $true'), miss: () => fakeCmd('Set-MpPreference -DisableRealtimeMonitoring $false') },
  ];
  const badFire = cases
    .filter((c) => !c.hit().includes(c.id))
    .map((c) => `${c.id} 未命中正样本`);
  const badSilent = cases
    .filter((c) => c.miss().includes(c.id))
    .map((c) => `${c.id} 误报反样本`);
  check(
    badFire.length === 0 && badSilent.length === 0,
    `正向/反向对照自检（${cases.length} 条规则 × 命中+静默）`,
    [...badFire, ...badSilent].join('；'),
  );

  // T1f-L03 的对照：侧表正文判据（writes 形态 / why 概念交集）同样要能判红。
  const bodyCases = [
    ['writes 合法（带目标）', writesProblem('HKLM\\X\\Y :: EnableLUA=0') === '', true],
    ['writes 合法（无目标）', writesProblem('EnableSmartScreen=0') === '', true],
    ['writes 只写路径', writesProblem('HKLM\\X\\Y') !== '', true],
    ['writes 值为空', writesProblem('HKLM\\X\\Y :: EnableLUA=') !== '', true],
    ['why 与规则概念有交集', whyOffTopic({ why: '关闭 UAC：提权不再弹窗', rules: ['uac-off'] }).length === 0, true],
    ['why 中文同义改写', whyOffTopic({ why: '关闭用户账户控制，提权不再弹窗', rules: ['uac-off'] }).length === 0, true],
    ['why 与规则概念无关', whyOffTopic({ why: '这条能释放约 200MB 磁盘空间', rules: ['uac-off'] }).length === 1, true],
    ['why 引用了不存在的规则', whyOffTopic({ why: '关闭 UAC', rules: ['no-such-rule'] }).length === 1, true],
  ];
  const bodyBad = bodyCases.filter(([, got, want]) => got !== want).map(([n]) => n);
  check(bodyBad.length === 0,
    `侧表正文判据对照（${bodyCases.length} 条样本）`,
    bodyBad.join('；'),
  );
}

// ---------------------------------------------------------------------------
// BCD 元素白名单（2026-10-11 C1）——数据层出现的 bcdedit 命令元素必须在登记集合内
// ---------------------------------------------------------------------------
// 允许的元素（5 行 BCD 面板的目标元素 + 相关联的 deletevalue 目标）
const BCD_ALLOWED_ELEMENTS = new Set([
  'disabledynamictick', 'useplatformtick', 'useplatformclock', // nara_bcd_timer
  'hypervisorlaunchtype', 'vsmlaunchtype', 'isolatedcontext', // nara_bcd_vsm
  'timeout', 'bootmenupolicy', 'bootux', 'quietboot', // nara_bcd_boot
  'firstmegabytepolicy', 'avoidlowmemory', 'nolowmem', 'allowedinmemorysettings', // nara_bcd_lowmem
  'configaccesspolicy', 'msi', 'usephysicaldestination', 'usefirmwarepcisettings', // nara_bcd_irq
  // store 标识符（bcdedit /enum {current} 里会出现，不算元素）
  'current', 'globalsettings', 'default',
]);
// 禁写元素（面板不托管：既有缓解开关 + 无文档自定义项，数据层出现即红）
// 注：这里的「禁写」是安全口径，不等于这些元素在用户机器上是「危险配置」——
// linearaddress57 / vm 等是本机既有的启动项，渲染层只对 custom:* 提示（见 commands/optimizer/bcd.rs）。
const BCD_FORBIDDEN_ELEMENTS = [
  /^increaseuserva$/i,
  /^vm$/i,
  /^custom:\d+$/,
  /^nx$/i,
  /^tpmbootentropy$/i,
  /^linearaddress\d+$/i,
];

// 从 bcdedit 命令文本里提取元素标识符
function extractBcdElements(text) {
  const out = new Set();
  // /set {store} <ELEMENT> <value>  或  /deletevalue {store} <ELEMENT>
  const setRx = /bcdedit[^\r\n]*?\/(?:set|deletevalue|enum)[^\r\n]*?(?:\{[^\}]*\}\s+)?([a-zA-Z][a-zA-Z0-9:-]*)/g;
  let m;
  while ((m = setRx.exec(text))) out.add(m[1].toLowerCase());
  return [...out];
}

{
  const catalog = JSON.parse(R(CATALOG));
  let bcdForbidden = [];
  let bcdUnknown = [];
  const bcdIds = new Set();
  for (const o of catalog) {
    const steps = [...(o.steps || []), ...(o.restore || [])];
    for (const st of steps) {
      const blob = [st.pwsh, st.cmd].filter((x) => typeof x === 'string').join('\n');
      if (!/bcdedit/i.test(blob)) continue;
      bcdIds.add(o.id);
      const elems = extractBcdElements(blob);
      for (const e of elems) {
        if ([...BCD_FORBIDDEN_ELEMENTS].some((rx) => rx.test(e))) {
          bcdForbidden.push(`${o.id} 的 bcdedit 命令出现禁写元素 ${e}`);
        } else if (!BCD_ALLOWED_ELEMENTS.has(e) && !['bcdedit', 'export', 'import', '/?', '-enum', '-set', '-deletevalue'].includes(e)) {
          bcdUnknown.push(`${o.id} 的 bcdedit 命令出现未登记元素 ${e}`);
        }
      }
    }
  }
  check(bcdForbidden.length === 0, 'BCD 禁写元素（面板不托管）', bcdForbidden.join('；') || '');
  check(bcdUnknown.length === 0, 'BCD 白名单元素登记', bcdUnknown.join('；') || '');
  // T1f-L01：先数 BCD 段的对象数，低于地板说明「白名单逐项对拍」整个没跑（判据失明），
  // 不是「仓库变干净」。地板取自现盘 5 行 BCD 面板（取数命令：`node -e` 扫
  // `optimizer-runtime.json` 里带 `bcdedit` 的项数）。
  const MIN_BCD_ITEMS = 5;
  check(bcdIds.size >= MIN_BCD_ITEMS,
    `BCD 段对象地板（${bcdIds.size} 项 ≥ ${MIN_BCD_ITEMS}）`,
    bcdIds.size >= MIN_BCD_ITEMS ? '' : `只认出 ${bcdIds.size} 项带 bcdedit 的优化项 ⇒ 扫描面失效，不是仓库变干净`);
  // 两条白名单断言：① 5 行 BCD 面板的目标项必须都在目录里（取数命令同上；漏登记 ⇒ 白名单会误判红）；
  // ② 白名单里登记的元素必须真的被数据侧用到（僵尸登记 ⇒ 白名单正在腐烂）。
  const BCD_PANEL_ITEMS = ['nara_bcd_timer', 'nara_bcd_vsm', 'nara_bcd_boot', 'nara_bcd_lowmem', 'nara_bcd_irq'];
  const panelMissing = BCD_PANEL_ITEMS.filter((id) => !bcdIds.has(id));
  check(panelMissing.length === 0,
    'BCD 面板 5 项都在目录里',
    panelMissing.length ? `目录里找不到：${panelMissing.join(', ')}` : '');
  const usedElements = new Set();
  for (const o of catalog) {
    for (const st of [...(o.steps || []), ...(o.restore || [])]) {
      const blob = [st.pwsh, st.cmd].filter((x) => typeof x === 'string').join('\n');
      if (!/bcdedit/i.test(blob)) continue;
      for (const e of extractBcdElements(blob)) usedElements.add(e);
    }
  }
  // 白名单里的 store 标识符（current/globalsettings/default）是 bcdedit 的固定参数，不是元素；
  // 它们不会被 extractBcdElements 当元素抓出来，故不参与僵尸登记检查。
  const STORE_TOKENS = new Set(['current', 'globalsettings', 'default']);
  const zombie = [...BCD_ALLOWED_ELEMENTS].filter((e) => !STORE_TOKENS.has(e) && !usedElements.has(e));
  check(zombie.length === 0,
    'BCD 白名单无僵尸元素',
    zombie.length ? `白名单登记但数据侧已不再出现：${zombie.join(', ')}` : '');
}

// ---------------------------------------------------------------------------
// 侧表 ⇄ 重算 逐条对拍
// ---------------------------------------------------------------------------
const catalog = JSON.parse(R(CATALOG));
const side = JSON.parse(R(SIDE));
const byId = new Map(catalog.map((o) => [o.id, o]));

// T1f-L07：`optimizer-security.json` 声明了 version，但 `rule-schema.json` 没有与它对应的
// 键、Rust 侧（catalog.rs）也只取 items —— 没有任何门禁读它。按现值钉住：删掉字段或
// 静默改版都会红；真升版时改这里，等于强制有人看一眼这张表为什么升版。
const SECURITY_TABLE_VERSION = 1;
check(side.version === SECURITY_TABLE_VERSION,
  `⓪ 侧表 version = ${SECURITY_TABLE_VERSION}（无 schema 对应键，按现值钉住）`,
  `实际 ${JSON.stringify(side.version)}`);

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
  // T1f-L03：writes / why 都从「只查非空」升级为查正文形态 —— 元素类型、`目标 :: 键=值`
  // 形态、以及 why 与所声明的规则之间必须有概念交集（判据见文件头的 writesProblem /
  // whyOffTopic，两者都有合成对照）。
  const bad = [];
  for (const [id, meta] of Object.entries(table)) {
    if (!meta || typeof meta !== 'object') { bad.push(`${id} 不是对象`); continue; }
    if (!['high', 'medium'].includes(meta.level)) bad.push(`${id} level 非法`);
    if (typeof meta.why !== 'string' || meta.why.trim().length < 6) {
      bad.push(`${id} 缺 why`);
    } else {
      const offTopic = whyOffTopic(meta);
      if (offTopic.length) bad.push(`${id} 的 why 与所声明规则 ${offTopic.join('/')} 对不上概念`);
    }
    if (!Array.isArray(meta.writes) || !meta.writes.length) {
      bad.push(`${id} 缺 writes`);
    } else {
      const wBad = meta.writes.map((w) => writesProblem(w)).filter(Boolean);
      if (wBad.length) bad.push(`${id} 的 writes 形态不合法：${wBad.slice(0, 2).join('/')}`);
      // T1f-L03：`writes` 里的键必须真的出现在该 id 的 steps/restore 文本里 —— 侧表写
      // 「改了哪个键」而目录里没有这个键，就是侧表在编事实（人读字段也必须登记 _说明）。
      const opt = byId.get(id);
      const hay = opt
        ? [...(opt.steps || []), ...(opt.restore || [])]
          .map((s) => `${s.cmd || ''} ${s.pwsh || ''} ${s.reg || ''} ${s.service || ''}`).join('\n').toLowerCase()
        : '';
      for (const w of meta.writes) {
        const at = w.lastIndexOf('::');
        const tail = (at >= 0 ? w.slice(at + 2) : w).trim();
        const key = tail.split('=')[0].trim();
        // 通配键（`Disable*=1`）按去掉通配后的前缀判存在。
        const probe = key.replace(/\*+$/, '').toLowerCase();
        if (probe && !hay.includes(probe)) {
          bad.push(`${id} 的 writes 键「${key}」在目录的 steps/restore 里找不到`);
        }
      }
    }
  }
  check(bad.length === 0, '③ 每条带 level(high|medium) / why（与规则同概念） / writes（键=值形态）', bad.join('；'));

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
console.log('对照: 正向/反向规则样本与侧表正文判据每次运行均判红');
process.exit(fail === 0 ? 0 : 1);

#!/usr/bin/env node
// gen-residue-fixture.mjs — 生成 tools/fixtures/residue-contract.json
//
// 为什么要这份夹具（方案 §4.3 第三步 / §6.1）：残留规则的语义校验有**两个实现**
// —— Rust 运行期校验器（唯一运行期真源）与 Node 契约门禁（发布前判红）。
// 两者不许互相调用，只能靠同一组正反例钉住：任何一侧口径漂移，另一侧立刻判红。
// 只加断言不加夹具不算收口（本项目有「假绿」前科，见 AGENTS.md §4）。
//
// 用法：node tools/gen-residue-fixture.mjs   （改完用例重新生成并提交产物）
'use strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'tools', 'fixtures', 'residue-contract.json');

// 按点分路径写值（仅本生成器使用，消费侧读的是静态 JSON）
function set(obj, dotted, value) {
  const keys = dotted.split('.');
  let cur = obj;
  for (const k of keys.slice(0, -1)) {
    if (cur[k] === undefined) cur[k] = /^\d+$/.test(k) ? [] : {};
    cur = cur[k];
  }
  cur[keys[keys.length - 1]] = value;
}
const del = (obj, dotted) => {
  const keys = dotted.split('.');
  let cur = obj;
  for (const k of keys.slice(0, -1)) cur = cur[k];
  delete cur[keys[keys.length - 1]];
};

function basePackage() {
  return {
    rulesVersion: 20260928,
    prov: [{ sourceClass: 'builtin-knowledge', reviewedAt: '2026-09-28' }],
    rules: [
      {
        id: 'fixture-acme',
        // 条目级版本戳：必须等于顶层 rulesVersion（V2 P2-A1）。基线包故意写对，
        // 下面两条用例专门测"缺失"与"不等"，让 Rust 与 Node 谁放宽都会被夹具抓。
        ver: 20260928,
        displayName: ['Acme Editor'],
        publisher: ['Acme Corp'],
        uninstallKey: ['AcmeEditor'],
        residue: [
          { kind: 'folder', target: '%APPDATA%\\Acme\\Editor', note: '用户配置目录' },
          { kind: 'file', target: '%LOCALAPPDATA%\\Acme\\editor.log', note: '运行日志' },
          { kind: 'reg_key', target: 'HKCU\\Software\\Acme\\Editor', note: '当前用户配置键' },
        ],
      },
    ],
    _sig: { alg: 'ed25519', sig: '' },
  };
}

/** 用例：mutate 回调改一处，ok=false 表示必须整包拒绝 */
const cases = [
  { label: '基线合法包', ok: true, mutate: () => {} },
  { label: '顶层未知字段', ok: false, mutate: (p) => set(p, 'extra', 1) },
  { label: '条目缺 ver（版本戳对齐）', ok: false, mutate: (p) => del(p, 'rules.0.ver') },
  { label: '条目 ver 与顶层不等', ok: false, mutate: (p) => set(p, 'rules.0.ver', 20260101) },
  { label: '条目 ver 非数字', ok: false, mutate: (p) => set(p, 'rules.0.ver', '20260928') },
  { label: '规则条目未知字段 recurse', ok: false, mutate: (p) => set(p, 'rules.0.recurse', true) },
  { label: 'residue 条目未知字段 flags', ok: false, mutate: (p) => set(p, 'rules.0.residue.0.flags', 'x') },
  { label: '未知 kind reg_value', ok: false, mutate: (p) => set(p, 'rules.0.residue.2.kind', 'reg_value') },
  { label: '未知 kind shortcut', ok: false, mutate: (p) => set(p, 'rules.0.residue.0.kind', 'shortcut') },
  { label: '三条件组只剩一组（双条件拍板）', ok: false, mutate: (p) => { set(p, 'rules.0.publisher', []); del(p, 'rules.0.uninstallKey'); } },
  { label: '三条件组全空', ok: false, mutate: (p) => { set(p, 'rules.0.displayName', []); set(p, 'rules.0.publisher', []); set(p, 'rules.0.uninstallKey', []); } },
  { label: '合法：恰好两组（放行边界）', ok: true, mutate: (p) => set(p, 'rules.0.publisher', []) },
  { label: 'displayName 不是数组', ok: false, mutate: (p) => set(p, 'rules.0.displayName', 'Acme Editor') },
  { label: '匹配组含空白元素', ok: false, mutate: (p) => set(p, 'rules.0.displayName', ['  ']) },
  { label: '未登记 %TOKEN%', ok: false, mutate: (p) => set(p, 'rules.0.residue.0.target', '%ONEDRIVE%\\Acme\\Editor') },
  { label: 'token 根（无子段）', ok: false, mutate: (p) => set(p, 'rules.0.residue.0.target', '%APPDATA%') },
  { label: 'token 根带尾随分隔符', ok: false, mutate: (p) => set(p, 'rules.0.residue.0.target', '%APPDATA%\\') },
  { label: '路径含通配符', ok: false, mutate: (p) => set(p, 'rules.0.residue.0.target', '%APPDATA%\\Acme*') },
  { label: '相对路径', ok: false, mutate: (p) => set(p, 'rules.0.residue.0.target', 'Acme\\Editor') },
  { label: '路径含 .. 段', ok: false, mutate: (p) => set(p, 'rules.0.residue.0.target', '%APPDATA%\\Acme\\..\\..\\Editor') },
  { label: 'target 首尾含空白', ok: false, mutate: (p) => set(p, 'rules.0.residue.0.target', ' %APPDATA%\\Acme\\Editor') },
  { label: '路径中第二个变量替换', ok: false, mutate: (p) => set(p, 'rules.0.residue.0.target', '%APPDATA%\\Acme\\%USERNAME%') },
  { label: 'note 缺失', ok: false, mutate: (p) => del(p, 'rules.0.residue.0.note') },
  { label: '规则 id 含非法字符', ok: false, mutate: (p) => set(p, 'rules.0.id', 'acme editor/1') },
  { label: '规则 id 重复', ok: false, mutate: (p) => { p.rules.push(structuredClone(p.rules[0])); } },
  { label: 'residue 为空数组', ok: false, mutate: (p) => set(p, 'rules.0.residue', []) },
  { label: 'rules 为空数组', ok: false, mutate: (p) => set(p, 'rules', []) },
  { label: 'prov 缺失', ok: false, mutate: (p) => del(p, 'prov') },
  { label: 'prov 条目含未知字段', ok: false, mutate: (p) => set(p, 'prov.0.note', 'x') },
  { label: 'rulesVersion 非数字', ok: false, mutate: (p) => set(p, 'rulesVersion', '20260928') },
  // 注册表目标：A1 硬否决必须在装载时就生效，而不是等到执行侧
  { label: 'reg_key 目标为 HKLM\\SOFTWARE', ok: false, mutate: (p) => set(p, 'rules.0.residue.2.target', 'HKLM\\SOFTWARE') },
  { label: 'reg_key 目标为 Microsoft 树下系统键', ok: false, mutate: (p) => set(p, 'rules.0.residue.2.target', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run') },
  { label: 'reg_key 目标带 ::值名', ok: false, mutate: (p) => set(p, 'rules.0.residue.2.target', 'HKCU\\Software\\Acme\\Editor::Value') },
  { label: 'reg_key 目标用不支持的 hive', ok: false, mutate: (p) => set(p, 'rules.0.residue.2.target', 'HKCR\\Acme') },
  { label: 'reg_key 目标含变量', ok: false, mutate: (p) => set(p, 'rules.0.residue.2.target', '%APPDATA%\\Acme') },
  // 合法例外形态（放行回测，防「过度收口把功能打死」）
  { label: '合法：HKLM 下产品键', ok: true, mutate: (p) => set(p, 'rules.0.residue.2.target', 'HKLM\\SOFTWARE\\ESET') },
  { label: '合法：Uninstall 下的产品键', ok: true, mutate: (p) => set(p, 'rules.0.residue.2.target', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AcmeEditor') },
  { label: '合法：WOW6432Node 下产品键', ok: true, mutate: (p) => set(p, 'rules.0.residue.2.target', 'HKLM\\SOFTWARE\\WOW6432Node\\Acme') },
  { label: '合法：盘符绝对路径', ok: true, mutate: (p) => set(p, 'rules.0.residue.0.target', 'C:\\Program Files\\Acme\\Editor') },
  { label: '合法：32 位 ProgramFiles 变量', ok: true, mutate: (p) => set(p, 'rules.0.residue.0.target', '%PROGRAMFILES(X86)%\\Acme\\Editor') },
];

// 注册表保护判定向量（方案 §4.3：为当前合法规则建放行回测 + 每个保护类别至少一个反例）
const regVectors = [
  // —— 拒绝：hive 与大类容器 ——
  { target: 'HKLM', blocked: true, cls: 'hive 根' },
  { target: 'HKCU', blocked: true, cls: 'hive 根' },
  { target: 'HKLM\\SOFTWARE', blocked: true, cls: '容器本身' },
  { target: 'HKCU\\Software', blocked: true, cls: '容器本身' },
  { target: 'HKLM\\SYSTEM', blocked: true, cls: '系统单元' },
  { target: 'HKLM\\SAM', blocked: true, cls: '系统单元' },
  { target: 'HKLM\\SOFTWARE\\WOW6432Node', blocked: true, cls: '容器本身' },
  { target: 'HKLM\\SOFTWARE\\Classes', blocked: true, cls: 'COM 命名空间' },
  { target: 'HKCU\\Software\\Classes\\AppID', blocked: true, cls: 'COM 命名空间' },
  { target: 'HKLM\\SOFTWARE\\Clients', blocked: true, cls: '系统命名空间' },
  { target: 'HKLM\\SOFTWARE\\RegisteredApplications', blocked: true, cls: '系统命名空间' },
  { target: 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows', blocked: true, cls: '组策略子树' },
  { target: 'HKCU\\Environment', blocked: true, cls: '环境层（D4 只报告不修改）' },
  { target: 'HKLM\\SOFTWARE\\ODBC\\ODBCINI', blocked: true, cls: '机器级共享' },
  // —— 拒绝：Microsoft 树默认整棵禁（逐条枚举会漏，故反向表达） ——
  { target: 'HKLM\\SOFTWARE\\Microsoft', blocked: true, cls: 'Microsoft 树根' },
  { target: 'HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN', blocked: true, cls: '自启动' },
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\Folders', blocked: true, cls: '安装器台账' },
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced', blocked: true, cls: '枚举漏网靠默认拒绝' },
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList', blocked: true, cls: '用户配置文件表' },
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\acme.exe', blocked: true, cls: 'IFEO 钩子' },
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender', blocked: true, cls: '安全产品' },
  { target: 'HKCU\\Software\\Microsoft\\Windows\\Shell\\MuiCache', blocked: true, cls: 'Shell 缓存' },
  { target: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules', blocked: true, cls: 'SYSTEM 子树覆盖' },
  // —— 拒绝：容器本身（其下叶键另有放行） ——
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall', blocked: true, cls: 'Uninstall 容器本身' },
  { target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths', blocked: true, cls: 'App Paths 容器本身' },
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Tracing', blocked: true, cls: 'Tracing 容器本身' },
  // —— 拒绝：绕过写法与非法形状 ——
  { target: 'HKEY_LOCAL_MACHINE\\SOFTWARE', blocked: true, cls: '长写法别名' },
  { target: 'hkey_local_machine\\software\\microsoft', blocked: true, cls: '小写别名' },
  { target: 'HKLM/SOFTWARE/Microsoft', blocked: true, cls: '斜杠改写' },
  { target: 'HKLM\\SOFTWARE\\', blocked: true, cls: '尾随分隔符' },
  { target: 'HKLM\\SOFTWARE\\.\\Microsoft', blocked: true, cls: '含 . 段' },
  { target: 'HKCR\\Acme', blocked: true, cls: '不支持的 hive' },
  { target: 'HKU\\S-1-5-21-0\\Software', blocked: true, cls: '不支持的 hive' },
  // —— 放行：现存合法产品键（收紧不许误杀） ——
  { target: 'HKLM\\SOFTWARE\\ESET', blocked: false, cls: '产品键' },
  { target: 'HKLM\\SOFTWARE\\360Safe', blocked: false, cls: '产品键' },
  { target: 'HKLM\\SOFTWARE\\Piriform', blocked: false, cls: '产品键' },
  { target: 'HKCU\\Software\\RoboForm', blocked: false, cls: '产品键' },
  { target: 'HKCU\\Software\\Tencent\\WeChat', blocked: false, cls: '产品键' },
  { target: 'HKLM\\SOFTWARE\\WOW6432Node\\ESET', blocked: false, cls: '32 位产品键' },
  { target: 'HKLM\\SOFTWARE\\ESET\\ESET Smart Security', blocked: false, cls: '产品键的下层' },
  // —— 放行：扫描器自身产出的合法候选（收紧后功能必须还在） ——
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VLC media player_is1', blocked: false, cls: '卸载键' },
  { target: 'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{1D180B6A-C6AE-4D6E-A2A8-000000001001}', blocked: false, cls: '32 位卸载键' },
  { target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AcmeEditor', blocked: false, cls: '当前用户卸载键' },
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Tracing\\acme_RASAPI32', blocked: false, cls: 'Tracing 叶键' },
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\acme.exe', blocked: false, cls: 'App Paths 叶键' },
];

const packages = cases.map(({ label, ok, mutate }) => {
  const pkg = basePackage();
  mutate(pkg);
  return { label, ok, pkg };
});

// 自校验：基线必须是放行用例；每条拒绝用例的 id 不许与基线重复（否则会把「id 重复」
// 之外的用例串成同一个失败原因，夹具就失去定位能力）
if (!packages[0].ok) throw new Error('基线用例必须是放行用例');
for (const c of packages.filter((x) => !x.ok)) {
  const dup = c.pkg.rules.length > 1 && !c.label.includes('id 重复');
  if (dup) throw new Error(`用例「${c.label}」意外含多条规则，请改为单条规则表达该缺陷`);
}

const doc = {
  _generatedBy: 'tools/gen-residue-fixture.mjs',
  _note:
    '卸载残留规则库契约夹具：Rust 运行期校验器与 Node 门禁各自独立实现断言，用同一组正反例钉口径（方案 §4.3 / §6.1）。改判定必须两侧同改并在此补用例。',
  regVectors,
  packages,
};
fs.writeFileSync(OUT, JSON.stringify(doc, null, 2) + '\n', 'utf8');
console.log(
  `已生成 ${path.relative(ROOT, OUT)}：regVectors ${regVectors.length} 条（拒绝 ${regVectors.filter((v) => v.blocked).length} / 放行 ${regVectors.filter((v) => !v.blocked).length}），packages ${packages.length} 条（拒绝 ${packages.filter((c) => !c.ok).length} / 放行 ${packages.filter((c) => c.ok).length}）`,
);

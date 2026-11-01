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
import { fileURLToPath, pathToFileURL } from 'node:url';

import { writeFileAtomic } from './lib/atomic-write.mjs';

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
  // Q8 2026-10-06 重拍：reg_value / shortcut 已放行，原「未知 kind」两条用例改造成
  // 新 kind 的边界用例（缺 :: / 值名空 / 键路径系统容器 / Run 系统命名空间 / 双 :: /
  // 变量形态 / 非 .lnk），另补两条放行回测防「过度收口把功能打死」
  { label: 'reg_value 缺 :: 分隔', ok: false, mutate: (p) => set(p, 'rules.0.residue.2.kind', 'reg_value') },
  { label: 'reg_value 值名为空', ok: false, mutate: (p) => { set(p, 'rules.0.residue.2.kind', 'reg_value'); set(p, 'rules.0.residue.2.target', 'HKCU\\Software\\Acme\\Editor::'); } },
  { label: 'reg_value 键路径为系统容器', ok: false, mutate: (p) => { set(p, 'rules.0.residue.2.kind', 'reg_value'); set(p, 'rules.0.residue.2.target', 'HKLM\\SOFTWARE::Acme'); } },
  { label: 'reg_value 键路径在 Run（系统命名空间按键路径否决）', ok: false, mutate: (p) => { set(p, 'rules.0.residue.2.kind', 'reg_value'); set(p, 'rules.0.residue.2.target', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run::Acme AutoStart'); } },
  { label: 'reg_value 含两个 ::', ok: false, mutate: (p) => { set(p, 'rules.0.residue.2.kind', 'reg_value'); set(p, 'rules.0.residue.2.target', 'HKCU\\Software\\Acme::a::b'); } },
  { label: 'reg_value 键路径用变量', ok: false, mutate: (p) => { set(p, 'rules.0.residue.2.kind', 'reg_value'); set(p, 'rules.0.residue.2.target', '%APPDATA%\\Acme::Foo'); } },
  { label: 'reg_value 值名首尾含空白', ok: false, mutate: (p) => { set(p, 'rules.0.residue.2.kind', 'reg_value'); set(p, 'rules.0.residue.2.target', 'HKCU\\Software\\Acme\\Editor::Foo '); } },
  { label: 'shortcut 非 .lnk 后缀', ok: false, mutate: (p) => set(p, 'rules.0.residue.0.kind', 'shortcut') },
  { label: 'shortcut 含通配符', ok: false, mutate: (p) => { set(p, 'rules.0.residue.0.kind', 'shortcut'); set(p, 'rules.0.residue.0.target', '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\*.lnk'); } },
  { label: '合法：reg_value 目标（键路径::值名）', ok: true, mutate: (p) => { set(p, 'rules.0.residue.2.kind', 'reg_value'); set(p, 'rules.0.residue.2.target', 'HKCU\\Software\\Acme\\Editor::InstallDir'); } },
  { label: '合法：shortcut 目标（.lnk）', ok: true, mutate: (p) => { set(p, 'rules.0.residue.0.kind', 'shortcut'); set(p, 'rules.0.residue.0.target', '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Acme Editor.lnk'); } },
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
  // R-1a（2026-10-07）：IFEO 补了 32 位视图（`SOFTWARE\\WOW6432Node\\...`）——
  // 32 位程序的钩子只挂在这棵下，禁删面必须同样拦住它（漏了就等于给新视图开了口子）。
  { target: 'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\acme.exe', blocked: true, cls: 'IFEO 钩子（32 位视图）' },
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender', blocked: true, cls: '安全产品' },
  { target: 'HKCU\\Software\\Microsoft\\Windows\\Shell\\MuiCache', blocked: true, cls: 'Shell 缓存' },
  { target: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules', blocked: true, cls: 'SYSTEM 子树覆盖' },
  // —— 拒绝：容器本身（其下叶键另有放行） ——
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall', blocked: true, cls: 'Uninstall 容器本身' },
  { target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths', blocked: true, cls: 'App Paths 容器本身' },
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Tracing', blocked: true, cls: 'Tracing 容器本身' },
  // —— 拒绝：T1g-M01 补齐「整棵禁删清单 ⇄ 向量」的缺口（原清单里有条目没有向量） ——
  // 为什么必须逐条有向量：Node 门禁 F1 与 Rust `reg_vectors_match_shared_fixture` 都只
  // 遍历向量表，清单条目被删而向量没删时两侧仍全绿 —— 受保护面可以静默缩小到「能删
  // 系统安全单元」。末段是 Windows 命名空间（POLICIES / CLIENTS / NETWORK）的根用
  // 「其下产品键」形态：等值形态还会被 REG_GENERIC_LEAF 兜住，只有下探一层才钉得住清单条目本身。
  { target: 'HKLM\\SECURITY', blocked: true, cls: '系统单元（清单等值）' },
  { target: 'HKLM\\BCD00000000', blocked: true, cls: '系统单元（清单等值）' },
  { target: 'HKLM\\COMPONENTS', blocked: true, cls: '系统单元（清单等值）' },
  { target: 'HKLM\\DRIVERS', blocked: true, cls: '系统单元（清单等值）' },
  { target: 'HKLM\\HARDWARE', blocked: true, cls: '系统单元（清单等值）' },
  { target: 'HKCU\\Software\\Policies\\Acme', blocked: true, cls: '组策略子树（其下产品键）' },
  { target: 'HKLM\\SOFTWARE\\WOW6432Node\\Policies\\Acme', blocked: true, cls: '组策略子树（32 位重定向，其下产品键）' },
  { target: 'HKCU\\Software\\Clients\\Mail\\Acme', blocked: true, cls: '客户端命名空间（其下产品键）' },
  { target: 'HKLM\\SOFTWARE\\Khronos', blocked: true, cls: '图形接口登记（清单等值）' },
  { target: 'HKLM\\SOFTWARE\\OpenGL', blocked: true, cls: '图形接口登记（清单等值）' },
  { target: 'HKCU\\Network\\Acme', blocked: true, cls: '用户网络映射（其下项）' },
  { target: 'HKCU\\Volatile Environment', blocked: true, cls: '环境层（清单等值）' },
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
  // T1g-M01：Microsoft 树叶放行表里原本有若干条没有任何向量 —— 删掉清单条目时门禁不会红，
  // 「能删什么」被悄悄收紧或放宽都无信号。逐条给一条「其下产品键」的放行向量。
  { target: 'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\acme.exe', blocked: false, cls: 'App Paths 叶键（32 位视图）' },
  { target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\acme.exe', blocked: false, cls: 'App Paths 叶键（当前用户）' },
  { target: 'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Tracing\\acme_RASAPI32', blocked: false, cls: 'Tracing 叶键（32 位视图）' },
  // R-1a 的**非 IFEO 正对照**：产品键路径里**含** "Image File Execution Options" 字样，
  // 但它不在系统 IFEO 那棵树下 ⇒ 必须放行。这条钉的是「判据认全路径、不是认子串」——
  // 只按关键字匹配的实现会在这里红。
  { target: 'HKLM\\SOFTWARE\\Acme\\Image File Execution Options\\acme.exe', blocked: false, cls: '非 IFEO 路径（同名字样的产品键）' },
];

// R-2（2026-10-07）启动项**删值**窄口子的正负样本（方案 §2.3 R-2 第 2 条）。
//
// 为什么必须进共享夹具：这是本仓第二处「A1 让路」，而且它开的是一棵**系统命名空间**
// （`…\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`）的删除面。判据有**两个独立实现**
// —— Rust `run_keys::reg_value_gate`（执行侧与快照白名单的真源）与 Node 门禁里的
// 独立实现（`check-residue-rule-contract.mjs` 的 F2）—— 两者谁也不调谁，只能靠
// 同一份字节钉住。任一侧放宽都会在这里红（第 3 条：Rust 判定与 Node 门禁读同一份夹具）。
//
// `gate` 取值即三态语义：allowed / denied / not-governed。
const runValueVectors = [
  // —— 放行：六条根 × 具名单值（现读复检不在这层，由执行侧另行现查） ——
  { target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run::Acme AutoStart', gate: 'allowed', cls: 'HKCU Run 具名值' },
  { target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce::Acme', gate: 'allowed', cls: 'HKCU RunOnce 具名值' },
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run::Acme', gate: 'allowed', cls: 'HKLM 64 位 Run' },
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce::Acme', gate: 'allowed', cls: 'HKLM 64 位 RunOnce' },
  { target: 'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run::Acme', gate: 'allowed', cls: 'HKLM 32 位 Run' },
  { target: 'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce::Acme', gate: 'allowed', cls: 'HKLM 32 位 RunOnce' },
  { target: 'HKEY_CURRENT_USER\\Software\\MICROSOFT\\windows\\currentversion\\run::Acme', gate: 'allowed', cls: '长写法 + 大小写混写归一后放行' },
  // —— 拒绝：父键是 Run 根但形态不合格（每一种都对应一条显式判据） ——
  { target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run::', gate: 'denied', cls: '值名为空' },
  { target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run::   ', gate: 'denied', cls: '值名纯空白' },
  { target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run::*', gate: 'denied', cls: '通配清值' },
  { target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run::Acme ', gate: 'denied', cls: '值名尾随空白' },
  { target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run:: Acme', gate: 'denied', cls: '值名前导空白' },
  { target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run::a\\b', gate: 'denied', cls: '值名含反斜杠（多层）' },
  { target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run::a::b', gate: 'denied', cls: '值名含 ::' },
  // —— 拒绝：Microsoft 树内、但不是那六条根（反向兜底，防「新增扫描组 = 无声多一条删除面」） ——
  { target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx::Acme', gate: 'denied', cls: 'RunOnceEx 不在本轮范围' },
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices::Acme', gate: 'denied', cls: 'RunServices 不在本轮范围' },
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Sub::Acme', gate: 'denied', cls: '更深一层不是根' },
  { target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU::X', gate: 'denied', cls: 'Microsoft 树内其它叶子' },
  { target: 'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx::Acme', gate: 'denied', cls: '32 位视图的 RunOnceEx' },
  // —— 不管辖：不在 Microsoft 树内、也不是 Run 值 ——
  // 这三条是**既有三类候选的替身**：它们必须保持 NotGoverned，否则 R-2 会把
  // MuiCache / 防火墙 / BAM 一起误拒（功能 100% 不可用）。
  { target: 'HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache::acme.exe.FriendlyAppName', gate: 'not-governed', cls: 'MuiCache（既有候选）' },
  { target: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules::{GUID-1}', gate: 'not-governed', cls: '防火墙规则（既有候选）' },
  { target: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\S-1-5-21-0::C:\\Gone\\a.exe', gate: 'not-governed', cls: 'BAM（既有候选）' },
  { target: 'HKCU\\Software\\Acme\\Editor::InstallDir', gate: 'not-governed', cls: '普通 HKCU 产品键值' },
  { target: 'HKLM\\SOFTWARE\\ESET::InstallDir', gate: 'not-governed', cls: '普通 HKLM 产品键值' },
  // —— 不管辖：根本不是「键::值名」形态（键目标/形状坏） ——
  { target: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', gate: 'not-governed', cls: '键目标（该走删树分支与 A1）' },
  { target: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\', gate: 'not-governed', cls: '尾随分隔符归一化失败附近形态（无 ::）' },
  // —— 拒绝：父键无法归一化（fail-closed，不许因「判不出来」而放行） ——
  { target: 'HKCR\\Acme::X', gate: 'denied', cls: '不支持的 hive' },
  { target: 'HKCU\\Software\\.\\Microsoft::X', gate: 'denied', cls: '含 . 段' },
  { target: 'HKCU\\Software\\Acme\\..\\Microsoft::X', gate: 'denied', cls: '含 .. 段' },
];

// T1g-L05：每条反例必须声明「应当被哪条断言拒」。旧夹具只钉 ok=false，
// 某条断言被删后包被另一条规则顺手拒掉仍绿；mustTrigger 取校验器拒因里的
// 稳定子串，Node 门禁按它断言命中（与 cleanup 侧 mustTrigger 同构）。
function triggerFor(label) {
  const table = [
    [/^顶层未知字段$/, '顶层 未知字段'],
    [/^条目缺 ver/, '缺条目级版本戳'],
    [/^条目 ver/, '与顶层 rulesVersion'],
    [/^规则条目未知字段/, '未知字段'],
    [/^residue 条目未知字段/, 'residue 未知字段'],
    [/^reg_value 缺 ::/, '恰好一个 ::'],
    [/^reg_value 值名为空/, '值名为空'],
    [/^reg_value 键路径为系统容器/, '受保护容器'],
    [/^reg_value 键路径在 Run/, '系统命名空间'],
    [/^reg_value 含两个/, '恰好一个 ::'],
    [/^reg_value 键路径用变量/, '不允许变量形态'],
    [/^reg_value 值名首尾/, '首尾含空白'],
    [/^shortcut 非/, '必须是 .lnk'],
    [/^shortcut 含通配符/, '目标含通配符'],
    [/^三条件组/, '三条件组只有'],
    [/^displayName 不是数组/, 'displayName 不是数组'],
    [/^匹配组含空白/, '含空白或超长条目'],
    [/^未登记 %TOKEN%/, '未登记'],
    [/^token 根/, '禁止 token 根'],
    [/^路径含通配符/, '目标含通配符'],
    [/^相对路径/, '既不是登记变量的子路径'],
    [/^路径含 \.\./, '含空段'],
    [/^target 首尾/, '首尾含空白'],
    [/^路径中第二个变量/, '第二个变量替换'],
    [/^note 缺失/, 'residue.note 缺失'],
    [/^规则 id 含非法/, '规则 id 缺失'],
    [/^规则 id 重复/, '规则 id 重复'],
    [/^residue 为空/, 'residue 缺失'],
    [/^rules 为空/, 'rules 缺失'],
    [/^prov 缺失/, 'prov 缺失'],
    [/^prov 条目含未知字段/, 'prov 未知字段'],
    [/^rulesVersion 非数字/, 'rulesVersion 缺失'],
    [/^reg_key 目标为 HKLM/, '受保护容器'],
    [/^reg_key 目标为 Microsoft/, '系统命名空间'],
    [/^reg_key 目标带 ::值名/, '::值名'],
    [/^reg_key 目标用不支持的 hive/, 'hive 只支持'],
    [/^reg_key 目标含变量/, '变量形态'],
  ];
  const hit = table.find(([re]) => re.test(label));
  return hit ? hit[1] : '';
}

const packages = cases.map(({ label, ok, mutate }) => {
  const pkg = basePackage();
  mutate(pkg);
  return ok ? { label, ok, pkg } : { label, ok, pkg, mustTrigger: triggerFor(label) };
});

// 自校验：基线必须是放行用例；每条拒绝用例的 id 不许与基线重复（否则会把「id 重复」
// 之外的用例串成同一个失败原因，夹具就失去定位能力）
if (!packages[0].ok) throw new Error('基线用例必须是放行用例');
for (const c of packages.filter((x) => !x.ok)) {
  const dup = c.pkg.rules.length > 1 && !c.label.includes('id 重复');
  if (dup) throw new Error(`用例「${c.label}」意外含多条规则，请改为单条规则表达该缺陷`);
  if (!c.mustTrigger) throw new Error(`反例「${c.label}」没有 mustTrigger 登记（新增反例必须写明应命中哪条断言）`);
}

const doc = {
  _generatedBy: 'tools/gen-residue-fixture.mjs',
  _note:
    '卸载残留规则库契约夹具：Rust 运行期校验器与 Node 门禁各自独立实现断言，用同一组正反例钉口径（方案 §4.3 / §6.1）。改判定必须两侧同改并在此补用例。',
  regVectors,
  runValueVectors,
  packages,
};
const docText = `${JSON.stringify(doc, null, 2)}\n`;

/** 夹具文本（唯一实现）：check-fixture-freshness.mjs import 同一份做逐字节对拍（T1c-M05）。
 *  import 本模块只做纯计算不落盘——写盘仅发生在直跑路径。 */
export function fixtureText() {
  return docText;
}

// 只有「被直接执行」时才落盘/校验：被 check-fixture-freshness.mjs import 时只借
// fixtureText()，不许有落盘副作用（同 gen-finder-delete-modes 的纪律）。
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.includes('--check')) {
    const have = fs.readFileSync(OUT, 'utf8');
    if (have !== docText) {
      console.error('✗ 盘上 residue-contract.json 与生成器输出不一致——夹具被手改或用例改后未重跑。重跑：node tools/gen-residue-fixture.mjs');
      process.exit(1);
    }
    console.log(`✓ residue-contract.json 与生成器输出逐字节一致（packages ${packages.length} / regVectors ${regVectors.length}）`);
    process.exit(0);
  }
  writeFileAtomic(OUT, docText);
  console.log(
    `已生成 ${path.relative(ROOT, OUT)}：regVectors ${regVectors.length} 条（拒绝 ${regVectors.filter((v) => v.blocked).length} / 放行 ${regVectors.filter((v) => !v.blocked).length}），runValueVectors ${runValueVectors.length} 条（放行 ${runValueVectors.filter((v) => v.gate === 'allowed').length} / 拒绝 ${runValueVectors.filter((v) => v.gate === 'denied').length} / 不管辖 ${runValueVectors.filter((v) => v.gate === 'not-governed').length}），packages ${packages.length} 条（拒绝 ${packages.filter((c) => !c.ok).length} / 放行 ${packages.filter((c) => c.ok).length}）`,
  );
}

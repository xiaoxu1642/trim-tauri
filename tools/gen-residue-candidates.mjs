#!/usr/bin/env node
// gen-residue-candidates.mjs — 卸载残留规则候选生成器（dev-only，方案 HiBit 借鉴 v2 §2.2）
//
// 【定位】草案产线，不是门禁：只读探测 + 输出规范化草案，**绝不写 uninstall-residue-rules.json**。
// 不入 check-gate-roster 台账（与 gen-* 系列同姿势）；入库判据唯一真源是
// check-residue-rule-contract.mjs（A2 语义校验 + 注册表硬否决 + 验签），本文件的预校验
// 只是「把明知会被拒的候选挡在草案外」的降噪措施，与门禁判定器刻意不共享实现——
// 草案即便漏放，并入后门禁照样红，不会静默进库。
//
// 【合规硬约束】（方案 §2.2 拍板，写死）：
// 1. **不引入 HiBit 的 LOCALDB 数据本身**（版权与验证责任都在我们这边）；本文件的
//    KNOWLEDGE 表只登记公开安装惯例下的字段模板（安装目录 / 用户配置目录 / 厂商键），
//    与 HiBit 的条目不逐字对表；对照关系只有「高产程序名单」这一层统计结论。
// 2. 草案必须**人工审核**后才并库：逐条确认形状过 A2、无系统容器、无本机私有路径。
//    并入时剥掉 `_` 前缀的草案标签字段（_probe/_why/_mode），规则库 schema 拒绝未知字段。
// 3. 生成器只读不写、不删任何东西；唯一写盘动作是 --out 指定的草案文件。
//
// 【探测面与 A1 的边界】（§2.1 第 7 步「否决判据按键路径」的推论，生成器照此收敛）：
// - reg_value 的 Run/RunOnce 面：键路径落在 HKCU\Software\Microsoft 树下，被注册表
//   硬否决整棵拦住——探测到也不产出（excluded 里留痕）；
// - MSI 注册表 Components 面（HKLM\...\Installer\UserData\...\Components）：同被
//   Microsoft 树硬否决——不产出；
// - MSI 缓存的**文件系统**面不受影响（%WINDIR%\Installer\{GUID}、Package Cache、
//   Downloaded Installations 均不在 protect 清单），folder 候选正常产出。
//
// 用法：
//   node tools/gen-residue-candidates.mjs                    # 知识模板 + 本机探测 → stdout
//   node tools/gen-residue-candidates.mjs --out <file>       # 同上，另写草案文件
//   node tools/gen-residue-candidates.mjs --lib-only         # 只输出知识模板候选（不探测本机）
//   node tools/gen-residue-candidates.mjs --probe-only       # 只探测本机（不含知识模板）
'use strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const RULES = path.join(ROOT, 'src-tauri', 'data', 'uninstall-residue-rules.json');

// 与 rule-schema.json residue 段对齐的上限（草案逐条预检；改 schema 后这里要人工同步）
const LIMITS = { maxRules: 400, maxResiduePerRule: 64, maxTargetLen: 260, maxSegments: 32, maxNoteLen: 40 };
const TOKENS = ['APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA', 'PROGRAMFILES', 'PROGRAMFILES(X86)', 'PROGRAMW6432', 'COMMONPROGRAMFILES', 'USERPROFILE', 'WINDIR', 'SYSTEMROOT'];
const KIND_ORDER = { folder: 0, file: 1, shortcut: 2, reg_key: 3, reg_value: 4 };

// ==================== 高产程序知识模板（公开安装惯例，人工维护） ====================
// 每条：id（slug 写死，中文品牌用英文惯称）/ displayName 别名 / publisher / uninstallKey /
// residue 字段模板。目标一律 token 形态；「(x86)」标记表示 32 位安装惯例。
// note ≤40 字中文短句。MSI/GUID 缓存面不进知识表——GUID 逐机不同，只走本机探测。
const KNOWLEDGE = [
  {
    id: 'residue-idm', displayName: ['IDM', 'Internet Download Manager'], publisher: ['Tonec'],
    uninstallKey: ['Internet Download Manager'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\Internet Download Manager', note: '安装目录（32 位安装惯例）' },
      { kind: 'folder', target: '%APPDATA%\\IDM', note: '用户配置目录（含下载队列与站点凭据库）' },
    ],
  },
  {
    id: 'residue-bitdefender', displayName: ['Bitdefender'], publisher: ['Bitdefender'],
    uninstallKey: ['Bitdefender'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES%\\Bitdefender', note: '安装目录' },
      { kind: 'folder', target: '%PROGRAMDATA%\\Bitdefender', note: '全局数据目录（隔离区与日志索引）' },
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\Bitdefender', note: '安装目录（32 位组件）' },
      { kind: 'reg_key', target: 'HKLM\\SOFTWARE\\Bitdefender', note: '主程序配置键' },
    ],
  },
  {
    id: 'residue-avg', displayName: ['AVG'], publisher: ['AVG Technologies'],
    uninstallKey: ['AVG'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES%\\AVG', note: '安装目录' },
      { kind: 'folder', target: '%PROGRAMDATA%\\AVG', note: '全局数据目录' },
      { kind: 'reg_key', target: 'HKLM\\SOFTWARE\\AVG', note: '主程序配置键' },
    ],
  },
  {
    id: 'residue-nordvpn', displayName: ['NordVPN'], publisher: ['Nord Security', 'NordVPN'],
    uninstallKey: ['NordVPN'],
    residue: [
      { kind: 'folder', target: '%LOCALAPPDATA%\\NordVPN', note: '用户数据目录（缓存与连接日志）' },
      { kind: 'folder', target: '%PROGRAMFILES%\\NordVPN', note: '安装目录' },
      { kind: 'reg_key', target: 'HKCU\\Software\\NordVPN', note: '当前用户配置键' },
    ],
  },
  {
    id: 'residue-adguard', displayName: ['AdGuard'], publisher: ['AdGuard'],
    uninstallKey: ['AdGuard'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\AdGuard', note: '安装目录（32 位安装惯例）' },
      { kind: 'folder', target: '%PROGRAMDATA%\\AdGuard', note: '全局数据目录（过滤日志与统计）' },
      { kind: 'reg_key', target: 'HKCU\\Software\\AdGuard', note: '当前用户配置键' },
    ],
  },
  {
    id: 'residue-protonvpn', displayName: ['Proton VPN', 'ProtonVPN'], publisher: ['Proton'],
    uninstallKey: ['Proton VPN'],
    residue: [
      { kind: 'folder', target: '%LOCALAPPDATA%\\Proton\\Proton VPN', note: '用户数据目录（Proton 套件子目录）' },
      { kind: 'folder', target: '%PROGRAMFILES%\\Proton\\Proton VPN', note: '安装目录（Proton 套件目录布局）' },
      { kind: 'reg_key', target: 'HKCU\\Software\\Proton', note: '当前用户配置键（套件级）' },
    ],
  },
  {
    id: 'residue-anydesk', displayName: ['AnyDesk'], publisher: ['AnyDesk Software'],
    uninstallKey: ['AnyDesk'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\AnyDesk', note: '安装目录（32 位安装惯例）' },
      { kind: 'folder', target: '%PROGRAMDATA%\\AnyDesk', note: '全局数据目录（连接日志与痕迹）' },
      { kind: 'folder', target: '%APPDATA%\\AnyDesk', note: '用户配置目录' },
      { kind: 'reg_key', target: 'HKLM\\SOFTWARE\\AnyDesk', note: '主程序配置键' },
    ],
  },
  {
    id: 'residue-teamviewer', displayName: ['TeamViewer'], publisher: ['TeamViewer'],
    uninstallKey: ['TeamViewer'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\TeamViewer', note: '安装目录（32 位安装惯例）' },
      { kind: 'folder', target: '%APPDATA%\\TeamViewer', note: '用户配置目录' },
      { kind: 'reg_key', target: 'HKCU\\Software\\TeamViewer', note: '当前用户配置键' },
    ],
  },
  {
    id: 'residue-skype', displayName: ['Skype'], publisher: ['Microsoft', 'Skype'],
    uninstallKey: ['Skype'],
    residue: [
      { kind: 'folder', target: '%APPDATA%\\Skype', note: '用户数据目录（聊天记录与缓存）' },
      { kind: 'folder', target: '%LOCALAPPDATA%\\Skype', note: '用户缓存目录' },
    ],
  },
  {
    id: 'residue-pidgin', displayName: ['Pidgin'], publisher: ['Pidgin'],
    uninstallKey: ['Pidgin'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\Pidgin', note: '安装目录（32 位安装惯例）' },
      { kind: 'folder', target: '%APPDATA%\\.purple', note: '用户数据目录（libpurple 账号与日志）' },
    ],
  },
  {
    id: 'residue-winrar', displayName: ['WinRAR'], publisher: ['RARLAB', 'win.rar'],
    uninstallKey: ['WinRAR'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES%\\WinRAR', note: '安装目录' },
      { kind: 'folder', target: '%APPDATA%\\WinRAR', note: '用户配置目录' },
    ],
  },
  {
    id: 'residue-7zip', displayName: ['7-Zip'], publisher: ['Igor Pavlov'],
    uninstallKey: ['7-Zip'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES%\\7-Zip', note: '安装目录（64 位）' },
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\7-Zip', note: '安装目录（32 位）' },
    ],
  },
  {
    id: 'residue-notepad-plus-plus', displayName: ['Notepad++'], publisher: ['Notepad++', 'Don HO'],
    uninstallKey: ['Notepad++'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES%\\Notepad++', note: '安装目录' },
      { kind: 'folder', target: '%APPDATA%\\Notepad++', note: '用户配置目录（含插件配置）' },
    ],
  },
  {
    id: 'residue-vlc', displayName: ['VLC media player', 'VLC'], publisher: ['VideoLAN'],
    uninstallKey: ['VLC'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES%\\VideoLAN\\VLC', note: '安装目录' },
      { kind: 'folder', target: '%APPDATA%\\vlc', note: '用户配置目录（ML.xspf 与缓存）' },
    ],
  },
  {
    id: 'residue-irfanview', displayName: ['IrfanView'], publisher: ['Irfan Skiljan'],
    uninstallKey: ['IrfanView'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\IrfanView', note: '安装目录（32 位安装惯例）' },
      { kind: 'folder', target: '%APPDATA%\\IrfanView', note: '用户配置目录' },
    ],
  },
  {
    id: 'residue-discord', displayName: ['Discord'], publisher: ['Discord Inc.'],
    uninstallKey: ['Discord'],
    residue: [
      { kind: 'folder', target: '%APPDATA%\\discord', note: '用户数据目录（Chromium 内核缓存）' },
      { kind: 'folder', target: '%LOCALAPPDATA%\\Discord', note: '应用本体与更新缓存（Update.exe 布局）' },
    ],
  },
  {
    id: 'residue-telegram', displayName: ['Telegram Desktop', 'Telegram'], publisher: ['Telegram FZ-LLC', 'Telegram'],
    uninstallKey: ['Telegram Desktop'],
    residue: [
      { kind: 'folder', target: '%APPDATA%\\Telegram Desktop', note: '用户数据目录（会话与媒体缓存）' },
      { kind: 'folder', target: '%LOCALAPPDATA%\\Telegram Desktop', note: '更新缓存目录' },
    ],
  },
  {
    id: 'residue-steam', displayName: ['Steam'], publisher: ['Valve'],
    uninstallKey: ['Steam'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\Steam', note: '安装目录（含库文件，删前确认游戏已迁走）' },
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\Steam\\steamapps\\shadercache', note: '着色器缓存（可独立清理）' },
    ],
  },
  {
    id: 'residue-epic-games', displayName: ['Epic Games Launcher', 'Epic Games'], publisher: ['Epic Games'],
    uninstallKey: ['Epic Games Launcher'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\Epic Games', note: '安装目录（含已装游戏，删前确认）' },
      { kind: 'folder', target: '%LOCALAPPDATA%\\EpicGamesLauncher', note: '启动器缓存目录' },
      { kind: 'folder', target: '%LOCALAPPDATA%\\Epic Games Launcher', note: '启动器缓存目录（空格命名变体）' },
    ],
  },
  {
    id: 'residue-obs-studio', displayName: ['OBS Studio', 'Open Broadcaster Software'], publisher: ['OBS Project'],
    uninstallKey: ['OBS Studio'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES%\\obs-studio', note: '安装目录' },
      { kind: 'folder', target: '%APPDATA%\\obs-studio', note: '用户配置目录（场景集与插件）' },
    ],
  },
  {
    id: 'residue-spotify', displayName: ['Spotify'], publisher: ['Spotify'],
    uninstallKey: ['Spotify'],
    residue: [
      { kind: 'folder', target: '%APPDATA%\\Spotify', note: '应用本体与缓存目录' },
      { kind: 'folder', target: '%LOCALAPPDATA%\\Spotify', note: '更新缓存目录' },
    ],
  },
  {
    id: 'residue-zoom', displayName: ['Zoom'], publisher: ['Zoom Video Communications'],
    uninstallKey: ['Zoom'],
    residue: [
      { kind: 'folder', target: '%APPDATA%\\Zoom', note: '用户数据目录（会议记录与日志）' },
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\Zoom', note: '安装目录（32 位安装惯例）' },
    ],
  },
  {
    id: 'residue-slack', displayName: ['Slack'], publisher: ['Slack Technologies'],
    uninstallKey: ['Slack'],
    residue: [
      { kind: 'folder', target: '%APPDATA%\\Slack', note: '用户数据目录（Chromium 内核缓存）' },
      { kind: 'folder', target: '%LOCALAPPDATA%\\Slack', note: '更新缓存目录' },
    ],
  },
  {
    id: 'residue-foxit', displayName: ['Foxit'], publisher: ['Foxit Software'],
    uninstallKey: ['Foxit'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\Foxit Software', note: '安装目录（以发行商命名）' },
      { kind: 'folder', target: '%APPDATA%\\Foxit Software', note: '用户配置目录' },
    ],
  },
  {
    id: 'residue-sumatrapdf', displayName: ['SumatraPDF'], publisher: ['Krzysztof Kowalczyk'],
    uninstallKey: ['SumatraPDF'],
    residue: [
      { kind: 'folder', target: '%LOCALAPPDATA%\\SumatraPDF', note: '用户数据目录（设置与缓存）' },
    ],
  },
  {
    id: 'residue-sublime-text', displayName: ['Sublime Text'], publisher: ['Sublime HQ'],
    uninstallKey: ['Sublime Text'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES%\\Sublime Text', note: '安装目录' },
      { kind: 'folder', target: '%APPDATA%\\Sublime Text', note: '用户配置目录（包与许可证）' },
    ],
  },
  {
    id: 'residue-vscode', displayName: ['Visual Studio Code', 'Microsoft Visual Studio Code'], publisher: ['Microsoft'],
    uninstallKey: ['Visual Studio Code'],
    residue: [
      { kind: 'folder', target: '%LOCALAPPDATA%\\Programs\\Microsoft VS Code', note: '用户级安装目录（默认装此处）' },
      { kind: 'folder', target: '%APPDATA%\\Code', note: '用户数据目录（扩展与工作区缓存）' },
    ],
  },
  {
    id: 'residue-git-windows', displayName: ['Git'], publisher: ['The Git Development Community'],
    uninstallKey: ['Git', 'Git_is1'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES%\\Git', note: '安装目录' },
    ],
  },
  {
    id: 'residue-gimp', displayName: ['GIMP'], publisher: ['GIMP'],
    uninstallKey: ['GIMP'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES%\\GIMP 2', note: '安装目录（GIMP 2 系列）' },
      { kind: 'folder', target: '%APPDATA%\\GIMP', note: '用户配置目录（笔刷与插件配置）' },
    ],
  },
  {
    id: 'residue-audacity', displayName: ['Audacity'], publisher: ['Audacity'],
    uninstallKey: ['Audacity'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES%\\Audacity', note: '安装目录' },
      { kind: 'folder', target: '%APPDATA%\\Audacity', note: '用户配置目录' },
    ],
  },
  {
    id: 'residue-k-lite', displayName: ['K-Lite Codec Pack'], publisher: ['Codec Guide'],
    uninstallKey: ['K-Lite Codec Pack'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\K-Lite Codec Pack', note: '安装目录（32 位安装惯例）' },
    ],
  },
  {
    id: 'residue-netease-music', displayName: ['网易云音乐', 'CloudMusic'], publisher: ['NetEase', '网易'],
    uninstallKey: ['CloudMusic'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\Netease\\CloudMusic', note: '安装目录' },
      { kind: 'folder', target: '%APPDATA%\\Netease\\CloudMusic', note: '用户数据目录（歌单缓存）' },
    ],
  },
  {
    id: 'residue-baidu-netdisk', displayName: ['百度网盘', 'BaiduNetdisk'], publisher: ['Baidu', '百度'],
    uninstallKey: ['BaiduNetdisk'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\BaiduNetdiskDownload', note: '默认下载目录（删前确认文件已迁移）' },
      { kind: 'folder', target: '%APPDATA%\\BaiduNetdisk', note: '用户配置目录' },
    ],
  },
  {
    id: 'residue-thunder', displayName: ['迅雷', 'Thunder'], publisher: ['Xunlei', '迅雷'],
    uninstallKey: ['Thunder'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\Thunder', note: '安装目录' },
      { kind: 'folder', target: '%APPDATA%\\Thunder', note: '用户数据目录（任务记录）' },
    ],
  },
  {
    id: 'residue-wps-office', displayName: ['WPS Office'], publisher: ['Kingsoft', '金山'],
    uninstallKey: ['WPS Office', 'Kingsoft Office'],
    residue: [
      { kind: 'folder', target: '%LOCALAPPDATA%\\Kingsoft\\WPS Office', note: '安装目录（用户级布局）' },
      { kind: 'folder', target: '%APPDATA%\\kingsoft', note: '用户配置目录' },
      { kind: 'shortcut', target: '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\WPS Office.lnk', note: '开始菜单快捷方式残留' },
      { kind: 'shortcut', target: '%USERPROFILE%\\Desktop\\WPS Office.lnk', note: '桌面快捷方式残留' },
      { kind: 'reg_key', target: 'HKCU\\Software\\Kingsoft', note: '当前用户配置键' },
    ],
  },
  {
    id: 'residue-snipaste', displayName: ['Snipaste'], publisher: ['Le Liu'],
    uninstallKey: ['Snipaste'],
    residue: [
      { kind: 'folder', target: '%APPDATA%\\Snipaste', note: '用户配置目录' },
    ],
  },
  {
    id: 'residue-meeting-teams', displayName: ['Microsoft Teams'], publisher: ['Microsoft'],
    uninstallKey: ['Microsoft Teams'],
    residue: [
      { kind: 'folder', target: '%LOCALAPPDATA%\\Microsoft\\Teams', note: '经典版缓存目录（new Teams 不落此处）' },
    ],
  },
  {
    id: 'residue-qq-music', displayName: ['QQ音乐', 'QQMusic'], publisher: ['Tencent', '腾讯'],
    uninstallKey: ['QQMusic'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\Tencent\\QQMusic', note: '安装目录' },
      { kind: 'folder', target: '%APPDATA%\\Tencent\\QQMusic', note: '用户数据目录（歌曲缓存）' },
    ],
  },
  {
    id: 'residue-iqiyi', displayName: ['爱奇艺', 'iQIYI'], publisher: ['iQIYI', '爱奇艺'],
    uninstallKey: ['iQIYI'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\IQIYI Video', note: '安装目录' },
      { kind: 'folder', target: '%APPDATA%\\IQIYI Video', note: '用户数据目录（视频缓存）' },
    ],
  },
  {
    id: 'residue-bandizip', displayName: ['Bandizip'], publisher: ['Bandisoft'],
    uninstallKey: ['Bandizip'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES%\\Bandizip', note: '安装目录' },
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\Bandizip', note: '安装目录（32 位版本）' },
    ],
  },
  {
    id: 'residue-meitu', displayName: ['美图秀秀', 'Meitu'], publisher: ['Meitu', '美图'],
    uninstallKey: ['Meitu'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\Meitu', note: '安装目录' },
      { kind: 'folder', target: '%APPDATA%\\Meitu', note: '用户配置目录' },
    ],
  },
  {
    id: 'residue-360zip', displayName: ['360压缩'], publisher: ['奇虎', 'Qihoo 360'],
    uninstallKey: ['360zip'],
    residue: [
      { kind: 'folder', target: '%PROGRAMFILES(X86)%\\360\\360zip', note: '安装目录' },
      { kind: 'reg_key', target: 'HKCU\\Software\\360Zip', note: '当前用户配置键' },
    ],
  },
];

// ==================== 本机探测（reg.exe 只读枚举） ====================

const UNINSTALL_ROOTS = [
  'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
  'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
  'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
];

// 中文系统上 reg query 的管道输出是 GBK，Node 零依赖解不了（乱码 displayName 会污染草案）。
// 改走 reg export：.reg 文件是 UTF-16LE，Node 原生 utf16le 解码；每根一次导出，快且无编码坑。
// 临时文件写在 os.tmpdir()，读完即删（dev 工具自清理，不在用户数据目录留痕）。
function exportRoot(root) {
  const tmp = path.join(os.tmpdir(), `trim-residue-probe-${process.pid}-${Math.random().toString(36).slice(2)}.reg`);
  try {
    execFileSync('reg', ['export', root, tmp, '/y'], { encoding: 'utf8', timeout: 30_000, stdio: ['ignore', 'pipe', 'ignore'] });
    const text = fs.readFileSync(tmp, 'utf16le');
    return text;
  } catch {
    return '';
  } finally {
    try { fs.unlinkSync(tmp); } catch { /* 文件没生成也算导出失败，已兜底返回空串 */ }
  }
}

/** 解析 .reg 文本 → [{ keyPath, values: {name: string} }]（只认 REG_SZ 的字符串值） */
function parseRegExport(text) {
  const out = [];
  let cur = null;
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith('[')) {
      cur = { keyPath: line.replace(/^\[|\]$/g, ''), values: {} };
      out.push(cur);
      continue;
    }
    if (!cur) continue;
    const m = line.match(/^"([^"]+)"="(.*)"$/);
    if (m) cur.values[m[1]] = m[2];
  }
  return out;
}

/** 枚举一个卸载根：返回 [{ keyName, displayName, publisher, installLocation, systemComponent, windowsInstaller }] */
function enumUninstallRoot(root) {
  const hivePrefix = root.split('\\')[0]; // HKLM / HKCU（.reg 键路径用长名，解析时归一）
  const items = [];
  for (const { keyPath, values } of parseRegExport(exportRoot(root))) {
    const idx = keyPath.toLowerCase().lastIndexOf('uninstall\\');
    if (idx < 0) continue;
    const sub = keyPath.slice(idx + 'uninstall\\'.length);
    if (!sub) continue;
    items.push({
      keyName: sub,
      displayName: values.DisplayName || '',
      publisher: values.Publisher || '',
      installLocation: values.InstallLocation || '',
      systemComponent: values.SystemComponent || '',
      windowsInstaller: values.WindowsInstaller || '',
      hive: hivePrefix,
    });
  }
  return items;
}

/** 注册表键存在性（探测面只读） */
function regExists(key) {
  try {
    execFileSync('reg', ['query', key], { encoding: 'utf8', timeout: 10_000, stdio: ['ignore', 'pipe', 'ignore'] });
    return true;
  } catch {
    return false;
  }
}

function existsPath(p) {
  try { return fs.existsSync(p); } catch { return false; }
}

function envOf(name) {
  return process.env[name] || '';
}

/** token → 本机真实路径（探测用）；未知 token 返回 null（跳过该候选） */
function expandToken(target) {
  const m = target.match(/^%([A-Z()0-9]+)%\\(.*)$/);
  if (!m) return null;
  const map = {
    APPDATA: envOf('APPDATA'), LOCALAPPDATA: envOf('LOCALAPPDATA'), PROGRAMDATA: envOf('PROGRAMDATA'),
    PROGRAMFILES: envOf('ProgramFiles'), 'PROGRAMFILES(X86)': envOf('ProgramFiles(x86)'),
    PROGRAMW6432: envOf('ProgramW6432'), COMMONPROGRAMFILES: envOf('CommonProgramFiles'),
    USERPROFILE: envOf('USERPROFILE'), WINDIR: envOf('WINDIR'), SYSTEMROOT: envOf('SystemRoot'),
  };
  const base = map[m[1]];
  if (!base) return null;
  return path.join(base, ...m[2].split('\\'));
}

// ==================== A2 预校验（降噪用；真判据在门禁） ====================

const REG_DENY_PREFIX = [
  'HKLM\\SYSTEM', 'HKLM\\SAM', 'HKLM\\SECURITY', 'HKLM\\SOFTWARE\\CLASSES', 'HKCU\\SOFTWARE\\CLASSES',
  'HKLM\\SOFTWARE\\POLICIES', 'HKLM\\SOFTWARE\\MICROSOFT', 'HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT',
  'HKCU\\SOFTWARE\\MICROSOFT', 'HKCU\\ENVIRONMENT', 'HKLM\\SOFTWARE\\WOW6432NODE',
];

/** 返回 null=形状可入草案；字符串=预校验拒绝原因 */
function precheck(kind, target) {
  if ([...target].length > LIMITS.maxTargetLen) return '超 MAX_PATH';
  if (target.split(/[\\/]/).length > LIMITS.maxSegments + 1) return '段数超上限';
  if (target.includes('*') || target.includes('?')) return '含通配符';
  if (kind === 'reg_key') {
    const up = target.toUpperCase();
    if (!up.startsWith('HKLM\\') && !up.startsWith('HKCU\\')) return 'hive 不支持';
    if (target.includes('::') || target.includes('%')) return '注册表目标不允许变量';
    for (const d of REG_DENY_PREFIX) {
      if (up === d || up.startsWith(d + '\\')) return `注册表硬否决面（${d}）`;
    }
    return null;
  }
  const m = target.match(/^%([A-Z()0-9]+)%\\/);
  if (!m) return '非 token 子路径（草案只收 token 形态，防本机私有路径混入）';
  if (!TOKENS.includes(m[1])) return `token 未登记：%${m[1]}%`;
  const body = target.slice(m[0].length);
  if (!body) return 'token 根';
  if (kind === 'shortcut' && !/\.lnk$/i.test(target)) return 'shortcut 必须 .lnk';
  return null;
}

// ==================== 草案组装与规范化 ====================

function dedupeSorted(arr) {
  return [...new Set(arr.map((s) => s.trim()).filter(Boolean))].sort((a, b) => a.localeCompare(b, 'en'));
}

function normalizeRule(rule) {
  const residue = [...rule.residue]
    .sort((a, b) => (KIND_ORDER[a.kind] - KIND_ORDER[b.kind]) || a.target.localeCompare(b.target, 'en'))
    .slice(0, LIMITS.maxResiduePerRule);
  return {
    id: rule.id,
    displayName: dedupeSorted(rule.displayName),
    publisher: dedupeSorted(rule.publisher),
    uninstallKey: dedupeSorted(rule.uninstallKey),
    residue,
  };
}

/** 通用名称候选：displayName 全名与主词、卸载键名（去花括号 GUID） */
function nameCandidates(displayName, keyName) {
  const out = new Set();
  const push = (s) => { const t = String(s || '').trim(); if (t && !t.startsWith('{')) out.add(t); };
  push(displayName);
  push(keyName);
  // 「Foo Bar 2024 (x64)」类后缀裁剪：取前两词作为目录名候选（目录常以产品主名命名）
  const words = String(displayName || '').trim().split(/\s+/);
  if (words.length > 1) push(words.slice(0, 2).join(' '));
  return [...out];
}

/** 程序主名清理：去尾部版本号与 (x64)/(x86) 标记（「Qoder 0.4.3」→「Qoder」；
 *  版本号进 displayName 组会让下个版本失配，slug 与匹配都用清理后的名字） */
function cleanProgramName(displayName) {
  return String(displayName || '')
    .replace(/\s*v?\d+(\.\d+)+\s*$/i, '')
    .replace(/\s*\(x64\)\s*$/i, '')
    .replace(/\s*\(x86\)\s*$/i, '')
    .replace(/\s*\(32 位|64 位\)\s*$/i, '')
    .trim();
}

/** 规范定义（方案 §2.2）：slug = 程序主名小写化，非字母数字转 -；程序主名取 displayName
 *  （清理后），中文等无 ASCII 惯称时退回卸载键名。冲突后缀由调用方处理。 */
function slugOf(displayName, keyName) {
  const base = slugBase(cleanProgramName(displayName)) || slugBase(keyName || '');
  return base;
}
function slugBase(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

function main() {
  const argv = process.argv.slice(2);
  const outIdx = argv.indexOf('--out');
  const libOnly = argv.includes('--lib-only');
  const probeOnly = argv.includes('--probe-only');

  const excluded = [];
  const rules = [];
  const existing = JSON.parse(fs.readFileSync(RULES, 'utf8'));
  const existingIds = new Set(existing.rules.map((r) => r.id));
  // 库内已有 target 集合（id → target 小写集合），增量片段按此去重
  const existingTargets = new Map(existing.rules.map((r) => [r.id, new Set(r.residue.map((e) => e.target.toLowerCase()))]));

  const addRule = (raw, mode, probeDefault) => {
    const residue = [];
    for (const e of raw.residue) {
      const why = precheck(e.kind, e.target);
      if (why) {
        excluded.push({ id: raw.id, kind: e.kind, target: e.target, why });
        continue;
      }
      residue.push({ kind: e.kind, target: e.target, note: e.note, _probe: e._probe ?? probeDefault, _why: e._why || '' });
    }
    if (!residue.length) return;
    const isNew = !existingIds.has(raw.id);
    let finalResidue = residue;
    if (!isNew) {
      // extend 模式：只保留库内没有的 target（大小写不敏感比对）
      finalResidue = residue.filter((e) => !existingTargets.get(raw.id).has(e.target.toLowerCase()));
      if (!finalResidue.length) return;
    }
    // 同 id 在草案内只保留一条（合并落点）：HKLM/HKCU 双根探测或知识表+探测都命中同一程序时
    const dupe = rules.find((r) => r.id === raw.id);
    if (dupe) {
      const seen = new Set(dupe.residue.map((e) => `${e.kind}:${e.target.toLowerCase()}`));
      for (const e of finalResidue) {
        const k = `${e.kind}:${e.target.toLowerCase()}`;
        if (!seen.has(k)) { dupe.residue.push(e); seen.add(k); }
      }
      dupe._mode = existingIds.has(dupe.id) ? 'extend' : dupe._mode;
      return;
    }
    rules.push({
      _mode: isNew ? 'new' : 'extend', id: raw.id,
      displayName: raw.displayName, publisher: raw.publisher, uninstallKey: raw.uninstallKey,
      residue: finalResidue,
    });
  };

  // —— 1) 知识模板候选 ——
  if (!probeOnly) {
    for (const k of KNOWLEDGE) {
      addRule(
        { id: k.id, displayName: k.displayName, publisher: k.publisher, uninstallKey: k.uninstallKey, residue: k.residue },
        'lib', false,
      );
    }
  }

  // —— 2) 本机探测候选 ——
  let probedPrograms = 0;
  if (!libOnly) {
    // 知识表索引：清理后的 displayName 别名与 uninstallKey → 知识条 id（探测命中时并入该 id，
    // 不另立同程序的新条目——7-Zip/Git/WPS 这类「知识表已覆盖」的程序，探测只做增量落点）
    const knowByName = new Map();
    const knowByKey = new Map();
    for (const k of KNOWLEDGE) {
      for (const nm of k.displayName) knowByName.set(cleanProgramName(nm).toLowerCase(), k);
      for (const key of k.uninstallKey) knowByKey.set(key.toLowerCase(), k);
    }
    const seenPrograms = new Set(); // (displayName|keyName) 去重：HKLM 与 HKCU 双根重复登记同一程序
    const slugTaken = new Set(); // slug 冲突检测（同轮探测内）
    for (const root of UNINSTALL_ROOTS) {
      for (const item of enumUninstallRoot(root)) {
        const displayName = item.displayName;
        const keyName = item.keyName;
        const dedupeKey = `${displayName.toLowerCase()}|${keyName.toLowerCase()}`;
        if (seenPrograms.has(dedupeKey)) continue;
        // 过滤：无显示名 / 隐藏项 / 系统更新与运行库（残留知识价值低且易误配）/ Trim 自身
        if (!displayName || displayName.length < 3) continue;
        if (item.systemComponent === '0x1') continue;
        if (/microsoft|update|redistributable|runtime|kb\d{6}|driver|service pack/i.test(displayName)) continue;
        if (cleanProgramName(displayName).toLowerCase() === 'trim') continue;
        seenPrograms.add(dedupeKey);
        probedPrograms += 1;
        const residue = [];
        const names = nameCandidates(cleanProgramName(displayName), keyName);

        // folder 面：五根 token × 名称候选
        const folderRoots = ['%LOCALAPPDATA%', '%APPDATA%', '%PROGRAMDATA%', '%PROGRAMFILES%', '%PROGRAMFILES(X86)%'];
        for (const rootTok of folderRoots) {
          for (const nm of names) {
            const target = `${rootTok}\\${nm}`;
            const real = expandToken(target);
            if (real && existsPath(real)) {
              const note = rootTok === '%PROGRAMFILES%' || rootTok === '%PROGRAMFILES(X86)%' ? '安装目录（默认装此处）' : '用户数据目录';
              residue.push({ kind: 'folder', target, note, _probe: true, _why: `本机存在 ${real}` });
            }
          }
        }
        // reg_key 面：三根 × 名称候选
        for (const nm of names) {
          for (const regRoot of [`HKLM\\SOFTWARE\\${nm}`, `HKLM\\SOFTWARE\\WOW6432Node\\${nm}`, `HKCU\\Software\\${nm}`]) {
            if (regExists(regRoot)) {
              residue.push({ kind: 'reg_key', target: regRoot, note: '程序配置键', _probe: true, _why: '注册表键存在' });
            }
          }
        }
        // shortcut 面：开始菜单（用户/公共）与桌面
        for (const nm of names) {
          const lnkRoots = [
            '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs',
            '%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs',
            '%USERPROFILE%\\Desktop',
          ];
          for (const lr of lnkRoots) {
            const target = `${lr}\\${nm}.lnk`;
            const real = expandToken(target);
            if (real && existsPath(real)) {
              residue.push({ kind: 'shortcut', target, note: '开始菜单/桌面快捷方式残留', _probe: true, _why: `本机存在 ${real}` });
            }
          }
        }
        // MSI 缓存文件系统面：GUID 键名 → Installer/{GUID} 与 Package Cache
        if (item.windowsInstaller === '0x1' || /^\{[0-9A-F-]+\}$/i.test(keyName)) {
          const guid = (keyName.match(/^\{([0-9A-F-]+)\}$/i) || [])[1];
          if (guid) {
            for (const tpl of ['%WINDIR%\\Installer\\{GUID}', '%PROGRAMDATA%\\Package Cache\\{GUID}', '%LOCALAPPDATA%\\Package Cache\\{GUID}']) {
              const target = tpl.replace('{GUID}', `{${guid}}`);
              const real = expandToken(target);
              if (real && existsPath(real)) {
                residue.push({ kind: 'folder', target, note: 'MSI 安装器缓存（卸载后成为残留）', _probe: true, _why: `本机存在 ${real}` });
              }
            }
          }
        }
        // Downloaded Installations（InstallShield MSI 缓存）按 InstallLocation 尾段探测
        if (item.installLocation && !/^c:\\users/i.test(item.installLocation)) {
          const nm = item.installLocation.split('\\').filter(Boolean).pop();
          if (nm) {
            const target = `%LOCALAPPDATA%\\Downloaded Installations\\${nm}`;
            const real = expandToken(target);
            if (real && existsPath(real)) {
              residue.push({ kind: 'folder', target, note: 'InstallShield 安装包缓存', _probe: true, _why: `本机存在 ${real}` });
            }
          }
        }
        if (!residue.length) continue;

        // 命中知识表 → 并入其 id（extend）；否则新 id。displayName 组用清理后的名字。
        const cleaned = cleanProgramName(displayName);
        const know = knowByName.get(cleaned.toLowerCase()) || knowByKey.get(keyName.toLowerCase());
        if (know) {
          addRule(
            {
              id: know.id, displayName: know.displayName, publisher: know.publisher, uninstallKey: know.uninstallKey,
              residue,
            },
            'extend', true,
          );
          continue;
        }
        let slug = slugOf(displayName, keyName) || `probe-${probedPrograms}`;
        while (slugTaken.has(slug)) slug = `${slug}-2`;
        slugTaken.add(slug);
        addRule(
          {
            id: `residue-${slug}`, displayName: [cleaned], publisher: item.publisher ? [item.publisher] : [],
            uninstallKey: [keyName], residue,
          },
          'probe', true,
        );
      }
    }
  }

  // —— 规范化输出 ——
  // Windows 路径大小写不敏感：探测用 displayName 与键名各跑一遍会产生 Oopz/oopz 双份，
  // 草案按「kind + target 小写」去重，只保留首现写法（规范定义：同 kind 按 target 字典序前的整齐形态）
  for (const r of rules) {
    const seen = new Set();
    r.residue = r.residue.filter((e) => {
      const k = `${e.kind}:${e.target.toLowerCase()}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }
  rules.sort((a, b) => a.id.localeCompare(b.id, 'en'));
  const normalized = rules.map((r) => ({ ...normalizeRule(r), _mode: r._mode, residue: undefined }))
    .map((r, i) => ({ ...r, residue: rules[i].residue }));
  const totalRules = normalized.filter((r) => r._mode === 'new').length + existing.rules.length;
  const overLimit = totalRules > LIMITS.maxRules ? `⚠ 并库后规则数 ${totalRules} 超 maxRules=${LIMITS.maxRules}，需人工取舍` : '';

  const doc = {
    _generator: 'tools/gen-residue-candidates.mjs',
    _note: '草案（人工审核后并入 src-tauri/data/uninstall-residue-rules.json，剥 _ 前缀字段）；_probe=true 表示本机实测存在',
    _meta: {
      knowledgeTemplates: probeOnly ? 0 : KNOWLEDGE.length,
      probedPrograms,
      newRules: normalized.filter((r) => r._mode === 'new').length,
      extendRules: normalized.filter((r) => r._mode === 'extend').length,
      excludedCount: excluded.length,
      totalRulesAfterMerge: totalRules,
      overLimit,
    },
    excluded,
    rules: normalized,
  };
  const text = JSON.stringify(doc, null, 2) + '\n';
  if (outIdx >= 0 && argv[outIdx + 1]) {
    fs.writeFileSync(argv[outIdx + 1], text, 'utf8');
    console.log(`草案已写 ${argv[outIdx + 1]}`);
  } else {
    process.stdout.write(text);
  }
  console.error(
    `知识模板 ${probeOnly ? 0 : KNOWLEDGE.length} · 本机探测程序 ${probedPrograms} · 新规则 ${doc._meta.newRules} · 扩充 ${doc._meta.extendRules} · 预校验拦截 ${excluded.length} ${overLimit}`,
  );
}

main();

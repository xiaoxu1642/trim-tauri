#!/usr/bin/env node
// import-winapp2.mjs —— WinApp2.ini → Trim 清理规则库的**精选导入器**
//
// 用法：
//   node tools/import-winapp2.mjs stats --src <winapp2.ini>        只看源库画像，不写任何文件
//   node tools/import-winapp2.mjs plan  --src <winapp2.ini>        输出精选结果（不落盘）
//   node tools/import-winapp2.mjs apply --src <winapp2.ini>        写入 src-tauri/data/cleanup-rules.json
//
// 为什么单独一个工具而不是一次性脚本：WinApp2 每月都在涨（本机这份 260915 / 4068 条），
// 「再次精选」是重复动作。把口径写成代码，下次换版本只换 --src，口径不变。
//
// 口径（每条都对得上清理规则库契约 tools/rule-schema.json 与 A1-A14 断言）：
//   · 只收 Windows 桌面可达的目标：路径 token 必须落在契约表 cleanup.tokens 内（大小写敏感）；
//   · pattern 只允许单星（执行侧 glob_match 能力），多星一律降级成 `*` 或弃用；
//   · 带 ExcludeKey 的条目**不收** —— 执行侧没有排除过滤，收进来等于「作者说别删的也删」；
//   · 带 Warning= 的条目不收（WinApp2 自己标了风险）；
//   · 与库内既有目标的指纹重复者不收（契约 A3）。
'use strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const RULES_REL = path.join('src-tauri', 'data', 'cleanup-rules.json');

const argv = process.argv.slice(2);
const mode = argv[0] || 'stats';
const srcArg = argv.includes('--src') ? argv[argv.indexOf('--src') + 1] : null;
const SRC = srcArg ? path.resolve(srcArg) : path.join(ROOT, 'docs', '本仓库竞品参考', 'cankao', '8', 'src-tauri', 'resources', 'Winapp2.ini');

// ---------------------------------------------------------------- 解析

function parseIni(text) {
  const sections = [];
  let cur = null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith(';') || line.startsWith('#')) continue;
    if (line.startsWith('[') && line.endsWith(']')) {
      cur = { name: line.slice(1, -1).trim(), body: [] };
      sections.push(cur);
      continue;
    }
    if (!cur) continue;
    const eq = line.indexOf('=');
    if (eq < 0) { cur.body.push([line, '']); continue; }
    const key = line.slice(0, eq).trim();
    const val = line.slice(eq + 1).trim();
    // 去掉尾注释（`;` 在值里通常就是注释起点）
    const semi = val.indexOf(';');
    cur.body.push([key, semi >= 0 ? val.slice(0, semi).trim() : val]);
  }
  return sections;
}

const directiveBase = (k) => k.replace(/\d+$/, '');

function directivesOf(sec) {
  const out = {};
  for (const [k, v] of sec.body) {
    const base = directiveBase(k);
    (out[base] ||= []).push(v);
  }
  return out;
}

// ---------------------------------------------------------------- token 归一

// WinApp2 的目录变量 → 契约表登记集（**大小写敏感**，照抄契约表写法）
const TOKEN_MAP = new Map(Object.entries({
  '%APPDATA%': '%APPDATA%',
  '%LOCALAPPDATA%': '%LOCALAPPDATA%',
  '%COMMONAPPDATA%': '%PROGRAMDATA%',
  '%PROGRAMDATA%': '%PROGRAMDATA%',
  '%WINDIR%': '%WINDIR%',
  '%SYSTEMROOT%': '%SystemRoot%',
  '%SYSTEMDRIVE%': '%SystemDrive%',
  '%PROGRAMFILES%': '%ProgramFiles%',
  '%PROGRAMFILES(X86)%': '%ProgramFiles(x86)%',
  '%TEMP%': '%TEMP%',
  '%TMP%': '%TMP%',
  '%USERPROFILE%': '%USERPROFILE%',
  '%PUBLIC%': '%PUBLIC%',
  '%HOMEDRIVE%': '%HOMEDRIVE%',
  '%HOMEPATH%': '%HOMEPATH%',
  // 契约表没有 Documents 变量：折成 USERPROFILE\Documents（同一棵树，执行侧可展开）
  '%DOCUMENTS%': '%USERPROFILE%\\Documents',
  '%MUSIC%': '%USERPROFILE%\\Music',
  '%PICTURES%': '%USERPROFILE%\\Pictures',
  '%VIDEOS%': '%USERPROFILE%\\Videos',
  '%DESKTOP%': '%USERPROFILE%\\Desktop',
  '%DOWNLOADS%': '%USERPROFILE%\\Downloads',
  // CommonProgramFiles 在 64 位 Windows 上就是 `%ProgramFiles%\Common Files`；
  // 32 位系统上两边同指 Program Files (x86)，也仍然成立。
  '%COMMONPROGRAMFILES%': '%ProgramFiles%\\Common Files',
  '%COMMONPROGRAMFILES(X86)%': '%ProgramFiles(x86)%\\Common Files',
  '%LOCALLOWAPPDATA%': '%USERPROFILE%\\AppData\\LocalLow',
}));

const ALLOWED_TOKENS = ['LOCALAPPDATA', 'APPDATA', 'USERPROFILE', 'WINDIR', 'SystemRoot',
  'SystemDrive', 'PROGRAMDATA', 'TEMP', 'TMP', 'PUBLIC', 'ProgramFiles', 'ProgramFiles(x86)',
  'HOMEDRIVE', 'HOMEPATH'];

function normalizePath(p) {
  let out = String(p ?? '').replace(/\//g, '\\');
  // 逐个 %X% 替换：只认映射表里的，映射表里没有的原样留着 → 后面 token 检查会拒
  out = out.replace(/%[A-Za-z0-9_()]+%/g, (m) => TOKEN_MAP.get(m.toUpperCase()) ?? m);
  return out;
}

function unknownTokens(p) {
  const bad = [];
  for (const m of String(p).matchAll(/%([^%]+)%/g)) {
    if (!ALLOWED_TOKENS.includes(m[1])) bad.push(m[0]);
  }
  return bad;
}

// ---------------------------------------------------------------- 统计

function stats() {
  const text = fs.readFileSync(SRC, 'utf8');
  const sections = parseIni(text);
  const byLang = new Map();
  let withExclude = 0, withWarning = 0, withDetect = 0, withDetectOS = 0, regOnly = 0;
  const badTokens = new Map();
  const multiStar = new Map();
  for (const sec of sections) {
    const d = directivesOf(sec);
    const lang = (d.LangSecRef || ['?'])[0];
    byLang.set(lang, (byLang.get(lang) || 0) + 1);
    if (d.ExcludeKey) withExclude++;
    if (d.Warning) withWarning++;
    if (d.Detect) withDetect++;
    if (d.DetectOS) withDetectOS++;
    if (!d.FileKey && d.RegKey) regOnly++;
    for (const fk of d.FileKey || []) {
      const parts = fk.split('|');
      const np = normalizePath(parts[0]);
      for (const t of unknownTokens(np)) badTokens.set(t, (badTokens.get(t) || 0) + 1);
      const pat = parts[1] || '*';
      if (pat !== '*' && (pat.match(/\*/g) || []).length > 1) multiStar.set(pat, (multiStar.get(pat) || 0) + 1);
    }
  }
  const top = (m, n = 15) => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
  console.log(`源: ${SRC}`);
  console.log(`section 数: ${sections.length}`);
  console.log('LangSecRef 分布:', [...byLang.entries()].sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}:${v}`).join('  '));
  console.log(`带 ExcludeKey: ${withExclude}   带 Warning: ${withWarning}   带 Detect: ${withDetect}   带 DetectOS: ${withDetectOS}   仅 RegKey: ${regOnly}`);
  console.log('未登记 token:', top(badTokens, 20).map(([k, v]) => `${k}:${v}`).join('  '));
  console.log('多星 pattern 样例:', top(multiStar, 20).map(([k, v]) => `${k}:${v}`).join('  '));
}

// ---------------------------------------------------------------- 精选

const LANG_DOMAIN = {
  3021: 'app', 3022: 'browser', 3023: 'app', 3024: 'app', 3025: 'system',
};

const OPTION_WORDS = new Set(['RECURSE', 'REMOVESELF']);
function parseFileKey(v) {
  const parts = String(v).split('|');
  const opts = (parts[2] || '').toUpperCase();
  let pat = (parts[1] || '').trim();
  // 有的条目写成 `<path>|RECURSE`（把选项放到了第二个字段）：那是 `*|RECURSE` 的变体，
  // 不是「找名叫 RECURSE 的文件」。
  if (OPTION_WORDS.has(pat.toUpperCase())) pat = '';
  return {
    path: normalizePath(parts[0] || ''),
    pattern: pat || '*',
    recurse: opts.includes('RECURSE') || OPTION_WORDS.has(pat.toUpperCase()),
    removeSelf: opts.includes('REMOVESELF'),
  };
}

/// 执行侧 `glob_match` 本身认字面量（`pattern == name` 兜底），但**门禁 A2 不认**：
/// 它只放行 `*` 或「恰好一个星」。WinApp2 里一大批精确文件名（`debug.log`、
/// `MEMORY.DMP`、`hh.dat`）因此进不来 —— 这是契约比引擎严的一处，按纪律改导入侧
/// 而不是松门禁，作为遗留记在导入日志里。
function patternOk(p) {
  if (p === '*') return true;
  if (p.includes('?') || p.includes('/')) return false;
  return (p.match(/\*/g) || []).length === 1;
}

/// 一条 FileKey 能不能进库（任一不过 → 整条 section 弃用，不做「部分导入」）。
function fileKeyProblem(fk) {
  if (!fk.path.trim()) return '空路径';
  const bad = unknownTokens(fk.path);
  if (bad.length) return `未登记 token ${bad.join(',')}`;
  if (fk.path.length > 260) return '路径超长';
  if (fk.path.includes('?')) return '路径含 ? 通配';
  if (fk.path.startsWith('\\\\.\\') || fk.path.startsWith('\\\\?\\') || fk.path.startsWith('\\??\\')) return '设备/长路径前缀';
  if (!patternOk(fk.pattern)) return `pattern 不合单星口径: ${fk.pattern}`;
  return null;
}

/// `a` 是不是 `b` 的祖先目录（含自身）。遇到带 `*` 的段就停：那是通配，证不出包含关系。
function isAncestor(a, b) {
  const A = String(a).toLowerCase().split('\\').filter(Boolean);
  const B = String(b).toLowerCase().split('\\').filter(Boolean);
  if (B.length < A.length) return false;
  for (let i = 0; i < A.length; i++) {
    if (A[i].includes('*') || B[i].includes('*')) return false;
    if (A[i] !== B[i]) return false;
  }
  return true;
}

function candidates() {
  const text = fs.readFileSync(SRC, 'utf8');
  const sections = parseIni(text);
  const out = [];
  const drop = new Map();
  const bump = (k) => drop.set(k, (drop.get(k) || 0) + 1);
  for (const sec of sections) {
    const d = directivesOf(sec);
    if (d.ExcludeKey) { bump('带 ExcludeKey（执行侧无排除能力）'); continue; }
    if (d.Warning) { bump('带 Warning（WinApp2 自标风险）'); continue; }
    if (d.SpecialDetect) { bump('带 SpecialDetect（需专用判定）'); continue; }
    const detectFile = (d.DetectFile || [])[0] || '';
    const detects = d.Detect || [];
    if (!detectFile && detects.length === 0) { bump('无安装检测（无法门控展示）'); continue; }
    const fks = (d.FileKey || []).map(parseFileKey);
    if (fks.length === 0) { bump('无 FileKey（清理域以文件为主）'); continue; }
    let bad = null;
    for (const fk of fks) { bad = fileKeyProblem(fk); if (bad) break; }
    if (bad) { bump(`FileKey 不合口径: ${bad}`); continue; }
    const lang = (d.LangSecRef || [])[0];
    out.push({
      section: sec.name,
      owner: (d.Section || [])[0] || '',
      lang,
      domain: LANG_DOMAIN[lang] || null,
      detectFile: normalizePath(detectFile),
      detects,
      fileKeys: fks,
      regKeys: (d.RegKey || []).map((r) => {
        const p = String(r).split('|');
        return { path: p[0], value: p[1] || '*' };
      }),
      hasRemoveSelf: fks.some((f) => f.removeSelf),
    });
  }
  return { out, drop, total: sections.length };
}

// ---------------------------------------------------------------- 分层

/// Tier B：国内外主流白名单。写进库的都是「大多数中文用户机器上有可能存在、
/// 且删了不会出事」的那一批；WinApp2 里大量的小众软件不在其中。
const TIER_B = [
  'wechat', 'weixin', 'qq', 'tencent', 'tim', 'wegame', 'wegame', 'douyin', 'tiktok', 'capcut',
  'jianying', 'doubao', 'baidu', 'wangpan', 'quark', 'aliyun', 'alibaba', 'taobao', 'dingtalk',
  'feishu', 'lark', 'wps', 'kingsoft', 'netease', 'cloudmusic', 'youdao', 'ximalaya', 'bilibili',
  'kugou', 'kuwo', 'qqmusic', 'xunlei', 'thunder', '115', '123pan', 'pikpak', 'onedrive',
  'dropbox', 'google drive', 'microsoft office', 'office', 'excel', 'word', 'powerpoint',
  'outlook', 'adobe', 'acrobat', 'photoshop', 'premiere', 'after effects', 'lightroom',
  'illustrator', 'audition', 'foxit', 'chrome', 'chromium', 'edge', 'firefox', 'opera',
  'vivaldi', 'brave', 'yandex', 'safari', '360', 'sogou', 'qqbrowser', 'maxthon', 'thorium',
  'steam', 'epic games', 'epic games launcher', 'origin', 'ea app', 'uplay', 'ubisoft',
  'gog galaxy', 'battle.net', 'riot', 'valorant', 'league of legends', 'minecraft', 'roblox',
  'unity', 'unreal', 'xbox', 'playstation', 'nintendo', 'discord', 'telegram', 'whatsapp',
  'skype', 'zoom', 'slack', 'teams', 'signal', 'viber', 'line',
  'potplayer', 'vlc', 'kmplayer', 'foobar', 'aimp', 'winamp', 'itunes', 'spotify', 'obs studio',
  'bandicam', 'handbrake', 'audacity', 'ffmpeg',
  'nvidia', 'geforce', 'amd', 'radeon', 'intel', 'msi afterburner', 'wallpaper engine',
  'visual studio', 'vscode', 'visual studio code', 'node', 'npm', 'yarn', 'pnpm', 'python',
  'pip', 'java', 'jdk', 'gradle', 'maven', 'git', 'docker', 'wsl', 'android studio',
  'intellij', 'pycharm', 'webstorm', 'eclipse', 'qt', 'rust', 'cargo', 'golang', 'ruby',
  'php', 'composer', 'cmake', 'sublime', 'notepad++', 'vim', 'emacs', 'cursor', 'trae',
  'windsurf', 'claude', 'openai', 'github', 'obsidian', 'notion', 'typora', 'evernote',
  '7-zip', 'winrar', 'bandizip', 'everything', 'todesk', 'sunlogin', 'teamviewer', 'anydesk',
  'uplay', 'mumu', 'ldplayer', 'bluestacks', 'nox',
];

const installedArg = argv.includes('--installed') ? argv[argv.indexOf('--installed') + 1] : null;
const INSTALLED = [];
if (installedArg && fs.existsSync(installedArg)) {
  for (const line of fs.readFileSync(installedArg, 'utf8').split(/\r?\n/)) {
    const s = line.trim();
    if (s) INSTALLED.push(s);
  }
}

const norm = (s) => String(s).toLowerCase().replace(/[^a-z0-9一-龥]+/g, ' ').trim();

/// 词边界命中。⚠️ **不能 `includes`**：`programdata` 里藏着子串 `a-m-d`，
/// 会被当成「AMD 驱动已装」，`[Composer…]` 因此被误判成 Tier A（实测翻车）。
function hasWord(hay, word) {
  const w = word.replace(/[^a-z0-9]/g, '');
  if (!w) return false;
  return new RegExp(`(^|[^a-z0-9])${w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z0-9]|$)`).test(hay);
}

function tierOf(c) {
  // Detect 指向 \Microsoft\Windows\ 之下的一律是**系统登记位置**（Uninstall/Installer/
  // Applets…），对「装了什么」零信息量，却带着 'windows' 字样——本机装着 Windows SDK
  // 系列开发组件，两词匹配（windows+software / windows+app）会把 GEAR DIFx、
  // Active@ File Recovery 这类特征只有系统键的软件整批误判成 Tier A（三轮实测踩坑）。
  // 组 hay 前先剔除；软件专属键（HKCU\Software\Steam 这类）保留。
  const informative = (c.detects || []).filter(d => !/Microsoft\\Windows\\/i.test(String(d)));
  const hay = norm(`${c.section} ${c.owner} ${c.detectFile} ${informative.join(' ')}`);
  // 系统泛词开头的已装名（Windows SDK / Microsoft ... 运行库等）不做特征：
  // 「Windows Software Development Kit」的两词 windows+software 会命中任何
  // 名字里恰好带 'for windows' 或 '... software' 的第三方软件（SeaTools 实测）。
  // Windows 自身的清理已由内置 82 条覆盖，不因跳过而损失。
  const GENERIC_HEADS = new Set(['windows', 'microsoft']);
  for (const n of INSTALLED) {
    // 取已装名的前两个词做**全命中**：单词名（Trim / QQ）一个词即判；两词名
    // （Microsoft Edge / Windows App Certification Kit）必须都出现——单词匹配
    // 会让「本机有 Windows SDK」覆盖一切名字带 windows 的软件（上一轮踩的坑）。
    const words = norm(n).split(' ').filter(w => w.length >= 2).slice(0, 2);
    if (!words.length || GENERIC_HEADS.has(words[0])) continue;
    if (words.every(w => hasWord(hay, w))) return 'A';
  }
  for (const k of TIER_B) {
    if (/\s/.test(k) ? hay.includes(k) : hasWord(hay, k)) return 'B';
  }
  return null;
}

// ---------------------------------------------------------------- 类目映射

const RX = (s) => new RegExp(s, 'i');
const BROWSER = RX('\\b(chrome|chromium|edge|firefox|opera|vivaldi|brave|yandex|browser|webkit|safari|ie11|internet explorer|qqbrowser|sogou|ucbrowser|maxthon|thorium|waterfox|pale ?moon|seamonkey|tor browser)\\b');
const GFX = RX('(nvidia|geforce|amd|radeon|ati |intel graphics|shader|directx|vulkan|opengl|graphics driver|display driver|afterburner|wallpaper engine|msi )');
const GAME = RX('(steam|epic games|origin|ea app|uplay|ubisoft|gog galaxy|battle\\.net|riot|valorant|league of legends|wegame|minecraft|roblox|unity|unreal|xbox|playstation|nintendo|emulator|mumu|ldplayer|bluestacks|nox|game)');
const DEV = RX('(visual studio|vscode|visual studio code|node|npm|yarn|pnpm|python|pip|java|jdk|gradle|maven|\\bgit\\b|docker|wsl|android studio|intellij|pycharm|webstorm|eclipse|qt creator|rust|cargo|golang|\\bgo\\b|ruby|perl|\\bphp\\b|composer|sdk|\\.net|dotnet|typescript|cmake|msys|mingw|cygwin|sublime|notepad\\+\\+|\\bvim\\b|emacs|cursor|trae|windsurf|github|gitlab)');
const IM = RX('(wechat|weixin|微信|\\bqq\\b|\\btim\\b|telegram|discord|slack|skype|whatsapp|\\bline\\b|viber|zoom|teams|dingtalk|钉钉|feishu|飞书|weibo|微博|signal|doubao|豆包)');
const MEDIA = RX('(potplayer|vlc|kmplayer|mpc-|foobar|aimp|winamp|itunes|spotify|netease|cloudmusic|网易云|kugou|kuwo|剪映|capcut|premiere|after effects|vegas|davinci|obs studio|bandicam|ffmpeg|handbrake|audacity|adobe|photoshop|lightroom|illustrator|audition|播放器|音乐|视频|直播|剪映专业版)');
const NETDISK = RX('(onedrive|dropbox|google drive|百度网盘|baidunetdisk|aliyun|阿里云|quark|夸克|115网盘|123pan|天翼|pcloud|mega|坚果云|nutstore|netdisk|网盘|xunlei|迅雷|thunder)');
const OFFICE = RX('(microsoft office|\\boffice\\b|\\bword\\b|excel|powerpoint|outlook|wps|kingsoft|金山|libreoffice|openoffice|acrobat|foxit|\\bpdf\\b|notion|obsidian|typora|evernote|onenote)');
const SYSTEMISH = RX('(windows|microsoft|\\.net|visual c\\+\\+|directx|windows installer|windows update|prefetch|thumbnail|icon cache|font cache|event log|recycle|driver store|winsxs|wer |crash|temp|tmp)');

/// 是不是 Windows 自身的东西。**不能只看关键词**：`Auslogics Windows Slimmer`
/// 名字里有 Windows 但它是第三方软件，塞进「系统清理」会误导用户以为系统自带。
/// 所以只认 LangSecRef=3025，或名字**开头**就是系统组件名（不扫全串）。
const SYSTEM_HEAD = /^(windows|microsoft|\.net|directx|visual c\+\+|msi|internet explorer|windows defender|media player)/i;
function classify(c) {
  const hay = `${c.section} ${c.owner}`;
  // 浏览器判定必须在系统之前：'Microsoft Edge …' 以 Microsoft 开头，会被
  // SYSTEM_HEAD 抢进「系统清理」（实测 Edge Sync/PDF 系列整批错落 system/stale）。
  if (BROWSER.test(hay) || BROWSER.test(c.detectFile)) {
    return { domain: 'browser', group: browserGroup(c) };
  }
  if (c.lang === '3025' || SYSTEM_HEAD.test(c.section.trim())) {
    return { domain: 'system', group: systemGroup(c) };
  }
  if (GFX.test(hay)) return { domain: 'gfx', group: gfxGroup(c) };
  if (NETDISK.test(hay)) return { domain: 'app', group: 'netdisk' };
  if (IM.test(hay)) return { domain: 'app', group: 'im' };
  if (MEDIA.test(hay)) return { domain: 'app', group: 'media' };
  if (OFFICE.test(hay)) return { domain: 'app', group: 'office' };
  if (GAME.test(hay)) return { domain: 'app', group: 'game' };
  if (DEV.test(hay)) return { domain: 'app', group: 'dev' };
  return null;
}

function systemGroup(c) {
  const h = `${c.section} ${c.fileKeys.map((f) => `${f.path} ${f.pattern}`).join(' ')}`;
  if (RX('(dump|minidump|crash|\\.dmp)').test(h)) return 'dumps';
  if (RX('(update|installer|patch|hotfix|winsxs|driver store|downloaded|setup|upgrad)').test(h)) return 'updates';
  if (RX('(\\blog\\b|logs|\\.log|report|trace|wer|etl)').test(h)) return 'logs';
  if (RX('(\\btemp\\b|\\btmp\\b|temporary)').test(h)) return 'temps';
  if (RX('(history|recent|mru|jump|last|visited)').test(h)) return 'history';
  if (RX('(stale|orphan|leftover|obsolete|old)').test(h)) return 'stale';
  if (RX('(cache|thumbnail|icon|font|webcache|prefetch)').test(h)) return 'caches';
  return 'stale';
}
function browserGroup(c) {
  const h = `${c.section} ${c.fileKeys.map((f) => `${f.path} ${f.pattern}`).join(' ')}`;
  if (RX('(password|login|credential|autofill|cookie|session|bookmark|sync|profile|preference|extension)').test(h)) return 'sync';
  if (RX('(history|visited|download|last|recent|favicon|thumb)').test(h)) return 'stale';
  if (RX('(web ?data|form|media|storage|indexeddb|service worker)').test(h)) return 'webpage';
  return 'codecache';
}
function gfxGroup(c) {
  const h = `${c.section}`;
  if (RX('(driver|installer|setup|package|display driver)').test(h)) return 'drivers';
  if (RX('(shader|cache|glcache|dxcache)').test(h)) return 'shader';
  return 'sysgfx';
}

// ---------------------------------------------------------------- 语义字段

function natureOf(c) {
  const h = `${c.section} ${c.fileKeys.map((f) => `${f.path} ${f.pattern}`).join(' ')}`;
  if (RX('(dump|minidump|crash|\\.dmp)').test(h)) return 'dump';
  if (RX('(\\blog\\b|logs|\\.log|logfile|log\\.txt|trace|report)').test(h)) return 'log';
  if (RX('(history|recent|mru|visited|last ?used)').test(h)) return 'history';
  if (RX('(update|installer|patch|hotfix|setup|upgrade|redist)').test(h)) return 'updateResidual';
  if (RX('(\\.bak|backup|\\.old|stale)').test(h)) return 'staleBackup';
  if (RX('(\\btemp\\b|\\btmp\\b|temporary)').test(h)) return 'temp';
  return 'cache';
}

const REGENERABLE = new Set(['cache', 'log', 'temp', 'updateResidual', 'fileClean']);

function riskOf(c) {
  const h = `${c.section} ${c.fileKeys.map((f) => f.pattern).join(' ')}`;
  if (RX('(password|credential|token|private key|login data|\\bwallet\\b)').test(h)) return 'high';
  if (RX('(session|cookie|autofill|bookmark|preference|setting|config|profile|database|\\.db|sqlite|\\.json|history|\\.ini)').test(h)) return 'medium';
  if (c.hasRemoveSelf) return 'medium';
  return 'low';
}

/// 应用/对象名的中文对照。表里没有的保留 WinApp2 原名（中文软件里保留英文产品名是常态）。
const ZH_APP = new Map(Object.entries({
  steam: 'Steam', wechat: '微信', weixin: '微信', qq: 'QQ', tencent: '腾讯', tim: 'TIM',
  wegame: 'WeGame', douyin: '抖音', tiktok: 'TikTok', capcut: '剪映', jianying: '剪映',
  doubao: '豆包', baidu: '百度', wangpan: '网盘', quark: '夸克', aliyun: '阿里云',
  dingtalk: '钉钉', feishu: '飞书', wps: 'WPS', kingsoft: '金山', netease: '网易',
  cloudmusic: '网易云音乐', bilibili: '哔哩哔哩', kugou: '酷狗', kuwo: '酷我',
  xunlei: '迅雷', onedrive: 'OneDrive', dropbox: 'Dropbox', office: 'Office',
  excel: 'Excel', word: 'Word', powerpoint: 'PowerPoint', outlook: 'Outlook',
  adobe: 'Adobe', acrobat: 'Acrobat', photoshop: 'Photoshop', premiere: 'Premiere',
  chrome: 'Chrome', chromium: 'Chromium', edge: 'Edge', firefox: 'Firefox',
  opera: 'Opera', vivaldi: 'Vivaldi', brave: 'Brave', yandex: 'Yandex', safari: 'Safari',
  epic: 'Epic', origin: 'Origin', uplay: 'Uplay', ubisoft: '育碧', riot: '拳头',
  valorant: '无畏契约', minecraft: '我的世界', roblox: 'Roblox', unity: 'Unity',
  unreal: 'Unreal', xbox: 'Xbox', discord: 'Discord', telegram: 'Telegram',
  whatsapp: 'WhatsApp', skype: 'Skype', zoom: 'Zoom', slack: 'Slack', teams: 'Teams',
  potplayer: 'PotPlayer', vlc: 'VLC', kmplayer: 'KMPlayer', foobar: 'foobar2000',
  itunes: 'iTunes', spotify: 'Spotify', obs: 'OBS', nvidia: 'NVIDIA', geforce: 'GeForce',
  amd: 'AMD', radeon: 'Radeon', intel: 'Intel', 'visual studio': 'Visual Studio',
  vscode: 'VS Code', node: 'Node.js', npm: 'npm', yarn: 'Yarn', pnpm: 'pnpm',
  python: 'Python', pip: 'pip', java: 'Java', git: 'Git', docker: 'Docker',
  wsl: 'WSL', github: 'GitHub', obsidian: 'Obsidian', notion: 'Notion',
  '7-zip': '7-Zip', winrar: 'WinRAR', todesk: 'ToDesk', teamviewer: 'TeamViewer',
  mumu: 'MuMu模拟器', windows: 'Windows', microsoft: 'Microsoft', directx: 'DirectX',
}));
const ZH_OBJ = new Map(Object.entries({
  shader: '着色器', thumbnail: '缩略图', thumb: '缩略图', icon: '图标', font: '字体',
  cookie: 'Cookie', password: '已保存密码', session: '会话', bookmark: '书签',
  autofill: '表单自动填充', history: '历史记录', download: '下载', cache: '缓存',
  log: '日志', temp: '临时文件', crash: '崩溃转储', dump: '转储', backup: '备份',
  update: '更新', setup: '安装', installer: '安装程序', prefetch: '预读',
  database: '数据库', preference: '偏好设置', report: '报告',
}));
const ZH_NATURE = {
  cache: '缓存', log: '日志', temp: '临时文件', history: '历史记录',
  updateResidual: '更新残留', dump: '崩溃转储', staleBackup: '旧备份', fileClean: '文件残留',
};

/// 性质词：section 名里出现这些词就「切一刀」，前面的是产品名。
/// 没这一刀的话 `[Adobe After Effects *]` 之类还能看，但
/// `[Google Chrome Bookmark Favicons *]` 会拿整串当产品名。
const NATURE_SPLIT = /\b(caches?|logs?|log ?files?|history|temps?|tmp|temporary|cookies?|bookmarks?|favicons?|sessions?|passwords?|usernames?|autofill|preferences|settings|config|backups?|dumps?|crash|reports?|updates?|installers?|setup|prefetch|thumbnails?|icons?|fonts?|saved|entries|files?)\b/i;

function zhName(c, nature) {
  let product = (c.section || '').replace(/\s*\*\s*$/, '').trim();
  const m = product.match(NATURE_SPLIT);
  if (m && m.index >= 3) product = product.slice(0, m.index).trim();
  const words = product.split(/\s+/);
  if (words.length > 4) product = words.slice(0, 3).join(' ');

  let app = product;
  for (const [en, zh] of ZH_APP) {
    const w = en.replace(/[^a-z0-9]/g, '');
    if (!w) continue;
    const re = new RegExp(`(^|[^a-z0-9])${w}([^a-z0-9]|$)`, 'i');
    // 命中的那个词换成中文，前后缀照留英文（`Adobe After Effects`、`Google Chrome`）。
    // ⚠️ 起点要**跳过正则的前导边界字符**：直接用 `search` 的 index 会把前导空格算进
    // 前缀，切出 `Google Chrome e` 这种多一个字母的残片（实测翻车）。
    const mm = re.exec(product.toLowerCase());
    if (!mm) continue;
    const start = mm.index + (mm[1] || '').length;
    const lead = product.slice(0, start).trim();
    const rest = product.slice(start + w.length).trim();
    const leadWords = lead ? lead.split(/\s+/).length : 0;
    app = [leadWords <= 2 ? lead : '', zh, rest].filter(Boolean).join(' ').replace(/\s+/g, ' ').trim();
    break;
  }
  if (!app) app = (c.owner || c.section).replace(/\s*\*\s*$/, '').trim();
  let obj = '';
  for (const [en, zh] of ZH_OBJ) {
    if (RX(`\\b${en}\\b`).test(`${c.section}`)) { obj = zh; break; }
  }
  const tail = obj || ZH_NATURE[nature] || '缓存';
  const name = `${app} ${tail}`.replace(/\s+/g, ' ').trim();
  return [...name].length > 60 ? `${[...name].slice(0, 57).join('')}…` : name;
}

function toId(c) {
  const base = (c.section || '').replace(/[^A-Za-z0-9]+/g, ' ').trim().split(/\s+/)
    .map((w, i) => (i === 0 ? w.toLowerCase() : w[0].toUpperCase() + w.slice(1).toLowerCase()))
    .join('');
  return (base || 'winapp2Item').replace(/[^A-Za-z0-9._-]/g, '');
}

// ---------------------------------------------------------------- 组装

function loadRules() {
  return JSON.parse(fs.readFileSync(path.join(ROOT, RULES_REL), 'utf8'));
}

function existingFingerprints(rules) {
  const set = new Set();
  const ids = new Set();
  const paths = new Set();
  for (const g of rules.groups) {
    for (const s of g.subGroups || []) {
      for (const it of s.items || []) {
        ids.add(it.id);
        for (const fk of it.fileKeys || []) {
          set.add(`file|${String(fk.path).toLowerCase()}|${fk.pattern ?? '*'}|${fk.recurse === false ? 'false' : 'true'}`);
          paths.add(String(fk.path).toLowerCase());
        }
      }
    }
  }
  return { fps: set, ids, paths };
}

function buildItem(c, cls, rulesVersion, seen) {
  const nature = natureOf(c);
  const fileKeys = c.fileKeys.map((f) => ({ path: f.path, pattern: f.pattern, recurse: !!f.recurse }));
  const fps = fileKeys.map((f) => `file|${f.path.toLowerCase()}|${f.pattern}|${f.recurse ? 'true' : 'false'}`);
  // A3：任一条目标撞车就不收 —— 不只要比对库内既有，还要比对**本次导入彼此之间**
  // （Adobe 那批条目里有整段相同的 FileKey，第一轮就撞出 3 条重复）。
  if (fps.some((f) => seen.fps.has(f))) return { skip: '目标与其它规则重复（A3）' };
  fps.forEach((f) => seen.fps.add(f));
  let id = toId(c);
  let n = 2;
  while (seen.ids.has(id)) id = `${toId(c)}${n++}`;
  seen.ids.add(id);

  const risk = riskOf(c);
  const name = zhName(c, nature);
  const detect = [];
  if (c.detectFile && !c.detectFile.includes('?') && !c.detectFile.includes('/')
      && !unknownTokens(c.detectFile).length && c.detectFile.length <= 260) {
    detect.push({ type: 'file', path: c.detectFile });
  } else {
    for (const dp of c.detects) {
      const p = String(dp).split('|')[0];
      if (/^(HKLM|HKCU|HKCR)\\/i.test(p) && !p.includes('%')) detect.push({ type: 'reg', path: p });
    }
  }
  const today = new Date().toISOString().slice(0, 10);
  const item = {
    id,
    name,
    risk,
    evidence: `WinApp2 规则库「${c.section}」登记的${ZH_NATURE[nature] || '残留'}目标（${fileKeys.length} 个路径）`,
    recommended: risk === 'low',
    domain: cls.domain,
    group: cls.group,
    nature,
    regenerable: REGENERABLE.has(nature),
    prov: {
      source: 'builtin',
      sourceClass: 'winapp2-clue',
      ref: `winapp2/${c.section}`,
      importedAt: today,
      reviewedAt: today,
    },
    ver: rulesVersion,
    evidenceItems: [
      { text: `WinApp2 规则库（本机源 ${srcVersion(SRC)}）「${c.section}」登记了这条目标`, weight: 2 },
      REGENERABLE.has(nature)
        ? { text: '目标是应用或系统可自行重建的产物，删除后不影响功能', weight: 1 }
        : { text: '删除后该记录不可恢复，仅在你不再需要它时清理', weight: 0 },
    ],
  };
  if (fileKeys.length) item.fileKeys = fileKeys;
  if (detect.length) item.detect = detect;
  return { item };
}

function srcVersion(file) {
  try {
    const head = fs.readFileSync(file, 'utf8').slice(0, 400);
    return (head.match(/Version:\s*([0-9]+)/) || [, '?'])[1];
  } catch { return '?'; }
}

// ---------------------------------------------------------------- 精选收敛

/// WinApp2 给**每一个** Steam 独立游戏都单列一条（`10 Years After`、`140`…）。
/// 这类条目只有装了那个游戏才成立，而 Trim 的 detect 只到目录级，装没装无法分辨；
/// 收进来就是几百条「几乎永远不命中」的规则，把类目冲稀。一律不收。
const STEAM_GAME = /Steam(Apps)?\\(SteamApps\\)?common\\/i;
function isStrayGame(c) {
  const p = c.fileKeys.map((f) => f.path).join(' ');
  if (STEAM_GAME.test(p)) return true;
  return /^(Games|Steam Games|Indie Games)$/i.test((c.owner || '').trim());
}

/// 同一个软件 WinApp2 常有几十个 section（Chrome 就有 40+ 条）。
/// 按「软件」聚组，每组只留最有代表性的几条 —— 这才是「精选」，不是全量搬运。
function groupKeyOf(c) {
  const det = c.detectFile || '';
  if (det) {
    // 取检测目录的上层（去掉 `User Data`、`Cache` 这类末段）作为软件身份
    const segs = det.split('\\').filter(Boolean);
    const cut = segs.findIndex((s) => /^(user data|cache|cachestorage|logs?|profiles?|data)$/i.test(s));
    const keep = cut > 0 ? segs.slice(0, cut) : segs.slice(0, Math.min(segs.length, 3));
    return keep.join('\\').toLowerCase();
  }
  return norm(c.owner || c.section).slice(0, 40);
}

/// 组内优先级：性质（缓存 > 临时 > 日志 > 其它）→ 路径短 → 目标数少。
function sortKey(c, nature) {
  const rank = { cache: 0, temp: 1, updateResidual: 2, log: 3, staleBackup: 4, history: 5, dump: 6 };
  return [
    rank[nature] ?? 9,
    c.fileKeys.map((f) => f.path.length).reduce((a, b) => a + b, 0),
    c.fileKeys.length,
  ];
}

// 每软件条数上限按层分档：Tier A 是**本机确认已装**的软件（用户明确要多收），
// Tier B 是主流白名单（保持精选密度）。
const PER_APP_CAP = { A: 10, B: 3 };

function build() {
  const { out } = candidates();
  const rules = loadRules();
  const seen = existingFingerprints(rules);
  const rulesVersion = Number(new Date().toISOString().slice(0, 10).replace(/-/g, ''));
  const rejected = new Map();
  const bumpR = (k) => rejected.set(k, (rejected.get(k) || 0) + 1);

  // ① 分层 + 类目 + 安全闸，先算出合格候选
  let pool = [];
  for (const c of out) {
    if (isStrayGame(c)) { bumpR('单游戏条目（detect 分辨不出装没装）'); continue; }
    const tier = tierOf(c);
    if (!tier) { bumpR('不在 Tier A（本机已装）/ Tier B（主流白名单）'); continue; }
    let cls = classify(c);
    if (!cls && tier === 'A') {
      // 本机确认已装但特征词没命中的：落「其他已装软件」兜底，而不是直接扔。
      // Tier B 不兜底——白名单的意义就是精选，塞进杂项等于稀释。
      cls = { domain: 'app', group: 'other' };
    }
    if (!cls) { bumpR('映射不到现有类目（宁可不收，不硬塞）'); continue; }
    if (riskOf(c) === 'high') { bumpR('high 风险（会丢密码/凭据，不进默认库）'); continue; }
    if (c.fileKeys.length > 32) { bumpR('fileKeys 超 32 条上限'); continue; }
    pool.push({ c, tier, cls, nature: natureOf(c), key: groupKeyOf(c) });
  }

  // ② 宽窄包含闸：某条目标若是**另一条目标的祖先目录**，勾选它就等于顺手把别的规则
  //    的目标也清了（门禁点名的是宽的那条）。`[Windows Image Acquisition]` 那种
  //    `%UserProfile%` 目标是活例：它把 .nuget / .cargo / JetBrains 一整片都罩住了。
  let allPaths = [...seen.paths];
  for (const p of pool) for (const f of p.c.fileKeys) allPaths.push(f.path.toLowerCase());
  pool = pool.filter((p) => {
    for (const f of p.c.fileKeys) {
      for (const other of allPaths) {
        if (other !== f.path.toLowerCase() && isAncestor(f.path, other)) {
          bumpR('目标是别的规则的祖先目录（宽窄包含）');
          return false;
        }
      }
    }
    return true;
  });
  // ② 按软件聚组，组内择优，每组至多 PER_APP_CAP 条
  const groups = new Map();
  for (const p of pool) {
    const g = groups.get(p.key) || [];
    g.push(p);
    groups.set(p.key, g);
  }
  // cap 计数要把**库里已有**的同组条目算进去：扩库是第二轮动作，第一轮已收的
  // 软件（Chrome/Edge 各 4 条）若不计入，A=6 的上限会被再灌 6 条成 10+。
  const existingByGroup = new Map();
  for (const g of rules.groups) {
    for (const sg of g.subGroups || []) {
      for (const it of sg.items || []) {
        const det = (it.detect || [])[0];
        if (!det || !det.path) continue;
        const k = groupKeyOf({ detectFile: det.path, section: it.name || '', owner: '' });
        existingByGroup.set(k, (existingByGroup.get(k) || 0) + 1);
      }
    }
  }
  const picked = [];
  const overCap = { n: 0 };
  for (const g of groups.values()) {
    g.sort((a, b) => {
      const ka = sortKey(a.c, a.nature);
      const kb = sortKey(b.c, b.nature);
      return ka[0] - kb[0] || ka[1] - kb[1] || ka[2] - kb[2];
    });
    for (const p of g) {
      const cap = PER_APP_CAP[p.tier] ?? 3;
      const already = (existingByGroup.get(p.key) || 0) + picked.filter((x) => x._key === p.key).length;
      if (already >= cap) { overCap.n++; continue; }
      const built = buildItem(p.c, p.cls, rulesVersion, seen);
      if (built.skip) { bumpR(built.skip); continue; }
      picked.push({ ...built.item, _tier: p.tier, _key: p.key });
    }
  }
  if (overCap.n) rejected.set('超出每软件条数上限（A=10/B=3）', overCap.n);
  return { picked, rejected, total: out.length, rulesVersion, apps: groups.size };
}

function plan() {
  const { picked, rejected, total, rulesVersion, apps } = build();
  console.log(`硬闸候选 ${total} → 收录 ${picked.length} 条 / ${apps} 个软件（rulesVersion 将是 ${rulesVersion}）`);
  const byTier = new Map();
  for (const p of picked) byTier.set(p._tier, (byTier.get(p._tier) || 0) + 1);
  console.log('分层:', [...byTier.entries()].map(([k, v]) => `Tier${k}=${v}`).join('  '));
  const byCat = new Map();
  for (const p of picked) {
    const k = `${p.domain}/${p.group}`;
    byCat.set(k, (byCat.get(k) || 0) + 1);
  }
  console.log('落位分布:');
  for (const [k, v] of [...byCat.entries()].sort()) console.log(`  ${k}\t${v}`);
  const byRisk = new Map();
  for (const p of picked) byRisk.set(p.risk, (byRisk.get(p.risk) || 0) + 1);
  console.log('风险:', [...byRisk.entries()].map(([k, v]) => `${k}=${v}`).join('  '));
  console.log('淘汰:', [...rejected.entries()].sort((a, b) => b[1] - a[1]).map(([k, v]) => `${v}× ${k}`).join(' | '));
  console.log('\n样例（Tier A 前 12）:');
  for (const p of picked.filter((x) => x._tier === 'A').slice(0, 12)) {
    console.log(`  ${p.id.padEnd(28)} ${p.name.padEnd(24)} ${p.domain}/${p.group} ${p.risk} ${JSON.stringify(p.fileKeys[0])}`);
  }
  console.log('\n样例（Tier B 前 12）:');
  for (const p of picked.filter((x) => x._tier === 'B').slice(0, 12)) {
    console.log(`  ${p.id.padEnd(28)} ${p.name.padEnd(24)} ${p.domain}/${p.group} ${p.risk} ${JSON.stringify(p.fileKeys[0])}`);
  }
}

// ---------------------------------------------------------------- 落盘

function apply() {
  const { picked, rulesVersion } = build();
  const rules = loadRules();
  const before = rules.groups.reduce((n, g) => n + (g.subGroups || []).reduce((m, s) => m + (s.items || []).length, 0), 0);
  rules.rulesVersion = rulesVersion;
  // 每条 ver 必须等于顶层 rulesVersion（契约 A12）：整库统一重刷，不是只刷新增的
  const stamp = (it) => { it.ver = rulesVersion; return it; };
  for (const g of rules.groups) {
    for (const s of g.subGroups || []) (s.items || []).forEach(stamp);
  }
  const index = new Map();
  for (const g of rules.groups) {
    for (const s of g.subGroups || []) index.set(`${g.key}/${s.id}`, s);
  }
  let placed = 0;
  const missing = new Set();
  for (const p of picked) {
    const slot = index.get(`${p.domain}/${p.group}`);
    if (!slot) { missing.add(`${p.domain}/${p.group}`); continue; }
    (slot.items ||= []).push(p);
    // 内部字段不下发
    delete p._tier;
    delete p._key;
    placed++;
  }
  if (missing.size) console.error('✗ 找不到目标子类目:', [...missing].join(', '));
  const out = path.join(ROOT, RULES_REL);
  fs.writeFileSync(out, `${JSON.stringify(rules, null, 2)}\n`, 'utf8');
  const after = rules.groups.reduce((n, g) => n + (g.subGroups || []).reduce((m, s) => m + (s.items || []).length, 0), 0);
  console.log(`已写入 ${path.relative(ROOT, out)}`);
  console.log(`  条目 ${before} → ${after}（新增 ${placed}）  rulesVersion=${rulesVersion}`);
  console.log('  下一步：node tools/sign-cleanup-rules.mjs sign && node tools/sign-cleanup-rules.mjs gen-fallback && node tools/check-data-parity.mjs');
}

if (mode === 'stats') stats();
else if (mode === 'plan') plan();
else if (mode === 'apply') apply();
else console.error(`未实现的模式: ${mode}`);

// gen-protect-parity.mjs —— 生成「受保护路径」三端同源对拍夹具（Rust ↔ JS）
//
// 背景：`src/main/ps-protect-path.js` 自述为受保护路径清单的唯一权威实现，清理工具
// 「能改规则文件 = 能递归删任意路径」的防线就在这里。C 批在 Rust 侧新增了一份移植
// （`src-tauri/src/engine/protect.rs`，供原生删除与 cleanup 执行注入清单用），
// **必须与 JS 侧逐条同口径**，否则会出现「JS 判拒、Rust 放行」的静默漏防。
//
// 做法：本脚本用 JS 侧真实现算出（① 清单 JSON ② 一批向量的判定结果），写成夹具文件；
// Rust 侧 `engine::protect` 的单测读同一夹具比对。夹具里记录了用到的 extra 目录，
// 使测试可在任意机器复现（不依赖本机 known folder）。
//
// 用法：node tools/gen-protect-parity.mjs

import { createRequire } from 'node:module';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

import { ORIGIN } from './ps-origin.mjs';

const require = createRequire(import.meta.url);
const PROTECT = require(`${ORIGIN}/src/main/ps-protect-path.js`);

const APPDATA = process.env.APPDATA || '';
const LOCALAPPDATA = process.env.LOCALAPPDATA || '';
const HOME = process.env.USERPROFILE || '';
const WINDIR = process.env.WINDIR || 'C:\\Windows';

// 与生产链路同构：主进程启动时用 known folder 补 exact、用自身数据目录补 subtree。
// Electron 版的 APP_DATA_DIR 是 %APPDATA%\Trim；Tauri 版是 %APPDATA%\<identifier>，
// 两者都必须在 exact/subtree 里有正确语义 —— 夹具把它们一起覆盖。
const extras = {
  extraSubtree: [join(APPDATA, 'Trim')],
  extraExact: [
    join(HOME, 'Desktop'),
    join(HOME, 'Documents'),
    join(HOME, 'Downloads'),
  ],
};
PROTECT.configureProtectedRoots(extras);

const roots = PROTECT.protectedRoots();
const rootsJson = PROTECT.protectedRootsJson();

// 向量集：覆盖「历史上真实踩过的坑」——那句注释里列的 16 条误判、拟删除的缓存目录、
// 短名/长路径前缀绕过、盘符根、任意盘符同名目录、UNC 与相对路径。
const vectors = [
  // 必须判拒（fail-closed 与真保护）
  '', '   ', 'C:', 'C:\\', 'D:\\',
  WINDIR,
  `${WINDIR}\\`,
  `${WINDIR}\\..\\${WINDIR.split('\\').pop()}`,
  `${WINDIR}\\System32\\config`,
  `${WINDIR}\\System32\\config\\SAM`,
  join(APPDATA, 'Trim'),
  join(APPDATA, 'Trim', 'cleanup', 'custom', 'x.json'),
  HOME,
  join(HOME, 'Desktop'),
  join(HOME, 'Documents'),
  join(HOME, 'Downloads'),
  APPDATA,
  LOCALAPPDATA,
  process.env.ProgramFiles || 'C:\\Program Files',
  process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)',
  process.env.PROGRAMDATA || 'C:\\ProgramData',
  'C:\\System Volume Information',
  'C:\\System Volume Information\\foo',
  'D:\\System Volume Information\\foo',
  '\\\\?\\C:\\Windows\\Temp',
  // 必须放行（清理工具的主力目标：系统根**之下**的缓存/日志）
  `${WINDIR}\\Prefetch`,
  `${WINDIR}\\SoftwareDistribution\\Download`,
  `${WINDIR}\\Logs\\WindowsUpdate`,
  `${WINDIR}\\System32\\winevt\\Logs`,
  `${WINDIR}\\System32\\DriverStore\\Temp`,
  `${WINDIR}\\WinSxS\\Temp`,
  `C:\\Program Files (x86)\\Steam\\appcache`,
  'C:\\$Recycle.Bin',
  join(APPDATA, 'Tencent', 'QQ'),
  join(APPDATA, 'Code'),
  join(HOME, 'Documents', 'xwechat_files', 'a', 'temp'),
  join(LOCALAPPDATA, 'Temp'),
  process.env.TEMP || join(LOCALAPPDATA, 'Temp'),
];

const result = {
  // 夹具生成时的输入，Rust 测试用同样输入调用 configure()
  extras,
  rootsJson,
  roots: { subtree: roots.subtree, exact: roots.exact, anyDrive: roots.anyDrive },
  vectors: vectors.map(p => ({ p, protected: PROTECT.isPathProtected(p) })),
};

const dir = join(new URL('..', import.meta.url).pathname.replace(/^\//, '').replace(/\//g, '\\'), 'tools', 'fixtures');
mkdirSync(dir, { recursive: true });
const file = join(dir, 'protect-parity.json');
writeFileSync(file, JSON.stringify(result, null, 2), 'utf8');

const denied = result.vectors.filter(v => v.protected).length;
console.log(`✓ 夹具已生成: ${file}`);
console.log(`  清单：subtree ${roots.subtree.length} / exact ${roots.exact.length} / anyDrive ${roots.anyDrive.length}`);
console.log(`  向量：${result.vectors.length} 条（判拒 ${denied} / 放行 ${result.vectors.length - denied}）`);
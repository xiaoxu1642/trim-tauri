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
// 用法：node tools/gen-protect-parity.mjs        # 重算并落盘夹具
//
// 审查 v2-M17：夹具「有没有漂」不再靠人肉记得跑生成器 —— `buildParityFixture()` 被
// `tools/check-data-parity.mjs` 直接调用做内存重算比对（生成与校验共用同一段实现，
// 才不会让「校验逻辑」本身变成第二个会漂的副本）。本文件被 import 时**不写盘**。
//
// ⚠ 关于「把夹具里的用户目录脱敏」（审查 v2-L9）：**不能只在本文件里钉合成环境**，
// 试过，并被 `cargo test --lib protect::` 实证否决：Rust 侧 `matches_js_authority` 拿
// `build_roots(extras)` 与夹具 `rootsJson` **整串**比，而 `build_roots` 的默认段读的是
// **测试进程自己的** %USERPROFILE%/%APPDATA%（`protect.rs` 与 JS 侧 `buildDefaultRoots` 对称）。
// 生成器把环境钉成 `C:\Users\ParityUser` 后，两侧就成了「钉过的默认段」⇄「真机默认段 ∪ extras」，
// 断言必红（实测 left 同时含 administrator 与 parityuser 两组条目）。
// ⇒ 真正脱敏要 `protect.rs` 那条用例把「默认段」也吃夹具输入（夹具多存一份 env，
//    测试里先 set_var 再 build_roots）——那是 .rs 侧改动，本轮只登记、不动手、不留红。
// ⇒ 顺带量到一个同源事实：夹具冻的是**出生机**的用户目录，换机器 `cargo test` 即红，
//    必须重跑一次生成器；`check-data-parity.mjs` 的 P4 按这个口径给了显式提示。

import { createRequire } from 'node:module';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { ORIGIN, REPO_ROOT } from './ps-origin.mjs';

/**
 * 用 JS 权威实现算出夹具内容（不落盘）。
 * @returns {{extras: object, rootsJson: string, roots: object, vectors: Array<{p: string, protected: boolean}>}}
 */
export function buildParityFixture() {
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
    // 本机 %TEMP% 常是 8.3 短名形式（如 C:\Users\<人>\ 的短名 + AppData\Local\Temp）：
    // JS 侧 realpathSync.native、Rust 侧 GetLongPathNameW 都会先触盘展开再判，展开不掉才 fail-closed。
    // ⚠ 这一条是**机器相关**的（换机可能既没有短名、也展开不动），与上面「夹具冻出生机用户目录」
    // 是同一个待修问题；本轮不改判定形状，只在 check-data-parity.mjs 的 P4 里显式提示。
    process.env.TEMP || join(LOCALAPPDATA, 'Temp'),
  ];

  return {
    // 夹具生成时的输入，Rust 测试用同样输入调用 configure()
    extras,
    rootsJson,
    roots: { subtree: roots.subtree, exact: roots.exact, anyDrive: roots.anyDrive },
    vectors: vectors.map(p => ({ p, protected: PROTECT.isPathProtected(p) })),
  };
}

/** 夹具落盘路径（生成器写、门禁读，坐标只此一处） */
export const FIXTURE_PATH = join(REPO_ROOT, 'tools', 'fixtures', 'protect-parity.json');

// 只有「被直接执行」时才写盘：被 check-data-parity.mjs import 时只借 buildParityFixture()，
// 不许有落盘副作用（门禁跑一次就把仓库文件改了，等于门禁自己掩盖漂移）。
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = buildParityFixture();
  mkdirSync(join(FIXTURE_PATH, '..'), { recursive: true });
  writeFileSync(FIXTURE_PATH, JSON.stringify(result, null, 2), 'utf8');
  const denied = result.vectors.filter(v => v.protected).length;
  console.log(`✓ 夹具已生成: ${FIXTURE_PATH}`);
  console.log(`  清单：subtree ${result.roots.subtree.length} / exact ${result.roots.exact.length} / anyDrive ${result.roots.anyDrive.length}`);
  console.log(`  向量：${result.vectors.length} 条（判拒 ${denied} / 放行 ${result.vectors.length - denied}）`);
}

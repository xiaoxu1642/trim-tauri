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
// T1c-M41：生成时固定一套合成环境，落盘前把具体路径换成 `%USERPROFILE%` /
// `%APPDATA%` / `%LOCALAPPDATA%` / `%WINDIR%` / `%ProgramFiles%` 等占位符。
// Rust 消费侧按测试进程自己的环境展开，因此夹具既不携带出生机用户名，也不要求换机后
// 先重跑生成器。

import { createRequire } from 'node:module';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { ORIGIN, REPO_ROOT } from './ps-origin.mjs';
import { writeFileAtomic } from './lib/atomic-write.mjs';

// T1c-L09：PS 探针脚本落仓根 tmp/（.gitignore 已忽略），不落全局 %TEMP% ——
// 后者被 check-test-sandbox 当「trim-* 残留」观测，崩溃一次就给该观测项喂一条残渣。
const PSV_TMP_ROOT = join(REPO_ROOT, 'tmp');

const PARITY_ENV = {
  SystemDrive: 'C:',
  USERPROFILE: 'C:\\ParityHome',
  HOMEDRIVE: 'C:',
  HOMEPATH: '\\ParityHome',
  APPDATA: 'C:\\ParityHome\\AppData\\Roaming',
  LOCALAPPDATA: 'C:\\ParityHome\\AppData\\Local',
  WINDIR: 'C:\\Windows',
  SystemRoot: 'C:\\Windows',
  PROGRAMDATA: 'C:\\ProgramData',
  ProgramFiles: 'C:\\Program Files',
  'ProgramFiles(x86)': 'C:\\Program Files (x86)',
  TEMP: 'C:\\ParityHome\\AppData\\Local\\Temp',
  TMP: 'C:\\ParityHome\\AppData\\Local\\Temp',
};

const ENV_PLACEHOLDERS = [
  ['TEMP', '%TEMP%'],
  ['LOCALAPPDATA', '%LOCALAPPDATA%'],
  ['APPDATA', '%APPDATA%'],
  ['ProgramFiles(x86)', '%ProgramFiles(x86)%'],
  ['ProgramFiles', '%ProgramFiles%'],
  ['PROGRAMDATA', '%PROGRAMDATA%'],
  ['WINDIR', '%WINDIR%'],
  ['USERPROFILE', '%USERPROFILE%'],
];

/** 只在生成器进程内钉住合成环境，返回前逐键恢复，避免污染同进程门禁。 */
function withParityEnv(fn) {
  const saved = new Map();
  for (const [key, val] of Object.entries(PARITY_ENV)) {
    saved.set(key, process.env[key]);
    process.env[key] = val;
  }
  try {
    return fn();
  } finally {
    for (const [key, val] of saved) {
      if (val === undefined) delete process.env[key];
      else process.env[key] = val;
    }
  }
}

function replaceEnvPath(s, from, to) {
  const re = new RegExp(from.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
  return s.replace(re, to);
}

function replaceEnvPaths(value) {
  if (typeof value === 'string') {
    let out = value;
    for (const [key, token] of ENV_PLACEHOLDERS) {
      out = replaceEnvPath(out, PARITY_ENV[key], token);
      const escapedFrom = JSON.stringify(PARITY_ENV[key]).slice(1, -1);
      const escapedTo = JSON.stringify(token).slice(1, -1);
      out = replaceEnvPath(out, escapedFrom, escapedTo);
    }
    return out;
  }
  if (Array.isArray(value)) return value.map(replaceEnvPaths);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, replaceEnvPaths(v)]));
  }
  return value;
}

/**
 * 真实执行 PS 端 Test-PathProtected（P1-05/S1 根治）：把权威模块的 PS 函数落临时
 * 脚本，注入含 neverNames 的 roots，对同一批向量给出布尔判定。
 * 这是 PS 端唯一的自动化执行验证（夹具里的 psVectors），避免「PS 正则折叠/口径漂移
 * 却无人执行」。返回布尔数组；执行失败返回 {error}（Rust 测试会据此判红，不静默）。
 */
function runPsVectors(PROTECT, vectors) {
  const rootsJson = PROTECT.protectedRootsJson();
  const pathsJson = JSON.stringify(vectors.map((v) => v.p));
  // 用单引号 here-string 承载 JSON（JSON 全双引号、单行，无 '@ 序列，安全）
  const wrapper = [
    PROTECT.PROTECT_PATH_PS,
    "$tfProtectedRoots = @'",
    rootsJson,
    "'@ | ConvertFrom-Json",
    "$paths = @'",
    pathsJson,
    "'@ | ConvertFrom-Json",
    'foreach ($p in $paths) {',
    '  $hit = Test-PathProtected -Path $p -Roots $tfProtectedRoots',
    '  Write-Output ($hit.ToString())',
    '}',
  ].join('\n');
  mkdirSync(PSV_TMP_ROOT, { recursive: true });
  const dir = mkdtempSync(join(PSV_TMP_ROOT, 'trim-psv-'));
  const file = join(dir, 'probe.ps1');
  // 关键：Windows PowerShell 5.1 tokenizer 在 **LF-only** 文件的 # 注释里会跨行
  // 吞噬后续代码（实测：纯 LF 时注释把 function/if 吞并报 Unexpected '}'）。
  // 统一用 CRLF 写出，模板语法本身正确。
  writeFileSync(file, wrapper.replace(/\r?\n/g, '\r\n'), 'utf8');
  try {
    const out = execFileSync(
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', file],
      { encoding: 'utf8', timeout: 60_000 },
    );
    const bools = out.trim().split(/\r?\n/).map((x) => x.trim() === 'True');
    if (bools.length !== vectors.length) {
      return { error: `PS 输出行数 ${bools.length} ≠ 向量数 ${vectors.length}` };
    }
    return bools;
  } catch (e) {
    return { error: String((e && e.message) || e).slice(0, 200) };
  } finally {
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

/**
 * 用 JS 权威实现算出夹具内容（不落盘）。
 *
 * T1c-M07（v7.2 C09）：`runPs` 默认 **false** —— check-data-parity（MUST_RUN）import
 * 本函数时不再真实 spawn powershell.exe，也不写全局 %TEMP%（此前跑一次必跑门禁
 * = 一次真实 PS 5.1 执行，MUST_RUN 入口因此不是只读的）。PS 端执行验证（psVectors）
 * 只在显式重生成路径产生：`node tools/gen-protect-parity.mjs`（直跑档传 runPs:true）。
 *
 * @returns {{extras: object, rootsJson: string, roots: object, vectors: Array<{p: string, protected: boolean}>, psVectors?: Array<boolean>|{error: string}}}
 */
export function buildParityFixture({ runPs = false } = {}) {
  return withParityEnv(() => buildParityFixtureInEnv({ runPs }));
}

function buildParityFixtureInEnv({ runPs }) {
  const require = createRequire(import.meta.url);
  const PROTECT = require(`${ORIGIN}/src/main/ps-protect-path.js`);

  const APPDATA = process.env.APPDATA;
  const LOCALAPPDATA = process.env.LOCALAPPDATA;
  const HOME = process.env.USERPROFILE;
  const WINDIR = process.env.WINDIR;

  // 与生产链路同构：主进程启动时用 known folder 补 exact、用自身数据目录补 subtree。
  // Electron 版的 APP_DATA_DIR 是 %APPDATA%\Trim；Tauri 版是 %APPDATA%\<identifier>，
  // 两者都必须在 exact/subtree 里有正确语义 —— 夹具把它们一起覆盖。
  const extras = {
    // T1g-L06：加一条不与默认清单重合的合成子树，证明 extras 合并语义真的被夹具覆盖；
    // 旧夹具的 extras 全是默认段的同值副本，退化成「忽略 extras」也不会红。
    extraSubtree: [join(APPDATA, 'Trim'), 'C:\\TrimParityExtra\\Data'],
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
    // T1g-L06：落在合成 extras 子树下的目标必须判拒（旧夹具没有这条覆盖）
    'C:\\TrimParityExtra\\Data\\child.txt',
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
    // P1-05：凭据文件名诱饵 —— 文件名命中（.env/id_rsa/*.pem/云凭据）
    join(HOME, 'chillsweep-probe.env'),
    join(HOME, '.ssh', 'id_rsa'),
    join(HOME, 'certs', 'server.pem'),
    join(HOME, '.aws', 'credentials'),
    join(HOME, 'gcp', 'service_account_key.json'),
    join(HOME, 'tf', 'terraform.tfstate'),
    // 祖先目录名命中（.env 目录下的普通文件仍拒）
    join(HOME, 'proj', '.env', 'lib', 'x.txt'),
    // 必须放行的近形：段名仅包含模式而非相等/通配
    join(HOME, 'proj', 'environment', 'config.json'),
    join(HOME, 'proj', 'env.local.txt'),
    '\\\\?\\C:\\Windows\\Temp',
    // v2-L4P-17（B-3）：UNC 三形态向量。本机默认清单无 UNC 根 ⇒ 全部放行（与 Rust 一致）；
    // 向量锁的是「三端对同一形态判同一结果」：plain UNC（保留体）、\\?\UNC\（还原后再判）、
    // 正斜杠 UNC。翻转场景（受保护根本身是 UNC）在 Rust 单测 unc_prefix_forms_converge_and_do_not_flip_protection 里用注入根证明。
    '\\\\srv\\pub\\Windows\\System32',
    '\\\\srv\\pub\\cache',
    '\\\\?\\UNC\\srv\\pub\\Windows\\System32',
    '\\\\?\\UNC\\srv\\pub\\cache',
    '//srv/pub/Windows/System32',
    // 必须放行（清理工具的主力目标：系统根**之下**的缓存/日志）
    // T1g-L06 近形对照：合成 extras 的兄弟目录不得被误判为受保护
    'C:\\TrimParityExtra\\Other\\child.txt',
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
    // TEMP 同样先落成占位符，消费侧按当前测试进程的 TEMP 展开；短名展开语义不变。
    process.env.TEMP || join(LOCALAPPDATA, 'Temp'),
  ];

  const vectorResults = vectors.map((p) => ({ p, protected: PROTECT.isPathProtected(p) }));

  return replaceEnvPaths({
    // 夹具生成时的输入，Rust 测试用同样输入调用 configure()
    extras,
    rootsJson,
    roots: {
      subtree: roots.subtree,
      exact: roots.exact,
      anyDrive: roots.anyDrive,
      neverNames: roots.neverNames,
    },
    vectors: vectorResults,
    // P1-05/S1：PS 端真实执行判定（应与 JS vectors.protected 逐项一致）。
    // 仅显式重生成路径产生（runPs:true）；MUST_RUN 门禁的内存重算不含本字段。
    ...(runPs ? { psVectors: runPsVectors(PROTECT, vectorResults) } : {}),
  });
}

/** 夹具落盘路径（生成器写、门禁读，坐标只此一处） */
export const FIXTURE_PATH = join(REPO_ROOT, 'tools', 'fixtures', 'protect-parity.json');

// 只有「被直接执行」时才写盘：被 check-data-parity.mjs import 时只借 buildParityFixture()，
// 不许有落盘副作用（门禁跑一次就把仓库文件改了，等于门禁自己掩盖漂移）。
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  // 直跑 = 显式重生成路径：这一档才允许 spawn PS 产 psVectors（T1c-M07 的开关意义）
  const result = buildParityFixture({ runPs: true });
  // T1c-M05：PS 端验证是「PS 侧唯一的自动化执行验证」，它失败时这一档不许以 exit 0 收场，
  // 也不许落盘 —— 写下去的夹具只会带着一个「看起来有值」的 psVectors（{error}，或与 JS
  // 判定不一致的布尔表），唯一的判红点在 cargo test 里，等于直跑档自己没有失败信号。
  if (!Array.isArray(result.psVectors)) {
    const why = result.psVectors && result.psVectors.error ? result.psVectors.error : '未产出 psVectors';
    console.error(`✗ PS 端执行验证失败，夹具未写：${why}`);
    process.exit(1);
  }
  const mismatched = result.psVectors
    .map((h, i) => ({ i, p: result.vectors[i].p, js: result.vectors[i].protected, ps: h }))
    .filter((x) => x.js !== x.ps);
  if (mismatched.length) {
    console.error(`✗ PS 端判定与 JS 权威实现不一致（${mismatched.length}/${result.vectors.length} 条），夹具未写：`);
    for (const m of mismatched) {
      console.error(`  [${m.i}] ${JSON.stringify(m.p)}`);
      console.error(`       JS=${m.js}  PS=${m.ps}`);
    }
    process.exit(1);
  }
  mkdirSync(join(FIXTURE_PATH, '..'), { recursive: true });
  writeFileAtomic(FIXTURE_PATH, JSON.stringify(result, null, 2));
  const denied = result.vectors.filter(v => v.protected).length;
  console.log(`✓ 夹具已生成: ${FIXTURE_PATH}`);
  console.log(`  清单：subtree ${result.roots.subtree.length} / exact ${result.roots.exact.length} / anyDrive ${result.roots.anyDrive.length} / neverNames ${result.roots.neverNames.length}`);
  console.log(`  向量：${result.vectors.length} 条（判拒 ${denied} / 放行 ${result.vectors.length - denied}）`);
  console.log(`  PS 真实执行：与 JS 判定逐项一致 ✓（${result.psVectors.length} 条）`);
}

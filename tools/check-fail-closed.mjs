// check-fail-closed.mjs —— fail-closed 口径门禁（审查 v3-M2 / v3-L7）
//
// 为什么判红：安全敏感的目录解析与路径转换一旦带「降级回退」，就是把 fail-closed
// 改成 fail-open ——
//   A. `paths::temp_script_dir()` 在私有 tmp 被 junction 替换时返回 Err（审查 L12 的
//      成果），任何调用方把 Err 回退成 `std::env::temp_dir()` 都等于在提权上下文里
//      用可预测路径写文件再导入（TOCTOU 提权窗口）。真实违规见 optimizer.rs 的
//      `Err(_) => std::env::temp_dir()`（v3-M2，已修）。
//   B. `Path::to_str().unwrap()` 在含孤立代理项的非 UTF-8 路径上直接 panic；本项目
//      口径（AGENTS §5 / I3）是批量操作单项失败要跳过并回传，不是崩溃。
//   C. 备份/数据根唯一真源（v2-M19）：老根 `%APPDATA%\Trim` 只许在 engine/paths.rs 里
//      拼出来，别处手拼就意味着便携实例的备份又回到宿主机、两根分叉。
//
// 判定粒度是「语句」（向前扩到最近的 ;{}，向后扩到括号深度 0 的分号），而不是
// 函数级 —— 函数级会误伤 cleanup_temp_scripts 这类「私有 tmp + 遗留 %TEMP% 残留
// 都要扫着删」的合法清扫槽。
//
// 用法：node tools/check-fail-closed.mjs

import { readFileSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';
import { walkRs } from './lib/fs-walk.mjs';
import { gate } from './lib/gate.mjs';
import { splitFunctions } from './lib/src-scan.mjs';

const SRC = join(REPO_ROOT, 'src-tauri', 'src');
// N2（2026-09-29）：老根棘轮必须把原生扫描器一起扫。它在仓库里是 path 依赖、不是
// workspace 成员，历史上一直在 `src-tauri/src` 之外自己拼 `%APPDATA%\Trim`
// （排除名单与空目录忽略名单），标准实例与便携实例共写同一份文件。
// A/B 两段与扫描器无关（它没有 temp_script_dir），只有 C 段扩范围。
const SCANNER = join(REPO_ROOT, 'native-scanner', 'src');

/**
 * 豁免清单（{file, anchor, why} → 理由）。A6/T1a-M09：禁用 file:行号键——
 * 行号漂移后会把真实违例静默豁免。anchor 必须在本文件命中恰好 1 行。
 * 目标是保持为空；新增豁免必须写明为什么不违反 fail-closed。
 */
const EXEMPT = [
  // 空集：pwsh/mod.rs 的 `unwrap_or_else(|_| PathBuf::from("."))` 不含
  // env::temp_dir，天然不触发断言 A（清扫槽只删不写）。
];

/** 取 occurrence 起所在「语句」文本（只向后扫）。
 * 规则：括号深度计数（字符串字面量内容不计），停在深度 0 的 `;`；
 * 但若某个 `}` 把深度从 1 归 0 且其后的首个非空白字符不是 `;`（块语句收尾，
 * 如 `if let … { … }` 后直接换行），也在此停 —— 不越过语句边界吞进下一条。
 * 这样 `match temp_script_dir() { … Err(_) => env::temp_dir() };` 整体纳入，
 * 而 cleanup_temp_scripts 里相邻的 `dirs.push(env::temp_dir()…)` 不会被误并。 */
function statementFrom(text, idx) {
  let end = idx;
  let depth = 0;
  for (; end < text.length; end++) {
    const c = text[end];
    if (c === '"' || c === "'") {
      const q = c;
      end++;
      while (end < text.length && text[end] !== q) {
        if (text[end] === '\\') end++;
        end++;
      }
      continue;
    }
    if (c === '{' || c === '(' || c === '[') depth++;
    else if (c === '}' || c === ')' || c === ']') {
      depth--;
      if (depth === 0 && c === '}') {
        let k = end + 1;
        while (k < text.length && /\s/.test(text[k])) k++;
        if (text[k] !== ';') { end = k; break; }
      }
    } else if (c === ';' && depth === 0) break;
  }
  return text.slice(idx, end);
}

const files = walkRs(SRC);
const g = gate(import.meta.url);
const check = (ok, label, detail = '') => {
  const line = `${label}${detail ? ' — ' + detail : ''}`;
  if (ok) g.ok(line); else g.fail(line);
};

console.log('=== fail-closed 口径门禁 ===\n');

// ---- A. temp_script_dir() 的结果不得在同语句回退到 env::temp_dir() ----
// v6-P2（T1 假绿扫尾）：A/B 判定器抽成纯函数（喂 text+rel+exempt），合成样本自检
// 与真仓扫描共用同一实现——此前判据只有真仓扫描，判定器失灵即恒绿。
function tempScriptDowngrades(text, rel, exempt = []) {
  const hits = [];
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') starts.push(i + 1);
  const lineOf = (off) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= off) lo = mid; else hi = mid - 1;
    }
    return lo;
  };
  const re = /temp_script_dir\(/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    // 注释/文档里出现是讲原理（paths.rs 定义处、pwsh 模块头），不是调用点
    const lnIdx = lineOf(m.index);
    const lineStart = starts[lnIdx];
    const lineEnd = text.indexOf('\n', lineStart);
    if (text.slice(lineStart, lineEnd < 0 ? undefined : lineEnd).trimStart().startsWith('//')) continue;
    const stmt = statementFrom(text, m.index);
    if (!/env::temp_dir\(\)/.test(stmt)) continue;
    const ln = lnIdx + 1;
    const lineText = text.slice(lineStart, lineEnd < 0 ? undefined : lineEnd);
    if (exempt.some((e) => e.file === rel && lineText.includes(e.anchor))) continue;
    hits.push(`${rel}:${ln}`);
  }
  return hits;
}
/** B 组判定（纯函数）：路径转字符串禁 unwrap */
function toStrUnwraps(text, rel, exempt = []) {
  const hits = [];
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') starts.push(i + 1);
  const lineOf = (off) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= off) lo = mid; else hi = mid - 1;
    }
    return lo;
  };
  const re = /\.(to_str|to_string)\(\)\s*\.(unwrap|expect)\(/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const lnIdx = lineOf(m.index);
    const lineStart = starts[lnIdx];
    const lineEnd = text.indexOf('\n', lineStart);
    if (text.slice(lineStart, lineEnd < 0 ? undefined : lineEnd).trimStart().startsWith('//')) continue;
    const ln = lnIdx + 1;
    const lineText = text.slice(lineStart, lineEnd < 0 ? undefined : lineEnd);
    if (exempt.some((e) => e.file === rel && lineText.includes(e.anchor))) continue;
    hits.push(`${rel}:${ln}`);
  }
  return hits;
}
{
  // 正向对照四件：A 违例样本必中 / A 干净样本放行 / B 违例样本必中 / B 注释行放行
  const aBad = tempScriptDowngrades(
    'fn x() { let t = paths::temp_script_dir().unwrap_or_else(|_| std::env::temp_dir()); }',
    'fake.rs',
  );
  const aOk = tempScriptDowngrades('fn x(p: &Path) -> Result<(), E> { let t = paths::temp_script_dir()?; Ok(()) }', 'fake.rs');
  const bBad = toStrUnwraps('fn y(p: &Path) { let s = p.to_str().unwrap(); }', 'fake.rs');
  const bExpect = toStrUnwraps('fn y(p: &Path) { let s = p.to_str().expect("utf8"); }', 'fake.rs');
  const bOk = toStrUnwraps('// 迁移说明：旧写法 p.to_str().unwrap() 已由 ok()? 替代\nfn z(p: &Path) -> Option<&str> { p.to_str() }', 'fake.rs');
  if (aBad.length !== 1 || aOk.length !== 0 || bBad.length !== 1 || bExpect.length !== 1 || bOk.length !== 0) {
    g.fail(
      `fail-closed 判定器自检失败：A 违例=${aBad.length}（应 1） A 干净=${aOk.length}（应 0） ` +
        `B unwrap=${bBad.length}（应 1） B expect=${bExpect.length}（应 1） B 注释/干净=${bOk.length}（应 0）`,
    );
  } else {
    console.log('对照: A/B 违例样本（含 expect）必中、干净与注释样本放行');
  }
}
const aHits = [];
// T1a-M09：anchor 型豁免必须真命中恰好 1 行，否则是死条目/歧义条目。
for (const e of EXEMPT) {
  const text = readFileSync(join(REPO_ROOT, e.file), 'utf8');
  const n = text.split(/\r?\n/).filter((l) => l.includes(e.anchor)).length;
  if (n !== 1) g.fail(`EXEMPT 条目 ${e.file} 的 anchor 命中 ${n} 行（应恰好 1）：${e.anchor}`);
}
for (const f of files) {
  const text = readFileSync(f, 'utf8');
  const rel = relative(REPO_ROOT, f).replace(/\\/g, '/');
  aHits.push(...tempScriptDowngrades(text, rel, EXEMPT));
}
check(
  aHits.length === 0,
  'A. temp_script_dir() 的结果不得在同语句回退到 env::temp_dir()',
  aHits.length ? `违规 ${JSON.stringify(aHits)}（私有 tmp 被替换时必须 Err 传播，不得降级到全局可写 %TEMP%）` : '',
);

// ---- B. 生产代码禁 to_str().unwrap()（非 UTF-8 路径 panic） ----
const bHits = [];
for (const f of files) {
  const text = readFileSync(f, 'utf8');
  const rel = relative(REPO_ROOT, f).replace(/\\/g, '/');
  bHits.push(...toStrUnwraps(text, rel, EXEMPT));
}
check(
  bHits.length === 0,
  'B. 路径转字符串禁用 unwrap()（非 UTF-8 路径会 panic，应跳过并回传失败）',
  bHits.length ? `违规 ${JSON.stringify(bHits)}` : '',
);

// C. 备份/数据根唯一真源（审查 v2-M19）
//
// `%APPDATA%\Trim` 是 Electron 轨的数据根，Tauri 轨的新根由 `engine::paths::app_data_dir()`
// 决定（便携模式随盘走）。历史上各处自己拼 `.join("Trim")`，于是便携实例的新备份落在宿主
// 机漫游目录、带不走，标准与便携实例还共写同一批目录。现在写入恒走
// `paths::backup_write_dir`、读取恒走 `paths::backup_read_dirs`，老根只允许在
// `engine/paths.rs` 里被拼出来（`legacy_data_dir` / 更早的 CleanTool 兜底）。
// 这条是源码级棘轮：谁再手拼一次老根，就会在门禁里留下文件名与行号。
//
// N2（2026-09-29）把扫描范围扩到 `native-scanner/src`：那里历史上也自己拼老根
// （排除名单 / 空目录忽略名单），而扫描器不在 workspace 内，只扫 `src-tauri/src`
// 的话这类拼法永远不会被判红 —— 便携模式的标准实例与便携实例共写同一份名单就是这么漏的。
// 允许拼老根的两个文件：主 crate 的数据根唯一真源，和扫描器里 CLI 专用的那一个助手。
//
// T1a-L06：旧判据三个口子 —— ① 只认 `.join("Trim")`，`.push("Trim")` 与 `"\\Trim"`
// 字面量（format!/字面串形态）都不判；② 只在回看窗口内找 appdata，中间隔超过窗口的
// `.join("Trim")` 被判成「与数据根无关」；③ 反过来，appdata 不在回看窗口里的手拼
// 老根（哪怕函数头就是 `appdata_dir()`）同样漏判。
// 现在：令牌扩成 join/push 与独立 `"\\Trim"` 字面量，窗口扩到**所在函数体**，
// 唯一豁免是函数体内出现 `temp_dir()`（TEMP 遗留清扫槽，与数据根无关）。
const ROOT_OWNERS = [
  'src-tauri/src/engine/paths.rs',
  'native-scanner/src/util.rs',
];
const TRIM_ROOT_TOKENS = [
  /\.(?:join|push)\s*\(\s*"Trim"\s*\)/,
  // `"\\Trim"` 与 `format!("{}\\Trim", …)` 两种字面拼接形态。两条锚定避免误伤：
  // `{`/`}`/引号必须紧贴 `\\Trim`，且 Trim 后只能是 `\` 或字符串收尾 ——
  // `Software\\Trim\\…`（注册表）、`…Roaming\\Trim\\fonts`（URL 夹具）、
  // `{base}\\Trim-DiskBench`（自产基准目录）都不判。
  /[{}"']\\\\Trim(?=\\\\|\s*")/,
];
/**
 * C 组豁免（{file, anchor, why}，anchor 必须在文件里命中恰好 1 行）。
 * 只收「同一个老根、但语义是防御性登记而非数据根构造」的两处：protect roots 把老根
 * 列为不可删子树（只读保护面），少列一项 = 保护面变小，所以它必须独立硬编码、
 * 不能随 paths.rs 的改名一起漂走。
 */
const TRIM_ROOT_EXEMPT = [
  {
    file: 'src-tauri/src/engine/protect.rs',
    anchor: 'subtree: norm(vec![format!("{}\\\\Trim", appdata)',
    why: 'protect roots 把老根登记为不可删子树（只读保护面，非数据根构造）；硬编码是刻意的——跟着 paths.rs 漂走等于保护面缩小',
  },
  {
    file: 'native-scanner/src/scan.rs',
    anchor: 'norm(format!("{}\\\\Trim", appdata)),',
    why: '扫描器 CLI 兜底 ProtectRoots 同口径：老根只作不可删子树，不读不写',
  },
];
/** C 组判定器（纯函数）：返回手拼老根的行坐标。 */
function trimRootHits(text, rel, exemptAnchors = []) {
  const lines = text.split(/\r?\n/);
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') starts.push(i + 1);
  const fns = splitFunctions(text);
  const hits = [];
  lines.forEach((line, i) => {
    if (line.trimStart().startsWith('//')) return;
    if (!TRIM_ROOT_TOKENS.some((re) => re.test(line))) return;
    if (exemptAnchors.some((a) => line.includes(a))) return;
    const off = starts[i];
    const fn = fns.find((f) => off >= f.start && off < f.end);
    const window = fn ? text.slice(fn.start, fn.end) : lines.slice(Math.max(0, i - 3), i + 1).join('\n');
    // `%TEMP%\Trim` 是 pwsh 遗留清扫槽，与数据根无关（见 pwsh/mod.rs 的清理槽候选）
    if (/temp_dir\(\)/.test(window)) return;
    hits.push(`${rel}:${i + 1}`);
  });
  return hits;
}
{
  // 正向对照五项：join/push 两形态必中；旧实现漏掉的跨行形态必中；temp_dir 槽放行；
  // 干净样本放行。
  const cJoin = trimRootHits('fn f(base: PathBuf) { let p = base.join("Trim"); }', 'fake.rs');
  const cPush = trimRootHits('fn f(dirs: &mut Vec<PathBuf>, appdata: String) { dirs.push("Trim"); }', 'fake.rs');
  const cFmt = trimRootHits('fn f(appdata: String) { let p = format!("{}\\\\Trim", appdata); }', 'fake.rs');
  const cTemp = trimRootHits(
    'fn f() {\n  let base = std::env::temp_dir();\n  let a = 1;\n  let b = 2;\n  let c = 3;\n  let p = base.join("Trim");\n}',
    'fake.rs',
  );
  const cClean = trimRootHits('fn f(base: PathBuf) { let p = base.join("TrimCache"); }', 'fake.rs');
  if (cJoin.length !== 1 || cPush.length !== 1 || cFmt.length !== 1 || cTemp.length !== 0 || cClean.length !== 0) {
    g.fail(
      `C 组判定器自检失败：join=${cJoin.length}（应 1） push=${cPush.length}（应 1） format-literal=${cFmt.length}（应 1） ` +
        `temp_dir 槽=${cTemp.length}（应 0，窗口需扩到函数体） 干净=${cClean.length}（应 0）`,
    );
  } else {
    console.log('✓ 判定器自检：C 组 join/push/字面量三形态必中、temp_dir 槽与干净样本放行（五样本）');
  }
}
const cFiles = [...files, ...walkRs(SCANNER)];
const cHits = [];
// 豁免锚点必须真命中恰好一行，否则是死条目/歧义条目（与 A/B 的 EXEMPT 同纪律）。
for (const e of TRIM_ROOT_EXEMPT) {
  const p = join(REPO_ROOT, e.file);
  const n = existsSync(p) ? readFileSync(p, 'utf8').split(/\r?\n/).filter((l) => l.includes(e.anchor)).length : -1;
  if (n !== 1) g.fail(`C 组豁免条目 ${e.file} 的 anchor 命中 ${n} 行（应恰好 1）：${e.anchor}`);
}
for (const f of cFiles) {
  const rel = relative(REPO_ROOT, f).replace(/\\/g, '/');
  if (ROOT_OWNERS.includes(rel)) continue;
  const exemptAnchors = TRIM_ROOT_EXEMPT.filter((e) => e.file === rel).map((e) => e.anchor);
  cHits.push(...trimRootHits(readFileSync(f, 'utf8'), rel, exemptAnchors));
}
check(
  cHits.length === 0,
  `C. 老根 %APPDATA%\\Trim 只许在 ${ROOT_OWNERS.join(' / ')} 里拼（备份与名单根唯一真源，v2-M19 / N2）`,
  cHits.length ? `违规 ${JSON.stringify(cHits)}` : '',
);
// T1a-L06：A/B/C 三组的扫描面地板 —— `src-tauri/src` 被搬走/改名时 A/B 以 0 命中打 ✓，
// C 只剩 scanner 一支也照样绿（现算 .rs 文件数：命令 rg --files src-tauri/src -g "*.rs" | wc -l，地板取一半）。
check(
  files.length >= 50,
  `A/B/C 扫描面地板（src-tauri/src 现算 ${files.length} 个 .rs ≥ 50；T1a-L06）`,
  files.length < 50 ? `只扫到 ${files.length} 个 .rs ⇒ 扫描根被搬走/改名，A/B 断言已空转` : '',
);

// D. 扫描器名单根必须由主 crate 注入（N2）
//
// `util::list_file_path` 在没有注入时把名单按**空**处理，而排除/忽略名单是"少删"的保护面：
// 名单为空 = 删除面变大。所以注入点必须存在且只有一处真源 —— 摘掉下面这行调用，
// 运行时不会立刻报错（OnceLock 静默为空），只能靠这条源码断言拦住。
const pathsSrc = readFileSync(join(SRC, 'engine', 'paths.rs'), 'utf8');
const injected = /trim_finder::util::set_data_roots\s*\(/.test(pathsSrc);
const scannerUsesRoots = walkRs(SCANNER).some((f) =>
  /crate::util::list_file_path\s*\(/.test(readFileSync(f, 'utf8')));
check(
  injected && scannerUsesRoots,
  'D. 扫描器名单根注入只许发生在 paths::app_data_dir()，且扫描器只经 util::list_file_path 取名单',
  `${injected ? '' : ' 缺注入'}${scannerUsesRoots ? '' : ' 扫描器未走统一入口'}`.trim(),
);

// ---- E. 裁根不得含老根（v2-L4P-14，B-2/C-3 用户拍板 D-1） ----
// 老根 `%APPDATA%\Trim` 是升级前备份的唯一还原依据，红线依据 §9.2① 冻结「老根只读不裁」。
// pwsh::prune_reg_backups 与 peripheral::prune_backups 曾把 backup_read_dirs（读兜底清单）
// 直接当裁根清单用 ⇒ 超额老根被投回收站。本断言钉死：两个裁剪函数的函数体必须以
// backup_write_dir 单根为裁根、不得出现 backup_read_dirs。正向对照：backup_read_dirs
// 必须仍在仓内被读取侧使用（API 改名/消失时断言失效要立刻暴露，而不是恒绿）。
const PRUNE_FNS = [
  { file: 'pwsh/mod.rs', fn: 'prune_reg_backups' },
  { file: 'commands/peripheral.rs', fn: 'prune_backups' },
];
function fnBody(src, fnName) {
  const re = new RegExp(`\\bfn\\s+${fnName}\\s*[<(]`);
  const m = src.match(re);
  if (!m) return null;
  let i = src.indexOf('{', m.index);
  if (i < 0) return null;
  let depth = 0;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') { depth--; if (depth === 0) break; }
  }
  return src.slice(m.index, i);
}
const readDirsStillUsed = files.some((f) => /backup_read_dirs\s*\(/.test(readFileSync(f, 'utf8')));
check(readDirsStillUsed, 'E0. 正向对照：backup_read_dirs 读取侧仍在仓内使用（断言 E1-E2 防恒绿）', readDirsStillUsed ? '' : '读兜底 API 已消失——请复核 E 组断言是否还有意义');
let eHits = [];
for (const { file, fn } of PRUNE_FNS) {
  const p = join(SRC, file);
  const body = fnBody(readFileSync(p, 'utf8'), fn);
  if (!body) { eHits.push(`${file}:${fn} 函数体定位失败`); continue; }
  if (!/backup_write_dir\s*\(/.test(body)) eHits.push(`${file}:${fn} 裁根未走 backup_write_dir 单根`);
  if (/backup_read_dirs\s*\(/.test(body)) eHits.push(`${file}:${fn} 裁根含读兜底清单（老根会被裁）`);
}
check(
  eHits.length === 0,
  'E. 裁剪函数裁根 = backup_write_dir 单根，老根只读不裁（v2-L4P-14）',
  eHits.length ? `违规 ${JSON.stringify(eHits)}` : `${PRUNE_FNS.length} 个裁剪函数全部写侧单根`,
);

console.log('');
g.finish('fail-closed 门禁全部通过');

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

import { readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

import { REPO_ROOT } from './ps-origin.mjs';
import { walkRs } from './lib/fs-walk.mjs';
import { gate } from './lib/gate.mjs';

const SRC = join(REPO_ROOT, 'src-tauri', 'src');
// N2（2026-09-29）：老根棘轮必须把原生扫描器一起扫。它在仓库里是 path 依赖、不是
// workspace 成员，历史上一直在 `src-tauri/src` 之外自己拼 `%APPDATA%\Trim`
// （排除名单与空目录忽略名单），标准实例与便携实例共写同一份文件。
// A/B 两段与扫描器无关（它没有 temp_script_dir），只有 C 段扩范围。
const SCANNER = join(REPO_ROOT, 'native-scanner', 'src');

/**
 * 豁免清单（file:line → 理由）。line 以门禁自己的行号计算为准。
 * 目标是保持为空；新增豁免必须写明为什么不违反 fail-closed。
 */
const EXEMPT = {
  // 空集：pwsh/mod.rs:452 的 `unwrap_or_else(|_| PathBuf::from("."))` 不含
  // env::temp_dir，天然不触发断言 A（清扫槽只删不写）。
};

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
const aHits = [];
for (const f of files) {
  const text = readFileSync(f, 'utf8');
  const rel = relative(REPO_ROOT, f).replace(/\\/g, '/');
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
    if (EXEMPT[`${rel}:${ln}`]) continue;
    aHits.push(`${rel}:${ln}`);
  }
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
  const re = /\.(to_str|to_string)\(\)\s*\.unwrap\(\)/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const lnIdx = lineOf(m.index);
    const lineStart = starts[lnIdx];
    const lineEnd = text.indexOf('\n', lineStart);
    if (text.slice(lineStart, lineEnd < 0 ? undefined : lineEnd).trimStart().startsWith('//')) continue;
    const ln = lnIdx + 1;
    if (EXEMPT[`${rel}:${ln}`]) continue;
    bHits.push(`${rel}:${ln}`);
  }
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
const ROOT_OWNERS = [
  'src-tauri/src/engine/paths.rs',
  'native-scanner/src/util.rs',
];
const cFiles = [...files, ...walkRs(SCANNER)];
const cHits = [];
for (const f of cFiles) {
  const rel = relative(REPO_ROOT, f).replace(/\\/g, '/');
  if (ROOT_OWNERS.includes(rel)) continue;
  const lines = readFileSync(f, 'utf8').split(/\r?\n/);
  lines.forEach((line, i) => {
    if (line.trimStart().startsWith('//')) return;
    if (!/\.join\(\s*"Trim"\s*\)/.test(line)) return;
    // 往上再看 3 行：`PathBuf::from(appdata)\n    .join("Trim")` 这种换行拼法也要抓到
    const window = lines.slice(Math.max(0, i - 3), i + 1).join('\n');
    // `%TEMP%\Trim` 是 pwsh 遗留清扫槽，与数据根无关（见 pwsh/mod.rs 的清理槽候选）
    if (/temp_dir\(\)/.test(window)) return;
    if (/appdata/i.test(window)) cHits.push(`${rel}:${i + 1}`);
  });
}
check(
  cHits.length === 0,
  `C. 老根 %APPDATA%\\Trim 只许在 ${ROOT_OWNERS.join(' / ')} 里拼（备份与名单根唯一真源，v2-M19 / N2）`,
  cHits.length ? `违规 ${JSON.stringify(cHits)}` : '',
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
// 老根 `%APPDATA%\Trim` 是升级前备份的唯一还原依据，AGENTS §9.2① 冻结「老根只读不裁」。
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

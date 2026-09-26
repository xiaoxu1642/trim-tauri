// check-ps-substitution.mjs —— cleanup 域 PS 模板「替换口径」对拍门禁
//
// 背景：cleanup 的三个脚本是**模板模式**产物（`src-tauri/ps/cleanup_*.ps1` 保留
// `${X_PLACEHOLDER}`，真实插值在生成期已求值），真正的运行期替换在 Rust 侧
// （`commands/cleanup.rs` 的 build_scan_script / build_execute_script / build_detail_script）。
// 替换口径一旦漂移（少转义一处单引号、布尔写成 `True`、JSON 键序变了），
// 脚本会**静默走错分支**而不是报错——必须逐字节对拍。
//
// 做法：
//   ① 合成一组覆盖边界（单引号 / 反斜杠 / 非 ASCII / 空数组 / 嵌套对象 / 数字布尔 null）的输入；
//   ② 用 JS 侧 `CLEANUP_SCRIPT.scan/execute/detail` 生成三份脚本（Electron 真实产物）；
//   ③ 把输入与 JS 产物写进临时目录，调 `cargo test ps_substitution`，
//      由 Rust 侧同口径替换模板后与 JS 产物**逐字节**比较（不一致即测试失败并打印首个差异）。
//
// 用法：node tools/check-ps-substitution.mjs
//   [--dir <目录>]       把夹具写到指定目录（默认写临时目录，跑完即删）
//   [--fixtures-only]    只生成夹具、不跑 cargo（供隔离验证 / 人工 diff 用）
// 退出码：0 = 三份脚本逐字节一致；1 = 有不一致或无法执行（差异明细见 cargo 输出）

import { createRequire } from 'node:module';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { ORIGIN } from './ps-origin.mjs';

const ARGV = process.argv.slice(2);
const DIR_IDX = ARGV.indexOf('--dir');
const FIXED_DIR = DIR_IDX >= 0 ? ARGV[DIR_IDX + 1] : null;
const FIXTURES_ONLY = ARGV.includes('--fixtures-only');

const require = createRequire(import.meta.url);
// 与 sync-ps-from-js.mjs 同一套路径取法（Windows 下把 URL pathname 转成反斜杠路径）
const ROOT = new URL('..', import.meta.url).pathname.replace(/^\//, '').replace(/\//g, '\\');
const CRATE = join(ROOT, 'src-tauri');

// S3：cleanup 域 PS 脚本已删除，本门禁不再适用
const CLEANUP_PS = join(ROOT, 'src-tauri', 'ps', 'cleanup_scan.ps1');
if (!existsSync(CLEANUP_PS)) {
  // 审查 F1：打印「✓」会被当成「跑过且通过」（假绿）。这里没有执行任何断言，
  // 必须显式标 SKIP，让验收日志能区分「真跑过」与「无对象可查」。
  console.log('SKIP（未执行任何断言）：cleanup 域 PS 脚本已 S3 退役，替换口径对拍无对象可查；若模板重新引入需恢复本门禁');
  process.exit(0);
}

const CLEANUP = require(`${ORIGIN}/src/scripts-powershell/cleanup-scripts.js`);
const PROTECT = require(`${ORIGIN}/src/main/ps-protect-path.js`);

// ---------- 合成输入（边界优先） ----------
const DLL = "C:\\Fake Dir\\o'brien\\TrimFastSize.dll";
const CATEGORIES = ["temp", "recycleBin", "o'brien's cache", '系统临时文件'];
const CONFIGURED = {
  wechatCacheDir: "D:\\x'y\\wechat",
  neteaseCacheDir: '',
  emptyList: [],
  nested: { a: [1, 2.5, true, null], 'k\'q': "v'w" },
  n: 0,
};
const ITEMS = [
  { id: "temp's", name: "临时文件'", path: "C:\\Windows\\Temp", risk: 'low', size: 1024 },
  { id: 'empty-files', name: '空', path: '', fileKeys: [{ path: "%TEMP%\\*.tmp" }] },
];
const FORCE = true;
const TO_RECYCLE = true;
const AUTO_REBUILD = false;
const DETAIL = { id: "temp's", path: "C:\\Users\\a b\\AppData\\Local\\Temp" };

const rules = CLEANUP.rules();
const rulesJson = JSON.stringify(rules);
const protectedJson = PROTECT.protectedRootsJson();

// ---------- JS 侧产物（Electron 真实执行的那份） ----------
CLEANUP.setFastSizeDll(DLL); // 与 Rust 侧 build_* 的 dll 参数同值
const js = {
  scan: CLEANUP.scan(CATEGORIES, CONFIGURED, rules),
  execute: CLEANUP.execute(ITEMS, FORCE, TO_RECYCLE, AUTO_REBUILD),
  detail: CLEANUP.detail(DETAIL.id, DETAIL.path),
};

// ---------- 夹具落临时目录 ----------
const work = FIXED_DIR || mkdtempSync(join(tmpdir(), 'trim-ps-subst-'));
if (FIXED_DIR) mkdirSync(work, { recursive: true });
const inputs = {
  dll: DLL,
  categories: CATEGORIES,
  configured: CONFIGURED,
  // 直接落「JSON.stringify 后的紧凑文本对应的值」——Rust 侧会重新序列化，
  // 这一步同时校验 serde_json(preserve_order) 与 JSON.stringify 的等价性
  rules: JSON.parse(rulesJson),
  rulesJson,
  protectedJson,
  items: ITEMS,
  force: FORCE,
  toRecycle: TO_RECYCLE,
  autoRebuild: AUTO_REBUILD,
  detail: DETAIL,
};
writeFileSync(join(work, 'inputs.json'), JSON.stringify(inputs, null, 2), 'utf8');
for (const [name, text] of Object.entries(js)) {
  writeFileSync(join(work, `js.${name}.ps1`), text, 'utf8');
}
console.log(`夹具目录：${work}`);
console.log(`JS 产物：scan ${js.scan.length} 字符 / execute ${js.execute.length} / detail ${js.detail.length}`);

// 顺带断言 JS 产物确实已把占位符替换掉（防止夹具本身是「模板」）
let placeholders = 0;
for (const text of Object.values(js)) {
  placeholders += (text.match(/\$\{[A-Z_]+\}/g) || []).length;
}
if (placeholders > 0) {
  console.log(`✗ JS 产物仍残留 ${placeholders} 处 \${X_PLACEHOLDER}（夹具异常）`);
  process.exit(1);
}
if (FIXTURES_ONLY) {
  console.log('（--fixtures-only：夹具已就位，未跑 cargo）');
  process.exit(0);
}

// ---------- Rust 侧同口径替换后逐字节比较 ----------
if (!existsSync(join(CRATE, 'Cargo.toml'))) {
  console.log('✗ 未找到 src-tauri/Cargo.toml');
  process.exit(1);
}
// 审查 M13：`ps_substitution_matches_js` 现在是 `#[ignore]` 用例，必须带 `--ignored` 才会跑；
// 更要紧的是**断言它真的跑了** —— 只认退出码的话，「0 passed / 1 ignored」也是 0，
// 又回到「显示通过其实没跑」。所以这里把输出接回来自己核对 `1 passed`。
const r = spawnSync(
  'cargo',
  ['test', '--message-format', 'short', 'ps_substitution', '--', '--nocapture', '--ignored'],
  { cwd: CRATE, env: { ...process.env, TRIM_PS_SUBST_DIR: work }, encoding: 'utf8', shell: false }
);
if (!FIXED_DIR) {
  rmSync(work, { recursive: true, force: true });
}
const cargoText = `${r.stdout || ''}${r.stderr || ''}`;
console.log(cargoText.trimEnd());
const ran = /\b1 passed\b/.test(cargoText);
if (!ran && r.status === 0) {
  console.log('\n✗ 对拍用例没有实际执行（期望 1 passed；多半是被 ignore 过滤掉了）');
  process.exit(1);
}
if (r.status !== 0 || !ran) {
  console.log('\n✗ PS 模板替换对拍未通过（差异见上方 cargo 输出）');
  process.exit(1);
}
console.log('\n✓ PS 模板替换对拍通过（三份脚本逐字节一致）');
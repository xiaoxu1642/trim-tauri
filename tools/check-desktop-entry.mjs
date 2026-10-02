#!/usr/bin/env node
// check-desktop-entry.mjs —— 桌面稳定入口与发布暂存目录的合并守卫（2026-10-02 用户裁定 dist-app 并入 build-release）
//
// 抓什么：
//   1. 仓库里不得再有 `dist-app/` 残留，`.gitignore` 也不得再写 `dist-app/` 规则
//      —— 合并过一次就必须是**一个**入口目录，否则下一次会话会照旧口径把 exe 写回两处。
//   2. 桌面符号链接（`%USERPROFILE%\Desktop\Trim.exe`）必须解析到 `build-release\Trim.exe`，
//      且目标真实存在、不是 0 字节占位。链接断掉在 Windows 上的表现是双击没反应/资源管理器
//      报"找不到"，不会有任何日志，所以只能在这里判红。
//   3. `build-release/` 里只要还有版本化产物（`Trim_x.y.z_*`），固定名 `Trim.exe` 就必须在位
//      —— 这是把 AGENTS §7.4「发版收尾逐个清理旧 exe/zip」的那只手按住：清理清单里
//      `Trim.exe` 属**永不删**位，被当旧产物裁掉就等于把用户桌面上那个图标删了。
//
// 刻意不做的事：不复制/不创建任何文件，只读校验；本机既没有 `build-release/` 也没有桌面链接
//   （干净克隆）时打 SKIP 并说明，但**只要 `build-release/` 存在，链接缺失就判红**，
//   不把"这台机器没配过"吞成绿灯（AGENTS §4 的假绿纪律：恒 SKIP 的死门禁要不得）。
//
// 用法：node tools/check-desktop-entry.mjs
'use strict';
import { existsSync, readFileSync, readdirSync, statSync, lstatSync, readlinkSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const REL = join(ROOT, 'build-release');
const ENTRY = join(REL, 'Trim.exe');
const STALE_DIR = join(ROOT, 'dist-app');
const GITIGNORE = join(ROOT, '.gitignore');

let failed = 0;
const ok = (m, d = '') => console.log(`✓ ${m}${d ? ' — ' + d : ''}`);
const bad = (m, d = '') => { console.error(`✗ ${m}${d ? ' — ' + d : ''}`); failed++; };

// ---- 1. 合并后只剩一个入口目录 ----
if (existsSync(STALE_DIR)) bad('仓库里仍有 dist-app/：合并未生效或被抄回来', STALE_DIR);
else ok('1. 仓库无 dist-app/ 残留（入口只有 build-release/）');

const gi = existsSync(GITIGNORE) ? readFileSync(GITIGNORE, 'utf8') : '';
const giHit = gi.split(/\r?\n/).filter((l) => /^\s*dist-app\/?\s*$/.test(l));
if (giHit.length) bad('2. .gitignore 仍写着 dist-app 规则（旧口径未清）', giHit.join(','));
else ok('2. .gitignore 不再为 dist-app 留规则');

// ---- 3. 桌面符号链接指向合并后的稳定入口 ----
const desktop = join(process.env.USERPROFILE || join(homedir()), 'Desktop', 'Trim.exe');
const relExists = existsSync(REL);
if (!existsSync(desktop)) {
  if (relExists) bad('3. 桌面链接不存在，但 build-release/ 在位', `期望 ${desktop} → ${ENTRY}`);
  else console.log('ℹ 3. SKIP：本机既无 build-release/ 也无桌面链接（干净克隆），本条无对象');
} else {
  let st = null;
  try { st = lstatSync(desktop); } catch (e) { bad('3. 桌面链接 lstat 失败', e.message); }
  let target = null;
  if (st && st.isSymbolicLink()) { try { target = readlinkSync(desktop); } catch (e) { target = null; } }
  if (!st || !st.isSymbolicLink()) {
    bad('3. 桌面 Trim.exe 不是符号链接（发版收尾覆盖运行入口靠的是链接按路径解析，实体文件会跟新版分叉）', desktop);
  } else if (!target || !target.replace(/[\\/]/g, '\\').toLowerCase().endsWith(join('build-release', 'Trim.exe').toLowerCase())) {
    bad('3. 桌面链接指向的不是 build-release\\Trim.exe', `实际 → ${target}`);
  } else if (!existsSync(ENTRY)) {
    bad('3. 链接目标已不存在（下一次发版清理把它裁掉了）', ENTRY);
  } else if (statSync(ENTRY).size < 1024 * 1024) {
    bad('3. 入口文件小于 1 MiB，不像是真 exe', `${statSync(ENTRY).size} B`);
  } else {
    ok('3. 桌面链接 → build-release\\Trim.exe 且目标在位', `${(statSync(ENTRY).size / 1024 / 1024).toFixed(1)} MB`);
  }
}

// ---- 4. 暂存区里有版本化产物时，固定名入口必须在位（清理清单的永不删位）----
if (relExists) {
  const files = readdirSync(REL);
  const versioned = files.filter((f) => /^Trim_\d+\.\d+\.\d+/.test(f));
  if (versioned.length && !files.includes('Trim.exe')) {
    bad('4. build-release/ 有版本化产物却没有固定名 Trim.exe', `旧产物 ${versioned.length} 件在位`);
  } else {
    ok('4. 固定名入口与版本化产物同区共存（清理旧产物时 Trim.exe 属永不删位）',
      `版本化 ${versioned.length} 件 / Trim.exe ${files.includes('Trim.exe') ? '在位' : '无'}`);
  }
  // 版本化产物自身不得叫 Trim.exe（那是入口名，混起来就没法判断"旧产物"了）
  const fixedSetup = files.filter((f) => /^Trim(-setup|\.zip)/i.test(f));
  if (fixedSetup.length) bad('4b. build-release/ 出现用固定名命名的发布资产，与运行入口同名易误删', fixedSetup.join(','));
  else ok('4b. 发布资产一律带版本号命名，与入口名不冲突');
} else {
  console.log('ℹ 4. SKIP：build-release/ 不存在（本机尚未构建发布产物）');
}

console.log('');
if (failed) { console.error(`桌面入口守卫：${failed} 条判红`); process.exit(1); }
console.log('桌面入口守卫全部通过');

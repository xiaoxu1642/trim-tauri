#!/usr/bin/env node
// check-desktop-entry.mjs —— 桌面稳定入口与发布暂存目录的合并守卫（2026-10-02 用户裁定 dist-app 并入 build-release）
//
// 抓什么：
//   1. 仓库里不得再有 `dist-app/` 残留，`.gitignore` 也不得再写 `dist-app/` 规则
//      —— 合并过一次就必须是**一个**入口目录，否则下一次会话会照旧口径把 exe 写回两处。
//   2. 桌面符号链接（`<桌面>\Trim.exe`）必须解析到 `build-release\Trim.exe`，
//      且目标真实存在、不是 0 字节占位。链接断掉在 Windows 上的表现是双击没反应/资源管理器
//      报"找不到"，不会有任何日志，所以只能在这里判红。
//      但「本机有没有这个链接」是**机器状态**（还有人用 OneDrive 重定向桌面），不是仓内
//      不变量：第二台构建机只要没建链接就假红，而桌面目录被重定向时还会误判成「链接不存在」。
//      所以默认只在链接**在位**时判它「是符号链接、指向 build-release、目标在位」；
//      链接缺席一律 SKIP 并声明未校验，要把它当作机检时必须显式设 TRIM_DESKTOP_GUARD=1
//      （发版收尾的人工项），届时缺席即红（T1b-L07）。
//   3. `build-release/` 里只要还有版本化产物（`Trim_x.y.z_*`），固定名 `Trim.exe` 就必须在位
//      —— 这是把发版手册 §7.4「发版收尾逐个清理旧 exe/zip」的那只手按住：清理清单里
//      `Trim.exe` 属**永不删**位，被当旧产物裁掉就等于把用户桌面上那个图标删了。
//
// 刻意不做的事：不复制/不创建任何文件，只读校验；桌面那条判的是**本机桌面**，默认只观测
//   ——链接不在位就 SKIP 并声明未校验（第二台构建机 / 桌面被 OneDrive 重定向都不假红），
//   要把它当机检就设 TRIM_DESKTOP_GUARD=1。入口目录与清理清单那几条是仓内不变量，恒判。
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
// SKIP 计数：门禁末尾不许在「有节未校验」时照旧写「全部通过」（与 T1b-L03 同口径）。
let skipped = 0;
const ok = (m, d = '') => console.log(`✓ ${m}${d ? ' — ' + d : ''}`);
const bad = (m, d = '') => { console.error(`✗ ${m}${d ? ' — ' + d : ''}`); failed++; };
const skip = (m, d = '') => { console.log(`ℹ ${m}${d ? ' — ' + d : ''}`); skipped++; };

// ---- 1. 合并后只剩一个入口目录 ----
if (existsSync(STALE_DIR)) bad('仓库里仍有 dist-app/：合并未生效或被抄回来', STALE_DIR);
else ok('1. 仓库无 dist-app/ 残留（入口只有 build-release/）');

const gi = existsSync(GITIGNORE) ? readFileSync(GITIGNORE, 'utf8') : '';
const giHit = gi.split(/\r?\n/).filter((l) => /^\s*dist-app\/?\s*$/.test(l));
if (giHit.length) bad('2. .gitignore 仍写着 dist-app 规则（旧口径未清）', giHit.join(','));
else ok('2. .gitignore 不再为 dist-app 留规则');

// ---- 3. 桌面符号链接指向合并后的稳定入口（机器状态；默认只观测，见头注 T1b-L07）----
// 桌面目录可能被 OneDrive 重定向：逐个候选取「文件真的在」的那一个，取不到再退回第一个候选。
const deskCandidates = [
  process.env.USERPROFILE && join(process.env.USERPROFILE, 'Desktop'),
  process.env.OneDrive && join(process.env.OneDrive, 'Desktop'),
  join(homedir(), 'Desktop'),
].filter(Boolean).map((d) => join(d, 'Trim.exe'));
const desktop = deskCandidates.find((p) => existsSync(p)) || deskCandidates[0];
const relExists = existsSync(REL);
const deskGuard = process.env.TRIM_DESKTOP_GUARD === '1';
if (!existsSync(desktop)) {
  if (!relExists) skip('3. 本机既无 build-release/ 也无桌面链接（干净克隆），本条无对象 —— 未校验');
  else if (!deskGuard) skip(`3. 桌面 ${desktop} 不在位 —— 这是本机环境项，**未校验**（不是通过）；发版收尾要机检这一条请设 TRIM_DESKTOP_GUARD=1`);
  else bad('3. 桌面链接不存在，但 build-release/ 在位（TRIM_DESKTOP_GUARD=1 已要求机检）', `期望 ${desktop} → ${ENTRY}`);
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
  skip('4. build-release/ 不存在（本机尚未构建发布产物）—— 未校验');
}

console.log('');
if (failed) { console.error(`桌面入口守卫：${failed} 条判红`); process.exit(1); }
console.log(skipped
  ? `桌面入口守卫：仓内不变量全部通过，另有 ${skipped} 条未校验（SKIP，不是通过）`
  : '桌面入口守卫全部通过');

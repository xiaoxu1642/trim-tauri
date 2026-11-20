#!/usr/bin/env node
// check-material-parity.mjs —— 材质链退役收口（2026-11-21，方案 v1.6 §6.4）
// 原判据（Rust 枚举 ⇄ 设置页卡片 ⇄ none 等价开关三方一致）随材质 UI 整链退役：
// 卡片集合与枚举的一致性不再有意义，改为「已退役」断言——UI/控制器/命令三面
// 不得残留任何材质 UI 形态；原生 DWM 应用链（engine::appearance::MATERIALS 与
// apply_material_outcome）按方案保留，不在本门禁射程内。
'use strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPO_ROOT } from './ps-origin.mjs';

const html = readFileSync(join(REPO_ROOT, 'src/index.html'), 'utf8');
const rustCommands = readFileSync(join(REPO_ROOT, 'src-tauri/src/commands/appearance.rs'), 'utf8');
const rustLib = readFileSync(join(REPO_ROOT, 'src-tauri/src/lib.rs'), 'utf8');
const controllerPath = join(REPO_ROOT, 'src/scripts/pathbinding-material.js');

const judgeRetired = (htmlSrc, rustCmdSrc, rustLibSrc, controllerExists) => {
  const bad = [];
  if (/class="material-card"/.test(htmlSrc)) bad.push('index.html 仍有材质卡');
  if (/id="materialMasterToggle"/.test(htmlSrc)) bad.push('index.html 仍有材质总开关');
  if (/id="bgBlur"/.test(htmlSrc)) bad.push('index.html 仍有磨砂滑杆 #bgBlur');
  if (/appearance_get_material|appearance_set_material/.test(rustCmdSrc)) bad.push('commands/appearance.rs 仍有材质命令 fn');
  if (/appearance_get_material|appearance_set_material/.test(rustLibSrc)) bad.push('lib.rs generate_handler 仍注册材质命令');
  if (controllerExists) bad.push('pathbinding-material.js 控制器仍在盘上');
  return bad;
};
const bad = judgeRetired(html, rustCommands, rustLib, existsSync(controllerPath));
if (bad.length) {
  console.error(`✗ 材质链退役不彻底：\n  ${bad.join('\n  ')}`);
  process.exit(1);
}
{
  // 正向对照：合成残留样本必须判红（判定器可翻红，不是恒绿装饰）。
  const probe = judgeRetired('<div class="material-card" data-material="mica">', '', '', false);
  const probeCtrl = judgeRetired('<div class="appearance-card">', '', '', false);
  if (probe.length !== 1 || probeCtrl.length !== 0) {
    console.error('✗ 退役判定器自检失败（残留样本未判红 / 干净样本误报）');
    process.exit(1);
  }
}
console.log('✓ 材质 UI / 控制器 / IPC 命令三面均已退役（原生 DWM 应用链按方案保留）');

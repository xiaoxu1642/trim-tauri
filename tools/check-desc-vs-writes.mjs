#!/usr/bin/env node
// check-desc-vs-writes.mjs —— P1-03：desc「保持默认/不再修改」与步骤写入交叉判据
//
// 为什么要有它：tf_svc_bulk 的 desc 曾写「商店与同步相关服务保持系统默认（不再修改）」，
// 唯一步骤却无条件把 wuauserv Start 写成 3 —— 用户按文案预期「没动这些服务」，实际被改。
// 文案与写入分叉属确定性缺陷，不能只靠人读（WindowsCleaner R1 方案要求机器拦截）。
//
// 判据口径（刻意收窄，防误伤精确表述）：
//   ① 扫 desc 中含「保持…默认」或「不再修改」的子句；
//   ② 子句含「其余 / 其他」⇒ 作者已显式把未点名对象排除（如「其余服务保持默认」），放行；
//   ③ 否则若该优化项任一 pwsh 步骤对 HKLM\…\Services 写 Start 值 ⇒ 判红。
//
// 假绿防线（AGENTS §4.1）：判红能力由 check-positive-controls 的 desc-vs-writes 条目验证
// （喂入原缺陷形态文案必须判红，见同文件）。
'use strict';
import { createRequire } from 'node:module';
import { gate } from './lib/gate.mjs';
import { ORIGIN } from './ps-origin.mjs';

const require = createRequire(import.meta.url);
const { OPTIONS } = require(`${ORIGIN}/src/scripts-powershell/optimizer-scripts.js`);

const g = gate(import.meta.url);

if (!Array.isArray(OPTIONS) || OPTIONS.length === 0) {
  g.fail('vendor OPTIONS 不是非空数组（源形状变了？）');
  g.finish();
}

/**
 * 找「声称保持默认/不再修改」且未用「其余/其他」精确限定的子句。
 * @returns {string[]} 命中的子句原文
 */
function unscopedDefaultClaims(desc) {
  const out = [];
  for (let seg of String(desc || '').split(/[。\n]/)) {
    seg = seg.trim();
    if (!seg) continue;
    if (!/保持[^，；]{0,20}默认|不再修改/.test(seg)) continue;
    if (/其余|其他/.test(seg)) continue; // 精确限定：未点名对象不评估
    out.push(seg);
  }
  return out;
}

/** 该步骤体是否对 Services 下的键写 Start 值（两信号同体）。 */
function writesServiceStart(pwsh) {
  const t = String(pwsh || '');
  return t.includes('CurrentControlSet\\Services') && /-Name\s+Start\s+-Value/.test(t);
}

let flagged = 0;
for (const o of OPTIONS) {
  const claims = unscopedDefaultClaims(o.desc);
  if (claims.length === 0) continue;
  const bodies = [];
  for (const key of ['steps', 'restore']) {
    for (const s of o[key] || []) {
      if (s.pwsh) bodies.push(s.pwsh);
    }
  }
  if (bodies.some(writesServiceStart)) {
    flagged++;
    g.fail(
      `${o.id}：desc 声称「${claims[0].slice(0, 40)}…」，步骤却在写服务 Start 值；\n` +
      '        要么改文案如实说明，要么把该写入移出（未精确限定的「保持默认」不许含服务写入）',
    );
  }
}

if (flagged === 0) {
  g.ok(`desc 与步骤写入交叉判据通过（扫描 ${OPTIONS.length} 项，无未限定的「保持默认+服务写入」）`);
}

// ==================== POSITIVE_CONTROLS：判定器自检 ====================
// 原缺陷形态必须判红；精确限定与近形必须放行（防判据变成「永远红」）。
{
  const svcBody =
    'foreach ($n in $disabled) { $p = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$n"; ' +
    'if (Test-Path $p) { New-ItemProperty -Path $p -Name Start -Value 4 -Force } }';
  const cases = [
    {
      label: '原缺陷（未限定保持默认 + 服务写入）',
      item: { id: 'fake_bad', desc: '商店与同步相关服务保持系统默认（不再修改）。', steps: [{ pwsh: svcBody }] },
      wantHit: true,
    },
    {
      label: '精确限定（其余服务保持默认）',
      item: { id: 'fake_scoped', desc: '应用商店其余服务保持默认。', steps: [{ pwsh: svcBody }] },
      wantHit: false,
    },
    {
      label: '无声称 + 服务写入',
      item: { id: 'fake_plain', desc: '批量禁用非必要服务 Start=4。', steps: [{ pwsh: svcBody }] },
      wantHit: false,
    },
  ];
  for (const c of cases) {
    const claims = unscopedDefaultClaims(c.item.desc);
    const bodies = c.item.steps.filter((s) => s.pwsh).map((s) => s.pwsh);
    const hit = claims.length > 0 && bodies.some(writesServiceStart);
    if (hit !== c.wantHit) {
      g.fail(`正向对照「${c.label}」：期望${c.wantHit ? '判红' : '放行'}，实测${hit ? '判红' : '放行'}`);
    }
  }
  g.ok(`POSITIVE_CONTROLS：${cases.length} 条判定器样本（红/放行）结论正确`);
}

g.finish('check-desc-vs-writes: 全部通过');

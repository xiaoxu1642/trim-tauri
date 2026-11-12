'use strict';
// tools/check-silent-catch.mjs —— 静默 catch / reject 出口（F4c-L18）
import { existsSync, readFileSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gate } from './lib/gate.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const g = gate(import.meta.url);

const SITES = [
  { file: 'src/scripts/fontmanager.js', fn: 'restore', needToast: '字体恢复失败，已用默认字体', needLog: '字体恢复失败' },
  { file: 'src/scripts/theme.js', fn: 'initAppearance', needToast: '读取窗口材质失败', needLog: '读取系统信息失败' },
];

// 生产判据：单站点函数体必须含 catch 出口且两条留痕都到位。
// 返回违规消息数组（空=通过），由调用方决定是否 fail——正向对照复用同一函数，
// 不污染主门禁的 failed 计数；避免旧实现里局部副本判据与生产漂移。
function judgeBody(body, site) {
  const bad = [];
  if (!/\bcatch\s*\(/.test(body)) bad.push(`${site.file}:${site.fn}：缺少 catch 出口`);
  if (!body.includes(site.needToast)) bad.push(`${site.file}:${site.fn}：缺少留痕「${site.needToast}」`);
  if (!body.includes(site.needLog)) bad.push(`${site.file}:${site.fn}：缺少留痕「${site.needLog}」`);
  return bad;
}

let skipped = false;
for (const site of SITES) {
  const abs = join(ROOT, site.file);
  if (!g.skipUnlessPresent(abs, site.file)) { skipped = true; continue; }
  const src = readFileSync(abs, 'utf8');
  const fnStart = src.indexOf(`async function ${site.fn}(`);
  if (fnStart < 0) { g.fail(`${site.file}：找不到 ${site.fn} ⇒ 判据形状漂移`); continue; }
  const open = src.indexOf('{', fnStart);
  if (open < 0) { g.fail(`${site.file}:${site.fn}：函数体缺失`); continue; }
  let depth = 0;
  let end = -1;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') { depth--; if (!depth) { end = i; break; } }
  }
  if (end < 0) { g.fail(`${site.file}:${site.fn}：函数体闭合缺失`); continue; }
  const body = src.slice(open, end + 1);
  for (const msg of judgeBody(body, site)) g.fail(msg);
}

{
  // 正向对照：复用同一判定函数——正确留痕样本不误判、静默 catch 必须识别，
  // 仅用返回的违规数组长度判定，不污染主门禁的 failed 计数。
  const good = 'async function restore() { try { await q(); } catch (e) { log("字体恢复失败"); toast("字体恢复失败，已用默认字体"); } try { await r(); } catch (e) { log("读取系统信息失败"); } }';
  const bad = 'async function restore() { try { await q(); } catch (e) {} }';
  if (judgeBody(good, SITES[0]).length > 0) g.fail('正向对照失败：正确留痕样本被误判为违规');
  if (judgeBody(bad, SITES[0]).length === 0) g.fail('正向对照失败：静默 catch 未被判定器识别');
}

if (skipped) {
  g.finish('check-silent-catch: 本节未校验（部分跟踪文件缺席，已 SKIP，不视为通过）');
} else {
  g.finish('check-silent-catch: 全部通过');
}

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

for (const site of SITES) {
  const abs = join(ROOT, site.file);
  if (!g.skipUnlessPresent(abs, site.file)) continue;
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
  if (!/\bcatch\s*\(/.test(body)) g.fail(`${site.file}:${site.fn}：缺少 catch 出口`);
  if (!body.includes(site.needToast)) g.fail(`${site.file}:${site.fn}：缺少留痕「${site.needToast}」`);
  if (!body.includes(site.needLog)) g.fail(`${site.file}:${site.fn}：缺少留痕「${site.needLog}」`);
}

{
  const good = 'async function restore() { try { await q(); } catch (e) { log("字体恢复失败"); toast("字体恢复失败，已用默认字体"); } try { await r(); } catch (e) { log("读取系统信息失败"); } }';
  const bad = 'async function restore() { try { await q(); } catch (e) {} }';
  const judge = (text) => text.includes('} catch (e) {') && text.includes('字体恢复失败') && text.includes('字体恢复失败，已用默认字体') && text.includes('读取系统信息失败');
  if (!judge(good) || judge(bad)) g.fail('正向对照失败：静默 catch 判定器失真');
}

g.finish('check-silent-catch: 全部通过');

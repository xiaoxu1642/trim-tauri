#!/usr/bin/env node
// check-cleanup-postactions.mjs —— P2-06/D-02：清理项「后置动作」侧表机械重算核对。
//
// 为什么要有它：cleanup-postactions.json 的档位不是逐条真跑得来，而是按目标路径
// 机械判定；若判定规则与侧表脱节（手改表、规则改了表没刷），前端会漏提示或多提示
// 重启资源管理器。本门禁用同一条规则独立重算全量清理项，与侧表逐 id 比对。
//
// 判据（与侧表 _rule 一致）：目标路径（fileKeys[].path / pathPs 展开的提示）落在
// `%LOCALAPPDATA%\Microsoft\Windows\Explorer`、含 `IconCache.db`、或 INetCache 类
// ⇒ explorer；其余 ⇒ none。
'use strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gate } from './lib/gate.mjs';
import { allItems } from './lib/rule-shape.mjs';

const g = gate(import.meta.url);
// T1b-L08：钉绝对根，不依赖调用方 CWD（--run 传 cwd: ROOT 只是掩盖）。
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const rulesPkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'src-tauri', 'data', 'cleanup-rules.json'), 'utf8'));
const postPkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'src-tauri', 'data', 'cleanup-postactions.json'), 'utf8'));
const table = postPkg.postActions || {};

// 收集全部清理项（顶层 items 与 subGroups.items 两层都算，口径见 tools/lib/rule-shape.mjs）
const items = allItems(rulesPkg);

/** 机械判定：从一条规则的目标位置推导后置动作。 */
function derivePostAction(it) {
  const hay = [];
  for (const fk of it.fileKeys ?? []) hay.push(fk.path || '');
  if (it.pathPs) hay.push(String(it.pathPs).toLowerCase());
  const blob = hay.join('\n').replace(/\//g, '\\').toLowerCase();
  if (blob.includes('%localappdata%\\microsoft\\windows\\explorer')) return 'explorer';
  if (blob.includes('iconcache.db')) return 'explorer';
  if (blob.includes('\\inetcache')) return 'explorer';
  return 'none';
}

let problems = 0;
const explorerFound = [];
for (const it of items) {
  const want = derivePostAction(it);
  const got = table[it.id] ?? 'none';
  if (want === 'explorer') explorerFound.push(it.id);
  if (want !== got) {
    problems++;
    g.fail(`${it.id}：机械判定=${want} 侧表=${got}（表与路径推导脱节 —— 刷 cleanup-postactions.json）`);
  }
}

// 反向护栏：侧表不许登记「机械规则推不出来」的项（防手工塞私货/规则被放宽却不报警）
const knownIds = new Set(items.map((it) => it.id));
for (const [id, action] of Object.entries(table)) {
  if (!knownIds.has(id)) {
    problems++;
    g.fail(`${id}：规则库已无此项，侧表仍登记 ${action}（退役规则必须同步摘除，none 方向同样适用）`);
    continue;
  }
  if (action === 'explorer' && !explorerFound.includes(id)) {
    problems++;
    g.fail(`${id}：侧表标 explorer，但目标路径推不出该结论（机械规则不认，来源是什么？）`);
  }
}

if (problems === 0) {
  g.ok(`后置动作侧表与路径机械重算一致（${items.length} 项，explorer: ${explorerFound.join(' / ') || '无'}）`);
}
g.finish('check-cleanup-postactions: 全部通过');

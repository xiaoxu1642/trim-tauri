'use strict';
// tools/check-user-copy-policy.mjs —— 活跃优化目录的用户可见文案不得指向已退役项、不得夹带内部术语
//
// 出处：2026-10-27 全仓重审 P1（D1-M08）。
// 病根：活跃目录里有一条项（关闭游戏 DVR 录制）的描述写着「全屏优化(FSO)相关键已统一由
// 「全屏优化(FSO)行为」负责……与 tf_fso 取值相反……第六大点-A（2026-09-14）已移交」。
// 这段字有两个问题：
//   一、指向的是**已退役项**（tf_fso 已从目录移除）⇒ 用户照着文案去找，找不到那一项；
//   二、内部 id（tf_fso）、内部轮次术语（第六大点-A）、评审日期（2026-09-14）进了**用户可见
//      文案**，而且这段文案会出现在**危险操作确认框**里（optimizer.js 的高危确认正文拼 opt.desc）。
//
// 判据面（只管活跃目录 = optimizer-runtime.json 的用户可见字段）：
//   退役 id 出现在文案里      ⇒ 红（指向已下线的项，用户找不到）
//   退役标题出现在文案里      ⇒ 红（同上）
//   轮次术语 / 评审日期括注   ⇒ 红（内部评审语言不是用户语言）
// 退役登记的权威源 = src-tauri/data/retired-optimizations.json。
//
// ⚠ 判定只作用在**活跃目录**上：item-intro.json 故意保留已退役项的介绍（那是「已下线项说明」
//   用的），把它纳入判据面会误伤 —— 现算该文件的退役 id 命中数是十六处，属预期。
//
// 用法：node tools/check-user-copy-policy.mjs

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { gate } from './lib/gate.mjs';

const ROOT = process.cwd();
const g = gate(import.meta.url);

const RUNTIME = join(ROOT, 'src-tauri', 'data', 'optimizer-runtime.json');
const RETIRED = join(ROOT, 'src-tauri', 'data', 'retired-optimizations.json');
const USER_FIELDS = ['title', 'desc', 'effect', 'pros', 'cons'];

// 轮次术语：中文「第N大点」与带评审日期的括注（半角/全角都算）
const RE_ROUND = /第[一二三四五六七八九十]+大点|[（(]\s*\d{4}-\d{2}-\d{2}\s*[)）]/;

const textOf = (v) => {
  if (typeof v === 'string') return v;
  if (Array.isArray(v)) return v.filter(x => typeof x === 'string').join('\n');
  return '';
};

/**
 * 判据本体：给定「用户可见文本」与「退役 id / 标题集合」，返回违规清单。
 * 抽成独立函数是为了让合成对照与真仓扫描共用同一判据（否则对照样例验不到真判据）。
 */
const violations = (text, ids, titles) => {
  const out = [];
  for (const id of ids) if (id && text.includes(id)) out.push(`退役 id「${id}」`);
  for (const t of titles) if (t && text.includes(t)) out.push(`退役标题「${t}」`);
  if (RE_ROUND.test(text)) out.push('内部轮次术语或评审日期');
  return out;
};

if (!g.skipUnlessPresent(RUNTIME, 'src-tauri/data（活跃优化目录）')) g.finish();

if (!existsSync(RETIRED)) {
  g.fail('退役登记 src-tauri/data/retired-optimizations.json 不存在 ⇒ 无法判「指向已退役项」');
  g.finish();
}

const runtime = JSON.parse(readFileSync(RUNTIME, 'utf8'));
const retiredItems = (JSON.parse(readFileSync(RETIRED, 'utf8')).items) || [];
const ids = retiredItems.map(x => x.id).filter(Boolean);
const titles = retiredItems.map(x => x.title).filter(Boolean);

if (!Array.isArray(runtime) || runtime.length === 0) {
  g.fail('活跃优化目录解析失败（不是非空数组）⇒ 判据对象失效');
  g.finish();
}

// 合成对照：判据必须能把「合规文案」与「违规文案」分开，否则下面这些绿是空绿
{
  const good = '关闭后台录制，减少后台录制带来的性能占用。全屏优化(FSO)相关键不在本项职责内。';
  const bad = '全屏优化(FSO)相关键已统一由「全屏优化(FSO)行为」负责，与 tf_fso 取值相反，第六大点-A（2026-09-14）已移交。';
  const okJudge = violations(good, ids, titles).length === 0;
  const badJudge = violations(bad, ids, titles).length >= 3;
  if (!okJudge || !badJudge) {
    g.fail('正向对照失败：用户文案判据失真（必须能把「合规」与「指向退役项 + 夹带轮次术语」分开）');
  } else {
    g.ok('正向对照通过：合规文案放行，指向退役项 / 夹带轮次术语必被拦');
  }
}

let bad = 0;
for (const item of runtime) {
  for (const f of USER_FIELDS) {
    const text = textOf(item[f]);
    if (!text) continue;
    const vs = violations(text, ids, titles);
    if (vs.length > 0) {
      g.fail(`活跃目录「${item.id}」的 ${f} 字段命中用户禁语：${vs.join('、')}`);
      bad++;
    }
  }
}

if (bad === 0) {
  g.ok(`活跃优化目录的用户可见文案干净（逐项扫过 ${runtime.length} 个条目的用户可见字段）`);
}

g.finish('check-user-copy-policy: 全部通过');

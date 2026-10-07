#!/usr/bin/env node
// new-residue-rule.mjs — 卸载残留规则「向导 + 干跑」（方案 §5·A8）
//
// 为什么要有这个工具：新增一条残留规则以前要手写 JSON、肉眼比对字段白名单、
// 改完再跑门禁才发现某一处不合规——而门禁的报错发生在「已经改了真库」之后。
// 本工具把反馈提前：组装候选包 → 用装载侧同一个语义校验器干跑 → 通过才谈合并。
//
// 刻意不做的事：
//   1. 不复制一份字段规则。形状/双条件/token 允许集/注册表硬否决全部交给
//      tools/check-residue-rule-contract.mjs --preview（它内部与 Rust 运行期同口径）。
//      向导里再写一遍判定就是"更新放行、装载拒绝"那种分叉的起点。
//   2. 不签名。私钥只在发布机（AGENTS §5.20），本工具只打印重签命令。
//   3. 默认不写真库，只出候选包；--apply 才合并，且合并后签名必然失效，
//      这一步是有意留给人复核的。
//
// 用法：
//   node tools/new-residue-rule.mjs --id residue-foo \
//     --name "Foo App" --publisher "Example Inc" --key "Foo" \
//     --residue "folder|%PROGRAMFILES%\Foo|安装目录" \
//     --residue "reg_key|HKLM\SOFTWARE\Foo|配置键" [--apply] [--out 候选.json]
//
// --residue 用竖线分三段：kind|target|note。target 里不要出现竖线。
'use strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const RULES = path.join(ROOT, 'src-tauri', 'data', 'uninstall-residue-rules.json');
const GATE = path.join(ROOT, 'tools', 'check-residue-rule-contract.mjs');

const { values: opt } = parseArgs({
  options: {
    id: { type: 'string' },
    name: { type: 'string', multiple: true, default: [] },
    publisher: { type: 'string', multiple: true, default: [] },
    key: { type: 'string', multiple: true, default: [] },
    residue: { type: 'string', multiple: true, default: [] },
    'reviewed-at': { type: 'string' },
    version: { type: 'string' },
    out: { type: 'string' },
    apply: { type: 'boolean', default: false },
  },
  allowPositionals: false,
});

const die = (msg) => {
  console.error('✗ ' + msg);
  process.exit(2);
};

// 只校验「能不能组装」，不校验「合不合规则库契约」——后者归门禁，见文件头第 1 条。
if (!opt.id) die('缺少 --id');
if (!/^residue-[a-z0-9][a-z0-9_-]*$/.test(opt.id)) {
  die('--id 必须形如 residue-xxx（小写字母数字/-/_，与门禁的字符集一致）');
}
if (!opt.residue.length) die('至少一条 --residue "kind|target|note"');

const residue = opt.residue.map((raw, i) => {
  const parts = raw.split('|');
  if (parts.length !== 3) die(`第 ${i + 1} 条 --residue 需要 kind|target|note 三段（当前 ${parts.length} 段）`);
  const [kind, target, note] = parts.map((s) => s.trim());
  if (!kind || !target || !note) die(`第 ${i + 1} 条 --residue 三段不得为空`);
  return { kind, target, note };
});

const rule = { id: opt.id };
if (opt.name.length) rule.displayName = opt.name;
if (opt.publisher.length) rule.publisher = opt.publisher;
if (opt.key.length) rule.uninstallKey = opt.key;
rule.residue = residue;

let base;
try {
  base = JSON.parse(fs.readFileSync(RULES, 'utf8'));
} catch (e) {
  die(`现有规则库读取失败: ${e.message}`);
}

const curVer = Number(base.rulesVersion) || 0;
const today = (() => {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return Number(`${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}`);
})();
const nextVer = opt.version ? Number(opt.version) : Math.max(today, curVer + 1);
if (!Number.isInteger(nextVer) || nextVer <= curVer) {
  die(`rulesVersion 必须大于当前值 ${curVer}（当前请求 ${opt.version ?? '自动'}）`);
}

const prov = Array.isArray(base.prov) ? base.prov.slice() : [];
prov.push({
  sourceClass: 'author-reviewed',
  reviewedAt: opt['reviewed-at'] || new Date().toISOString().slice(0, 10),
});

const candidate = {
  rulesVersion: nextVer,
  prov,
  rules: (Array.isArray(base.rules) ? base.rules : []).concat([rule]),
};

// --preview 只跑装载侧同口径的语义校验 + 注册表硬否决，不验签（私钥在发布机）。
const tmp = opt.out ? path.resolve(ROOT, opt.out) : path.join(os.tmpdir(), `trim-residue-cand-${process.pid}.json`);
if (opt.out && fs.existsSync(tmp)) die(`--out 指向的文件已存在，拒绝覆盖: ${tmp}`);
fs.writeFileSync(tmp, JSON.stringify(candidate, null, 2) + '\n', 'utf8');

const run = spawnSync(process.execPath, [GATE, '--preview', tmp], { encoding: 'utf8', cwd: ROOT });
const out = (run.stdout || '') + (run.stderr || '');
console.log(out.replace(/^/gm, '  '));

if (run.status !== 0) {
  if (!opt.out) fs.rmSync(tmp, { force: true });
  console.error('✗ 干跑未通过，真库未改动。按上面的原因修正参数后重跑。');
  process.exit(1);
}

console.log(`候选包已写出：${path.relative(ROOT, tmp).replace(/\\/g, '/')}`);
console.log(`合并后 rulesVersion: ${curVer} → ${nextVer}，规则数 ${(base.rules || []).length} → ${candidate.rules.length}`);

if (!opt.apply) {
  if (!opt.out) fs.rmSync(tmp, { force: true });
  console.log('未合并（默认只干跑）。确认候选内容后加 --apply 写入 src-tauri/data/uninstall-residue-rules.json。');
  process.exit(0);
}

// 合并时刻意丢掉 _sig：正文变了，旧签名必然验不过。留着它只会让下一次门禁报出一条
// 语义不明的「验签失败」，不如现在就让它报「缺少 _sig」并给出重签命令。
const merged = { ...candidate };
delete merged._sig;
fs.writeFileSync(RULES, JSON.stringify(merged, null, 2) + '\n', 'utf8');
console.log('✓ 已合并进真库（签名已剥离，此时门禁的 D 组会判红，属预期）');
console.log('下一步必做（私钥只在发布机，AGENTS §5.16）：');
console.log('  node tools/sign-cleanup-rules.mjs sign --file src-tauri/data/uninstall-residue-rules.json');
console.log('  node tools/check-residue-rule-contract.mjs');
console.log('回退：git checkout -- src-tauri/data/uninstall-residue-rules.json');

#!/usr/bin/env node
// check-release-artifacts.mjs —— 发布产物签名三方对拍（D1-L03）
//
// 病根：`tauri.conf.json` 没有 `createUpdaterArtifacts`，`.sig` 由发版手册手工签。
// 漏签时用户端 `requireSignedVersion: true` 会拒绝更新——症状是「新版本发了，
// 所有用户永远收不到更新」，而当前没有任何门禁检查 `build-release/` 里
// setup.exe ⇄ .sig ⇄ latest*.json.signature 是否成对。
//
// 判据（只在产物存在时判；缺产物显式 SKIP，不冒充通过）：
//   ① 当前版本的 Trim_<ver>_x64-setup.exe 与同名 .sig 成对；
//   ② 两份清单（latest.json / latest-atomgit.json）的 version = conf version；
//   ③ 两份清单的 signature 与 .sig 内容和 platforms.signature 三方一致；
//   ④ 两份清单的 sha256 与 setup 实际 sha256 一致。
//
// 用法：node tools/check-release-artifacts.mjs

import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { gate } from './lib/gate.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'build-release');
const CONF = join(ROOT, 'src-tauri', 'tauri.conf.json');
const g = gate(import.meta.url);

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

/** 纯判据：真仓与合成样本共用同一实现。 */
export function judgeReleaseArtifacts({ exeSha, sigText, version, manifests }) {
  const problems = [];
  for (const [name, m] of Object.entries(manifests)) {
    if (!m || typeof m !== 'object' || Array.isArray(m)) {
      problems.push(`${name}: 不是 JSON 对象`);
      continue;
    }
    if (m.version !== version) problems.push(`${name}: version=${JSON.stringify(m.version)} ≠ conf ${version}`);
    if (typeof m.signature !== 'string' || !m.signature) {
      problems.push(`${name}: 缺 signature`);
    } else if (sigText && m.signature !== sigText) {
      const trimmed = m.signature.trim();
      if (trimmed === sigText.trim()) {
        problems.push(`${name}: 签名含空白漂移（清单 signature 与 .sig 的原文不一致）`);
      } else {
        problems.push(`${name}: signature 与 .sig 内容不一致`);
      }
    }
    if (typeof m.sha256 !== 'string' || !m.sha256) {
      problems.push(`${name}: 缺 sha256`);
    } else if (exeSha && m.sha256 !== exeSha) {
      problems.push(`${name}: sha256 与 setup 实际哈希不一致`);
    }
    const p = m.platforms?.['windows-x86_64'];
    if (p) {
      if (p.signature !== m.signature) problems.push(`${name}: platforms.signature 与顶层不一致`);
      if (p.sha256 !== m.sha256) problems.push(`${name}: platforms.sha256 与顶层不一致`);
    }
  }
  return problems;
}

// ---- 判定器自检：正确样本放行；签名字节不符 / 哈希不符 / 版本漂移各自判红 ----
{
  const exeSha = 'a'.repeat(64);
  const sig = 'SIG';
  const good = {
    exeSha,
    sigText: sig,
    version: '1.2.3',
    manifests: {
      'latest.json': { version: '1.2.3', signature: sig, sha256: exeSha, platforms: { 'windows-x86_64': { signature: sig, sha256: exeSha } } },
      'latest-atomgit.json': { version: '1.2.3', signature: sig, sha256: exeSha },
    },
  };
  const cases = [
    ['正确样本放行', good, 0],
    ['签名字节空白漂移', {
      ...good,
      manifests: {
        'latest.json': {
          ...good.manifests['latest.json'],
          signature: `${sig} `,
          platforms: { 'windows-x86_64': { signature: `${sig} `, sha256: exeSha } },
        },
      },
    }, 1],
    ['签名字节不符', { ...good, manifests: { 'latest.json': { ...good.manifests['latest.json'], signature: 'OTHER', platforms: { 'windows-x86_64': { signature: 'OTHER', sha256: exeSha } } } } }, 1],
    ['sha256 不符', { ...good, exeSha: 'b'.repeat(64) }, 2],
    ['版本漂移', { ...good, version: '9.9.9' }, 2],
  ];
  let bad = 0;
  for (const [label, input, want] of cases) {
    const got = judgeReleaseArtifacts(input).length;
    if (got !== want) {
      bad++;
      g.fail(`正向对照「${label}」：期望 ${want} 处问题，实测 ${got} 处`);
    }
  }
  if (bad === 0) g.ok(`正向对照自检：${cases.length} 组样本结论正确`);
}

if (!existsSync(OUT)) {
  console.log('⊘ SKIP build-release/ 不存在（尚未构建/已清理）——发布产物签名本节**未校验**');
  g.finish();
  process.exit(0);
}

if (!existsSync(CONF)) {
  g.fail('src-tauri/tauri.conf.json 不存在，无法确定版本');
  g.finish();
  process.exit(1);
}

const version = JSON.parse(readFileSync(CONF, 'utf8')).version;
const setupName = `Trim_${version}_x64-setup.exe`;
const setup = join(OUT, setupName);
const sigPath = `${setup}.sig`;
if (!existsSync(setup)) {
  console.log(`⊘ SKIP build-release/ 里没有 ${setupName}（当前版本尚未构建）——本节**未校验**`);
  g.finish();
  process.exit(0);
}

const manifests = {};
for (const name of ['latest.json', 'latest-atomgit.json']) {
  const p = join(OUT, name);
  if (!existsSync(p)) {
    g.fail(`${name} 不存在——setup 已产出但清单未生成（先跑 publish-atomgit.mjs --offline 或全流程）`);
    continue;
  }
  try {
    manifests[name] = JSON.parse(readFileSync(p, 'utf8'));
  } catch (e) {
    g.fail(`${name} 不是合法 JSON：${e.message}`);
  }
}

if (!existsSync(sigPath)) {
  g.fail(`${setupName}.sig 不存在——漏签的更新包会让所有客户端永远收不到更新`);
} else {
  const sigText = readFileSync(sigPath, 'utf8');
  const exeSha = sha256(readFileSync(setup));
  const problems = judgeReleaseArtifacts({ exeSha, sigText, version, manifests });
  for (const p of problems) g.fail(p);
  if (problems.length === 0) {
    g.ok(`${setupName} ⇄ .sig ⇄ 两份清单三方一致（version=${version}，sha256=${exeSha.slice(0, 12)}…）`);
  }
}

g.finish('check-release-artifacts: 全部通过');

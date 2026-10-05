#!/usr/bin/env node
// publish-atomgit.mjs —— AtomGit 线路发版：清单生成 + 建 release + 传附件 + 回读校验
//
// 用法（发版顺序见 §7；本工具只碰 AtomGit API。GitHub 侧上传仍归 gh CLI，不在这里）：
//   node tools/publish-atomgit.mjs --dry-run         # 本地预检 + 打印计划，不写文件不联网
//   node tools/publish-atomgit.mjs --offline         # 只生成三份清单（产物区两份 + 仓根 latest-atomgit.json）
//   node tools/publish-atomgit.mjs --token-file <p>  # 全流程：等 tag 就位 → 建 release → 传三件 → 匿名回读验 sha256
//   node tools/publish-atomgit.mjs --verify-feed     # push 之后：轮询 AtomGit raw 清单直到与仓根逐字节一致
//
// 令牌：环境变量 ATOMGIT_TOKEN，或 --token-file 指向一个只含令牌的文件（首尾空白剔除）。
//   **刻意没有默认路径**——密钥材料目录属于本机信息，跟踪文件里连注释都不写（§2）。
//   请求只走 PRIVATE-TOKEN 头，绝不进 URL、不打印。
//
// 为什么清单生成也在这里：notes / 签名 / sha256 只保留一份实现，AtomGit 与 GitHub 两条
// 线路的清单由同一份字节派生 —— Gitee 时代两份清单各自手工拼，漂移过一次（M-18 同型）。
//
// 顺序硬约束：**先建 release、传齐附件，再推仓根清单**。清单先于附件上线 = 客户端拼出
// 404 下载地址；`upload_url` 在 release 不存在时恒 404（2026-10-05 实测）。本工具按这个
// 顺序执行，但仓根的 commit/push 留给发版人（push 是共享操作，脚本不替人做）。
//
// 为什么下载端点用 api.atomgit.com/.../attach_files/{file}/download：
// 三条死路实测（2026-10-05，见 updater.rs FEEDS 注释）——raw.gitcode.com 对 json 恒 403、
// gitcode.com 网页直链匿名 418 反爬、releases/latest/download 同形别名不存在。
// 这个 attach 下载端点是匿名可用的（302 到 CDN 后 200，46MB 完整下载实测过）。
'use strict';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
// 发布暂存区（未跟踪）约定见 §7.3；本工具只在发版时刻跑，缺目录 = 还没构建，报错并指路
const OUT = join(ROOT, 'build-release');
const MANIFEST_NAME = 'latest-atomgit.json';

// AtomGit 侧 owner 比 GitHub 多一个 'a'（xiao*xiao*xu1642），别照抄 GitHub 的 slug
const ATOMGIT_SLUG = 'xiaoxiaoxu1642/trim-tauri';
const GITHUB_SLUG = 'xiaoxu1642/trim-tauri';
const API = `https://api.atomgit.com/api/v5/repos/${ATOMGIT_SLUG}`;
const FEED_URL = `${API}/raw/${MANIFEST_NAME}`;

// 等待上限：平台镜像同步已于 2026-10-05 停用，代码/tag 改为直推 AtomGit，应立刻可见；
// 保留 10 分钟上限只是容忍账号侧延迟 —— 超时只报「再等等重跑」，不留半成品。
const TAG_WAIT_MS = 10 * 60 * 1000;
const FEED_WAIT_MS = 10 * 60 * 1000;
const POLL_MS = 30_000;

const argv = process.argv.slice(2);
const has = (f) => argv.includes(f);
const optVal = (f) => {
  const i = argv.indexOf(f);
  return i >= 0 ? argv[i + 1] : null;
};
const DRY = has('--dry-run');
const OFFLINE = has('--offline') || DRY;
const VERIFY_FEED = has('--verify-feed');

let failures = 0;
const ok = (m) => console.log(`✓ ${m}`);
const info = (m) => console.log(`  ${m}`);
const warn = (m) => console.log(`⚠ ${m}`);
const fail = (m) => {
  failures++;
  console.error(`✗ ${m}`);
};
const die = (m) => {
  console.error(`✗ ${m}`);
  process.exit(1);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const read = (p) => readFileSync(p, 'utf8');

// ---------------- 本地预检与清单生成 ----------------

const conf = JSON.parse(read(join(ROOT, 'src-tauri', 'tauri.conf.json')));
const ver = String(conf.version ?? '');
if (!/^\d+\.\d+\.\d+$/.test(ver)) die(`tauri.conf.json 的 version 不规范：${ver}`);

const setupName = `Trim_${ver}_x64-setup.exe`;
const sigName = `${setupName}.sig`;
const portableName = `Trim_${ver}_x64-portable.zip`;

function preflight() {
  if (!existsSync(OUT)) die(`发布暂存区不存在：${OUT}（先按 §7.3 构建并签名）`);
  const files = {
    setup: join(OUT, setupName),
    sig: join(OUT, sigName),
    portable: join(OUT, portableName),
  };
  for (const [kind, p] of Object.entries(files)) {
    if (!existsSync(p)) die(`缺产物（${kind}）：${p}（先按 §7.3 构建并签名）`);
  }
  ok(`产物三件齐（${ver}）：setup ${(readFileSync(files.setup).length / 1048576).toFixed(1)}MB / portable / sig`);

  // 签名形状 + 版本钉死：--app-version 漏传时 trusted comment 缺 `version:`，
  // 客户端 requireSignedVersion 会把整批更新判 MissingSignedVersion（§7.4 的坑）
  const sigText = read(files.sig);
  const lines = Buffer.from(sigText.replace(/\s+/g, ''), 'base64').toString('utf8').split('\n');
  const sigOk =
    lines[0]?.startsWith('untrusted comment: signature from tauri secret key') &&
    new RegExp(`(?:^|\\t)version:${ver.replace(/\./g, '\\.')}$`).test(lines[2] ?? '') &&
    (lines[2] ?? '').includes(`file:${setupName}`);
  if (!sigOk) {
    fail(`签名与版本 ${ver} 不匹配或形状不对（解出的 minisign 文本第 3 行没有 file:${setupName} 与 version:${ver}）—— 重签：--app-version 必传且先删旧 .sig`);
  } else {
    ok(`签名 trusted comment 含 file:${setupName} 且 version:${ver}（requireSignedVersion 可过）`);
  }

  // notes 与 update.md 顶部条目钉死：清单里的说明就是本版更新日志，不许错版
  const md = read(join(ROOT, 'update.md')).split(/\r?\n/);
  const start = md.findIndex((l) => l.startsWith('## 版本 '));
  if (start < 0) die('update.md 里找不到「## 版本」条目');
  if (!md[start].startsWith(`## 版本 ${ver}`)) {
    die(`update.md 顶部条目是「${md[start]}」，与版本 ${ver} 不符 —— 先把本版更新日志写到最上面`);
  }
  let end = md.findIndex((l, i) => i > start && l.startsWith('## 版本 '));
  if (end < 0) end = md.length;
  const notes = md.slice(start, end).join('\n').trim();
  ok(`notes 取自 update.md 顶部条目（${notes.length} 字符）`);

  const setupSha = sha256(readFileSync(files.setup));
  info(`setup sha256 = ${setupSha}`);

  return { files, sigText, notes, setupSha };
}

function manifestFor(notes, sigText, setupSha, url) {
  return {
    version: ver,
    notes,
    pub_date: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    url,
    signature: sigText,
    sha256: setupSha,
    platforms: {
      'windows-x86_64': { url, signature: sigText, sha256: setupSha },
    },
  };
}

const json = (o) => JSON.stringify(o, null, 2) + '\n';

function writeManifests(notes, sigText, setupSha) {
  const attachUrl = `${API}/releases/v${ver}/attach_files/${encodeURIComponent(setupName)}/download`;
  const targets = [
    [join(OUT, MANIFEST_NAME), manifestFor(notes, sigText, setupSha, attachUrl)],
    [join(OUT, 'latest.json'), manifestFor(notes, sigText, setupSha, `https://github.com/${GITHUB_SLUG}/releases/download/v${ver}/${setupName}`)],
    [join(ROOT, MANIFEST_NAME), manifestFor(notes, sigText, setupSha, attachUrl)],
  ];
  for (const [p, obj] of targets) {
    writeFileSync(p, json(obj));
    ok(`写入 ${p.replace(ROOT + '\\', '').replace(ROOT + '/', '')}`);
  }
}

// ---------------- AtomGit API ----------------

function loadToken() {
  const tf = optVal('--token-file');
  if (tf) {
    if (!existsSync(tf)) die(`--token-file 指向的文件不存在：${tf}`);
    return read(tf).trim();
  }
  const env = process.env.ATOMGIT_TOKEN;
  if (env && env.trim()) return env.trim();
  die('缺少 AtomGit 令牌：用环境变量 ATOMGIT_TOKEN 或 --token-file 传入（仓库外的本机密钥材料，以 §7.4 为准）');
}

async function api(path, { method = 'GET', token, body, timeout = 60_000 } = {}) {
  const res = await fetch(API + path, {
    method,
    headers: {
      ...(token ? { 'PRIVATE-TOKEN': token } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeout),
  });
  const text = await res.text();
  let data = null;
  try {
    data = JSON.parse(text);
  } catch {
    /* 非 JSON（CDN/网关错误页）—— 原样留在 text 里给报错用 */
  }
  return { status: res.status, ok: res.ok, data, text };
}

// 匿名回读 —— 与客户端同一条路：不带任何头，302 到 CDN 后拿完整字节算 sha256
async function remoteSha(name) {
  try {
    const res = await fetch(`${API}/releases/v${ver}/attach_files/${encodeURIComponent(name)}/download`, {
      signal: AbortSignal.timeout(300_000),
    });
    if (res.status === 404) return { missing: true };
    if (!res.ok) return { error: `HTTP ${res.status}` };
    return { sha: sha256(Buffer.from(await res.arrayBuffer())) };
  } catch (e) {
    return { error: e?.message ?? String(e) };
  }
}

async function waitTag(token) {
  const deadline = Date.now() + TAG_WAIT_MS;
  for (;;) {
    const r = await api('/tags?per_page=100', { token });
    if (r.ok && Array.isArray(r.data) && r.data.some((t) => t.name === `v${ver}`)) return;
    if (Date.now() > deadline) {
      die(`等不到 AtomGit 的 tag v${ver}（已等 ${TAG_WAIT_MS / 60000} 分钟）。确认 tag 已直推到 AtomGit，稍后重跑本脚本（重跑安全，不会留半成品）`);
    }
    info(`AtomGit 尚无 tag v${ver}（等 push 到达），30s 后重查`);
    await sleep(POLL_MS);
  }
}

async function ensureRelease(token, notes) {
  const tag = `v${ver}`;
  const detail = await api(`/releases/${tag}`, { token });
  if (detail.ok) {
    info(`release ${tag} 已存在，PATCH 同步标题与说明`);
    const p = await api(`/releases/${tag}`, { method: 'PATCH', token, body: { name: `Trim ${ver}`, body: notes } });
    if (!p.ok) warn(`PATCH 失败（HTTP ${p.status}）：${p.text.slice(0, 200)} —— 不影响附件与下载，继续`);
    return;
  }
  if (detail.status !== 404) die(`查 release 状态失败：HTTP ${detail.status} ${detail.text.slice(0, 200)}`);
  // release_status 暂不带：字段语义未实测，先按最小集建；可见性由后面的匿名下载验证兜底
  let c = await api('/releases', {
    method: 'POST',
    token,
    body: { tag_name: tag, name: `Trim ${ver}`, body: notes, target_commitish: 'main' },
  });
  if (!c.ok) {
    warn(`POST 建 release 失败（HTTP ${c.status}）：${c.text.slice(0, 200)} —— 去掉 target_commitish 重试一次`);
    c = await api('/releases', { method: 'POST', token, body: { tag_name: tag, name: `Trim ${ver}`, body: notes } });
  }
  if (!c.ok) die(`建 release 失败：HTTP ${c.status} ${c.text.slice(0, 300)}`);
  ok(`release ${tag} 已创建（name=Trim ${ver}）`);
}

async function ensureAsset(token, name, localPath) {
  const localSha = sha256(readFileSync(localPath));
  let r = await remoteSha(name);
  if (r.sha === localSha) {
    ok(`${name} 线上已有且 sha256 一致，跳过上传`);
    return;
  }
  if (r.sha && r.sha !== localSha) {
    die(`${name} 线上已有同名附件但字节不一致（线上 ${r.sha.slice(0, 12)}… ≠ 本地 ${localSha.slice(0, 12)}…）—— 人工核查，不自动覆盖`);
  }
  if (r.error) warn(`${name} 回读探测异常（${r.error}），尝试直接上传`);

  const up = await api(`/releases/v${ver}/upload_url?file_name=${encodeURIComponent(name)}`, { token });
  if (!up.ok || !up.data?.url) die(`${name} 取 upload_url 失败：HTTP ${up.status} ${up.text.slice(0, 200)}`);
  const put = await fetch(up.data.url, {
    method: 'PUT',
    headers: up.data.headers ?? {},
    body: readFileSync(localPath),
    signal: AbortSignal.timeout(600_000),
  });
  if (!put.ok) die(`${name} 上传失败：HTTP ${put.status} ${(await put.text()).slice(0, 200)}`);

  for (let i = 0; i < 6; i++) {
    r = await remoteSha(name);
    if (r.sha === localSha) {
      ok(`${name} 上传成功，匿名回读 sha256 一致（${localSha.slice(0, 12)}…）`);
      return;
    }
    await sleep(3000);
  }
  die(`${name} 上传后匿名回读不一致或读不到：${JSON.stringify(r).slice(0, 200)}`);
}

async function verifyFeed() {
  const localPath = join(ROOT, MANIFEST_NAME);
  if (!existsSync(localPath)) die(`仓根没有 ${MANIFEST_NAME} —— 先跑一次生成`);
  const localSha = sha256(readFileSync(localPath));
  const deadline = Date.now() + FEED_WAIT_MS;
  for (;;) {
    const res = await fetch(FEED_URL, { signal: AbortSignal.timeout(30_000), cache: 'no-store' });
    if (res.ok) {
      const buf = Buffer.from(await res.arrayBuffer());
      if (sha256(buf) === localSha) {
        let j = null;
        try {
          j = JSON.parse(buf.toString('utf8'));
        } catch {
          /* 字节一致但 JSON 解析失败不可能走到这 —— 下方版本断言兜底 */
        }
        if (j?.version !== ver) die(`raw 清单与仓根逐字节一致，但 version=${j?.version} ≠ conf ${ver} —— 仓根文件是不是没重生成？`);
        ok(`AtomGit raw 清单已与仓根逐字节一致（version=${ver}，sha256=${localSha.slice(0, 12)}…）`);
        return;
      }
      warn('raw 清单已存在但与仓根不一致（push 未到达或内容分叉），30s 后再查');
    } else if (res.status === 404) {
      info('raw 清单还没出现（push 尚未到达 AtomGit），30s 后再查');
    } else {
      warn(`raw 清单读取异常 HTTP ${res.status}，30s 后再查`);
    }
    if (Date.now() > deadline) die(`等不到 raw 清单更新（已等 ${FEED_WAIT_MS / 60000} 分钟）—— 确认仓根清单已直推到 AtomGit main，之后再跑 --verify-feed`);
    await sleep(POLL_MS);
  }
}

// ---------------- 主流程 ----------------

try {
  if (VERIFY_FEED) {
    await verifyFeed();
  } else {
    const { files, sigText, notes, setupSha } = preflight();
    if (failures > 0) die('预检未过，终止（清单未写、未联网）');

    if (DRY) {
      console.log('');
      console.log('[dry-run] 将写入：');
      console.log(`  build-release/${MANIFEST_NAME}、build-release/latest.json、仓根 ${MANIFEST_NAME}`);
      console.log(`[dry-run] 将执行（联网）：等 tag v${ver} 就位 → 建 release（name=Trim ${ver}）→ 上传 ${setupName} / ${portableName} / ${sigName} → 匿名回读验 sha256`);
      console.log('[dry-run] 不写文件、不联网。');
      process.exit(0);
    }

    writeManifests(notes, sigText, setupSha);

    if (OFFLINE) {
      console.log('');
      info('--offline：到此为止。仓根清单已生成，先 commit/push 再跑联网流程（或直接跑全流程）');
    } else {
      const token = loadToken();
      console.log('');
      await waitTag(token);
      ok(`AtomGit 已有 tag v${ver}`);
      await ensureRelease(token, notes);
      await ensureAsset(token, setupName, files.setup);
      await ensureAsset(token, portableName, files.portable);
      await ensureAsset(token, sigName, files.sig);
      console.log('');
      console.log('附件已全部上线。下一步（顺序不能反）：');
      console.log(`  git add ${MANIFEST_NAME} && git commit && git push   # 推仓根清单；镜像已停用，AtomGit 须直推（§7.4）`);
      console.log('  AtomGit 收到后：node tools/publish-atomgit.mjs --verify-feed');
    }
  }
} catch (e) {
  die(`意外错误：${e?.message ?? e}`);
}

console.log('');
if (failures > 0) {
  console.error('publish-atomgit: 有断言未通过');
  process.exit(1);
}
console.log('publish-atomgit: 完成');

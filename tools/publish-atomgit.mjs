#!/usr/bin/env node
// publish-atomgit.mjs —— AtomGit 线路发版：清单生成 + 建 release + 传附件 + 回读校验
//
// 用法（发版顺序见发版手册 §7；本工具只碰 AtomGit API。GitHub 侧上传仍归 gh CLI，不在这里）：
//   node tools/publish-atomgit.mjs --dry-run         # 本地预检 + 打印计划，不写文件不联网
//   node tools/publish-atomgit.mjs --offline         # 只生成产物区两份清单；仓根清单等附件上线后再写
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
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign as signEd25519,
  verify as verifyEd25519,
} from 'node:crypto';

import { writeFileAtomic } from './lib/atomic-write.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
// 发布暂存区（未跟踪）约定见发版手册 §7.3；本工具只在发版时刻跑，缺目录 = 还没构建，报错并指路
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

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function decodeMinisignEnvelope(text, kind) {
  const b64 = String(text ?? '');
  if (!b64 || !/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) {
    throw new Error(`${kind} 不是单层 base64`);
  }
  const raw = Buffer.from(b64, 'base64');
  if (!raw.length) throw new Error(`${kind} base64 解出空内容`);
  return raw.toString('utf8');
}

function parseMinisignSignature(sigText) {
  const inner = decodeMinisignEnvelope(sigText, '.sig').split(/\r?\n/).filter((l) => l.length);
  if (inner.length !== 4) throw new Error(`签名应为四行 minisign 文本，实得 ${inner.length} 行`);
  const bin = Buffer.from(inner[1], 'base64');
  const global = Buffer.from(inner[3], 'base64');
  if (bin.length !== 74 || global.length !== 64) {
    throw new Error(`签名 blob 长度异常（signature=${bin.length}, global=${global.length}）`);
  }
  const algorithm = bin.subarray(0, 2).toString('latin1');
  if (algorithm !== 'Ed' && algorithm !== 'ED') {
    throw new Error(`不支持的 minisign 算法 ${JSON.stringify(algorithm)}`);
  }
  if (!inner[2].startsWith('trusted comment: ')) {
    throw new Error('签名第三行不是 trusted comment');
  }
  return {
    algorithm,
    keyId: bin.subarray(2, 10),
    signature: bin.subarray(10, 74),
    trustedComment: inner[2].slice('trusted comment: '.length),
    globalSignature: global,
  };
}

function parseMinisignPublicKey(pubkeyText) {
  const inner = decodeMinisignEnvelope(pubkeyText, 'updater pubkey').split(/\r?\n/).filter((l) => l.length);
  if (inner.length !== 2) throw new Error(`公钥应为两行 minisign 文本，实得 ${inner.length} 行`);
  const bin = Buffer.from(inner[1], 'base64');
  if (bin.length !== 42) throw new Error(`公钥 blob 应为 42 字节，实得 ${bin.length}`);
  const algorithm = bin.subarray(0, 2).toString('latin1');
  if (algorithm !== 'Ed' && algorithm !== 'ED') {
    throw new Error(`不支持的 minisign 公钥算法 ${JSON.stringify(algorithm)}`);
  }
  const der = Buffer.concat([ED25519_SPKI_PREFIX, bin.subarray(10, 42)]);
  return {
    keyId: bin.subarray(2, 10),
    key: createPublicKey({ key: der, format: 'der', type: 'spki' }),
  };
}

/**
 * 与 `tauri-plugin-updater::verify_signature` 的公开验签链同口径：
 * 先按签名算法验文件（ED=Blake2b-512 预哈希，Ed=旧版直签），再验 global signature。
 * trusted comment 只有在这两步都通过后才可以消费。
 */
function verifyMinisign(data, sigText, pubkeyText) {
  const sig = parseMinisignSignature(sigText);
  const pub = parseMinisignPublicKey(pubkeyText);
  if (!sig.keyId.equals(pub.keyId)) {
    throw new Error(`签名 keyid=${sig.keyId.toString('hex')} 与 updater 公钥=${pub.keyId.toString('hex')} 不一致`);
  }
  const signed = sig.algorithm === 'ED'
    ? createHash('blake2b512').update(data).digest()
    : data;
  if (!verifyEd25519(null, signed, pub.key, sig.signature)) {
    throw new Error('setup.exe 字节验签失败');
  }
  const global = Buffer.concat([sig.signature, Buffer.from(sig.trustedComment, 'utf8')]);
  if (!verifyEd25519(null, global, pub.key, sig.globalSignature)) {
    throw new Error('minisign trusted comment 的 global signature 验签失败');
  }
  return { trustedComment: sig.trustedComment };
}

function selfTestMinisign() {
  // 正向对照：minisign-verify 0.2.5 自带测试向量的预哈希签名（消息为 `test`）。
  // 该向量不经过本脚本自造密钥，能发现“自签自验但算法口径整体写错”的假绿。
  const knownPub = Buffer.from([
    'untrusted comment: minisign public key E7620F1842B4E81F',
    'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3',
    '',
  ].join('\n')).toString('base64');
  const knownSig = Buffer.from([
    'untrusted comment: signature from minisign secret key',
    'RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=',
    'trusted comment: timestamp:1556193335\tfile:test',
    'y/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==',
    '',
  ].join('\n')).toString('base64');
  verifyMinisign(Buffer.from('test'), knownSig, knownPub);

  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const rawPublic = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const keyId = Buffer.from('0102030405060708', 'hex');
  const pubBlob = Buffer.concat([Buffer.from('ED', 'latin1'), keyId, rawPublic]);
  const pubEnvelope = Buffer.from(
    `untrusted comment: minisign public key: 0102030405060708\n${pubBlob.toString('base64')}\n`,
  ).toString('base64');
  const data = Buffer.from('synthetic setup bytes for publish preflight', 'utf8');
  const digest = createHash('blake2b512').update(data).digest();
  const signature = signEd25519(null, digest, privateKey);
  const trustedComment = 'timestamp:0\tfile:Trim_1.0.0_x64-setup.exe\tversion:1.0.0';
  const globalSignature = signEd25519(
    null,
    Buffer.concat([signature, Buffer.from(trustedComment, 'utf8')]),
    privateKey,
  );
  const sigBlob = Buffer.concat([Buffer.from('ED', 'latin1'), keyId, signature]);
  const sigEnvelope = Buffer.from(
    [
      'untrusted comment: signature from tauri secret key',
      sigBlob.toString('base64'),
      `trusted comment: ${trustedComment}`,
      globalSignature.toString('base64'),
      '',
    ].join('\n'),
  ).toString('base64');

  const got = verifyMinisign(data, sigEnvelope, pubEnvelope);
  if (got.trustedComment !== trustedComment) throw new Error('正例 trusted comment 不一致');

  const tampered = Buffer.from(data);
  tampered[0] ^= 1;
  let dataRejected = false;
  try {
    verifyMinisign(tampered, sigEnvelope, pubEnvelope);
  } catch {
    dataRejected = true;
  }
  if (!dataRejected) throw new Error('篡改 setup 字节仍通过验签 —— 判据失明');

  // 版本号写在 trusted comment 里，必须由 global signature 一并背书；只验包体而不验
  // 注释，会让攻击者把旧包配上新版本号。这里保留原 global signature，单独改注释。
  const tamperedComment = trustedComment.replace('version:1.0.0', 'version:9.9.9');
  if (tamperedComment === trustedComment) throw new Error('自检向量未覆盖 version 字段');
  const tamperedCommentSig = Buffer.from(
    [
      'untrusted comment: signature from tauri secret key',
      sigBlob.toString('base64'),
      `trusted comment: ${tamperedComment}`,
      globalSignature.toString('base64'),
      '',
    ].join('\n'),
  ).toString('base64');
  let commentRejected = false;
  try {
    verifyMinisign(data, tamperedCommentSig, pubEnvelope);
  } catch {
    commentRejected = true;
  }
  if (!commentRejected) throw new Error('篡改 trusted comment 仍通过验签 —— 版本绑定失明');

  console.log('✓ minisign 自检：真实验签正例通过，包体篡改与 trusted comment 篡改负例均被拒');
}

if (has('--self-test-minisign')) {
  try {
    selfTestMinisign();
    process.exit(0);
  } catch (e) {
    die(`minisign 自检失败：${e?.message ?? e}`);
  }
}

// ---------------- 本地预检与清单生成 ----------------

const conf = JSON.parse(read(join(ROOT, 'src-tauri', 'tauri.conf.json')));
const ver = String(conf.version ?? '');
if (!/^\d+\.\d+\.\d+$/.test(ver)) die(`tauri.conf.json 的 version 不规范：${ver}`);

const setupName = `Trim_${ver}_x64-setup.exe`;
const sigName = `${setupName}.sig`;
const portableName = `Trim_${ver}_x64-portable.zip`;

function preflight() {
  if (!existsSync(OUT)) die(`发布暂存区不存在：${OUT}（先按发版手册 §7.3 构建并签名）`);
  const files = {
    setup: join(OUT, setupName),
    sig: join(OUT, sigName),
    portable: join(OUT, portableName),
  };
  for (const [kind, p] of Object.entries(files)) {
    if (!existsSync(p)) die(`缺产物（${kind}）：${p}（先按发版手册 §7.3 构建并签名）`);
  }
  // 签名验的是**这一份实际字节**，sha256 也从同一 Buffer 派生；后续重建未重签时，
  // 不会出现「清单 hash 来自新包、签名只解注释」的假通过。
  const setupBuf = readFileSync(files.setup);
  ok(`产物三件齐（${ver}）：setup ${(setupBuf.length / 1048576).toFixed(1)}MB / portable / sig`);

  // 与 updater 插件同链验签：updater 公钥 → minisign 文件签名 → global signature。
  // trusted comment 必须等密码学验证通过后才能消费。
  const sigText = read(files.sig);
  let trustedComment = '';
  try {
    trustedComment = verifyMinisign(
      setupBuf,
      sigText,
      String(conf?.plugins?.updater?.pubkey ?? ''),
    ).trustedComment;
    ok(`setup.exe 实字节验签通过（updater keyid 与 .sig 一致）`);
  } catch (e) {
    fail(`setup.exe 实字节验签失败：${e?.message ?? e} —— 必须重签，禁止只替换 .sig 注释`);
  }
  if (trustedComment) {
    const sigOk =
      new RegExp(`(?:^|\\t)version:${ver.replace(/\./g, '\\.')}$`).test(trustedComment) &&
      trustedComment.includes(`file:${setupName}`);
    if (!sigOk) {
      fail(`签名 trusted comment 与版本 ${ver}/file:${setupName} 不匹配 —— 重签时 --app-version 必传`);
    } else {
      ok(`签名 trusted comment 含 file:${setupName} 且 version:${ver}（requireSignedVersion 可过）`);
    }
  }

  // notes 与 update.md 顶部条目钉死：清单里的说明就是本版更新日志，不许错版
  const md = read(join(ROOT, 'update.md')).split(/\r?\n/);
  const start = md.findIndex((l) => l.startsWith('## 版本 '));
  if (start < 0) die('update.md 里找不到「## 版本」条目');
  if (!md[start].startsWith(`## 版本 ${ver}`)) {
    die(`update.md 顶部条目是「${md[start]}」，与版本 ${ver} 不符 —— 先把本版更新日志写到最上面`);
  }
  // 条目边界是**任意二级标题**，不是「下一个 ## 版本」：0.8.9 上面新增的
  // 「## 文档整理」不是版本条目，旧边界会把它整段吞进更新说明（2026-11-02 实测）。
  let end = md.findIndex((l, i) => i > start && l.startsWith('## '));
  if (end < 0) end = md.length;
  const notes = md.slice(start, end).join('\n').trim();
  ok(`notes 取自 update.md 顶部条目（${notes.length} 字符）`);

  const setupSha = sha256(setupBuf);
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

const atomgitAttachUrl = () =>
  `${API}/releases/v${ver}/attach_files/${encodeURIComponent(setupName)}/download`;

/** T1c-M06：产物区两份清单与附件无关，可先写；仓根清单是「客户端会立刻拉」的入口，
 *  必须等三次 ensureAsset 成功后再写——否则 --offline 会让发版人先 push 一份指向 404 的清单。 */
function writeBuildManifests(notes, sigText, setupSha) {
  const targets = [
    [join(OUT, MANIFEST_NAME), manifestFor(notes, sigText, setupSha, atomgitAttachUrl())],
    [join(OUT, 'latest.json'), manifestFor(notes, sigText, setupSha, `https://github.com/${GITHUB_SLUG}/releases/download/v${ver}/${setupName}`)],
  ];
  for (const [p, obj] of targets) {
    writeFileAtomic(p, json(obj));
    ok(`写入 ${p.replace(ROOT + '\\', '').replace(ROOT + '/', '')}`);
  }
}

function writeRootManifest(notes, sigText, setupSha) {
  const p = join(ROOT, MANIFEST_NAME);
  writeFileAtomic(p, json(manifestFor(notes, sigText, setupSha, atomgitAttachUrl())));
  ok(`写入 ${MANIFEST_NAME}（附件已全部上线之后）`);
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
  die('缺少 AtomGit 令牌：用环境变量 ATOMGIT_TOKEN 或 --token-file 传入（仓库外的本机密钥材料，以发版手册 §7.4 为准）');
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

    writeBuildManifests(notes, sigText, setupSha);

    if (OFFLINE) {
      console.log('');
      info('--offline：只生成 build-release 两份清单。仓根清单未写——它必须等附件上线后再生成，');
      info('  否则 hash/url 指向还不存在的附件，客户端会拿到 404。联网流程会自动在三次上传后写它。');
    } else {
      const token = loadToken();
      console.log('');
      await waitTag(token);
      ok(`AtomGit 已有 tag v${ver}`);
      await ensureRelease(token, notes);
      await ensureAsset(token, setupName, files.setup);
      await ensureAsset(token, portableName, files.portable);
      await ensureAsset(token, sigName, files.sig);
      writeRootManifest(notes, sigText, setupSha);
      console.log('');
      console.log('附件已全部上线。下一步（顺序不能反）：');
      console.log(`  git add ${MANIFEST_NAME} && git commit && git push   # 推仓根清单；镜像已停用，AtomGit 须直推（发版手册 §7.4）`);
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

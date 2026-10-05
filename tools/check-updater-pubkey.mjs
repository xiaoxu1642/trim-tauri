#!/usr/bin/env node
// check-updater-pubkey.mjs —— 更新验签的公钥形状门禁（2026-10-05 由真实事故固化）
//
// 抓什么：`tauri.conf.json` 的 `plugins.updater.pubkey` 必须是 **base64(minisign 公钥两行文本)**，
// 也就是 `cargo tauri signer generate` 写出的 `.pub` 文件内容本身。
// 多包一层 base64 的话，插件 `verify_signature` 的第一步就解不开，症状是客户端下载完安装包后
// 报 `Invalid encoding in minisign data` —— 而**检查更新本身仍然返回「发现新版本」**，
// 于是线路通、清单对、包也下完了，只有最后一步永远失败：所有在线客户端都升不了级。
//
// 为什么值得单开一条门禁：这个形状在 conf 里是一串看不出自家套了几层的 base64，
// 人眼读不出来、单测跑不到（要真下载）、发布清单也测不到（清单里那个字段是签名不是公钥）。
// 真机坐实过一次：0.6.3 发出去后用真实老客户端跑「检查→下载」才暴露，公钥是 204 字符（两层），
// 而正确值是 152 字符（一层）。
//
// 用法：node tools/check-updater-pubkey.mjs
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
let failed = 0;
const ok = (m) => console.log(`✓ ${m}`);
const fail = (m) => { console.error(`✗ ${m}`); failed++; };
const skip = (m) => console.log(`⊘ ${m}`);

const conf = JSON.parse(readFileSync(join(ROOT, 'src-tauri', 'tauri.conf.json'), 'utf8'));
const up = conf?.plugins?.updater;

// 1) requireSignedVersion 必须是 true（AGENTS §5.8：插件 serde 默认 false，
//    关掉后伪造响应可以把虚高版本号配旧版合法签名，实现强制降级）
if (!up) {
  fail('tauri.conf.json 里没有 plugins.updater 段');
} else {
  if (up.requireSignedVersion === true) ok('1. plugins.updater.requireSignedVersion = true（防强制降级）');
  else fail(`1. requireSignedVersion 必须是 true，实得 ${JSON.stringify(up.requireSignedVersion)} —— 关掉即可被伪造清单强制降级`);

  // 2) 公钥形状：解一层 base64 → 两行文本 → 第二行再解 base64 → 恰好 42 字节且算法是 Ed/ED
  const pk = String(up.pubkey ?? '');
  if (!pk) {
    fail('2. plugins.updater.pubkey 为空');
  } else {
    let layer1 = null;
    try { layer1 = Buffer.from(pk, 'base64').toString('utf8'); } catch (e) { /* 下面按形状判 */ }
    const lines = (layer1 ?? '').split(/\r?\n/).filter((l) => l.length);
    if (!layer1 || lines.length !== 2) {
      fail(`2. pubkey 解一层 base64 后不是「两行 minisign 文本」（实得 ${lines.length} 行）`
        + ` —— 长度 ${pk.length} 字符，多半是多包/少包了一层 base64；正确值就是 .pub 文件内容本身`);
    } else if (!/^untrusted comment: minisign public key:/.test(lines[0])) {
      fail(`2. pubkey 首行不是 untrusted comment（实得 ${JSON.stringify(lines[0].slice(0, 40))}）`);
    } else {
      const bin = Buffer.from(lines[1], 'base64');
      const algo = bin.subarray(0, 2).toString('latin1');
      if (bin.length !== 42) {
        fail(`2. 公钥 blob 应恰好 42 字节（算法 2 + keyid 8 + 密钥 32），实得 ${bin.length}`);
      } else if (algo !== 'Ed' && algo !== 'ED') {
        fail(`2. 公钥算法段应为 Ed/ED，实得 ${JSON.stringify(algo)}`);
      } else {
        ok(`2. pubkey 形状正确（一层 base64 → 两行文本 → 42 字节 Ed 公钥，keyid ${bin.subarray(2, 10).toString('hex')}）`);

        // 3) 有本地签名产物时顺手对 keyid：清单里那份签名必须是这把公钥签的。
        //    build-release/ 是**未跟踪**的发版产物区，换机器/干净克隆里没有 ⇒ 缺件就 SKIP，
        //    不 ENOENT 崩掉整轮验收，也不打 ✓ 冒充校验过（AGENTS §2 红线）。
        const sigDir = join(ROOT, 'build-release');
        let target = null;
        if (existsSync(sigDir)) {
          const cand = readdirSync(sigDir).filter((f) => f.endsWith('.exe.sig'));
          // 只取与当前版本同号的那份；没有就取任意一份（keyid 与版本无关）
          const want = `Trim_${conf.version}_x64-setup.exe.sig`;
          target = cand.includes(want) ? want : cand[0] || null;
        }
        if (!target) {
          skip(`3. 本机没有 .exe.sig 产物（build-release/ 未跟踪）—— 公钥与签名的 keyid 一致性**未校验**`);
        } else {
          const sigText = readFileSync(join(sigDir, target), 'utf8').trim();
          const inner = Buffer.from(sigText, 'base64').toString('utf8').split(/\r?\n/).filter((l) => l.length);
          if (inner.length < 4) {
            fail(`3. ${target} 解一层后不是四行 minisign 签名（实得 ${inner.length} 行）`);
          } else {
            const sbin = Buffer.from(inner[1], 'base64');
            const sid = sbin.subarray(2, 10).toString('hex');
            const pid = bin.subarray(2, 10).toString('hex');
            if (sid === pid) ok(`3. ${target} 的 keyid 与 conf 公钥一致（${pid}）`);
            else fail(`3. keyid 不一致：conf 公钥 ${pid} / 签名 ${sid} —— 这份包永远验不过，客户端会卡在验签`);
          }
        }
      }
    }
  }
}

console.log('');
if (failed > 0) {
  console.error(`更新公钥形状门禁失败 ${failed} 项。`);
  process.exit(1);
}
console.log('更新公钥形状门禁全部通过');

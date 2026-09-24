// src/main/update-signature.js — 自动更新通道的可信锚点（v3.6.5 M1-1）
// 为什么：latest.yml 与安装包同源同前缀（.../releases/latest/download/），通道被接管时
//   可以同时提供「恶意 latest.yml（写恶意包的 sha512）」与「恶意安装包（sha512 自洽）」，
//   electron-updater 的 sha512 强校验照样通过——因为校验锚点由通道自己提供。
//   因此 sha512 必须由「应用内置公钥」背书，而不是由「通道」提供。
//   规则库更新（rules-signature.js）早已是这个模型，本模块把更新链拉齐到同一标准。
// 约束：本模块只做纯计算（crypto + 字符串），**不得 require electron** —— test-features.js 要直接单测它。
// 约束：私钥只存在于发布机（scripts/sign-update.js gen 生成，默认 ~/.trim-signing/），绝不入仓库。
'use strict';
const crypto = require('crypto');

// 内置公钥**数组**（不是单值）：更新链必须支持密钥轮换。
// 轮换顺序是硬约束（详见 scripts/sign-update.js 头部注释）：
//   先发一版内置 [旧, 新] 的应用 → 等用户升级 → 再用新私钥签名 → 稳定后再发一版收敛为 [新]。
//   若反过来「先换私钥再发新版」，老用户（只有旧公钥）会永久验签失败，等同锁死。
const UPDATE_PUBKEYS = [
`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAQPbp0L/krZFebt5B3/OGQPtPQ1ZwOqpPfPTG3gSNckc=
-----END PUBLIC KEY-----`
];

// 验签：对 latest.yml 的**原始字节**做 ed25519 验签。
// 为什么强调「原始字节」：绝不可先 toString()/trim()/JSON 归一化再签验——不同平台的换行与 BOM
// 处理会让发布侧与客户端算出不同摘要，导致正版也被误判为 mismatch（本次就要避免的自伤）。
// 返回三态：
//   { ok: true }
//   { ok: false, kind: 'unsigned', reason }  —— 没有签名（发布事故/漏签），可自愈
//   { ok: false, kind: 'mismatch', reason }  —— 签名存在但验不过（可疑篡改），必须对用户明说
// 为什么区分 unsigned 与 mismatch：前者是发布方疏忽，后者是安全事件，文案与日志级别都不同。
function verifyUpdateInfoSignature(rawBuf, sigText) {
  if (rawBuf == null) return { ok: false, kind: 'unsigned', reason: 'latest.yml 内容为空' };
  const b64 = String(sigText == null ? '' : sigText).trim();
  if (!b64) return { ok: false, kind: 'unsigned', reason: '未取得发布签名（latest.yml.sig 为空）' };

  let signature;
  try {
    signature = Buffer.from(b64, 'base64');
  } catch (e) {
    return { ok: false, kind: 'mismatch', reason: '签名数据解码失败' };
  }
  // ed25519 签名固定 64 字节；长度不对必然不是本算法产出，直接判 mismatch（不是 unsigned）
  if (signature.length !== 64) {
    return { ok: false, kind: 'mismatch', reason: `签名长度非法（应为 64 字节，实际 ${signature.length}）` };
  }

  for (const pem of UPDATE_PUBKEYS) {
    try {
      if (crypto.verify(null, rawBuf, pem, signature)) return { ok: true };
    } catch (_) {
      // 公钥格式异常（含尚未回填的占位块）时跳过，继续试数组里下一把公钥
    }
  }
  return { ok: false, kind: 'mismatch', reason: '签名校验失败：latest.yml 可能被篡改' };
}

// 从**已验签**的 latest.yml 原文抽锚点（version / sha512 / path）。
// 为什么不解析 YAML：零新增依赖是红线，且锚点只需要 3 个标量字段。
// 安全性来自「文本已验签」这一步，正则只影响可用性与健壮性；解析不出就返回 null，调用方 fail-closed。
// 顶层键用 ^ 锚定行首，避免命中 files[] 里缩进的同名字段。
function extractUpdateAnchor(text) {
  if (typeof text !== 'string' || !text) return null;
  const version = (text.match(/^version:[ \t]*(\S+)[ \t]*$/m) || [])[1] || '';
  const sha512 = (text.match(/^sha512:[ \t]*(\S+)[ \t]*$/m) || [])[1] || '';
  const file = (text.match(/^path:[ \t]*(\S+)[ \t]*$/m) || [])[1] || '';
  // 三个字段都必须是可判定的形态，任一不符即视为结构异常（返回 null → fail-closed）
  if (!/^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$/.test(version)) return null;
  if (!/^[A-Za-z0-9+/]{86,90}={0,2}$/.test(sha512)) return null; // base64(64B) ≈ 88 字符
  if (!/^[A-Za-z0-9._-]+\.exe$/i.test(file)) return null;
  return { version, sha512, file };
}

module.exports = { verifyUpdateInfoSignature, extractUpdateAnchor, UPDATE_PUBKEYS };

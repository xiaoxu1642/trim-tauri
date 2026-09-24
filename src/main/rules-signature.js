// rules-signature.js - 清理规则库验签（审查 1-1）
// 规则内容直接决定 PowerShell 删除目标（pathPs / fileKeys / regKeys），在线更新链路的
// 任何 HTTP 源（含第三方代理 gh-proxy）都只视为不可信传输通道，内容必须凭内置公钥自证。
// 私钥仅保存在发布机（scripts/sign-rules.js gen 生成，默认 ~/.trim-signing/），绝不入仓库。
'use strict';
const crypto = require('crypto');

// 内置公钥（由 scripts/sign-rules.js gen 生成并自动回填；更换密钥对必须同步发新版应用）
const RULES_PUBKEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAQehWbhuKKCxcWOje/8AZXYN192Z3Ryi8+cQ6ENwXAtY=
-----END PUBLIC KEY-----`;

// 签名对象 = 规则 JSON 根对象去掉 _sig 字段后的紧凑序列化文本（UTF-8 字节）。
// 签名端与验签端必须共用本函数，保证序列化结果一致（键序随 parse 插入序，规则文件无数字键）。
function canonicalBodyText(parsed) {
  const body = { ...parsed };
  delete body._sig;
  return JSON.stringify(body);
}

// 验签：text 为完整规则文件文本。通过返回 { ok: true }，否则 { ok: false, reason }
function verifyRulesSignature(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return { ok: false, reason: 'JSON 解析失败' };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, reason: '规则文件根不是 JSON 对象' };
  }
  const sig = parsed._sig;
  if (!sig || typeof sig !== 'object' || typeof sig.sig !== 'string' || !sig.sig) {
    return { ok: false, reason: '缺少签名块 _sig，已拒绝（发布方需先经 scripts/sign-rules.js 签名）' };
  }
  if (sig.alg && sig.alg !== 'ed25519') {
    return { ok: false, reason: `不支持的签名算法: ${sig.alg}` };
  }
  let body, signature;
  try {
    body = Buffer.from(canonicalBodyText(parsed), 'utf8');
    signature = Buffer.from(sig.sig, 'base64');
  } catch (e) {
    return { ok: false, reason: '签名数据解码失败' };
  }
  let ok = false;
  try {
    ok = crypto.verify(null, body, RULES_PUBKEY_PEM, signature);
  } catch (e) {
    return { ok: false, reason: '签名校验异常: ' + e.message };
  }
  return ok ? { ok: true } : { ok: false, reason: '签名校验失败，内容可能被篡改，已拒绝' };
}

module.exports = { verifyRulesSignature, canonicalBodyText, RULES_PUBKEY_PEM };

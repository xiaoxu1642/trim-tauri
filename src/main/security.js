'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SECRET_PREFIX = 'dpapi:v1:';

// 审查 L-5（2026-09-14）：临时文件名加入 4 字节随机后缀，避免同一进程同一毫秒
// 对同一文件并发写时撞名（旧实现 pid+Date.now() 在极端并发下会重名导致 rename 覆盖）。
function atomicWriteFile(filePath, contents, encoding = 'utf8') {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const rand = crypto.randomBytes(4).toString('hex');
  const tempPath = path.join(dir, `.${path.basename(filePath)}.${process.pid}.${Date.now()}.${rand}.tmp`);
  let fd;
  try {
    fd = fs.openSync(tempPath, 'w');
    fs.writeFileSync(fd, contents, { encoding });
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tempPath, filePath);
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch (_) {}
    }
    try { if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath); } catch (_) {}
  }
}

function atomicWriteJson(filePath, value) {
  atomicWriteFile(filePath, JSON.stringify(value, null, 2), 'utf8');
}

function encryptSecret(value, safeStorage) {
  const plain = String(value || '');
  if (!plain) return '';
  if (!safeStorage || !safeStorage.isEncryptionAvailable()) {
    throw new Error('当前系统暂不可用安全密钥存储，拒绝明文保存 API 密钥');
  }
  return SECRET_PREFIX + safeStorage.encryptString(plain).toString('base64');
}

function decryptSecret(value, safeStorage) {
  const raw = String(value || '');
  if (!raw.startsWith(SECRET_PREFIX)) return raw;
  if (!safeStorage || !safeStorage.isEncryptionAvailable()) return '';
  try {
    return safeStorage.decryptString(Buffer.from(raw.slice(SECRET_PREFIX.length), 'base64'));
  } catch (_) {
    return '';
  }
}

const SECRET_FIELDS = new Set(['apiKey', 'aiApiKey', 'baiduApiKey', 'metasoApiKey', 'zhihuApiKey', 'zhihuAccessSecret']);

function transformSecrets(value, transform) {
  if (!value || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(item => transformSecrets(item, transform));
  const out = {};
  for (const [key, item] of Object.entries(value)) {
    out[key] = SECRET_FIELDS.has(key) && typeof item === 'string'
      ? transform(item)
      : transformSecrets(item, transform);
  }
  return out;
}

function encryptSettings(settings, safeStorage) {
  return transformSecrets(settings, value => encryptSecret(value, safeStorage));
}

function decryptSettings(settings, safeStorage) {
  return transformSecrets(settings, value => decryptSecret(value, safeStorage));
}

// 火眼眼审查 2026-09-14（LOW）：统一脱敏出口——发往渲染层前把全部已配置密钥字段
// 替换为掩码（与 main.js API_KEY_MASK 同值），IPC 返回密钥相关数据时强制过一遍，
// 防个别处理点遗忘手工掩码泄露明文。空值保持空串（表示「未配置」，不伪装成已配置）；
// 幂等：已是掩码的值重复调用结果不变。
const SECRET_MASK = '••••••••';
function maskSettings(settings) {
  return transformSecrets(settings, value => (value ? SECRET_MASK : value));
}

module.exports = {
  SECRET_PREFIX,
  SECRET_MASK,
  atomicWriteFile,
  atomicWriteJson,
  encryptSecret,
  decryptSecret,
  encryptSettings,
  decryptSettings,
  maskSettings
};

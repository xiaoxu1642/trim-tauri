// src/main/optimization-state.js — 优化项「已应用状态」记账（v2.6.0 P0-1）
// 批次：v2.6.0 优化中心安全增强（借鉴 Pavise SuppressionCore 的 fail-closed 记账不变式）：
//   ① 先记账：执行前写入 pending 记录，写不进去就不改（fail-closed）；
//   ② 执行成功后才把记录转正为 applied；
//   ③ 还原成功才销账：还原失败保留记录，等下次重试。
// 为什么需要它：optimizer-backups.json 只记注册表原值，fsutil 命令 / 服务启停等
// cmd、service 类步骤此前没有任何持久化痕迹；崩溃/重启后无从知道「改过什么」，
// 退役项与半途而废的批量执行会变成永远说不清的历史包袱。
// 数据文件：%APPDATA%\Trim\optimization-state.json（安装版；便携版为程序目录\data，同机制）
// 损坏隔离，与 optimizer-backups 同策略。v2.7.0 起同时承载 detected 段：
//   detected[id] = { optimized: bool, at: ISO } —— 启动全量扫描 + 执行/还原后的及时回写，
//   让「哪些条目已做过优化」跨启动持久留痕（常态化记录），而非只存在渲染层内存里。
const fs = require('fs');
const path = require('path');
const SECURITY = require('./security');

let stateFile = null;
let writeLog = () => {};

function initDataDir(dataDir, logger) {
  stateFile = path.join(dataDir, 'optimization-state.json');
  if (typeof logger === 'function') writeLog = logger;
}

function ready() {
  return !!stateFile;
}

function load() {
  if (!stateFile) return { version: 1, items: {}, detected: {} };
  try {
    const m = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
    if (m && typeof m === 'object' && m.items && typeof m.items === 'object') {
      return {
        version: 1,
        items: m.items,
        detected: (m.detected && typeof m.detected === 'object') ? m.detected : {}
      };
    }
    // 结构不符按损坏处理（与 loadOptBackups 的隔离策略一致）
    throw new Error('结构不符');
  } catch (e) {
    if (fs.existsSync(stateFile)) {
      try {
        const bad = stateFile + '.corrupt-' + Date.now();
        fs.renameSync(stateFile, bad);
        writeLog('warn', `优化状态文件损坏已隔离: ${bad}（${e.message}）`);
      } catch (_) { /* 隔离失败则后续 save 直接覆盖 */ }
    }
    return { version: 1, items: {}, detected: {} };
  }
}

function save(state) {
  if (!stateFile) return false;
  try {
    fs.mkdirSync(path.dirname(stateFile), { recursive: true });
    SECURITY.atomicWriteJson(stateFile, state);
    return true;
  } catch (e) {
    writeLog('error', `写入优化状态失败: ${e.message}`);
    return false;
  }
}

// 读取单条记录（无则 null）
function get(id) {
  return load().items[id] || null;
}

// 执行前记账：写入 pending。返回 false = 写入失败（调用方必须中止执行，fail-closed）。
function recordPending(id, { title = '', kinds = [] } = {}) {
  if (!id) return false;
  const state = load();
  state.items[id] = {
    title: String(title || id),
    appliedAt: new Date().toISOString(),
    kinds: Array.isArray(kinds) ? kinds.filter(k => ['reg', 'cmd', 'service'].includes(k)) : [],
    status: 'pending',        // pending = 已记账但未确认完成（含执行中断/崩溃遗留）
    lastVerify: null,         // pass | partial | unknown（执行后回读验证结果）
    verifiedAt: null
  };
  return save(state);
}

// 执行成功转正：status → applied，并记录回读验证结果
function markApplied(id, verify) {
  if (!id) return false;
  const state = load();
  const rec = state.items[id];
  if (!rec) return false;
  rec.status = 'applied';
  rec.lastVerify = ['pass', 'partial', 'unknown'].includes(verify) ? verify : 'unknown';
  rec.verifiedAt = new Date().toISOString();
  return save(state);
}

// 仅更新回读验证结果（不改状态）
function markVerify(id, verify) {
  if (!id) return false;
  const state = load();
  const rec = state.items[id];
  if (!rec) return false;
  rec.lastVerify = ['pass', 'partial', 'unknown'].includes(verify) ? verify : 'unknown';
  rec.verifiedAt = new Date().toISOString();
  return save(state);
}

// 还原成功后销账。只有调用方确认「还原确实成功」才应调用——失败时保留记录等下次重试。
function remove(id) {
  if (!id) return false;
  const state = load();
  if (!state.items[id]) return true; // 本就不存在，视为已销账
  delete state.items[id];
  return save(state);
}

// 全量清单（供启动扫描 / 状态总览 IPC）
function all() {
  return load().items;
}

// ==================== detected：已优化检测结果持久化（v2.7.0） ====================
// 读取全部检测结果：{ [id]: { optimized, at } }
function getDetectedAll() {
  return load().detected;
}

// 全量替换检测结果（启动扫描完成后调用；只合并写入，不覆盖本函数未涉及的条目以外的段）
function replaceDetected(map) {
  if (!stateFile) return false;
  const state = load();
  state.detected = (map && typeof map === 'object') ? map : {};
  return save(state);
}

// 及时回写单条（执行 pass/partial、还原成功后立即调用，不等下次启动扫描）
function setDetectedEntry(id, optimized) {
  if (!id) return false;
  const state = load();
  state.detected[id] = { optimized: optimized === true, at: new Date().toISOString() };
  return save(state);
}

module.exports = { initDataDir, ready, get, recordPending, markApplied, markVerify, remove, all, getDetectedAll, replaceDetected, setDetectedEntry };

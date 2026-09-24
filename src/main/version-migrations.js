// src/main/version-migrations.js — 退役优化项版本迁移（v2.6.0 P0-3）
// 批次：v2.6.0 优化中心安全增强（借鉴 Pavise VersionMigrations.Retired[] 的残留检测驱动迁移）
// 解决的问题：优化项从目录删除后，其 optimizer-backups.json 备份记录会变成永久孤儿，
// 用户系统上残留的改动无从还原。本模块在应用启动时扫描备份文件，对「已不在当前
// 优化项目录里」的 id 按记录的原值还原注册表，成功后删除备份记录（幂等：
// 还原失败的条目保留原记录，下次启动自动重试——还原失败不清账）。
// 元数据来源 src/data/retired-optimizations.json（title/note 仅用于日志与回报，缺省也可还原）。
const fs = require('fs');
const path = require('path');

// 读取退役清单；缺失或损坏时返回空数组（迁移逻辑不依赖清单也能按「不在目录即还原」工作）。
// dataDir 形参当前未使用（为未来数据目录级清单预留），保留以稳定导出签名（火眼眼审查 LOW：
// 原「空 if 死块」已移除，仅留本注释说明）。
function loadRetiredList(dataDir) {
  void dataDir;
  const file = path.join(__dirname, '..', 'data', 'retired-optimizations.json');
  try {
    const m = JSON.parse(fs.readFileSync(file, 'utf8'));
    const items = Array.isArray(m.items) ? m.items : [];
    return items.filter(it => it && typeof it.id === 'string');
  } catch (e) {
    return [];
  }
}

// 执行迁移。依赖注入说明（避免本模块反向依赖 main.js 巨型文件）：
//   knownIds      : Set<string>，当前优化项目录里的全部 id
//   loadBackups() : 读取 optimizer-backups.json → { [id]: { at, values } }
//   saveBackups() : 原子写回备份文件
//   restoreEntry(id, entry) : 按备份原值还原（与 optimizer:restore-reg 同一套 reg.exe 写回逻辑）
//   removeState(id)         : 清除该 id 的已应用状态记账（若有）
// 返回 { restored: [{id,title}], failed: [{id,title,reason}] }
async function runRetiredMigrations({ knownIds, loadBackups, saveBackups, restoreEntry, removeState, writeLog }) {
  const log = typeof writeLog === 'function' ? writeLog : () => {};
  const known = knownIds instanceof Set ? knownIds : new Set(knownIds || []);
  const retiredMeta = new Map(loadRetiredList().map(it => [it.id, it]));
  let backups;
  try {
    backups = loadBackups();
  } catch (e) {
    log('warn', `退役迁移读取备份失败，本轮跳过: ${e.message}`);
    return { restored: [], failed: [] };
  }
  const targets = Object.keys(backups || {}).filter(id => id && !known.has(id));
  if (!targets.length) return { restored: [], failed: [] };

  const restored = [];
  const failed = [];
  for (const id of targets) {
    const meta = retiredMeta.get(id) || {};
    const title = meta.title || id;
    try {
      const r = await restoreEntry(id, backups[id]);
      if (r && r.ok) {
        delete backups[id];
        if (typeof removeState === 'function') { try { removeState(id); } catch (_) {} }
        restored.push({ id, title });
        log('info', `退役优化项已按备份自动还原: ${title}（${meta.note || '目录中已移除'}）`);
      } else {
        failed.push({ id, title, reason: (r && r.reason) || '还原失败' });
        log('warn', `退役优化项还原失败（保留记录待下次重试）: ${title}: ${(r && r.reason) || ''}`);
      }
    } catch (e) {
      failed.push({ id, title, reason: e.message });
      log('warn', `退役优化项还原异常（保留记录待下次重试）: ${title}: ${e.message}`);
    }
  }
  if (restored.length) {
    try { saveBackups(backups); } catch (e) { log('error', `退役迁移写回备份文件失败: ${e.message}`); }
  }
  return { restored, failed };
}

module.exports = { loadRetiredList, runRetiredMigrations };

// tauri-api.js - Tauri 适配层（零依赖、零模块加载器）
// defer 链首位加载（theme-boot.js 是更早的同步无 IPC 主题脚本；旧注释称「脚本链最前面」与实际不符，F2-L09 订正）。
// 职责：复刻 preload.js 暴露的 window.api 形状，把 Electron IPC 转成 Tauri 命令，渲染层调用点零改动。
// 双轨约定：检测到 window.__TAURI_INTERNALS__ 才接管；Electron 下直接 return。
// 协议按 @tauri-apps/api 2.x 实测：invoke(cmd, args)；回调 transformCallback(cb, once) -> id 与 unregisterCallback(id)；
// listen/unlisten/emit 走 plugin:event|*，窗口走 plugin:window|<snake>（start_resize_dragging 载荷为 'NorthEast' 等 8 向字符串）。
// 未迁 Rust 通道的 invoke 会 reject（与 Electron 缺 handler 同型），渲染层有 catch 兜底。
(function () {
  'use strict';

  var internals = window.__TAURI_INTERNALS__;
  if (!internals) return;

  document.documentElement.classList.add('tauri-runtime');
  if (document.body) document.body.classList.add('tauri-runtime');
  else document.addEventListener('DOMContentLoaded', function () {
    document.body.classList.add('tauri-runtime');
  }, { once: true });

  // 内核调用

  function currentLabel() {
    return internals.metadata && internals.metadata.currentWindow && internals.metadata.currentWindow.label;
  }

  // CHANNEL_MAP：Electron 通道（preload.js 快照为契约锚点）→ Rust snake_case 命令。
  // 键集合必须与 preload 的 invoke 通道集合对拍；条数以 node tools/check-channel-map.mjs 现算为准
  // （F2-L06：不写死统计数字，防过期误导）。生成规则：':' 与 '-' 统一转 '_'，显式列出、不做运行时
  // 隐式推导，防「Rust 有了、前端没接 / 拼错」静默断裂。
  var CHANNEL_MAP = {
    // app 域（onMemoryTrim 是事件，不在此表）
    'app:get-info': 'app_get_info',
    'app:read-usage': 'app_read_usage',
    'app:open-external': 'app_open_external',
    // updater 域（onState 是事件）
    'updater:check': 'updater_check',
    'updater:completion': 'updater_completion',
    'updater:download': 'updater_download',
    'updater:cancel-download': 'updater_cancel_download',
    'updater:install': 'updater_install',
    // updater:set-mirror / updater:get-mirror 2026-10-06 随更新线路 UI 整链退役
    // （顺序固化国内源优先，无需用户选择）。
    // device / overview
    // overview:checkup 2026-10-12 随首页「体检结论」区块全链路退役
    'device:scan': 'device_scan',
    'overview:metrics': 'overview_metrics',
    'overview:hardware': 'overview_hardware',
    // log
    'log:write': 'log_write',
    'log:read': 'log_read',
    'log:export': 'log_export',
    // cleanup
    'cleanup:rules': 'cleanup_rules',
    'cleanup:allow-preview-assets': 'cleanup_allow_preview_assets',
    'cleanup:reg-backup-list': 'cleanup_reg_backup_list',
    'cleanup:reg-backup-restore': 'cleanup_reg_backup_restore',
    'cleanup:file-backup-list': 'cleanup_file_backup_list',
    'cleanup:file-backup-restore': 'cleanup_file_backup_restore',
    'cleanup:scan': 'cleanup_scan',
    'cleanup:execute': 'cleanup_execute',
    'cleanup:check-locked': 'cleanup_check_locked',
    'cleanup:kill-locked-processes': 'cleanup_kill_locked_processes',
    'cleanup:query-locked': 'cleanup_query_locked',
    'cleanup:item-detail': 'cleanup_item_detail',
    'cleanup:age-policy': 'cleanup_age_policy',
    'cleanup:set-age-policy': 'cleanup_set_age_policy',
    // G-4：回收站清空改 Shell API（选项 B）——查询条目数与体积 / 清空（不可逆）
    'cleanup:recycle-stats': 'cleanup_recycle_stats',
    'cleanup:empty-recycle-bin': 'cleanup_empty_recycle_bin',
    'cleanup:open-recycle-bin': 'cleanup_open_recycle_bin',
    // runtimes
    'runtimes:collect': 'runtimes_collect',
    'runtimes:install': 'runtimes_install',
    // finder
    'finder:scan': 'finder_scan',
    'finder:delete': 'finder_delete',
    'finder:delete-manifest': 'finder_delete_manifest',
    'finder:open-backup-dir': 'finder_open_backup_dir',
    'finder:ignore-folder': 'finder_ignore_folder',
    'finder:ignore-list': 'finder_ignore_list',
    'finder:ignore-remove': 'finder_ignore_remove',
    // uninstall：卸载域（report/appx-logo 为只读档，其余 MAIN）
    'uninstall:list': 'uninstall_list',
    'uninstall:run': 'uninstall_run',
    'uninstall:modify': 'uninstall_modify',
    'uninstall:pending-add': 'uninstall_pending_add',
    'uninstall:pending-list': 'uninstall_pending_list',
    'uninstall:pending-revoke': 'uninstall_pending_revoke',
    'uninstall:residue-scan': 'uninstall_residue_scan',
    'uninstall:residue-execute': 'uninstall_residue_execute',
    'uninstall:dir-size': 'uninstall_dir_size',
    'uninstall:reg-backup-list': 'uninstall_reg_backup_list',
    'uninstall:reg-backup-restore': 'uninstall_reg_backup_restore',
    'uninstall:batch-list': 'uninstall_batch_list',
    'uninstall:batch-restore': 'uninstall_batch_restore',
    'uninstall:report-list': 'uninstall_report_list',
    'uninstall:report-get': 'uninstall_report_get',
    'uninstall:appx-logo': 'uninstall_appx_logo',
    // contextmenu（8→5）：backup/remove/restore 2026-10-09 随「删除链整链退役」用户裁定（D3）
    // 同撤（命令 + 原生实现 + 桥接 + 前端入口一并摘除；本页只保留启停能力）。
    'contextmenu:scan': 'contextmenu_scan',
    'contextmenu:toggle': 'contextmenu_toggle',
    'contextmenu:icons': 'contextmenu_icons',
    'contextmenu:open-in-regedit': 'contextmenu_open_in_regedit',
    'contextmenu:restart-explorer': 'contextmenu_restart_explorer',
    // modal（2）/ diag / settings / intro
    'modal:open': 'modal_open',
    'modal:close': 'modal_close',
    'diag:dwm-conflict': 'diag_dwm_conflict',
    'settings:load': 'settings_load',
    // v4 P2-13：UI 偏好键的后端真源（防恢复三键 / 残留备份开关 / 液态动效 / 鼠标拖尾）
    'settings:get-prefs': 'settings_get_prefs',
    'settings:set-pref': 'settings_set_pref',
    'intro:load': 'intro_load',
    // models 窗口 + models 配置（合计 5）
    'models:open-window': 'models_open_window',
    'models:close-window': 'models_close_window',
    'models:save': 'models_save',
    'models:set-scope': 'models_set_scope',
    'models:test': 'models_test',
    // fonts（4）
    'fonts:list': 'fonts_list',
    'fonts:import': 'fonts_import',
    'fonts:remove-imported': 'fonts_remove_imported',
    'fonts:save-config': 'fonts_save_config',
    // appearance（8）
    'appearance:get-material': 'appearance_get_material',
    'appearance:set-material': 'appearance_set_material',
    'appearance:set-material-enabled': 'appearance_set_material_enabled',
    'appearance:get-env': 'appearance_get_env',
    'appearance:bg-import': 'appearance_bg_import',
    'appearance:bg-delete': 'appearance_bg_delete',
    'appearance:bg-list': 'appearance_bg_list',
    'appearance:bg-open-dir': 'appearance_bg_open_dir',
    // aidesc / diskbench
    'aidesc:get': 'aidesc_get',
    'diskbench:run': 'diskbench_run',
    // realtime
    'realtime:adapters': 'realtime_adapters',
    'realtime:sample': 'realtime_sample',
    'realtime:loss': 'realtime_loss',
    'realtime:report-save': 'realtime_report_save',
    'realtime:report-list': 'realtime_report_list',
    'realtime:report-get': 'realtime_report_get',
    'realtime:report-delete': 'realtime_report_delete',
    'realtime:report-clear': 'realtime_report_clear',
    // bench-history（4）/ elevate（1）
    'bench-history:add': 'bench_history_add',
    'bench-history:list': 'bench_history_list',
    'bench-history:delete': 'bench_history_delete',
    'bench-history:clear': 'bench_history_clear',
    'elevate:request': 'elevate_request',
    // paths（6）
    'paths:scan': 'paths_scan',
    'paths:load': 'paths_load',
    'paths:save': 'paths_save',
    'paths:browse': 'paths_browse',
    'paths:app-icon': 'paths_app_icon',
    'paths:file-icon': 'paths_file_icon',
    // fileclean（4）
    'fileclean:scan': 'fileclean_scan',
    'fileclean:execute': 'fileclean_execute',
    'fileclean:delete-file': 'fileclean_delete_file',
    // maintenance（2）/ netcheck（2）
    'maintenance:tasks': 'maintenance_tasks',
    'maintenance:run': 'maintenance_run',
    'netcheck:collect': 'netcheck_collect',
    'netcheck:repair': 'netcheck_repair',
    // memory（6）/ processManager 窗口（2）/ peripheral（3）
    'memory:info': 'memory_info',
    'memory:clean': 'memory_clean',
    'memory:stubborn-kill': 'memory_stubborn_kill',
    'memory:stubborn-block': 'memory_stubborn_block',
    'memory:processes': 'memory_processes',
    'memory:kill': 'memory_kill',
    'processManager:open-window': 'process_manager_open_window',
    'processManager:close-window': 'process_manager_close_window',
    // residue 窗口（2）—— v0.5.0 残留扫描副窗（用户裁决 4：扫描全在副窗，主窗只留入口）
    'residue:open-window': 'residue_open_window',
    'residue:close-window': 'residue_close_window',
    'peripheral:query': 'peripheral_query',
    'peripheral:apply': 'peripheral_apply',
    'peripheral:restore-backup': 'peripheral_restore_backup',
    // quickcmds / optimizer
    'quickcmds:run': 'quickcmds_run',
    'optimizer:run': 'optimizer_run',
    'optimizer:list': 'optimizer_list',
    'optimizer:genadvice': 'optimizer_genadvice',
    'optimizer:check-restore': 'optimizer_check_restore',
    'optimizer:create-restore': 'optimizer_create_restore',
    'optimizer:list-restore': 'optimizer_list_restore',
    'optimizer:restore-frequency': 'optimizer_restore_frequency',
    'optimizer:check-optimized': 'optimizer_check_optimized',
    'optimizer:batch-preflight': 'optimizer_batch_preflight',
    'optimizer:svc-mem-current': 'optimizer_svc_mem_current',
    'optimizer:backup-reg': 'optimizer_backup_reg',
    'optimizer:restore-reg': 'optimizer_restore_reg',
    'optimizer:state-overview': 'optimizer_state_overview',
    'optimizer:stale-dismiss': 'optimizer_stale_dismiss',
    'optimizer:list-groups': 'optimizer_list_groups',
    'optimizer:touch-recent': 'optimizer_touch_recent',
    'optimizer:bcd-enum': 'optimizer_bcd_enum',
    'optimizer:nara-panel': 'optimizer_nara_panel',
    'optimizer:privacy-panel': 'optimizer_privacy_panel',
    'optimizer:external-scan': 'optimizer_external_scan',
    // system / startup（5）
    'system:disk-type': 'system_disk_type',
    'system:disk-list': 'system_disk_list',
    'startup:scan': 'startup_scan',
    'startup:toggle': 'startup_toggle',
    'startup:delete': 'startup_delete',
    'startup:openlocation': 'startup_openlocation',
    'startup:open-source': 'startup_open_source',
    'startup:add': 'startup_add',
    // syspanel（P2 §3.6：电源计划 + 虚拟内存面板，只在主窗 Windows设置 页调用）
    'syspanel:power-plan-get': 'syspanel_power_plan_get',
    'syspanel:power-plan-apply': 'syspanel_power_plan_apply',
    'syspanel:power-settings-dump': 'syspanel_power_settings_dump',
    'syspanel:power-plan-duplicate': 'syspanel_power_plan_duplicate',
    'syspanel:power-plan-rename': 'syspanel_power_plan_rename',
    'syspanel:power-plan-delete': 'syspanel_power_plan_delete',
    'syspanel:power-plan-import': 'syspanel_power_plan_import',
    'syspanel:power-plan-export': 'syspanel_power_plan_export',
    'syspanel:power-settings-unlock': 'syspanel_power_settings_unlock',
    'syspanel:power-settings-apply': 'syspanel_power_settings_apply',
    'syspanel:power-settings-revert': 'syspanel_power_settings_revert',
    'syspanel:power-settings-compare': 'syspanel_power_settings_compare',
    'syspanel:power-settings-open-regedit': 'syspanel_power_settings_open_regedit',
    'syspanel:power-ultimate-enable': 'syspanel_power_ultimate_enable',
    'syspanel:power-hide-high-performance': 'syspanel_power_hide_high_performance',
    'syspanel:power-restore-high-performance': 'syspanel_power_restore_high_performance',
    'syspanel:pagefile-state': 'syspanel_pagefile_state',
    'syspanel:pagefile-apply': 'syspanel_pagefile_apply'
  };

  // F2-L03：契约层自身的失败也要进用户侧日志（console 用户看不见）；判 window.api 存在再写，写失败静默——绝不因记日志再抛错。
  function bridgeLog(level, text) {
    try {
      if (window.api && window.api.log) window.api.log.write(level, text).catch(function () {});
    } catch (e) { /* 上报失败不再抛 */ }
  }

  function invokeChannel(channel, args) {
    // F2-L02：hasOwnProperty 判登记——原型链属性（__proto__/constructor）不算合法通道
    if (!Object.prototype.hasOwnProperty.call(CHANNEL_MAP, channel)) {
      bridgeLog('warn', 'tauri-api：未登记通道 ' + channel);
      return Promise.reject(new Error('tauri-api：未登记通道 ' + channel));
    }
    return invokeCore(CHANNEL_MAP[channel], args || {});
  }

  function invokeCore(cmd, args) {
    return internals.invoke(cmd, args || {}, undefined);
  }

  function pluginInvoke(pluginCmd, extra) {
    var args = Object.assign({ label: currentLabel() }, extra || {});
    return invokeCore('plugin:window|' + pluginCmd, args);
  }

  /**
   * SEND_MAP：fire-and-forget send 通道的显式映射（与 invoke 集合互斥；条数以 check-channel-map 现算为准）。
   * window:minimize/maximize/close 走窗口插件、app:first-paint 走直连命令，均不经过 sendChannel。
   * 禁止运行时隐式 replace——驼峰域（processManager）隐式转换会拼错 Rust snake_case 命令（Phase 0 发现）。
   */
  var SEND_MAP = {
    'processManager:report': 'process_manager_report'
  };

  function sendChannel(channel, args) {
    var cmd = SEND_MAP[channel];
    if (!cmd) {
      console.warn('[tauri-api] 未登记的 send 通道: ' + channel);
      bridgeLog('warn', 'tauri-api：未登记的 send 通道 ' + channel);
      return Promise.resolve(false);
    }
    // send 语义是「不等回执」但不等于出错也瞒着（审查 L13）：返回布尔 promise 供要回执的调用方 await（v2-F17）。
    return invokeCore(cmd, args || {})
      .then(function () { return true; })
      .catch(function (e) {
        console.error('[tauri-api] send 通道失败 ' + channel + ': ' + ((e && e.message) || e));
        bridgeLog('error', 'tauri-api：send 通道失败 ' + channel + ': ' + ((e && e.message) || e));
        return false;
      });
  }

  // 事件：onXxx 必须同步返回 unsubscribe（Electron removeListener 同形状）

  // 订阅后端事件：handler 收到剥掉 Tauri event 信封的 payload（对齐 preload 的 (_, data) => cb(data)），
  // 返回同步可用的退订函数。
  function onEvent(event, handler) {
    var active = true;
    var offPromise = new Promise(function (resolve) {
      var callbackId = internals.transformCallback(function (rawEvent) {
        try { handler(rawEvent && rawEvent.payload !== undefined ? rawEvent.payload : rawEvent); }
        catch (e) { console.error('[tauri-api] 事件处理器异常 ' + event, e); }
      });
      invokeCore('plugin:event|listen', {
        event: event,
        target: { kind: 'Any' },
        handler: callbackId
      }).then(function (eventId) {
        resolve(function () {
          // 2.11 的事件插件注入了本地注销表；存在则先注销（与官方 api 同序）
          try {
            if (window.__TAURI_EVENT_PLUGIN_INTERNALS__ &&
                typeof window.__TAURI_EVENT_PLUGIN_INTERNALS__.unregisterListener === 'function') {
              window.__TAURI_EVENT_PLUGIN_INTERNALS__.unregisterListener(event, eventId);
            }
          } catch (e) { bridgeLog('warn', 'tauri-api：事件本地退订异常 ' + event); }
          return invokeCore('plugin:event|unlisten', { event: event, eventId: eventId });
        });
      }).catch(function (e) {
        console.error('[tauri-api] 事件订阅失败 ' + event, e);
        // F2-L08：listen 失败时 transformCallback 已注册的 id 不会自动回收（once=false 只由 unregisterCallback 删除），不显式注销就每次泄漏一个闭包。
        if (typeof internals.unregisterCallback === 'function') internals.unregisterCallback(callbackId);
        bridgeLog('error', 'tauri-api：事件订阅失败 ' + event + ': ' + ((e && e.message) || e));
        resolve(function () {});
      });
    });
    return function unsubscribe() {
      if (!active) return;
      active = false;
      offPromise.then(function (off) {
        off().catch(function () { bridgeLog('warn', 'tauri-api：事件退订失败 ' + event); });
      });
    };
  }

  // window.api：逐方法复刻 preload.js（含参数整形，一个都不能走样）

  var api = {
    /**
     * 绝对路径 → 页面可加载 URL。页源是 http://tauri.localhost，Chromium 拦掉跨源的 file: 子资源
     * （CSP 里留着 `file:` 也放行不了 —— 表现为「路径正确但图/字体就是不出来」），必须走 asset 协议
     * （conf 的 assetProtocol.scope 只放行了 backgrounds 与 fonts）。URL 形态按平台不同，不在前端复刻
     * 规则，直接用注入脚本提供的 convertFileSrc；取不到时退回 file:///，保证非 Tauri 环境不白屏。
     */
    pathToUrl: function (filePath) {
      if (!filePath) return '';
      try {
        if (internals && typeof internals.convertFileSrc === 'function') {
          return internals.convertFileSrc(String(filePath));
        }
      } catch (e) { /* 落兜底 */ }
      return 'file:///' + String(filePath).replace(/\\/g, '/').replace(/^\//, '');
    },

    app: {
      getInfo: function () { return invokeChannel('app:get-info'); },
      readUsage: function () { return invokeChannel('app:read-usage'); },
      // 裸标量载荷（preload 直传 url 而非对象）：Tauri 命令必须收到具名参数，此处整形为 { url }
      openExternal: function (url) { return invokeChannel('app:open-external', { url: url }); },
      onMemoryTrim: function (callback) { return onEvent('memory:trim', function () { callback(); }); }
    },

    updater: {
      check: function () { return invokeChannel('updater:check'); },
      completion: function () { return invokeChannel('updater:completion'); },
      download: function () { return invokeChannel('updater:download'); },
      cancelDownload: function () { return invokeChannel('updater:cancel-download'); },
      install: function () { return invokeChannel('updater:install'); },
      onState: function (callback) { return onEvent('updater:state-changed', callback); }
    },

    device: {
      scan: function () { return invokeChannel('device:scan'); }
    },

    overview: {
      metrics: function () { return invokeChannel('overview:metrics'); },
      hardware: function (options) {
        if (options === void 0) options = {};
        return invokeChannel('overview:hardware', options);
      }
    },

    window: {
      // A 批备注：close 在 Phase 2 前是硬关窗（无静默收尾）；迁移后走 shutdown 流程
      minimize: function () { return pluginInvoke('minimize'); },
      maximize: function () { return pluginInvoke('toggle_maximize'); },
      close: function () { return pluginInvoke('close'); },
      onFocusState: function (callback) { return bridgeFocusState(callback); },
      onResized: function (callback) { return bridgeResized(callback); },
      // 黑闪握手：与 preload 同逻辑（双 rAF + 200ms 竞速），适配层加载即自动执行一次
      notifyFirstPaint: notifyFirstPaint
    },

    log: {
      write: function (level, message) { return invokeChannel('log:write', { level: level, message: message }); },
      read: function (date) { return invokeChannel('log:read', { date: date }); },
      export: function () { return invokeChannel('log:export'); }
    },

    cleanup: {
      rules: function () { return invokeChannel('cleanup:rules'); },
      // 图片预览前按需放行 asset 协议（只放本次点开的那组图，暴露面不常开）
      allowPreviewAssets: function (paths) { return invokeChannel('cleanup:allow-preview-assets', { paths: paths }); },
      regBackupList: function () { return invokeChannel('cleanup:reg-backup-list'); },
      regBackupRestore: function (file) { return invokeChannel('cleanup:reg-backup-restore', { file: file }); },
      fileBackupList: function () { return invokeChannel('cleanup:file-backup-list'); },
      fileBackupRestore: function (file, index) { return invokeChannel('cleanup:file-backup-restore', { file: file, index: index }); },
      // partial：扫描范围是勾选项的子集（后端保快照桶并合并；全量扫描传 false）
      scan: function (categories, partial) { return invokeChannel('cleanup:scan', { categories: categories, partial: partial === true }); },
      execute: function (items, force, toRecycle, autoRebuild) {
        return invokeChannel('cleanup:execute', {
          items: items,
          force: force === true,
          toRecycle: toRecycle === true,
          autoRebuild: autoRebuild === true
        });
      },
      checkLocked: function (ids) { return invokeChannel('cleanup:check-locked', { ids: ids }); },
      killLockedProcesses: function () { return invokeChannel('cleanup:kill-locked-processes'); },
      // C1-1（2026-10-16）：占用查询——用户任意路径 ⇒ 谁占着它（主窗内嵌卡片；
      // 只读，与 check-locked 走同一条 RM 管线；结束进程仍走 killLockedProcesses）
      queryLocked: function (path) { return invokeChannel('cleanup:query-locked', { path: path }); },
      itemDetail: function (id, path) {
        if (path === void 0) path = '';
        return invokeChannel('cleanup:item-detail', { id: id, path: path });
      },
      // G-2 全局年龄策略：只收紧不放宽（档位由后端闸死，前端只是三选一）
      agePolicy: function () { return invokeChannel('cleanup:age-policy'); },
      setAgePolicy: function (days) { return invokeChannel('cleanup:set-age-policy', { days: days }); },
      // G-4：回收站条目数与体积（权威来源，扫描占位行刻意写 0）
      recycleStats: function () { return invokeChannel('cleanup:recycle-stats'); },
      // G-4：清空回收站（不可逆；渲染层必须先走 confirmDanger 再调）
      emptyRecycleBin: function () { return invokeChannel('cleanup:empty-recycle-bin'); },
      // G-4 修订（2026-10-07）：回收站行「明细」= 打开系统回收站（幂等，无危险确认）
      openRecycleBin: function () { return invokeChannel('cleanup:open-recycle-bin'); },
      onScanProgress: function (callback) { return onEvent('cleanup:scan-progress', callback); },
      // 2026-10-12：执行逐项进度（每项开工推一次：第 k/N 项 + 名称）
      onExecuteProgress: function (callback) { return onEvent('cleanup:execute-progress', callback); }
    },

    runtimes: {
      collect: function () { return invokeChannel('runtimes:collect'); },
      install: function (actionId) { return invokeChannel('runtimes:install', { actionId: actionId }); },
      onProgress: function (callback) { return onEvent('runtimes:install-progress', callback); }
    },

    // R1（2026-10-01）：`pwsh` 命名空间随 pwsh:status 通道整链摘除——右键图标改原生取图后本应用不再有 PS7 使用者，探测失去对象。

    finder: {
      scan: function (scanType, opts) {
        if (opts === void 0) opts = {};
        return invokeChannel('finder:scan', Object.assign({ scanType: scanType }, opts));
      },
      delete: function (items) {
        return invokeChannel('finder:delete', { items: items });
      },
      onProgress: function (callback) { return onEvent('finder:progress', callback); },
      deleteManifest: function () { return invokeChannel('finder:delete-manifest'); },
      openBackupDir: function () { return invokeChannel('finder:open-backup-dir'); },
      ignoreFolder: function (path) { return invokeChannel('finder:ignore-folder', { path: path }); },
      ignoreList: function () { return invokeChannel('finder:ignore-list'); },
      ignoreRemove: function (path) { return invokeChannel('finder:ignore-remove', { path: path }); }
    },

    uninstall: {
      list: function (scope) { return invokeChannel('uninstall:list', { scope: scope }); },
      run: function (appId) { return invokeChannel('uninstall:run', { appId: appId }); },
      modify: function (appId, mode) { return invokeChannel('uninstall:modify', { appId: appId, mode: mode }); },
      pendingAdd: function (targets) { return invokeChannel('uninstall:pending-add', { targets: targets }); },
      pendingList: function () { return invokeChannel('uninstall:pending-list'); },
      pendingRevoke: function (batchId) { return invokeChannel('uninstall:pending-revoke', { batchId: batchId }); },
      residueScan: function (appId) { return invokeChannel('uninstall:residue-scan', { appId: appId }); },
      residueExecute: function (appId, targets, backup) { return invokeChannel('uninstall:residue-execute', { appId: appId, targets: targets, backup: !!backup }); },
      dirSize: function (path) { return invokeChannel('uninstall:dir-size', { path: path }); },
      regBackupList: function () { return invokeChannel('uninstall:reg-backup-list'); },
      regBackupRestore: function (file) { return invokeChannel('uninstall:reg-backup-restore', { file: file }); },
      batchList: function () { return invokeChannel('uninstall:batch-list'); },
      batchRestore: function (batchId) { return invokeChannel('uninstall:batch-restore', { batchId: batchId }); },
      reportList: function () { return invokeChannel('uninstall:report-list'); },
      reportGet: function (batchId) { return invokeChannel('uninstall:report-get', { batchId: batchId }); },
      appxLogo: function (logoPath) { return invokeChannel('uninstall:appx-logo', { logoPath: logoPath }); }
    },

    contextmenu: {
      scan: function (refresh) {
        if (refresh === void 0) refresh = false;
        return invokeChannel('contextmenu:scan', { refresh: refresh });
      },
      toggle: function (items) { return invokeChannel('contextmenu:toggle', { items: items }); },
      icons: function (items) { return invokeChannel('contextmenu:icons', { items: items }); },
      openInRegedit: function (regPath) { return invokeChannel('contextmenu:open-in-regedit', { regPath: regPath }); },
      restartExplorer: function () { return invokeChannel('contextmenu:restart-explorer'); },
    },

    modal: {
      open: function (info) { return invokeChannel('modal:open', Object.assign({}, info)); },
      close: function (info) { return invokeChannel('modal:close', Object.assign({}, info)); }
    },

    diag: {
      dwmConflict: function () { return invokeChannel('diag:dwm-conflict'); }
    },

    // 审查 v2-F4：`settings:save` 整链摘除（零调用方的死写入通道，AI 配置写入归 models 域）；将来开配置页走 models:save，别复活这条。
    settings: {
      load: function () { return invokeChannel('settings:load'); },
      // v4 P2-13：偏好键读写（get 返回 {success, data:{键:值|null}}；set 进白名单键）
      getPrefs: function () { return invokeChannel('settings:get-prefs'); },
      setPref: function (key, value) { return invokeChannel('settings:set-pref', { key: key, value: value }); }
    },

    intro: {
      load: function () { return invokeChannel('intro:load'); }
    },

    modelsWindow: {
      open: function () { return invokeChannel('models:open-window'); },
      close: function () { return invokeChannel('models:close-window'); }
    },

    models: {
      save: function (key, config, scope) { return invokeChannel('models:save', { key: key, config: config, scope: scope }); },
      setScope: function (scope, key) { return invokeChannel('models:set-scope', { scope: scope, key: key }); },
      test: function (key, config) { return invokeChannel('models:test', { key: key, config: config }); }
    },

    fonts: {
      list: function () { return invokeChannel('fonts:list'); },
      importFont: function () { return invokeChannel('fonts:import'); },
      removeImported: function () { return invokeChannel('fonts:remove-imported'); },
      saveConfig: function (config) { return invokeChannel('fonts:save-config', { config: config }); }
    },

    appearance: {
      getMaterial: function () { return invokeChannel('appearance:get-material'); },
      setMaterial: function (material) { return invokeChannel('appearance:set-material', { material: material }); },
      setMaterialEnabled: function (enabled) { return invokeChannel('appearance:set-material-enabled', { enabled: enabled }); },
      onMaterialChanged: function (callback) { return onEvent('appearance:material-changed', callback); },
      getEnv: function () { return invokeChannel('appearance:get-env'); },
      onEnvState: function (callback) { return onEvent('appearance:env-state', callback); },
      importBg: function () { return invokeChannel('appearance:bg-import'); },
      deleteBg: function (file) { return invokeChannel('appearance:bg-delete', { file: file }); },
      listBg: function () { return invokeChannel('appearance:bg-list'); },
      openBgDir: function () { return invokeChannel('appearance:bg-open-dir'); }
    },

    aidesc: {
      // detail 只给 scope='residue' 用：{target,kind,class}，后端按白名单筛后再进 prompt
      get: function (name, company, force, scope, detail) {
        return invokeChannel('aidesc:get', { name: name, company: company, force: force, scope: scope, detail: detail || null });
      }
    },

    diskbench: {
      run: function (options) { return invokeChannel('diskbench:run', { options: options }); },
      onProgress: function (cb) { return onEvent('diskbench:progress', cb); }
    },

    realtime: {
      adapters: function () { return invokeChannel('realtime:adapters'); },
      sample: function () { return invokeChannel('realtime:sample'); },
      loss: function () { return invokeChannel('realtime:loss'); },
      reportSave: function (data) { return invokeChannel('realtime:report-save', { data: data }); },
      reportList: function () { return invokeChannel('realtime:report-list'); },
      reportGet: function (name) { return invokeChannel('realtime:report-get', { name: name }); },
      reportDelete: function (name) { return invokeChannel('realtime:report-delete', { name: name }); },
      reportClear: function () { return invokeChannel('realtime:report-clear'); }
    },

    benchHistory: {
      add: function (record) { return invokeChannel('bench-history:add', { record: record }); },
      list: function () { return invokeChannel('bench-history:list'); },
      delete: function (id) { return invokeChannel('bench-history:delete', { id: id }); },
      clear: function () { return invokeChannel('bench-history:clear'); }
    },

    elevate: {
      request: function (launchToken) { return launchToken == null ? invokeChannel('elevate:request') : invokeChannel('elevate:request', { launchToken: launchToken }); },
      onNotice: function (callback) { return onEvent('elevate:notice', callback); }
    },


    paths: {
      scan: function () { return invokeChannel('paths:scan'); },
      load: function () { return invokeChannel('paths:load'); },
      save: function (key, value) { return invokeChannel('paths:save', { key: key, value: value }); },
      browse: function (title, defaultPath) { return invokeChannel('paths:browse', { title: title, defaultPath: defaultPath }); },
      appIcon: function (installPath, exeCandidates) {
        return invokeChannel('paths:app-icon', { installPath: installPath, exeCandidates: exeCandidates });
      },
      fileIcon: function (filePath) { return invokeChannel('paths:file-icon', { filePath: filePath }); }
    },

    fileclean: {
      scan: function (scanType, customPath) {
        return invokeChannel('fileclean:scan', {
          scanType: scanType, customPath: customPath
        });
      },
      execute: function (files) { return invokeChannel('fileclean:execute', { files: files }); },
      deleteFile: function (filePath) { return invokeChannel('fileclean:delete-file', { filePath: filePath }); }
    },

    maintenance: {
      tasks: function () { return invokeChannel('maintenance:tasks'); },
      run: function (taskId) { return invokeChannel('maintenance:run', { taskId: taskId }); },
      onOutput: function (callback) { return onEvent('maintenance:output', callback); }
    },


    netcheck: {
      collect: function () { return invokeChannel('netcheck:collect'); },
      repair: function (actionId) { return invokeChannel('netcheck:repair', { actionId: actionId }); }
    },

    memory: {
      info: function () { return invokeChannel('memory:info'); },
      clean: function (items) { return invokeChannel('memory:clean', { items: items }); },
      stubbornKill: function () { return invokeChannel('memory:stubborn-kill'); },
      stubbornBlock: function () { return invokeChannel('memory:stubborn-block'); },
      processes: function () { return invokeChannel('memory:processes'); },
      kill: function (pid) { return invokeChannel('memory:kill', { pid: pid }); }
    },

    processManager: {
      openWindow: function () { return invokeChannel('processManager:open-window'); },
      closeWindow: function () { return invokeChannel('processManager:close-window'); },
      report: function (payload) { sendChannel('processManager:report', Object.assign({}, payload)); },
      onUpdate: function (callback) { return onEvent('processManager:update', callback); }
    },

    peripheralWindow: {
      query: function () { return invokeChannel('peripheral:query'); },
      apply: function (options) { return invokeChannel('peripheral:apply', { options: options }); },
      restoreBackup: function (ok) { return invokeChannel('peripheral:restore-backup', { confirmedHighRisk: ok === true }); }
    },

    residueWindow: {
      // v0.7.0：残留面板整块搬进这扇窗，卸载成功后带目标进来。appId 只是「提示后端扫哪个」，真正的取值闸在 Rust 侧
      // （开窗前一次、执行链再一次），这里空串一律不送，免得把 `?app=` 空值当成合法目标。
      openWindow: function (appId) {
        return invokeChannel('residue:open-window', appId ? { appId: appId } : undefined);
      },
      closeWindow: function () { return invokeChannel('residue:close-window'); },
      // 副窗已开着时主窗又点了「查残留」：新目标走事件进来（能力面已授 core:event:allow-listen）
      onTarget: function (callback) { return onEvent('residue:target', function (payload) { callback(payload); }); }
    },

    quickCmds: {
      // 裸标量载荷：preload 直传 id 字符串，Tauri 侧整形为 { id }
      run: function (id) { return invokeChannel('quickcmds:run', { id: id }); }
    },

    optimizer: {
      run: function (optionId, params) { return invokeChannel('optimizer:run', { optionId: optionId, params: params }); },
      list: function () { return invokeChannel('optimizer:list'); },
      genAdvice: function (optionId) { return invokeChannel('optimizer:genadvice', { optionId: optionId }); },
      checkRestore: function () { return invokeChannel('optimizer:check-restore'); },
      createRestore: function () { return invokeChannel('optimizer:create-restore'); },
      listRestore: function () { return invokeChannel('optimizer:list-restore'); },
      restoreFrequency: function () { return invokeChannel('optimizer:restore-frequency'); },
      // ids 缺省（不传）= 后端对整个优化目录做一次静默只读体检（启动时全量检测）；显式传 id 数组 = 只检指定项。两种都不改任何系统状态。
      checkOptimized: function (ids) {
        return arguments.length === 0 || ids == null
          ? invokeChannel('optimizer:check-optimized', {})
          : invokeChannel('optimizer:check-optimized', { ids: ids });
      },
      batchPreflight: function (ids, restore) { return invokeChannel('optimizer:batch-preflight', { ids: ids, restore: !!restore }); },
      svcMemCurrent: function () { return invokeChannel('optimizer:svc-mem-current'); },
      backupReg: function (optionId) { return invokeChannel('optimizer:backup-reg', { optionId: optionId }); },
      restoreReg: function (optionId) { return invokeChannel('optimizer:restore-reg', { optionId: optionId }); },
      stateOverview: function () { return invokeChannel('optimizer:state-overview'); },
      staleDismiss: function (ids) { return invokeChannel('optimizer:stale-dismiss', { ids: ids }); },
      listGroups: function () { return invokeChannel('optimizer:list-groups'); },
      touchRecent: function (optionId) { return invokeChannel('optimizer:touch-recent', { optionId: optionId }); },
      bcdEnum: function () { return invokeChannel('optimizer:bcd-enum'); },
      naraPanel: function () { return invokeChannel('optimizer:nara-panel'); },
      privacyPanel: function () { return invokeChannel('optimizer:privacy-panel'); },
      externalScan: function () { return invokeChannel('optimizer:external-scan'); },
      onProgress: function (callback) { return onEvent('optimizer:progress', callback); }
    },

    system: {
      diskType: function (opts) {
        if (opts === void 0) opts = {};
        return invokeChannel('system:disk-type', opts);
      },
      // 固定磁盘盘符列表（finder 大文件/空文件页盘符点选器，2026-09-28 六轮拍板）
      diskList: function () { return invokeChannel('system:disk-list'); }
    },

    // syspanel（P2 §3.6）：电源计划读写 + 虚拟内存读写；主窗 Windows设置 页专用
    syspanel: {
      powerPlanGet: function () { return invokeChannel('syspanel:power-plan-get'); },
      powerPlanApply: function (guid) { return invokeChannel('syspanel:power-plan-apply', { guid: guid }); },
      powerSettingsDump: function (schemeGuid) { return invokeChannel('syspanel:power-settings-dump', { schemeGuid: schemeGuid }); },
      powerPlanDuplicate: function (sourceGuid, name) { return invokeChannel('syspanel:power-plan-duplicate', { sourceGuid: sourceGuid, name: name }); },
      powerPlanRename: function (guid, name) { return invokeChannel('syspanel:power-plan-rename', { guid: guid, name: name }); },
      powerPlanDelete: function (guid, confirmedHighRisk) { return invokeChannel('syspanel:power-plan-delete', { guid: guid, confirmedHighRisk: !!confirmedHighRisk }); },
      powerPlanImport: function () { return invokeChannel('syspanel:power-plan-import'); },
      powerPlanExport: function (guid) { return invokeChannel('syspanel:power-plan-export', { guid: guid }); },
      powerSettingsUnlock: function (schemeGuid) { return invokeChannel('syspanel:power-settings-unlock', { schemeGuid: schemeGuid }); },
      powerSettingsApply: function (schemeGuid, changes, applyActive) { return invokeChannel('syspanel:power-settings-apply', { schemeGuid: schemeGuid, changes: changes || [], applyActive: !!applyActive }); },
      powerSettingsRevert: function (schemeGuid, sessionId) { return invokeChannel('syspanel:power-settings-revert', { schemeGuid: schemeGuid, sessionId: sessionId }); },
      powerSettingsCompare: function (subgroupGuid, settingGuid) { return invokeChannel('syspanel:power-settings-compare', { subgroupGuid: subgroupGuid, settingGuid: settingGuid }); },
      powerSettingsOpenRegedit: function (subgroupGuid, settingGuid) { return invokeChannel('syspanel:power-settings-open-regedit', { subgroupGuid: subgroupGuid, settingGuid: settingGuid }); },
      powerUltimateEnable: function () { return invokeChannel('syspanel:power-ultimate-enable'); },
      powerHideHighPerformance: function (confirmedHighRisk) { return invokeChannel('syspanel:power-hide-high-performance', { confirmedHighRisk: !!confirmedHighRisk }); },
      powerRestoreHighPerformance: function () { return invokeChannel('syspanel:power-restore-high-performance'); },
      // 提权重启接回编辑态：新实例首帧后主进程发一次（lib.rs），消费者在 app.js。
      onEditIntent: function (callback) { return onEvent('syspanel:edit-intent', callback); },
      pagefileState: function () { return invokeChannel('syspanel:pagefile-state'); },
      // 高危：confirmedHighRisk 必须由**调用点**传入（v4-K05：此前桥接层硬编码 true，等于任何调用点天生「已确认」，
      // 后端那道确认闸对渲染层结构性失效）。调用点要先弹 red 档确认（syspanel.js 的 applyPagefile）再传凭据进来。
      pagefileApply: function (managed, entries, confirmedHighRisk) {
        return invokeChannel('syspanel:pagefile-apply', {
          managed: managed,
          entries: entries || [],
          confirmedHighRisk: !!confirmedHighRisk
        });
      }
    },

    startup: {
      scan: function (refresh) {
        if (refresh === void 0) refresh = false;
        return invokeChannel('startup:scan', { refresh: refresh });
      },
      toggle: function (items, enable) { return invokeChannel('startup:toggle', { items: items, enable: enable }); },
      remove: function (items) { return invokeChannel('startup:delete', { items: items }); },
      openLocation: function (targetPath) { return invokeChannel('startup:openlocation', { path: targetPath }); },
      // B-6 增强：同时打开软件位置与其登记来源（注册表键 / 计划任务落盘文件）
      openSource: function (coords) { return invokeChannel('startup:open-source', coords); },
      add: function () { return invokeChannel('startup:add', {}); }
    }
  };

  // window:focus-state / window:resized：Tauri 核心窗口事件桥接（Phase 0 草案，A 批双跑对照时逐字段校准；
  // 当前载荷形状按 main.js notifyRendererResize 复刻）

  function bridgeFocusState(callback) {
    var offs = [
      onTauriWindowEvent('tauri://focus', function () { callback({ focused: true }); }),
      onTauriWindowEvent('tauri://blur', function () { callback({ focused: false }); })
    ];
    return function () { offs.forEach(function (off) { off(); }); };
  }

  function bridgeResized(callback) {
    return onTauriWindowEvent('tauri://resize', function (size) {
      // Tauri 给物理像素，Electron 发的是 getContentBounds 逻辑像素
      var scale = window.devicePixelRatio || 1;
      var bounds = {
        width: Math.round((size && size.width || 0) / scale),
        height: Math.round((size && size.height || 0) / scale)
      };
      pluginInvoke('is_maximized').then(function (maximized) {
        callback({ width: bounds.width, height: bounds.height, maximized: !!maximized });
        syncMaximizeVisual(!!maximized);
      }).catch(function () {
        callback({ width: bounds.width, height: bounds.height, maximized: false });
      });
    });
  }

  // 与 onEvent 相同，但语义上标记为 tauri:// 核心窗口事件
  function onTauriWindowEvent(name, cb) { return onEvent(name, cb); }

  // 黑闪握手：DOMContentLoaded 后双 rAF（200ms 竞速兜底）通知 Rust show()

  // 真幂等（F3-M08）：守卫必须在模块作用域——此前 `var sent = false` 是每次调用的闭包变量 ⇒ 两次调用 = 两份 DCL 监听
  // + 两份双 rAF + 两份 200ms 竞速 + 两次 `app_first_paint` invoke；后端「只认首个通知」把症状盖住了，
  // 但白名单/审计看到的是「一次握手发了两回」。
  var firstPaintSent = false;

  function notifyFirstPaint() {
    function send() {
      if (firstPaintSent) return;
      firstPaintSent = true;
      // app:first-paint 属于 onSafe 的 send 通道（8 条之一），不在 133 invoke 的 CHANNEL_MAP 内：直连 Rust snake_case 命令，不兑现会走 Rust 3s/8s 兜底。
      invokeCore('app_first_paint').catch(function () {});
    }
    function arm() {
      requestAnimationFrame(function () { requestAnimationFrame(send); });
      setTimeout(send, 200);
    }
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', arm, { once: true });
    } else {
      arm();
    }
  }

  // 自绘 caption 三按钮 + 拖动 + 8 向缩放命中区（D3，Phase 0 实测件）
  // 样式注入遵守 CSP：style-src 已含 'unsafe-inline'；脚本仍全部外链。
  // Phase 2 定稿后样式迁入 main.css 既有 token、命中区改走选定方案（自绘命中区 vs tao 原生 resize 边框），此处为唯一待替换点。

  var EDGE_SIZE = 6;   // 边缘命中厚度 px
  var CORNER_SIZE = 14; // 角区命中 px

  function injectCaptionStyles() {
    if (document.getElementById('tauri-caption-style')) return;
    var style = document.createElement('style');
    style.id = 'tauri-caption-style';
    style.textContent = [
      // 高度必须与 main.css .titlebar（36px）一致：46px 时代字形中心比品牌行低 5px（真机目检实锤）。
      '.tauri-caption{position:fixed;top:0;right:0;height:36px;display:flex;z-index:100000;',
      '  -webkit-user-select:none;user-select:none;}',
      '.tauri-caption-btn{width:46px;height:100%;border:0;background:transparent;cursor:default;',
      '  display:flex;align-items:center;justify-content:center;padding:0;color:currentColor;',
      '  font-size:10px;line-height:1;opacity:.72;transition:background .12s ease,opacity .12s ease;}',
      '.tauri-caption-btn svg{width:11px;height:11px;stroke:currentColor;fill:none;stroke-width:1.4;}',
      // 审查 v2-L5：原先的 `rgba(0,0,0,.07)` 与 `#c42b1c`/`#fff` 三个字面色值既不随主题走（暗色下 7% 黑 hover 几乎看不见）、
      // 白字又违反「实底语义色前景必须走 token」；改用既有 token（暗/亮两主题对比度均已验）。
      '.tauri-caption-btn:hover{background:var(--bg-card-hover);opacity:1;}',
      '.tauri-caption-btn[data-act=close]:hover{background:var(--danger);color:var(--danger-text);opacity:1;}',
      '.tauri-caption-btn[data-act=maximize] .tauri-cap-restore{display:none;}',
      'body.tauri-maximized .tauri-caption-btn[data-act=maximize] .tauri-cap-max{display:none;}',
      'body.tauri-maximized .tauri-caption-btn[data-act=maximize] .tauri-cap-restore{display:block;}',
      '.tauri-resize-zone{position:fixed;z-index:99999;}',
      '.tauri-resize-zone[data-dir=n]{top:0;left:0;right:0;height:' + EDGE_SIZE + 'px;cursor:n-resize;}',
      '.tauri-resize-zone[data-dir=s]{bottom:0;left:0;right:0;height:' + EDGE_SIZE + 'px;cursor:s-resize;}',
      '.tauri-resize-zone[data-dir=w]{top:0;bottom:0;left:0;width:' + EDGE_SIZE + 'px;cursor:w-resize;}',
      '.tauri-resize-zone[data-dir=e]{top:0;bottom:0;right:0;width:' + EDGE_SIZE + 'px;cursor:e-resize;}',
      '.tauri-resize-zone[data-dir=ne]{top:0;right:0;width:' + CORNER_SIZE + 'px;height:' + CORNER_SIZE + 'px;cursor:ne-resize;z-index:100001;}',
      '.tauri-resize-zone[data-dir=nw]{top:0;left:0;width:' + CORNER_SIZE + 'px;height:' + CORNER_SIZE + 'px;cursor:nw-resize;z-index:100001;}',
      '.tauri-resize-zone[data-dir=se]{bottom:0;right:0;width:' + CORNER_SIZE + 'px;height:' + CORNER_SIZE + 'px;cursor:se-resize;z-index:100001;}',
      '.tauri-resize-zone[data-dir=sw]{bottom:0;left:0;width:' + CORNER_SIZE + 'px;height:' + CORNER_SIZE + 'px;cursor:sw-resize;z-index:100001;}',
      'body.tauri-maximized .tauri-resize-zone{display:none;}'
    ].join('');
    document.head.appendChild(style);
  }

  function capSvg(inner) {
    return '<svg viewBox="0 0 12 12" aria-hidden="true">' + inner + '</svg>';
  }

  function injectCaption() {
    if (document.querySelector('.tauri-caption')) return;
    // 审查 M4：自绘 caption 只给主窗装。两个子窗（models / processManager）建窗时没关原生装饰，标题栏本来就由系统提供，
    // 这层叠加件在它们身上只是「点了会去要 close/drag/resize 权限」的空壳——正是它逼着 capabilities 给所有窗口发
    // allow-close；去掉叠加件，权限就能收回主窗一处（见 capabilities/default.json 与 subwindows.json 的拆分）。
    if (currentLabel() !== 'main') return;
    injectCaptionStyles();

    var bar = document.createElement('div');
    bar.className = 'tauri-caption';
    // 审查 v2-F8：`decorations(false)`（lib.rs:439）已排除原生标题栏，这套自绘按钮是最小化/最大化/关闭的**唯一**入口。
    // 原先三个按钮都带 `tabindex="-1"`，纯键盘用户完全不可达（`ds.js` 的焦点陷阱选择器也排除 `[tabindex="-1"]`），且
    // `index.html:32/40` 还留着「由 Windows 原生 titleBarOverlay 渲染」的过时注释。这里去掉限制，容器升级为 `role="toolbar"`。
    bar.setAttribute('role', 'toolbar');
    bar.setAttribute('aria-label', '窗口控制');
    bar.innerHTML =
      '<button type="button" class="tauri-caption-btn" data-act="minimize" aria-label="最小化">' +
        capSvg('<line x1="2" y1="6" x2="10" y2="6"/>') + '</button>' +
      '<button type="button" class="tauri-caption-btn" data-act="maximize" aria-label="最大化/还原">' +
        '<svg class="tauri-cap-max" viewBox="0 0 12 12" aria-hidden="true"><rect x="2.5" y="2.5" width="7" height="7"/></svg>' +
        '<svg class="tauri-cap-restore" viewBox="0 0 12 12" aria-hidden="true"><rect x="3.5" y="1.5" width="6" height="6"/><path d="M2 4v6h6"/></svg>' +
      '</button>' +
      '<button type="button" class="tauri-caption-btn" data-act="close" aria-label="关闭">' +
        capSvg('<line x1="2.5" y1="2.5" x2="9.5" y2="9.5"/><line x1="9.5" y1="2.5" x2="2.5" y2="9.5"/>') + '</button>';
    document.body.appendChild(bar);

    bar.addEventListener('click', function (e) {
      var btn = e.target.closest && e.target.closest('.tauri-caption-btn');
      if (!btn) return;
      var act = btn.getAttribute('data-act');
      if (act === 'minimize') pluginInvoke('minimize').catch(function (e) {
        // A2-L03：同文件 maximize/drag/resize 都留痕，只有 minimize 漏接 reject。
        if (window.app && window.app.log) window.app.log('warn', '窗口最小化失败: ' + ((e && e.message) || e));
      });
      else if (act === 'maximize') pluginInvoke('toggle_maximize').then(refreshMaximizeVisual).catch(function (e) {
        // NEW-4（L3 2026-10-01）：最大化切换失败必须留痕（与下方拖拽失败同一口径），不能无声
        if (window.app && window.app.log) window.app.log('warn', '窗口最大化切换失败: ' + ((e && e.message) || e));
      });
      else if (act === 'close') api.window.close();
    });

    ['n', 's', 'w', 'e', 'ne', 'nw', 'se', 'sw'].forEach(function (dir) {
      var zone = document.createElement('div');
      zone.className = 'tauri-resize-zone';
      zone.setAttribute('data-dir', dir);
      document.body.appendChild(zone);
      zone.addEventListener('mousedown', function (e) {
        if (e.button !== 0) return;
        e.preventDefault();
        // ResizeDirection 序列化为 PascalCase 字符串（与 @tauri-apps/api 2.11.1 一致）
        var value = ({
          n: 'North', s: 'South', w: 'West', e: 'East',
          ne: 'NorthEast', nw: 'NorthWest', se: 'SouthEast', sw: 'SouthWest'
        })[dir];
        invokeCore('plugin:window|start_resize_dragging', { label: currentLabel(), value: value }).catch(function (e) {
          // 审查 v3-L2：拖拽失败的表现是「拖不动边框」，此前完全静默（连日志都没有）。
          // 至少留痕，便于定位是窗口已销毁还是插件能力缺失。
          if (window.app && window.app.log) window.app.log('warn', '窗口缩放拖拽失败: ' + (e && e.message ? e.message : e));
        });
      });
    });

    // 标题栏拖动 + 双击最大化（#titlebar 是渲染层既有拖带；按钮区排除）
    document.addEventListener('mousedown', function (e) {
      if (e.button !== 0) return;
      if (e.target.closest && (e.target.closest('.tauri-caption') || e.target.closest('.tauri-resize-zone'))) return;
      var titlebar = e.target.closest && e.target.closest('#titlebar');
      if (!titlebar) return;
      e.preventDefault();
      pluginInvoke('start_dragging').catch(function (e) {
        // 审查 v3-L2：同上，标题栏拖动失败需留痕
        if (window.app && window.app.log) window.app.log('warn', '标题栏拖动失败: ' + (e && e.message ? e.message : e));
      });
    }, true);
    document.addEventListener('dblclick', function (e) {
      var titlebar = e.target.closest && e.target.closest('#titlebar');
      if (!titlebar) return;
      if (e.target.closest && e.target.closest('.tauri-caption')) return;
      pluginInvoke('toggle_maximize').then(refreshMaximizeVisual).catch(function (e) {
        if (window.app && window.app.log) window.app.log('warn', '窗口最大化切换失败: ' + ((e && e.message) || e));
      });
    });

    refreshMaximizeVisual();
  }

  function syncMaximizeVisual(maximized) {
    document.body.classList.toggle('tauri-maximized', maximized);
  }
  function refreshMaximizeVisual() {
    pluginInvoke('is_maximized').then(function (m) { syncMaximizeVisual(!!m); }).catch(function () {});
  }

  function initCaption() {
    if (document.body) injectCaption();
    else document.addEventListener('DOMContentLoaded', injectCaption, { once: true });
  }

  // 挂载

  // 与 contextBridge 同语义：只读代理即可满足现有用法（渲染层从不赋值 window.api）
  Object.defineProperty(window, 'api', {
    value: api,
    writable: false,
    configurable: false
  });

  // Phase 0 的 window.__trimSpike 探针已随 commands/spike.rs 一并删除：更要紧的是它导出的 `raw: invokeCore` ——
  // 那等于把「直调任意 Rust 命令」的入口挂在 window 上，绕过上面手工挑选的 window.api 白名单，与本项目
  // 「preload 只做白名单转发」的安全前提直接冲突。调试要看通道名就读 tools/check-channel-map.mjs 的输出，不要重开这个口子。

  // 渲染层诊断上报（N3，2026-09-29 借鉴杰瑞调机助手的 boot.log 做法）：JS 异常与未处理的 Promise 拒绝此前只在
  // DevTools 里、用户侧完全不可见，白屏与材质不渲染（v2-U4）因此无从诊断，而 AGENTS §4 也不允许随手起前台窗口目检。
  // 走**既有** log:write 通道（本轮补了清洗：换行、长度、level 白名单），不新开 IPC 面。
  (function installRendererDiagnostics() {
    if (window.__trimDiagInstalled) return;
    window.__trimDiagInstalled = true;
    var MAX_REPORTS = 20; // 一处循环里持续抛错不能把日志刷爆
    var sent = 0;
    function report(kind, detail) {
      if (sent >= MAX_REPORTS) return;
      sent += 1;
      try {
        window.api.log.write('error', '渲染层' + kind + '：' + String(detail == null ? '' : detail).slice(0, 500));
      } catch (e) {
        // 上报本身失败绝不再抛：那会变成「记错误导致新错误」的递归
      }
    }
    // capture 阶段才能收到 img/link/script 的加载失败（它们不冒泡）
    window.addEventListener('error', function (ev) {
      var t = ev.target;
      if (t && t !== window && (t.src || t.href)) {
        report('资源加载失败', (t.tagName || 'ELEMENT') + ' ' + (t.src || t.href));
        return;
      }
      // ResizeObserver「loop completed with undelivered notifications」不是未捕获异常：它是浏览器在同帧内尺寸反复变化时
      // 自投的投递轮次上限提示（filename 恒为页面根、lineno 0、无栈），记成 ERROR 级会把真异常淹掉（2026-09-30 日志唯一那条就是它）。
      if (/^ResizeObserver loop/i.test(ev.message || '')) {
        try { console.debug('[Trim] ResizeObserver 投递轮次提示（已忽略）:', ev.message); } catch (e) {}
        return;
      }
      report('异常', (ev.message || '') + ' @' + (ev.filename || '') + ':' + (ev.lineno || 0));
    }, true);
    window.addEventListener('unhandledrejection', function (ev) {
      var r = ev.reason;
      report('未处理的 Promise 拒绝', (r && (r.message || r.stack)) || String(r));
    });
  })();

  initCaption();
  notifyFirstPaint();
})();

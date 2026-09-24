// tauri-api.js - Tauri 适配层（迁移方案 D1/D2，Phase 0 草案 v0.1）
// ============================================================================
// 唯一新增的前端文件，零依赖、零模块加载器，在 index.html 脚本链最前面加载。
// 职责：完整复刻 preload.js 暴露的 window.api 形状，内部把 Electron IPC 转成
// Tauri 命令，使 43 个渲染脚本里的 326 处 window.api 调用点零改动。
//
// 双轨约定：检测到 window.__TAURI_INTERNALS__ 才接管；Electron 下直接 return，
// window.api 仍由 preload.js contextBridge 提供（Phase 5 前双轨并存）。
//
// 协议来源（Phase 0 第 3 项实测核对，@tauri-apps/api 2.11.1）：
//   调用：window.__TAURI_INTERNALS__.invoke(cmd, args, options)
//   回调：window.__TAURI_INTERNALS__.transformCallback(cb, once) -> id
//         window.__TAURI_INTERNALS__.unregisterCallback(id)
//   监听：invoke('plugin:event|listen',  { event, target:{kind:'Any'}, handler:id }) -> eventId
//   退订：__TAURI_EVENT_PLUGIN_INTERNALS__.unregisterListener(event, eventId)（若注入存在）
//         + invoke('plugin:event|unlisten', { event, eventId })
//   发事件：invoke('plugin:event|emit', { event, payload })
//   窗口：invoke('plugin:window|<snake>', { label, ... })
//         start_resize_dragging 载荷 { label, value: 'NorthEast' 等 8 向字符串 }
//
// Phase 0 草案范围：window.api 全形状 + 发送通道 + 事件 + 自绘 caption/拖动/缩放
// 实测件。未迁 Rust 通道的 invoke 会 reject（与 Electron 缺 handler 同型），
// 渲染层已有 catch 兜底；逐批迁移时只动 CHANNEL_MAP 与 Rust 侧。
(function () {
  'use strict';

  var internals = window.__TAURI_INTERNALS__;
  // Electron（或任何非 Tauri 环境）：不接管，preload.js 的 window.api 生效。
  if (!internals) return;

  document.documentElement.classList.add('tauri-runtime');
  if (document.body) document.body.classList.add('tauri-runtime');
  else document.addEventListener('DOMContentLoaded', function () {
    document.body.classList.add('tauri-runtime');
  }, { once: true });

  // --------------------------------------------------------------------------
  // 内核调用
  // --------------------------------------------------------------------------

  function currentLabel() {
    return internals.metadata && internals.metadata.currentWindow && internals.metadata.currentWindow.label;
  }

  /**
   * CHANNEL_MAP：Electron 通道（preload.js 唯一真源）→ Rust snake_case 命令。
   * D2：本键集合必须恒等于 preload.js 的 invoke 通道集合（133 条）；
   * Phase 1 起 Node 一致性脚本进门禁，新增通道必须同表登记。
   * 生成规则：':' 与 '-' 统一转 '_'（此处显式列出，不做运行时隐式推导，
   * 防止「Rust 有了、前端没接 / 拼错」静默断裂）。
   */
  var CHANNEL_MAP = {
    // app 域（onMemoryTrim 是事件，不在此表）
    'app:get-info': 'app_get_info',
    'app:get-theme': 'app_get_theme',
    'app:read-usage': 'app_read_usage',
    'app:open-external': 'app_open_external',
    // updater 域（onState 是事件）
    'updater:check': 'updater_check',
    'updater:download': 'updater_download',
    'updater:cancel-download': 'updater_cancel_download',
    'updater:install': 'updater_install',
    'updater:set-mirror': 'updater_set_mirror',
    'updater:get-mirror': 'updater_get_mirror',
    // device / overview
    'device:scan': 'device_scan',
    'overview:metrics': 'overview_metrics',
    'overview:hardware': 'overview_hardware',
    'overview:checkup': 'overview_checkup',
    // window（update-overlay：Tauri 无原生 overlay，Phase A 落 noop 命令）
    'window:update-overlay': 'window_update_overlay',
    // log
    'log:write': 'log_write',
    'log:read': 'log_read',
    'log:export': 'log_export',
    // cleanup（9）
    'cleanup:rules': 'cleanup_rules',
    'cleanup:scan': 'cleanup_scan',
    'cleanup:execute': 'cleanup_execute',
    'cleanup:update-rules': 'cleanup_update_rules',
    'cleanup:check-rules-version': 'cleanup_check_rules_version',
    'cleanup:retry-failed-delete': 'cleanup_retry_failed_delete',
    'cleanup:check-locked': 'cleanup_check_locked',
    'cleanup:kill-locked-processes': 'cleanup_kill_locked_processes',
    'cleanup:item-detail': 'cleanup_item_detail',
    // runtimes / pwsh
    'runtimes:collect': 'runtimes_collect',
    'runtimes:install': 'runtimes_install',
    'pwsh:status': 'pwsh_status',
    'pwsh:prepare': 'pwsh_prepare',
    // finder（4）
    'finder:scan': 'finder_scan',
    'finder:delete': 'finder_delete',
    'finder:delete-manifest': 'finder_delete_manifest',
    'finder:open-backup-dir': 'finder_open_backup_dir',
    // contextmenu（10）
    'contextmenu:scan': 'contextmenu_scan',
    'contextmenu:backup': 'contextmenu_backup',
    'contextmenu:remove': 'contextmenu_remove',
    'contextmenu:toggle': 'contextmenu_toggle',
    'contextmenu:restore': 'contextmenu_restore',
    'contextmenu:icons': 'contextmenu_icons',
    'contextmenu:open-in-regedit': 'contextmenu_open_in_regedit',
    'contextmenu:restart-explorer': 'contextmenu_restart_explorer',
    'contextmenu:win11-classic': 'contextmenu_win11_classic',
    'contextmenu:blocked-list': 'contextmenu_blocked_list',
    // modal（2）/ diag / settings / intro
    'modal:open': 'modal_open',
    'modal:close': 'modal_close',
    'diag:dwm-conflict': 'diag_dwm_conflict',
    'settings:load': 'settings_load',
    'settings:save': 'settings_save',
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
    // aidesc / netspeed / diskbench
    'aidesc:get': 'aidesc_get',
    'netspeed:ping': 'netspeed_ping',
    'netspeed:throughput': 'netspeed_throughput',
    'diskbench:run': 'diskbench_run',
    // realtime（7）
    'realtime:adapters': 'realtime_adapters',
    'realtime:sample': 'realtime_sample',
    'realtime:loss': 'realtime_loss',
    'realtime:report-save': 'realtime_report_save',
    'realtime:report-list': 'realtime_report_list',
    'realtime:report-delete': 'realtime_report_delete',
    'realtime:report-clear': 'realtime_report_clear',
    // bench-history（4）/ elevate（2）
    'bench-history:add': 'bench_history_add',
    'bench-history:list': 'bench_history_list',
    'bench-history:delete': 'bench_history_delete',
    'bench-history:clear': 'bench_history_clear',
    'elevate:status': 'elevate_status',
    'elevate:request': 'elevate_request',
    // paths（7）
    'paths:scan': 'paths_scan',
    'paths:load': 'paths_load',
    'paths:save': 'paths_save',
    'paths:browse': 'paths_browse',
    'paths:validate': 'paths_validate',
    'paths:app-icon': 'paths_app_icon',
    'paths:file-icon': 'paths_file_icon',
    // fileclean（4）
    'fileclean:scan': 'fileclean_scan',
    'fileclean:read-image': 'fileclean_read_image',
    'fileclean:execute': 'fileclean_execute',
    'fileclean:delete-file': 'fileclean_delete_file',
    // maintenance（2）/ netcheck（2）
    'maintenance:tasks': 'maintenance_tasks',
    'maintenance:run': 'maintenance_run',
    'netcheck:collect': 'netcheck_collect',
    'netcheck:repair': 'netcheck_repair',
    // preview 窗口（2）
    'preview:open-window': 'preview_open_window',
    'preview:close-window': 'preview_close_window',
    // memory（6）/ processManager 窗口（2）/ peripheral（5）
    'memory:info': 'memory_info',
    'memory:clean': 'memory_clean',
    'memory:stubborn-kill': 'memory_stubborn_kill',
    'memory:stubborn-block': 'memory_stubborn_block',
    'memory:processes': 'memory_processes',
    'memory:kill': 'memory_kill',
    'processManager:open-window': 'process_manager_open_window',
    'processManager:close-window': 'process_manager_close_window',
    'peripheral:open-window': 'peripheral_open_window',
    'peripheral:close-window': 'peripheral_close_window',
    'peripheral:query': 'peripheral_query',
    'peripheral:apply': 'peripheral_apply',
    'peripheral:restore-backup': 'peripheral_restore_backup',
    // quickcmds / optimizer（11）
    'quickcmds:run': 'quickcmds_run',
    'optimizer:run': 'optimizer_run',
    'optimizer:list': 'optimizer_list',
    'optimizer:genadvice': 'optimizer_genadvice',
    'optimizer:check-restore': 'optimizer_check_restore',
    'optimizer:create-restore': 'optimizer_create_restore',
    'optimizer:list-restore': 'optimizer_list_restore',
    'optimizer:check-optimized': 'optimizer_check_optimized',
    'optimizer:svc-mem-current': 'optimizer_svc_mem_current',
    'optimizer:backup-reg': 'optimizer_backup_reg',
    'optimizer:restore-reg': 'optimizer_restore_reg',
    'optimizer:state-overview': 'optimizer_state_overview',
    // system / startup（5）
    'system:disk-type': 'system_disk_type',
    'startup:scan': 'startup_scan',
    'startup:toggle': 'startup_toggle',
    'startup:delete': 'startup_delete',
    'startup:openlocation': 'startup_openlocation',
    'startup:add': 'startup_add'
  };

  /** Electron invoke 通道 → Promise（成功 resolve / 失败 reject，与 ipcRenderer.invoke 同契约）。 */
  function invokeChannel(channel, args) {
    var cmd = CHANNEL_MAP[channel];
    if (!cmd) return Promise.reject(new Error('tauri-api：未登记通道 ' + channel));
    return invokeCore(cmd, args || {});
  }

  function invokeCore(cmd, args) {
    return internals.invoke(cmd, args || {}, undefined);
  }

  function pluginInvoke(pluginCmd, extra) {
    var args = Object.assign({ label: currentLabel() }, extra || {});
    return invokeCore('plugin:window|' + pluginCmd, args);
  }

  /**
   * SEND_MAP：preload.js 的 8 条 ipcRenderer.send 通道（与 133 invoke 集合互斥）。
   * - window:minimize/maximize/close 走窗口插件、app:first-paint 走直连命令，
   *   均不经过 sendChannel（各自有专用桥接）；
   * - 其余 4 条 fire-and-forget 在此显式映射。禁止运行时隐式 replace——
   *   驼峰域（processManager）隐式转换会拼错 Rust snake_case 命令（Phase 0 发现）。
   */
  var SEND_MAP = {
    'shutdown:begin': 'shutdown_begin',
    'shutdown:complete': 'shutdown_complete',
    'preview:image-deleted': 'preview_image_deleted',
    'processManager:report': 'process_manager_report'
  };

  /** Electron ipcRenderer.send 等价（fire-and-forget；Rust 未迁时静默吞错，同 send 无回执语义）。 */
  function sendChannel(channel, args) {
    var cmd = SEND_MAP[channel];
    if (!cmd) {
      console.warn('[tauri-api] 未登记的 send 通道: ' + channel);
      return;
    }
    invokeCore(cmd, args || {}).catch(function () {});
  }

  // --------------------------------------------------------------------------
  // 事件：onXxx 必须同步返回 unsubscribe（Electron removeListener 同形状）
  // --------------------------------------------------------------------------

  /**
   * 订阅后端事件，handler 收到 payload（已剥掉 Tauri event 信封，
   * 对齐 preload 里 (_, data) => cb(data)）。返回同步可用的退订函数。
   */
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
          } catch (e) {}
          return invokeCore('plugin:event|unlisten', { event: event, eventId: eventId });
        });
      }).catch(function (e) {
        console.error('[tauri-api] 事件订阅失败 ' + event, e);
        resolve(function () {});
      });
    });
    return function unsubscribe() {
      if (!active) return;
      active = false;
      offPromise.then(function (off) { off().catch(function () {}); });
    };
  }

  // --------------------------------------------------------------------------
  // window.api：逐方法复刻 preload.js（含参数整形，一个都不能走样）
  // --------------------------------------------------------------------------

  var api = {
    /**
     * 绝对路径 → 页面可直接加载的 URL。
     *
     * 为什么要走这里而不是沿用调用方手拼的 `file:///`：Tauri 的页源是
     * `http://tauri.localhost`，Chromium 会拦掉跨源的 `file:` 子资源，
     * CSP 里留着 `file:` 也放行不了 —— 表现为「路径正确但图/字体就是不出来」。
     * 必须走 asset 协议（conf 的 assetProtocol.scope 只放行了 backgrounds 与 fonts）。
     *
     * URL 形态按平台不同（Windows 是 `http://asset.localhost/<encoded>`，
     * macOS/Linux 是 `asset://localhost/<encoded>`），所以**不在前端复刻规则**，
     * 直接用 Tauri 注入脚本提供的 convertFileSrc。
     * 取不到时退回 file:///，保证非 Tauri 环境（或注入脚本缺席）不白屏。
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
      getTheme: function () { return invokeChannel('app:get-theme'); },
      readUsage: function () { return invokeChannel('app:read-usage'); },
      // 裸标量载荷（preload 直传 url 而非对象）：Tauri 命令必须收到具名参数，此处整形为 { url }
      openExternal: function (url) { return invokeChannel('app:open-external', { url: url }); },
      onMemoryTrim: function (callback) { return onEvent('memory:trim', function () { callback(); }); }
    },

    updater: {
      check: function () { return invokeChannel('updater:check'); },
      download: function () { return invokeChannel('updater:download'); },
      cancelDownload: function () { return invokeChannel('updater:cancel-download'); },
      install: function () { return invokeChannel('updater:install'); },
      setMirror: function (mirror) { return invokeChannel('updater:set-mirror', { mirror: mirror }); },
      getMirror: function () { return invokeChannel('updater:get-mirror'); },
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
      },
      checkup: function (options) {
        if (options === void 0) options = {};
        return invokeChannel('overview:checkup', options);
      }
    },

    window: {
      // A 批备注：close 在 Phase 2 前是硬关窗（无静默收尾）；迁移后走 shutdown 流程
      minimize: function () { return pluginInvoke('minimize'); },
      maximize: function () { return pluginInvoke('toggle_maximize'); },
      close: function () { return pluginInvoke('close'); },
      // Tauri 无原生 titleBarOverlay；按钮配色由自绘 caption 的 CSS 主题负责。
      // 但仍要真实过一遍通道（Electron 返回 true，渲染层可能依赖回执），
      // Rust 侧为 no-op 命令。
      updateOverlay: function (isDark) { return invokeChannel('window:update-overlay', { isDark: isDark }); },
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
      scan: function (categories) { return invokeChannel('cleanup:scan', { categories: categories }); },
      execute: function (items, force, toRecycle, autoRebuild) {
        return invokeChannel('cleanup:execute', {
          items: items,
          force: force === true,
          toRecycle: toRecycle === true,
          autoRebuild: autoRebuild === true
        });
      },
      updateRules: function () { return invokeChannel('cleanup:update-rules'); },
      checkRulesVersion: function () { return invokeChannel('cleanup:check-rules-version'); },
      onRulesDownloadProgress: function (callback) { return onEvent('cleanup:rules-download-progress', callback); },
      retryFailedDelete: function () { return invokeChannel('cleanup:retry-failed-delete'); },
      checkLocked: function (ids) { return invokeChannel('cleanup:check-locked', { ids: ids }); },
      killLockedProcesses: function () { return invokeChannel('cleanup:kill-locked-processes'); },
      itemDetail: function (id, path) {
        if (path === void 0) path = '';
        return invokeChannel('cleanup:item-detail', { id: id, path: path });
      },
      onScanProgress: function (callback) { return onEvent('cleanup:scan-progress', callback); }
    },

    runtimes: {
      collect: function () { return invokeChannel('runtimes:collect'); },
      install: function (actionId) { return invokeChannel('runtimes:install', { actionId: actionId }); },
      onProgress: function (callback) { return onEvent('runtimes:install-progress', callback); }
    },

    pwsh: {
      getStatus: function () { return invokeChannel('pwsh:status'); },
      prepare: function () { return invokeChannel('pwsh:prepare'); },
      onStatus: function (callback) { return onEvent('pwsh:status', callback); }
    },

    finder: {
      scan: function (scanType, opts) {
        if (opts === void 0) opts = {};
        return invokeChannel('finder:scan', Object.assign({ scanType: scanType }, opts));
      },
      delete: function (items) { return invokeChannel('finder:delete', { items: items }); },
      onProgress: function (callback) { return onEvent('finder:progress', callback); },
      deleteManifest: function () { return invokeChannel('finder:delete-manifest'); },
      openBackupDir: function () { return invokeChannel('finder:open-backup-dir'); }
    },

    contextmenu: {
      scan: function (refresh) {
        if (refresh === void 0) refresh = false;
        return invokeChannel('contextmenu:scan', { refresh: refresh });
      },
      backup: function (items) { return invokeChannel('contextmenu:backup', { items: items }); },
      remove: function (items) { return invokeChannel('contextmenu:remove', { items: items }); },
      toggle: function (items) { return invokeChannel('contextmenu:toggle', { items: items }); },
      restore: function () { return invokeChannel('contextmenu:restore'); },
      icons: function (items) { return invokeChannel('contextmenu:icons', { items: items }); },
      openInRegedit: function (regPath) { return invokeChannel('contextmenu:open-in-regedit', { regPath: regPath }); },
      restartExplorer: function () { return invokeChannel('contextmenu:restart-explorer'); },
      win11Mode: function (action) { return invokeChannel('contextmenu:win11-classic', { action: action }); },
      blockedList: function () { return invokeChannel('contextmenu:blocked-list'); }
    },

    modal: {
      open: function (info) { return invokeChannel('modal:open', Object.assign({}, info)); },
      close: function (info) { return invokeChannel('modal:close', Object.assign({}, info)); }
    },

    diag: {
      dwmConflict: function () { return invokeChannel('diag:dwm-conflict'); }
    },

    settings: {
      load: function () { return invokeChannel('settings:load'); },
      save: function (settings) { return invokeChannel('settings:save', { settings: settings }); }
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
      get: function (name, company, force, scope) {
        return invokeChannel('aidesc:get', { name: name, company: company, force: force, scope: scope });
      }
    },

    netspeed: {
      ping: function () { return invokeChannel('netspeed:ping'); },
      throughput: function (duration) { return invokeChannel('netspeed:throughput', { duration: duration }); }
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
      status: function () { return invokeChannel('elevate:status'); },
      request: function () { return invokeChannel('elevate:request'); },
      onNotice: function (callback) { return onEvent('elevate:notice', callback); }
    },

    shutdown: {
      begin: function () { sendChannel('shutdown:begin'); },
      complete: function () { sendChannel('shutdown:complete'); }
    },

    paths: {
      scan: function () { return invokeChannel('paths:scan'); },
      load: function () { return invokeChannel('paths:load'); },
      save: function (key, value) { return invokeChannel('paths:save', { key: key, value: value }); },
      browse: function (title, defaultPath) { return invokeChannel('paths:browse', { title: title, defaultPath: defaultPath }); },
      validate: function (dirPath) { return invokeChannel('paths:validate', { path: dirPath }); },
      appIcon: function (installPath, exeCandidates) {
        return invokeChannel('paths:app-icon', { installPath: installPath, exeCandidates: exeCandidates });
      },
      fileIcon: function (filePath) { return invokeChannel('paths:file-icon', { filePath: filePath }); }
    },

    fileclean: {
      scan: function (type, customPath, total, doneBase) {
        return invokeChannel('fileclean:scan', {
          type: type, customPath: customPath, total: total, doneBase: doneBase
        });
      },
      readImage: function (filePath) { return invokeChannel('fileclean:read-image', { filePath: filePath }); },
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

    previewWindow: {
      open: function (payload) { return invokeChannel('preview:open-window', { payload: payload }); },
      close: function () { return invokeChannel('preview:close-window'); },
      onData: function (callback) { return onEvent('preview:data', callback); },
      notifyDeleted: function (filePath) { sendChannel('preview:image-deleted', { path: filePath }); },
      onImageDeleted: function (callback) { return onEvent('preview:image-deleted', callback); }
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
      openWindow: function () { return invokeChannel('peripheral:open-window'); },
      closeWindow: function () { return invokeChannel('peripheral:close-window'); },
      query: function () { return invokeChannel('peripheral:query'); },
      apply: function (options) { return invokeChannel('peripheral:apply', { options: options }); },
      restoreBackup: function () { return invokeChannel('peripheral:restore-backup'); }
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
      checkOptimized: function (ids) { return invokeChannel('optimizer:check-optimized', { ids: ids }); },
      svcMemCurrent: function () { return invokeChannel('optimizer:svc-mem-current'); },
      backupReg: function (optionId, steps) { return invokeChannel('optimizer:backup-reg', { optionId: optionId, steps: steps }); },
      restoreReg: function (optionId) { return invokeChannel('optimizer:restore-reg', { optionId: optionId }); },
      stateOverview: function () { return invokeChannel('optimizer:state-overview'); },
      onProgress: function (callback) { return onEvent('optimizer:progress', callback); }
    },

    system: {
      diskType: function (opts) {
        if (opts === void 0) opts = {};
        return invokeChannel('system:disk-type', opts);
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
      add: function () { return invokeChannel('startup:add', {}); }
    }
  };

  // --------------------------------------------------------------------------
  // window:focus-state / window:resized：Tauri 核心窗口事件桥接（Phase 0 草案，
  // A 批双跑对照时逐字段校准；当前载荷形状按 main.js notifyRendererResize 复刻）
  // --------------------------------------------------------------------------

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

  // --------------------------------------------------------------------------
  // 黑闪握手：DOMContentLoaded 后双 rAF（200ms 竞速兜底）通知 Rust show()
  // --------------------------------------------------------------------------

  function notifyFirstPaint() {
    var sent = false;
    function send() {
      if (sent) return;
      sent = true;
      // app:first-paint 属于 onSafe 的 send 通道（8 条之一），不在 133 invoke 的
      // CHANNEL_MAP 内，直连 Rust snake_case 命令；不兑现会走 Rust 3s/8s 兜底。
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

  // --------------------------------------------------------------------------
  // 自绘 caption 三按钮 + 拖动 + 8 向缩放命中区（D3，Phase 0 实测件）
  // 样式注入遵守 CSP：style-src 已含 'unsafe-inline'；脚本仍全部外链。
  // Phase 2 决策定稿后：样式迁入 main.css 既有 token、命中区改走选定方案
  // （自绘命中区 vs tao 原生 resize 边框），此处为唯一待替换点。
  // --------------------------------------------------------------------------

  var EDGE_SIZE = 6;   // 边缘命中厚度 px
  var CORNER_SIZE = 14; // 角区命中 px

  function injectCaptionStyles() {
    if (document.getElementById('tauri-caption-style')) return;
    var style = document.createElement('style');
    style.id = 'tauri-caption-style';
    style.textContent = [
      '.tauri-caption{position:fixed;top:0;right:0;height:46px;display:flex;z-index:100000;',
      '  -webkit-user-select:none;user-select:none;}',
      '.tauri-caption-btn{width:46px;height:100%;border:0;background:transparent;cursor:default;',
      '  display:flex;align-items:center;justify-content:center;padding:0;color:currentColor;',
      '  font-size:10px;line-height:1;opacity:.72;transition:background .12s ease,opacity .12s ease;}',
      '.tauri-caption-btn svg{width:11px;height:11px;stroke:currentColor;fill:none;stroke-width:1.4;}',
      '.tauri-caption-btn:hover{background:rgba(0,0,0,.07);opacity:1;}',
      '.tauri-caption-btn[data-act=close]:hover{background:#c42b1c;color:#fff;opacity:1;}',
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
    injectCaptionStyles();

    var bar = document.createElement('div');
    bar.className = 'tauri-caption';
    bar.setAttribute('role', 'group');
    bar.setAttribute('aria-label', '窗口控制');
    bar.innerHTML =
      '<button type="button" class="tauri-caption-btn" data-act="minimize" aria-label="最小化" tabindex="-1">' +
        capSvg('<line x1="2" y1="6" x2="10" y2="6"/>') + '</button>' +
      '<button type="button" class="tauri-caption-btn" data-act="maximize" aria-label="最大化/还原" tabindex="-1">' +
        '<svg class="tauri-cap-max" viewBox="0 0 12 12" aria-hidden="true"><rect x="2.5" y="2.5" width="7" height="7"/></svg>' +
        '<svg class="tauri-cap-restore" viewBox="0 0 12 12" aria-hidden="true"><rect x="3.5" y="1.5" width="6" height="6"/><path d="M2 4v6h6"/></svg>' +
      '</button>' +
      '<button type="button" class="tauri-caption-btn" data-act="close" aria-label="关闭" tabindex="-1">' +
        capSvg('<line x1="2.5" y1="2.5" x2="9.5" y2="9.5"/><line x1="9.5" y1="2.5" x2="2.5" y2="9.5"/>') + '</button>';
    document.body.appendChild(bar);

    bar.addEventListener('click', function (e) {
      var btn = e.target.closest && e.target.closest('.tauri-caption-btn');
      if (!btn) return;
      var act = btn.getAttribute('data-act');
      if (act === 'minimize') pluginInvoke('minimize');
      else if (act === 'maximize') pluginInvoke('toggle_maximize').then(refreshMaximizeVisual);
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
        invokeCore('plugin:window|start_resize_dragging', { label: currentLabel(), value: value }).catch(function () {});
      });
    });

    // 标题栏拖动 + 双击最大化（#titlebar 是渲染层既有拖带；按钮区排除）
    document.addEventListener('mousedown', function (e) {
      if (e.button !== 0) return;
      if (e.target.closest && (e.target.closest('.tauri-caption') || e.target.closest('.tauri-resize-zone'))) return;
      var titlebar = e.target.closest && e.target.closest('#titlebar');
      if (!titlebar) return;
      e.preventDefault();
      pluginInvoke('start_dragging').catch(function () {});
    }, true);
    document.addEventListener('dblclick', function (e) {
      var titlebar = e.target.closest && e.target.closest('#titlebar');
      if (!titlebar) return;
      if (e.target.closest && e.target.closest('.tauri-caption')) return;
      pluginInvoke('toggle_maximize').then(refreshMaximizeVisual);
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

  // --------------------------------------------------------------------------
  // 挂载
  // --------------------------------------------------------------------------

  // 与 contextBridge 同语义：只读代理即可满足现有用法（渲染层从不赋值 window.api）
  Object.defineProperty(window, 'api', {
    value: api,
    writable: false,
    configurable: false
  });

  // Phase 0 探针工具（非契约面，CDP/控制台验证用，Phase 1 前删除）
  window.__trimSpike = {
    channelMapKeys: function () { return Object.keys(CHANNEL_MAP); },
    ping: function () { return invokeCore('spike_ping'); },
    onPong: function (cb) { return onEvent('spike:pong', cb); },
    applyMaterial: function (m) { return invokeCore('spike_apply_material', { material: m }); },
    raw: invokeCore
  };

  initCaption();
  notifyFirstPaint();
})();

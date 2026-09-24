// preload.js - 安全 IPC 桥接
// 通过 contextBridge 暴露受限 API 给渲染进程
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  // 应用信息
  app: {
    getInfo: () => ipcRenderer.invoke('app:get-info'),
    getTheme: () => ipcRenderer.invoke('app:get-theme'),
    readUsage: () => ipcRenderer.invoke('app:read-usage'),
    // 外部 https 链接（主进程只放行 https，防注入）
    openExternal: (url) => ipcRenderer.invoke('app:open-external', url),
    onMemoryTrim: (callback) => {
      const handler = () => callback();
      ipcRenderer.on('memory:trim', handler);
      return () => ipcRenderer.removeListener('memory:trim', handler);
    }
  },
  // 应用自动更新（electron-updater；状态由主进程推送，渲染层只订阅）
  updater: {
    check: () => ipcRenderer.invoke('updater:check'),
    download: () => ipcRenderer.invoke('updater:download'),
    cancelDownload: () => ipcRenderer.invoke('updater:cancel-download'),
    install: () => ipcRenderer.invoke('updater:install'),
    // v2.6.0（P2-8）：更新镜像偏好（auto = GitHub 优先失败自动回退）
    setMirror: (mirror) => ipcRenderer.invoke('updater:set-mirror', { mirror }),
    getMirror: () => ipcRenderer.invoke('updater:get-mirror'),
    onState: (callback) => {
      const handler = (_, state) => callback(state);
      ipcRenderer.on('updater:state-changed', handler);
      return () => ipcRenderer.removeListener('updater:state-changed', handler);
    }
  },

  device: {
    scan: () => ipcRenderer.invoke('device:scan')
  },
  overview: {
    metrics: () => ipcRenderer.invoke('overview:metrics'),
    hardware: (options = {}) => ipcRenderer.invoke('overview:hardware', options),
    // v2.6.0（P1-6）：系统体检（只读诊断，返回 {checks:[{id,title,status,value,detail,evidence}]}）
    checkup: (options = {}) => ipcRenderer.invoke('overview:checkup', options)
  },

  // 窗口控制（原生 titleBarOverlay 提供 min/max/close，此处保留兼容）
  window: {
    minimize: () => ipcRenderer.send('window:minimize'),
    maximize: () => ipcRenderer.send('window:maximize'),
    close: () => ipcRenderer.send('window:close'),
    updateOverlay: (isDark) => ipcRenderer.invoke('window:update-overlay', { isDark }),
    // v2.8.0：窗口焦点状态（失焦差异化视觉纱）
    onFocusState: (callback) => {
      const handler = (_, state) => callback(state);
      ipcRenderer.on('window:focus-state', handler);
      return () => ipcRenderer.removeListener('window:focus-state', handler);
    },
    onResized: (callback) => {
      const handler = (_, bounds) => callback(bounds);
      ipcRenderer.on('window:resized', handler);
      return () => ipcRenderer.removeListener('window:resized', handler);
    },
    // 启动黑闪修复：DOMContentLoaded 后连排两个 rAF（确保首帧 UI 已真实提交合成），
    // 再通知主进程显示窗口。主进程按 sender 识别窗口，仅主窗口首个通知生效。
    // rAF 万一被节流，用 200ms 定时器竞速兜底，保证通知一定能发出。
    notifyFirstPaint: () => {
      let sent = false;
      const send = () => {
        if (sent) return;
        sent = true;
        try { ipcRenderer.send('app:first-paint'); } catch (e) {}
      };
      const arm = () => {
        requestAnimationFrame(() => requestAnimationFrame(send));
        setTimeout(send, 200);
      };
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', arm, { once: true });
      } else {
        arm();
      }
    }
  },

  // 日志
  log: {
    write: (level, message) => ipcRenderer.invoke('log:write', { level, message }),
    read: (date) => ipcRenderer.invoke('log:read', { date }),
    export: () => ipcRenderer.invoke('log:export')
  },

  // 清理
  cleanup: {
    rules: () => ipcRenderer.invoke('cleanup:rules'),
    scan: (categories) => ipcRenderer.invoke('cleanup:scan', { categories }),
    // P3：force / toRecycle / autoRebuild 三个执行选项由渲染层勾选框决定
    execute: (items, force = false, toRecycle = false, autoRebuild = false) => ipcRenderer.invoke('cleanup:execute', { items, force, toRecycle, autoRebuild }),
    // P2 规则库在线更新：从发布源下载并经校验后写入数据目录（防降级 + 原子替换）
    updateRules: () => ipcRenderer.invoke('cleanup:update-rules'),
    // v3.2.1：规则库版本检测（只读，远端验签后仅返回 rulesVersion，不写盘）
    checkRulesVersion: () => ipcRenderer.invoke('cleanup:check-rules-version'),
    // v3.2.1：规则库下载进度（0-99，主进程流式推送；返回解绑函数）
    onRulesDownloadProgress: (callback) => {
      const handler = (_, data) => callback(data);
      ipcRenderer.on('cleanup:rules-download-progress', handler);
      return () => ipcRenderer.removeListener('cleanup:rules-download-progress', handler);
    },
    // 审查 4-4：回收站失败项经用户红色确认后永久删除重试（目标由主进程白名单留存，渲染层不可指定）
    retryFailedDelete: () => ipcRenderer.invoke('cleanup:retry-failed-delete'),
    // v3.3.4：清理前占用检测（只读）与「结束占用进程」（PID 白名单由主进程最近一次检测结果决定）
    checkLocked: (ids) => ipcRenderer.invoke('cleanup:check-locked', { ids }),
    killLockedProcesses: () => ipcRenderer.invoke('cleanup:kill-locked-processes'),
    // P3 条目明细：枚举单个条目的文件清单（只读，供明细弹窗展示）
    itemDetail: (id, path = '') => ipcRenderer.invoke('cleanup:item-detail', { id, path }),
    onScanProgress: (callback) => {
      const handler = (_, data) => callback(data);
      ipcRenderer.on('cleanup:scan-progress', handler);
      return () => ipcRenderer.removeListener('cleanup:scan-progress', handler);
    }
  },

  // 运行库修复（v3.3.0）：collect 只读检测；install 只传 actionId（下载/校验/执行全在主进程）
  runtimes: {
    collect: () => ipcRenderer.invoke('runtimes:collect'),
    install: (actionId) => ipcRenderer.invoke('runtimes:install', { actionId }),
    onProgress: (callback) => {
      const handler = (_, data) => callback(data);
      ipcRenderer.on('runtimes:install-progress', handler);
      return () => ipcRenderer.removeListener('runtimes:install-progress', handler);
    }
  },

  // 内置 PowerShell 7 运行时（v3.3.x，方案 A 兜底）
  pwsh: {
    getStatus: () => ipcRenderer.invoke('pwsh:status'),
    prepare: () => ipcRenderer.invoke('pwsh:prepare'),
    onStatus: (callback) => {
      const handler = (_, data) => callback(data);
      ipcRenderer.on('pwsh:status', handler);
      return () => ipcRenderer.removeListener('pwsh:status', handler);
    }
  },

  // 磁盘清理 · Rust 原生查找器（重复/大文件/空/AppData）
  finder: {
    scan: (scanType, opts = {}) => ipcRenderer.invoke('finder:scan', { scanType, ...opts }),
    delete: (items) => ipcRenderer.invoke('finder:delete', { items }),
    onProgress: (callback) => {
      const handler = (_, data) => callback(data);
      ipcRenderer.on('finder:progress', handler);
      return () => ipcRenderer.removeListener('finder:progress', handler);
    },
    // 删除清单：查看最近删除项（含是否已进回收站）与打开清单目录
    deleteManifest: () => ipcRenderer.invoke('finder:delete-manifest'),
    openBackupDir: () => ipcRenderer.invoke('finder:open-backup-dir')
  },

  // 右键菜单
  contextmenu: {
    // v3.2.1：refresh=false 优先读持久缓存（首启扫描一次落盘）；true 强制重新扫描
    scan: (refresh = false) => ipcRenderer.invoke('contextmenu:scan', { refresh }),
    // 传递完整扫描项（包含 regPath/source），这样注册表项和“发送到”文件都能正确备份
    backup: (items) => ipcRenderer.invoke('contextmenu:backup', { items }),
    remove: (items) => ipcRenderer.invoke('contextmenu:remove', { items }),
    // 启停切换（Autoruns 模式：勾选=启用，取消=禁用；items: [{name, regPath, source, enabled}]）
    toggle: (items) => ipcRenderer.invoke('contextmenu:toggle', { items }),
    restore: () => ipcRenderer.invoke('contextmenu:restore'),
    // 提取程序图标（CLSID → DLL 图标，返回 {clsid: dataUrl}）
    icons: (items) => ipcRenderer.invoke('contextmenu:icons', { items }),
    // 在注册表编辑器中定位到指定注册表项（需要管理员权限时自动提权）
    openInRegedit: (regPath) => ipcRenderer.invoke('contextmenu:open-in-regedit', { regPath }),
    // 批次 B：重启当前会话的资源管理器，使右键菜单改动生效（渲染层先做红色确认）
    restartExplorer: () => ipcRenderer.invoke('contextmenu:restart-explorer'),
    // 批次 B：Win11 菜单模式，action ∈ get | set-classic | set-modern（只写 HKCU，不需要管理员）
    win11Mode: (action) => ipcRenderer.invoke('contextmenu:win11-classic', { action }),
    // 批次 B：Shell Extensions\Blocked 屏蔽表枚举（只读，名称由渲染层用扫描结果反查）
    blockedList: () => ipcRenderer.invoke('contextmenu:blocked-list')
  },

  // 统一弹窗通道（全部应用内弹窗经此 IPC 记录日志，DOM 由渲染层统一服务构建）
  modal: {
    open: (info) => ipcRenderer.invoke('modal:open', { ...info }),
    close: (info) => ipcRenderer.invoke('modal:close', { ...info })
  },

  // 诊断（只读）：环境兼容性提示
  diag: {
    // v2.8.0：第三方 DWM 注入类美化工具痕迹检测（主进程启动后一次性检测的结果）
    dwmConflict: () => ipcRenderer.invoke('diag:dwm-conflict')
  },

  // AI 简介设置
  settings: {
    load: () => ipcRenderer.invoke('settings:load'),
    save: (settings) => ipcRenderer.invoke('settings:save', { settings })
  },

  // 本地内置简介库（离线，随应用分发）
  intro: {
    load: () => ipcRenderer.invoke('intro:load')
  },

  // 大模型管理（独立窗口）：窗口开关；模型配置存取仍走下方 models IPC
  modelsWindow: {
    open: () => ipcRenderer.invoke('models:open-window'),
    close: () => ipcRenderer.invoke('models:close-window')
  },

  // 大模型管理（设置 → 大模型管理，应用内弹窗）：四个模型项各自独立配置
  models: {
    save: (key, config, scope) => ipcRenderer.invoke('models:save', { key, config, scope }),
    // 设置某个模块使用的模型（optimizer / startup / contextmenu 各自独立）
    setScope: (scope, key) => ipcRenderer.invoke('models:set-scope', { scope, key }),
    // 单独测试连通性（发送确认消息，不落盘）
    test: (key, config) => ipcRenderer.invoke('models:test', { key, config })
  },

  // 字体管理（设置 → 字体选择，应用内弹窗）
  fonts: {
    // 字体清单（5 款系统字体可用性 + 内嵌 MiSans + 已导入字体）与当前配置
    list: () => ipcRenderer.invoke('fonts:list'),
    // 导入 1 款外部字体（对话框 → 校验 → 复制副本 → 持久化）
    importFont: () => ipcRenderer.invoke('fonts:import'),
    // 删除已导入字体（移除记录 + 删除副本）
    removeImported: () => ipcRenderer.invoke('fonts:remove-imported'),
    // 保存字体配置（family / weight / size）
    saveConfig: (config) => ipcRenderer.invoke('fonts:save-config', { config })
  },

  // 外观设置：窗口材质切换 + 背景图片导入 / 删除 / 列表
  appearance: {
    getMaterial: () => ipcRenderer.invoke('appearance:get-material'),
    setMaterial: (material) => ipcRenderer.invoke('appearance:set-material', { material }),
    // 材质总开关（窗口界面升级3）：关闭 = 生效材质置 none，所选材质保留记忆
    setMaterialEnabled: (enabled) => ipcRenderer.invoke('appearance:set-material-enabled', { enabled }),
    // 材质变更广播（主进程会发给全部存活窗口，子窗口的 window-material.js 依赖）
    onMaterialChanged: (callback) => {
      const handler = (_, material) => callback(material);
      ipcRenderer.on('appearance:material-changed', handler);
      return () => ipcRenderer.removeListener('appearance:material-changed', handler);
    },
    // v2.8.0：环境状态（电池/系统透明开关）——主动查询 + 主进程推送（会话级降级用）
    getEnv: () => ipcRenderer.invoke('appearance:get-env'),
    onEnvState: (callback) => {
      const handler = (_, env) => callback(env);
      ipcRenderer.on('appearance:env-state', handler);
      return () => ipcRenderer.removeListener('appearance:env-state', handler);
    },
    importBg: () => ipcRenderer.invoke('appearance:bg-import'),
    deleteBg: (file) => ipcRenderer.invoke('appearance:bg-delete', { file }),
    listBg: () => ipcRenderer.invoke('appearance:bg-list'),
    openBgDir: () => ipcRenderer.invoke('appearance:bg-open-dir')
    // v3.7.0：专家模式（getExpert / setExpert）随「默认应用接管」一并退役，已移除
  },

  // AI 简介获取（按模块隔离：电脑优化中心 / 启动项管理 / 右键管理 各自使用所选模型）
  aidesc: {
    get: (name, company, force, scope) => ipcRenderer.invoke('aidesc:get', { name, company, force, scope })
  },

  // 网速测试
  netspeed: {
    ping: () => ipcRenderer.invoke('netspeed:ping'),
    throughput: (duration) => ipcRenderer.invoke('netspeed:throughput', { duration })
  },
  diskbench: {
    run: (options) => ipcRenderer.invoke('diskbench:run', options),
    // 测速进度事件（phase: seqwrite/seqread/randread/randwrite, percent: 0-100）
    onProgress: (cb) => {
      const handler = (e, d) => cb(d);
      ipcRenderer.on('diskbench:progress', handler);
      return () => ipcRenderer.removeListener('diskbench:progress', handler);
    }
  },

  // 实时网速监控
  realtime: {
    adapters: () => ipcRenderer.invoke('realtime:adapters'),
    sample: () => ipcRenderer.invoke('realtime:sample'),
    loss: () => ipcRenderer.invoke('realtime:loss'),
    // 网速记录报告（存 %APPDATA%\Trim\cache\realtime-reports\，7 天自动清理）
    reportSave: (data) => ipcRenderer.invoke('realtime:report-save', { data }),
    reportList: () => ipcRenderer.invoke('realtime:report-list'),
    reportDelete: (name) => ipcRenderer.invoke('realtime:report-delete', { name }),
    reportClear: () => ipcRenderer.invoke('realtime:report-clear')
  },

  // 磁盘测速历史记录
  benchHistory: {
    add: (record) => ipcRenderer.invoke('bench-history:add', { record }),
    list: () => ipcRenderer.invoke('bench-history:list'),
    delete: (id) => ipcRenderer.invoke('bench-history:delete', { id }),
    clear: () => ipcRenderer.invoke('bench-history:clear')
  },

  // 权限提升
  elevate: {
    status: () => ipcRenderer.invoke('elevate:status'),
    request: () => ipcRenderer.invoke('elevate:request'),
    // B5：提权后新实例未启动等异常情况的主进程通知
    onNotice: (callback) => {
      const handler = (_, data) => callback(data);
      ipcRenderer.on('elevate:notice', handler);
      return () => ipcRenderer.removeListener('elevate:notice', handler);
    }
  },

  // 关闭流程（L1，2026-09-19）：onRequest 已随主进程 shutdown 流程重构移除——
  // 主进程不再发送 app:shutdown、app.js 不再监听，此处同步删除暴露，消除死订阅面。
  shutdown: {
    begin: () => ipcRenderer.send('shutdown:begin'),
    complete: () => ipcRenderer.send('shutdown:complete')
  },

  // 安装路径绑定
  paths: {
    scan: () => ipcRenderer.invoke('paths:scan'),
    load: () => ipcRenderer.invoke('paths:load'),
    save: (key, value) => ipcRenderer.invoke('paths:save', { key, value }),
    browse: (title, defaultPath) => ipcRenderer.invoke('paths:browse', { title, defaultPath }),
    validate: (dirPath) => ipcRenderer.invoke('paths:validate', { path: dirPath }),
    // 提取安装目录主程序 exe 图标（dataURL），用于路径绑定弹窗分组标题头
    appIcon: (installPath, exeCandidates) => ipcRenderer.invoke('paths:app-icon', { installPath, exeCandidates }),
    // 按绝对路径提取图标（.ico/.exe/.dll），用于固定图标路径兜底（如抖音 app_icon.ico）
    fileIcon: (filePath) => ipcRenderer.invoke('paths:file-icon', { filePath })
  },

  // 文件清理（QQ/微信文件目录）
  fileclean: {
    scan: (type, customPath, total, doneBase) => ipcRenderer.invoke('fileclean:scan', { type, customPath, total, doneBase }),
    readImage: (filePath) => ipcRenderer.invoke('fileclean:read-image', { filePath }),
    execute: (files) => ipcRenderer.invoke('fileclean:execute', { files }),
    deleteFile: (filePath) => ipcRenderer.invoke('fileclean:delete-file', { filePath })
  },

  // 系统维护修复组（P2-16）：任务清单 + 单项执行 + 实时输出
  maintenance: {
    tasks: () => ipcRenderer.invoke('maintenance:tasks'),
    run: (taskId) => ipcRenderer.invoke('maintenance:run', { taskId }),
    onOutput: (callback) => {
      const handler = (_, data) => callback(data);
      ipcRenderer.on('maintenance:output', handler);
      return () => ipcRenderer.removeListener('maintenance:output', handler);
    }
  },

  // v3.7.0：「默认应用接管」整块退役（含 9 条 IPC 通道与专家模式），此处同步移除转发。

  // 网络检测（v3.0）：只读采集 + 白名单化一键修复（渲染层只传动作 id）
  netcheck: {
    collect: () => ipcRenderer.invoke('netcheck:collect'),
    repair: (actionId) => ipcRenderer.invoke('netcheck:repair', { actionId })
  },

  // 图片预览（磁盘清理 → 文件清理 → 预览图片，独立窗口）
  previewWindow: {
    open: (payload) => ipcRenderer.invoke('preview:open-window', payload),
    close: () => ipcRenderer.invoke('preview:close-window'),
    // 独立窗口侧接收主窗口传入的图片数据
    onData: (callback) => {
      const handler = (_, data) => callback(data);
      ipcRenderer.on('preview:data', handler);
      return () => ipcRenderer.removeListener('preview:data', handler);
    },
    // 预览窗口删除图片后通知主窗口刷新
    notifyDeleted: (filePath) => ipcRenderer.send('preview:image-deleted', filePath),
    // 主窗口侧监听：图片预览窗口删除图片后刷新文件列表
    onImageDeleted: (callback) => {
      const handler = (_, filePath) => callback(filePath);
      ipcRenderer.on('preview:image-deleted', handler);
      return () => ipcRenderer.removeListener('preview:image-deleted', handler);
    }
  },

  // 内存清理（Mem Reduct 思路：NtSetSystemInformation 清理内存区域 + 进程管理）
  memory: {
    info: () => ipcRenderer.invoke('memory:info'),
    clean: (items) => ipcRenderer.invoke('memory:clean', { items }),
    // 顽固软件治理（N1，2026-09-14）：第一层「立即结束进程」= stubbornKill（一次性），
    // 第二层「阻止开机自启」= stubbornBlock（改服务为手动 + 删 WPS 更新任务，持久且不自动还原）
    stubbornKill: () => ipcRenderer.invoke('memory:stubborn-kill'),
    stubbornBlock: () => ipcRenderer.invoke('memory:stubborn-block'),
    processes: () => ipcRenderer.invoke('memory:processes'),
    kill: (pid) => ipcRenderer.invoke('memory:kill', { pid })
  },

  // 应用进程管理（内存清理 → 独立窗口）
  processManager: {
    openWindow: () => ipcRenderer.invoke('processManager:open-window'),
    closeWindow: () => ipcRenderer.invoke('processManager:close-window'),
    // 独立窗口操作完成后向主窗口推送统计（进程总数），供内存清理页进程卡片回显
    report: (payload) => ipcRenderer.send('processManager:report', { ...payload }),
    // 主窗口侧监听：进程管理窗口结束进程后的最新统计
    onUpdate: (callback) => {
      const handler = (_, data) => callback(data);
      ipcRenderer.on('processManager:update', handler);
      return () => ipcRenderer.removeListener('processManager:update', handler);
    }
  },

  // 外设优化（电脑优化中心-外设调优 → 「更多调优项」独立窗口）
  peripheralWindow: {
    openWindow: () => ipcRenderer.invoke('peripheral:open-window'),
    closeWindow: () => ipcRenderer.invoke('peripheral:close-window'),
    query: () => ipcRenderer.invoke('peripheral:query'),
    apply: (options) => ipcRenderer.invoke('peripheral:apply', options),
    restoreBackup: () => ipcRenderer.invoke('peripheral:restore-backup')
  },

  // 快捷指令（侧边栏 → 63 条系统快捷入口；主进程按白名单执行，渲染层只传 id）
  quickCmds: {
    run: (id) => ipcRenderer.invoke('quickcmds:run', id)
  },

  // 优化电脑：执行选项 + 实时进度推送
  optimizer: {
    run: (optionId, params) => ipcRenderer.invoke('optimizer:run', { optionId, params }),
    list: () => ipcRenderer.invoke('optimizer:list'),
    genAdvice: (optionId) => ipcRenderer.invoke('optimizer:genadvice', { optionId }),
    checkRestore: () => ipcRenderer.invoke('optimizer:check-restore'),
    createRestore: () => ipcRenderer.invoke('optimizer:create-restore'),
    listRestore: () => ipcRenderer.invoke('optimizer:list-restore'),
    // 安全托底：批量检测注册表优化项是否已生效（只读检测，返回 {id: optimized} 映射）
    checkOptimized: (ids) => ipcRenderer.invoke('optimizer:check-optimized', { ids }),
    // 读取当前 SVCHost 拆分阈值并映射为档位（null=系统默认未优化）
    svcMemCurrent: () => ipcRenderer.invoke('optimizer:svc-mem-current'),
    // 执行前备份目标注册表键值当前状态（按 optionId 存档）
    backupReg: (optionId, steps) => ipcRenderer.invoke('optimizer:backup-reg', { optionId, steps }),
    // 按备份还原注册表键值（无备份返回 missing:true）
    restoreReg: (optionId) => ipcRenderer.invoke('optimizer:restore-reg', { optionId }),
    // v2.6.0（P0-1）：已应用状态总览（启动扫描核对 + stale 清单 + 退役迁移结果）
    stateOverview: () => ipcRenderer.invoke('optimizer:state-overview'),
    onProgress: (callback) => {
      const handler = (_, data) => callback(data);
      ipcRenderer.on('optimizer:progress', handler);
      return () => ipcRenderer.removeListener('optimizer:progress', handler);
    }
  },

  // 系统信息（C2，2026-09-14 重复点审查）：系统盘介质类型（SSD/HDD），
  // 供优化中心与磁盘清理按硬件显隐预读相关选项（unknown 时两边都不隐藏）
  system: {
    diskType: (opts = {}) => ipcRenderer.invoke('system:disk-type', opts)
  },

  // 启动项管理：扫描 / 启停 / 删除 / 打开所在位置 / 添加
  startup: {
    scan: (refresh = false) => ipcRenderer.invoke('startup:scan', { refresh }),
    toggle: (items, enable) => ipcRenderer.invoke('startup:toggle', { items, enable }),
    remove: (items) => ipcRenderer.invoke('startup:delete', { items }),
    openLocation: (targetPath) => ipcRenderer.invoke('startup:openlocation', { path: targetPath }),
    add: () => ipcRenderer.invoke('startup:add', {})
  }
});

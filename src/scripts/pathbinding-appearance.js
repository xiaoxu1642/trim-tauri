// pathbinding-appearance.js - 设置页外观偏好的真源层（路径绑定模块拆分后的共享半边）
//
// 为什么整族住在一个文件：`APPEARANCE_KEY` / `APPEARANCE_PREF_KEYS` / 镜像读写 /
// 增量推真源 / 后端回读 / 雾化度换算与迁移是「localStorage 镜像 ⇄ appearance.json 真源」
// 的唯一口径，`tools/check-appearance-prefs.mjs` 按**单文件**抽这族符号做跨语言对拍。
// 拆到别的文件后仍必须整族留在这里，否则「这族符号住哪儿」这条契约本身失去机检对象。
//
// 加载顺序：本文件最先（背景图 / 壁纸轮换各面只读这里的出口），
// `pathbinding.js` 入口最后（它负责把各面装配起来）。各面对镜像的读写一律走
// `window.pathbindingAppearance`，不许自行碰 localStorage —— 否则损坏降级与键名
// 变更就会各处各判。
(function () {
  'use strict';

  // 模块共用的日志出口：各面都要写运行日志，「window.app.log 在不在」只留这一份判定。
  function writeLog(level, message) {
    if (window.app?.log) window.app.log(level, message);
  }

  const APPEARANCE_KEY = 'trim-appearance';

  // F4a2-M01：外观域真源已迁到 `appearance.json`（与材质同文件、同一条读-改-写原语）。
  // 老键 `trim-appearance` 降级为**镜像 + 兜底初值**，迁移完成前不得删除——存量用户的这套
  // 状态目前只存在那儿。口径与 F4a1-M08 一致：读时后端优先、后端未设置时用老键现值迁移上去；
  // 写时两边都写。启动期读这份镜像的第二消费点（`theme.js` 的 applySkinAndPreset）因此
  // 每次写都必须同步更新镜像。
  // 2026-10-22 用户裁定删除「用户自定义强调色」：颜色一律以 main.css 的 `--accent` 为准。
  // 存量镜像与 appearance.json 里的历史 `accent` 键不进这张表 ⇒ 回读不采纳、写入不迁移，
  // 也不会被推回后端（未知键对 localStorage 对象与 serde_json::Value 都是天然容忍）。
  const APPEARANCE_PREF_KEYS = [
    { key: 'bgPath' },
    { key: 'bgOpacity' },
    { key: 'bgOpacityFog' },
    { key: 'bgPosX' },
    { key: 'bgPosY' },
    { key: 'bgBlur' },
    { key: 'presetBg' },
    // 镜像存 '1' / ''（复选框时代的字符串哨兵），真源存布尔：换算只许有这一处定义，
    // 前后端各转一次就是 AGENTS §5.16 判禁止的「同一判定两份实现」。
    { key: 'wallpaperRotate', toBackend: (v) => v === '1', fromBackend: (v) => (v ? '1' : '') },
    // 镜像存 <select> 的字符串秒数，真源存整数秒
    { key: 'wallpaperInterval', toBackend: (v) => Number(v), fromBackend: (v) => String(v) },
    { key: 'wallpaperBlur' },
  ];

  // 真源侧的回读快照：null = 尚未回读；对象 = 已回读（值 null = 后端未设置该键）。
  // 增量推账就记在这份快照上，写失败的键不落账 ⇒ 下一次写会自然重试。
  let apBackendState = null;
  let apPushTimer = null;

  function loadAppearance() {
    try {
      const v = JSON.parse(localStorage.getItem(APPEARANCE_KEY) || '{}');
      return v && typeof v === 'object' ? v : {};
    } catch (e) { return {}; }
  }
  function saveAppearance(v) {
    try { localStorage.setItem(APPEARANCE_KEY, JSON.stringify(v)); } catch (e) {}
    queueAppearancePush(v);
  }

  // 写两边的真源半边：整份镜像同步落 localStorage（原有语义，重启首帧仍靠它），真源按键**增量**推。
  // 增量而不是整表：滑块拖动一次会打上百次 saveAppearance，整表推 = 上百次读-改-写盘。
  // 150ms 合并窗口内恰好退出的丢失风险由下一次进页的回读兜住——后端缺该键时镜像现值会被推上去。
  function queueAppearancePush(snapshot) {
    // 真源尚未回读（apBackendState 为 null）时一律不推：本文件求值期就有两处一次性迁移
    // （skin→模糊、bgOpacity→雾化）会写镜像，若此刻整表推上去，「后端优先」会被反转成
    // 「镜像反压后端」——存量用户后端里更新过的值被老镜像盖掉。
    // 回读失败/降级同样不推：行为退回迁移前（只用镜像），而不是猜后端。
    if (!apBackendState) return;
    if (!window.api?.appearance?.setPref) return; // 桥未就位：只写镜像（与迁移前同形）
    const v = snapshot ? { ...snapshot } : {};
    clearTimeout(apPushTimer);
    apPushTimer = setTimeout(() => { pushAppearanceDiff(v); }, 150);
  }

  async function pushAppearanceDiff(snapshot) {
    for (const spec of APPEARANCE_PREF_KEYS) {
      const mirror = snapshot[spec.key];
      if (mirror == null) {
        if ((apBackendState || {})[spec.key] == null) continue;
        await setAppearancePref(spec.key, null); // 镜像里已删除 ⇒ 真源同步清除
        continue;
      }
      const want = spec.toBackend ? spec.toBackend(mirror) : mirror;
      if (want == null || (typeof want === 'number' && !Number.isFinite(want))) {
        // 换算不出可信值（老键里的坏数据）：按清除处理，免得真源留着比镜像更旧的值反压界面
        if ((apBackendState || {})[spec.key] == null) continue;
        await setAppearancePref(spec.key, null);
        continue;
      }
      if ((apBackendState || {})[spec.key] === want) continue;
      await setAppearancePref(spec.key, want);
    }
  }

  async function setAppearancePref(key, value) {
    try {
      const resp = await window.api.appearance.setPref(key, value);
      if (!resp || resp.success !== true) {
        // 形状闸拒绝时后端根本没写盘（拒在落盘前），这里只留痕：真源快照不记账，下次写重试
        writeLog('warn', `外观偏好 ${key} 未写入真源：${(resp && resp.message) || '回执异常'}`);
        return false;
      }
      if (apBackendState) apBackendState[key] = value;
      return true;
    } catch (e) {
      writeLog('warn', `外观偏好 ${key} 未写入真源：${(e && e.message) || e}`);
      return false;
    }
  }

  // 一次性回读（进设置页执行一次）：后端优先合并进镜像，后端缺失的按键迁移上去。
  // 返回合并后的整份外观值；回读失败/降级返回 null（调用方继续用镜像，行为等同迁移前）。
  async function syncAppearanceFromBackend() {
    if (!window.api?.appearance?.getPrefs) return null;
    let resp = null;
    try {
      resp = await window.api.appearance.getPrefs();
    } catch (e) {
      writeLog('warn', '外观偏好回读失败：' + ((e && e.message) || e));
      return null;
    }
    if (!resp || resp.success !== true) {
      writeLog('warn', '外观偏好回读失败：' + ((resp && resp.message) || '回执异常'));
      return null;
    }
    if (resp.degraded === true) {
      // appearance.json 读失败 ≠ 「全部未设置」：既不采纳也不迁移，继续按镜像展示。
      // 若此时去推镜像值，等于把用户数据反复推给一个写不进去的文件（写侧本身 fail-closed）。
      writeLog('warn', '外观配置读取降级，本轮按本地镜像展示');
      return null;
    }
    const data = resp.data || {};
    apBackendState = { ...data };
    const ap = loadAppearance();
    let changed = false;
    const migrate = [];
    for (const spec of APPEARANCE_PREF_KEYS) {
      const b = data[spec.key];
      if (b != null) {
        const mirrorVal = spec.fromBackend ? spec.fromBackend(b) : b;
        if (ap[spec.key] !== mirrorVal) { ap[spec.key] = mirrorVal; changed = true; }
        continue;
      }
      const m = ap[spec.key];
      if (m == null) continue;
      const want = spec.toBackend ? spec.toBackend(m) : m;
      if (want == null || (typeof want === 'number' && !Number.isFinite(want))) continue;
      migrate.push([spec.key, want]);
    }
    if (changed) {
      // 只落镜像，不走 saveAppearance：那会再排一次增量推，与下面的迁移重复
      try { localStorage.setItem(APPEARANCE_KEY, JSON.stringify(ap)); } catch (e) {}
      applyAll(ap);
    }
    for (const [key, want] of migrate) await setAppearancePref(key, want);
    return ap;
  }

  // 批次：雾化度语义反转 —— 旧值存的是「图片不透明度」（100=纯图），新值为「雾化强度」
  // （0=纯图，100=全雾），所以是取反。
  // R6b-L07（AGENTS §5.16：同一判定不许两侧各写一份）：这条换算在 Rust 侧
  // `src-tauri/src/engine/appearance.rs` 的 bg_opacity_to_fog 有同一判定的另一份实现，
  // 跨语言只能共享判据不能共享函数，两侧口径（取反基数 + 是否取整）由跨语言对拍门禁钉住。
  // 不同步改两侧的症状是两次迁移叠加后落盘值分叉（旧值 33.4 → 一侧取整成 67、一侧留 66.6），
  // 而小数百分比进 CSS 的 calc 与 --bg-blur 时观感也会不一致。
  // 取整口径要跟上 Rust 的 f64::round()「半值远离 0」：旧值越界（>100）时 100-v 为负，
  // 直接用 Math.round 会朝 +∞ 取半，两边又分叉一次。
  function bgOpacityToFog(opacity) {
    const d = 100 - opacity;
    return d < 0 ? -Math.round(-d) : Math.round(d);
  }

  // 一次性迁移（幂等，打 bgOpacityFog 标记防重复）。
  // 只换算有限数值：非数值不动，与 Rust 侧 as_f64 取不到即跳过同口径——旧实现走 JS 强转，
  // 字符串会算出 NaN 再经 JSON 序列化成 null，把坏值洗成另一种坏值（Rust 侧压根不写盘）。
  // 标记仍要照打：滑块写回的是雾化语义值且不碰标记，本函数是渲染层唯一的防重复入口，
  // 「旧值缺失也打标记」少了它会让下一次加载把新值再取反一遍。
  function migrateBgOpacityToFog(ap) {
    if (ap.bgOpacityFog === true) return ap;
    if (Number.isFinite(ap.bgOpacity)) ap.bgOpacity = bgOpacityToFog(ap.bgOpacity);
    ap.bgOpacityFog = true;
    saveAppearance(ap);
    return ap;
  }

  // 「真源值 → 界面」的唯一重放出口：首帧展示与后端回读后重放共用这一份实现
  // （AGENTS §5.16：同一判据不许两处各写一份）。各面只登记自己的应用函数，
  // 不各写一段「读镜像再刷界面」的重复实现。
  const applyHooks = [];
  function registerApply(fn) {
    if (typeof fn === 'function') applyHooks.push(fn);
  }
  function applyAll(resolved) {
    const cur = resolved || loadAppearance();
    for (const fn of applyHooks) fn(cur);
  }

  window.pathbindingAppearance = {
    load: loadAppearance,
    save: saveAppearance,
    log: writeLog,
    migrateBgOpacityToFog,
    registerApply,
    applyAll,
    syncFromBackend: syncAppearanceFromBackend,
  };
})();

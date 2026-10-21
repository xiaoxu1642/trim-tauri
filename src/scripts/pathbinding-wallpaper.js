// pathbinding-wallpaper.js - 设置页「壁纸轮换」面
//
// 职责：内置实拍壁纸（wp-*）按间隔自动轮换，窗口隐藏（最小化/切走）时暂停、回来继续。
// 渐变与「无背景」不参与轮换（计时器空转但不动画面）。
//
// 依赖：镜像读写与重放登记在 `pathbinding-appearance.js`；换图动作复用背景图面的
// `crossfadeBg` / `applyPresetBg`（淡入淡出与预设白名单只许有一份实现），
// 本文件不自己写 CSS 变量、也不自己判预设是否在售。
(function () {
  'use strict';

  function init() {
    // ==================== 内置实拍壁纸轮换（v2.8.0） ====================
    // 仅 wp-* 实拍壁纸预设参与轮换（渐变/无背景时计时器空转）；默认 10s，可调/可关；
    // 窗口隐藏时自动暂停（visibilitychange），省电不打扰。状态存 trim-appearance。
    // v3.2.0：预设壁纸下架「山峰 wp-mountain」（连同极光/落日渐变），WP_LIST 仅保留在售实拍壁纸
    const WP_LIST = ['wp-winter', 'wp-gaming', 'wp-anime', 'wp-doll'];
    const wpRotateToggle = document.getElementById('wallpaperRotateToggle');
    const wpIntervalSelect = document.getElementById('wallpaperIntervalSelect');
    // 预设背景选择器：轮换换图后同步回写它的选中项（元素的事件由背景图面绑定）
    const presetBgSelect = document.getElementById('presetBgSelect');
    let wpTimer = null;
    function wpRotateOn() { return !!(wpRotateToggle && wpRotateToggle.checked); }
    function wpIntervalMs() {
      const v = parseInt(wpIntervalSelect && wpIntervalSelect.value, 10);
      return Number.isFinite(v) && v >= 5 ? v * 1000 : 10000;
    }
    function wpStop() { if (wpTimer) { clearInterval(wpTimer); wpTimer = null; } }
    function wpCurrent() {
      const cur = window.pathbindingAppearance.load().presetBg || '';
      return WP_LIST.indexOf(cur);
    }
    function wpTick() {
      const idx = wpCurrent();
      if (idx === -1) return; // 当前不是实拍壁纸（用户切到渐变/无背景），保持不动
      const next = WP_LIST[(idx + 1) % WP_LIST.length];
      const ap2 = window.pathbindingAppearance.load();
      ap2.presetBg = next;
      window.pathbindingAppearance.save(ap2);
      window.pathbindingBackground.crossfadeBg('--preset-bg-fade', () => window.pathbindingBackground.applyPresetBg(next));
      if (presetBgSelect) presetBgSelect.value = next; // 选择器同步跟随，所见即所得
    }
    function wpSync() {
      wpStop();
      if (!wpRotateOn()) return;
      // 开启轮换但当前不是实拍壁纸：先落到第一张，立即进入轮换节奏
      if (wpCurrent() === -1) {
        const ap2 = window.pathbindingAppearance.load();
        ap2.presetBg = WP_LIST[0];
        window.pathbindingAppearance.save(ap2);
        window.pathbindingBackground.crossfadeBg('--preset-bg-fade', () => window.pathbindingBackground.applyPresetBg(WP_LIST[0]));
        if (presetBgSelect) presetBgSelect.value = WP_LIST[0];
      }
      wpTimer = setInterval(wpTick, wpIntervalMs());
    }
    if (wpRotateToggle) {
      wpRotateToggle.addEventListener('change', () => {
        const ap2 = window.pathbindingAppearance.load();
        ap2.wallpaperRotate = wpRotateToggle.checked ? '1' : '';
        window.pathbindingAppearance.save(ap2);
        wpSync();
      });
    }
    if (wpIntervalSelect) {
      wpIntervalSelect.addEventListener('change', () => {
        const ap2 = window.pathbindingAppearance.load();
        ap2.wallpaperInterval = wpIntervalSelect.value;
        window.pathbindingAppearance.save(ap2);
        wpSync(); // 间隔变化立即按新周期重启计时器
      });
    }
    // 窗口隐藏（最小化/切走）暂停轮换，回来继续——省电且不空转
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) wpStop();
      else wpSync();
    });

    window.pathbindingAppearance.registerApply(function (cur) {
      const rotate = document.getElementById('wallpaperRotateToggle');
      if (rotate) rotate.checked = cur.wallpaperRotate === '1';
      const interval = document.getElementById('wallpaperIntervalSelect');
      if (interval) interval.value = cur.wallpaperInterval || '10';
      wpSync();
    });
  }

  window.pathbindingWallpaper = { init };
})();

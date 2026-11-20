// theme-boot.js - html 级主题引导（提案 V1：浅色缺省，外观镜像 theme 键可切深色）
// 同步执行、不挂 defer（F2 唯一豁免位）：main.css 浅色值在 .theme-light、深色值在 :root
// （v2.0 碳墨暗档，2026-11-21 用户裁定恢复可达），html 挂哪个类就定哪套 token，body 由
// theme.js / window-material.js 幂等补挂。镜像键 trim-appearance.theme 由外观族持久化；
// boot 先于外观族加载，直读 localStorage 是首帧时序例外（运行时写一律走外观族出口）。
// 缺省恒浅色（键缺失 / 非 'dark' 都按浅色，保留 v2.1 防回暗语义）；吞异常=静默不防闪（火眼眼 2026-09-14）。
(function () {
  try {
    var dark = false;
    try {
      dark = (JSON.parse(localStorage.getItem('trim-appearance') || '{}') || {}).theme === 'dark';
    } catch (_) {}
    document.documentElement.classList.add(dark ? 'theme-dark' : 'theme-light');
  } catch (_) {}
})();

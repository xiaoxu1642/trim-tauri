// theme-boot.js - 首帧前应用浅色主题（v2.1：应用恒浅色，不再读取保存主题或系统主题）
// 原内联写法被 CSP（script-src 'self'）静默拦截；改外部文件后必须同步执行、不挂 defer（在
// index.html 的 body 内，是首屏门禁 F2 的唯一豁免位）——defer 晚于首个可见帧就会闪色。类挂
// documentElement 而非 body：html 级覆盖 `:root` 暗值不依赖 <body> 是否已开始解析，main.css
// 的 .theme-light 是裸类选择器、级联对 html 同样生效；theme.js / window-material.js 再给 body
// 补挂同一类（幂等）。历史坑（火眼眼 2026-09-14 MED）：写 body.className 后被 try/catch 吞异常 ⇒ 静默不防闪。
(function () {
  try {
    document.documentElement.classList.add('theme-light');
  } catch (_) {}
})();

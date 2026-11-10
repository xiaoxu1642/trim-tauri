// theme-boot.js - html 级浅色主题引导（v2.1：应用恒浅色，不再读取保存主题或系统主题）
// 今天四窗的 body 都已静态挂 theme-light，本脚本不再影响首帧；它保留下来只为两件事：
// ① html 级级联（:root 暗值在 html 上的覆盖）；
// ② 防未来有人删掉 body 的静态类时静默回到暗色。
// 所以它仍需同步执行、不挂 defer（在 index.html 的 body 内，是首屏门禁 F2 的唯一豁免位）。
// 类挂 documentElement 而非 body：html 级覆盖 `:root` 暗值不依赖 <body> 是否已开始解析，main.css
// 的 .theme-light 是裸类选择器、级联对 html 同样生效；theme.js / window-material.js 再给 body
// 补挂同一类（幂等）。历史坑（火眼眼 2026-09-14 MED）：写 body.className 后被 try/catch 吞异常 ⇒ 静默不防闪。
(function () {
  try {
    document.documentElement.classList.add('theme-light');
  } catch (_) {}
})();

// theme-boot.js - 首帧前应用浅色主题（v2.1：应用恒浅色，不再读取保存主题或系统主题）
// 原 内联写法被 CSP（script-src 'self'）拦截，主题引导从未生效；
// 改为外部文件后在解析时同步执行，在首个可见帧前挂好 theme-light，避免启动闪色。
// 火眼眼审查 2026-09-14（MED）：本脚本由 index.html 在 <head> 加载，执行时 document.body
// 尚不存在，原写 body.className 会被 try/catch 吞掉导致防闪完全失效——改挂
// documentElement（main.css 的 .theme-light 为裸类选择器，变量级联对 html 同样生效；
// 后续 window-material.js 再给 body 补挂同一类，互不冲突）。
(function () {
  try {
    document.documentElement.classList.add('theme-light');
  } catch (_) {}
})();

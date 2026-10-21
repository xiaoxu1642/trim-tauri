// pathbinding-accent.js - 设置页「强调色」面
//
// 职责：把用户选的强调色写进 CSS 变量组（按钮 / 高亮 / 选中态即时生效），并按 WCAG
// 相对亮度自动选定实底上的可读前景色。默认值只有一个真源：`main.css` 的 `--accent`
// （恢复默认时从计算样式现读，本文件不硬编码色值）。
//
// 依赖：外观偏好的镜像读写与重放入口在 `pathbinding-appearance.js`；本文件不碰
// localStorage，也不定义第二份重放逻辑——只往外观层登记一个应用函数。
(function () {
  'use strict';

  // 应用强调色：写入 CSS 变量（按钮 / 高亮 / 选中态即时生效）
  function applyAccent(color) {
    const root = document.documentElement;
    if (color) {
      // 前景文字色按 WCAG 相对亮度自动选定；交互态与 soft/glow 同步派生，
      // 避免自定义色只影响按钮底色，其他高亮仍停留在默认薰衣草色。
      root.style.setProperty('--accent', color);
      root.style.setProperty('--accent-hover', `color-mix(in srgb, ${color} 82%, white)`);
      root.style.setProperty('--accent-press', `color-mix(in srgb, ${color} 82%, black)`);
      root.style.setProperty('--accent-light', `color-mix(in srgb, ${color} 16%, transparent)`);
      root.style.setProperty('--accent-soft', `color-mix(in srgb, ${color} 16%, transparent)`);
      root.style.setProperty('--accent-glow', `color-mix(in srgb, ${color} 32%, transparent)`);
      root.style.setProperty('--border-accent', color);
      root.style.setProperty('--accent-text', readableAccentText(color));
    } else {
      for (const name of ['--accent', '--accent-hover', '--accent-press', '--accent-light', '--accent-soft', '--accent-glow', '--border-accent', '--accent-text']) {
        root.style.removeProperty(name);
      }
    }
  }

  // 按相对亮度（WCAG L 公式）判定 accent 实底上的可读前景色
  function readableAccentText(hex) {
    const m = /^#?([0-9a-f]{6})$/i.exec(String(hex || '').trim());
    if (!m) return '#FFFFFF';
    const n = parseInt(m[1], 16);
    const ch = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map(v => {
      const s = v / 255;
      return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
    });
    const lum = 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2];
    // 与白/黑文字对比度取更优者（阈值 0.35 介于白 5:1 与黑 5:1 的交点附近）
    return lum > 0.35 ? '#23244E' : '#FFFFFF';
  }

  function init() {
    // 强调色（初始值与真源回读后的重放统一走外观层的重放入口）
    const accentInput = document.getElementById('accentColor');
    const accentReset = document.getElementById('btnAccentReset');
    accentInput?.addEventListener('input', () => {
      applyAccent(accentInput.value);
      const ap2 = window.pathbindingAppearance.load();
      ap2.accent = accentInput.value;
      window.pathbindingAppearance.save(ap2);
    });
    accentReset?.addEventListener('click', () => {
      applyAccent(null);
      const ap2 = window.pathbindingAppearance.load();
      delete ap2.accent;
      window.pathbindingAppearance.save(ap2);
      // 审查 v3-L4：原先硬编码 `#6A59C9`，与 main.css 的 `--accent` 默认值构成双源
      // （改 CSS 默认值不跟着变，且无门禁能抓）。改为**从 CSS 变量现读**，
      // 让 main.css 成为默认强调色的唯一真源。取不到时退回空串（不臆造色值）。
      if (accentInput) {
        accentInput.value = (getComputedStyle(document.documentElement)
          .getPropertyValue('--accent') || '').trim();
      }
      window.app?.toast('success', '已恢复默认强调色');
    });

    window.pathbindingAppearance.registerApply(function (cur) {
      // 强调色：空值 = 用户没自定义，交回 main.css 的 --accent 默认值（此处不硬编码色值）
      const aInput = document.getElementById('accentColor');
      if (cur.accent) {
        if (aInput) aInput.value = cur.accent;
        applyAccent(cur.accent);
      } else {
        applyAccent(null);
      }
    });
  }

  window.pathbindingAccent = { init };
})();

// pathbinding-background.js - 设置页「背景图」面
//
// 职责：导入 / 删除 / 选中已导入图片，把背景铺到 body 底层（--app-bg-image 系列变量），
// 视角与雾化度、预设背景（渐变 / 实拍壁纸）以及壁纸层模糊滑块。
//
// 依赖：镜像读写与重放登记在 `pathbinding-appearance.js`；壁纸轮换面复用本文件的
// `applyPresetBg` 与 `crossfadeBg`（淡入淡出语义只许有一份实现）。
// 列表加载失败的两句文案由 `pathbinding.js` 的失败出口提供：Rust 侧源码形状断言
// 按那个文件的字节判「读取失败不得与没有数据同形」，文案不能搬离入口文件。
(function () {
  'use strict';

  function escapeHtml(text) { return window.ds.esc(text); }

  // 折叠头的键盘等价路径：div 头带 cursor:pointer 且只挂 click ⇒ 键盘既聚焦不了也按不动。
  // 与 `pathbinding.js` / `cleanup.js` 各留一份：三处都是按需页，而 ds.js 在首屏 12 脚本内、
  // 首屏预算 2026-10-22 已裁定不再上调（现算余量 48 B），不值得为它挤首屏字节；
  // 接线是否还在由 check-a11y 的「折叠头键盘接线」判据钉住。
  function bindCollapseKeys(el) {
    if (!el || el.matches('button,a,input') || el.hasAttribute('tabindex')) return;
    el.setAttribute('tabindex', '0');
    if (!el.getAttribute('role')) el.setAttribute('role', 'button');
    el.addEventListener('keydown', (e) => {
      if ((e.key === 'Enter' || e.key === ' ') && e.target === el) {
        e.preventDefault();
        el.click();
      }
    });
  }

  // 背景图/缩略图的 URL 构造：Tauri 下必须走 asset 协议（页源 http://tauri.localhost
  // 跨不到 file:），Electron 下 window.api.pathToUrl 不存在、退回原来的 file:/// 手拼。
  function toImgUrl(file) {
    if (!file) return '';
    if (window.api && typeof window.api.pathToUrl === 'function') return window.api.pathToUrl(file);
    return 'file:///' + String(file).replace(/\\/g, '/').replace(/^\//, '');
  }

  // 应用背景图片：body::before 水印式铺底（置于内容之上、弹窗之下）。
  // 批次：雾化度语义反转 —— 入参 opacity 现为「雾化度」（0=零效果纯展示图片，100=雾化效果100%），
  // 图片不透明度 = (100 - 雾化度)/100；旧语义（值=图片不透明度）已在读取侧一次性迁移。
  // 批次：背景视角可调 —— posX/posY 为 0-100 的裁切窗口位置百分比（cover 下只对图片超出
  // 窗口的那根轴生效），不传回落 50/50（居中，与旧行为一致）。
  function applyBackground(file, opacity, posX, posY) {
    const root = document.documentElement;
    if (file) {
      const url = toImgUrl(file);
      root.style.setProperty('--app-bg-image', `url("${url}")`);
      const fog = opacity == null ? 85 : opacity;
      root.style.setProperty('--app-bg-opacity', String((100 - fog) / 100));
      const px = clampPercent(posX, 50);
      const py = clampPercent(posY, 50);
      root.style.setProperty('--app-bg-position', `${px}% ${py}%`);
      document.body.classList.add('bg-image-on');
    } else {
      root.style.removeProperty('--app-bg-image');
      root.style.removeProperty('--app-bg-opacity');
      root.style.removeProperty('--app-bg-position');
      document.body.classList.remove('bg-image-on');
    }
  }

  // 百分比参数钳位：非数值/越界一律收敛到 0-100，异常时取 fallback
  function clampPercent(v, fallback) {
    const n = Number(v);
    if (!Number.isFinite(n)) return fallback;
    return Math.max(0, Math.min(100, Math.round(n)));
  }

  // 批次（v3.0）：背景图切换淡入淡出 —— 先把对应背景层透明度淡到 0，换图后再淡回。
  // fadeVar：预设层 --preset-bg-fade / 导入层 --app-bg-fade（main.css 乘进 opacity）。
  // reduce-motion 直接应用（无动画红线）；淡出仍在途时立即换图并淡入，避免连续切换排队卡顿。
  const BG_FADE_MS = 340; // 与 --duration-slow(320ms) 同步，留少量余量
  function crossfadeBg(fadeVar, applyFn) {
    const root = document.documentElement;
    let reduced = false;
    try { reduced = !!(window.ds && window.ds.reducedMotion && window.ds.reducedMotion()); } catch (e) {}
    if (reduced) { applyFn(); return; }
    if (root.style.getPropertyValue(fadeVar) === '0') {
      applyFn();
      root.style.setProperty(fadeVar, '1');
      return;
    }
    root.style.setProperty(fadeVar, '0');
    setTimeout(() => {
      applyFn();
      void document.body.offsetWidth; // 强制样式重算：新图先以零透明度渲染，再开始淡入
      root.style.setProperty(fadeVar, '1');
    }, BG_FADE_MS);
  }

  // ---- UI 设计系统：背景模糊度 + 预设背景（设置页整合4） ----
  // 原「皮肤：经典/液态玻璃」二选一下拉与背景磨砂合并为 0-100% 无级「背景模糊度」滑块：
  // >0% = 液态玻璃面板，模糊半径按百分比线性缩放
  // （100% = 26px，与原液态玻璃一致；theme.js 启动期应用共用同一常量约定，改动需两处同步）。
  // v3.0 全局玻璃化：0% 仅表示「无磨砂」（移除 data-skin），容器表面仍为玻璃 alpha——
  // 表面 token 真源（main.css --surface-tint + 统一 alpha 表）本身就是玻璃值，无实心态。
  // 审查 5-5：上限常量收敛到 window.ds（theme.js 同源读取），ds 未加载时退回同值兜底
  const GLASS_MAX_BLUR_PX = window.ds?.GLASS_MAX_BLUR_PX || 26;
  function applyBgBlur(pct) {
    const v = Math.max(0, Math.min(100, Math.round(Number(pct) || 0)));
    if (v > 0) {
      document.body.dataset.skin = 'glass';
      document.documentElement.style.setProperty('--glass-blur', ((v / 100) * GLASS_MAX_BLUR_PX).toFixed(1) + 'px');
    } else {
      delete document.body.dataset.skin;
      document.documentElement.style.removeProperty('--glass-blur');
    }
  }
  // 旧值迁移：仅存有 skin 键的历史配置按 glass=100% / classic=0% 折算为 bgBlur
  function migrateSkinToBlur(stored) {
    if (stored.bgBlur == null) {
      stored.bgBlur = stored.skin === 'glass' ? 100 : 0;
      delete stored.skin;
      window.pathbindingAppearance.save(stored);
    }
    return stored;
  }
  // applyPresetBg：body[data-preset-bg="graphite|wp-*"] 设置底层渐变/实拍墙纸
  // v3.2.0：白名单校验——已下架预设（aurora/sunset/wp-mountain）残留旧值时静默回落「无」，
  // 避免 body 挂着无 CSS 定义的 data-preset-bg 造成空白覆盖层
  const PRESET_BG_VALID = ['graphite', 'wp-winter', 'wp-gaming', 'wp-anime', 'wp-doll'];
  function applyPresetBg(preset) {
    const v = PRESET_BG_VALID.includes(preset) ? preset : '';
    if (v) document.body.dataset.presetBg = v;
    else delete document.body.dataset.presetBg;
  }

  function renderBgList(ap) {
    const listEl = document.getElementById('bgList');
    const bodyEl = document.getElementById('bgListBody');
    const currentRow = document.getElementById('bgCurrentRow');
    const thumb = document.getElementById('bgThumb');
    if (!listEl || !bodyEl) return;
    window.api?.appearance?.listBg?.().then(resp => {
      // A1-L02：success:false 不能与「没导入过图片」同形（否则整块 display:none）。
      if (!resp || resp.success === false) {
        window.pathbinding.bgListReadFailed(listEl, bodyEl);
        return;
      }
      const files = resp.data || [];
      const head = listEl.querySelector('.bg-list-head');
      if (head) head.firstChild && (head.firstChild.textContent = `已导入的图片（${files.length}）`);
      if (!files.length) {
        listEl.style.display = 'none';
        bodyEl.innerHTML = '';
        return;
      }
      listEl.style.display = 'block';
      bodyEl.innerHTML = files.map(f => `
        <div class="bg-list-item${ap.bgPath === f.path ? ' active' : ''}" data-file="${escapeHtml(f.path)}" data-tip="点击设为背景">
          <span class="bg-list-name">${escapeHtml(f.name)}</span>
          <button class="bg-list-del" data-file="${escapeHtml(f.path)}" data-tip="删除此图片">✕</button>
        </div>
      `).join('');
      bodyEl.querySelectorAll('.bg-list-item').forEach(el => {
        el.addEventListener('click', (e) => {
          if (e.target.closest('.bg-list-del')) return;
          const file = el.dataset.file;
          const ap2 = window.pathbindingAppearance.load();
          ap2.bgPath = file;
          window.pathbindingAppearance.save(ap2);
          crossfadeBg('--app-bg-fade', () => applyBackground(file, ap2.bgOpacity, ap2.bgPosX, ap2.bgPosY));
          refreshBgCurrent(ap2);
          renderBgList(ap2);
        });
      });
      bodyEl.querySelectorAll('.bg-list-del').forEach(btn => {
        btn.addEventListener('click', async (e) => {
          e.stopPropagation();
          // P1-7（F4c-M01）：外层那条 `.then(...).catch(...)` 链**管不到这里** —— 事件
          // handler 是被浏览器另行调用的独立 Promise，它的 reject 不会回流到渲染链的 catch。
          // 确认件与 deleteBg 两个 await 必须有自己的出口，否则「点删除没反应」无从归因。
          try {
            const file = btn.dataset.file;
            // 审查 M11：本文件此前是「唯一没走红色二次确认的删除出口」（AGENTS §2：删除类
            // 操作必须红色确认；设置页其它删除入口与 app.js 的约定都遵守了）。
            // 后端校验虽是全仓最严（直接子项 + 扩展名白名单 + 拒符号链接 + protect），
            // 但误触即删掉用户自备素材这件事本身不该靠后端兜。
            const name = String(file).split('\\').pop();
            // P1-7：`window.app?.confirmDanger?.(...)` 在确认件缺失时返回 undefined，
            // 旧写法会把它当成「用户点了取消」静默 return —— 删除动作没发生，但用户看到的
            // 仍是「点了没反应」。判据要分清「方法不存在」与「用户拒绝」，前者必须报出来。
            if (typeof window.app?.confirmDanger !== 'function') {
              window.app?.toast?.('error', '确认组件不可用，已取消删除（未做任何改动）');
              return;
            }
            const ok = await window.app.confirmDanger(
              '删除背景图片',
              `将删除「${name}」（移入回收站，可在回收站还原）。`,
              '删除',
              '取消',
              '导入的图片被删除后，若它正被用作应用内渐变之外的自定义背景，背景会随即失效。'
            );
            if (!ok) return;
            const resp = await window.api?.appearance?.deleteBg?.(file);
            if (resp && resp.success === false) {
              window.app?.toast?.('error', '删除失败：' + (resp.message || '未知原因'));
              return;
            }
            const ap2 = window.pathbindingAppearance.load();
            if (ap2.bgPath === file) {
              delete ap2.bgPath;
              window.pathbindingAppearance.save(ap2);
              crossfadeBg('--app-bg-fade', () => applyBackground(null));
              refreshBgCurrent(ap2);
            }
            renderBgList(ap2);
          } catch (err) {
            window.app?.toast?.('error', '删除背景图片未完成：' + ((err && err.message) || err));
          }
        });
      });
      }).catch((e) => {
        // NEW-4（L3 2026-10-01）：背景图列表 IPC 失败必须显性留痕，不能静默空白
        window.pathbinding.bgListLoadFailed(e);
      });
    if (currentRow) currentRow.style.display = ap.bgPath ? 'flex' : 'none';
    if (thumb && ap.bgPath) thumb.src = toImgUrl(ap.bgPath);
  }

  function refreshBgCurrent(ap) {
    const currentRow = document.getElementById('bgCurrentRow');
    const thumb = document.getElementById('bgThumb');
    const slider = document.getElementById('bgOpacity');
    const val = document.getElementById('bgOpacityVal');
    // 批次：背景视角可调 —— 视角滑块与重置按钮跟「已选图片」同进退
    const viewRow = document.getElementById('bgViewRow');
    const posXSlider = document.getElementById('bgPosX');
    const posYSlider = document.getElementById('bgPosY');
    const posXVal = document.getElementById('bgPosXVal');
    const posYVal = document.getElementById('bgPosYVal');
    if (currentRow) currentRow.style.display = ap.bgPath ? 'flex' : 'none';
    if (viewRow) viewRow.style.display = ap.bgPath ? 'flex' : 'none';
    if (thumb && ap.bgPath) thumb.src = toImgUrl(ap.bgPath);
    if (slider) {
      slider.value = ap.bgOpacity == null ? 85 : ap.bgOpacity;
      // 编程式赋值不触发 input 事件，手动同步轨道填充（ds.slider）
      window.ds?.slider?.sync?.(slider);
    }
    if (val) val.textContent = (ap.bgOpacity == null ? 85 : ap.bgOpacity) + '%';
    // 视角滑块同步存储值（缺省 50 = 居中），同样手动同步轨道填充
    const px = ap.bgPosX == null ? 50 : ap.bgPosX;
    const py = ap.bgPosY == null ? 50 : ap.bgPosY;
    if (posXSlider) {
      posXSlider.value = px;
      window.ds?.slider?.sync?.(posXSlider);
    }
    if (posYSlider) {
      posYSlider.value = py;
      window.ds?.slider?.sync?.(posYSlider);
    }
    if (posXVal) posXVal.textContent = px + '%';
    if (posYVal) posYVal.textContent = py + '%';
  }

  // 壁纸层模糊滑块的「真源值 → 界面」出口：由 initWallpaperBlur 登记，外观层重放时调用。
  let wpBlurApply = null;

  // 背景模糊度滑块（Motion.Lab range-drag 适配）：拖动实时模糊壁纸 .app-wallpaper::before
  function initWallpaperBlur() {
    var range = document.getElementById('bgBlurRange');
    if (!range) return;
    var track = range.querySelector('.bbr-track');
    var fill = range.querySelector('.bbr-fill');
    var knob = range.querySelector('.bbr-knob');
    var valEl = document.getElementById('bgBlurVal');
    // 上限与启动期 theme.js 同源（ds.WALLPAPER_MAX_BLUR_PX），两处各写一个数字必然漂移
    var MAX_BLUR = window.ds?.WALLPAPER_MAX_BLUR_PX || 20;
    var dragging = false;
    var blurSaveTimer = null;
    function setBlur(pct) {
      pct = Math.max(0, Math.min(100, pct));
      var px = (pct / 100 * MAX_BLUR).toFixed(1);
      fill.style.width = pct + '%';
      knob.style.left = pct + '%';
      valEl.textContent = Math.round(pct) + '%';
      document.documentElement.style.setProperty('--bg-blur', px + 'px');
      // v3.5.1 动效审查 M7：原实现每次 mousemove 都同步写一遍全量 appearance，
      // 拖动一次会打出上百次 JSON 序列化 + 同步 IO（阻塞主线程）；改为 150ms 防抖落盘，
      // 与上方另一处滑块（blurSaveTimer 模式）统一。
      clearTimeout(blurSaveTimer);
      blurSaveTimer = setTimeout(function () {
        // F4a2-L06：外观键读写统一走外观层的 load/save ——
        // 同键裸读写此前绕过 helper（§5.28 同族：域内写路径不收口，损坏降级/键名
        // 改动就会各处各判），收敛到单一函数对后只有一个口径。
        var ap = window.pathbindingAppearance.load();
        ap.wallpaperBlur = Math.round(pct);
        window.pathbindingAppearance.save(ap);
      }, 150);
    }
    function updateFromClientX(clientX) {
      var r = track.getBoundingClientRect();
      var pct = (clientX - r.left) / r.width * 100;
      setBlur(pct);
    }
    // 登记给外观层的重放入口：后端回读可能晚于本页初始化，需要一条不改
    // 「位置计算只有一份」前提的重放路径（此处是唯一的 setBlur 实现）。
    wpBlurApply = setBlur;
    track.addEventListener('mousedown', function (e) {
      dragging = true;
      range.classList.add('dragging');
      updateFromClientX(e.clientX);
      e.preventDefault();
    });
    window.addEventListener('mousemove', function (e) {
      if (dragging) updateFromClientX(e.clientX);
    });
    window.addEventListener('mouseup', function () {
      if (dragging) { dragging = false; range.classList.remove('dragging'); }
    });
    // F4a2-L06：初值读取同样走外观层的 load（损坏降级已在那里统一）
    var ap2 = window.pathbindingAppearance.load();
    // 兜底用同一个默认值：theme.js 正常已在启动期把 wallpaperBlur 落进存储，
    // 走到这里说明它是空的（老配置/写入失败），滑块位置要和实际生效值一致，不能显示 0%
    var defBlur = window.ds?.DEFAULT_WALLPAPER_BLUR ?? 0;
    setBlur(typeof ap2.wallpaperBlur === 'number' ? ap2.wallpaperBlur : defBlur);
  }

  // 绑定背景图面全部控件；返回 skin→模糊迁移后的镜像，供外观层接着做雾化度迁移。
  function init() {
    // 批次：雾化度语义反转 —— 皮肤键迁移后由外观层接着做雾化度一次性迁移；
    // 本面先做 skin→bgBlur，是因为背景模糊滑块与背景图读的是同一份镜像。
    const ap = migrateSkinToBlur(window.pathbindingAppearance.load());

    // 背景图片（初始展示走外观层登记的重放钩子）
    document.getElementById('btnBgImport')?.addEventListener('click', async () => {
      // P1-7（F4c-M01）：整个 handler 原先没有 reject 出口 —— `appearance:import-bg` 是
      // IPC，通道级失败直接变 unhandled rejection，用户点了没任何反应，还得自己猜是不是坏了。
      try {
        const resp = await window.api?.appearance?.importBg?.();
        if (!resp || resp.canceled) return;
        if (!resp.success) {
          window.app?.toast('error', (resp && resp.message) || '导入背景图片失败');
          return;
        }
        const ap2 = window.pathbindingAppearance.load();
        ap2.bgPath = resp.data.path;
        if (ap2.bgOpacity == null) ap2.bgOpacity = 85;
        // 新图新视角：换图即把裁切窗口回到居中，避免沿用上一张的取景
        delete ap2.bgPosX;
        delete ap2.bgPosY;
        window.pathbindingAppearance.save(ap2);
        crossfadeBg('--app-bg-fade', () => applyBackground(ap2.bgPath, ap2.bgOpacity, ap2.bgPosX, ap2.bgPosY));
        refreshBgCurrent(ap2);
        renderBgList(ap2);
        window.app?.toast('success', '背景图片已导入并应用');
      } catch (e) {
        window.app?.toast?.('error', '导入背景图片失败：' + ((e && e.message) || e));
      }
    });
    document.getElementById('btnBgClear')?.addEventListener('click', () => {
      const ap2 = window.pathbindingAppearance.load();
      delete ap2.bgPath;
      window.pathbindingAppearance.save(ap2);
      crossfadeBg('--app-bg-fade', () => applyBackground(null));
      refreshBgCurrent(ap2);
      window.app?.toast('success', '已清除背景图片');
    });
    // 打开背景图片存放目录（需求：点击跳转本地 backgrounds 目录）
    document.getElementById('btnOpenBgDir')?.addEventListener('click', () => {
      window.api?.appearance?.openBgDir?.()
        .then(r => { if (r && !r.success) window.app?.toast('error', (r.message) || '无法打开背景目录'); })
        .catch(() => window.app?.toast('error', '无法打开背景目录'));
    });
    const opacitySlider = document.getElementById('bgOpacity');
    opacitySlider?.addEventListener('input', () => {
      const v = parseInt(opacitySlider.value, 10);
      const val = document.getElementById('bgOpacityVal');
      if (val) val.textContent = v + '%';
      const ap2 = window.pathbindingAppearance.load();
      ap2.bgOpacity = v;
      window.pathbindingAppearance.save(ap2);
      applyBackground(ap2.bgPath, v, ap2.bgPosX, ap2.bgPosY);
    });
    // 批次：背景视角可调 —— 水平/垂直位置滑块，拖动即时生效并持久化（0-100 裁切窗口百分比）
    function bindBgPosSlider(sliderId, valId, storeKey) {
      const el = document.getElementById(sliderId);
      el?.addEventListener('input', () => {
        const v = parseInt(el.value, 10);
        const val = document.getElementById(valId);
        if (val) val.textContent = v + '%';
        const ap2 = window.pathbindingAppearance.load();
        ap2[storeKey] = v;
        window.pathbindingAppearance.save(ap2);
        applyBackground(ap2.bgPath, ap2.bgOpacity, ap2.bgPosX, ap2.bgPosY);
      });
    }
    bindBgPosSlider('bgPosX', 'bgPosXVal', 'bgPosX');
    bindBgPosSlider('bgPosY', 'bgPosYVal', 'bgPosY');
    // 重置视角：回到居中（50/50），与默认行为一致
    document.getElementById('btnBgViewReset')?.addEventListener('click', () => {
      const ap2 = window.pathbindingAppearance.load();
      ap2.bgPosX = 50;
      ap2.bgPosY = 50;
      window.pathbindingAppearance.save(ap2);
      applyBackground(ap2.bgPath, ap2.bgOpacity, 50, 50);
      refreshBgCurrent(ap2);
    });
    // 已导入图片列表折叠
    document.getElementById('bgListToggle')?.addEventListener('click', () => {
      const body = document.getElementById('bgListBody');
      const chev = document.querySelector('#bgListToggle .bg-list-chevron');
      if (!body) return;
      const open = body.style.display !== 'none';
      body.style.display = open ? 'none' : 'block';
      if (chev) chev.textContent = open ? '⌄' : '⌃';
    });
    window.ds?.accordion?.enhance(
      document.getElementById('bgListToggle'),
      document.getElementById('bgListBody')
    );
    // 键盘等价路径（A3-M03）：`ds.accordion.enhance` 只补 ARIA，不加 tabindex/keydown，
    // 所以「用了 ds 件」不等于「键盘可达」——这个 div 头此前键盘走不到。
    // 刻意写在本文件而不是塞进 ds.js：ds.js 在首屏 12 脚本内，而首屏预算 2026-10-22 已裁定
    // 不再上调（现算余量 48 B），为一个只有按需页用的能力加字节不划算。两处调用点各留一份，
    // 由 check-a11y 的「折叠头键盘接线」钉住，改回去会红。
    bindCollapseKeys(document.getElementById('bgListToggle'));

    const presetBgSelect = document.getElementById('presetBgSelect');
    presetBgSelect?.addEventListener('change', () => {
      const ap2 = window.pathbindingAppearance.load();
      ap2.presetBg = presetBgSelect.value || '';
      window.pathbindingAppearance.save(ap2);
      crossfadeBg('--preset-bg-fade', () => applyPresetBg(ap2.presetBg));
    });

    // 背景模糊度滑块（位于「背景图片」卡内，预设背景/导入图片均可叠加）。
    // P2-4（v4）：本读数 span 原与自定义滑块（#bgBlurRange 的 .bbr-val）**撞 id**，
    // getElementById 恒取文档里第一个 ⇒ 原生滑块读数写进了另一套控件的 span、自己恒 0%。
    // 原生滑块这一侧改用专属 id `bgBlurInputVal`（勿用 bgOpacityVal——那是「雾化度」滑块的读数）。
    const blurSlider = document.getElementById('bgBlur');
    const blurVal = document.getElementById('bgBlurInputVal');
    if (blurSlider) {
      // 审查 3-3：视觉即时生效，存储防抖 150ms——一次拖动不再产生上百次同步 localStorage 写
      let blurSaveTimer = null;
      blurSlider.addEventListener('input', () => {
        const v = parseInt(blurSlider.value, 10) || 0;
        if (blurVal) blurVal.textContent = v + '%';
        applyBgBlur(v);
        clearTimeout(blurSaveTimer);
        blurSaveTimer = setTimeout(() => {
          const ap2 = migrateSkinToBlur(window.pathbindingAppearance.load());
          ap2.bgBlur = v;
          window.pathbindingAppearance.save(ap2);
        }, 150);
      });
    }

    window.pathbindingAppearance.registerApply(function (cur) {
      refreshBgCurrent(cur);
      renderBgList(cur);
      applyBackground(cur.bgPath, cur.bgOpacity, cur.bgPosX, cur.bgPosY);
      const pSel = document.getElementById('presetBgSelect');
      if (pSel) pSel.value = cur.presetBg || '';
      applyPresetBg(cur.presetBg);
      const bSlider = document.getElementById('bgBlur');
      if (bSlider) {
        bSlider.value = cur.bgBlur == null ? 0 : cur.bgBlur;
        const bVal = document.getElementById('bgBlurInputVal');
        if (bVal) bVal.textContent = bSlider.value + '%';
        // 编程式赋值不触发 input 事件，手动同步轨道填充（ds.slider）
        window.ds?.slider?.sync?.(bSlider);
        applyBgBlur(bSlider.value);
      }
      // 壁纸层模糊的自定义滑块（#bgBlurRange）的读数与轨道由 initWallpaperBlur 自己管，
      // 这里只调它登记的出口，不再抄一份位置计算。
      if (typeof wpBlurApply === 'function') {
        wpBlurApply(typeof cur.wallpaperBlur === 'number'
          ? cur.wallpaperBlur
          : (window.ds?.DEFAULT_WALLPAPER_BLUR ?? 0));
      }
    });

    return ap;
  }

  window.pathbindingBackground = { init, initWallpaperBlur, applyPresetBg, crossfadeBg };
})();

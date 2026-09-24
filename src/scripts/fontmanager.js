// fontmanager.js - 设置 → 字体选择 应用内弹窗
// 复用「安装路径绑定」的 usage-backdrop > usage-modal 弹窗样式。
// 能力：5 款系统字体识别（缺失置灰）+ 内嵌 MiSans 可变字体（默认）+ 导入 1 款外部字体；
// 字重滑块（100-1000，MiSans 无级连续调节）与字号滑块（12-24px）全局生效，
// 经 --app-font-family / --font-weight-scale / --font-size-scale 三个 CSS 变量驱动全部界面文本。
// 配置持久化到 settings.json 的 font 字段，应用重启后自动恢复。
(function () {
  'use strict';

  const SIZE_BASE = 16;   // 字号缩放基准（默认 16px → scale = 1）
  const WEIGHT_BASE = 400; // 字重缩放基准（默认 400 → scale = 1）
  const IMPORTED_STYLE_ID = 'importedFontFace';

  let modal = null;      // { backdrop, select, weightInput, sizeInput, preview, weightVal, sizeVal, tip }
  let escHandler = null;
  let fontList = [];
  let settings = { family: 'MiSans', weight: 400, size: 16 };
  let importedFamily = '';
  let importedUrl = '';

  function escapeHtml(text) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(text == null ? '' : text).replace(/[&<>"']/g, m => map[m]);
  }

  // ---------- 导入字体的动态 @font-face（单字体约束：同一时刻仅一条规则） ----------
  function injectImportedFace(family, url) {
    document.getElementById(IMPORTED_STYLE_ID)?.remove();
    importedFamily = '';
    importedUrl = '';
    if (!family || !url) return;
    const style = document.createElement('style');
    style.id = IMPORTED_STYLE_ID;
    style.textContent = `@font-face { font-family: '${family.replace(/['\\]/g, '')}'; src: url('${url}'); font-display: swap; }`;
    document.head.appendChild(style);
    importedFamily = family;
    importedUrl = url;
  }

  // ---------- 全局应用（三个 CSS 变量驱动 main.css 内全部 calc 字号 / 字重） ----------
  function stackFor(family) {
    const found = fontList.find(f => f.family === family && f.available);
    return found ? found.cssStack : "'MiSans', '微软雅黑', 'Microsoft YaHei', sans-serif";
  }

  function applyToRoot() {
    const root = document.documentElement;
    root.style.setProperty('--app-font-family', stackFor(settings.family));
    root.style.setProperty('--font-size-scale', String(settings.size / SIZE_BASE));
    root.style.setProperty('--font-weight-scale', String(settings.weight / WEIGHT_BASE));
  }

  function weightPercent(w) {
    return `${Math.round(w / 10)}%`;
  }

  // ---------- 弹窗渲染 ----------
  function renderSelect() {
    if (!modal) return;
    const sel = modal.select;
    sel.innerHTML = fontList.map(f => {
      const label = f.imported ? `${f.family}（已导入）` : f.builtin ? `${f.family}（内嵌）` : f.family;
      const selected = f.family === settings.family ? ' selected' : '';
      const disabled = f.available ? '' : ' disabled';
      return `<option value="${escapeHtml(f.family)}"${selected}${disabled}>${escapeHtml(label)}${f.available ? '' : '（未安装）'}</option>`;
    }).join('');
  }

  function renderPreview() {
    if (!modal) return;
    const stack = stackFor(settings.family);
    modal.preview.style.fontFamily = stack;
    modal.preview.style.fontWeight = String(settings.weight);
    modal.preview.style.fontSize = `${settings.size}px`;
    modal.weightVal.textContent = `${settings.weight} · ${weightPercent(settings.weight)}`;
    modal.sizeVal.textContent = `${settings.size}px`;
    const meta = fontList.find(f => f.family === settings.family);
    modal.tip.textContent = meta
      ? `当前：${meta.family}${meta.imported ? '（已导入）' : meta.builtin ? '（内嵌可变字体，字重 100-1000 无级调节）' : ''} · 字重 ${settings.weight}（${weightPercent(settings.weight)}）· 字号 ${settings.size}px`
      : `当前：${settings.family}`;
    const isMisans = settings.family === 'MiSans';
    modal.weightInput.title = isMisans
      ? 'MiSans 可变字体：100-1000 无级连续调节'
      : '系统字体受自身字重限制，滑块按最接近的可用字重渲染';
  }

  function refreshDeleteBtn() {
    if (!modal) return;
    const has = fontList.some(f => f.imported);
    modal.delBtn.disabled = !has;
    modal.delBtn.title = has ? `删除已导入字体「${importedFamily}」（本地副本一并删除，不影响原始文件）` : '当前没有已导入的字体';
  }

  // 需要改为：调整仅实时预览（只改预览区），点击「应用」才全局生效并保持打开
  function bindEvents() {
    if (!modal) return;
    modal.select.addEventListener('change', () => {
      settings.family = modal.select.value;
      renderPreview();
    });
    // 拖动过程（input）仅实时预览（不写根变量，不落盘）
    modal.weightInput.addEventListener('input', () => {
      settings.weight = Math.min(1000, Math.max(100, Number(modal.weightInput.value) || WEIGHT_BASE));
      renderPreview();
    });
    modal.sizeInput.addEventListener('input', () => {
      settings.size = Math.min(24, Math.max(12, Number(modal.sizeInput.value) || SIZE_BASE));
      renderPreview();
    });
    // 「应用」按钮：把预览值真正应用到整体界面（写根变量）并保存，弹窗保持打开
    modal.applyBtn.addEventListener('click', async () => {
      settings.family = modal.select.value;
      settings.weight = Math.min(1000, Math.max(100, Number(modal.weightInput.value) || WEIGHT_BASE));
      settings.size = Math.min(24, Math.max(12, Number(modal.sizeInput.value) || SIZE_BASE));
      applyToRoot();
      await saveConfig();
      window.app?.toast('success', `已应用：${settings.family} · 字重 ${settings.weight} · 字号 ${settings.size}px`);
    });
    // 「恢复默认」：把预览区和设置都改回默认（尚未全局应用，需再点「应用」）
    modal.resetBtn.addEventListener('click', () => {
      settings = { family: 'MiSans', weight: WEIGHT_BASE, size: SIZE_BASE };
      modal.weightInput.value = String(WEIGHT_BASE);
      modal.sizeInput.value = String(SIZE_BASE);
      renderSelect();
      renderPreview();
      window.app?.toast('info', '已重置为默认：MiSans · 400 字重 · 16px，点击「应用」生效');
    });
    modal.importBtn.addEventListener('click', async () => {
      if (!window.api?.fonts?.importFont) { window.app?.toast('warning', '当前环境不支持导入字体'); return; }
      modal.importBtn.disabled = true;
      try {
        const resp = await window.api.fonts.importFont();
        if (resp && resp.success) {
          await load(true);
          // 导入后仅选中并进入预览，不自动全局应用（用户需点「应用」）
          settings.family = resp.data.family;
          renderSelect();
          renderPreview();
          refreshDeleteBtn();
          window.app?.toast('success', `已导入字体「${resp.data.family}」，预览下方效果，点击「应用」生效`);
        } else if (resp && resp.canceled) {
          // 用户取消选择，不做任何处理
        } else {
          window.app?.toast('error', (resp && resp.message) || '导入字体失败');
        }
      } catch (e) {
        window.app?.toast('error', `导入字体异常：${e.message}`);
      } finally {
        modal.importBtn.disabled = false;
      }
    });
    modal.delBtn.addEventListener('click', async () => {
      if (!window.api?.fonts?.removeImported) { window.app?.toast('warning', '当前环境不支持删除字体'); return; }
      if (!fontList.some(f => f.imported)) return;
      if (!window.confirm(`确定删除已导入字体「${importedFamily}」吗？\n本地副本将一并删除（不影响原始文件），界面将回退到 MiSans。`)) return;
      try {
        const resp = await window.api.fonts.removeImported();
        if (resp && resp.success) {
          injectImportedFace('', '');
          await load(true);
          if (settings.family === importedFamily || !fontList.some(f => f.family === settings.family)) {
            settings.family = 'MiSans';
          }
          applyToRoot();
          renderSelect();
          renderPreview();
          refreshDeleteBtn();
          saveConfig();
          window.app?.toast('success', '已删除导入字体');
        } else {
          window.app?.toast('error', (resp && resp.message) || '删除导入字体失败');
        }
      } catch (e) {
        window.app?.toast('error', `删除字体异常：${e.message}`);
      }
    });
  }

  async function saveConfig() {
    try {
      if (window.api?.fonts?.saveConfig) await window.api.fonts.saveConfig(settings);
    } catch (e) {
      window.app?.toast('error', '字体配置保存失败');
    }
  }

  // ---------- 数据加载（open 时静默刷新；startup 时仅恢复应用） ----------
  async function load(silent) {
    try {
      const resp = await window.api.fonts.list();
      if (resp && resp.success && resp.data) {
        fontList = resp.data.list || [];
        settings = { ...settings, ...resp.data.settings };
        const imported = resp.data.imported;
        const importedEntry = fontList.find(f => f.imported);
        if (importedEntry && importedEntry.copyUrl) {
          injectImportedFace(importedEntry.family, importedEntry.copyUrl);
        } else if (!imported) {
          injectImportedFace('', '');
        }
      }
    } catch (e) {
      if (!silent) window.app?.toast('error', '读取字体配置失败');
      return;
    }
    if (modal) {
      modal.weightInput.value = String(settings.weight);
      modal.sizeInput.value = String(settings.size);
      renderSelect();
      renderPreview();
      refreshDeleteBtn();
    }
  }

  // 应用启动时恢复已保存的字体设置（不弹窗）
  async function restore() {
    if (!window.api?.fonts?.list) return;
    await load(true);
    applyToRoot();
  }

  function close() {
    // v3.2.0：骨架由 modal.js 工厂创建，close 即销毁（Esc/遮罩由工厂接管）
    if (modal) { modal.ctrl.close(); modal = null; }
  }

  async function open() {
    close();
    // v3.2.0 弹窗统一批次：骨架改由 modal.js 工厂生成
    const ctrl = window.modal.create({
      id: 'fontModalBackdrop',
      title: '字体选择',
      backdropClass: 'font-modal-backdrop',
      modalClass: 'font-modal',
      bodyClass: 'fm-body',
      bodyHtml: `
          <p class="model-picker-tip">选择应用界面显示字体，支持系统字体、内嵌 MiSans 与自定义导入字体。字重滑块调节字体粗细（100-1000，MiSans 可变字体支持无级连续调节），字号滑块（12-24px）在所有字体通用。调整仅实时预览于下方「字体预览」，点击右下角「应用」后才会应用到整体界面。</p>
          <div class="fm-field">
            <span class="fm-field-label">界面字体</span>
            <div class="fm-field-main">
              <div class="fm-row">
                <select class="field-input" data-role="select" aria-label="选择界面字体"></select>
                <button class="btn btn-secondary btn-small" data-role="importBtn" type="button" data-tip="导入 1 款外部字体文件（.ttf / .otf / .woff / .woff2），将替换当前已导入字体">导入字体</button>
                <button class="btn btn-secondary btn-small" data-role="delBtn" type="button">删除导入字体</button>
              </div>
              <span class="fm-field-tip" data-role="tip">正在读取字体配置…</span>
            </div>
          </div>
          <div class="fm-field">
            <span class="fm-field-label">字重</span>
            <div class="fm-field-main">
              <div class="fm-slider-row">
                <input type="range" data-role="weightInput" min="100" max="1000" step="10" value="400" />
                <span class="fm-slider-val" data-role="weightVal">400 · 40%</span>
              </div>
              <span class="fm-field-tip">基准 400 · 范围 100-1000 · 显示当前粗细百分比（400 = 40%）</span>
            </div>
          </div>
          <div class="fm-field">
            <span class="fm-field-label">字号</span>
            <div class="fm-field-main">
              <div class="fm-slider-row">
                <input type="range" data-role="sizeInput" min="12" max="24" step="1" value="16" />
                <span class="fm-slider-val" data-role="sizeVal">16px</span>
              </div>
              <span class="fm-field-tip">范围 12px-24px · 对所有字体全局生效（基准 16px）</span>
            </div>
          </div>
          <div class="fm-preview" data-role="previewBox">
            <div class="fm-preview-title">字体预览</div>
            <div class="fm-preview-text" data-role="preview">永和九年，岁在癸丑，暮春之初，会于会稽山阴之兰亭。The quick brown fox jumps over the lazy dog. 0123456789</div>
          </div>`,
      footerClass: 'pw-footer',
      footerHtml: `
          <span class="pw-last-scan">配置保存在本机 %APPDATA%\\Trim\\settings.json</span>
          <span class="model-picker-spacer"></span>
          <button class="btn btn-secondary" data-role="resetBtn" type="button">恢复默认</button>
          <button class="btn btn-primary" data-role="applyBtn" type="button">应用</button>`,
      onClose() { modal = null; }
    });
    modal = {
      ctrl,
      backdrop: ctrl.backdrop,
      select: ctrl.body.querySelector('[data-role="select"]'),
      weightInput: ctrl.body.querySelector('[data-role="weightInput"]'),
      sizeInput: ctrl.body.querySelector('[data-role="sizeInput"]'),
      weightVal: ctrl.body.querySelector('[data-role="weightVal"]'),
      sizeVal: ctrl.body.querySelector('[data-role="sizeVal"]'),
      preview: ctrl.body.querySelector('[data-role="preview"]'),
      tip: ctrl.body.querySelector('[data-role="tip"]'),
      importBtn: ctrl.body.querySelector('[data-role="importBtn"]'),
      delBtn: ctrl.body.querySelector('[data-role="delBtn"]'),
      resetBtn: ctrl.footer.querySelector('[data-role="resetBtn"]'),
      applyBtn: ctrl.footer.querySelector('[data-role="applyBtn"]')
    };

    bindEvents();
    await load(false);
    renderSelect();
    renderPreview();
    refreshDeleteBtn();
  }

  window.fontmanager = { open, close, restore, applyToRoot };
})();

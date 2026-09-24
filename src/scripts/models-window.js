// models-window.js - 设置 → 大模型管理 独立窗口
// 由 models-modal.js（应用内弹窗）迁移而来：渲染逻辑与配置项保持不变，
// 去掉 backdrop 遮罩，改为铺满窗口的页面容器；「完成」按钮调用 IPC 关闭窗口。
// 配置存取仍复用 window.api.models.save / setScope / test（与弹窗版一致）。
(function () {
  'use strict';

  const MODEL_META = {
    baidu_pro: {
      name: '百度千帆',
      sub: '百度智能搜索引擎，支持思考模型',
      icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm3 15H9v-1.5h6zm.5-3.5H8.5v-1h7zm0-3.5h-7V8.5h7z"/></svg>',
      needsModel: true,
      modelMode: 'select'
    },
    zhihu: {
      name: '知乎直答',
      sub: '知乎官方直答，含引用来源',
      icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm3 15H9v-1.5h6zm.5-3.5H8.5v-1h7zm0-3.5h-7V8.5h7z"/></svg>',
      needsModel: true,
      modelMode: 'text'
    },
    metaso: {
      name: '秘塔 AI',
      sub: '秘塔检索问答，无广告、带引用',
      icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 4a6 6 0 0 1 6 6 6 6 0 0 1-6 6 6 6 0 0 1-6-6 6 6 0 0 1 6-6zm0 3a3 3 0 1 0 3 3 3 3 0 0 0-3-3z"/></svg>',
      needsModel: true,
      modelMode: 'text'
    },
    custom: {
      name: '自定义模型',
      sub: '接入任意 OpenAI 兼容模型',
      icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm3.5 6.5c0-1.1.9-2 2-2s2 .9 2 2-.9 2-2 2-2-.9-2-2zm-11 0c0-1.1.9-2 2-2s2 .9 2 2-.9 2-2 2-2-.9-2-2zM12 19c-3.87 0-7-3.13-7-7h2c0 2.76 2.24 5 5 5s5-2.24 5-5h2c0 3.87-3.13 7-7 7z"/></svg>',
      needsModel: true,
      modelMode: 'text'
    }
  };
  const ORDER = ['baidu_pro', 'zhihu', 'metaso', 'custom'];
  const VERIFY_TEXT = 'api是什么，用三十个字简略回答';

  // 各模型 API 文档超链接（显示在分组标题名称右侧，点击用系统浏览器打开）
  const DOC_LINKS = {
    baidu_pro: {
      url: 'https://cloud.baidu.com/doc/qianfan/s/Kmiy99ziv',
      label: '还没有？去获取API',
      tip: '获取百度千帆 Access Key（打开 API 文档）'
    },
    zhihu: {
      url: 'https://developer.zhihu.com/docs?key=zhida',
      label: 'API 文档',
      tip: '查看知乎直答 API 文档'
    },
    metaso: {
      url: 'https://metaso.cn/search-api/playground',
      label: 'API 文档',
      tip: '查看秘塔 AI 搜索 API 文档'
    }
  };

  let models = {};
  let defaults = {};
  let collapsed = {};
  let body = null;         // #mwBody 页面容器
  let els = {};            // 关键元素缓存

  function $(id) { return document.getElementById(id); }
  function escapeAttr(s) {
    return String(s || '').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  function escapeHtml(text) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(text == null ? '' : text).replace(/[&<>"']/g, m => map[m]);
  }

  // 独立窗口的轻量提示（写入底部全局提示行）
  function toast(type, message) {
    const host = $('mwGlobalHint');
    if (!host) return;
    host.textContent = message || '';
    host.style.color = type === 'error' ? 'var(--danger)'
      : type === 'success' ? 'var(--success)'
        : type === 'warning' ? 'var(--warning)' : 'var(--fg-tertiary)';
    if (message) setTimeout(() => { if (host.textContent === message) host.textContent = ''; }, 5000);
  }

  function stateBadge(key) {
    const cfg = models[key] || {};
    if (cfg.enabled && cfg.verified) return '<span class="mw-state ok">已启用 · 已验证</span>';
    if (cfg.enabled) return '<span class="mw-state warn">已启用 · 未验证</span>';
    return '<span class="mw-state">未启用</span>';
  }

  function render() {
    if (!body) return;
    body.innerHTML = ORDER.map(key => {
      const meta = MODEL_META[key];
      const cfg = models[key] || {};
      const isCustom = key === 'custom';
      const isBaiduPro = key === 'baidu_pro';
      const thinkValues = ['thinking', 'auto_thinking', 'non_thinking'];
      return `
        <section class="mw-group${collapsed[key] ? ' collapsed' : ''}" data-model="${key}">
          <div class="mw-group-head" data-toggle="${key}">
            <svg class="mw-group-chevron" viewBox="0 0 24 24" width="14" height="14" fill="currentColor"><path d="M7 10l5 5 5-5z"/></svg>
            <span class="mw-group-icon">${meta.icon}</span>
            <div>
              <div class="mw-group-title">${escapeHtml(meta.name)}${DOC_LINKS[key] ? `<a class="mw-doc-link" href="${escapeAttr(DOC_LINKS[key].url)}" target="_blank" rel="noopener noreferrer" title="${escapeAttr(DOC_LINKS[key].tip)}">${escapeHtml(DOC_LINKS[key].label)}</a>` : ''}</div>
              <div class="mw-group-sub">${escapeHtml(meta.sub)}</div>
            </div>
            <span class="mw-group-meta">${stateBadge(key)}</span>
          </div>
          <div class="mw-group-content">
            <div class="mw-field">
              <span class="mw-field-label">启用AI简介</span>
              <div class="mw-field-main">
                <div class="mw-row">
                  <label class="toggle-switch" title="开启后，该模型可被各模块的「获取AI简介」调用">
                    <input type="checkbox" data-role="enabled" data-model="${key}" ${cfg.enabled ? 'checked' : ''} />
                    <span class="toggle-track"><span class="toggle-thumb"></span></span>
                  </label>
                  <span class="mw-field-tip mw-inline-tip">关闭后，选择该模型时不会发起任何联网请求</span>
                </div>
              </div>
            </div>
            <div class="mw-field">
              <span class="mw-field-label">API 接口地址</span>
              <div class="mw-field-main">
                <input type="text" class="field-input" data-role="apiUrl" data-model="${key}"
                       value="${escapeAttr(cfg.apiUrl || '')}" placeholder="https://..." spellcheck="false" />
                <span class="mw-field-tip">${isBaiduPro ? '百度千帆：固定为 /v2/ai_search/web_summary' : 'OpenAI 兼容地址，需以 /chat/completions 结尾'}</span>
              </div>
            </div>
            <div class="mw-field">
              <span class="mw-field-label">Access Key / API Key</span>
              <div class="mw-field-main">
                <div class="mw-row">
                  <input type="password" class="field-input" data-role="apiKey" data-model="${key}"
                         value="${escapeAttr(cfg.apiKey || '')}" placeholder="请输入密钥（默认留空，保存后校验通过方可启用）" autocomplete="off" />
                  <button class="btn btn-secondary btn-small" data-role="toggleKey" data-model="${key}" type="button">显示</button>
                </div>
                <span class="mw-field-tip">密钥仅保存在本机 %APPDATA%\\Trim\\settings.json，不会写入日志；留空保存时不会发起校验</span>
              </div>
            </div>
            ${isBaiduPro ? `
            <div class="mw-field">
              <span class="mw-field-label">模型（思考能力）</span>
              <div class="mw-field-main">
                <select class="field-input" data-role="model" data-model="${key}">
                  ${thinkValues.map(v => `<option value="${v}" ${(cfg.model || 'thinking') === v ? 'selected' : ''}>${v === 'thinking' ? 'thinking（使用思考模型）' : v === 'auto_thinking' ? 'auto_thinking（自适应）' : 'non_thinking（非思考模型）'}</option>`).join('')}
                </select>
                <span class="mw-field-tip">百度千帆使用固定枚举：thinking / auto_thinking / non_thinking</span>
              </div>
            </div>` : `
            <div class="mw-field">
              <span class="mw-field-label">模型名称</span>
              <div class="mw-field-main">
                <input type="text" class="field-input" data-role="model" data-model="${key}"
                       value="${escapeAttr(cfg.model || '')}" placeholder="${isCustom ? '例如 Qwen2.5-72B-Instruct、gpt-4o-mini' : '例如 fast_thinking、zhida-fast-1p5'}" spellcheck="false" />
                <span class="mw-field-tip">${isCustom ? '此处填写的名称会直接显示在各模块的模型选择列表中' : '按服务商提供的模型档位填写'}</span>
              </div>
            </div>`}
            ${isCustom ? `
            <div class="mw-field">
              <span class="mw-field-label">展示名称（可选）</span>
              <div class="mw-field-main">
                <input type="text" class="field-input" data-role="customName" data-model="custom"
                       value="${escapeAttr(cfg.customName || '')}" placeholder="留空则直接使用「模型名称」" spellcheck="false" />
                <span class="mw-field-tip">用于在选择列表中显示一个更好记的名字</span>
              </div>
            </div>` : ''}
            <div class="mw-field">
              <span class="mw-field-label">超时时间（秒）</span>
              <div class="mw-field-main">
                <input type="number" class="field-input mw-timeout" data-role="timeout" data-model="${key}"
                       value="${escapeAttr(cfg.timeout || 30)}" min="5" max="120" step="1" />
                <span class="mw-field-tip">取值范围 5 ~ 120 秒，默认 30 秒</span>
              </div>
            </div>
            <div class="mw-actions">
              <button class="btn btn-primary btn-small" data-role="save" data-model="${key}" type="button">保存</button>
              <button class="btn btn-secondary btn-small" data-role="test" data-model="${key}" type="button">测试连接</button>
              <button class="btn btn-secondary btn-small" data-role="reset" data-model="${key}" type="button">恢复默认</button>
            </div>
            <div class="mw-log" data-role="log" data-model="${key}" hidden></div>
          </div>
        </section>`;
    }).join('');
    bind();
  }

  function log(key, text, type) {
    if (!body) return;
    const box = body.querySelector(`[data-role="log"][data-model="${key}"]`);
    if (!box) return;
    box.hidden = false;
    box.textContent = text;
    box.style.color = type === 'error' ? 'var(--danger)'
      : type === 'success' ? 'var(--success)' : 'var(--fg-secondary)';
  }

  function readForm(key) {
    if (!body) return {};
    const pick = role => body.querySelector(`[data-role="${role}"][data-model="${key}"]`);
    const enabledEl = pick('enabled');
    const modelEl = pick('model');
    const customNameEl = pick('customName');
    return {
      enabled: enabledEl ? !!enabledEl.checked : false,
      apiUrl: (pick('apiUrl') || {}).value || '',
      apiKey: (pick('apiKey') || {}).value || '',
      model: modelEl ? modelEl.value : '',
      customName: customNameEl ? customNameEl.value : '',
      timeout: Number((pick('timeout') || {}).value) || 30
    };
  }

  function bind() {
    if (!body) return;
    body.querySelectorAll('[data-toggle]').forEach(head => {
      head.addEventListener('click', e => {
        // 点击「API 文档 / 去获取API」超链接不触发折叠，交由系统浏览器打开
        if (e.target.closest('a')) return;
        const key = head.dataset.toggle;
        const group = head.closest('.mw-group');
        collapsed[key] = !group.classList.contains('collapsed');
        group.classList.toggle('collapsed', !!collapsed[key]);
      });
    });
    body.querySelectorAll('[data-role="toggleKey"]').forEach(btn => {
      btn.addEventListener('click', () => {
        const input = body.querySelector(`[data-role="apiKey"][data-model="${btn.dataset.model}"]`);
        if (!input) return;
        const show = input.type === 'password';
        input.type = show ? 'text' : 'password';
        btn.textContent = show ? '隐藏' : '显示';
      });
    });
    body.querySelectorAll('[data-role="reset"]').forEach(btn => {
      btn.addEventListener('click', () => {
        const key = btn.dataset.model;
        const def = (defaults && defaults[key]) || null;
        if (!def) { log(key, '未获取到默认配置，请点击「重新载入」', 'error'); return; }
        models[key] = { ...models[key], ...def, apiKey: (models[key] || {}).apiKey || '' };
        render();
        log(key, `已恢复「${MODEL_META[key].name}」的默认配置（点击保存后生效）`);
      });
    });
    body.querySelectorAll('[data-role="test"]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const key = btn.dataset.model;
        const cfg = readForm(key);
        btn.disabled = true;
        btn.textContent = '测试中…';
        log(key, `正在发送确认消息：「${VERIFY_TEXT}」…`);
        try {
          const resp = await window.api.models.test(key, cfg);
          if (resp && resp.success) {
            log(key, `连接成功（${resp.latencyMs ?? '--'} ms）\n模型回复：${(resp.data && resp.data.reply) || ''}`, 'success');
          } else {
            log(key, `连接失败：${(resp && resp.message) || '未获得有效响应'}`, 'error');
          }
        } catch (e) {
          log(key, `测试异常：${e.message}`, 'error');
        } finally {
          btn.disabled = false;
          btn.textContent = '测试连接';
        }
      });
    });
    body.querySelectorAll('[data-role="save"]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const key = btn.dataset.model;
        const cfg = readForm(key);
        if (key !== 'baidu_pro' && !/^https?:\/\//i.test(String(cfg.apiUrl || '').trim())) {
          log(key, 'API 接口地址格式无效，请以 http(s):// 开头', 'error');
          return;
        }
        if (key === 'custom' && !String(cfg.model || '').trim()) {
          log(key, '自定义模型需要填写模型名称', 'error');
          return;
        }
        btn.disabled = true;
        btn.textContent = '保存中…';
        const hasKey = !!(cfg.apiKey || '').trim();
        log(key, hasKey ? `正在保存并发送确认消息：「${VERIFY_TEXT}」…` : '正在保存配置（密钥为空，未启用，暂不发起校验）…');
        try {
          const resp = await window.api.models.save(key, cfg);
          if (resp && resp.success) {
            await load();
            const ok = !!(resp.data && resp.data.verified);
            if (ok) {
              log(key, `保存成功，模型已返回确认内容${resp.data.reply ? '：\n' + resp.data.reply : ''}\n该模型已可用于各模块的「获取AI简介」`, 'success');
              toast('success', `「${MODEL_META[key].name}」保存成功`);
            } else if (resp.data && resp.data.emptyKey) {
              log(key, '配置已保存，但密钥为空：该模型暂未启用。请填入 Access Key / API Key 后再次保存并校验', 'error');
              toast('warning', `「${MODEL_META[key].name}」已保存，填密钥后可启用`);
            } else {
              log(key, '配置已保存，但模型未返回内容，请检查地址、密钥与模型名称后再试', 'error');
              toast('warning', `「${MODEL_META[key].name}」已保存但未通过校验`);
            }
          } else {
            log(key, `保存失败：${(resp && resp.message) || '未知错误'}`, 'error');
            toast('error', `「${MODEL_META[key].name}」保存失败`);
          }
        } catch (e) {
          log(key, `保存异常：${e.message}`, 'error');
        } finally {
          btn.disabled = false;
          btn.textContent = '保存';
        }
      });
    });
  }

  async function load() {
    try {
      const resp = await window.api.settings.load();
      if (resp && resp.success && resp.data) {
        models = resp.data.models || {};
        defaults = resp.data.modelDefaults || {};
      }
    } catch (e) {
      toast('error', '读取模型配置失败');
    }
    render();
  }

  function closeWindow() {
    if (window.api?.modelsWindow?.close) window.api.modelsWindow.close();
    else window.close();
  }

  // 恒浅色（v2.1：应用固定浅色，不再跟随系统主题；v2.8.0 清理死代码不再 remove theme-dark）
  function applyTheme() {
    document.body.classList.add('theme-light');
  }

  function init() {
    body = $('mwBody');
    els.refresh = $('mwRefreshBtn');
    els.close = $('mwCloseBtn');
    els.refresh?.addEventListener('click', () => load());
    els.close?.addEventListener('click', closeWindow);
    document.addEventListener('keydown', e => { if (e.key === 'Escape') closeWindow(); });
    applyTheme();
    load();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
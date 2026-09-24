// intro.js - 本地简介库 + 联网 AI 简介面板
// 1) 本地简介：随应用分发的离线简介库（src/data/item-intro.json），覆盖
//    电脑优化中心全部优化项、启动项管理（按名称关键字/来源）、右键管理（按分类）。
// 2) 联网 AI 简介：默认不发起任何请求；只有在详情/简介弹窗打开后，
//    由用户再次点击「获取AI简介」才调用所选大模型生成，三个模块各自独立。
(function () {
  'use strict';

  let introData = null;
  let loading = null;

  const SCOPE_LABEL = {
    optimizer: '电脑优化中心',
    startup: '启动项管理',
    contextmenu: '右键管理',
    memoryclean: '内存清理'
  };

  function escapeHtml(text) {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(text == null ? '' : text).replace(/[&<>"']/g, m => map[m]);
  }

  // 加载本地简介库（主进程读取 src/data/item-intro.json）
  function load() {
    if (introData) return Promise.resolve(introData);
    if (loading) return loading;
    loading = (async () => {
      try {
        if (window.api?.intro?.load) {
          const resp = await window.api.intro.load();
          if (resp && resp.success && resp.data) {
            introData = resp.data;
            return introData;
          }
        }
      } catch (e) { /* 读取失败时回落为空库，由各模块使用兜底文案 */ }
      introData = { scopes: {} };
      return introData;
    })();
    return loading;
  }

  function scopeConfig(scope) {
    const scopes = (introData && introData.scopes) || {};
    return scopes[scope] || {};
  }

  function compact(text, maxLength) {
    const value = String(text || '').replace(/\s+/g, ' ').trim();
    return value.length > maxLength ? value.slice(0, maxLength - 1) + '…' : value;
  }

  function appendFacts(base, facts) {
    const detail = facts.filter(Boolean).join('；');
    return detail ? `${base} 条目信息：${detail}。` : base;
  }

  // 电脑优化中心：按优化项 id 精确匹配，其次按所属分组，最后兜底
  function getOptimizer(item) {
    const cfg = scopeConfig('optimizer');
    const byId = cfg.byId || {};
    const byGroup = cfg.byGroup || {};
    const id = String((item && (item.id || item.optionId)) || '').trim();
    if (id && byId[id]) return { text: byId[id], level: 'item', label: '本项简介' };
    if (item && item.desc) return { text: String(item.desc), level: 'item', label: '本项简介' };
    const group = String((item && (item.group || item.category)) || '').trim();
    if (group && byGroup[group]) return { text: byGroup[group], level: 'group', label: group + '（分组简介）' };
    return { text: cfg.default || '', level: 'default', label: '通用说明' };
  }

  // 启动项管理：按名称关键字匹配，其次按来源（注册表/启动文件夹/计划任务），最后兜底
  function getStartup(item) {
    const cfg = scopeConfig('startup');
    const byName = cfg.byName || {};
    const bySource = cfg.bySource || {};
    const name = String((item && item.name) || '').toLowerCase();
    if (name) {
      const keys = Object.keys(byName);
      // 优先匹配最长的关键词，避免「QQ」被更短的通用词抢占
      keys.sort((a, b) => b.length - a.length);
      for (const key of keys) {
        if (name.includes(String(key).toLowerCase())) {
          return {
            text: appendFacts(byName[key], [
              item.publisher ? `发布者为 ${compact(item.publisher, 60)}` : '',
              item.enabled === false ? '当前已禁用' : item.enabled === true ? '当前已启用' : '',
              item.location ? `来源位置为 ${compact(item.location, 100)}` : ''
            ]),
            level: 'name',
            label: '本项简介'
          };
        }
      }
    }
    const source = String((item && item.source) || '').trim();
    const base = (source && bySource[source]) || cfg.default || '';
    return {
      text: appendFacts(base, [
        item.name ? `名称为 ${compact(item.name, 80)}` : '',
        item.publisher ? `发布者为 ${compact(item.publisher, 60)}` : '',
        item.enabled === false ? '当前已禁用' : item.enabled === true ? '当前已启用' : '',
        item.command ? `登录时执行 ${compact(item.command, 140)}` : '',
        item.location ? `来源位置为 ${compact(item.location, 100)}` : ''
      ]),
      level: source && bySource[source] ? 'source' : 'default',
      label: '条目简介'
    };
  }

  // 右键管理：按分类匹配，其次按是否第三方，最后兜底
  function getContextmenu(item) {
    const cfg = scopeConfig('contextmenu');
    const byCategory = cfg.byCategory || {};
    const category = String((item && item.category) || '').trim();
    const base = (category && byCategory[category]) || cfg.default || '';
    return {
      text: appendFacts(base, [
        item.name ? `菜单项为 ${compact(item.name, 80)}` : '',
        item.company ? `发布者为 ${compact(item.company, 60)}` : '',
        item.isThirdParty === true ? '属于第三方扩展' : item.isThirdParty === false ? '属于系统或已注册组件' : '',
        item.risk === 'protected' ? '受系统保护' : '',
        item.enabled === false ? '当前已禁用' : item.enabled === true ? '当前已启用' : '',
        (item.regPath || item.location) ? `注册位置为 ${compact(item.regPath || item.location, 120)}` : ''
      ]),
      level: category && byCategory[category] ? 'category' : 'default',
      label: '条目简介'
    };
  }

  // 内存清理：按区域 id 精确匹配，其次兜底
  function getMemoryclean(item) {
    const cfg = scopeConfig('memoryclean');
    const byId = cfg.byId || {};
    const id = String((item && (item.id || item.name)) || '').trim();
    if (id && byId[id]) return { text: byId[id], level: 'item', label: '本项简介' };
    return { text: cfg.default || '', level: 'default', label: '通用说明' };
  }

  function getLocal(scope, item) {
    if (scope === 'optimizer') return getOptimizer(item);
    if (scope === 'startup') return getStartup(item);
    if (scope === 'memoryclean') return getMemoryclean(item);
    return getContextmenu(item);
  }

  // 当前生效模型（统筹全局：读取「大模型管理」设置的全局模型，未取到时回落为「未选择」）
  async function currentModelName(scope) {
    try {
      if (window.api?.settings?.load) {
        const resp = await window.api.settings.load();
        const scopes = (resp && resp.data && resp.data.aiScopes) || {};
        const models = (resp && resp.data && resp.data.models) || {};
        const list = (resp && resp.data && resp.data.modelList) || [];
        const key = scopes.global || 'metaso';
        const meta = list.find(m => m.key === key);
        if (meta) return { key, name: meta.displayName || meta.label, enabled: !!meta.enabled, verified: !!meta.verified };
        const cfg = models[key] || {};
        const name = key === 'custom' ? (cfg.customName || '自定义模型')
          : key === 'baidu_pro' ? '百度千帆'
            : (cfg.label || key);
        return { key, name, enabled: !!cfg.enabled, verified: !!cfg.verified };
      }
    } catch (e) { /* 忽略 */ }
    return { key: 'metaso', name: '秘塔 AI', enabled: false, verified: false };
  }

  // ==================== 简介面板（三个模块共用） ====================
  // 行为：打开详情时只展示本地简介；联网 AI 简介必须再次点击「获取AI简介」才请求大模型。
  async function mountIntroPanel(opts) {
    const mount = opts && opts.mount;
    if (!mount) return;
    const scope = (opts && opts.scope) || 'contextmenu';
    const name = String((opts && opts.name) || '').trim();
    const company = String((opts && opts.company) || '').trim();
    const item = (opts && opts.item) || { name, company };

    await load();
    const local = getLocal(scope, item);

    mount.innerHTML = `
      <div class="intro-panel" data-scope="${escapeHtml(scope)}">
        <div class="intro-block intro-local">
          <div class="intro-block-head">
            <span class="intro-block-title">本地简介</span>
            <span class="intro-block-tag">离线内置 · ${escapeHtml(local.label)}</span>
          </div>
          <div class="intro-local-text">${escapeHtml(local.text || '暂无本地简介')}</div>
        </div>
        <div class="intro-block intro-ai">
          <div class="intro-block-head">
            <span class="intro-block-title">联网 AI 简介</span>
          </div>
          <div class="intro-ai-content" data-role="content">
            <div class="intro-ai-idle">点击「获取AI简介」后，由所选大模型生成本条目的联网简介</div>
          </div>
          <div class="intro-ai-actions">
            <button class="btn btn-secondary btn-small" data-role="fetch" type="button">获取AI简介</button>
            <button class="btn btn-secondary btn-small" data-role="pick" type="button">选择模型</button>
            <button class="btn btn-secondary btn-small" data-role="manage" type="button">去设置</button>
          </div>
        </div>
      </div>
    `;

    const contentEl = mount.querySelector('[data-role="content"]');
    const fetchBtn = mount.querySelector('[data-role="fetch"]');
    const pickBtn = mount.querySelector('[data-role="pick"]');
    const manageBtn = mount.querySelector('[data-role="manage"]');

    async function fetchAi(force) {
      if (!window.api?.aidesc) {
        contentEl.innerHTML = '<div class="intro-ai-fail">当前环境不支持联网 AI 简介</div>';
        return;
      }
      const modelInfo = await currentModelName(scope);
      // 该模块所选模型未启用/未验证 → 直接打开「大模型管理」独立窗口引导配置
      if (!modelInfo.enabled) {
        contentEl.innerHTML = `<div class="intro-ai-fail">该模块所选模型尚未启用，正在打开「大模型管理」设置…</div>`;
        if (window.api?.modelsWindow?.open) {
          window.api.modelsWindow.open();
        } else {
          window.app?.toast('warning', '请到「设置 - 大模型管理」中启用并保存模型');
        }
        return;
      }
      fetchBtn.disabled = true;
      fetchBtn.textContent = '获取中…';
      contentEl.innerHTML = '<div class="intro-ai-skeleton"><span></span><span></span></div>';
      try {
        const resp = await window.api.aidesc.get(name, company, !!force, scope);
        if (resp && resp.success && resp.data && resp.data.desc) {
          contentEl.innerHTML = `
            <div class="intro-ai-text">${escapeHtml(resp.data.desc)}</div>
            <div class="intro-ai-meta">来源：${escapeHtml(resp.data.source || modelInfo.name)}${resp.data.cached ? ' · 缓存' : ''}</div>`;
        } else if (resp && resp.message === 'disabled') {
          contentEl.innerHTML = `<div class="intro-ai-fail">「${escapeHtml(modelInfo.name)}」未启用，请在「设置 - 大模型管理」中启用后重试。</div>`;
        } else {
          contentEl.innerHTML = `
            <div class="intro-ai-fail">${escapeHtml((resp && resp.message) || '暂时无法获取该条目的简介')}</div>
            <button class="intro-ai-retry" data-role="retry" type="button">🔄 重新获取</button>`;
          contentEl.querySelector('[data-role="retry"]')?.addEventListener('click', () => fetchAi(true));
        }
      } catch (e) {
        contentEl.innerHTML = `<div class="intro-ai-fail">获取失败：${escapeHtml(e.message)}</div>`;
      } finally {
        fetchBtn.disabled = false;
        fetchBtn.textContent = '获取AI简介';
      }
    }

    fetchBtn.addEventListener('click', () => fetchAi(false));
    pickBtn.addEventListener('click', async () => {
      if (window.modelpicker && typeof window.modelpicker.open === 'function') {
        await window.modelpicker.open(scope);
      } else {
        window.app?.toast('warning', '模型选择暂不可用，请稍后重试');
      }
    });
    manageBtn.addEventListener('click', () => {
      if (window.api?.modelsWindow?.open) {
        window.api.modelsWindow.open();
      } else {
        window.app?.toast('warning', '当前环境不支持打开大模型管理窗口');
      }
    });
  }

  window.intro = { load, getLocal, getOptimizer, getStartup, getContextmenu, getMemoryclean, mountIntroPanel, currentModelName, SCOPE_LABEL };
})();

// pathbinding-material.js - 设置页「窗口材质」面
//
// 职责：材质卡片选中态 + 材质总开关（关闭 = 各窗口按「无材质」观感回落不透明，
// 所选材质保留、重开即恢复）+ 主进程材质广播跟随。
//
// 依赖：material / materialEnabled 的单一真源是 appearance.json（主进程持久化），
// 本面**不**读写 localStorage 镜像——材质键刻意不在外观偏好表里（C3 组的约束），
// 应用与广播都走 appearance:set-material / get-material 这条链。
(function () {
  'use strict';

  function init() {
    // 窗口材质五卡片：点击切换 + 高亮 + IPC 应用（即时生效并持久化）
    const materialCards = document.querySelectorAll('.material-card');
    function refreshMaterialCards(current) {
      materialCards.forEach(c => c.classList.toggle('selected', c.dataset.material === current));
    }
    // 材质总开关（窗口界面升级3，Motion.Lab toggle-flip 滑动开关）：
    // 关闭 = 各窗口即按「无材质」观感回落不透明；所选材质保留，重开即恢复
    const materialMaster = document.getElementById('materialMasterToggle');
    let materialOn = true;
    function syncMaterialMaster(on) {
      materialMaster?.classList.toggle('on', on);
      materialMaster?.setAttribute('aria-checked', on ? 'true' : 'false');
      materialMaster?.closest('.appearance-card')?.classList.toggle('material-off', !on);
    }
    // 审查 M-16（2026-10-03 L4）：role="switch" + tabindex="0" 承诺了可操作语义，
    // 唯一激活监听是 click ⇒ 键盘用户看得见焦点圈却按不动（M-11 同族漏网）。
    // Enter/Space 走同一 click 路径（overview.js 跳转卡同款）。
    materialMaster?.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      e.preventDefault();
      materialMaster.click();
    });
    materialMaster?.addEventListener('click', async () => {
      const next = !materialOn;
      materialOn = next;
      syncMaterialMaster(next);
      try {
        const resp = await window.api?.appearance?.setMaterialEnabled?.(next);
        if (resp && resp.success) {
          if (resp.material) document.body.dataset.material = resp.material;
          // 审查 2-4：material/materialEnabled 单一真源 = appearance.json（主进程持久化），
          // 不再镜像写入 localStorage（原双写导致两套存储可能漂移）
          window.app?.toast('success', next ? '窗口材质已开启' : '窗口材质已关闭（所选材质已记忆）');
        } else {
          materialOn = !next;
          syncMaterialMaster(materialOn);
          window.app?.toast('error', (resp && resp.message) || '材质开关切换失败');
        }
      } catch (e) {
        materialOn = !next;
        syncMaterialMaster(materialOn);
        window.app?.toast('error', '材质开关切换失败：' + e.message);
      }
    });
    // P2-5（v4）：此处原有第二个同效 keydown（Enter/Space → click），与上面带审查
    // 注释的那处重复登记 —— 同元素同事件双监听会让一次键盘激活跑两遍 click（净效果为零）。
    // 初始高亮以主进程持久化值为准（窗口实际材质），避免与 localStorage 不一致
    // 导致「选中项和窗口效果对不上」。取不到时回退 mica（与主进程默认一致）。
    (async () => {
      let current = 'mica-alt';
      try {
        const resp = await window.api?.appearance?.getMaterial?.();
        if (resp && resp.material) current = resp.material;
        materialOn = resp ? resp.materialEnabled !== false : true;
      } catch (e) {}
      // 「无材质」卡片已移除（设置页整合4）：存储值为 none 时与总开关关闭等价，按关闭态展示；
      // 不回写主进程，用户重开总开关或点选任一材质卡后自然覆盖
      if (current === 'none' && materialOn) materialOn = false;
      refreshMaterialCards(current);
      syncMaterialMaster(materialOn);
    })();
    // 主进程材质广播：所有窗口（含本窗）统一跟随，body[data-material] 实时驱动 CSS 分级
    // （广播载荷是「生效材质」：总开关关闭时为 'none'，此时卡片高亮保持用户所选值不变）
    window.api?.appearance?.onMaterialChanged?.((m) => {
      document.body.dataset.material = m;
      if (materialOn) refreshMaterialCards(m);
    });
    materialCards.forEach(card => {
      card.addEventListener('click', async () => {
        if (!materialOn) return; // 总开关关闭期间材质卡为暂停态
        const m = card.dataset.material;
        refreshMaterialCards(m);
        // IPC reject（通道异常/桥未就位）与 resp.success=false 必须走同一条回滚：
        // 只判 success 会让 reject 直接抛出、乐观高亮永远留着，选中态与窗口真实材质长期不一致
        let resp = null;
        try {
          resp = await window.api?.appearance?.setMaterial?.(m);
        } catch (e) {
          resp = { success: false, message: (e && e.message) || String(e) };
        }
        if (resp && resp.success) {
          // 同步材质标识到 body，CSS 据此做材质差异化着色
          document.body.dataset.material = m;
          // 审查 2-4：material 单一真源 = appearance.json，不再镜像写入 localStorage
          window.app?.toast('success', '窗口材质已切换：' + card.querySelector('.material-name')?.textContent);
        } else {
          // 失败回滚到主进程记录的真实材质
          try {
            const cur = await window.api?.appearance?.getMaterial?.();
            refreshMaterialCards((cur && cur.material) || 'mica-alt');
          } catch (e) {
            refreshMaterialCards('mica-alt');
          }
          window.app?.toast('error', (resp && resp.message) || '材质切换失败');
        }
      });
    });
  }

  window.pathbindingMaterial = { init };
})();

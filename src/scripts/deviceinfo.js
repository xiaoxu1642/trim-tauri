// 设置页设备信息展示与扫描
(function () {
  'use strict';
  const PREVIEW = {
    system: 'Windows 11 专业工作站版 64位 版本号 28000.2525',
    processor: 'AMD Ryzen 7 7800X3D 核心数 8 线程数 16 工艺 5 nm',
    graphics: 'NVIDIA GeForce RTX 5060 流处理器 3840 显存 8G (GDDR7 Micron)',
    motherboard: 'B650M-AYW WIFI ASUSTeK 芯片组 AMD B650',
    disks: 'Lexar SSD THOR PRO 1TB 实际容量 954GB 类型 SSD',
    monitors: 'SANC G41 分辨率 1920×1080 刷新率 320Hz 屏幕尺寸 24.3英寸',
    memory: 'Asgard DDR5-6000 (3000 MHz) 8GB；Asgard DDR5-6000 (3000 MHz) 8GB；容量 16 GB，通道 2，频率 6000 MHz，时序 28-38-38-38 1T'
  };

  function text(value) { return String(value ?? '').trim() || '--'; }
  // 💭1：硬件/固件字符串来自 WMI，虽非用户输入，仍按项目惯例转义后再进 innerHTML，保持一致与纵深。
  function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
  function render(data) {
    const rows = [
      ['系统', data.system], ['处理器', data.processor], ['显卡', data.graphics],
      ['主板', data.motherboard], ['硬盘', data.disks], ['显示器', data.monitors], ['内存', data.memory]
    ];
    const el = document.getElementById('deviceInfoRows');
    if (!el) return;
    el.innerHTML = rows.map(([label, value]) => `<div class="device-info-row"><span class="device-info-label">${label}</span><span class="device-info-value">${esc(text(value))}</span></div>`).join('');
    const status = document.getElementById('deviceInfoStatus');
    if (status) status.textContent = data.preview ? '已加载' : `已扫描 · ${new Date().toLocaleTimeString()}`;
  }

  function normalize(raw) {
    if (!raw) return { ...PREVIEW, preview: true };
    const join = (items, fn) => (items || []).map(fn).filter(Boolean).join('；');
    const os = raw.system || {};
    const cpu = raw.processor || {};
    const board = raw.motherboard || {};
    return {
      system: [os.caption, os.architecture, os.version ? `版本号 ${os.version}` : '', os.build ? `Build ${os.build}` : ''].filter(Boolean).join(' '),
      processor: [cpu.name, cpu.cores ? `核心数 ${cpu.cores}` : '', cpu.threads ? `线程数 ${cpu.threads}` : '', cpu.process ? `工艺 ${cpu.process}` : ''].filter(Boolean).join(' '),
      graphics: (() => {
        const gpus = raw.graphics || [];
        if (!gpus.length) return '--';
        // 默认只显示主力独显（优先 NVIDIA GeForce），隐藏虚拟显示适配器/核显
        const isVirtual = (name) => /Virtual|Basic Display|Remote Display|Microsoft 基本|虚拟|VirtIO/i.test(name || '');
        const primary = gpus.find(g => /NVIDIA.*GeForce/i.test(g.name || ''))
          || gpus.find(g => !isVirtual(g.name))
          || gpus[0];
        return [primary.name, primary.memory ? `显存 ${primary.memory}` : ''].filter(Boolean).join(' ');
      })(),
      motherboard: [board.product, board.manufacturer, board.chipset ? `芯片组 ${board.chipset}` : ''].filter(Boolean).join(' '),
      disks: join(raw.disks, d => [d.name, d.capacity ? `实际容量 ${d.capacity}` : '', d.media ? `类型 ${d.media}` : ''].filter(Boolean).join(' ')),
      monitors: (() => {
        const s = join(raw.monitors, m => [m.name, m.width && m.height ? `分辨率 ${m.width}×${m.height}` : '', m.refresh ? `刷新率 ${m.refresh}Hz` : '', m.size ? `屏幕尺寸 ${m.size}` : ''].filter(Boolean).join(' '));
        // F6（2026-09-15）：不再回填开发者机型——检测失败/仅读到通用名时如实显示 '--',
        // 避免把伪造的"显示器"当真机信息展示给用户（原兜底来自开发者本机 SANC G41）。
        return s;
      })(),
      memory: join(raw.memory, m => [m.manufacturer, m.part, m.capacity, m.speed ? `${m.speed} MHz` : ''].filter(Boolean).join(' ')),
      preview: false
    };
  }

  async function scan() {
    const status = document.getElementById('deviceInfoStatus');
    if (status) status.textContent = '扫描中...';
    try {
      // 手动扫描：强制刷新并更新缓存配置
      if (window.api?.overview?.hardware) {
        const response = await window.api.overview.hardware({ refresh: true });
        if (!response.success) throw new Error(response.message);
        render(normalize(response.data));
      } else if (window.api?.device) {
        const response = await window.api.device.scan();
        if (!response.success) throw new Error(response.message);
        render(normalize(response.data));
      } else {
        await new Promise(resolve => setTimeout(resolve, 500));
        render({ ...PREVIEW, preview: true });
      }
    } catch (error) {
      if (status) status.textContent = '扫描失败';
      window.app?.toast('error', `设备信息扫描失败：${error.message}`);
    }
  }

  async function init() {
    // 设置页「设备信息」板块已移除（系统概览页已展示硬件信息），
    // 本模块仅保留 normalize 供系统概览复用；首次进入概览时由 overview 拉取缓存。
    try {
      if (window.api?.overview?.hardware) {
        const resp = await window.api.overview.hardware({ refresh: false });
        if (resp && resp.success) {
          // 预热系统信息缓存，供 overview 硬件表格快速展示
        }
      }
    } catch (e) {}
  }
  window.deviceinfo = { init, scan, normalize };
})();

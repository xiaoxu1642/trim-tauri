// 设置页设备信息展示与扫描
(function () {
  'use strict';
  // F4c-L02：没有原始数据时不再回填开发者本机机型——那会把别人的硬件当成用户的设备展示。
  // 占位交给消费侧，normalize 只负责如实说「读不到」。
  const EMPTY = {
    system: '--', processor: '--', graphics: '--', motherboard: '--',
    disks: '--', monitors: '--', memory: '--'
  };

  // 💭1：硬件/固件字符串来自 WMI，虽非用户输入，仍按项目惯例转义后再进 innerHTML，保持一致与纵深。
  // P3-5（F4a-G-8 派生）：本文件曾有的 render/scan（引 deviceInfoRows/deviceInfoStatus）随
  // 「设置页设备信息板块移除」已成死代码 —— 那两个 id 全仓不存在、且 scan 零调用方，
  // 按「不留死代码」删净；本模块只剩 normalize 供系统概览复用 + init 预热缓存。

  function normalize(raw) {
    if (!raw) return { ...EMPTY, preview: true };
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

  async function init() {
    // 设置页「设备信息」板块已移除（系统概览页已展示硬件信息），本模块只剩 normalize 供概览复用
    // 与这条预热。预热不该打扰用户，但必须留排查痕迹——原先成功与失败同形（空 if 块 + 全静默
    // catch），概览硬件表空着时分不清「没预热成功」还是「后端本就没数据」。
    if (!window.api?.overview?.hardware) return;
    try {
      const resp = await window.api.overview.hardware({ refresh: false });
      if (resp && resp.success) window.app?.log?.('info', '设备信息缓存预热完成');
      else window.app?.log?.('warn', '设备信息缓存预热未成功：' + ((resp && resp.message) || '无回执'));
    } catch (e) {
      window.app?.log?.('warn', '设备信息缓存预热异常：' + ((e && e.message) || e));
    }
  }
  window.deviceinfo = { init, normalize };
})();

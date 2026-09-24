// netspeed-detector.js - 网络测速上传阶段结束判定（浏览器与 Node 测试共用）
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.netSpeedDetection = api;
})(typeof window !== 'undefined' ? window : globalThis, function () {
  'use strict';

  const MIB = 1024 * 1024;
  const DEFAULTS = Object.freeze({
    uploadBurstBps: 1 * MIB,
    uploadQuietBps: 256 * 1024,
    dropWindowMs: 2400,
    dropConfirmMs: 600,
    quietConfirmMs: 2400,
    minRecordingMs: 4000,
    minDropBps: 5 * MIB,
    maxDropBps: 10 * MIB,
    dropRatio: 0.4
  });

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function createUploadEndDetector(options) {
    const cfg = Object.assign({}, DEFAULTS, options || {});
    const state = {
      uploadSeen: false,
      uploadPeak: 0,
      recent: [],
      dropSince: 0,
      quietSince: 0
    };

    function update(sample) {
      const now = Number(sample?.time) || Date.now();
      const elapsed = Math.max(0, Number(sample?.elapsed) || 0);
      const up = Math.max(0, Number(sample?.up) || 0);
      const uploadStartedNow = !state.uploadSeen && up >= cfg.uploadBurstBps;

      if (uploadStartedNow) state.uploadSeen = true;
      state.uploadPeak = Math.max(state.uploadPeak, up);
      state.recent.push({ time: now, up });
      state.recent = state.recent.filter(point => now - point.time <= cfg.dropWindowMs);

      const recentPeak = state.recent.reduce((max, point) => Math.max(max, point.up), 0);
      const dropThreshold = clamp(recentPeak * cfg.dropRatio, cfg.minDropBps, cfg.maxDropBps);
      const largeDrop = state.uploadSeen &&
        elapsed >= cfg.minRecordingMs &&
        recentPeak >= cfg.minDropBps &&
        recentPeak - up >= dropThreshold &&
        up <= recentPeak * 0.5;

      if (largeDrop) {
        if (!state.dropSince) state.dropSince = now;
      } else {
        state.dropSince = 0;
      }

      const uploadQuiet = state.uploadSeen && elapsed >= cfg.minRecordingMs && up <= cfg.uploadQuietBps;
      if (uploadQuiet) {
        if (!state.quietSince) state.quietSince = now;
      } else {
        state.quietSince = 0;
      }

      const dropConfirmed = !!state.dropSince && now - state.dropSince >= cfg.dropConfirmMs;
      const quietConfirmed = !!state.quietSince && now - state.quietSince >= cfg.quietConfirmMs;

      return {
        finish: dropConfirmed || quietConfirmed,
        reason: dropConfirmed ? 'upload-drop' : quietConfirmed ? 'upload-quiet' : '',
        uploadStartedNow,
        uploadSeen: state.uploadSeen,
        uploadPeak: state.uploadPeak,
        recentPeak,
        dropThreshold
      };
    }

    return { update, state };
  }

  return { DEFAULTS, createUploadEndDetector };
});

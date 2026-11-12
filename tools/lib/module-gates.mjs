'use strict';
// tools/lib/module-gates.mjs —— 「按模块跑门禁」的挑选判据（纯函数）
//
// 为什么必须是纯函数：这条判据的失效形态是**静默少跑**（挑了少数几条却以为挑全了），
// 不像普通断言会当场红。所以它必须能被 check-positive-controls 用合成样本喂坏样本，
// 证明「基线缺失 / 指纹过期 / 读取面塌缩 / 全局门禁被漏挂」四种坏形态都判红。
//
// 判据（与 check-gate-roster 的 --emit-reads 产出一一对应）：
//   ① 基线里没有这条门禁（新门禁还没重算）=> 算全局，宁可多跑不可漏跑；
//   ② 门禁源码指纹对不上 => stale（映射可能已失效，调用方必须判红要求重算）；
//   ③ 读取面为空，或触及模块数 >= globalMin => 全局门禁，任何模块都跑；
//   ④ 读取面里出现模块表之外的 ID => stale（基线比模块表旧）；
//   ⑤ 每个模块的门禁集合 = 该模块专属 ∪ 全部全局（漏挂全局 = 该模块少跑守卫）。

/**
 * @param {{
 *   mustRun: string[],
 *   modules: Array<{id:string}>,
 *   reads: Record<string,string[]>,
 *   srcHash: Record<string,string>,
 *   hashOf: (name:string)=>string|null,
 *   globalMin: number,
 * }} input
 * @returns {{byModule: Map<string,string[]>, global: string[], stale: string[]}}
 */
export function buildModuleGates({ mustRun, modules, reads, srcHash, hashOf, globalMin }) {
  const stale = [];
  const global = [];
  const byModule = new Map(modules.map((m) => [m.id, []]));
  for (const name of mustRun) {
    const mods = reads?.[name];
    if (!Array.isArray(mods)) {
      global.push(name);
      continue;
    }
    if (srcHash?.[name] !== hashOf(name)) {
      stale.push(name);
      continue;
    }
    if (mods.length === 0 || mods.length >= globalMin) {
      global.push(name);
      continue;
    }
    const unknown = mods.filter((m) => !byModule.has(m));
    if (unknown.length) {
      stale.push(`${name}（基线里的模块 ${unknown.join('/')} 不在模块表）`);
      continue;
    }
    for (const m of mods) byModule.get(m).push(name);
  }
  for (const [m, list] of byModule) byModule.set(m, [...new Set([...list, ...global])]);
  return { byModule, global, stale };
}

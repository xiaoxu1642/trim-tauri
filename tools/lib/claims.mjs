'use strict';
// tools/lib/claims.mjs —— 审查单元「文件认领」唯一实现
//
// 为什么单独成模块：check-review-units（U1–U4 台账机检）与按模块跑门禁
// （check-gate-roster --module）必须用**同一份**认领结果。两份实现会漂移：
// 台账说某文件归 R3，模块映射说归别处，于是「按模块跑」静默漏掉该跑的门禁 ——
// 这正是本轮要消灭的假绿形态（AGENTS §4.1）。
//
// 语义（与 check-review-units 自 2026-10-09 起的口径逐字一致）：
//   - 认领根（AUDIT_ROOTS）先枚举出「可被认领的全部文件」；
//   - 单元按表内顺序**先到先得**：`files` 显式点名优先，`dirs` 只吃此前无人认领的文件；
//   - `generated` 只是「精读剔除清单」，不参与认领竞争。
import { readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';

import { walkFiles } from './fs-walk.mjs';

export const IGNORE_DIR = (n) => n === 'target' || n === 'node_modules' || n === 'vendor' || n === '.git';
export const norm = (p) => p.replace(/\\/g, '/');

/**
 * 枚举认领根下的全部文件。
 * @param {string} root 仓库根
 * @param {Array<{dir?:string,file?:string,ext?:string[],depth?:number}>} auditRoots
 * @returns {{files:Set<string>, rootCounts:Record<string,number>, rootLabels:string[]}}
 */
export function collectAuditFiles(root, auditRoots) {
  const rootCounts = {};
  const files = new Set();
  const rootLabels = [];
  for (const r of auditRoots) {
    if (r.file) {
      const label = r.file;
      rootLabels.push(label);
      const n = existsSync(join(root, r.file)) ? 1 : 0;
      rootCounts[label] = n;
      if (n) files.add(r.file);
      continue;
    }
    const abs = join(root, r.dir);
    const label = `${r.dir}${r.ext ? ' *' + r.ext.join(',') : ''}${r.depth ? ' (直属)' : ''}`;
    rootLabels.push(label);
    if (!existsSync(abs) || !statSync(abs).isDirectory()) {
      rootCounts[label] = 0;
      continue;
    }
    let list;
    if (r.depth === 1) {
      list = readdirSync(abs, { withFileTypes: true })
        .filter((e) => e.isFile() && (!r.ext || r.ext.some((x) => e.name.endsWith(x))))
        .map((e) => norm(join(relative(root, abs), e.name)));
    } else {
      list = walkFiles(abs, (n) => !r.ext || r.ext.some((x) => n.endsWith(x)), { ignoreDir: IGNORE_DIR })
        .map((p) => norm(relative(root, p)));
    }
    rootCounts[label] = list.length;
    for (const f of list) files.add(f);
  }
  return { files, rootCounts, rootLabels };
}

/** 单个 `dirs` 认领项展开成文件清单（含 onlyPrefix / notPrefix 过滤）。 */
function expandDirClaim(root, d) {
  const abs = join(root, d.dir);
  if (!existsSync(abs)) return [];
  let list;
  if (d.depth === 1) {
    list = readdirSync(abs, { withFileTypes: true })
      .filter((e) => e.isFile() && (!d.ext || d.ext.some((x) => e.name.endsWith(x))))
      .map((e) => norm(join(relative(root, d.dir), e.name)));
  } else {
    list = walkFiles(abs, (n) => !d.ext || d.ext.some((x) => n.endsWith(x)), { ignoreDir: IGNORE_DIR })
      .map((p) => norm(relative(root, p)));
  }
  return list.filter((f) => {
    if (d.onlyPrefix && !f.split('/').pop().startsWith(d.onlyPrefix)) return false;
    const nps = Array.isArray(d.notPrefix) ? d.notPrefix : d.notPrefix ? [d.notPrefix] : [];
    return !nps.some((np) => f.split('/').pop().startsWith(np));
  });
}

/**
 * 按单元表做先到先得认领。
 * @returns {{ownerOf:Map<string,string>, unitsWithClaims:Array}}
 */
export function claimUnits({ root, units, auditFiles }) {
  const ownerOf = new Map();
  const unitsWithClaims = units.map((u) => {
    const claimed = [];
    for (const f of u.files ?? []) {
      if (!auditFiles.has(f)) continue;
      if (ownerOf.has(f)) continue;
      ownerOf.set(f, u.id);
      claimed.push(f);
    }
    const dirClaimed = [];
    for (const d of u.dirs ?? []) {
      for (const f of expandDirClaim(root, d)) {
        if (ownerOf.has(f)) continue;
        ownerOf.set(f, u.id);
        claimed.push(f);
        dirClaimed.push(f);
      }
    }
    return { ...u, claimed, dirClaims: [dirClaimed] };
  });
  return { ownerOf, unitsWithClaims };
}

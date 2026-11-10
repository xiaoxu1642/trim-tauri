#!/usr/bin/env node
// check-material-parity.mjs —— 材质枚举 ⇄ 设置页卡片 ⇄ 总开关关闭态（R6b-L24）
'use strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPO_ROOT } from './ps-origin.mjs';

const rust = readFileSync(join(REPO_ROOT, 'src-tauri/src/engine/appearance.rs'), 'utf8');
const html = readFileSync(join(REPO_ROOT, 'src/index.html'), 'utf8');
const js = readFileSync(join(REPO_ROOT, 'src/scripts/pathbinding-material.js'), 'utf8');

const list = (() => {
    const m = /pub\(crate\) const MATERIALS:[^=]*=\s*&\[([^\]]+)\]/.exec(rust);
    if (!m) return null;
    return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
})();
const cards = [...html.matchAll(/class="material-card" data-material="([^"]+)"/g)].map((m) => m[1]);
const badCards = html.replace('data-material="mica"', 'data-material="mica-extra"');
const badNone = js.replace("current === 'none' && materialOn", "current === 'other' && materialOn");
const badEnum = rust.replace('"thin-acrylic", "none"', '"thin-acrylic", "extra", "none"');
const check = (ok, label) => {
    if (!ok) {
        console.error(`✗ ${label}`);
        process.exit(1);
    }
};
const judgeAll = (rustSrc, htmlSrc, jsSrc) => {
    const m = /pub\(crate\) const MATERIALS:[^=]*=\s*&\[([^\]]+)\]/.exec(rustSrc);
    const materials = m ? [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]) : [];
    const cardSet = [...htmlSrc.matchAll(/class="material-card" data-material="([^"]+)"/g)].map((x) => x[1]);
    const selectable = materials.filter((x) => x !== 'none');
    const same = selectable.length === cardSet.length
        && selectable.every((x) => cardSet.includes(x))
        && cardSet.every((x) => selectable.includes(x));
    return same
        && jsSrc.includes("current === 'none' && materialOn")
        && jsSrc.includes('materialOn = false');
};
check(judgeAll(rust, html, js), '材质枚举、卡片集合或 none 等价开关不一致');
check(!judgeAll(rust, badCards, js), '改动卡片集合必须判红');
check(!judgeAll(rust, html, badNone), '删除 none 等价语义必须判红');
check(!judgeAll(badEnum, html, js), '新增枚举项必须判红');
console.log(`✓ 材质枚举去掉 none 后与 ${cards.length} 张卡片一致，none 与总开关关闭态等价`);

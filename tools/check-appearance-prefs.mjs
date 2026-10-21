// uE-gate.snippet.mjs —— P1-W3 单元代理交付的门禁片段（覆盖 R6b-L07 渲染层半边 + F4a1-M08）
//
// 合并目标：tools/check-appearance-prefs.mjs（无扩展名写法 tools/check-appearance-prefs 注册进
// check-gate-roster.mjs 的 MUST_RUN 表；本片段自带目录遍历，合并后可换用 lib/fs-walk.mjs）。
//
// 抓什么（两组、每组都能判红）：
//  A 组「bgOpacity → 雾化」换算的跨语言口径对拍（R6b-L07）
//    同一判定在两处各有一份实现：Rust 侧 bg_opacity_to_fog 与渲染层 bgOpacityToFog。
//    跨语言不能共享函数（AGENTS §5.16），只能把两侧表达式的**结构签名**（取反基数 +
//    取整口径 + 非数值跳过 + 防重复标记）拿来对拍；任一侧单独改动即红。
//    以前只有 Rust 带取整、渲染层不取整且走 JS 强转，两次迁移叠加后落盘值会分叉。
//  B 组「保护层偏好」的真源对拍（F4a1-M08）
//    渲染层里以 *_BACKEND_KEY 常量声明的键必须逐个出现在 settings.rs 的 PREF_KEYS 白名单里
//    （漏一个的症状是 setPref 永远返回「未知的偏好键」，开关静默回到默认）；
//    同时钉住「老 localStorage 键仍在、但只作镜像」：老键被删 = 存量用户这项状态直接断链，
//    执行侧改成直读 localStorage = 真源又退回镜像（本条红线）。
//
// 判红验证（本片段的路径开关就是为破坏自测准备的：src-tauri/** 不许单元代理改，
// 所以把 Rust / settings.rs 拷到盘外改掉再指回来；JS 侧同理）：
//   ① Rust 侧把 (100.0 - opacity).round() 的 .round() 删掉 → A 组「取整口径」判红；
//   ② Rust 侧把基数 100.0 改成 99.0 → A 组「基数」判红；
//   ③ JS 侧把 bgOpacityToFog 简化成 return Math.round(100 - opacity); → A 组「取整口径」判红；
//   ④ JS 侧删掉 bgOpacityToFog 整个函数 → A 组「取不到换算体」判红；
//   ⑤ settings.rs 的 PREF_KEYS 里删掉 uninstallRestorePoint → B 组白名单对拍判红；
//   ⑥ uninstall.js 里删掉老键字面量 trim.uninstall.restorePoint → B 组「镜像仍在」判红；
//   ⑦ uninstall.js 里把 readRestorePref 改回直读 localStorage → B 组「执行侧不读镜像」判红。
//
// 用法：node tools/check-appearance-prefs.mjs
//      （盘外破坏自测：node uE-gate.snippet.mjs --rust <副本.rs> --js <副本.js>）
'use strict';

import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// 仓库根：从本文件所在位置向上找到第一个含 src-tauri/Cargo.toml 的目录。
// 不硬编码绝对路径，也不假设本片段一定躺在 tools/ 下（交付期在日志目录里自测）。
const REPO = (() => {
  let d = dirname(fileURLToPath(import.meta.url));
  while (true) {
    if (existsSync(join(d, 'src-tauri', 'Cargo.toml'))) return d;
    const up = dirname(d);
    if (up === d) throw new Error('找不到仓库根（向上没有 src-tauri/Cargo.toml）');
    d = up;
  }
})();

let failures = 0;
const hits = [];
const ok = (msg) => { hits.push(msg); console.log(`  ✓ ${msg}`); };
const bad = (msg) => { failures += 1; console.error(`  ✗ ${msg}`); };

const argPath = (flag, rel) => {
  const i = process.argv.indexOf(flag);
  if (i < 0) return join(REPO, ...rel.split('/'));
  const p = process.argv[i + 1];
  if (!p) throw new Error(`${flag} 后面缺少路径`);
  return p;
};

function readRequired(label, path) {
  if (!existsSync(path)) {
    bad(`${label} 读不到：${path}（路径开关给错，或该文件已不在）`);
    return null;
  }
  return readFileSync(path, 'utf8');
}

// 截一个函数体：从锚点正则命中处往后到第一个「行首 closeAt」为止。
// 前提（踩过才写）：Rust 顶层 fn 的收尾花括号在第 0 列，JS 模块内的收尾在第 2 列；
// 两侧被截的函数体里都不存在「行首就一个 }」的字符串——Rust 的 format! 里那个 {e}
// 不在行首，naive 计数反而会被它带偏，所以不用花括号配对、用行首收尾标记。
function sliceFn(text, anchorRe, closeAt, label) {
  const m = anchorRe.exec(text);
  if (!m) {
    bad(`${label} 没找到（${anchorRe.source}）——函数被改名/删除/挪走都会断对拍，此处判红`);
    return null;
  }
  const end = text.indexOf(closeAt, m.index);
  if (end < 0) {
    bad(`${label} 找到了但截不到函数体（收尾括号形态变了，行首 ${JSON.stringify(closeAt)}）`);
    return null;
  }
  return text.slice(m.index, end);
}

// ── A 组：bgOpacity → 雾化 换算的跨语言口径对拍 ──────────────────────────────
const RS_APPEARANCE = argPath('--rust', 'src-tauri/src/engine/appearance.rs');
const JS_PATHBINDING = argPath('--js', 'src/scripts/pathbinding.js');

function normalizeSpaces(s) { return s.replace(/\s+/g, ' ').trim(); }

// Rust：`(100.0 - opacity).round()` ⇄ JS：`const d = 100 - opacity;` + 半值远离 0 的取整
// round 口径三个档位：half-away-from-zero（两侧一致的唯一合法解）/ half-up / none。
function specFromRust(body, label) {
  const t = normalizeSpaces(body);
  const withRound = /\(\s*(\d+(?:\.\d+)?)\s*-\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\.\s*(round|trunc|floor|ceil)\s*\(\s*\)/.exec(t);
  if (withRound) {
    return {
      label, base: Number(withRound[1]), operand: withRound[2], direction: 'base-minus-param',
      round: withRound[3] === 'round' ? 'half-away-from-zero' : `rust-${withRound[3]}`, src: withRound[0],
    };
  }
  const bare = /\(\s*(\d+(?:\.\d+)?)\s*-\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)/.exec(t);
  if (bare) return { label, base: Number(bare[1]), operand: bare[2], direction: 'base-minus-param', round: 'none', src: bare[0] };
  const reversed = /\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*-\s*(\d+(?:\.\d+)?)\s*\)/.exec(t);
  if (reversed) return { label, base: Number(reversed[2]), operand: reversed[1], direction: 'param-minus-base', round: 'none', src: reversed[0] };
  return null;
}

function specFromJs(body, label) {
  const t = normalizeSpaces(body);
  const sub = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(\d+(?:\.\d+)?)\s*-\s*([A-Za-z_$][\w$]*)\s*;/.exec(t);
  if (sub) {
    const temp = sub[1];
    const away = new RegExp(`${temp}\\s*<\\s*0\\s*\\?\\s*-\\s*Math\\.round\\(\\s*-${temp}\\s*\\)\\s*:\\s*Math\\.round\\(\\s*${temp}\\s*\\)`).exec(t);
    const halfUp = new RegExp(`Math\\.round\\(\\s*${temp}\\s*\\)`).exec(t);
    return {
      label, base: Number(sub[2]), operand: sub[3], direction: 'base-minus-param',
      round: away ? 'half-away-from-zero' : (halfUp ? 'half-up' : 'none'), src: sub[0],
    };
  }
  const inline = /Math\.round\(\s*(\d+(?:\.\d+)?)\s*-\s*([A-Za-z_$][\w$]*)\s*\)/.exec(t);
  if (inline) return { label, base: Number(inline[1]), operand: inline[2], direction: 'base-minus-param', round: 'half-up', src: inline[0] };
  const bare = /(\d+(?:\.\d+)?)\s*-\s*([A-Za-z_$][\w$]*)/.exec(t);
  if (bare) return { label, base: Number(bare[1]), operand: bare[2], direction: 'base-minus-param', round: 'none', src: bare[0] };
  return null;
}

const appearanceRs = readRequired('引擎侧外观模块', RS_APPEARANCE);
const pathbindingJs = readRequired('渲染层设置页脚本', JS_PATHBINDING);

if (appearanceRs && pathbindingJs) {
  const rustFogBody = sliceFn(appearanceRs, /pub fn bg_opacity_to_fog/, '\n}', 'Rust 侧雾化换算函数');
  const jsFogBody = sliceFn(pathbindingJs, /function bgOpacityToFog/, '\n  }', '渲染层雾化换算函数');
  const rustSpec = rustFogBody ? specFromRust(rustFogBody, 'rust') : null;
  const jsSpec = jsFogBody ? specFromJs(jsFogBody, 'js') : null;

  if (!rustSpec) bad('R6b-L07 对拍取不到 Rust 侧换算表达式（口径已不再是「基数 − 入参」再取整）');
  if (!jsSpec) bad('R6b-L07 对拍取不到渲染层换算表达式（换算被内联回迁移函数或改了形态）');

  if (rustSpec && jsSpec) {
    if (rustSpec.base === jsSpec.base && rustSpec.base === 100) {
      ok(`A1 取反基数两侧一致且为 100：Rust ${rustSpec.src} ⇄ JS ${jsSpec.src}`);
    } else {
      bad(`A1 取反基数分叉：Rust ${rustSpec.base} / JS ${jsSpec.base}（雾化语义的基数必须是 100）`);
    }
    if (rustSpec.direction === 'base-minus-param' && jsSpec.direction === 'base-minus-param') {
      ok('A2 取反方向两侧一致（基数 − 旧值，不是旧值 − 基数）');
    } else {
      bad(`A2 取反方向分叉：Rust ${rustSpec.direction} / JS ${jsSpec.direction}`);
    }
    if (rustSpec.round === jsSpec.round && rustSpec.round === 'half-away-from-zero') {
      ok('A3 取整口径两侧一致（半值远离 0 的取整；Rust 用 .round()，JS 必须带负半值守卫）');
    } else {
      bad(`A3 取整口径分叉：Rust ${rustSpec.round} / JS ${jsSpec.round}（两侧不同步改，两次迁移叠加就会分叉）`);
    }
  }

  // 非数值：Rust 走 as_f64 取不到即不迁移，渲染层必须走 Number.isFinite（不是 != null 的 JS 强转）
  const rustMigrateBody = sliceFn(appearanceRs, /pub fn migrate_bg_opacity_fog/, '\n}', 'Rust 侧雾化迁移入口');
  const jsMigrateBody = sliceFn(pathbindingJs, /function migrateBgOpacityToFog/, '\n  }', '渲染层雾化迁移入口');
  if (rustMigrateBody && jsMigrateBody) {
    const rustSkips = /\.as_f64\(\)/.test(rustMigrateBody) && /\.is_some\(\)/.test(rustMigrateBody);
    const jsSkips = /Number\.isFinite\(/.test(jsMigrateBody);
    const jsCoerce = /!=\s*null\s*\)?\s*[\w.]+\s*=\s*100\s*-/.test(jsMigrateBody);
    if (rustSkips && jsSkips && !jsCoerce) {
      ok('A4 非数值两侧同口径：Rust as_f64 取不到即跳过 ⇄ 渲染层 Number.isFinite 守卫（无 JS 强转残留）');
    } else {
      bad(`A4 非数值口径分叉：Rust 跳过判定=${rustSkips} / 渲染层数值守卫=${jsSkips} / 渲染层强转残留=${jsCoerce}` +
        `（强转会把字符串洗成 NaN 再序列化成 null）`);
    }
    if (/bgOpacityFog/.test(rustMigrateBody) && /bgOpacityFog\s*=\s*true/.test(jsMigrateBody)) {
      ok('A5 防重复标记两侧都在：Rust 写 bgOpacityFog ⇄ 渲染层置 bgOpacityFog = true');
    } else {
      bad('A5 防重复标记缺一侧（丢了的后果是同一条换算被重复执行，值被再取反一遍）');
    }
  }
  // 渲染层内部也不许再有第二份换算（否则 A 组对拍只钉住了两份里的一份）
  if (/100\s*-\s*ap2?\.bgOpacity/.test(pathbindingJs)) {
    bad('A6 渲染层出现内联的第二份换算（100 − ap.bgOpacity），换算必须只走 bgOpacityToFog');
  } else {
    ok('A6 渲染层换算只有一份：bgOpacityToFog（内联 100 − ap.bgOpacity 命中 0 处）');
  }
}

// ── B 组：保护层偏好的真源对拍（老键作镜像）────────────────────────────────
const SETTINGS_RS = argPath('--settings', 'src-tauri/src/commands/settings.rs');
const JS_UNINSTALL = argPath('--uninstall', 'src/scripts/uninstall.js');
const settingsRs = readRequired('设置命令层', SETTINGS_RS);
const uninstallJs = readRequired('卸载页脚本', JS_UNINSTALL);

// 后端白名单键集合
function extractPrefKeys(text) {
  const m = /const\s+PREF_KEYS\s*:\s*&\[&str\]\s*=\s*&\s*\[([\s\S]*?)\]/.exec(text);
  if (!m) {
    bad('B0 从 settings.rs 截不到 PREF_KEYS 数组（形态变了 ⇒ 白名单对拍会假绿，判红）');
    return null;
  }
  const keys = [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
  if (!keys.length) { bad('B0 PREF_KEYS 抽到 0 个键（正则命中空表 ⇒ 对拍无意义，判红）'); return null; }
  ok(`B1 PREF_KEYS 现算命中 ${keys.length} 个键：${keys.join(' / ')}`);
  return keys;
}

// 渲染层声明的后端键（*_BACKEND_KEY 常量）——每个都必须被白名单放行
function walkJs(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (name === 'node_modules' || name === 'vendor') continue;
    if (statSync(p).isDirectory()) walkJs(p, out);
    else if (name.endsWith('.js')) out.push(p);
  }
  return out;
}

if (settingsRs && uninstallJs) {
  const prefKeys = extractPrefKeys(settingsRs);
  if (prefKeys) {
    if (prefKeys.includes('uninstallRestorePoint')) {
      ok('B2 卸载前还原点开关的后端键已在白名单里：uninstallRestorePoint（真源 settings.json）');
    } else {
      bad('B2 白名单缺 uninstallRestorePoint ⇒ setPref 恒返回「未知的偏好键」，开关退回「清一次存储就丢」');
    }
    const declared = [];
    for (const f of walkJs(join(REPO, 'src', 'scripts'))) {
      const text = f === JS_UNINSTALL ? uninstallJs : readFileSync(f, 'utf8');
      for (const m of text.matchAll(/(?:const|let|var)\s+([A-Za-z0-9_]*BACKEND_KEY[A-Za-z0-9_]*)\s*=\s*'([^']+)'/g)) {
        declared.push({ file: f, name: m[1], key: m[2] });
      }
    }
    if (!declared.length) {
      bad('B3 渲染层一个 *_BACKEND_KEY 常量都没命中 ⇒ 后端键已退回字面量或改了命名，白名单对拍失去对象（判红防假绿）');
    } else {
      const orphans = declared.filter((d) => !prefKeys.includes(d.key));
      if (orphans.length) {
        for (const o of orphans) bad(`B3 渲染层声明的后端键不在 PREF_KEYS 白名单：${o.key}（${o.name}）`);
      } else {
        ok(`B3 渲染层声明的 ${declared.length} 个后端键逐个命中白名单：${declared.map((d) => `${d.name}=${d.key}`).join(' / ')}`);
      }
    }
  }

  // 老键仍在（镜像 + 存量兜底），但执行侧不得再直读镜像
  if (/['"]trim\.uninstall\.restorePoint['"]/.test(uninstallJs)) {
    ok('B4 老 localStorage 键 trim.uninstall.restorePoint 仍在（作镜像与存量兜底，迁移完成前不得删）');
  } else {
    bad('B4 老键被删：存量用户的「卸载前建还原点」状态只存在那儿，删掉即静默回到关');
  }

  const readBody = sliceFn(uninstallJs, /function readRestorePref/, '\n  }', '卸载页还原点读取入口');
  if (readBody) {
    const readsLs = /localStorage\.getItem/.test(readBody);
    if (!readsLs && /return\s+restorePref\s*===\s*true/.test(readBody)) {
      ok('B5 执行侧判定走合并后的状态位 restorePref（后端优先、老键只作兜底初值），不在执行路径直读 localStorage');
    } else {
      bad(`B5 执行侧又直读镜像（readRestorePref 体内 localStorage.getItem=${readsLs}）⇒ 真源退回 localStorage，F4a1-M08 复发`);
    }
  }

  const writeBody = sliceFn(uninstallJs, /function writeRestorePref/, '\n  }', '卸载页还原点写入入口');
  if (writeBody) {
    const both = /localStorage\.setItem\(\s*RESTORE_PREF_KEY/.test(writeBody)
      && /setPref\?\.\(\s*RESTORE_PREF_BACKEND_KEY/.test(writeBody);
    if (both) ok('B6 写路径两边都写：老键镜像 + setPref 后端真源（只写一边的话另一边会在下次启动覆盖用户选择）');
    else bad('B6 写路径缺一边（localStorage 镜像 或 setPref 真源）⇒ 两边下次启动互相覆盖');
  }

  const syncBody = sliceFn(uninstallJs, /\(async function syncRestorePref/, '\n  })', '卸载页后端真源回读');
  if (syncBody) {
    const hasAdopt = /getPrefs\?\.\(/.test(syncBody) && /typeof\s+v\s*===\s*'boolean'/.test(syncBody);
    const hasMigrate = /writeRestorePref\(/.test(syncBody);
    if (hasAdopt && hasMigrate) ok('B7 后端优先回读在位：getPrefs 采纳 boolean 真源 + 后端未设置时把本地现值迁移上去');
    else bad(`B7 真源回读不完整（采纳=${hasAdopt} 迁移=${hasMigrate}）⇒ 后端值不覆盖镜像，等于没迁`);
  }
}

console.log(`\ncheck-appearance-prefs: 命中断言 ${hits.length} 条，失败 ${failures} 条`);
if (failures) { console.error('check-appearance-prefs: 判红'); process.exit(1); }
console.log('check-appearance-prefs: 全部通过');
process.exit(0);

'use strict';
// tools/lib/src-scan.mjs —— 门禁用的「把非代码区域抹成空格」共享件
//
// 为什么必须有它：本轮审查确证过两类假绿——
//   ① `check-comment-rot` R3c 只验「文件存在 + 行号不越界」，注释里写的坐标内容对不对没人管；
//   ② 新门禁 `check-delete-root-guard` 的判据若是「文件里出现过 inspect_root 就算过」，
//      那么注释或字符串里提一句就永远绿（`check-native-hygiene` N4 也栽在行号口径上）。
// 所以判据必须作用在**只剩代码**的文本上。本模块的做法是「等长抹除」而不是「删行」：
// 长度与换行数一一对应，命中位置仍是原文件的真实偏移，行号可以直接算，不必二次映射。
//
// 抹除范围：行注释、块注释（Rust 块注释可嵌套，JS 不嵌套也按同一实现走，宁可多抹）、
// 普通字符串、Rust 原始字符串 r#"…"#、JS 模板字符串（含 `${}` 内插递归）、Rust 字符字面量。
// Rust 生命周期 `'a` 不算字符字面量：只在「同一段内闭合且长度合理」时才抹，避免把整行误抹。

/** 把注释与字符串字面量抹成空格（等长）。@param {string} text @param {'rs'|'js'} lang */
export function blankNonCode(text, lang = 'rs') {
  const out = text.split('');
  const blank = (from, to) => {
    for (let i = from; i < to && i < out.length; i++) if (out[i] !== '\n' && out[i] !== '\r') out[i] = ' ';
  };
  const isRs = lang === 'rs';
  let i = 0;
  const n = text.length;
  // JS 正则字面量的上下文判据：`/` 到底是「新正则开头」还是「除号/注释」。
  // 没有这一条时，`!/^https?:\/\//i.test(x)` 里的 `//`（其实是转义斜杠的一部分）会被当成
  // 行注释，把该行后半段（含结尾的 `{`）一起抹掉 ⇒ 后面的 `}` 变成「多出来的闭合括号」，
  // skipBraces 提前收口，函数体被切短 —— 真实存在的 `try` 就此看不见（B3 在
  // `check-async-exits` 上实测到，models-window.js 的保存 handler 被误报成无出口）。
  const REGEX_PREV = '(,=:[!&|?{;+-*/%^~<>';
  const KEYWORD_BEFORE = /(?:^|[^\w$])(return|typeof|case|in|of|new|delete|void|instanceof|do|else|yield|await)\s*$/;
  // 前一个「有意义字符」：随扫描推进，不回头找 —— 回头扫会被抹白的字符串/注释骗过
  // （`x = "abc" / 2` 的 `/` 前面会被看成 `=`，于是把除号当正则起点，抹掉一片真代码）。
  let prev = '';
  const regexCouldStart = () => {
    if (!prev) return true;
    if (/[0-9a-zA-Z_$]/.test(prev)) return KEYWORD_BEFORE.test(text.slice(0, i));
    if (prev === ')' || prev === ']' || prev === '}') return false; // 值结尾，这是除号
    return REGEX_PREV.includes(prev);
  };
  while (i < n) {
    const c = text[i], d = text[i + 1];
    if (!isRs && c === '/' && d !== '/' && d !== '*' && regexCouldStart()) {
      let j = i + 1, inClass = false, closed = false;
      while (j < n) {
        const e = text[j];
        if (e === '\\') { j += 2; continue; }
        if (e === '\n') break; // 正则字面量不跨行
        if (inClass) { if (e === ']') inClass = false; j++; continue; }
        if (e === '[') { inClass = true; j++; continue; }
        if (e === '/') { j++; closed = true; break; }
        j++;
      }
      if (closed) {
        while (j < n && /[dgimsuyv]/.test(text[j])) j++; // 标志位
        blank(i, j); i = j; prev = '/'; continue;
      }
    }
    if (c === '/' && d === '/') {
      let j = i; while (j < n && text[j] !== '\n') j++;
      blank(i, j); i = j; continue;
    }
    if (c === '/' && d === '*') {
      let j = i + 2, depth = 1;
      while (j < n && depth > 0) {
        if (isRs && text[j] === '/' && text[j + 1] === '*') { depth++; j += 2; continue; }
        if (text[j] === '*' && text[j + 1] === '/') { depth--; j += 2; continue; }
        j++;
      }
      blank(i, Math.min(j, n)); i = j; continue;
    }
    // Rust 原始字符串：r"..." / r#"..."#（可多个 #）
    if (isRs && c === 'r' && /["#]/.test(d || '')) {
      let k = i + 1, hashes = 0;
      while (text[k] === '#') { hashes++; k++; }
      if (text[k] === '"') {
        const close = '"' + '#'.repeat(hashes);
        const at = text.indexOf(close, k + 1);
        const end = at < 0 ? n : at + close.length;
        blank(i, end); i = end; prev = '"'; continue;
      }
    }
    if (c === '"') {
      let j = i + 1;
      while (j < n) { if (text[j] === '\\') { j += 2; continue; } if (text[j] === '"') { j++; break; } if (text[j] === '\n' && !isRs) break; j++; }
      blank(i, j); i = j; prev = '"'; continue;
    }
    if (!isRs && c === '`') {
      let j = i + 1;
      while (j < n) {
        if (text[j] === '\\') { j += 2; continue; }
        if (text[j] === '${') { const inner = skipBraces(text, j + 1); j = inner; continue; }
        if (text[j] === '`') { j++; break; }
        j++;
      }
      blank(i, j); i = j; prev = '`'; continue;
    }
    if (isRs && c === "'") {
      const m = /^'(?:\\.|[^'\\\n]){1,2}'/.exec(text.slice(i, i + 8));
      if (m) { blank(i, i + m[0].length); i += m[0].length; prev = "'"; continue; }
    }
    if (!/\s/.test(c)) prev = c;
    i++;
  }
  return out.join('');
}

/** 从 `{` 处往后配平，返回闭合后的下标（找不到就返回文本末尾）。 */
export function skipBraces(text, open) {
  let depth = 0;
  for (let j = open; j < text.length; j++) {
    if (text[j] === '{') depth++;
    else if (text[j] === '}') { depth--; if (depth === 0) return j + 1; }
  }
  return text.length;
}

/**
 * 切函数：返回 `[{ name, start, bodyStart, end, sigLine }]`，区间是**原文**偏移。
 * 判定作用在 blankNonCode 之后的文本上，所以注释里写一句 `fn 名字` 不会被当成函数。
 */
export function splitFunctions(code, lang = 'rs') {
  const blanked = blankNonCode(code, lang);
  const pat = lang === 'rs'
    ? /\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+|unsafe\s+|extern\s+"[^"]*"\s+)*fn\s+([A-Za-z0-9_]+)/g
    : /\b(?:async\s+)?function\s*([A-Za-z0-9_$]*)\s*\(|\b([A-Za-z0-9_$]+)\s*:\s*(?:async\s*)?\(?[^)]*\)\s*=>/g;
  const out = [];
  let m;
  while ((m = pat.exec(blanked))) {
    const name = (m[1] || m[2] || '').trim() || '(匿名)';
    const open = blanked.indexOf('{', m.index + m[0].length);
    if (open < 0) continue;
    const end = skipBraces(blanked, open);
    out.push({
      name,
      start: m.index,
      bodyStart: open + 1,
      end,
      sigLine: code.slice(0, m.index).split('\n').length,
    });
  }
  return out;
}

/** 偏移 → 1 起的行号。 */
export function lineAt(text, offset) {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i++) if (text[i] === '\n') line++;
  return line;
}

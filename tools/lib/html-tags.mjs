// tools/lib/html-tags.mjs —— 前端 HTML 标签解析的单一实现（T1d-L02）
//
// 此前三条门禁各写一份：check-first-paint 认 src 在前的 <script>、check-subwindow-css
// 认 rel="stylesheet" 在前的 <link>、check-a11y 认 href 在前的 <link>。写法一变就
// 有一处失明。这里只做「取标签 → 取属性」两件事，判定仍由各门禁自己写。

const stripComments = (html) => html.replace(/<!--[\s\S]*?-->/g, ' ');

function parseAttrs(text) {
  const out = {};
  for (const m of text.matchAll(/([:\w-]+)(?:\s*=\s*"([^"]*)")?/g)) {
    out[m[1].toLowerCase()] = m[2] === undefined ? '' : m[2];
  }
  return out;
}

/** 顺序返回所有带 src 的 <script>（defer 为属性存在性）。 */
export function scriptSrcs(html) {
  const clean = stripComments(html);
  const out = [];
  for (const m of clean.matchAll(/<script\b([^>]*)>[\s\S]*?<\/script>/gi)) {
    const attrs = parseAttrs(m[1]);
    if (!attrs.src) continue;
    out.push({ src: attrs.src, defer: Object.prototype.hasOwnProperty.call(attrs, 'defer') });
  }
  return out;
}

/** 顺序返回 rel 含 stylesheet 的 <link href>。 */
export function styleLinks(html) {
  const clean = stripComments(html);
  const out = [];
  for (const m of clean.matchAll(/<link\b([^>]*)>/gi)) {
    const attrs = parseAttrs(m[1]);
    if (!attrs.href) continue;
    if (!/\bstylesheet\b/i.test(attrs.rel || '')) continue;
    out.push(attrs.href);
  }
  return out;
}

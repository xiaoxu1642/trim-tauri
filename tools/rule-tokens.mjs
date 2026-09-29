// 规则库 token 的共享查法与报错口径（A7 / N6，2026-09-29）
//
// 只共享「怎么找 token、怎么报未登记」这两件事，**不共享允许集合**：
// 清理库与残留库的变量表当前并不等价（清理侧带 TEMP/TMP/HOMEDRIVE 等 14 个、大小写按
// 环境变量原样比对；残留侧 10 个且按大小写不敏感匹配，还要额外拒「token 根」与
// 「一条路径里第二个变量」）。合并成一份等价清单会制造假一致 —— 那正是三报告 A7 明确
// 反对的做法，也是 `check-data-parity` 一类双源对拍反复踩的坑。
//
// 展开器唯一实现仍是 Rust 侧 `trim_finder::cleanup_scan::expand_env_path`；本文件的
// 登记表存在的意义是「签名发布物里的 token 必须显式登记过」，防的是本机有值、别机没有
// 的用户态变量混进规则造成跨机器行为漂移。
const TOKEN_RE = /%([^%\s]+)%/g;

/** 递归收集一个值里出现的所有 `%TOKEN%`（按出现顺序，不去重 ⇒ 报错能指到具体位置） */
export function collectTokens(value) {
  const strings = [];
  const walk = (v) => {
    if (typeof v === 'string') strings.push(v);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') Object.values(v).forEach(walk);
  };
  walk(value);
  const out = [];
  for (const s of strings) for (const m of s.matchAll(TOKEN_RE)) out.push(m[1]);
  return out;
}

/**
 * 造一个 token 判定器。`allowed` 由各门禁自己显式维护（见上面注释），
 * `caseInsensitive` 决定比对口径 —— 两侧当前就是不同的，别顺手统一。
 * 返回 `null` = 允许；返回字符串 = 拒绝原因（调用方决定怎么落红）。
 */
export function makeTokenChecker(allowed, { caseInsensitive = false } = {}) {
  const set = caseInsensitive
    ? new Set([...allowed].map((t) => String(t).toLowerCase()))
    : new Set([...allowed].map(String));
  const has = (tok) => set.has(caseInsensitive ? String(tok).toLowerCase() : String(tok));
  return (tok) =>
    has(tok) ? null : `变量 %${tok}% 未登记（先确认展开器可解析，再登记进本门禁的允许集合）`;
}

/**
 * 残留库目标串的 token 形态判定：只允许**开头一个**变量替换，且变量后必须跟分隔符与
 * 非空子段（禁 `%APPDATA%` 这种 token 根 —— 那等于把整棵用户配置目录交给删除面）。
 * 返回 `{ token }` 或 `{ error }`；无 token 前缀时返回 `{ token: null }`。
 */
export function leadingToken(target) {
  if (/[\0\r\n\t]/.test(target)) return { error: '目标含控制字符' };
  if (!target.startsWith('%')) return { token: null };
  const rest = target.slice(1);
  const end = rest.indexOf('%');
  if (end < 0) return { error: '变量名未闭合' };
  const token = rest.slice(0, end);
  if (!token) return { error: '变量名为空' };
  const tail = rest.slice(end + 1);
  if (tail.includes('%')) return { error: '路径中不允许出现第二个变量替换' };
  if (!tail.startsWith('\\') && !tail.startsWith('/')) {
    return { error: '变量后必须有分隔符与非空子段（禁止 token 根）' };
  }
  if (!tail.slice(1)) return { error: '变量后必须有分隔符与非空子段（禁止 token 根）' };
  return { token, body: tail.slice(1) };
}

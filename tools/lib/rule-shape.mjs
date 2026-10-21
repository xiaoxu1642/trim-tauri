// tools/lib/rule-shape.mjs — 清理规则分组条目的统一遍历口径（唯一实现，其余门禁调用）
//
// 为什么单独抽这里：规则库允许两种组形状——「subGroups 各带 items」与「组直接带顶层 items」，
// 且同一个组也可能两者并存（Rust 装载侧按超集处理）。门禁各写一份遍历时，把某个域扁平化
// 就会有一半门禁数不到条目：2026-10-22 实测只认 subGroups 的写法会让总数少算（special 域归零）。
//
// 约束：Node 侧门禁/工具一律 import 本模块，不许各自再抄一份遍历（AGENTS §2「口径一处实现」）。
// 走序与 Rust `collect_group_items` 一致：subGroups 各 items 在前，组顶层 items 在后。

/** 组内全部条目（两层合计）。 */
export function groupItems(group) {
  const out = [];
  for (const sg of group?.subGroups ?? []) {
    for (const it of sg?.items ?? []) out.push(it);
  }
  for (const it of group?.items ?? []) out.push(it);
  return out;
}

/** 整包全部条目：groups[].subGroups[].items ∪ groups[].items。 */
export function allItems(pkg) {
  const out = [];
  for (const g of pkg?.groups ?? []) out.push(...groupItems(g));
  return out;
}

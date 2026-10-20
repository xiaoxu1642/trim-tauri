// 删除/破坏性原语的单一真源（T1a-M07）：check-delete-callsites 与 check-delete-exits
// 都从这里 import，禁止各自再抄一份名单。
//
// 名单 = 原 callsites 的 9 项 + exits 的 Shell/引擎出口，合并后无遗漏：
// - `MoveFileExW` / `SHFileOperation` / `SHEmptyRecycleBinW`：Shell 级删除出口；
// - `send_to_trash*` / `remove_owned_font_copy` / `reg_key_remove` / `reg_restore_delete`
//   / `startup_delete`：引擎删除 helper（二跳发现网）；
// - `reg_import_apply`：整键覆写的破坏性写回，与删除同一条棘轮。
export const DELETE_APIS = [
  'MoveFileExW',
  'remove_dir_all',
  'remove_file',
  'DeleteFileW',
  'SHFileOperation',
  'SHEmptyRecycleBinW',
  'RegDeleteTreeW',
  'RegDeleteValueW',
  'RegDeleteKeyW',
  'RegDeleteKeyExW',
  'remove_dir',
  'send_to_trash',
  'send_to_trash_os',
  'remove_owned_font_copy',
  'reg_key_remove',
  'reg_restore_delete',
  'startup_delete',
  'reg_import_apply',
];

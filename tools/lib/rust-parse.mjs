'use strict';
// tools/lib/rust-parse.mjs —— Rust 侧「句柄型 API」名单的单一真源
//
// 为什么抽成共享模块：`check-native-hygiene` 的 N3（句柄被 is_ok/is_err 直接判定 ⇒ 丢弃句柄）
// 与 `check-handle-lifecycle` 的 L2（句柄绑定后从不判定）盯的是**同一族 API**。
// 两处各写一份 ⇒ 将来「新增一个句柄 API 却只补一边」永远不会被发现（§4.1 不许抄第二套判据）。
//
// 名单口径：这些 API 用「**返回值即句柄**」的契约表达失败（失败给 NULL 或
// INVALID_HANDLE_VALUE），所以拿到返回值就必须判。
// 句柄走 out-param 的（`RegOpenKeyExW` 类）**不在**本名单 —— 那类由返回值
// `WIN32_ERROR` 表达失败，判定方式不同（见 `check-native-hygiene` N3 头注）。

/** 名单的正则源码（不含定界符）。调用方自建 RegExp，避免共享 `lastIndex`。 */
export const HANDLE_API_SRC =
  '(?:FindFirstFileW|FindFirstVolumeW|CreateFileW|OpenProcess|CreateToolhelp32Snapshot|' +
  'CreateEventW|CreateMutexW|CreateProcessW|OpenServiceW|OpenSCManagerW|CreateJobObjectW)\\s*\\(';

/** 句柄型 API 的调用形态（用于「获取点」定位）。 */
export const handleApiRe = (flags = 'g') => new RegExp(HANDLE_API_SRC, flags);

/** `let <var> = <句柄API>(` 的绑定形态。多行实参也落在绑定行，故单行匹配即可。 */
export const handleBindRe = (flags = 'g') =>
  new RegExp(
    `let\\s+(?:mut\\s+)?([A-Za-z_]\\w*)\\s*=\\s*(?:unsafe\\s*\\{\\s*)?${HANDLE_API_SRC}`,
    flags,
  );

# AGENTS.md — Trim (Tauri) 智能体协作约束

> 只写规则与红线，不写架构教材。
> 本文随仓库分发，因此**不得写入本机绝对路径、智能体归档布局、单机操作姿势**——
> 那类内容属本地资料区，随仓库分发会误导其他机器（也是本仓库把 `docs/` 整体排除出版本跟踪的原因）。
> 需要引用位置时用相对路径或环境变量名，例如 `%APPDATA%\<identifier>`。

Trim = Windows 11 清理优化工具的 **Tauri v2 + Rust** 实现（前端为零框架原生 HTML/CSS/JS，中文 UI，Fluent Design）。
由 Electron 版逐域迁移而来。迁移进度与批次史实属**本地资料区**（`docs/` 已整体不入库），不随仓库分发：接手时以本文件 + 代码内注释为准，不要去找「仓库内方案文档」——它不在版本跟踪里。

## 1. 工作流程

1. 接到任务先列待办清单供审核；存在分歧点先问清再动手。用户消息本身已是明确清单时按单执行、逐项汇报。
2. 只改点名范围，不主动扩展、不回滚他人既有未提交改动。
3. UI 文案、注释、汇报一律中文；注释写「为什么 / 约束 / 根因」，不解释代码在做什么。
4. 完成后按第 4 节验收，交付说明必须写清**验证方式、覆盖范围、遗留缺口**，不许把"没报错"当"已验证"。

## 2. 硬性红线（违反即回退）

- **零前端框架、不新增 npm 依赖。** Rust 侧新增依赖或新开 feature 必须登记进方案文档的依赖清单小节。
- **`src/*.html` 禁内联 script**（CSP 静默拦截）。脚本加载顺序：`ds.js` 先于一切 `window.ds` 使用方，`spotlight.js` 在 `liquid-glass.js` 之后。
- **设计系统**：只用 `main.css` 既有 token；圆角走既有档位（small 6 / btn 8 / medium 10 / large 14，胶囊与徽章除外）；禁彩色渐变与装饰性氛围光；`prefers-reduced-motion` 下无动画（**唯一豁免**：开屏 splash 的一次性走场）；文本一律转义、禁拼 HTML；提示用 `data-tip` 不用 `title`；新交互先查 ds 有没有现成件。
- **转义/字节格式化的唯一真源是 `ds.js`**（审查 M18）：`ds.esc` / `ds.escAttr` / `ds.fmtBytes`。新代码禁止再定义本地 `escapeHtml`/`escapeAttr`/字节格式化函数（历史存量仍有，别再扩散）；`ds.escAttr` 与 `ds.esc` 同字符集（含单引号），因为「哪个引号包属性」会随下次改动变。
- **子窗口 HTML 必须挂 `ds.css` + `ds.js`**（审查 M17）：`modal.js:148` 的焦点陷阱按「`window.ds` 缺席即降级」写，`data-tip` 的样式与委托都在 ds 里 —— 少挂 ds，子窗的高危确认就没有 Tab 圈闭，`data-tip` 退回无样式。`ds.js` 的位置按 §2 的加载序，排在一切 `window.ds` 使用方之前。
- **分类/分组不得用离表色**（审查 M20）：看板与卡片的分组标识色走 `--c` / `--accent-soft` 的 token 兜底，不再按分类注入 hex 或渐变（原 `GROUP_ACCENT`/`GROUP_COLORS`/`CAT_META.color|grad` 已删）。
- **视觉语言「雾屿 V1」**：theme-light 中性色温紫调（bg `#F6F4FB` / ink `#292536`）、默认 accent `#6A59C9`（白字对比度 5.4:1）、阴影淡紫染色、`--ease-standard` 用柔和 ease-out。设置页自定义 accent 仍在运行时覆盖默认值。
- **窗口刻意设计，禁止"优化"删除**：主窗口最小尺寸常量、独立窗口黑闪握手（`app:first-paint` 之后才 show）、预览窗纯黑底、最大化/还原路径不做原生材质操作、`body.win-maximized` 与 `data-material="none"` 必须完全不透明。
- 图标统一放 `src/assets/ico/`；资源文件移动后，`tauri.conf.json` 的 bundle 清单与全部引用同步改。

## 3. 安全模型（IPC 面）

Electron 时代的 `handleSafe/onSafe` 在 Rust 侧对应三层，**新增通道三层都要落**：

1. **`capabilities/default.json`** —— 窗口能力与事件权限白名单。
2. **命令内显式来源校验** —— 两档：`guard(&window, guard::MAIN)`（主窗专属）与 `guard_readonly(&window)`（**放行 `APP_WINDOWS` 全部五个窗口 label**，含四个子窗）。名字里的 readonly 是 Electron `handleSafe` 只读白名单的历史叫法，**它不代表「只读」也不代表「主窗」**——别按字面理解成安全档位；真正的读/写差异在命令体内。多窗口应用**不能裸注册命令**：子窗口一旦被注入，裸注册就让它能调主窗专属高危通道。
3. **渲染层 `src/scripts/tauri-api.js` 的 `CHANNEL_MAP`** —— 通道名→命令名的唯一真源，兼作 preload 白名单。

由此派生的固定动作：

- 新增 `#[tauri::command]` 必须同步：`lib.rs` 的 `generate_handler!` 注册 + `CHANNEL_MAP` 条目。少一处，`tools/check-channel-map.mjs` 的 D1/D2/D3 断言会红。
- **档位以「谁真的需要调它」为准，写错方向会锁死功能**（审查 M1~M3 的教训）：`peripheral_apply`/`peripheral_restore_backup`/`fileclean_delete_file` 是 `APP_WINDOWS` 档——唯一调用方就是子窗口，按 `MAIN` 校验等于让功能 100% 不可用；它们各自的真闸门是 `is_admin()`+取值白名单、以及**扫描槽 `in_scope`**（子窗经 `fileclean::scope_owner` 读的是主窗那次扫描的集合，不是任意路径）。**新增子窗专属通道时同样按这条判，别照抄 `MAIN`**；反之 `elevate_request` 等高危及主窗专属通道**不得**下放（回归网：`tests/ipc_smoke.rs` 末尾「子窗口来源校验档位」一组）。
- **不要**再往 `window` 上挂任何能直调命令的原始入口（历史上 `__trimSpike.raw = invokeCore` 就是这种东西，会绕过 `window.api` 白名单调任意命令，已删，别加回来）。
- 删除一律回收站优先：`trim_finder::scan::recycle::send_to_trash`，且先过 `engine::protect::is_path_protected`。**不做永久删除兜底**（上游 Electron 版在回收站失败时会永久删，这是刻意收紧的差异）。
- 写 JSON 走 `security::atomic_write_json`；配置损坏先 `quarantine_file`；临时脚本只写应用私有 tmp 目录（ACL 保护，不用全局可写的 `%TEMP%`，提权场景有 TOCTOU 提权窗口）。
- 密钥不明文回渲染层（掩码常量见 `settings::SECRET_MASK`，掩码即视为未修改）；日志不落敏感信息，危险操作前 `log::flush_sync()`。
- 提权入口 `elevate:request` 只认主窗口 label。

## 4. 验收（改完必做）

```bash
cd src-tauri
cargo check --all-targets        # 期望 0 错误 0 警告
cargo test                       # 期望全绿（默认不跑 #[ignore]）
cd ..
node tools/check-channel-map.mjs --strict
node tools/check-ps-extraction.mjs
node tools/check-ps-substitution.mjs
node --check <每个改动的 .js>
```

- **渲染层改动必须真机看**：本项目**不使用 CDP**。验证手段只有 `cargo test`（`tauri::test` + MockRuntime，覆盖无窗口的命令逻辑）与应用内 DevTools 人工目检（覆盖真实 WebView、材质、事件投递、子窗口生命周期）。MockRuntime 覆盖不到的一律如实标注为未验证。
- 调试启动用 `TRIM_DEV_NOACTIVATE=1`（窗口显示但不抢前台），发布链路不带该变量。
- **`cargo check` 的 `Finished` 不是产物新鲜的证据**：它只有增量意义，且 profile 未必是 release。发布前必须真实执行 `cargo build --release`，并核对产物 mtime 晚于所有 `.rs` 与 `Cargo.toml`。
- 发布前另须实跑被 `#[ignore]` 的门禁用例，共 **15 条**（真实 pwsh / 网络 / 大目录 / DPAPI 密文样本）。
  **照下面原样跑，别自作主张合并成一条 `--lib -- --ignored`**——`ps_substitution_matches_js` 要
  夹具与 `TRIM_PS_SUBST_DIR`，裸跑必 panic（那是 v1 M13 刻意改成的 fail-loud，不是坏用例）：
  ```bash
  cargo test --lib -- --ignored --skip ps_substitution_matches_js  # 5 条：真实 pwsh / 网络
  node tools/check-ps-substitution.mjs                            # 1 条：它负责造夹具再跑
  cargo test --test ipc_smoke -- --ignored                        # 7 条慢集成
  cargo test --test safestorage_compat -- --ignored                # 2 条，需 TRIM_DPAPI_SAMPLE
  ```
  条数以 `cargo test -- --ignored --list` 现算为准，别信任何文档里的静态数字（这里写过的 14/11 都已过期）。

## 5. 本仓库特有的陷阱（动前先读）

1. **`.ps1` 是「字节即内容」的例外**：`check-ps-extraction` 与 `check-ps-substitution` 拿 `src-tauri/ps/*.ps1` 与前端 JS 模板字面量做**逐字节**对拍，而上游字面量里嵌的 `.reg` 文本自带 `\r\n`。因此 `.gitattributes` 里 `*.ps1` 必须是 `-text`，**不能**并入"全仓 LF"。这些脚本禁止手改，改源 JS 后跑 `node tools/sync-ps-from-js.mjs`。
2. **被 ` ```ignore ` 围栏的文档块会登记成"被忽略的 doctest"**：对它跑 `cargo test --doc -- --ignored` 会真去编译并必然失败。纯示意（注册清单、无函数体签名）一律用 ` ```text `。
3. **被 `generate_handler!` 注册的命令若要 `WebviewWindow`，签名必须写 `WebviewWindow<R>` 且函数加 `<R: tauri::Runtime>`**，否则 `CommandArg` 不满足。命令参数结构体及其**所有字段**必须 `pub`。
4. **嵌套结构体字段没有 camelCase 自动转换**：Tauri 对顶层命令参数名会做 camelCase↔snake_case，但嵌套 `struct` 字段不会。高危确认类字段（如 `confirmedHighRisk`）不加 `#[serde(rename)]` 会被静默判为未确认，等于绕过安全门。
5. **`&str::clone()` 返回的还是 `&str`**，不是 `String`。把 `&str` 捕获进 `'static` 闭包要用 `.to_string()`。
6. **启用 asset 协议要两处**：`tauri.conf.json` 的 `app.security.assetProtocol.{enable,scope}` **且** Cargo 里 `tauri` 开 `protocol-asset` feature。只改 conf 会让构建脚本以「features 与 conf allowlist 不符」失败。scope 只能是静态 glob，因此图源为用户自选目录的通道（如 `fileclean:read-image`）不适合改走 asset。
7. **`tauri-plugin-single-instance` 的 Windows 实现会让第二实例无条件退出**（发完 `WM_COPYDATA` 就 `process::exit(0)`）。所以「旧进程让位给提权后的新进程」不能靠它的回调做，见 `commands/elevate.rs` 的文件握手状态机。
8. **updater 的验签发生在 `download()`、不在 `check()`**。`tauri.conf.json` 的 `requireSignedVersion` 必须为 true，否则伪造响应可把虚高版本号配旧版的合法签名，实现强制降级。
9. **CSP 唯一真源是 `index.html` 的 meta 标签**，`tauri.conf.json` 的 `app.security.csp` 保持 `null`（两者叠加取严、双份维护必然漂移）。子窗口 HTML 的 CSP 要同步改。
10. **首次启动的数据目录迁移是同步执行的**（`engine::paths`），清单判据是「丢了用户就恢复不了」；`copy_dir_missing_only` 只补不覆盖，勿改成覆盖。
11. **依赖里有仓库外的相对路径就会断构建**：原生扫描器已 vendor 进仓库、仅作 path 依赖（不并成 workspace 成员），新增此类依赖时保持同样姿势。
12. **`vendor/upstream-js/` 是「只读上游基线」，不是前端代码**：`.ps1` 生成器与三套 Node 门禁的源坐标指向它（`tools/ps-origin.mjs` 的 `ORIGIN`）。要改脚本逻辑就改 Electron 轨后**整文件重新复制**，禁止手工编辑；它在 `.gitattributes` 里是 `-text`（模板里的真实换行属于内容，被归一成 LF 会让逐字节对拍整批红）。快照是否腐烂用 `node tools/check-origin-drift.mjs` 复核——**它是可选工具，不得被任何必做门禁 import**，也不许把绝对本机路径写回代码（安装型脚本的安装包路径一律用 `@@TRIM_INSTALLER_PATH@@` 占位，Rust 侧运行前替换；该 token 缺失时 `replace_installer_path` 直接报错，勿放宽）。
13. **pwsh 执行层把子进程树关进 Job Object**（审查 M6）：`child.kill()` 只杀 pwsh 本体，`& dism`/`sfc`/`Start-Process -Wait` 起的子孙会继续握着 stdout 写端，而 `join()` 不可中断 —— 实测「5s 超时」实际挂 24s。现在超时先 `TerminateJobObject`，读线程改用 channel + 5s 宽限期（`take_reader`）。**由此产生的新约束**：`.ps1` 里不要用 `Start-Process -NoNewWindow` 留长命进程（会在宽限期后被终止）；需要留下活着的程序时，用不带 `-NoNewWindow` 的 `Start-Process`（不继承管道）。刻意**没有**用 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`：`cleanup_execute.ps1` 重启被清理应用、`cm_restart_explorer.ps1` 拉起 explorer 都是 job 成员，「关句柄即杀全树」会在正常结束时把它们一起杀掉。
14. 后台调试不要试图用 CDP 端口验证窗口 OS 手感（拖动/缩放是 `WM_NCLBUTTONDOWN` 模态循环，合成事件测不出来）。
15. **带 `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` 启动时，子窗必须走 `lib.rs::with_browser_args`**：主窗早就透传这份参数（Phase 0 为了让 CDP 端口生效），子窗当年没透传 —— 同一 WebView2 user-data-folder 下浏览器参数不一致时第二个 core 建不出来，而 `builder.build()` **照样返回 Ok、`get_webview_window(label)` 照样查得到**，只是 `hwnd=0x0`、OS 层根本没有窗口。实测踩过：据此把四个子窗误判成「产品坏了」，还顺手做了个没必要的 `run_on_main_thread` 重构（已回滚）。两条永久教训：① 新增建窗点必须过 `with_browser_args`；② **判定「窗口在不在」只能看 `hwnd()` 或 OS 枚举，Tauri 的成功回执不算证据**。

## 6. 数据目录与文件

- 数据目录：`engine::paths::app_data_dir()`，**便携模式感知**（存在便携标记文件时走 exe 同级 `data/`）。开发构建恒判标准模式，避免把构建目录当便携盘。
- 受保护路径判定：`engine::protect`（清单以生成器产出为准，勿手改）。
- **不要手改**由生成器/导出产出的数据文件（优化项运行时数据、维护任务表、清理规则库等）；要改就改上游源并重新生成。
- 只读缓存（扫描结果、体检结果）可重扫，损坏时静默降级即可，不要为它们加隔离/报错路径。

// winerror-codes.source.mjs — 维护错误码人话表的唯一真源（P1-A / Dism++ D-04b，2026-10-16）
//
// 定位：维护任务（sfc / DISM / Windows 更新组件重置 / 服务 / 网络栈）原生执行失败时，
// 回给界面的是一句机器输出，里面躺着一串 0x 开头的 HRESULT。本表把**维护任务实际会
// 撞到的**码翻成人话，由 tools/gen-winerror-codes.mjs 生成
// src-tauri/data/winerror-codes.json，Rust 侧 commands/maintenance.rs 的
// annotate_error_codes 消费（编译期 include_str! 嵌入）。
//
// 口径纪律（v3 §6 P1-6）：
// - **只收维护任务实际会撞到的 code**；不追求全库。宁少勿错：没收的码不注解，
//   也绝不现场猜一个解释。
// - 中文解释按微软公开文档（Microsoft Learn 排查文档）**重写**，不照抄；
//   Dism++ 的 MessageTable 只作码表指路（它回答「哪些码会出现」，不回答「怎么修」）。
// - 本文件禁出现本机资料区路径或 Dism++ 安装路径（跟踪文件红线，AGENTS §2）。
// - 新增条目必须能说清是哪个维护任务撞到的；说不清的先别加。
//
// 字段：code = 规范化小写 0x 前缀 8 位 hex；title = 一句话结论；detail = 根因与下一步；
//       tasks = 会撞到它的维护任务 id（对齐 data/maintenance-tasks.json）。

export const WINERROR_CODES = [
  {
    code: '0x800f081f',
    title: '找不到修复所需的源文件',
    detail: 'DISM 联机修复拿不到修复文件（Windows Update 不可达或 /Source 指定的路径无效）。可挂载与当前版本匹配的 Windows 安装镜像，用 /Source:wim:<镜像>\\sources\\install.wim 指定本地源后重试；或先执行 /StartComponentCleanup 再 /RestoreHealth。',
    tasks: ['dism', 'wu'],
  },
  {
    code: '0x800f0805',
    title: '程序包不适用（架构或版本不匹配）',
    detail: '要安装或修复的程序包与当前系统架构/版本不匹配。换用匹配当前版本的修复源或更新包；先跑 DISM /CheckHealth 确认组件存储状态。',
    tasks: ['dism', 'wu'],
  },
  {
    code: '0x80073712',
    title: '组件存储损坏',
    detail: '组件存储（WinSxS）已损坏，常规清理修不动。按顺序执行 DISM /RestoreHealth → sfc /scannow，两者都完成后再重试清理；反复失败可能需要就地修复安装。',
    tasks: ['dism', 'sfc'],
  },
  {
    code: '0x800f0831',
    title: '组件存储损坏（CBS 判定）',
    detail: 'CBS 报告组件存储损坏。与 0x80073712 同族：先 DISM /RestoreHealth 再 sfc /scannow，别手工删 WinSxS 里的文件。',
    tasks: ['dism', 'sfc'],
  },
  {
    code: '0x800f0922',
    title: '安装阶段失败（高级安装程序出错）',
    detail: ' servicing 的安装阶段没有走完。先重启（可能只是挂起的操作占着），确认系统保留分区有可用空间，暂时退出 VPN/代理类软件后重试。',
    tasks: ['dism', 'wu'],
  },
  {
    code: '0x800705b9',
    title: '服务堆栈或元数据解析失败',
    detail: 'Windows 更新相关 XML/元数据解析失败，通常意味着服务堆栈损坏。重置 Windows 更新组件（停服务、清 SoftwareDistribution、重启服务）后重试。',
    tasks: ['wu'],
  },
  {
    code: '0x80070005',
    title: '拒绝访问（权限不足）',
    detail: '执行上下文权限不够。确认以管理员身份运行（本工具内该任务会先要求提权）；若已提权仍报，检查组策略或安全软件是否拦截。',
    tasks: ['sfc', 'dism', 'wu', 'audio', 'search', 'netstack'],
  },
  {
    code: '0x80070002',
    title: '系统找不到指定的文件',
    detail: '目标文件缺失——更新缓存损坏或修复源不完整。重置 Windows 更新组件或换修复源后重试。',
    tasks: ['sfc', 'dism', 'wu'],
  },
  {
    code: '0x80070003',
    title: '系统找不到指定的路径',
    detail: '目标路径缺失——常见于缓存目录被清空或修复源结构不完整。核对路径后重试，必要时重置更新组件。',
    tasks: ['sfc', 'dism', 'wu'],
  },
  {
    code: '0x80070490',
    title: '找不到元素（目标组件/文件不存在）',
    detail: '请求的组件或文件在系统里不存在。确认任务与当前系统版本相符；组件存储异常时先做健康检查。',
    tasks: ['dism', 'wu'],
  },
];

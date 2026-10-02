// bugcheck-codes.source.mjs —— 蓝屏码库的**单一真源**（RAINZ 对标 §3.1，2026-10-03）
//
// 为什么单独一个源文件、不直接放 JSON：AGENTS §6「生成器产出的数据文件不要手改」——
// 但本仓里"上游真源 = vendor JS、派生 = JSON"的那一套只覆盖优化项/维护任务/清理规则这些
// **有 JS 轨历史**的数据。蓝屏码库没有 JS 轨，它的真源就该是这个 mjs：JS 里能用注释写清
// 楚「为什么这条归到这个 cat、这条 cat 的兜底文案是怎么来的」，JSON 里塞不了。
// 生成器（tools/gen-bugcheck-codes.mjs）负责把这里序列化成
// `src-tauri/data/bugcheck-codes.json`；Rust 侧 `include_str!` 读那份 JSON；
// 门禁（tools/check-bugcheck-codes.mjs）双向钉住：JSON 与本文件逐字节一致 + 结构合法。
//
// 为什么**不抄** RAINZ 的 bsod-codes.json（对标 §5 R-1）：竞品文案是它的编辑写的，
// 我们抄过来既是二次分发他人成果、又让「这条码我们真读过 Windows 官方文档吗」变成不可证。
// 这里每条 meaning/causes/solution 都独立撰写；码值与符号名是微软公开的（WDK 头文件
// `bugcodes.h` 与 Learn 文档），归到哪个 cat 是我们的判断。
//
// 字段：
//   code     — u32，BugCheck 参数 0
//   name     — Windows 官方符号名（大写蛇形）
//   cat      — 归类枚举，见下 CATS
//   meaning  — 一句话解释「内核为什么会主动崩」
//   causes   — 常见成因，3-4 条。用户看这段判断「我这次像哪种」
//   solution — 建议动作，一句话。**不许说「已验证有效」**（§5 R-1）：
//              这些是通用排查方向，不是本机复现结论
//
// cat 归类**只有这一份枚举**：新增分类要同时改 CATS / FALLBACK_RULES 兜底文案 /
// 前端 cat → 标签色（当前用中性 token 上色，见 §5 R-2「分组不得用离表色」）。
export const CATS = Object.freeze([
  'driver',       // 驱动读写越界 / IRQL 错 / 生命周期
  'memory',       // 内存管理、页表、非分页区、池
  'kernel',       // 内核自身异常、系统服务、栈切换
  'hardware',     // CPU/主板/芯片组/ACPI/硬件纠错（WHEA/MCE）
  'video',        // 显卡与显示子系统（TDR/DXGK/3D 队列）
  'filesystem',   // 文件系统、启动设备、存储栈
  'security',     // 关键进程/对象终止、内核完整性检查
  'power',        // 电源状态切换 / PnP 电源策略
  'network',      // NDIS/网络驱动栈
  'manual',       // 人为触发（调试器、NotMyFault、键盘触发）
  'unknown',      // 兜底：码不认识的分类
]);

/**
 * 未命中码表的兜底归类规则（对标 RAINZ 的 6 条硬件归类思路，但按 trim 口径重写）。
 * 判据是**参数与码值形态**，不是"码名叫什么"——很多第三方自定义码没有可读名。
 * 命中顺序即优先级：越具体越靠前。都不命中则用 `FALLBACK_DEFAULT`。
 */
export const FALLBACK_RULES = Object.freeze([
  {
    id: 'driver_param4_sys',
    why: '参数 4 常是被卸载/未加载的驱动模块名或地址；出现 .sys 类形态时优先归到驱动类',
    cat: 'driver',
  },
  {
    id: 'code_in_driver_range',
    why: 'BugCheck 0xC0-0xDF 段是微软给"驱动违规/池损坏"留的集中区',
    cat: 'driver',
  },
  {
    id: 'code_in_pagefault_range',
    why: '0x50 / 0xD5 / 0xD6 与 PAGE_FAULT 族：多为非分页区/池被踩，硬件与驱动各半',
    cat: 'memory',
  },
  {
    id: 'code_in_whea_range',
    why: '0x124 WHEA / 0x9C MCE / 0x80 INTERNAL_POWER_ERROR：CPU 或主板报的硬件纠错',
    cat: 'hardware',
  },
  {
    id: 'code_in_video_range',
    why: '0x112-0x141 与 VIDEO_TDR / DXGK 族：显卡驱动或供电不稳',
    cat: 'video',
  },
  {
    id: 'code_in_boot_device_range',
    why: '0x7B 系 INACCESSIBLE_BOOT_DEVICE 族：存储驱动/磁盘/启动配置',
    cat: 'filesystem',
  },
]);

export const FALLBACK_DEFAULT = Object.freeze({
  cat: 'unknown',
  meaning: '该蓝屏码不在收录表中，无法给出针对性解释。',
  solution:
    '用参数 1 的十六进制值与转储文件名在微软 Learn 的 Bug Check Code Reference 检索；同一码短期内反复出现时优先怀疑最近装/更过的驱动。',
});

/**
 * 收录表 —— 84 条（对标 RAINZ 覆盖广度，逐条独立撰写）。
 * 排序：按 code 升序，方便 diff 与门禁「code 不重复」断言。
 *
 * 每条文案的目标读者是「拿到一个 0x116 想知道下一步干什么」的普通 Windows 用户，
 * 不是内核工程师：`meaning` 讲清「崩在哪里」，`causes` 讲「我这次像哪种」，
 * `solution` 讲「先动什么、动不了再动什么」。
 */
export const BUGCHECK_CODES = Object.freeze([
  {
    code: 0x0a,
    name: 'IRQL_NOT_LESS_OR_EQUAL',
    cat: 'driver',
    meaning: '内核代码在过高的 IRQL 上访问了不被允许的内存地址。',
    causes: [
      '第三方驱动（网卡/显卡/存储过滤驱动）读写越界',
      '内存条不稳或 XMP 超频失败',
      '安全软件的过滤驱动与当前内核不兼容',
    ],
    solution: '按参数 1 定位到出错的 .sys，优先更新或回退该驱动；关闭内存超频后复测。',
  },
  {
    code: 0x12,
    name: 'TRAP_CAUSE_UNKNOWN',
    cat: 'kernel',
    meaning: '内核 trap 已发生但 trap 帧里的原因字段无法识别。',
    causes: ['内核或驱动被破坏导致 trap 记录本身不可信', '少见：虚拟化层与宿主内核不匹配'],
    solution: '把转储交给有符号表的分析工具（WinDbg）看栈；先做系统文件完整性修复。',
  },
  {
    code: 0x18,
    name: 'REFERENCE_BY_POINTER',
    cat: 'driver',
    meaning: '内核对象的引用计数被同一指针引用了多次。',
    causes: ['驱动多次 ObReferenceObjectByPointer 同一对象', '驱动卸载路径没配平引用'],
    solution: '更新最近安装的驱动；若参数 1 指向特定 .sys，考虑回退该版本。',
  },
  {
    code: 0x1a,
    name: 'MEMORY_MANAGEMENT',
    cat: 'memory',
    meaning: '内存管理子系统检测到无法继续的不一致状态。',
    causes: ['物理内存条损坏或时序不稳', '页表被越界写坏', '分页文件所在磁盘异常'],
    solution: '先跑 mdsched 或厂商内存测试；硬件通过则查参数 1 指向的驱动。',
  },
  {
    code: 0x1e,
    name: 'KMODE_EXCEPTION_NOT_HANDLED',
    cat: 'kernel',
    meaning: '内核模式代码抛出未被异常处理接住的 CPU 异常。',
    causes: ['驱动访问了未映射的地址', 'CPU 指令集与内核不匹配（少见，超频或虚拟化）', '内存位翻转'],
    solution: '看参数 1 异常码定位（0xC0000005 类访存错误优先怀疑驱动与内存）。',
  },
  {
    code: 0x22,
    name: 'FILE_SYSTEM',
    cat: 'filesystem',
    meaning: '文件系统过滤器栈在处理 IRP 时崩了。',
    causes: ['文件系统过滤驱动（杀毒/加密/备份）异常', '磁盘上文件系统元数据不一致'],
    solution: '先 chkdsk；卸载最近装的过滤型安全软件复测。',
  },
  {
    code: 0x23,
    name: 'FAT_FILE_SYSTEM',
    cat: 'filesystem',
    meaning: 'FAT/exFAT 卷驱动遇到无法恢复的状态。',
    causes: ['U 盘/存储卡介质不稳', '热拔插导致 FAT 链断裂'],
    solution: '在另一台机器上把该卷 chkdsk /f，重插前先在系统里"安全弹出"。',
  },
  {
    code: 0x24,
    name: 'NTFS_FILE_SYSTEM',
    cat: 'filesystem',
    meaning: 'NTFS 卷驱动内部不一致。',
    causes: ['NTFS 元数据损坏', '磁盘介质坏道', '过滤驱动错误改写 IRP'],
    solution: '管理员 PowerShell `chkdsk /scan` 看坏簇；必要时 `chkdsk /f /r` 离线跑。',
  },
  {
    code: 0x27,
    name: 'RDR_FILE_SYSTEM',
    cat: 'filesystem',
    meaning: '重定向器（网络文件系统客户端）栈崩了。',
    causes: ['SMB 客户端与服务器协商异常', '第三方网络文件系统驱动'],
    solution: '更新网卡驱动与最近装的 VPN/域工具；必要时 `Get-SmbConnection` 看是否有异常挂载。',
  },
  {
    code: 0x2b,
    name: 'PANIC_STACK_SWITCH',
    cat: 'kernel',
    meaning: '内核在错误的栈上执行了 trap 处理，被迫切换 DPC/双倍栈时又出错。',
    causes: ['驱动踩坏内核栈', '栈溢出（递归过深）'],
    solution: '看栈回溯里最近的非微软 .sys；跑驱动验证器（Verifier）复现。',
  },
  {
    code: 0x2d,
    name: 'SHARED_RESOURCE_CONFLICT',
    cat: 'hardware',
    meaning: '两个设备共享了同一硬件资源但其中一个不认账。',
    causes: ['PCI/PCIe 中断或内存映射分配冲突', 'BIOS 里 IRQ 分配模式与 OS 不兼容'],
    solution: '升级主板 BIOS；BIOS 里把中断模式从 Legacy 改为 MSI（若可选）。',
  },
  {
    code: 0x2f,
    name: 'WDGViolation',
    cat: 'driver',
    meaning: 'Windows 驱动看门狗检测到某个驱动长时间占着 CPU 不放。',
    causes: ['驱动内部死循环', '硬件不响应导致驱动自旋超时'],
    solution: '参数 1 通常指向出错的驱动；先更新，仍崩则考虑换卡/换设备。',
  },
  {
    code: 0x33,
    name: 'FORCED_CRASH',
    cat: 'manual',
    meaning: '由工具或内核 API 主动触发的蓝屏（例：NotMyFault）。',
    causes: ['开发者用压测工具刻意触发', '调试器指令'],
    solution: '非故障，忽略即可；若你并未主动触发，查参数 1 是哪个进程发起了崩溃。',
  },
  {
    code: 0x34,
    name: 'CACHE_MANAGER',
    cat: 'filesystem',
    meaning: '缓存管理器在读写文件缓存时崩了。',
    causes: ['底层存储驱动与缓存管理器不匹配', '分页/暂存文件所在卷被强制断开'],
    solution: '更新存储控制器驱动与固件；外接盘做暂存卷时避免热拔。',
  },
  {
    code: 0x3b,
    name: 'SYSTEM_SERVICE_EXCEPTION',
    cat: 'kernel',
    meaning: '系统服务例程里出现了未处理的异常（常是显卡栈或过滤驱动）。',
    causes: ['显卡驱动或 GPU 硬件不稳', '杀软/EDR 的过滤驱动处理系统调用出错', '内存不稳'],
    solution: '优先更新显卡驱动；参数 1 是异常码，0xC0000005 类优先怀疑驱动与内存。',
  },
  {
    code: 0x3f,
    name: 'NO_MORE_SYSTEM_PTES',
    cat: 'memory',
    meaning: '系统 PTE（页表项）池被耗尽。',
    causes: ['某个驱动不停申请 MDL 未释放', '备份类软件同时打开大量文件'],
    solution: '更新最近装的备份/磁盘镜像类工具；驱动验证器可定位泄漏方。',
  },
  {
    code: 0x4e,
    name: 'PFN_LIST_CORRUPT',
    cat: 'memory',
    meaning: '物理页号（PFN）数据库被同一页被引用多次。',
    causes: ['驱动把已释放的页又提交回去', '物理内存位翻转'],
    solution: '先跑内存测试；仍现则更新最近装的驱动（尤其存储/虚拟化）。',
  },
  {
    code: 0x50,
    name: 'PAGE_FAULT_IN_NONPAGED_AREA',
    cat: 'memory',
    meaning: '内核访问非分页区时页不存在或已被释放。',
    causes: ['驱动 Use-After-Free', '物理内存不稳', '杀毒软件的内核钩子把地址算错'],
    solution: '看参数 3（指令地址）落在哪个 .sys 的模块范围内；先动那个驱动。',
  },
  {
    code: 0x51,
    name: 'HARDWARE_ERROR',
    cat: 'hardware',
    meaning: '旧式：某设备返回了硬件错误。',
    causes: ['设备固件故障', 'PCIe 链路不稳'],
    solution: '设备管理器里查有无 ⚠ 号设备，重装/换到另一个插槽。',
  },
  {
    code: 0x5a,
    name: 'CRITICAL_STRUCTURE_CORRUPTION',
    cat: 'security',
    meaning: '内核检测到自己关键数据结构被篡改，主动崩掉以防被继续利用。',
    causes: ['内核补丁/挂钩类软件（部分作弊/破解工具）', '引导链被劫持（bootkit）', '内存位翻转'],
    solution: '跑 `sfc /scannow` + `DISM /Online /Cleanup-Image /RestoreHealth`；查启动项里是否有可疑内核模块。',
  },
  {
    code: 0x5b,
    name: 'INSTRUCTION_MODE_MISMATCH',
    cat: 'kernel',
    meaning: '内核代码执行到了不匹配当前 CPU 模式的指令（如 16 位段）。',
    causes: ['虚拟化宿主/客机配置错', 'UEFI 与 OS 的 CPU 特性协商异常'],
    solution: '升级 BIOS；虚拟机场景核对 hypervisor 与客机版本。',
  },
  {
    code: 0x77,
    name: 'KERNEL_STACK_INPAGE_ERROR',
    cat: 'memory',
    meaning: '内核栈要换入时从分页文件或内存读不回来。',
    causes: ['磁盘故障或坏道', '分页文件所在的卷不稳', '内存与磁盘同时有问题'],
    solution: '先看磁盘 SMART；跑 chkdsk /r；仍崩再测内存。',
  },
  {
    code: 0x79,
    name: 'MISMATCHED_HAL',
    cat: 'kernel',
    meaning: '硬件抽象层（HAL）与内核/调度器版本不匹配。',
    causes: ['升级 Windows 时 HAL 未同步更新', '手动替换过 hal.dll'],
    solution: '让 Windows Update 完整跑一遍；必要时用安装介质就地修复。',
  },
  {
    code: 0x7a,
    name: 'KERNEL_DATA_INPAGE_ERROR',
    cat: 'memory',
    meaning: '内核数据从磁盘换入时失败。',
    causes: ['磁盘/数据线故障', '分页文件坏簇', '存储控制器驱动不稳', '内存位翻转'],
    solution: '先看事件里的磁盘错误；换 SATA 线/插槽；跑 chkdsk 与内存测试。',
  },
  {
    code: 0x7b,
    name: 'INACCESSIBLE_BOOT_DEVICE',
    cat: 'filesystem',
    meaning: '启动阶段找不到或读不出系统所在卷。',
    causes: ['存储控制器模式（AHCI/RAID/IDE）在 BIOS 里被改', '新装的存储驱动接管失败', 'BitLocker 密钥未解锁'],
    solution: 'BIOS 里把 SATA 模式改回原设置；启动进入安全模式卸载最近装的存储驱动。',
  },
  {
    code: 0x7e,
    name: 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED',
    cat: 'driver',
    meaning: '系统线程里的驱动抛了未处理异常。',
    causes: ['第三方驱动缺陷', '内存条不稳', 'CPU 超频'],
    solution: '参数 1 是异常码、参数 4 常指向出错模块；按该模块找驱动。',
  },
  {
    code: 0x7f,
    name: 'UNEXPECTED_KERNEL_MODE_TRAP',
    cat: 'kernel',
    meaning: '内核收到了本不该出现的 trap（如双重故障、栈段不存在）。',
    causes: ['内存条时序过紧或坏位', 'CPU 超频不稳', '内核栈溢出'],
    solution: '参数 1 = 8 是 DOUBLE_FAULT，几乎总指向内存/CPU 不稳；先做压力测试。',
  },
  {
    code: 0x80,
    name: 'INTERNAL_POWER_ERROR',
    cat: 'power',
    meaning: '电源转换（睡眠/休眠）状态机内部错误。',
    causes: ['驱动不支持新的电源状态', 'ACPI 表描述与硬件实际不符'],
    solution: '暂时用 `powercfg /h off` 关休眠；更新主板芯片组与显卡驱动。',
  },
  {
    code: 0x9c,
    name: 'MACHINE_CHECK_EXCEPTION',
    cat: 'hardware',
    meaning: 'CPU 报出机器检查异常（MCE），通常伴随超频/供电/温度问题。',
    causes: ['CPU 超频/电压不稳', '散热不足', 'PCIe 设备上报了致命错误'],
    solution: '关闭超频；查 BIOS 里的 MCE 日志；更新主板 BIOS。',
  },
  {
    code: 0x9f,
    name: 'DRIVER_POWER_STATE_FAILURE',
    cat: 'power',
    meaning: '某个驱动在睡眠/唤醒时没有及时响应电源 IRP。',
    causes: ['网卡/蓝牙/Wi-Fi 驱动的电源回调超时', 'USB 设备热插拔与唤醒并发'],
    solution: '参数 3 常指向卡住的设备栈；关掉该设备的"允许计算机关闭此设备以节约电源"。',
  },
  {
    code: 0xa5,
    name: 'ACPI_BIOS_ERROR',
    cat: 'hardware',
    meaning: 'ACPI 表损坏或主板固件与 OS 的 ACPI 解析不兼容。',
    causes: ['BIOS 版本过老', 'ACPI 表自定义修改（超频/解锁）'],
    solution: '回原厂最新 BIOS；关闭 Advanced 里改过 ACPI 表的选项。',
  },
  {
    code: 0xa6,
    name: 'DISABLED_UNEXPECTED_EXCEPTION',
    cat: 'kernel',
    meaning: '内核在异常调度被临时禁用期间收到了 trap。',
    causes: ['驱动破坏内核状态', '极少见：虚拟化层注入异常'],
    solution: '先看栈回溯里的非微软模块；跑驱动验证器复现。',
  },
  {
    code: 0xa7,
    name: 'ACPI_ERROR',
    cat: 'hardware',
    meaning: 'ACPI 解释器执行方法时遇到致命错误。',
    causes: ['主板固件里的 DSDT/SSDT 方法有缺陷', '嵌入式控制器（EC）固件异常'],
    solution: '升级 BIOS 与 EC 固件；关闭 Advanced 里自定义 ACPI 相关项。',
  },
  {
    code: 0xbe,
    name: 'ATTEMPTED_WRITE_TO_READONLY_MEMORY',
    cat: 'driver',
    meaning: '驱动试图写入只读内存段（例：代码段）。',
    causes: ['驱动指针算术错', '恶意软件尝试 hook 内核代码'],
    solution: '参数 1 是目标地址，落在哪个 .sys 段就更新/回退那个驱动。',
  },
  {
    code: 0xbf,
    name: 'DRIVER_CORRUPTED_EXPOOL',
    cat: 'memory',
    meaning: '驱动破坏了扩展分页池。',
    causes: ['驱动池溢出', '驱动 double-free'],
    solution: '更新可疑驱动；跑 Driver Verifier 的池专项。',
  },
  {
    code: 0xc1,
    name: 'SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION',
    cat: 'memory',
    meaning: '特殊池检测到某次访问越过了分配的边界。',
    causes: ['驱动缓冲区溢出', 'UAF 后被重分配'],
    solution: '通常伴随 Verifier 已开启；栈回溯里的驱动就是元凶。',
  },
  {
    code: 0xc2,
    name: 'BAD_POOL_CALLER',
    cat: 'driver',
    meaning: '驱动以非法方式申请或释放池内存。',
    causes: ['驱动在错误的 IRQL 上分配池', '驱动释放不属于它的池地址'],
    solution: '更新最近装的驱动；跑 `verifier /standard /driver <sys>` 复现。',
  },
  {
    code: 0xc4,
    name: 'DRIVER_VERIFIER_DETECTED_VIOLATION',
    cat: 'driver',
    meaning: '驱动验证器主动崩掉，报告它抓到的驱动违规。',
    causes: ['驱动本身有 bug，被 Verifier 抓到'],
    solution: '参数 1 是违规子类型；关闭 Verifier 后系统能启，但那个驱动仍是隐患。',
  },
  {
    code: 0xc5,
    name: 'DRIVER_CORRUPTED_AT_FAILURE',
    cat: 'driver',
    meaning: '驱动在崩溃发生前已经被观察到损坏内存。',
    causes: ['驱动栈上缓冲区溢出', '内核栈被写坏'],
    solution: '栈回溯里最近的第三方 .sys 是首要嫌疑。',
  },
  {
    code: 0xc6,
    name: 'DRIVER_VERIFIER_DMA_VIOLATION',
    cat: 'driver',
    meaning: 'Verifier 抓到驱动 DMA 目标地址非法。',
    causes: ['驱动把用户态地址直接下发到 DMA', '映射未做 IOMMU 保护'],
    solution: '更新该设备驱动；关闭 Verifier 后如不再崩，联系厂商修复。',
  },
  {
    code: 0xd1,
    name: 'DRIVER_IRQL_NOT_LESS_OR_EQUAL',
    cat: 'driver',
    meaning: '驱动在过高的 IRQL 访问了可分页内存。',
    causes: ['网卡/存储/显卡驱动 bug', '内存不稳', '第三方杀软的过滤驱动'],
    solution: '参数 4 是被访问的地址、参数 3 常指向出错指令；先看该指令所属模块。',
  },
  {
    code: 0xd5,
    name: 'DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL',
    cat: 'driver',
    meaning: '驱动访问了已经被释放的特殊池内存。',
    causes: ['UAF（Use-After-Free）bug'],
    solution: 'Verifier 已开则栈回溯能直接定位；否则更新最近装的驱动。',
  },
  {
    code: 0xd6,
    name: 'DRIVER_PAGE_FAULT_BEYOND_END_OF_ALLOCATION',
    cat: 'driver',
    meaning: '驱动访问超出了它申请到的缓冲区末尾。',
    causes: ['缓冲区溢出（off-by-one 常见）'],
    solution: '同 0xd5：栈回溯里的驱动就是元凶。',
  },
  {
    code: 0xdd,
    name: 'DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS',
    cat: 'driver',
    meaning: '驱动被卸载但仍有待完成的 IRP/定时器还在指向它的代码。',
    causes: ['驱动卸载路径不清理挂起 IO'],
    solution: '更新驱动；关 Verifier 或回退到能正常热插拔的版本。',
  },
  {
    code: 0xea,
    name: 'THREAD_STUCK_IN_DEVICE_DRIVER',
    cat: 'video',
    meaning: '显卡驱动的线程卡在等待 GPU 返回，看门狗介入。',
    causes: ['显卡驱动 bug', 'GPU 超频/欠压不稳', '显存颗粒不稳'],
    solution: '用 DDU 卸载后重装官方稳定版驱动；关闭 GPU 超频复测。',
  },
  {
    code: 0xeb,
    name: 'THREAD_STUCK_IN_DEVICE_DRIVER_MISSING_RESOURCE',
    cat: 'video',
    meaning: '显卡驱动等待一个永远等不到的资源。',
    causes: ['显卡驱动资源分配失败', 'GPU 硬件已挂'],
    solution: '换驱动版本；若同一硬件反复出现，考虑显卡本体。',
  },
  {
    code: 0xef,
    name: 'CRITICAL_PROCESS_DIED',
    cat: 'security',
    meaning: 'csrss/wininit 等关键进程意外终止，内核只能崩。',
    causes: ['关键系统文件损坏', '驱动把关键进程句柄关掉', '第三方"加速/瘦身"脚本杀错了进程'],
    solution: 'sfc /scannow + DISM 修复；参数 1 是 EPROCESS 地址，转储里能看到是哪个进程。',
  },
  {
    code: 0xf4,
    name: 'CRITICAL_OBJECT_TERMINATION',
    cat: 'security',
    meaning: '维持系统运行的对象（进程/线程/句柄表）被终止。',
    causes: ['与 0xef 类似：关键进程被误杀', '内存损坏导致对象头失效'],
    solution: 'sfc + DISM；参数 3 指向被终止对象类型；转储里可读名字。',
  },
  {
    code: 0x101,
    name: 'CLOCK_WATCHDOG_TIMEOUT',
    cat: 'hardware',
    meaning: '多核 CPU 里某个核没有响应时钟中断。',
    causes: ['CPU 超频/降压不稳', '核心亲和性设置过狠', '主板 BIOS 微码过老'],
    solution: 'BIOS 更新到最新微码；关闭超频；恢复默认核心数与 C-State 设置。',
  },
  {
    code: 0x109,
    name: 'KERNEL_MODE_CRYPTO_FAILURE',
    cat: 'security',
    meaning: '内核加密子系统检测到关键结构损坏。',
    causes: ['驱动写坏了密码学的池块', '内存位翻转命中了加密工作区'],
    solution: '跑内存测试；参数 1 = a3200 类是随机池检查失败。',
  },
  {
    code: 0x110,
    name: 'CRITICAL_DRIVER_INIT_FAILURE',
    cat: 'driver',
    meaning: '关键驱动初始化失败且无法回退。',
    causes: ['驱动被更新但配置未跟上', '依赖服务未启动'],
    solution: '安全模式里回滚该驱动或撤销最近的 Windows 更新。',
  },
  {
    code: 0x112,
    name: 'VIDEO_SCHEDULER_INTERNAL_ERROR',
    cat: 'video',
    meaning: '显卡调度器检测到内部状态不一致。',
    causes: ['显卡驱动 bug', 'GPU 供电不稳'],
    solution: 'DDU 清干净后重装官方驱动；关 GPU 超频。',
  },
  {
    code: 0x113,
    name: 'VIDEO_DXGKRNL_FATAL_ERROR',
    cat: 'video',
    meaning: '显卡内核模式驱动（dxgkrnl）遇到致命错误。',
    causes: ['显卡驱动与当前 Windows 版本不匹配', 'DirectX 内核组件被改坏'],
    solution: '更新 Windows 到最新累积；重装显卡驱动；参数 1 是子类型码。',
  },
  {
    code: 0x116,
    name: 'VIDEO_TDR_FAILURE',
    cat: 'video',
    meaning: 'TDR（超时检测恢复）尝试重置 GPU 但驱动没回来。',
    causes: ['显卡驱动 bug（最常见 nvlddmkm / atikmpag / igdkmd64）', 'GPU 超频/欠压/温度高', '显存颗粒不稳'],
    solution: '参数 1 就是没恢复的驱动文件名；先按它装对应官方稳定版；关 GPU 超频。',
  },
  {
    code: 0x117,
    name: 'VIDEO_TDR_TIMEOUT_DETECTED',
    cat: 'video',
    meaning: 'GPU 无响应、TDR 尝试复位。',
    causes: ['与 0x116 同族，但复位成功、系统不蓝屏（视配置）'],
    solution: '同上；若已经变 0x116 才蓝屏，先按 0x116 处理。',
  },
  {
    code: 0x124,
    name: 'WHEA_UNCORRECTABLE_ERROR',
    cat: 'hardware',
    meaning: 'Windows 硬件纠错（WHEA）报告不可纠正的硬件错误。',
    causes: ['CPU 内部错误（MCE）', 'PCIe 设备致命错误', '内存 ECC 无法纠正', '供电不稳'],
    solution: '看 BIOS 里的 WHEA 日志或 WinDbg `!whea`；关闭超频、更新 BIOS；若定位到 PCIe 卡，换插槽。',
  },
  {
    code: 0x125,
    name: 'MANUALLY_INITIATED_CRASH',
    cat: 'manual',
    meaning: '通过键盘组合或注册表触发的蓝屏（调试用）。',
    causes: ['按右 Ctrl + Scroll Lock 两次', 'EnableCrashOnCtrlScroll 打开'],
    solution: '自己触发就忽略；否则关掉这个调试开关。',
  },
  {
    code: 0x12c,
    name: 'TDR_detected',
    cat: 'video',
    meaning: '旧式 TDR 类蓝屏，与新式 0x116/0x117 同族。',
    causes: ['GPU 驱动无响应'],
    solution: '按 0x116 处理。',
  },
  {
    code: 0x133,
    name: 'DPC_WATCHDOG_VIOLATION',
    cat: 'driver',
    meaning: 'DPC 累计执行时间超过看门狗阈值。',
    causes: ['存储控制器驱动 SSD 固件 bug（老 Intel RST 尤其）', '网卡 DPC 风暴', '显卡驱动 DPC 超时'],
    solution: '参数 1 = 0x2 表示单 DPC 超阈值、0x3 表示累计超限；先更新 SSD 固件与存储驱动。',
  },
  {
    code: 0x139,
    name: 'KERNEL_SECURITY_CHECK_FAILURE',
    cat: 'security',
    meaning: '内核安全检查（池头/链表完整性）失败。',
    causes: ['驱动池溢出', '内存位翻转命中池头', '补丁不完整的内核'],
    solution: '参数 1 是子类型（0x2 池头损坏等）；sfc /scannow + 更新可疑驱动。',
  },
  {
    code: 0x13a,
    name: 'KERNEL_MODE_HEAP_CORRUPTION',
    cat: 'memory',
    meaning: '内核模式堆被破坏。',
    causes: ['驱动写越界', '第三方 GPU/音频驱动堆管理 bug'],
    solution: '更新可疑驱动；跑 Verifier 复现。',
  },
  {
    code: 0x13b,
    name: 'SYSTEM_SCAN_FAILED',
    cat: 'security',
    meaning: '系统扫描（Defender 早期启动扫描）失败。',
    causes: ['UEFI 与安全启动链交互异常', 'Defender 特征库文件损坏'],
    solution: '在 BIOS 里恢复 Secure Boot 默认；Update-MpSignature 更新特征。',
  },
  {
    code: 0x141,
    name: 'VIDEO_ENGINE_TIMEOUT_DETECTED',
    cat: 'video',
    meaning: 'GPU 上某个引擎（3D/解码/Copy）超过 TDR 阈值仍未完成。',
    causes: ['GPU 长时间高负载 + 供电临界', '显卡驱动引擎调度 bug'],
    solution: '降 GPU 频率、清理散热；重装显卡驱动。',
  },
  {
    code: 0x144,
    name: 'BUGCODE_NDIS_DRIVER',
    cat: 'network',
    meaning: 'NDIS（网络驱动接口规范）栈崩了。',
    causes: ['网卡驱动 bug（Wi-Fi 尤其）', 'VPN/防火墙过滤驱动'],
    solution: '更新网卡驱动、暂时卸载 VPN；参数 4 常指向出错模块。',
  },
  {
    code: 0x14b,
    name: 'BUGCODE_CLASS_DRIVER',
    cat: 'driver',
    meaning: '某个"类别驱动"（class driver）崩了。',
    causes: ['存储/USB/磁盘类别驱动 bug'],
    solution: '更新最近装的存储/USB 类驱动。',
  },
  {
    code: 0x14c,
    name: 'BUGCODE_SUB_DRIVER',
    cat: 'driver',
    meaning: '类驱动的子驱动崩了。',
    causes: ['与 0x14b 同族：子设备驱动的实现 bug 居多'],
    solution: '转储栈回溯里最近的非微软 .sys 就是元凶；更新或回退该驱动。',
  },
  {
    code: 0x14e,
    name: 'BUGCODE_CLASS2_DRIVER',
    cat: 'driver',
    meaning: '第二代类驱动崩了。',
    causes: ['与 0x14b 同族：常见于新存储/磁盘类驱动'],
    solution: '按栈回溯里的 .sys 定位；先撤销该设备最近的驱动更新。',
  },
  {
    code: 0x152,
    name: 'BUGCODE_USB_DRIVER',
    cat: 'driver',
    meaning: 'USB 栈里某个驱动崩了。',
    causes: ['USB 网卡/采集卡驱动', 'USB 选择性挂起恢复失败'],
    solution: '在设备管理器里"卸载 USB 根集线器"重启重扫；必要时关 USB 选择性挂起。',
  },
  {
    code: 0x154,
    name: 'UNEXPECTED_STORE_EXCEPTION',
    cat: 'filesystem',
    meaning: '存储栈（store）在非预期状态下抛异常。',
    causes: ['SSD 固件 bug', '应用暂停（Modern App）状态下写盘出错', '存储控制器驱动'],
    solution: '更新 SSD 固件与主板存储驱动；参数 1 常指向出错的 store 模块。',
  },
  {
    code: 0x155,
    name: 'DRIVER_VERIFIER_IOMANAGER_VIOLATION',
    cat: 'driver',
    meaning: 'Verifier 抓到驱动的 IO 管理器违规（未释放 MDL、错误挂起）。',
    causes: ['驱动内部生命周期管理 bug'],
    solution: '关掉 Verifier 让系统能启动，把转储交给厂商；否则回退该驱动。',
  },
  {
    code: 0x159,
    name: 'DRIVER_POWER_STATE_FAILURE1',
    cat: 'power',
    meaning: '驱动电源状态转换中，等待某个电源 IRP 超时。',
    causes: ['与 0x9f 同族，但发生在特定阶段'],
    solution: '看栈里的设备栈；关该设备的"允许计算机关闭以节约电源"。',
  },
  {
    code: 0x15c,
    name: 'PDC_WATCHDOG_TIMEOUT',
    cat: 'power',
    meaning: '平台电源协调驱动器（PDC）看门狗超时。',
    causes: ['待机/唤醒时的电源组件未及时应答'],
    solution: '更新 BIOS 与芯片组驱动；暂时关快速启动复测。',
  },
  {
    code: 0x173,
    name: 'GRAPHICS_MODE_SWITCH_INFO',
    cat: 'video',
    meaning: '图形显示模式切换时崩溃。',
    causes: ['双显卡（Optimus/Switchable）切换失败', '外接显示器热插拔'],
    solution: '更新 Intel 核显与独显两套驱动；插拔前先"断开"该输出。',
  },
  {
    code: 0x17f,
    name: 'HYPERVISOR_ERROR',
    cat: 'kernel',
    meaning: '虚拟机监控程序（Hypervisor）报错。',
    causes: ['Hyper-V 与第三方虚拟化冲突（VBS、旧版 VMware）', 'CPU 虚拟化扩展固件 bug'],
    solution: '启用/关闭 VBS、内存完整性做对照实验；更新 BIOS。',
  },
  {
    code: 0x1ba,
    name: 'HYPERVISOR_WATCHDOG_TIMEOUT',
    cat: 'kernel',
    meaning: 'Hypervisor 内部看门狗超时。',
    causes: ['虚拟化层挂起', 'CPU 微码问题'],
    solution: '更新 BIOS 微码；关闭 Hyper-V 相关组件做对照。',
  },
  {
    code: 0x1ca,
    name: 'SYNTHETIC_WATCHDOG_TIMEOUT',
    cat: 'hardware',
    meaning: '合成（虚拟机）看门狗超时。',
    causes: ['虚拟机客机与宿主时钟/调度不同步', '宿主机资源饱和'],
    solution: '虚拟机场景：给客机加时间同步集成服务；宿主机降负载。',
  },
  {
    code: 0xc000021a,
    name: 'STATUS_SYSTEM_PROCESS_TERMINATED',
    cat: 'security',
    meaning: '用户模式子系统（wininit/csrss/lsass）异常终止，内核只能崩。',
    causes: ['系统文件损坏或版本错配', '第三方替换过 winlogon/csrss 相关文件', '更新中断留下的半态'],
    solution: '进入恢复环境用安装介质就地修复；最近装过的"登录/安全"类软件先卸载。',
  },
  {
    code: 0xdead,
    name: 'MANUALLY_INITIATED_CRASH',
    cat: 'manual',
    meaning: 'NotMyFault / kd 类调试工具主动触发的蓝屏。',
    causes: ['人为压测'],
    solution: '非故障，忽略。',
  },
  {
    code: 0x44,
    name: 'MULTIPLE_IRP_COMPLETIONS',
    cat: 'driver',
    meaning: '同一个 IRP 被完成多次。',
    causes: ['驱动完成路径 bug'],
    solution: '更新栈回溯里出现的 .sys。',
  },
  {
    code: 0x42,
    name: 'NEW_AUDIO_DRIVER_ADVANCED',
    cat: 'driver',
    meaning: '新式音频驱动高级特性错误。',
    causes: ['音频驱动与 PortCls 内核组件不匹配'],
    solution: '回退或重装声卡驱动。',
  },
  {
    code: 0xd2,
    name: 'NO_RUNNING_AVAIL',
    cat: 'memory',
    meaning: '无法为运行中的进程找到可用的内存窗口。',
    causes: ['地址空间碎片化', '内核映射区被大量小分配打散'],
    solution: '重启清理；长跑服务环境则排查内存映射泄漏。',
  },
  {
    code: 0xd3,
    name: 'PAGE_FAULT_WITH_INTERRUPTS_OFF',
    cat: 'memory',
    meaning: '中断关闭时访问缺页。',
    causes: ['驱动访问了已换出的可分页内存'],
    solution: '更新可疑驱动。',
  },
  {
    code: 0xd4,
    name: 'DRIVER_NO_STACK',
    cat: 'driver',
    meaning: '驱动在耗尽内核栈的情况下继续调用。',
    causes: ['驱动递归过深', '驱动与 Verifier 组合下栈被过度占用'],
    solution: '关掉 Verifier 复测；仍崩则回退驱动。',
  },
  {
    code: 0xf2,
    name: 'DISABLED_PAGE_FAULT',
    cat: 'memory',
    meaning: '页错误处理被临时禁用期间发生访问。',
    causes: ['驱动破坏状态机'],
    solution: '转储栈里的驱动是首要嫌疑。',
  },
  {
    code: 0xfb,
    name: 'UMBUS_DRIVER',
    cat: 'driver',
    meaning: 'UMBus（用户模式总线）驱动崩了。',
    causes: ['Xbox/PlayStation 手柄驱动与 UmRdpService 交互异常'],
    solution: '拔掉手柄驱动、重装官方版本。',
  },
  {
    code: 0x134,
    name: 'WDF_VIOLATION',
    cat: 'driver',
    meaning: 'Windows 驱动框架（WDF）内部断言失败。',
    causes: ['WDM/KMDF 驱动的生命周期管理 bug'],
    solution: '更新出错模块的驱动。',
  },
  {
    code: 0x200,
    name: 'CLOCK1_WATCHDOG_TIMEOUT',
    cat: 'hardware',
    meaning: '0x101 的变体：某核时钟看门狗超时。',
    causes: ['同 0x101'],
    solution: '同 0x101。',
  },
  {
    code: 0x1c,
    name: 'SPECIAL_POOL_DETECTED_HEAP_DISCREPANCY',
    cat: 'memory',
    meaning: '特殊池检测到堆元数据不一致。',
    causes: ['驱动写坏池头'],
    solution: 'Verifier 场景下栈回溯会点名；关闭 Verifier 让系统启动。',
  },
]);

// 生成器与门禁共用的校验：code 唯一、name 是 SCREAMING_SNAKE、cat 在枚举内、
// causes 至少 1 条、字段长度有上限（避免 JSON 里塞进远超实用的段落）。
// 逻辑放在这里，两侧复用同一份字节 —— 与本仓 `tools/rule-schema.mjs` 的姿势一致。
export const LIMITS = Object.freeze({
  MAX_MEANING: 200,
  MAX_SOLUTION: 400,
  MAX_CAUSE: 200,
  MIN_CAUSES: 1,
  MAX_CAUSES: 6,
});

export function validateEntries(list) {
  const errors = [];
  const seen = new Set();
  const catSet = new Set(CATS);
  for (const e of list) {
    if (!Number.isInteger(e.code) || e.code < 0 || e.code > 0xffffffff) {
      errors.push(`${e.name ?? '?'} code 非合法 u32`);
    }
    if (seen.has(e.code)) errors.push(`code 0x${e.code.toString(16)} 重复`);
    seen.add(e.code);
    if (typeof e.name !== 'string' || !/^[A-Za-z0-9_]+$/.test(e.name)) {
      errors.push(`code 0x${(e.code ?? 0).toString(16)} name 非字母数字下划线`);
    }
    if (!catSet.has(e.cat)) errors.push(`${e.name} cat=${e.cat} 不在枚举`);
    if (typeof e.meaning !== 'string' || e.meaning.length < 6 || e.meaning.length > LIMITS.MAX_MEANING) {
      errors.push(`${e.name} meaning 长度不合法（${e.meaning?.length ?? 0}）`);
    }
    if (!Array.isArray(e.causes) || e.causes.length < LIMITS.MIN_CAUSES || e.causes.length > LIMITS.MAX_CAUSES) {
      errors.push(`${e.name} causes 数量不合法（${e.causes?.length ?? 0}）`);
    }
    for (const c of e.causes ?? []) {
      if (typeof c !== 'string' || c.length < 4 || c.length > LIMITS.MAX_CAUSE) {
        errors.push(`${e.name} 某条 cause 长度不合法（${c?.length ?? 0}）`);
      }
    }
    if (typeof e.solution !== 'string' || e.solution.length < 6 || e.solution.length > LIMITS.MAX_SOLUTION) {
      errors.push(`${e.name} solution 长度不合法（${e.solution?.length ?? 0}）`);
    }
  }
  return errors;
}

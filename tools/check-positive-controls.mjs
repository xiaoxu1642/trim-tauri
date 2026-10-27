#!/usr/bin/env node
// check-positive-controls.mjs —— 找违规型断言的正向对照管辖门禁
// （v2-L4P-44 / E-8、E-15，2026-10-02）
//
// 抓什么：「找违规型」门禁有两条失效方向——① 扫描前提失效（目录改名、正则过时）
// 导致 0 命中恒绿；② 判定器被误改坏（如正则加了个永远为 false 的分支）。两者都
// 不会让门禁本身报错，防线在无声中消失。范本是 check-cleanup-rule-contract 的
// 37 条反例自检：判定器必须能对**已知违规样本**判红，✓ 才可信。
//
// 本门禁断言：登记在案的每个找违规型门禁必须 (a) 内置 POSITIVE_CONTROLS 自检块、
// (b) 实际执行 exit 0（自检与扫描都在门禁自身内跑通）。新增找违规型门禁不登记即红。
'use strict';
import { readFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// 需要正向对照的找违规型门禁清单（新增必须登记，带理由）
const REGISTRY = [
  { file: 'check-delete-exits.mjs', reason: '删除出口枚举：剥离/命中两向自检' },
  { file: 'check-finder-scan-notes.mjs', reason: 'P1-04 finder 扫描提示条目：真实回执对照（丢根 2 + 根截断 ⇒ 两条提示）/ 零值对照（丢根 0 + 未截断 ⇒ 无提示）/ 字段名对照（把 rootsTruncated 读成 truncated ⇒ 文案必判红）/ 调用点不许悬空；实现直接切自 src/scripts/finder.js，不复制第二份' },
  { file: 'check-escape-delegation.mjs', reason: 'escape 委托：非委托样本自检' },
  { file: 'check-html-contract.mjs', reason: 'HTML 合同：内联 script 样本自检' },
  { file: 'check-cleanup-rule-contract.mjs', reason: '规则契约：37 条反例自检（既有范本）+ 4c 跨条目整树覆盖判据 8 组合成样本（真机形态必判红 / recurse:false 父条与兄弟目录不得过严 / 同根双向 / 路径含 ++ 不误判未知 / 空字面量必报不可判），台账双向咬合：缺行与陈旧行各判红一条' },
  { file: 'check-cleanup-aggregates.mjs', reason: '磁盘清理页体积汇总单一口径（dedupSize）：三个判定器（judgeAggregates 累加形态 / judgeDedupShape 本体形态 / judgeCallSites 调用点）与实仓扫描共用同一实现——12 条累加形态样本（F1 reduce 内联相加 / F2 sizeNumber 映射后紧跟 reduce 相加 / F3 体外 += / F3b 体外 x = x + / F4 两条体积相加写进 Map 各配违例并**逐条断言命中数**、同页两形态必须报 2 条、模板串插值里的累加必抓、正则字面量字符类不得让扫描器原地打转（真挂过）、dedupSize 体内累加与计数类 reduce、注释里的违例形态三类合规样本必须 0 命中）+ 5 条本体样本（S1 引用 overlapsWith / S2 扣减走 sizeNumber / S3「两端都在集合内」的门 / S4 非负兜底，逐条被摘必红、齐备本体 0 问题）+ 3 条计数与解析对照（四处调用点数得全、声明自身不计入、无本体必须返回 null）；真仓侧豁免台账双向咬合：两条锚点各命中 1 处并各认领一条违规，登记不命中即红；**调用点地板与页内 sizeNumber 扫描面地板两组靠真仓现算兜底**（无合成盘上样本）' },
  { file: 'check-rule-schema-sync.mjs', reason: '契约表⇄Rust 装载侧：5 条判定器自检（干净样本 / token 注入 / 缺键查询 / 路径漂移 / 剥离失败）' },
  { file: 'check-elapsed-facts.mjs', manual: true, reason: 'E4 耗时字段：7 条违规样本自检（B 反向判定 / C 失败路径计时）' },
  { file: 'check-optimizer-write-contract.mjs', reason: 'v6-K20：G 组 20 条样本喂**生产同一份**判据（judgeSideTableDiff / judgeStoreSeparation / judgeOptionKeys / judgeProvenanceCoverage / judgeDefaultItem；含 2 条干净样本防判据永远红）——生产与对照不再有两套实现，「全通过」日志已移到 G 组之后' },
  { file: 'check-subwindow-init.mjs', reason: '副窗初始化：residue 页两条正向对照（注入坏绑定 + 抽掉真实 id）；models/process 页一条坏绑定对照，抽件对照因无 warn 通道显式 SKIP 并计入汇总' },
  { file: 'check-subwindow-css.mjs', reason: '子窗 CSS 按需：S1 样式表序列 / S2 引用面 / S3 层叠翻转 / S4 token 真源四组各配正反样本 + 解析器形状对照（@media 内层与花括号字符串）+ S3b ds.css⇄main.css 同特异度棘轮对照（新增键必抓、收缩不误红、消失键可计数；基线由 --emit-ds-pairs 现算回填，不手抄、不走环境变量）' },
  { file: 'check-a11y.mjs', reason: '可达性四断言：勾选框三属性 / aria-live 宿主 / data-tip 反 title / RM 归零覆盖面各配正反样本自检 + 三类扫描面地板' },
  { file: 'check-contrast.mjs', reason: 'F 组玻璃面 floor 断言配正反向样本自检（P3-2）；F1a~F6b 操作面登记台账七类反例（裸 --bg-card / 后级覆写 / 修饰类另写底 / 台账过期 / background-image 绕开 floor / 语义实底被中性降级 / 折射白名单含未登记类）+ F3b 锚点对照（抹掉 wantRefract 的按钮排除必判红）+ floor 栈合成对照（空栈与只垫 floor 必红、完整栈放行）；A1/B/C 与 token 表等既有组仍缺合成样本' },
  { file: 'check-native-hygiene.mjs', reason: 'N1–N9 各配正反样本自检（裸 output / 定长解码 / 句柄丢弃 / .reg 读取 / 深度护栏 / 取最新 / 快照域 / origin 字面量闸 / 取用点登记闸），+ 模块可达性与扫描面地板' },
  { file: 'check-confirm-danger.mjs', reason: 'confirmedHighRisk 字面量判定器配正反样本自检（P3-5）；调用形态两组仍靠扫描面塌陷地板兜底' },
  { file: 'check-idle-scripts.mjs', manual: true, reason: 'loadScript 三态 + 数组序 init 断言配「违例 4 条全命中 / 合规放行」样本自检（P3-4；2026-10-23 加第 4 条：逐条挂 .then 的完成序形状必判红）；守卫与启动名单两组仍靠扫描面地板兜底' },
  { file: 'check-comment-rot.mjs', manual: true, reason: '注释腐烂：三条断言各配正反向对照（不存在路径/章节号/数字必判红 + 真实样本不假红）；另经真破坏验证——关掉待修豁免表后 8 处真实腐烂全被抓到，exit 1' },
  { file: 'check-review-units.mjs', selfTestArgs: ['--self-test'], reason: '审查单元台账：U1–U5 五条断言各配合成正反向样本（超上限/重复点名/未认领/台账塌缩必判红，干净表不假红）；另经真破坏验证——改名+降上限+抬地板三处同时判红，exit 1' },
  // v3 P2-I 新增三条：判据抽出成纯函数后与自检共用同一实现（不在别处抄第二套判据）
  { file: 'check-artifact-size.mjs', reason: '产物体积棘轮：4 组合成样本自检（超 cap 必红 / 等值放行 / 缩小只提示 / 未登记角色必红）；产物缺失走 SKIP 不冒充通过，另经真破坏验证——压低基线 cap 后 exit 1 并点名差值' },
  { file: 'check-first-paint.mjs', reason: '首屏关键路径：F1 预算双向 + F2 defer 不变量 + F4 首屏∩按需，7 组合成样本自检；豁免表与对照双向咬合——清空豁免表会让对照②立即判红（真破坏 exit 1），不是只松真样本' },
  { file: 'check-asset-size.mjs', reason: '资源体积三段判据抽出为单一 judgeAssets，5 组合成样本与之共用同一实现（塞未登记大文件 / 条目失踪 / 超 cap 必红，等值与干净样本放行）；从 PENDING_CONTROLS 迁入本表' },
  { file: 'check-desc-vs-writes.mjs', reason: 'P1-03 文案⇄写入：原缺陷形态判红 /「其余」精确限定与无声称放行，3 条判定器自检' },
  { file: 'check-power-write-surface.mjs', reason: 'P0-1 电源写面：9 条正反样本自检（powercfg 写命令/电源命名空间必判红，只读查询与页面文件步骤必须放行）+ ALLOW 双棘轮（登记不命中必红）' },
  { file: 'check-tools-doc-paths.mjs', reason: 'v6-K23：tools/ 仓外路径形态——path.join 的 docs 段 / 写死 docs 路径字面量四形态合成样本必须判红 + 注释与日志提及必须放行（剥注释、保留字符串的判定器）；另经真破坏验证——给 import-winapp2 塞回 docs 段后 exit 1' },
  { file: 'check-system-bin.mjs', reason: 'v6-K01/P0-2：判定器抽成 extractHitsFromText 后与 H 组 5 个合成样本共用同一实现（裸字面量/raw 版裸字面量/安装包路径误塞系统工具入口必判红，PINNED 解析与变量形态放行）+ F 组生产实参地板（12 个生产在用名掉表即红，与 systembin 单测两道防线）+ quiet 组扩到 timeout/raw 三个 spawn 门面（39+ 处超时调用点不再对 A/B 失明）+ G 组路径形态实参必红' },
  { file: 'check-layering.mjs', reason: 'v6-P2：判定器抽 layeringHit 纯函数，三样本自检（代码行必中 / **注释行也必中**——「注释不豁免」口径被悄悄改掉必须红 / 干净行放行）+ 既有扫描面地板与 commands 层正向对照' },
  { file: 'check-fail-closed.mjs', reason: 'v6-P2：A/B 判定器抽纯函数（tempScriptDowngrades / toStrUnwraps），四样本自检（A 违例必红、A 干净放行、B 违例必红、B 注释行放行）与真仓扫描共用同一实现' },
  { file: 'check-css-tokens.mjs', reason: 'v6-P2：三组判据抽纯函数（radiusViolations / undeclaredTokenRefs / curveOffenders），合成样本自检（违档 5px/2px 必红、档位与胶囊放行；未定义引用必红、已定义与 ALLOW 放行；曲线越集必红、值集内放行）' },
  { file: 'check-css-hygiene.mjs', reason: 'P2-E/P3 CSS 卫生六断言：颜色兜底 / 同名自引用 / 注释提前终止 / 99px 胶囊 / .ctx-detail-modal 声明唯一 / .titlebar-title 离表 hex，各配正反合成样本；真仓破坏对照另跑过（三项同时注入必红）' },
  { file: 'check-tests-helper-parity.mjs', reason: 'X1-M06：tests/ 底座 helper 单一真源——判定器抽 auditContent 纯函数（剥注释后判本地重复定义 / 调用未接真源），6 条合成样本与之共用同一实现（抄 fn main_window() 与 pub async fn invoke() 必红、use common 与全路径 common:: 放行、调 helper 未接真源必红、注释里的定义不误伤）；另设真源清单地板防塌缩恒绿' },
  // T1b-M02（v7.2 C09）：三条其实已带对照块、却因理由句写「缺合成样本」滞留 PENDING——
  // 对照块坏了没人红。迁入 REGISTRY 后受第 1/2 组实跑核验。
  { file: 'check-item-intro.mjs', reason: '对拍型：item-intro.json 多形态 ⇄ 前端消费口径（内置对照块随跑随验，2026-10-20 从 PENDING 迁入）' },
  { file: 'check-test-sandbox.mjs', reason: 'D 轮（2026-10-25）新增：测试沙箱必须走自删守卫。判定器 judge() 与门禁共用同一实现，内置三向合成对照——未登记新文件 / 计数上升 / 守卫实现整体消失，任一失效即红；另钉守卫本体活性（impl Drop + remove_dir_all 缺一即红，防「①全绿而守卫已被掏空」）' },
  { file: 'check-optimizer-security.mjs', reason: '找违规型：扩库夹带关闭安全组件即红（内置对照块随跑随验，2026-10-20 从 PENDING 迁入）' },
  { file: 'check-optimizer-groups-sidecar.mjs', reason: '对拍型：分类侧表 ⇄ 渲染层兜底常量（内置 6 条对照样本随跑随验，2026-10-20 从 PENDING 迁入）' },
  { file: 'check-optimizer-schema-sync.mjs', reason: '优化域标量 ⇄ 契约表 optimizer 段：六条合成样本（齐全放行 / Rust 常量、渲染层常量、风险档清单、目录越档 risk、侧表 schemaVer 各自判红）' },
  { file: 'check-bcd-row-ids.mjs', reason: '永劫 BCD 行 id 四端对拍：面板 JSON / NARA_ROW_LABEL / ALL_ROW_IDS / row_targets 分支；合成样本覆盖缺项、多项、解析为空 fail-closed' },
  // T1c-M02 / T1c-M05（v7.2 C09）两条新门禁：
  { file: 'check-data-signatures.mjs', reason: '数据产物逐件验签（D1-M03 扩到五件）：签名面现算 ⇄ 登记面双向对账（摘一件必红、塞一件无签名的必红，两向均在 2026-10-21 实跑判红并点名对象）+ 四件内联 _sig 产物逐件字节对照（正文追加空格 / 签名换尾八字节必须拒）；判定 import 自 sign-cleanup-rules 单一实现。段序=对账→对照→逐件验签，真样本验签不过归第 3 段以「改后必须重签」点名，不再冒充「判定器不可信」' },
  { file: 'check-fixture-freshness.mjs', reason: '夹具新鲜度：比对器 isFresh 正反合成样本钉方向（反相 = 全绿假象）；主断言「盘上 ⇄ 生成器导出逐字节」的手改破坏由真破坏验证兜底' },
  {
    file: 'check-pending-batch-limit.mjs',
    selfTestArgs: ['--selftest'],
    reason: 'IPC 载荷上限跨语言单源：8 组合成样本与现盘判定共用同一 judge（前端导出值改 33 必红 / 后端锚点消失必红 / 前端锚点重复必红 / 消费面字面量副本回归必红 / 漏读导出必红（reached 只 1 个）/ 非消费文件偷抄必红 / 注释里的举例不判红 / 干净样本不假红）；对照块每次运行都跑，不再只在 --selftest 才跑',
  },
  // B0（2026-10-24 全仓重审方案 §4 A-6…A-9）：四道「先让后续修复能被判红」的施工前置门禁，
  // 各自内置合成对照块且每次运行都跑，落地即入本表受第 1/2 组实跑核验。
  { file: 'check-degraded-consumption.mjs', reason: 'A-6 degraded 消费契约：发射面现算 ⇄ 通道表三态（consumed/pending/exempt）双向咬合——consumed 的 anchor 必须在源文件命中、pending 兑现后不回收必红；对照块验证「status 白名单判定本身不失真」（非法值恰好 1 个）。B1 已把 paths_load 从 pending 转 consumed，转换当天门禁即要求锚点存在' },
  { file: 'check-delete-root-guard.mjs', reason: 'A-7 删除根守卫：5 组合成样本与真仓扫描共用同一 build() 判据（read_dir+删除且无 inspect_root 必红、caller 先判根放行、**只在注释里写判定仍必红**、1 跳穿透必红、纯枚举工具放行）；TRANSITION 豁免表双向咬合（代码补上判定但台账未回收 ⇒ 红）+ 对象地板 5 条' },
  { file: 'check-ignored-isolation.mjs', reason: 'A-8 ignored 探针隔离：4 组合成样本与真仓解析共用同一判据（第 45 行才定根必红、注释里的属性不算属性、定根在首语句放行、纯函数不误报）；与 `cargo test -- --ignored --list` 的条数对账靠对象地板兜底' },
  { file: 'check-async-exits.mjs', reason: 'A-9 前端 await/出口：3 组合成样本与真仓扫描共用同一判据（置 busy 后 try 前有 await 必红、置 busy 立刻 try 放行、**await 只出现在注释里不得判红**——反向也要成立）；EXEMPT 台账双向咬合' },
  // B1（2026-10-27 全仓重审 P0）：注册表递归删树出口的容器准入与名字形态闸。
  { file: 'check-registry-delete-guard.mjs', reason: 'B1 注册表删树守卫：6 组合成样本与真仓扫描共用同一 build()/denyFaceReached() 判据（删树+无禁删面必红、本函数内有禁删面放行、**只在注释里写禁删面仍必红**、1 跳 callee 认账、无删树原语的函数不误伤、纯 to_wide 形态必红）+ 原语两道闸在场断言（空子键形态闸 `reg_delete_subkey_shape_is_malformed` / 名字形态闸 `to_wide_checked`，摘掉即红）+ pssteps 专项（整条链零禁删面必红，摘掉调用即被抓）+ TRANSITION 豁免表双向咬合（代码补上判定但台账未回收 ⇒ 红）+ 对象地板 4 条' },
  // P1-a（2026-10-27 全仓重审 P1 · F4b 回执三态）：五条形态各自配一组正反对照，
  // 判据都打在语义差上（M12 打「锁与解锁同函数且解锁在 finally 之后」，M14 打「清空态真定义 +
  // 进条件 + 确认件有清空分支」），只查关键字出现的写法一律视为判定器失真。
  { file: 'check-receipt-tri-state.mjs', reason: 'P1-a 回执三态：五条判据共用同一组正反对照（M10 有 else 且置 lossRate:null / M17 时长先绑定不再内联 / M18 三处写侧都读回执 / M12 锁在同一函数的 finally 里放 / M14 清空密钥也走红色确认件）；对照样本必须能把「修好」与「改坏」分开，改坏后门禁 exit≠0 并点名条目' },
  // P1-a（2026-10-27 全仓重审 P1 · D1-M08）：用户可见文案的禁语判据与真仓扫描共用同一
  // violations()；退役 id / 退役标题 / 轮次术语三类命中都必须报红并点名条目与字段。
  { file: 'check-user-copy-policy.mjs', reason: 'P1-a 用户文案纪律：合规样本放行、指向退役项 + 夹带轮次术语的样本必红（对照块每次运行都跑）；真仓扫描走同一判据，命中即点名条目与字段；判定只作用在活跃目录（item-intro.json 故意保留已退役项介绍，不在判据面内）' },
];

// MUST_RUN 里尚未配「内置正向对照自检」的存量门禁（T1-M05，2026-10-09 现算 33 条）。
// 每条登记必须写清「当前缺口形态」；本表**只减不增**：配好内置对照后移到 REGISTRY 并
// 从本表删除（断言 4/5 会核对两张表与 MUST_RUN 的一致性）。新增必跑门禁一律进 REGISTRY，
// 进不了就先在这里登记并写明为什么暂缺 —— 不登记即红。
const PENDING_CONTROLS = [
  { name: 'check-appearance-prefs', reason: 'P1-W3 Phase2c/d 新开门禁（A 组换算结构签名 ⇄ B 组卸载页偏好白名单与镜像 ⇄ C 组外观域 11 键表两侧对拍 + 迁移口径四条 + 四处同步落点）：判据本体在真源文件上做文本抽取，**尚无内置合成样本**；破坏走的是文件自带的 `--rust/--js/--api/--settings` 盘外副本开关，2026-10-22 主 agent 合并 C 组后实跑两向均判红并点名对象（改渲染层键名 ⇒ C1 报「只在 Rust [bgPosX] / 只在 JS [bgPosXz]」；删 CHANNEL_MAP 一条 ⇒ C7 红），单元代理侧另有六向破坏记录见 uF4a2m1-report.md。补齐合成样本后迁 REGISTRY' },
  { name: 'check-channel-map', reason: '对拍型：桥接表 ⇄ Rust 通道集合双向比对，缺「删/添一侧必须红」的合成样本' },
  { name: 'check-guard-tiers', reason: '对拍型：档位表 ⇄ 命令体 guard 调用逐条核对，缺合成样本' },
  // check-layering 已于 2026-10-18 v6 P2 配好判定器自检并迁入 REGISTRY（本表只减不增）。
  { name: 'check-delete-callsites', reason: '棘轮+地板：超基线/扫描面归零即红；缺「人为加一行 remove_file 必须红」的合成样本' },
  // check-fail-closed 已于 2026-10-18 v6 P2 配好 A/B 判定器自检并迁入 REGISTRY（本表只减不增）。
  { name: 'check-residue-rule-contract', reason: '对拍型：卸载残留规则库 ⇄ 执行侧契约，缺合成样本' },
  { name: 'check-scan-rule-diff', reason: '差分型：规则改动 → 命中集差分（按设计 spawn cargo test，重编译成本高），对照方案待定' },
  { name: 'check-ps-callsites', reason: '对拍型：PS 调用点 ⇄ 三张登记表（含超时秒数逐点核对），缺合成样本' },
  { name: 'check-ps-extraction', reason: '对拍型：JS 源 ⇄ .ps1 正文逐字（文本层 + --run 行为层双档），缺「单字节漂移必须红」样本' },
  { name: 'check-csp-consistency', reason: '对拍型：meta CSP ⇄ 三子窗副本逐字一致，缺合成样本' },
  // check-css-tokens 已于 2026-10-18 v6 P2 配好三组判定器自检并迁入 REGISTRY（本表只减不增）。
  { name: 'check-assets-used', reason: '找违规型：src/assets 零引用文件即红，缺违规样本自检' },
  // check-asset-size 已于 2026-10-14 v3 P2-I 配好内置正向对照并迁入 REGISTRY（本表只减不增）。
  { name: 'check-treemap-layout', reason: '性质型：squarified 布局数学性质（面积和/包含关系），缺「人为破坏性质必须红」样本' },
  // check-item-intro / check-optimizer-security / check-optimizer-groups-sidecar
  // 已于 2026-10-20（T1b-M02）证实各自带对照块，迁入 REGISTRY（本表只减不增）。
  { name: 'check-desktop-entry', reason: '对拍型：桌面入口 ⇄ 发布暂存目录合并状态，缺合成样本' },
  { name: 'check-data-parity', reason: '对拍型：data/*.json 派生副本 ⇄ 真源（6+1 个），缺「改一侧必须红」样本' },
  { name: 'check-optimizer-dynamic', reason: '对拍型：dynamic 标记 ⇄ 后端分支要求，缺合成样本；R3-L06（v7.2 P2）把参数校验合并进 dynamic_steps 后，A2/A3 的解析面已扩成「分派分支 + match 臂」两处来源（只找 `option_id ==` 会同时瞎两条），并经真破坏验证——把 svc_mem_gb 臂里的 `p.gb` 读取摘掉 ⇒ A3 判红且点名「判断体（match 臂）没读 p.gb」，恢复回绿' },
  { name: 'check-optimizer-subitem-contract', reason: '对拍型：可自选目标契约 ⇄ 侧表，缺合成样本' },
  { name: 'check-optimizer-subitem-contract', reason: '对拍型：可自选目标契约 ⇄ 侧表，缺合成样本' },
  { name: 'check-version-sync', reason: '对拍型：版本号四处一致，缺「单处漂移必须红」样本' },
  { name: 'check-updater-pubkey', reason: '对拍型：pubkey 形状（base64(minisign)），缺合成样本' },
  { name: 'check-readme-claims', reason: '对拍型：readme 数字 ⇄ 数据真源，缺合成样本' },
  { name: 'check-cleanup-postactions', reason: '对拍型：后置动作侧表 ⇄ 路径机械重算（双向），缺「单条侧表漂移必须红」合成样本' },
  { name: 'check-readme-negative-claims', reason: '找违规型：否定式承诺漂移即红，缺违规样本自检' },
  { name: 'check-doc-refs', reason: '找违规型：文档互引路径存在性 + 私钥令牌黑名单，缺违规样本自检' },
  { name: 'check-positive-controls', reason: '本文件即管辖门禁：其对照 = REGISTRY 各条实跑检查 + 差集断言（自指，不重复登记）' },
  { name: 'check-gate-roster', reason: '台账对拍：磁盘集合 ⇄ 三个注册表，缺「人为加/删一条注册必须红」样本' },
];

let fail = 0;
const check = (ok, label, detail = '') => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};

console.log('=== 正向对照管辖门禁 ===\n');
// v5 批次 9（门禁候选 4）：第 1 组从「文本关键词」改结构化对拍——旧判据只查文件里
// 含不含「正向对照」四个字，注释里写一句就过（被注释满足 = K07 同族的假绿）。
// 结构化判据：剥注释后必须存在**真实的对照断言行**（check(/fail( 调用且 label 含
// 「对照」）——写得出这行 = 判定器真有可判红的对照样本。
const missingSelfTest = [];
const brokenRun = [];
// v5 批次 9（门禁候选 4）：manual: true = 该门禁的对照形态是「人工/真破坏验证」
// （自检形态不在机检识别集内），显式登记而非静默漏判；机检条目数收口见第 1 组断言。
const manualEntries = [];
for (const e of REGISTRY) {
  if (e.manual) {
    manualEntries.push(e.file);
    continue;
  }
  const p = join(ROOT, 'tools', e.file);
  let text;
  try {
    text = readFileSync(p, 'utf8');
  } catch {
    brokenRun.push(`${e.file} 文件不存在`);
    continue;
  }
  const clean = text.replace(/^\s*\/\/.*$/gm, ' ').replace(/\/\*[\s\S]*?\*\//g, ' ');
  // 两种真实对照形态都要认：
  // ① check(/g.fail( 调用窗口内含「对照/正向/判红」（check 常跨行 ⇒ 起点后 400 字符窗口）；
  // ② fail-closed 对照串（`正向对照失败` 等 console.error+exit 形态，如
  //    check-escape-delegation / check-html-contract——字符串字面量在代码里，剥注释后仍在）。
  const hasRealControl =
    /正向对照失败|本门禁失效|必须判红|必须放行|永远不会被测坏|坏成永远放行|判定器没抓住|判定器误红|判据失灵/.test(clean) ||
    [...clean.matchAll(/(?:^|\n)\s*(?:check|g\.fail)\s*\(/g)].some(
      (m) => /对照|正向|判红/.test(clean.slice(m.index, m.index + 400)),
    );
  if (!hasRealControl) {
    missingSelfTest.push(`${e.file}（${e.reason}）—— 剥注释后无任何 check/fail 型对照断言行`);
    continue;
  }
  const r = spawnSync(process.execPath, [p, ...(e.selfTestArgs || [])], { cwd: ROOT, encoding: 'utf8' });
  if (r.status !== 0) brokenRun.push(`${e.file} 执行 exit ${r.status}`);
  // T1a-M02：flag-gated 门禁必须按登记参数跑，并真的打印对照组行；
  // 只 spawn 无参版本等于把「自检存在」当成「自检执行过」。
  if (e.selfTestArgs && !/对照|自检|正向/.test(r.stdout || '')) {
    brokenRun.push(`${e.file} 带 ${e.selfTestArgs.join(' ')} 执行后无对照/自检输出`);
  }
}
check(
  missingSelfTest.length === 0,
  `1. ${REGISTRY.length - manualEntries.length} 个机检型门禁均内置真实对照断言（剥注释后可判）+ ${manualEntries.length} 个显式登记人工/真破坏验证`,
  missingSelfTest.join('；'),
);
check(
  brokenRun.length === 0,
  '2. 全部登记门禁实际执行 exit 0（自检在门禁内随跑随验）',
  brokenRun.join('；'),
);

// ── 3~5（T1-M05）：MUST_RUN ⇄ REGISTRY 差集 —— 新增必跑门禁不登记即红 ──
// 唯一真源在 check-gate-roster.mjs 的 MUST_RUN；本文件不复制清单、只解析文本
// （复制一份必然漂移，两个真源各自漂移正是这条缺口当初的形态）。
const mustRun = (() => {
  const src = readFileSync(join(ROOT, 'tools', 'check-gate-roster.mjs'), 'utf8');
  const m = /const MUST_RUN = \[([\s\S]*?)\];/.exec(src);
  return m ? [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]) : [];
})();
check(
  mustRun.length >= 30,
  '3. MUST_RUN 解析自检（≥30 条；解析失效会让差集恒空 = 又一处「0 对象假绿」）',
  `解析到 ${mustRun.length} 条`,
);
const registeredNames = new Set(REGISTRY.map((e) => e.file.replace(/\.mjs$/, '')));
const pendingNames = new Set(PENDING_CONTROLS.map((e) => e.name));
const uncovered = mustRun.filter((n) => !registeredNames.has(n) && !pendingNames.has(n));
check(
  uncovered.length === 0,
  '4. MUST_RUN − REGISTRY − PENDING 为空（新增必跑门禁必须二选一登记）',
  uncovered.length
    ? `未登记：${uncovered.join('；')}`
    : `REGISTRY ${REGISTRY.length} 条 + PENDING ${PENDING_CONTROLS.length} 条 = MUST_RUN ${mustRun.length} 条`,
);
const stalePending = PENDING_CONTROLS.filter(
  (e) => !mustRun.includes(e.name) || registeredNames.has(e.name),
).map((e) => e.name);
check(
  stalePending.length === 0,
  '5. PENDING 白名单不腐烂（不在 MUST_RUN、或已进 REGISTRY 的条目必须删——迁移即收缩）',
  stalePending.join('；'),
);

// ── 5b~5d（T1b-M02，v7.2 C09）：单向核对补齐的三处盲区 ──
// ① PENDING 条目**已经带了对照块**却不被本管辖门禁执行（实算三条：item-intro /
//    optimizer-security / optimizer-groups-sidecar 各带 6/9/6 条合成样本，理由却写着
//    「缺合成样本」）——对照块坏了没人红。判据与第 1 组同一套剥注释口径。
const pendingWithControls = PENDING_CONTROLS.filter((e) => {
  // 自指豁免：本文件的 POSITIVE_CONTROLS 是登记表本身（reason 已写明「自指」），
  // 与各门禁「剥注释后判据定义文件排除自身」同一纪律。
  if (e.name === 'check-positive-controls') return false;
  let text;
  try {
    text = readFileSync(join(ROOT, 'tools', `${e.name}.mjs`), 'utf8');
  } catch {
    return false;
  }
  const clean = text.replace(/^\s*\/\/.*$/gm, ' ').replace(/\/\*[\s\S]*?\*\//g, ' ');
  return /POSITIVE_CONTROLS|positiveControls|正向对照失败|本门禁失效|必须判红/.test(clean);
}).map((e) => e.name);
check(
  pendingWithControls.length === 0,
  '5b. PENDING 条目不得已带对照块（带了却不执行 = 坏了没人红；迁入 REGISTRY 或删块）',
  pendingWithControls.length ? `已带对照仍留 PENDING：${pendingWithControls.join('；')}` : '无',
);
// ② manual 型登记此前不核文件存在、不核 reason 声称的样本——本次只补存在性（存在
//    是「人工验证可执行」的下界；样本条数核对归逐门禁自检）。
const manualMissing = manualEntries.filter((f) => !existsSync(join(ROOT, 'tools', f)));
check(
  manualMissing.length === 0,
  `5c. manual 型登记 ${manualEntries.length} 条的文件必须存在（此前不核，靠侥幸）`,
  manualMissing.join('；') || '全部在盘',
);
// ③ REGISTRY 条目退役/转 OPTIONAL 后必须同步摘牌（旧判据只查 MUST_RUN − 两表，
//    查不出「REGISTRY 里有 MUST_RUN 之外的孤儿」⇒ 并集 ≠ MUST_RUN）。
const registryOrphans = [...registeredNames].filter((n) => !mustRun.includes(n));
check(
  registryOrphans.length === 0,
  '5d. REGISTRY ∪ PENDING == MUST_RUN（双向差集；孤儿登记必须摘牌）',
  registryOrphans.length ? `REGISTRY 里不在 MUST_RUN 的孤儿：${registryOrphans.join('；')}` : '无孤儿',
);

if (fail > 0) {
  console.error('check-positive-controls: 存在缺口');
  process.exit(1);
}
console.log('check-positive-controls: 全部通过');

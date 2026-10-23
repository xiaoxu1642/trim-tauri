//! cleanup:scan / cleanup:execute / 失败重试 / 条目明细 / 锁定进程检查与终止。
//!
//! 删除口径（改这里之前先读 AGENTS §3）：常规清理按 v3.3.0 用户裁定**固定永久删**，
//! `toRecycle` 恒 false —— 这是产品语义不是回归；除常规清理外一律回收站优先。
//! 扫描走 `trim_finder`，删前过 `engine::protect::is_path_protected`；
//! 计划上限（PLAN_CAP_* / EXECUTE_MAX_ITEMS）是防止一键盘爆掉的保护位。
//! 被占用的项走 check-locked / kill-locked-processes，终止进程只白名单内放行。

use crate::engine::{guard, log};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tauri::Emitter;
use tauri::WebviewWindow;
use trim_finder::cleanup_scan;
use super::rules::*;
use super::state::*;

/// @@PLANFILE@@ 行字段长度上限（2026-10-04 审计 §3.4 落地的读侧防线；
/// v7.2-C03/N1a-L01：从内联字面量提成具名常量，与单源后的 PLAN_CAP_* 成对登记）。
const PLANFILE_ID_MAX_CHARS: usize = 160;
const PLANFILE_PATH_MAX_CHARS: usize = 2000;

// ==================== cleanup:scan ====================

/// 扫描累积器（对照 cleanup:scan 的 data / planBuf / planTruncated / planTotalRows）
#[derive(Default)]
pub(super) struct ScanAccum {
    data: Vec<Value>,
    plan: HashMap<String, Vec<Value>>,
    plan_truncated: HashSet<String>,
    plan_total: usize,
    total: usize,
    /// v2-L4P-34（C-6）：畸形行计数——静默丢弃等于把「行协议被畸形输入打破」
    /// 伪装成「什么都没扫到」（与 finder.rs ScanTally 同口径）
    malformed: usize,
    /// 只留第一条畸形原因（畸形内容可能是任意长文本，不照抄进日志）
    first_malformed: Option<String>,
}

impl ScanAccum {
    fn count_malformed(&mut self, reason: &str) {
        self.malformed += 1;
        if self.first_malformed.is_none() {
            self.first_malformed = Some(reason.chars().take(200).collect());
        }
    }

    /// 按行解析（对照 `onEngineStdout`），返回本轮新增的 `@@ITEM@@`（用于推进度）
    fn ingest_line(&mut self, line: &str) -> Option<Value> {
        if let Some(rest) = line.strip_prefix("@@PLANFILE@@") {
            // 计划文件行只进主进程快照（渲染层不消费），受总量防呆上限约束
            if self.plan_total >= PLAN_CAP_TOTAL {
                return None;
            }
            let pf = match serde_json::from_str::<Value>(rest) {
                Ok(v) => v,
                Err(e) => {
                    self.count_malformed(&format!("@@PLANFILE@@ 行解析失败: {e}"));
                    return None;
                }
            };
            let id = pf.get("id").and_then(|v| v.as_str());
            let path = pf.get("path").and_then(|v| v.as_str());
            match (id, path) {
                (Some(id), Some(path)) => {
                    // v7.2-C03（N1a-L01）：160/2000 从字面量提成具名常量（与上方
                    // 单源 PLAN_CAP 成对登记的字段长度上限）。
                    if id.chars().count() <= PLANFILE_ID_MAX_CHARS
                        && path.chars().count() <= PLANFILE_PATH_MAX_CHARS
                    {
                        let arr = self.plan.entry(id.to_string()).or_default();
                        if arr.len() < PLAN_CAP_PER_ITEM {
                            let size = pf.get("size").and_then(Value::as_u64).unwrap_or(0);
                            // Kudu S2（2026-10-16）：身份证基线随快照落地（0/缺 = 无基线，
                            // 删除侧不拦；父链重解析复检仍兜底）。
                            // ⚠️ 出生时间必须**按整数直读**，不许走 `js_num_or_zero`：那是
                            // `Number(x)||0` 的 f64 桥，而 UNIX 纳秒量级 1.79e18 远超双精度
                            // 能精确表示的 2^53 ⇒ 落地即被量化到 256ns 整倍数 ⇒ 执行侧现读的
                            // 精确值几乎必然不等 ⇒ 身份证守卫把整批文件判成「与扫描时不一致」
                            // 拒删（2026-10-22 真机实测：459 条基线 454 条被拒，界面报 976 MB、
                            // 实际只清出 1.7 MB）。ticks ≡ 0 (mod 64) 的那 1/64 才会侥幸相等。
                            let bt = pf.get("birthtimeNs").and_then(Value::as_u64).unwrap_or(0);
                            arr.push(json!({ "path": path, "size": size, "birthtimeNs": bt }));
                            self.plan_total += 1;
                        } else if self.plan_truncated.insert(id.to_string()) {
                            log::write_log(
                                "warn",
                                &format!("可删文件清单超过 {PLAN_CAP_PER_ITEM} 条上限: {id}"),
                            );
                        }
                    } else {
                        // 2026-10-04 审计 §3.4：超长行原先**既不入清单也不计数、不告警**
                        // —— 与本函数上面 `count_malformed` 建立的「必须计数或告警」
                        // 基线（v2-L4P-34 C-6）矛盾。一条 >2000 字符的路径
                        // （`\\?\` + 深树，MAX_PATH 是 32767）就这么从「明细」列表和
                        // 占用检测候选集里消失，无任何痕迹。
                        self.count_malformed(&format!(
                            "@@PLANFILE@@ 行超长（id {} 字符 / path {} 字符，上限 {} / {}）",
                            id.chars().count(),
                            path.chars().count(),
                            PLANFILE_ID_MAX_CHARS,
                            PLANFILE_PATH_MAX_CHARS
                        ));
                    }
                }
                _ => self.count_malformed("@@PLANFILE@@ 行缺少 id 或 path 字段"),
            }
            return None;
        }
        let Some(rest) = line.strip_prefix("@@ITEM@@") else {
            return None;
        };
        let item = match serde_json::from_str::<Value>(rest) {
            Ok(v) => v,
            Err(e) => {
                self.count_malformed(&format!("@@ITEM@@ 行解析失败: {e}"));
                return None;
            }
        };
        let id_ok = item.get("id").map(js_truthy).unwrap_or(false);
        if !id_ok {
            self.count_malformed("@@ITEM@@ 行缺少 id 字段");
            return None;
        }
        self.data.push(item.clone());
        Some(item)
    }
}

/// gameRedist 回填清单的条数闸（R4-L07，纯函数）。
///
/// 抽成纯函数是为了让「回填也受上限约束」这件事能被断言 —— 它发生在真实扫描之后、
/// 需要 `collect_redist_by_platform()` 触盘才走得到的位置，MockRuntime 与契约测试都
/// 够不着；只有把「截断 + 截断位」这一步做成纯函数，才能拿合成输入判红。
/// 上限真源与扫描侧同一个常量（`PLAN_CAP_PER_ITEM`，经 `rules.rs` 单源 re-export），
/// 不在本处再写一份数字（AGENTS §5.16）。
///
/// 返回 `(写入快照的 files 数组, 是否被截断)`。
pub(super) fn cap_backfill_files(files: &[(String, u64)], cap: usize) -> (Vec<Value>, bool) {
    let truncated = files.len() > cap;
    let arr = files
        .iter()
        .take(cap)
        .map(|(p, s)| json!({ "path": p, "size": *s as i64 }))
        .collect();
    (arr, truncated)
}

/// 跨条目重复计账配对（渲染层汇总去重的唯一数据源）。
///
/// 为什么要在主进程算：扫描侧每条 item 各自遍历自己的目标（native-scanner 的 `seen`
/// 只在单条目内生效），而渲染层的汇总历来是逐条相加。2026-10-22 真机实测：gfx 组
/// `nvidiaCache`（pathPs 整树）报的 387,378,791 B 与 `nvidiaShaderCache` 清单里落在
/// 同一目录树下的 157 个文件**逐字节相等** ⇒ 界面显示 976 MB、真实可清 608 MB（虚高 1.6×）。
///
/// 口径只有一条：**逐文件按 `paths::path_key` 认领**，第一个认领者留下、后来者按
/// (先到条目, 后到条目) 记一档重叠字节。2026-10-23 扫描器物化 pathPs 清单
/// （`get_path_deletable_stats(..., collect_files=true, cap)`）之后整树条目也在场，
/// 原先「拿父条根前缀反查别人清单」那档近似口径随之退役 —— 它会把子条目的字节整段
/// 扣给父条，和精确认领同时跑还要双重扣减。
///
/// 唯一残余边界：清单被 PLAN_CAP 截断（`filesTruncated`）的条目只按**已列出的部分**
/// 配对，未列出的重叠看不见 ⇒ 汇总偏大（退回旧行为方向，不会把可清量报小）。
/// pathPs ↔ pathPs 的字面同根由装载侧登记册（`rules.rs` 的 `ps|` 键）与 Node 门禁
/// `check-cleanup-rule-contract` 的覆盖台账兜住。
///
/// 每个无序对只挂在数组里**后到**的那一条上（`overlapsWith`），渲染层按「两端都在勾选
/// 集合内」扣一次，所以「只勾父条」时父条照样报满、不虚低。
fn attach_cross_item_pairs(data: &mut [Value]) -> u64 {
    // 单条扫描没有跨条目配对可做（partial 扫描的常见形状）：不建认领表。
    if data.len() < 2 {
        return 0;
    }
    let mut first_claim: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut pairs: std::collections::HashMap<(usize, usize), (u64, u64)> = std::collections::HashMap::new();

    for (idx, item) in data.iter().enumerate() {
        // 1B：files 只读，借用即可——旧形态 `.cloned()` 把整份数组复制进临时 Vec，
        // 十万级文件时是无谓的大块分配。判定与输出不变（golden 用例钉住）。
        let Some(files) = item.get("files").and_then(Value::as_array) else {
            continue;
        };
        // 条目内先按归一键去重：同一文件在同一条目里出现两次不算「跨条目重叠」，
        // 而且认领表只认一次，否则后一条会被同一文件扣两遍
        let mut seen_in_item: std::collections::HashSet<String> =
            std::collections::HashSet::with_capacity(files.len());
        for f in files {
            let Some(p) = f.get("path").and_then(Value::as_str) else { continue };
            let size = f.get("size").and_then(Value::as_u64).unwrap_or(0);
            let k = crate::engine::paths::path_key(p);
            if !seen_in_item.insert(k.clone()) {
                continue;
            }
            match first_claim.get(&k).copied() {
                Some(owner) if owner != idx => {
                    let e = pairs.entry((owner.min(idx), owner.max(idx))).or_default();
                    e.0 += size;
                    e.1 += 1;
                }
                Some(_) => {}
                None => {
                    first_claim.insert(k, idx);
                }
            }
        }
    }

    let mut inflated = 0u64;
    // 按 key 排序遍历：pairs 是 HashMap，遍历序不稳定 ⇒ 同尺寸输入必须产出逐字节相同的
    // data（§5.16「判据与数值表不许两套实现」的反例形态就是「顺序随哈希 seed 漂」）
    let mut keys: Vec<(usize, usize)> = pairs.keys().copied().collect();
    keys.sort_unstable();
    for (a, b) in keys {
        let (bytes, files) = pairs[&(a, b)];
        inflated += bytes;
        let other_id = data[a].get("id").and_then(Value::as_str).unwrap_or("").to_string();
        let entry = json!({ "with": other_id, "bytes": bytes, "files": files });
        if let Some(obj) = data[b].as_object_mut() {
            let arr = obj
                .entry("overlapsWith".to_string())
                .or_insert_with(|| Value::Array(Vec::new()));
            if let Some(v) = arr.as_array_mut() {
                v.push(entry);
            }
        }
    }
    inflated
}

/// 扫描核心（P2-B 抽取，2026-10-16）：与窗口/快照解耦——读规则 → 原生扫描 → 组装条目数据。
///
/// `emit` 是进度出口（本轮新增条目 + done/total）：窗口版（`do_cleanup_scan`）注入 emit 闭包
/// （原 `ingest_and_emit` 的 emit 负载 `{done,total,item}` 逐字保留在其闭包里）；无头版
/// （`cleanup_scan_headless`）传 no-op。**无窗口、无快照**——快照登记与 partial 语义留在
/// `do_cleanup_scan`（窗口态概念）。返回 `Ok((data, malformed_lines))` / `Err(message)`，
/// 两处错误消息与原实现逐字一致。
fn run_cleanup_scan_core<E: FnMut(&Value, usize, usize) + 'static>(cats: Vec<String>, mut emit: E) -> Result<(Vec<Value>, usize), String> {
    let configured = load_paths_config();
    let rules = rules_value_arc().map_err(|e| {
        log::write_log("error", &format!("扫描异常: {e}"));
        e
    })?;
    let cats_json = json_text(&Value::from(cats.clone()));
    let cfg_json = json_text(&configured);
    let rules_json = json_text(&rules);
    // R10（2026-10-15）：保护清单与执行侧同源注入（`protected_roots_json()`，
    // 与 finder 回收站链同一份）——扫描侧据此把受保护目标排除在**可删集**之外，
    // 不再出现「规则命中、执行侧恒拒、体积照报」。缺省时扫描侧走 default_from_env 兜底。
    let protect_json = crate::engine::protect::protected_roots_json();
    let accum = Arc::new(Mutex::new(ScanAccum {
        total: cats.len(),
        ..Default::default()
    }));
    // 原生引擎：进程内直调 + 逐行回调推进度（不再 spawn finder.exe；B 批 sink 化后的数据入口）。
    // 行 → ingest_line → 新增条目经 emit 出口（窗口版 emit 事件 / 无头版 no-op）。
    let hook_accum = accum.clone();
    let hook: Option<Box<dyn FnMut(&str)>> = Some(Box::new(move |line: &str| {
        let (item, done, total) = {
            let mut a = hook_accum.lock().unwrap_or_else(|e| e.into_inner());
            let item = a.ingest_line(line);
            (item, a.data.len(), a.total)
        };
        if let Some(item) = item {
            emit(&item, done, total);
        }
    }));
    // S3：纯 Rust 原生
    //
    // 退出码非 0 的分支**就地 return**（下面没有第二个 `if code != 0`）：原实现
    // 在块外又判了一次 `code != 0`，而块内已经 return 了，那句恒假、且让 `code`
    // 在块外留一个看似有意义的绑定。2026-10-04 审计 §3.2 顺手删掉。
    let stderr = {
        let (code, _stdout, stderr) = cleanup_scan::run_json(&[cats_json, cfg_json, protect_json], &rules_json, hook);
        if code != 0 {
            let msg = if stderr.trim().is_empty() { format!("退出码 {code}") } else { stderr.trim().to_string() };
            log::write_log("error", &format!("Rust 清理扫描失败: {msg}"));
            return Err(format!("原生扫描失败: {msg}"));
        }
        stderr
    };
    // 2026-10-04 磁盘清理审计 §3.2：stderr 是扫描引擎**唯一**的 fail-closed 留痕通道，
    // 此前只在退出码非 0 时被读，成功路径直接丢弃 —— 而「扫描成功但某个条目空」
    // 恰恰只发生在成功路径（单条规则变量没解析 / pathPs 被拒 → 该条目 exists:false、
    // size:0，用户看到「有条目但一个文件都没扫到」）。引擎自己给的判据是
    // 「供『扫描命中、执行 0 删』类问题对账」，对账通道在对账最需要的时候是关的。
    //
    // 刻意记 `warn` 而不是 `error`：这些不是失败，是「已按规则降级并留痕」。
    // 空 stderr 是绝大多数扫描的常态，不要为它写一行日志。
    if !stderr.trim().is_empty() {
        log::write_log("warn", &format!("清理扫描留痕（已降级处理，非失败）:\n{}", stderr.trim()));
    }
    // 把可删文件清单并进条目（无清单的条目补空数组，执行/明细侧统一按数组消费）
    // mut data：P2-06 注入 postAction 需要二次可变遍历（§P2-06 派生字段）
    let (mut data, plan_total, malformed) = {
        let mut a = accum.lock().unwrap_or_else(|e| e.into_inner());
        let plan = std::mem::take(&mut a.plan);
        let truncated = std::mem::take(&mut a.plan_truncated);
        let mut data = std::mem::take(&mut a.data);
        for item in data.iter_mut() {
            let id = item.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let files = plan.get(&id).cloned().unwrap_or_default();
            if let Some(obj) = item.as_object_mut() {
                obj.insert("files".into(), Value::Array(files));
                if truncated.contains(&id) {
                    obj.insert("filesTruncated".into(), Value::Bool(true));
                }
            }
        }
        (data, a.plan_total, (a.malformed, a.first_malformed.take()))
    };
    // 批次 B：gameRedist 三条规则的 size 与文件清单由 Rust 主进程回填（native-scanner 只发 size=0 占位）
    {
        const GAME_REDIST_IDS: &[&str] = &["steamRedistCache", "epicRedistCache", "wegameRedistCache"];
        let present = data.iter().any(|it| {
            GAME_REDIST_IDS.iter().any(|id| it.get("id").and_then(|v| v.as_str()) == Some(id))
        });
        if present {
            let redist_result = crate::commands::gameclean::collect_redist_by_platform();
            let mut backfill: HashMap<&str, (u64, Vec<(String, u64)>)> = HashMap::new();
            backfill.insert("steamRedistCache", (redist_result.steam.total_size, redist_result.steam.files.clone()));
            backfill.insert("epicRedistCache", (redist_result.epic.total_size, redist_result.epic.files.clone()));
            backfill.insert("wegameRedistCache", (redist_result.wegame.total_size, redist_result.wegame.files.clone()));
            let mut backfilled_items = 0usize;
            let mut backfilled_files = 0usize;
            for item in data.iter_mut() {
                // id 先取成 owned：下面 `item.as_object_mut()` 要可变借用，
                // 而日志串里还要用 id —— 借用跨进临界区会撞 E0502。
                let Some(id) = item.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()) else { continue };
                let Some((total_size, files)) = backfill.get(id.as_str()) else { continue };
                // R4-L07：回填清单必须过与扫描侧**同一个** PLAN_CAP_PER_ITEM，并在超限时
                // 置 filesTruncated。旧形态把整条清单原样塞回 —— 既绕开上限（回填条数无
                // 上限）又不重算截断位，用户在确认弹窗里看到的清单比实际少且看不出被截断。
                // 身份证基线：gameclean 只回 `{path,size}`，回填条目**没有 birthtimeNs**，
                // 引擎 Kudu S2 的 identity 表对这 3 条恒无基线（守卫不生效、方向是放行），
                // 该事实由 details 的 identityUnbaselined 计数外发；父链 reparse 复检仍兜底。
                // 要补 birthtime 得改 gameclean 的返回形状（他单元射程）。
                let (files_arr, files_truncated) = cap_backfill_files(files, PLAN_CAP_PER_ITEM);
                if let Some(obj) = item.as_object_mut() {
                    obj.insert("size".into(), Value::from(*total_size as i64));
                    obj.insert("exists".into(), Value::Bool(!files.is_empty()));
                    obj.insert("files".into(), Value::Array(files_arr));
                    if files_truncated {
                        obj.insert("filesTruncated".into(), Value::Bool(true));
                        log::write_log(
                            "warn",
                            &format!(
                                "gameRedist 回填清单超过 {PLAN_CAP_PER_ITEM} 条上限: {id}（实测 {} 个文件，清单已截断并标注）",
                                files.len()
                            ),
                        );
                    }
                }
                backfilled_items += 1;
                backfilled_files += files.len();
            }
            if backfilled_items > 0 {
                log::write_log(
                    "info",
                    &format!(
                        "gameRedist 回填: {backfilled_items} 个条目 / {backfilled_files} 个文件（无 birthtimeNs 身份证基线，引擎按 identityUnbaselined 记账）"
                    ),
                );
            }
            if !redist_result.notes.is_empty() {
                log::write_log("info", &format!("gameRedist 回填: {}", redist_result.notes.join("; ")));
            }
        }
    }
    // 跨条目重复计账配对：同一条目集里两条 item 覆盖到同一批文件时，逐条相加会虚高
    // （2026-10-22 真机：界面 976 MB、真实可清 607 MB）。配对挂在本轮数据上，
    // 渲染层的汇总一律按「两端都在勾选集合内」扣一次。
    let inflated = attach_cross_item_pairs(&mut data);
    if inflated > 0 {
        log::write_log(
            "info",
            &format!("跨条目重复计账 {inflated} 字节（已在配对里登记，渲染层汇总按配对扣减）"),
        );
    }
    // v2-L4P-34（C-6）：畸形行不再静默——计数进日志，UI 才能区分「真干净」与「协议被打破」
    if malformed.0 > 0 {
        log::write_log(
            "warn",
            &format!(
                "扫描行协议出现 {} 条畸形行（已丢弃），首因: {}",
                malformed.0,
                malformed.1.as_deref().unwrap_or("未知")
            ),
        );
    }
    log::write_log(
        "info",
        &format!(
            "扫描完成(rust): {} 项, 计划文件 {} 条",
            data.len(),
            plan_total
        ),
    );
    Ok((data, malformed.0))
}

/// 扫描主体（纯原生引擎；PS 回退已随 S3 删除，见 :11）——窗口版：核心 + 进度 emit + 快照登记。
pub(super) fn do_cleanup_scan<R: tauri::Runtime>(window: &WebviewWindow<R>, label: &str, cats: Vec<String>, partial: bool) -> Value {
    let win = window.clone();
    let (mut data, _malformed) = match run_cleanup_scan_core(cats, move |item, done, total| {
        let _ = win.emit(
            "cleanup:scan-progress",
            json!({ "done": done, "total": total, "item": item }),
        );
    }) {
        Ok(v) => v,
        Err(msg) => return json!({ "success": false, "message": msg, "data": [] }),
    };
    {
        // v2 §3.1/§4.2：剥离动作只放在窗口适配层。共享核心与无头入口仍返回完整 files，
        // 这里把进入本槽的条目清单搬进快照，窗口回执从此不再携带逐文件清单。
        let fresh = snapshot_by_id_taking(&mut data);
        let mut guard = snapshots().lock().unwrap_or_else(|e| e.into_inner());
        if partial {
            // partial：只覆盖本次命中的 id，其余条目的旧快照保留——否则「只刷新回收站」
            // 之后，未重扫条目的执行校验（validate_snapshot_items 缺快照即整批拒绝）会全部失败。
            guard.entry(label.to_string()).or_default().extend(fresh);
        } else {
            // X-1（2026-10-15）：只替换**本窗自己的槽**。`guard` 是全局
            // HashMap<label, …>，而 cleanup_scan 的档位是 guard_readonly（APP_WINDOWS
            // 四个 label 都能调）——整表替换会把其它窗口的槽全部清空，对方已扫条目
            // 执行时全报「不是最近一次扫描结果」。旧的「整表替换副作用式清空」经现算
            // 无任何调用方依赖（清桶只走命令侧本槽 insert-empty），可直接收窄。
            guard.insert(label.to_string(), fresh);
        }
    }
    inject_post_actions(&mut data);
    json!({ "success": true, "data": data })
}

/// P2-06：给每个命中项注入后置动作（postAction: explorer|none），供前端在清理
/// 完成后提示「需重启资源管理器」。派生响应字段，不进规则库、不触发重签。
/// （P2-B 起抽为独立函数：窗口版在**快照登记之后**调用、与重构前顺序一致——快照
/// 不携带 postAction；无头版在输出前调用。）
fn inject_post_actions(data: &mut [Value]) {
    for row in data.iter_mut() {
        // 先不可变取 id（结束借用），再可变插入，避免同一行上的借用冲突
        let id = row.get("id").and_then(|v| v.as_str()).map(str::to_string);
        if let (Some(obj), Some(id)) = (row.as_object_mut(), id) {
            obj.insert("postAction".into(), json!(post_action_of(&id)));
        }
    }
}

/// 把规则库某层的 items 数组里的 id 收进 out（headless 全量用）。
fn collect_rule_ids(items: Option<&Value>, out: &mut Vec<String>) {
    if let Some(arr) = items.and_then(|v| v.as_array()) {
        for it in arr {
            if let Some(id) = it.get("id").and_then(|v| v.as_str()) {
                out.push(id.to_string());
            }
        }
    }
}

/// 规则库全部条目 id（headless 缺省全量 = UI「全量扫描把全部条目 id 传上来」的等价物）。
fn all_rule_ids() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(rules) = rules_value_arc() {
        if let Some(groups) = rules.get("groups").and_then(|v| v.as_array()) {
            for g in groups {
                collect_rule_ids(g.get("items"), &mut out);
                if let Some(sgs) = g.get("subGroups").and_then(|v| v.as_array()) {
                    for sg in sgs {
                        collect_rule_ids(sg.get("items"), &mut out);
                    }
                }
            }
        }
    }
    out
}

/// P2-B（2026-10-16）：无头清理扫描入口（**只读**）——供 `examples/scan.rs` 与会话内脚本复用。
///
/// - 与 `cleanup:scan` **同一条核心**（`run_cleanup_scan_core`）；不绑定窗口、不登记快照、零写入；
/// - `cats` 为空 = 全量（现取规则库全部条目 id，与 UI「全量扫描」口径一致）；
/// - 返回 `{ success, data, counts }`。counts 口径：`lockedFiles/lockedEntries` 是扫描侧
///   **不可删**的口径（保护清单排除 + 独占探测失败**两类合并**，native 行协议单一口径
///   `lockedCount`——v3 规格里的 protected/locked 两词在数据面即是它，如实透传不虚拆）；
///   `filesTotal` 是可删文件清单条数；`malformedLines` 是行协议畸形行数（>0 即协议异常，
///   fail-loud 透传，与 `@@PLANFILE@@` 超长/坏行记账同源）。
pub fn cleanup_scan_headless(cats: Vec<String>) -> Value {
    let cats = if cats.is_empty() { all_rule_ids() } else { cats };
    let (mut data, malformed) = match run_cleanup_scan_core(cats, |_, _, _| {}) {
        Ok(v) => v,
        Err(msg) => return json!({ "success": false, "message": msg, "data": [], "counts": Value::Null }),
    };
    inject_post_actions(&mut data);
    let num = |v: Option<&Value>| -> u64 {
        // extra 字段（lockedCount/skippedReparse）走字符串形态（前端 Number() 转换），容错数字形态
        match v {
            Some(Value::String(s)) => s.parse().unwrap_or(0),
            Some(Value::Number(n)) => n.as_i64().unwrap_or(0).max(0) as u64,
            _ => 0,
        }
    };
    let mut entries: u64 = 0;
    let mut files_total: u64 = 0;
    let mut locked_files: u64 = 0;
    let mut locked_entries: u64 = 0;
    let mut truncated_entries: u64 = 0;
    let mut skipped_reparse_total: u64 = 0;
    for it in &data {
        entries += 1;
        if let Some(files) = it.get("files").and_then(|v| v.as_array()) {
            files_total += files.len() as u64;
        }
        let lc = num(it.get("lockedCount"));
        if lc > 0 {
            locked_files += lc;
            locked_entries += 1;
        }
        if it.get("filesTruncated").and_then(|v| v.as_bool()).unwrap_or(false) {
            truncated_entries += 1;
        }
        skipped_reparse_total += num(it.get("skippedReparse"));
    }
    json!({
        "success": true,
        "data": data,
        "counts": {
            "entries": entries,
            "filesTotal": files_total,
            "lockedFiles": locked_files,
            "lockedEntries": locked_entries,
            "truncatedEntries": truncated_entries,
            "skippedReparseTotal": skipped_reparse_total,
            "malformedLines": malformed,
        }
    })
}

/// cleanup:scan — 扫描可清理项（纯原生引擎；进度走 `cleanup:scan-progress`）
#[tauri::command]
pub async fn cleanup_scan<R: tauri::Runtime>(window: WebviewWindow<R>, categories: Option<Value>, partial: Option<bool>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg, "data": [] });
    }
    let cats: Option<Vec<String>> = categories.as_ref().and_then(|c| c.as_array()).and_then(|a| {
        // 上限 512 与契约 maxItems(400) 对齐并留余量：全量扫描把全部条目 id 传上来，
        // 规则库扩到 205 条时旧上限 200 直接把全量扫描拒成「清理分类参数无效」
        // （2026-10-13 真机复检实测引爆）。上限的本意是防滥用，不该比库容量还小。
        if a.is_empty() || a.len() > 512 {
            return None;
        }
        let mut out = Vec::with_capacity(a.len());
        for v in a {
            let s = v.as_str()?;
            if s.chars().count() > 160 {
                return None;
            }
            out.push(s.to_string());
        }
        Some(out)
    });
    let Some(cats) = cats else {
        return json!({ "success": false, "message": "清理分类参数无效", "data": [] });
    };
    let partial = partial.unwrap_or(false);
    let label = window.label().to_string();
    // 审查 2-3：先置空桶，扫描成功后填充（**仅全量扫描**）。
    // 2026-10-07 用户裁定「扫描范围 = 勾选项」：partial 扫描必须**保桶**并合并——其余
    // 条目的旧快照要供 cleanup:execute 校验（validate_snapshot_items 对缺快照的条目
    // 整批拒绝，清桶会让「只刷新回收站」之后清理其他项全部报快照失败）。
    //
    // 谁还能并行写这张表（X-1，2026-10-15）：另一窗口的 cleanup_scan——本表按 label
    // 分槽，四个 APP_WINDOWS 都能调（档位 guard_readonly）。因此本处与 do_cleanup_scan
    // 的落盘**都只许动本槽**：整表替换会把别人已扫的槽顶掉（§5.25 同族事故形态）。
    if !partial {
        snapshots()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(label.clone(), HashMap::new());
    }
    log::write_log("info", &format!("开始扫描{}: {}", if partial { "（仅勾选）" } else { "" }, cats.join(", ")));
    let win = window.clone();
    let task = tauri::async_runtime::spawn_blocking(move || do_cleanup_scan(&win, &label, cats, partial));
    match task.await {
        Ok(v) => v,
        Err(e) => json!({ "success": false, "message": e.to_string(), "data": [] }),
    }
}

// ==================== cleanup:execute ====================

/// cleanup:execute — 执行清理（危险通道：快照校验 + 删除前刷盘 + **全部直接永久删**）
///
/// # `to_recycle` 为什么收下参数却恒为 false
///
/// v3.3.0 用户裁定：常规清理**固定永久删**，`toRecycle` 恒 false。此前这条裁定
/// 只在渲染层强制（`cleanup.js` 里 `const toRecycle = false;`），命令侧是
/// `to_recycle.unwrap_or(false)` —— 也就是**任何**传 `true` 的调用方都能翻转。
/// 审计 §3.6 把它钉到删除真正发生的地方。
///
/// 2026-10-12 用户裁定（实测「清理一直卡死进度」后）：**移除批次 B 遗留的
/// gameRedist 回收站窄口径例外** —— 扫描出来的项目一律直接删除，不再逐文件走
/// `SHFileOperationW` 移入回收站。同日二次裁定：**回收站重试链整链退役**
/// （`cleanup:retry-failed-delete` / `TRASH_FAILURES` / 前端 `offerTrashRetry`
/// 一并撤除）——它的唯一喂给源就是那条回收站例外，退役后无任何消费者。
///
/// 参数**保留**是为了不破坏 `CHANNEL_MAP` 的载荷键（删字段会让渲染层与
/// `tauri-api.js` 两侧同时改，且旧版前端传了它会被静默吞掉）。收到 true 时
/// 如实回执并写日志，不静默改写 —— 让调用方知道自己的参数没生效。
///
/// 2026-10-04 审计 §5.5（NIT）：`force` 同属载荷兼容残留——「PS 闸」已随 S3
/// 纯原生删除，主进程对它**没有任何判定语义**，只进开始清理的日志供对账。
/// 渲染层 cleanup.js 侧指向这道不存在的门的旧注释已同步订正；别让日志里
/// 的 `force=true/false` 被误读成还有一道闸。
#[tauri::command]
pub async fn cleanup_execute<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    items: Option<Value>,
    force: Option<bool>,
    to_recycle: Option<bool>,
    auto_rebuild: Option<bool>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();
    let force = force.unwrap_or(false);
    // R4-L05：参数被忽略必须**上回执**，不能只写日志。函数头原本承诺「收到 true 时如实
    // 回执并写日志，不静默改写」，代码只落了日志那一半 —— 调用方从回执看不出自己的
    // 参数没生效（与 C06 回执诚实度同族：被忽略的入参要在回执上留痕）。
    let to_recycle_ignored = to_recycle == Some(true);
    if to_recycle_ignored {
        log::write_log(
            "warn",
            "cleanup:execute 收到 to_recycle=true，已按 v3.3.0 裁定忽略（常规清理固定永久删）",
        );
    }
    // R4-M02：这个钉桩必须**真正决定删除形态**。旧形态下删除原语吃的是字面 `false`，
    // 钉桩变量在 debug_assert 之后再无消费点、也不进 spawn_blocking 闭包 —— 把实参改成
    // `true` 会让引擎走「只枚举不删除、freed 照计」分支：一个文件没删也没进回收站，
    // 回执仍 success:true、释放量照报，而整套契约测试照样全绿。
    let to_recycle = false; // v3.3.0 用户裁定：常规清理固定永久删
    let auto_rebuild = auto_rebuild.unwrap_or(false);
    let snapshot = snapshots()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&label)
        .cloned()
        .unwrap_or_default();
    let Some(safe_items) = validate_snapshot_items(items.as_ref(), &snapshot) else {
        return json!({ "success": false, "message": "清理项不是最近一次扫描结果，已拒绝执行" });
    };
    let rules = match rules_value_arc() {
        Ok(r) => r,
        Err(e) => return json!({ "success": false, "message": e }),
    };
    log::write_log(
        "info",
        &format!(
            "开始清理: {} 项, force={force}, autoRebuild={auto_rebuild}",
            safe_items.len()
        ),
    );
    log::flush_sync(); // 审查v4-L3：危险操作执行前强制刷盘
    debug_assert!(!to_recycle, "v3.3.0 永久删钉桩（本命令固定全量永久删）");

    // 2026-10-12 用户裁定：不再分桶——扫描出来的项目一律直接永久删
    //（gameRedist 的回收站窄口径例外已移除，见上方 `to_recycle` 注释）。
    let win = window.clone();
    let task = tauri::async_runtime::spawn_blocking(move || {
        // S3：纯 Rust 原生——单批全量永久删
        let mut raw_stdout = String::new();
        let mut first_err: Option<String> = None;

        if !safe_items.is_empty() {
            // 逐项进度：每项开工前推送（第 k/N 项 + 名称），供渲染层把进度条从
            // 「假走到 90% 再冻结」改为按真实项数推进（2026-10-12 卡死观感修复）。
            let progress_cb = |done: usize, total: usize, name: &str| {
                let _ = win.emit(
                    "cleanup:execute-progress",
                    json!({ "done": done, "total": total, "name": name }),
                );
            };
            match crate::engine::native::cleanup_execute(
                &safe_items,
                &rules,
                to_recycle,
                auto_rebuild,
                Some(&progress_cb),
            ) {
                Ok(result) => {
                    let data = json!({
                        "details": result.details,
                        "freed": result.freed,
                        "fileCount": result.file_count,
                    });
                    raw_stdout.push_str(&serde_json::to_string(&data).unwrap_or_default());
                    raw_stdout.push('\n');
                }
                Err(e) => {
                    // R4-L04：回给渲染层的 message 不再带「永久删桶」——那是 2026-10-12
                    // 分桶退役前的词，渲染层把它当 toast 文案，等于当着用户说「还有另一个桶」。
                    // 桶/删除形态这类内部口径只留在日志里供对账。
                    log::write_log("error", &format!("原生执行失败(永久删形态): {e}"));
                    first_err = Some(format!("原生执行失败: {e}"));
                }
            }
        }

        if let Some(msg) = first_err {
            return json!({ "success": false, "message": msg });
        }

        let raw = raw_stdout;
        let diag_stripped = crate::diag::extract_diag_lines(&raw, "cleanup.execute");
        // 2026-10-12：@@RECYCLE@@ 回环协议随回收站例外一并移除（原生永久删桶从不
        // 产生条目），回执正文即原生输出原文，不再需要逐行分流与畸形行计数。
        let body = if raw.trim().is_empty() {
            diag_stripped.trim().to_string()
        } else {
            raw.trim().to_string()
        };
        let Ok(mut data) = serde_json::from_str::<Value>(&body) else {
            return json!({ "success": false, "message": "解析结果失败", "raw": diag_stripped });
        };
        let (total_freed, success, n_partial, skipped) = summarize_details(&data);
        let n_residual = data
            .get("details")
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|d| js_num_or_zero(d.get("residual")) > 0.0)
                    .count()
            })
            .unwrap_or(0);
        let failed = data
            .get("details")
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    // v5 C-3：引擎侧的硬失败有**两种**写法 —— `"error"`（备份失败等前置中止）
                    // 与 `"fail"`（DISM 失败 / 注册表全失败 / 文件全被占用）。此前只数 error，
                    // 于是 `success: failed == 0` 把整批真失败渲染成成功提示。
                    .filter(|d| matches!(d.get("status").and_then(|v| v.as_str()), Some("error") | Some("fail")))
                    .count()
            })
            .unwrap_or(0);
        // v6-K10：「全 skip / 0 删除」时把原因逐条透出（太新/排除/未解析变量/
        // 受保护拒绝……引擎侧 details.message 里都有）——渲染层要呈现时有据可查，
        // 不再是干巴巴的「释放 0 B」。上限 20 条防回执膨胀。
        let nothing_done = !cleanup_receipt_success(failed, success, n_partial);
        let skipped_reasons: Vec<Value> = if nothing_done {
            let empty: Vec<Value> = Vec::new();
            data.get("details")
                .and_then(|d| d.as_array())
                .unwrap_or(&empty)
                .iter()
                .take(20)
                .map(|d| {
                    json!({
                        "id": d.get("id"),
                        "name": d.get("name"),
                        "status": d.get("status"),
                        "message": d.get("message"),
                        "protectedBlocked": js_num_or_zero(d.get("protectedBlocked")) as i64,
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        if let Some(o) = data.as_object_mut() {
            o.insert("failed".into(), Value::from(failed as i64));
            o.insert("partial".into(), Value::from(n_partial as i64));
            // v5 C-2：四个汇总字段一律无条件回写（永久删路径也要有 totalFreed / success /
            // skipped，否则前端恒显「释放 0 B」）
            o.insert("totalFreed".into(), Value::from(total_freed));
            o.insert("success".into(), Value::from(success));
            o.insert("skipped".into(), Value::from(skipped));
            if nothing_done {
                o.insert("skippedReasons".into(), Value::Array(skipped_reasons));
            }
        }
        log::write_log(
            "info",
            &format!(
                "清理完成: 实测释放 {total_freed} 字节, 成功 {success}, 失败 {failed}, 部分成功 {n_partial}, 跳过 {skipped}, 有残留 {n_residual} 项"
            ),
        );
        if let Some(arr) = data.get("details").and_then(|d| d.as_array()) {
            for d in arr {
                let msg: String = d
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .chars()
                    .take(200)
                    .collect();
                let id = d.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let name = d
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|n| format!("（{}）", n.chars().take(60).collect::<String>()))
                    .unwrap_or_default();
                log::write_log(
                    "info",
                    &format!(
                        "  清理明细 [{}] {id}{name}: {msg}（释放 {} 字节, 残留 {}）",
                        d.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                        js_num_or_zero(d.get("freed")) as i64,
                        js_num_or_zero(d.get("residual")) as i64
                    ),
                );
            }
        }
        // 2026-10-04 审计 §4.3：确认清单（快照 files）与实际删除集（执行侧重遍历）
        // 的口径差逐条留痕 —— 不改语义（绑文件集是另一个裁定），只让「删了清单外
        // 的文件」这件事在日志里可对账。plan_delta_warnings 本体与断言在 state.rs。
        {
            let empty: Vec<Value> = Vec::new();
            let details = data.get("details").and_then(|d| d.as_array()).unwrap_or(&empty);
            for w in plan_delta_warnings(details, &snapshot) {
                log::write_log("warn", &w);
            }
        }
        // R2a-M03：本批「删除没有成功」的文件路径记进命令体侧的失败回执台账 ——
        // 「登记重启后删除」的第一道约束（只收删除失败项）从此有命令体判据，
        // 不再只由渲染层（cleanup.js 的 collectFailedPaths）维持。
        crate::engine::delete_failed::record(
            &label,
            crate::engine::delete_failed::DOMAIN_CLEANUP,
            cleanup_failed_paths(
                data.get("details")
                    .and_then(|d| d.as_array())
                    .map(|a| a.as_slice())
                    .unwrap_or(&[]),
            ),
        );
        // 成功判据（v6-K10 收口）：硬失败（error ∪ fail，见上面 v5 C-3）为 0
        // **且确实删了东西**——failed==0 但 success/partial 全 0 = 全 skip（太新/
        // 排除/未解析/受保护）或空跑，按「未达成」处理而不是 success:true；
        // partial 属「部分成功」，由渲染层另行提示
        json!({ "success": cleanup_receipt_success(failed, success, n_partial), "data": data })
    });
    match task.await {
        Ok(v) => with_ignored_flags(v, to_recycle_ignored),
        Err(e) => with_ignored_flags(
            json!({ "success": false, "message": e.to_string() }),
            to_recycle_ignored,
        ),
    }
}

/// R4-L05：把「被忽略的入参」写进回执（纯函数，便于断言）。
///
/// 判据口径来自 C06 回执诚实度：成功位不得由可选计数派生、失败要带状态位、
/// **被忽略的入参要在回执上留痕**。本函数只管第三句 —— 渲染层据此能把
/// 「你勾了进回收站但按裁定没走」显示出来，而不是只在日志里飘一条 warn。
pub(super) fn with_ignored_flags(receipt: Value, to_recycle_ignored: bool) -> Value {
    if !to_recycle_ignored {
        return receipt;
    }
    let mut v = receipt;
    if let Some(o) = v.as_object_mut() {
        o.insert("toRecycleIgnored".into(), Value::Bool(true));
    }
    v
}

/// v6-K10：清理回执的外层 success 判据（纯函数）。
///
/// 旧判据 `failed == 0` 有一个假绿方向：全部条目被 skip（太新 / 排除名单 /
/// 未解析变量 / 受保护拒绝）或根本没传条目时，failed 恒为 0 ⇒ 回 success:true，
/// 渲染层弹「清理完成！释放 0 B 空间」——「什么都没删」被说成「成功」。
/// 新口径：硬失败为 0 **且** success/partial 至少有一项（确实动过文件）。
/// 判红自证：把本函数改回 `failed == 0` ⇒ `全跳过回执必须 success_false` 红。
pub(super) fn cleanup_receipt_success(failed: usize, success: usize, partial: usize) -> bool {
    failed == 0 && (success > 0 || partial > 0)
}

/// 按 details 汇总 (totalFreed, success, partial, skipped)（对照 main.js 1416-1423）
pub(super) fn summarize_details(data: &Value) -> (i64, usize, usize, usize) {
    let mut total = 0i64;
    let mut success = 0usize;
    let mut partial = 0usize;
    let mut skipped = 0usize;
    for d in data
        .get("details")
        .and_then(|v| v.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[])
    {
        total += js_num_or_zero(d.get("freed")) as i64;
        match d.get("status").and_then(|v| v.as_str()) {
            Some("ok") => success += 1,
            Some("partial") => partial += 1,
            Some("skip") => skipped += 1,
            _ => {}
        }
    }
    (total, success, partial, skipped)
}

/// R2a-M03：本批「删除没有成功」的文件路径（纯函数，便于断言）。
///
/// 口径与渲染层 `cleanup.js` 的 `collectFailedPaths` 同源，但**更宽**：
///   · `failedFiles[].path` —— 引擎侧逐文件失败明细（被占用 / 权限不足）；
///   · `status` 为 `error` / `fail` 且自带 `path` 的行 —— 文件清理链那种「整项失败、
///     路径在行上」的形状。
/// 取「更宽」是刻意的：这道集合是**登记闸的白名单**（`pending_add` 凭它核对
/// 「只收删除失败项」），白名单窄于渲染层要送的那批时，登记会被误拒 —— 闸越宽，
/// 拦的只是「从没有失败过的文件」，而那正是闸要拦的东西。
pub(super) fn cleanup_failed_paths(details: &[Value]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in details {
        if let Some(ff) = d.get("failedFiles").and_then(|v| v.as_array()) {
            for f in ff {
                if let Some(p) = f.get("path").and_then(|v| v.as_str()) {
                    if !p.is_empty() {
                        out.push(p.to_string());
                    }
                }
            }
        }
        let status = d.get("status").and_then(|v| v.as_str()).unwrap_or("");
        if status == "error" || status == "fail" {
            if let Some(p) = d.get("path").and_then(|v| v.as_str()) {
                if !p.is_empty() {
                    out.push(p.to_string());
                }
            }
        }
    }
    let mut seen: Vec<String> = Vec::new();
    for p in out {
        if !seen.iter().any(|x| x.eq_ignore_ascii_case(&p)) {
            seen.push(p);
        }
    }
    seen
}

// ==================== cleanup:item-detail ====================

/// cleanup:item-detail — 枚举单个条目将删除的文件清单（只读）
#[tauri::command]
pub async fn cleanup_item_detail<R: tauri::Runtime>(window: WebviewWindow<R>, id: Option<String>, path: Option<String>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let id = match id {
        Some(s) if !s.is_empty() && s.chars().count() <= 160 => s,
        _ => return json!({ "success": false, "message": "参数无效" }),
    };
    let rules = rules_value_arc().unwrap_or_else(|_| Arc::new(json!({})));
    // v2.2 第3批（D13）：fileKeys 条目明细直接读扫描快照里的可删文件清单——明细与执行同源
    let (known_files, has_known) = {
        let buckets = snapshots().lock().unwrap_or_else(|e| e.into_inner());
        let known = buckets
            .get(window.label())
            .and_then(|m| m.get(&id))
            .and_then(|it| it.get("files"))
            .and_then(|f| f.as_array())
            .cloned();
        match known {
            Some(f) => (f, true),
            None => (Vec::new(), false),
        }
    };
    let rule = find_cleanup_rule_by_id(&rules, &id);
    let rule_file_keys_non_empty = rule
        .as_ref()
        .and_then(|r| r.get("fileKeys"))
        .and_then(|f| f.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    if rule_file_keys_non_empty && has_known {
        // 明细单次上限 600 条：与引擎侧 cleanup_detail 的枚举上限同值（R4-L06：旧注释裸写
        // 一个已随 S3 退役的 PS 明细脚本名，那个名字在本域已经不存在，等于给注释里
        // 编一道读不到的闸）。两侧数字分属命令层与引擎层、没有共享常量可指，
        // 由 contract_tests 的「预览上限与明细上限同一数字」现算对拍，改其一必须同步另一处。
        let cap = 600usize;
        let files: Vec<Value> = known_files
            .iter()
            .take(cap)
            .map(|f| {
                json!({
                    "path": f.get("path").cloned().unwrap_or(Value::Null),
                    "size": f.get("size").cloned().unwrap_or(Value::from(0)),
                })
            })
            .collect();
        return json!({
            "success": true,
            "data": {
                "kind": "files",
                "total": known_files.len(),
                "truncated": known_files.len() > cap,
                "files": files
            }
        });
    }
    let safe_path = match path {
        Some(p) if !p.is_empty() && p.chars().count() <= 600 => p,
        _ => String::new(),
    };
    // 2026-10-04 审计 §5.6：path 形参必须与**本窗口扫描快照**里该条目的 path
    // 同源（渲染层传的就是 result.path，与快照同一数据源，产品功能不受影响）。
    // 原先任意可读目录都会被枚举回最多 600 条路径，guard_readonly 又放行全部
    // 五窗——一条没有产品收益的任意目录读暴露面。口径沿用
    // validate_snapshot_items 的 path_resolve 词法折叠比对。
    if !safe_path.is_empty() {
        let snapshot_path = {
            let buckets = snapshots().lock().unwrap_or_else(|e| e.into_inner());
            buckets
                .get(window.label())
                .and_then(|m| m.get(&id))
                .and_then(|it| it.get("path"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        };
        let known = snapshot_path.as_deref().unwrap_or("");
        if known.is_empty() || path_resolve(&safe_path) != path_resolve(known) {
            return json!({ "success": false, "message": "明细路径不是本次扫描结果，已拒绝枚举" });
        }
    }
    // S3：纯 Rust 原生
    if let Some(rule) = find_cleanup_rule_by_id(&rules, &id) {
        match crate::engine::native::cleanup_detail(&rule, &safe_path) {
            Ok(detail) => return json!({ "success": true, "data": detail }),
            Err(e) => return json!({ "success": false, "message": format!("原生枚举失败: {e}") }),
        }
    }
    json!({ "success": false, "message": "未找到清理规则" })
}

// ==================== cleanup:check-locked / kill-locked-processes ====================

/// `@@LOCKED@@` 行协议解析结果（占用检测与占用查询共用，判定不重写）。
pub(super) struct LockedParse {
    pub(super) locked: Vec<Value>,
    pub(super) by_app: Map<String, Value>,
    pub(super) procs: Vec<Value>,
    pub(super) locked_by_item: Map<String, Value>,
    pub(super) whitelist: Vec<Value>,
    pub(super) malformed: usize,
}

/// 解析 checklocked_json 的 `@@LOCKED@@` 行协议（check-locked / query-locked 共用）。
///
/// 两条判据必须原样保留（v3.7.3 修复①②，抽成共用函数时逐条搬迁）：
/// ① RM 总会把调用方列入占用者名单 ⇒ 剔除自身 PID；
/// ② explorer 命中即 critical（只展示、无结束入口），并上扫描侧按 RM ApplicationType
///    判出的 critical（RmCritical=1000）——此前这个字段整条被丢掉，「系统关键进程」
///    实际只认 explorer 一个名字，lsass/csrss 这类真关键进程会被列进可结束名单。
///    名字规则仍要保留：实测 RM 对 explorer 报的是 Application 不是 RmCritical。
/// 畸形行不许静默丢（审查 L-21）：计数返回给调用方 warn 留痕。
pub(super) fn parse_locked_lines(stdout: &str, self_pid: i64) -> LockedParse {
    let mut locked: Vec<Value> = Vec::new();
    let mut locked_by_item: Map<String, Value> = Map::new();
    let mut by_app: Map<String, Value> = Map::new();
    let mut procs: Vec<Value> = Vec::new();
    let mut seen_pids: HashSet<i64> = HashSet::new();
    let mut malformed = 0usize;
    for line in stdout.lines() {
        // 前缀 '@@LOCKED@@' 恰 10 字符（勿与 '@@PLANFILE@@' 的 12 混淆）
        let Some(rest) = line.strip_prefix("@@LOCKED@@") else {
            continue;
        };
        let Ok(pf) = serde_json::from_str::<Value>(rest) else {
            malformed += 1;
            continue;
        };
        let Some(path) = pf.get("path").and_then(|v| v.as_str()) else {
            malformed += 1;
            continue;
        };
        if path.is_empty() {
            malformed += 1;
            continue;
        }
        let id = pf.get("id").and_then(|v| v.as_str()).unwrap_or("");
        locked.push(pf.clone());
        if !id.is_empty() {
            let n = locked_by_item.get(id).map(js_number).unwrap_or(0.0) + 1.0;
            locked_by_item.insert(id.to_string(), Value::from(n as i64));
        }
        for p in pf.get("procs").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
            let pid = match p.get("pid").and_then(|v| v.as_i64()) {
                Some(v) => v,
                None => continue,
            };
            let app = p.get("app").and_then(|v| v.as_str()).unwrap_or("");
            if app.is_empty() {
                continue;
            }
            if pid == self_pid {
                continue;
            }
            let critical = p.get("critical").and_then(|v| v.as_bool()).unwrap_or(false)
                || app.to_lowercase().contains("explorer")
                || app.contains("资源管理器");
            let n = by_app.get(app).map(js_number).unwrap_or(0.0) + 1.0;
            by_app.insert(app.to_string(), Value::from(n as i64));
            if seen_pids.insert(pid) {
                procs.push(json!({ "pid": pid, "app": app, "critical": critical }));
            }
        }
    }
    let whitelist: Vec<Value> = procs
        .iter()
        .filter(|p| p.get("critical").and_then(|v| v.as_bool()) == Some(false))
        .cloned()
        .collect();
    LockedParse { locked, by_app, procs, locked_by_item, whitelist, malformed }
}

/// cleanup:check-locked — 清理前占用检测（只读；PID 白名单仅供紧随其后的结束进程使用）
#[tauri::command]
pub async fn cleanup_check_locked<R: tauri::Runtime>(window: WebviewWindow<R>, ids: Option<Value>) -> Value {
    if let Err(msg) = guard::guard_readonly(&window) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();
    // 白名单先置空（R4-M03）：必须在**任何早退之前**。2026-10-04 磁盘清理审计 §3.5 那次
    // 只做了一半 —— check-locked 有这一步，query-locked 五条早退（缺参 / 盘符相对 /
    // 路径不存在 / 空目录或全 reparse / RM 调用失败）都不写槽，于是「上一次成功检测拿到的
    // 名单」在这次检测失败后仍能被「结束进程」杀掉，与本函数头第③条承诺相反。
    // 写入口径收在 state::reset_lock_whitelist / store_lock_whitelist，两条命令不许各自 insert。
    reset_lock_whitelist(&label);
    let snapshot = snapshots()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&label)
        .cloned()
        .unwrap_or_default();
    // 2026-10-04 磁盘清理审计 §3.5：候选装配已抽成纯函数 `collect_lock_candidates`
    // （state.rs），上限与去重在**装配过程中**生效 —— 原实现先把 ids 展开完再施加
    // PLAN_LOCK_CAP，而 ids 无长度限制、无去重，单条目 fileKeys 上限 10 万 ⇒
    // 渲染层一次 Array(200000).fill(<已扫 id>) 就能堆 2×10¹⁰ 个 Value 把主进程打爆。
    // 抽成纯函数也是因为这个形状**没法用集成测试验**（测它等于真 OOM 一次），
    // 只能在无盘无 IPC 的纯函数上钉住。口径与理由见该函数注释。
    let (files, truncated) = collect_lock_candidates(ids.as_ref(), &snapshot, PLAN_LOCK_CAP);
    if truncated {
        log::write_log(
            "warn",
            &format!("占用检测：候选装配被截断（上限 {PLAN_LOCK_CAP} 个文件），面板会标「已截断」"),
        );
    }
    // 截断信号由纯函数在装配过程中给出（见 collect_lock_candidates 的注释：
    // 装配后再比 len() 会让那句比较恒假、「被截断」永远报 false）
    if files.is_empty() {
        // 槽已由上面 reset 置空 ⇒ 这里早退不会留下任何可被结束的名单（R4-M03）
        return json!({
            "success": true, "locked": [], "byApp": {}, "procs": [],
            "lockedByItem": {}, "scanned": 0, "truncated": truncated
        });
    }
    let list: Vec<Value> = files;
    let scanned = list.len();
    // R10（2026-10-15）：占用检测的可删判定与扫描/执行侧同源——保护清单随候选一起注入
    let payload = json_text(&json!({ "files": list, "protect": crate::engine::protect::protected_roots_json() }));
    let task = tauri::async_runtime::spawn_blocking(move || {
        let (code, stdout, stderr) = cleanup_scan::checklocked_json(&payload);
        if code != 0 {
            let msg = if stderr.trim().is_empty() {
                format!("占用检测退出码 {code}")
            } else {
                stderr.trim().to_string()
            };
            return (None, msg);
        }
        // 行协议解析抽成 parse_locked_lines（与 cleanup:query-locked 共用，判定不重写）；
        // 自身 PID 剔除 / critical 判定 / 畸形行计数的判据见该函数注释。
        let parsed = parse_locked_lines(&stdout, std::process::id() as i64);
        if parsed.malformed > 0 {
            log::write_log(
                "warn",
                &format!("占用检测输出含 {} 条畸形 @@LOCKED@@ 行，已跳过（扫描器协议异常）", parsed.malformed),
            );
        }
        (
            Some((parsed.locked, parsed.by_app, parsed.procs, parsed.locked_by_item, parsed.whitelist)),
            String::new(),
        )
    });
    let (payload, err) = match task.await {
        Ok(v) => v,
        Err(e) => return json!({ "success": false, "message": e.to_string() }),
    };
    let Some((locked, by_app, procs, locked_by_item, whitelist)) = payload else {
        return json!({ "success": false, "message": err });
    };
    // 白名单每次检测覆盖（防「检测 A 文件后延时结束 B 进程」的窗口）；
    // 只有走到这一行（检测全成功）才有名单，失败路径留在前的 reset 上空槽（R4-M03）
    store_lock_whitelist(&label, whitelist);
    json!({
        "success": true,
        "locked": locked,
        "byApp": Value::Object(by_app),
        "procs": procs,
        "lockedByItem": Value::Object(locked_by_item),
        "scanned": scanned,
        "truncated": truncated
    })
}

/// 占用查询的目录整树收集上限（与 PLAN_LOCK_CAP 同数量级：RM 单次会话注册 2 万个
/// 文件足够覆盖任何真实目录，超限截断并如实标注，不许静默少查）。
pub(super) const QUERY_LOCK_CAP: usize = 20_000;

/// 占用查询的目录整树收集（清浊坑①：RM 只对**注册进去的文件**报告占用者，只注册
/// 目录本身不会覆盖树内文件 ⇒ 目录查询必须整树下钻）。跳过 reparse 点（与扫描/执行
/// 两侧同一判据 `protect::is_reparse`）、深度上限与 native-scanner `MAX_WALK_DEPTH`
/// 同口径；触上限即截断并由调用方标注「已截断」。
fn collect_query_tree(root: &str, out: &mut Vec<String>, truncated: &mut bool) {
    // 深度口径同 native-scanner MAX_WALK_DEPTH=64（v2-L4P-11/C-1）：超深目录树会把
    // 查询清单撑爆，而环状结构经普通目录绕不开 reparse 判定也构造不出来。
    const QUERY_WALK_MAX_DEPTH: usize = 64;
    fn walk(dir: &str, depth: usize, out: &mut Vec<String>, truncated: &mut bool) {
        if depth >= QUERY_WALK_MAX_DEPTH {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for entry in rd.filter_map(|e| e.ok()) {
            if out.len() >= QUERY_LOCK_CAP {
                *truncated = true;
                return;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if crate::engine::protect::is_reparse(&meta) {
                continue;
            }
            let p = entry.path().to_string_lossy().to_string();
            if meta.is_dir() {
                walk(&p, depth + 1, out, truncated);
            } else if meta.is_file() {
                out.push(p);
            }
        }
    }
    walk(root, 0, out, truncated);
}

/// 占用查询的 `checklocked_json` 输入装配：files 元素必须是「对象」形态
/// （`{"path","id"}`）——native-scanner `checklocked_body` 按 `f.get("path")` 取值。
/// **C1-1 真机探针抓出的坑**：原实现直接下发字符串数组，native 侧对每个元素
/// `get("path")` 恒为 None 而静默 `continue` ⇒ 输出恒空（假阴性「无占用」）；
/// MockRuntime 只覆盖到「路径不存在」早退、到不了 RM 分支，门禁网全部漏过——
/// 只有真机探针能咬住（判据：`cleanup_query_locked_probe_names_locking_process`）。
/// id 留空串：query 域不参与 lockedByItem 记账（那是 check-locked 的快照语义）。
pub(super) fn query_files_entries(files: &[String]) -> Vec<Value> {
    files.iter().map(|p| json!({ "path": p, "id": "" })).collect()
}

/// cleanup:query-locked — 占用查询（主窗内嵌卡片；给定任意路径，问「谁占着它」）
///
/// 清浊 C1-1（2026-10-16 拍板：主窗内嵌卡片/页签，复用 `guard::MAIN`，不开新子窗）。
/// 与 `cleanup:check-locked` 的分工：后者查「已扫描清理项里哪些被占」（候选来自扫描
/// 快照），本命令查「用户给的任意路径被谁占」——两条走同一条 RM 管线
/// （`checklocked_json` + `parse_locked_lines`），判定不重写。
///
/// 四个实现坑逐条对应（清浊 C1-1 判据）：
/// ① 目录查询必须**整树**注册 RM（collect_query_tree）——只注册目录本身，RM 不会
///    报告占用树内文件的进程；
/// ② RM 会话句柄只在 `checklocked_json`（native-scanner）内开合，本函数不持句柄
///    跨函数（Rust RAII；探测失败整体返回错误，不放半截结果出去）；
/// ③ 检测（本命令）与结束（`kill-locked-processes`）两步式不合并——结束只认本次
///    查询写下的一次性白名单；
/// ④ 入口复用磁盘清理页现成分段视图（占用查询 tab），不新开裸窗。
#[tauri::command]
pub async fn cleanup_query_locked<R: tauri::Runtime>(
    window: WebviewWindow<R>,
    path: Option<String>,
) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();
    // R4-M03：guard 之后**立刻**置空本槽。下面五条早退（缺参 / 盘符相对 / 路径不存在 /
    // 空目录或全 reparse / RM 调用失败）原本都不写白名单，于是「上一次成功检测拿到的名单」
    // 在这次注定失败的查询之后仍可被「结束进程」取走 —— 与函数头第③条（结束只认**本次**
    // 查询写下的一次性白名单）相反。清空放在早退之前，失败即留空名单。
    reset_lock_whitelist(&label);
    let raw = match path {
        Some(p) if !p.trim().is_empty() => p.trim().to_string(),
        _ => return json!({ "success": false, "message": "缺少要查询的路径" }),
    };
    // 与规则链同口径的路径展开：%VAR% 先展开；盘符相对形态拒查（§4.10：保护侧按
    // CWD 折叠、RM 按当前盘根解析，两侧比对对象不同）；展开后不存在就明说，不装「无占用」。
    let expanded = cleanup_scan::expand_env_path(&raw);
    if cleanup_scan::is_drive_relative(&expanded) {
        return json!({ "success": false, "message": format!("盘符相对路径无法查询：{raw}") });
    }
    let meta = match std::fs::symlink_metadata(&expanded) {
        Ok(m) => m,
        Err(_) => {
            return json!({ "success": false, "message": format!("路径不存在或不可访问：{expanded}") })
        }
    };
    // 坑①：目录 ⇒ 整树文件（上限 QUERY_LOCK_CAP，截断如实标注）；文件 ⇒ 单条。
    let mut files: Vec<String> = Vec::new();
    let mut truncated = false;
    if meta.is_dir() {
        collect_query_tree(&expanded, &mut files, &mut truncated);
    } else {
        files.push(expanded.clone());
    }
    let scanned = files.len();
    if files.is_empty() {
        // 空目录 / 全是 reparse 点：没有可注册的文件 ⇒ 无占用可言（明说，不放空结果充数）
        return json!({
            "success": true, "path": expanded, "locked": [], "byApp": {},
            "procs": [], "lockedByItem": {}, "scanned": 0, "truncated": truncated
        });
    }
    // R10（2026-10-15）同口径：保护清单随候选一起注入（可删判定与扫描/执行侧同源）。
    // C1-1：files 必须经 query_files_entries 装配成对象数组——直接下发字符串数组会让
    // native 侧静默全跳过（恒空输出），见该函数注释。
    let payload = json_text(&json!({
        "files": query_files_entries(&files),
        "protect": crate::engine::protect::protected_roots_json()
    }));
    let task = tauri::async_runtime::spawn_blocking(move || {
        let (code, stdout, stderr) = cleanup_scan::checklocked_json(&payload);
        if code != 0 {
            let msg = if stderr.trim().is_empty() {
                format!("占用查询退出码 {code}")
            } else {
                stderr.trim().to_string()
            };
            return (None, msg);
        }
        let parsed = parse_locked_lines(&stdout, std::process::id() as i64);
        if parsed.malformed > 0 {
            log::write_log(
                "warn",
                &format!("占用查询输出含 {} 条畸形 @@LOCKED@@ 行，已跳过（扫描器协议异常）", parsed.malformed),
            );
        }
        (Some(parsed), String::new())
    });
    let (parsed, err) = match task.await {
        Ok(v) => v,
        Err(e) => return json!({ "success": false, "message": e.to_string() }),
    };
    let Some(parsed) = parsed else {
        return json!({ "success": false, "message": err });
    };
    // 白名单每次查询覆盖（与 check-locked 同键同语义：紧随其后的结束进程只认这份名单，
    // 防「查询 A 路径后延时结束 B 进程」的窗口）
    store_lock_whitelist(&label, parsed.whitelist);
    json!({
        "success": true,
        "path": expanded,
        "locked": Value::Array(parsed.locked),
        "byApp": Value::Object(parsed.by_app),
        "procs": Value::Array(parsed.procs),
        "lockedByItem": Value::Object(parsed.locked_by_item),
        "scanned": scanned,
        "truncated": truncated
    })
}

/// 结束进程用的 kernel32 绑定（零依赖原则：手写 FFI，与 native-scanner 同风格）
#[cfg(windows)]
pub(super) mod kill_ffi {
    #[link(name = "kernel32")]
    extern "system" {
        pub fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> isize;
        pub fn TerminateProcess(process: isize, exit_code: u32) -> i32;
        pub fn CloseHandle(object: isize) -> i32;
    }
}

/// 结束进程（TerminateProcess；等价 Node `process.kill(pid)`）
#[cfg(windows)]
pub(super) fn terminate_process(pid: i64) -> Result<(), String> {
    if pid <= 0 || pid > u32::MAX as i64 {
        return Err("无效的进程 ID".to_string());
    }
    const PROCESS_TERMINATE: u32 = 0x0001;
    unsafe {
        let h = kill_ffi::OpenProcess(PROCESS_TERMINATE, 0, pid as u32);
        if h == 0 {
            return Err("无法打开目标进程（可能已退出或缺权限）".to_string());
        }
        let rc = kill_ffi::TerminateProcess(h, 1);
        // M-7（审查 2026-10-07）：CloseHandle 失败会泄漏内核句柄，此前返回值被直接丢弃。
        // 终止请求已发出，泄漏不影响本次结果语义，但必须留痕（句柄耗尽是累积症状）。
        if kill_ffi::CloseHandle(h) == 0 {
            log::write_log("warn", &format!("结束进程 {pid} 后 CloseHandle 失败，进程句柄可能泄漏"));
        }
        if rc == 0 {
            return Err("结束进程失败".to_string());
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub(super) fn terminate_process(_pid: i64) -> Result<(), String> {
    Err("仅支持 Windows".to_string())
}

/// cleanup:kill-locked-processes — 结束最近一次占用检测确认过的非关键进程（一次性白名单）
#[tauri::command]
pub fn cleanup_kill_locked_processes<R: tauri::Runtime>(window: WebviewWindow<R>) -> Value {
    if let Err(msg) = guard::guard(&window, guard::MAIN) {
        return json!({ "success": false, "message": msg });
    }
    let label = window.label().to_string();
    let targets = lock_whitelist()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&label)
        .unwrap_or_default();
    if targets.is_empty() {
        return json!({ "success": true, "killed": [], "failed": [] });
    }
    let self_pid = std::process::id() as i64;
    let mut killed: Vec<Value> = Vec::new();
    let mut failed: Vec<Value> = Vec::new();
    for p in targets {
        let pid = p.get("pid").and_then(|v| v.as_i64()).unwrap_or(-1);
        // v3.7.3 兜底：检测侧已剔除自身 PID，这里再挡一道——任何路径下都不允许 kill 自己
        if pid == self_pid {
            continue;
        }
        match terminate_process(pid) {
            Ok(()) => killed.push(p),
            Err(e) => {
                let mut v = p.clone();
                if let Some(o) = v.as_object_mut() {
                    o.insert("message".into(), Value::from(e));
                }
                failed.push(v);
            }
        }
    }
    let fail_note = if failed.is_empty() {
        String::new()
    } else {
        format!(
            "，失败 {} 个（{}）",
            failed.len(),
            failed
                .iter()
                .map(|f| format!(
                    "{}#{}",
                    f.get("app").and_then(|v| v.as_str()).unwrap_or(""),
                    f.get("pid").and_then(|v| v.as_i64()).unwrap_or(0)
                ))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    log::write_log(
        "warn",
        &format!("结束占用进程（用户确认）: 成功 {} 个{fail_note}", killed.len()),
    );
    json!({ "success": true, "killed": killed, "failed": failed })
}


// 2026-10-12：retry_accounting_tests（重试永久删的释放量口径）随回收站重试链整链退役。

#[cfg(test)]
mod tests {
    use super::*;

    /// `checklocked_json` 输入契约：files 元素必须是 `{"path","id"}` 对象——
    /// **真机抓出的回归面**：曾以字符串数组直接下发，native 侧 `f.get("path")`
    /// 恒 None 而静默跳过（输出恒空、假阴性「无占用」）。这条钉「与 native 侧
    /// 行协议的装配形态」，改动 payload 构造时它先红；完整行为由真机探针守。
    #[test]
    fn query_files_entries_matches_native_contract() {
        let files = vec![r"C:\a\x.txt".to_string(), r"C:\b\y.txt".to_string()];
        let entries = query_files_entries(&files);
        assert_eq!(entries.len(), files.len(), "条目数必须与文件数一致");
        for (i, e) in entries.iter().enumerate() {
            let obj = e
                .as_object()
                .unwrap_or_else(|| panic!("元素必须是对象（字符串元素会被 native 侧静默跳过）: {e}"));
            let path = obj.get("path").and_then(|v| v.as_str()).unwrap_or("");
            assert_eq!(path, files[i], "path 必须原样带上（native 侧按它注册 RM）: {e}");
            assert!(
                obj.contains_key("id"),
                "id 键必须在场（空串占位，lockedByItem 记账靠它）: {e}"
            );
        }
    }

    /// 真机抓出的「整批拒删」（2026-10-22 gfx 15 项扫描-清理）：`@@PLANFILE@@` 的
    /// `birthtimeNs` 是 UNIX 纳秒（量级 1.79e18），旧形态用 `js_num_or_zero`
    /// （`Number(x)||0` 的 f64 桥）读它 ⇒ 落地即被量化到 256ns 整倍数 ⇒ 执行侧现读的
    /// 精确值几乎必然不等 ⇒ 身份证守卫把整批文件判成「与扫描时不一致」拒删
    /// （实测 459 条基线 454 条被拒，界面报 976 MB、实际只清出 1.7 MB）。
    /// 判红自证：把 `as_u64` 换回 `js_num_or_zero(..) as i64` ⇒ 第一条断言红。
    #[test]
    fn planfile_纳秒出生时间必须整数直读() {
        // 本机 DXCache 文件的真实出生时间（FILETIME×100 粒度 ⇒ 100 的整倍数），
        // 不是编的样本：日志里「现状」那一栏与它逐位相同。
        const EXACT_NS: u64 = 1_792_427_260_192_258_000;
        // 样本自证：必须落在 JS 双精度的精确整数区之外，否则本用例测不到那个缺陷
        // （换成 100ns ticks 口径也一样超：6.4e16 > 2^53 ⇒ 任何「纳秒/百分之一微秒」量级都危险）
        assert!(
            EXACT_NS > (1u64 << 53),
            "样本量级不足以暴露双精度折位，本用例会变成恒绿"
        );
        let line = format!(
            "@@PLANFILE@@{{\"id\":\"probe\",\"path\":\"C:\\\\a.bin\",\"size\":65536,\"birthtimeNs\":{EXACT_NS}}}"
        );
        let mut a = ScanAccum::default();
        a.ingest_line(&line);
        let stored = a
            .plan
            .get("probe")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or(Value::Null);
        assert_eq!(
            stored.get("birthtimeNs").and_then(Value::as_u64),
            Some(EXACT_NS),
            "纳秒基线只要被折损一位，身份证守卫就把这个文件判成「已替换」而拒删"
        );
        assert_eq!(stored.get("size").and_then(Value::as_u64), Some(65536));
        // 反向对照：同一个数过一遍 f64 桥必然变形（本用例因此不是恒绿），
        // 而且变出来的正是本机日志里那条「扫描时」基线。
        let quantized = (EXACT_NS as f64) as u64;
        assert_eq!(quantized, 1_792_427_260_192_258_048, "量化结果要与真机日志的失真值对上");
        assert_ne!(quantized, EXACT_NS, "若两者相等本用例失去意义，须换一个不可精确表示的样本");
    }

    /// 跨条目重复计账配对（真机 2026-10-22 gfx：`nvidiaCache` 整树报的 387,378,791 B
    /// 与 `nvidiaShaderCache` 清单里同树的 157 个文件逐字节相等，界面因此虚高 1.6×）。
    /// 自 2026-10-23 扫描器物化 pathPs 清单后，两侧都在同一张精确认领表里，本用例喂的
    /// 就是物化后的真实形状（父条也带 files）。
    /// 判红自证：① 把 `Some(owner) if owner != idx` 改成 `Some(_)` ⇒ 第一条红（重叠整批看不见）；
    /// ② 把配对同时挂到两端 ⇒ 第二条红；③ 去掉 pairs 的 key 排序 ⇒ 复现断言红（序漂）。
    #[test]
    fn 两条覆盖同一批文件时只配一次对() {
        let build = || vec![
            // 整树型条目（pathPs）物化后的形状：size 是全量，files 是同一批文件
            json!({"id":"parent","path":"C:\\Users\\me\\AppData\\Local\\NVIDIA","size":300,
                   "files":[
                     {"path":"C:\\Users\\me\\AppData\\Local\\NVIDIA\\DXCache\\a.bin","size":100},
                     {"path":"C:\\Users\\me\\AppData\\Local\\NVIDIA\\DXCache\\b.bin","size":200}
                   ]}),
            json!({"id":"child","path":"C:\\Users\\me\\AppData\\Local\\NVIDIA\\DXCache","size":300,
                   "files":[
                     {"path":"C:\\Users\\me\\AppData\\Local\\NVIDIA\\DXCache\\a.bin","size":100},
                     // 大小写与分隔符混写：必须与上一条归一到同一个键（键不稳就是漏配）
                     {"path":"c:\\users\\ME\\appdata\\local\\nvidia\\dxcache\\b.bin","size":200}
                   ]}),
            // 负例：不与任何清单共享文件 ⇒ 不得被配对
            json!({"id":"elsewhere","path":"C:\\Users\\me\\AppData\\Local\\D3DSCache","size":7,
                   "files":[{"path":"C:\\Users\\me\\AppData\\Local\\D3DSCache\\c.bin","size":7}]}),
        ];
        let mut data = build();
        let inflated = attach_cross_item_pairs(&mut data);
        assert_eq!(inflated, 300, "父条已认领的 300 B 必须在子条上配出来");
        assert_eq!(
            data[1].get("overlapsWith").and_then(Value::as_array).map(|a| a.len()),
            Some(1),
            "一个无序对只能挂在后到的那一条上"
        );
        assert_eq!(data[0].get("overlapsWith"), None, "先到条目不带配对，否则渲染层会扣两次");
        assert_eq!(data[2].get("overlapsWith"), None, "不重叠的条目不得被配对");
        assert_eq!(data[1]["overlapsWith"][0]["with"], "parent");
        assert_eq!(data[1]["overlapsWith"][0]["bytes"], 300);
        assert_eq!(data[1]["overlapsWith"][0]["files"], 2);
        // 配对遍历序必须稳定（HashMap 直接遍历会让同输入产出不同 data）
        let mut again = build();
        attach_cross_item_pairs(&mut again);
        assert_eq!(serde_json::to_string(&data).unwrap(), serde_json::to_string(&again).unwrap(), "输出序随哈希 seed 漂即为不可复现");
    }

    /// 清单被 PLAN_CAP 截断的条目只按**已列出的部分**配对：未列出的重叠看不见，
    /// 汇总因此偏大（退回旧行为方向）。这条把该残余边界钉成显式断言，不许它变成暗坑。
    #[test]
    fn 截断条目只按已列出部分配对() {
        let mut data = vec![
            json!({"id":"parent","size":300,"filesTruncated":true,
                   "files":[{"path":"C:\\x\\a.bin","size":100}]}),
            json!({"id":"child","size":300,
                   "files":[{"path":"C:\\x\\a.bin","size":100},{"path":"C:\\x\\b.bin","size":200}]}),
        ];
        let inflated = attach_cross_item_pairs(&mut data);
        assert_eq!(inflated, 100, "父条没列出的 b.bin 不该被凭空扣掉");
        assert_eq!(data[1]["overlapsWith"][0]["files"], 1);
    }

    /// 同条目内部重复不得计成跨条目重叠（认领表按归一键只认一次）。
    #[test]
    fn 两条清单共享同一文件时配到后条() {
        let mut data = vec![
            json!({"id":"a","files":[{"path":"C:\\x\\share.log","size":42},{"path":"C:\\x\\own.log","size":8}]}),
            json!({"id":"b","files":[{"path":"c:\\X\\SHARE.LOG","size":42},{"path":"C:\\x\\share.log","size":42}]}),
        ];
        assert_eq!(attach_cross_item_pairs(&mut data), 42, "同条目内重复不得计成跨条目重叠");
        assert_eq!(data[1]["overlapsWith"][0]["with"], "a");
        assert_eq!(data[1]["overlapsWith"][0]["files"], 1, "b 里两条指向同一文件，只算一次重叠");
    }

    /// 1B：配对实现只许减少分配，不许改输出。固定输入的完整序列化结果逐字节钉住
    /// （golden 取自 1B 前的实现；改法若动了 pair 顺序/字段就红）。
    #[test]
    fn 配对输出逐字节不变() {
        let mut data = vec![
            json!({"id":"a","files":[{"path":"C:\\x\\share.log","size":42},{"path":"C:\\x\\own.log","size":8}]}),
            json!({"id":"b","files":[{"path":"c:\\X\\SHARE.LOG","size":42},{"path":"C:\\x\\share.log","size":42}]}),
            json!({"id":"c","files":[{"path":"C:\\x\\other.log","size":7}]}),
        ];
        let inflated = attach_cross_item_pairs(&mut data);
        assert_eq!(inflated, 42, "配对字节数不得变");
        assert_eq!(
            serde_json::to_string(&data).unwrap(),
            r#"[{"id":"a","files":[{"path":"C:\\x\\share.log","size":42},{"path":"C:\\x\\own.log","size":8}]},{"id":"b","files":[{"path":"c:\\X\\SHARE.LOG","size":42},{"path":"C:\\x\\share.log","size":42}],"overlapsWith":[{"with":"a","bytes":42,"files":1}]},{"id":"c","files":[{"path":"C:\\x\\other.log","size":7}]}]"#,
            "1B 只许减少分配，配对输出必须逐字节不变"
        );
    }

    /// 1B：单条/空输入没有跨条目配对可做，返回 0 且不得改动 data。
    #[test]
    fn 单条扫描不做配对() {
        let mut data = vec![json!({"id":"only","files":[{"path":"C:\\x\\a","size":1}]})];
        let before = serde_json::to_string(&data).unwrap();
        assert_eq!(attach_cross_item_pairs(&mut data), 0);
        assert_eq!(serde_json::to_string(&data).unwrap(), before, "单条扫描不得改 data");
        assert_eq!(attach_cross_item_pairs(&mut []), 0, "空输入必须返回 0");
    }

    /// 1B 分配成本实测（`#[ignore]`）：拿真实大树扫出的 data，分别计时
    /// ① 旧实现的「克隆整份 files 数组」；② 新实现（借用 + 单条短路）的配对本体。
    /// 只出数，不改判据；取数：`cargo test --lib 配对分配成本实测 -- --ignored --nocapture`。
    #[test]
    #[ignore = "真机实测：扫 windowsDownloadCache（5 万级文件）后计时，非回归判据"]
    fn 配对分配成本实测() {
        use std::time::Instant;
        let v = cleanup_scan_headless(vec!["windowsDownloadCache".to_string()]);
        let Some(data) = v.get("data").and_then(Value::as_array) else {
            println!("SKIP：无数据（success={:?}）", v.get("success"));
            return;
        };
        let mut data = data.clone();
        let files: usize = data
            .iter()
            .map(|it| it.get("files").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0))
            .sum();
        if files == 0 {
            println!("SKIP：本机 windowsDownloadCache 无文件（files=0）");
            return;
        }
        let t0 = Instant::now();
        let clones: Vec<Vec<Value>> = data
            .iter()
            .filter_map(|it| it.get("files").and_then(Value::as_array).cloned())
            .collect();
        let clone_ms = t0.elapsed().as_secs_f64() * 1e3;
        drop(clones);
        let t1 = Instant::now();
        let inflated = attach_cross_item_pairs(&mut data);
        let pair_ms = t1.elapsed().as_secs_f64() * 1e3;
        println!(
            "PAIRING_COST files={files} clone_ms={clone_ms:.1} pair_ms={pair_ms:.1} inflated={inflated}"
        );
    }
}

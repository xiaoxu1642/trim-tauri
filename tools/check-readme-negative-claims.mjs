// check-readme-negative-claims.mjs —— 「不提供」类承诺的否定式门禁（v2-R3，2026-10-01）
//
// 为什么数字对拍不够：`check-readme-claims` 钉的是「文档说 108 项，数据层就得是 108 项」。
// 但「刻意不提供」的承诺是**否定式**的——它没有任何数字可对拍，漂移形态是
// 「文档说不提供，数据层里躺着可勾选项」。本仓实测抓到三处这种对立：
//   · 文档说不提供 FSO/关 MPO，而 `tf_fso` 是可勾选项（R3 已退役）；
//   · 文档说不提供 MSI，而 `tf_gpu_msi` / `tf_usb_msi` 是可勾选项（R3 已退役）；
//   · 文档说不提供 MMCSS 相关调校，而 `audio_mmcss_priority` / `audio_mmcss_schedule` 在活动清单
//     ——这一条不是违规：承诺的主语是「给游戏提优先级」，音频任务调度是另一件事。
// 第三条恰恰说明**不能**用裸 substring 一刀切：拿「MMCSS」去扫数据层会把音频两项误伤成违规，
// 于是下一次改动就会有人把 allow 表当成「加个 id 就完事」的后门。所以每条 allow 必须带书面 scope，
// 且 scope 的**用户可见版本**必须能在承诺文档里找到原文（承诺与豁免两侧都要留痕）。
//
// **真源迁移（2026-10-15 用户裁定）**：承诺原文原在 readme 的「不做的事」章节；用户决定
// 该章节从用户文档删除，承诺迁入本机资料区「否定式承诺-不做的清单」（本仓库其他规范流程下），
// 本门禁改读该文件（文件名保留历史，不改名）。该文件**不入库**——按 AGENTS「门禁读未跟踪
// 文件必须先 existsSync 再判定」的红线：文件缺失时显式 SKIP 并声明「本节未校验」，不崩、也不打 ✓。
//
// **断言分两段（2026-11-02，T1b-M04）**：旧实现在真源缺席时整条门禁直接 exit 0，于是它虽是
// MUST_RUN，默认验收链上却是「零断言 × SKIP」——roster 的自报统计虽诚实，名分仍会被读成
// 「已覆盖」。现在按断言来源拆开：
//   · 数据层段（活动目录 ⇄ allow 反向棘轮 / hardZero）与承诺文档无关，**照常执行**，
//     默认链上就能判红；
//   · 文档段（docAnchor / scopeDocAnchor 原文在场）才随真源缺席显式 SKIP 并声明「本节未校验」。
// 承诺文档存在时两段都必须有可判红断言，杜绝 0 对象静默通过。
//
// 判定原则（每条主题都是双向棘轮，两个方向都会红）：
//   1. `docAnchor` 原文必须在承诺文档里 —— 承诺行被人删掉或改弱，等于静默放宽，红；
//   2. 数据层活动清单里命中 `matcher` 的项，必须逐条出现在 `allow` 中并带非空 scope，否则红；
//   3. `allow` 里的 id 若在活动清单里**不再命中**（项已退役或早就不命中），红——
//      白名单烂掉比没有白名单更危险，它会让人以为那道闸还在拦东西；
//   4. `hardZero` 主题（BCD / UCPD）不允许任何 allow 条目，命中即红。
//
// 用法：node tools/check-readme-negative-claims.mjs [--vault-root <Obsidian 库根>]
//       （或设 TRIM_VAULT_ROOT；不给根时文档段显式 SKIP、数据层段照常断言）

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

const optimizer = JSON.parse(read('src-tauri/data/optimizer-runtime.json'));
const retired = new Set(JSON.parse(read('src-tauri/data/retired-optimizations.json')).items.map((x) => x.id));
// T1b-M03：条件追加的服务禁用只在写入侧表里（storeServices / expectStart=4 的服务组），
// 不在 runtime 的 pwsh 主段文本里——只看 steps 会漏掉「弹窗确认后追加商店段」的真实写入。
const writes = JSON.parse(read('src-tauri/data/optimizer-writes.json'));

// ---- 承诺真源（本机资料区，不入库）：缺失时只有文档段 SKIP（红线口径），不崩也不打 ✓ ----
// T1a-K01：本机资料区的真实路径不得写进跟踪文件（含门禁源码），用段拼接；
// 「本机资料区」措辞本身是 AGENTS §2 认可的合法指代。
//
// A-4 / 拍板 D2（2026-10-25）：文档已从仓库内 `docs/` 搬进 Obsidian 库，本门禁**直接读
// 同一份**，不复制第二份。库根只从 `--vault-root <路径>` 或 `TRIM_VAULT_ROOT` 传入。
// 三档：没给根且仓内副本不在 ⇒ 文档段显式 SKIP（未校验），数据层段照跑；给了根 ⇒ 必须读得到，
// 读不到整条判红并列出两个候选路径（给根就是声明「真源该在这儿」，静默 SKIP 会把搬家做成长期失明）。
const CLAIMS_DOC_SEGMENTS = ['本仓库其他规范流程', '否定式承诺-不做的清单.md'];
const argOf = (name) => {
  const i = process.argv.indexOf(name);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : '';
};
const vaultRoot = argOf('--vault-root') || process.env.TRIM_VAULT_ROOT || '';
const claimsCandidates = [
  vaultRoot && path.join(vaultRoot, 'trim-tauri', ...CLAIMS_DOC_SEGMENTS),
  path.join(ROOT, 'docs', ...CLAIMS_DOC_SEGMENTS),
].filter(Boolean);
const claimsPath = claimsCandidates.find((p) => fs.existsSync(p)) || '';
if (!claimsPath && vaultRoot) {
  console.error(`✗ 给了 --vault-root / TRIM_VAULT_ROOT 却找不到承诺真源：${claimsCandidates.join(' ; ')}`);
  console.error('  ⇒ 库根传错、文件改名或搬家未同步本门禁 —— 按失败处理，不静默 SKIP');
  process.exit(1);
}
// 真源缺席只收窄文档段：数据层段不读承诺文档，下面照常执行（这是默认必跑链上
// 「有断言可判红」的前提）。文档段一律走 skip()，不打 ✓。
const docPresent = Boolean(claimsPath);
const claimsDoc = docPresent ? fs.readFileSync(claimsPath, 'utf8') : '';

/**
 * 主题表：一条 = 承诺文档里的一句否定式承诺。
 * matcher 一律走**结构**（id 或步骤字段正则），不做全文 substring：
 *   - `ids`：按优化项 id 精确点名；
 *   - `stepValueNames`：扫 steps/restore 里 `.reg` 文本写到的注册表值名；
 *   - `stepText`：扫 steps/restore 的全部可执行文本（cmd/pwsh/reg）。
 */
const THEMES = [
  {
    topic: 'MSI 中断模式 / 中断亲和性',
    docAnchor: '**MSI 中断模式 / 中断亲和性调优**',
    matcher: { ids: ['tf_gpu_msi', 'tf_usb_msi'] },
    reason: '无法可靠验证设备是否支持消息信号中断，误开会导致设备失联',
    allow: [],
  },
  {
    topic: 'MMCSS 给游戏提优先级',
    docAnchor: '**MMCSS 给游戏提优先级**',
    matcher: { ids: ['mmcss_optimize', 'mmcss_games'] },
    reason: '实测无可测收益；承诺范围只指「游戏抢优先级」',
    // 音频两项由下面的 SCOPE 断言单独钉，不在此列 allow —— 它们本来就不该被这个 matcher 命中
    // 2026-10-11 用户翻案：mmcss_games 在永劫无间专项面板内提供（承诺窄化为「专项内提供」）
    allow: [
      {
        id: 'mmcss_games',
        scope: 'MMCSS Tasks\\Games 七值（专项面板内提供）',
        scopeDocAnchor: '仅在「永劫无间优化专项」中提供 MMCSS',
        why: '音频两项不在这条承诺范围内，且 matcher 刻意不扫它们（避免误伤）；mmcss_games 仅在永劫无间专项面板提供，承诺窄化为「在专项内提供」',
      },
    ],
  },
  {
    topic: '禁用全屏优化（FSO）/ 关 MPO',
    docAnchor: '**禁用全屏优化（FSO）/ 关 MPO**',
    matcher: { stepValueNames: [/GameDVR_FSEBehavior/, /GameDVR_DSEBehavior/, /GameDVR_EFSEFeatureFlags/, /HonorUserFSEBehaviorMode/, /DXGIHonorFSE/] },
    reason: '会连带丢失 Auto HDR 与可变刷新率，或让画面全部改走合成影响录制捕获',
    allow: [
      {
        id: 'game_dvr',
        scope: '关闭游戏 DVR 录制',
        scopeDocAnchor: '不构成向用户提供 FSO 开关',
        why: '本项的主语是 DVR 录制开关，`GameDVR_FSEBehavior` 只是录制关掉后全屏游戏的附带条件，'
          + '不构成「提供 FSO 开关」。R3 裁定 (b)：保留本项，靠这条书面 scope 与主题门禁守边界，'
          + '而不是把 id 硬塞进黑名单。',
      },
    ],
  },
  {
    topic: 'BCD 启动配置类玄学参数',
    docAnchor: '**修改启动配置数据（BCD）类「玄学参数」**',
    matcher: { stepText: [/bcdedit/i] },
    reason: '属启动配置改动而非性能优化，收益不可测且失误影响开机',
    // 2026-10-11 用户翻案：BCD 改为条件命中式——只做只读体检，命中本机已有非默认项才允许对齐
    // 承诺窄化为「不主动创建或改写系统默认的 BCD 配置」，承诺仍在
    hardZero: false,
    allow: [
      {
        id: 'nara_bcd_timer',
        scope: '计时器条件对齐（disabledynamictick/useplatformtick，仅本机已有才写）',
        scopeDocAnchor: '计时器项仅在该元素本机已存在时才允许对齐',
        why: '条件命中式——只对已存在的非默认项对齐，不主动创建元素',
      },
      {
        id: 'nara_bcd_vsm',
        scope: 'Hyper-V/模拟器保护态跳过的虚拟化启动项（命中保护态自动 disabled）',
        scopeDocAnchor: '检测到 Hyper-V/模拟器正在使用的虚拟化配置自动跳过',
        why: '保护态自动跳过，不影响模拟器使用能力；只对已存在非默认值写回默认',
      },
      {
        id: 'nara_bcd_boot',
        scope: '启动菜单/开机画面（条件命中）',
        scopeDocAnchor: '不主动创建或改写系统默认的 BCD 配置',
        why: '条件命中式——不主动创建启动菜单，只对已存在的非默认值对齐',
      },
      {
        id: 'nara_bcd_lowmem',
        scope: '低 1MB/内存映射策略（主要作危险配置体检+还原出口）',
        scopeDocAnchor: '低 1MB/内存映射、启动菜单与自救入口等不提供一键写入',
        why: '主要作为体检告警与还原出口，常态不可执行；命中才写回默认值',
      },
      {
        id: 'nara_bcd_irq',
        scope: '中断路由策略（多为系统默认值，常态未命中）',
        scopeDocAnchor: '不主动创建或改写系统默认的 BCD 配置',
        why: '多为系统默认值，常态不可执行；条件命中式',
      },
    ],
  },
  {
    // T1b-M03：以下四条此前只存在于承诺文档、没有任何判据。
    topic: '清空待机列表「释放内存」',
    docAnchor: '**清空整个待机列表「释放内存」**',
    matcher: {
      ids: ['mem_clean', 'memory_clean', 'standby_clean', 'standby_list_clean'],
      stepText: [/EmptyStandbyList/i, /MemoryPurgeStandbyList/i, /clear[^\n]{0,40}standby/i, /待机列表/i],
    },
    reason: '待机列表本就计入可用内存，清空丢掉的是热缓存',
    allow: [],
  },
  {
    topic: '高频自动「内存整理」',
    docAnchor: '**高频自动「内存整理」**',
    matcher: {
      ids: ['mem_defrag', 'memory_defrag', 'mem_compact', 'memory_compact'],
      stepText: [/Memory\s*Compression/i, /内存整理/i, /内存压缩/i, /EmptyWorkingSet/i],
      // 计划任务里做内存整理：两条必须同一步命中，避免把普通计划任务项误伤
      stepTextAll: [[/schtasks|Register-ScheduledTask/i, /memory|内存/i]],
    },
    reason: '反复清工作集只会把数据换回页面文件再读回来',
    allow: [],
  },
  {
    topic: '禁用系统服务「越全越好」（商店/同步服务保持默认）',
    docAnchor: '**禁用系统服务「越全越好」**',
    matcher: {
      // 商店/账户同步相关服务：默认清单里必须保持系统默认。
      // CscService（离线文件缓存）不在此列：它不属于商店/账户同步承诺的范围。
      serviceDisableNames: [
        'AppXSvc', 'ClipSVC', 'InstallService', 'LicenseManager', 'StoreInstallService',
        'PushToInstall', 'wlidsvc', 'OneSyncSvc', 'Wns', 'TokenBroker',
      ],
    },
    reason: '商店与同步相关服务保持系统默认，批量禁用会破坏商店/更新/账户同步',
    allow: [
      {
        id: 'tf_svc_bulk',
        scope: '商店相关服务仅在用户弹窗确认后追加禁用（默认保持系统默认）',
        scopeDocAnchor: '商店相关服务仅在用户弹窗确认后追加禁用',
        why: '默认清单不含商店服务；includeStore 段由用户在独立弹窗确认后追加，'
          + '属用户显式选择，不是「越全越好」的默认批量禁用。写入侧表 storeServices 是这条边界的真源。',
      },
    ],
  },
  {
    topic: 'AMD 驱动注册表深度调优',
    docAnchor: '**AMD 驱动注册表深度调优**',
    matcher: {
      regKeyPaths: [/\\AMD(?:\\|$)/i, /\\Services\\amd/i],
      stepText: [/HKLM:\\+SOFTWARE\\+AMD/i, /HKLM:\\+SYSTEM\\+CurrentControlSet\\+Services\\+amd/i],
    },
    reason: 'A 卡用户实机反馈存在副作用，只保留清理类规则',
    allow: [],
  },
  {
    topic: '静默/永久禁用 UCPD 驱动',
    docAnchor: '**静默/永久禁用 UCPD 驱动来接管默认应用**',
    matcher: { stepText: [/UCPD/] },
    reason: '该驱动是系统对默认应用选择的防篡改保护层，静默禁用内核驱动易被安全软件判为风险行为',
    hardZero: true,
    allow: [],
  },
  {
    // R1-4a / 决策 D3：「优化项与规则不热更」写成有意设计。
    //
    // **为什么要有这条**：R1 各批次里「优化项能不能在线扩库」被反复提出来
    // （§5.11 M4 建议做签名体系时的隐含前提、方案 §5.5 的 provenance 侧表…），
    // 每次都要重新解释一遍为什么不热更。写成承诺 + 门禁，之后再有人提
    // 就直接指向这条，而不是重新辩论。
    //
    // **matcher 必须带足够限定，不能用裸 substring**（R1-4a.4 的前车之鉴就在本文件
    // 头部：拿 `MMCSS` 裸扫数据层会把音频两项误伤，于是下一次改动就有人把 allow 表
    // 当成「加个 id 就完事」的后门）。这里的限定是：
    //   · 只认「**下载/拉取**远程规则内容」的具体动作 —— `Invoke-WebRequest` / `irm` /
    //     `DownloadFile` / `Start-BitsTransfer` 这几个**真实下载 API**；
    //   · **不**认「在线更新」这几个汉字本身（`uninstall:update-residue-rules` 那个
    //     显式按钮的 label 就含这四个字，它是有意保留的用户触发动作，见 allow）。
    // 换句话说：承诺的主语是「**无人值守的后台自动替换**」，不是「有没有联网能力」。
    topic: '优化项 / 规则库的热更（无人值守自动替换）',
    docAnchor: '**没有「检查更新并热替换规则」这种入口**',
    matcher: {
      stepText: [
        /Invoke-WebRequest/i,
        /\birm\b/i,
        /DownloadFile/i,
        /Start-BitsTransfer/i,
        /System\.Net\.WebClient/i,
        /https?:\/\/[\w.-]+\/[\w./-]*\.(?:json|ps1|psm1)/i,
      ],
    },
    reason: '规则库是「改用户系统」的依据，无人值守替换等于让远端在用户不知情时改变判定口径；'
      + '本仓的信任根是随版本交付的 ed25519 签名 + 五组双源对拍，脱离版本交付的热更会绕过它',
    // allow **刻意为空**（2026-10-03 现算：全部优化项 × steps/restore 全量文本逐条匹配，
    // 上述六个下载 API +远程脚本 URL 形态**零命中**）。写 allow 之前先算过 ——
    // 这条纪律来自 MMCSS 那次教训：凭「印象里应该有一项」去写 allow，
    // 只会立刻触发「allow 条目已不再命中」的棘轮，把新门禁变成一片假红。
    //
    // 注意：残留规则库的「在线更新」动作在 `uninstall:update-residue-rules` 命令里
    // （Rust 侧 `reqwest` 路径），**不在优化项数据层** —— 所以本 matcher 扫不到它，
    // 这不是漏网。它是用户点按钮触发的显式替换，承诺文档已明写边界。
    allow: [],
  },
];

// ---------- 数据层匹配（结构化，不读承诺文正文）----------
function regValueNamesIn(text) {
  return [...String(text).matchAll(/"([^"]+)"\s*=/g)].map((m) => m[1]);
}

/** 步骤文本里的服务名（reg 段路径 / sc config / Set-Service / 显式 service 字段 / $disabled 数组）。 */
function serviceNamesInStep(st, text) {
  const names = new Set();
  for (const m of text.matchAll(/\\Services\\([^\\\]"'\s]+)/gi)) names.add(m[1]);
  for (const m of text.matchAll(/sc(?:\.exe)?\s+config\s+(?:"([^"]+)"|([^\s]+))/gi)) {
    names.add((m[1] || m[2] || '').replace(/^["']|["']$/g, ''));
  }
  for (const m of text.matchAll(/Set-Service[^\n]*?-Name\s+["']?([\w.$-]+)/gi)) names.add(m[1]);
  if (typeof st.service === 'string') names.add(st.service);
  // tf_svc_bulk 形态：$disabled = @("A","B",...) 后统一写 Start=4
  const arr = text.match(/\$(?:disabled|services|svc)\w*\s*=\s*@\(([\s\S]*?)\)/i);
  if (arr) for (const q of arr[1].matchAll(/["']([^"']+)["']/g)) names.add(q[1]);
  return [...names].filter((n) => n && !n.includes('$'));
}

/** 该步骤是否是「把服务改成禁用/手动」的写入（读操作不算）。 */
function isServiceDisableStep(st, text) {
  if (st.disable === true) return true;
  if (typeof st.service === 'string' && /disabled|^4$/i.test(String(st.startType ?? ''))) return true;
  return /(?:start\s*"?\s*=\s*(?:4\b|dword:0*4\b|disabled))|(?:-Name\s+["']?Start["']?\s+-Value\s+4\b)|(?:-StartupType\s+Disabled)/i.test(text);
}

/** 服务禁用主题：runtime 步骤 + 写入侧表（条件追加段）两处都查。 */
function serviceDisableHits(item, denyNames, writesItem) {
  const hit = [];
  const denied = (n) => denyNames.some((d) => {
    const want = String(d).toLowerCase();
    return String(n).toLowerCase() === want
      || (want.endsWith('*') && String(n).toLowerCase().startsWith(want.slice(0, -1)));
  });
  for (const st of [...(item.steps || []), ...(item.restore || [])]) {
    const text = [st.cmd, st.pwsh, st.reg].filter(Boolean).join('\n');
    if (!isServiceDisableStep(st, text)) continue;
    for (const n of serviceNamesInStep(st, text)) if (denied(n)) hit.push(`服务=${n}`);
  }
  const w = writesItem || {};
  const sideServices = new Set([
    ...(w.storeServices || []),
    ...(w.groups || []).filter((g) => g.expectStart === 4).flatMap((g) => g.services || []),
  ]);
  for (const n of sideServices) if (denied(n)) hit.push(`写入侧表=${n}`);
  return hit;
}

function matchesTheme(item, matcher, writesItem) {
  const hit = [];
  if (matcher.ids) {
    for (const id of matcher.ids) if (item.id === id) hit.push(`id=${id}`);
  }
  if (matcher.serviceDisableNames) {
    hit.push(...serviceDisableHits(item, matcher.serviceDisableNames, writesItem));
  }
  const steps = [...(item.steps || []), ...(item.restore || [])];
  for (const st of steps) {
    if (matcher.stepValueNames && st.reg) {
      const names = regValueNamesIn(st.reg);
      for (const rx of matcher.stepValueNames) {
        for (const n of names) if (rx.test(n)) hit.push(`值=${n}`);
      }
    }
    if (matcher.regKeyPaths && st.reg) {
      for (const m of st.reg.matchAll(/^\[([^\]]+)\]/gm)) {
        for (const rx of matcher.regKeyPaths) if (rx.test(m[1])) hit.push(`键=${m[1]}`);
      }
    }
    const blob = [st.cmd, st.pwsh, st.reg].filter(Boolean).join('\n');
    if (matcher.stepText) {
      for (const rx of matcher.stepText) if (rx.test(blob)) hit.push(`文本/${rx.source}`);
    }
    if (matcher.stepTextAll) {
      for (const pair of matcher.stepTextAll) {
        if (pair.every((rx) => rx.test(blob))) hit.push(`同一步文本/${pair.map((r) => r.source).join(' & ')}`);
      }
    }
  }
  return hit;
}

let fail = 0;
let asserted = 0;
let skipped = 0;
const check = (ok, label, detail = '') => {
  asserted++;
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) fail++;
};
// 显式 SKIP：不计入 ✓、也不计失败；末尾汇总单列节数（同 check-comment-rot 的 SKIP 口径）。
const skip = (label, detail = '') => {
  skipped++;
  console.log(`⊘ ${label}${detail ? ' — ' + detail : ''}`);
};

console.log(`=== 否定式承诺门禁（承诺真源：${docPresent ? claimsPath : '缺席'}） ===\n`);
if (!docPresent) {
  console.warn(`⚠ 承诺真源缺失（本机资料区·${CLAIMS_DOC_SEGMENTS.join('/')}）——承诺文档侧断言**未校验**（SKIP，不是通过）；数据层断言照常执行。`);
  console.warn('  · 该文件属本机资料区、不入库；干净克隆 / 他机下文档侧按 SKIP 处理是红线口径。');
  console.warn('  · 本机要连承诺原文一起校验：node tools/check-readme-negative-claims.mjs --vault-root <Obsidian 库根>（或设 TRIM_VAULT_ROOT）。');
}
console.log(`真源读数：活动优化项 ${optimizer.length} / 退役账本 ${retired.size}\n`);
// 对象地板：活动目录为空时主题匹配全部空转，「没有命中」会被读成「承诺没有漂移」。
check(optimizer.length > 0, '活动优化目录非空（否则主题匹配全部空转）', `读到 ${optimizer.length} 项`);

for (const t of THEMES) {
  const docProblems = []; // 文档段：锚点原文必须还在承诺文档里
  const problems = [];    // 数据层段：活动项 ⇄ allow / hardZero（不读承诺文档）

  // 1. 承诺原文必须还在承诺文档里（真源缺席时本节 SKIP，不打 ✓）
  if (docPresent && !claimsDoc.includes(t.docAnchor)) {
    docProblems.push(`承诺行在承诺文档里找不到原文（锚点 ${JSON.stringify(t.docAnchor)}）—— 承诺被删或被改弱，等于静默放宽`);
  }

  // 2. 活动清单逐条命中核对
  const hits = [];
  for (const o of optimizer) {
    const m = matchesTheme(o, t.matcher, writes.items?.[o.id]);
    if (m.length) hits.push({ id: o.id, title: o.title, evidence: [...new Set(m)] });
  }

  const allowIds = new Set(t.allow.map((a) => a.id));
  for (const h of hits) {
    if (!allowIds.has(h.id)) {
      problems.push(`活动项 ${h.id}（${h.title}）命中本主题却未在 allow 登记：${h.evidence.join(' ')} —— 文档说「${t.topic}」不提供`);
    }
  }

  // 3. allow 反向棘轮：登记了但不再命中 = 白名单烂掉
  for (const a of t.allow) {
    const still = hits.find((h) => h.id === a.id);
    if (!still) {
      problems.push(`allow 条目 ${a.id} 已不再命中本主题（项退役了或匹配器变了），请删掉这条登记`);
      continue;
    }
    if (!a.scope || !a.why) problems.push(`allow 条目 ${a.id} 缺书面 scope 或 why`);
    // scope 的用户可见版本必须在承诺文档里留痕，否则「边界写死」只存在于门禁内部
    if (docPresent && a.scopeDocAnchor && !claimsDoc.includes(a.scopeDocAnchor)) {
      docProblems.push(`allow 条目 ${a.id} 的 scope 在承诺文档里找不到原文（${JSON.stringify(a.scopeDocAnchor)}）—— 豁免边界必须留痕`);
    }
  }

  // 4. hardZero：这两类连 allow 都不许有
  if (t.hardZero) {
    if (t.allow.length) problems.push('本主题为 hardZero（一律不提供），不允许任何 allow 条目');
    if (hits.length) problems.push(`本主题为 hardZero，却命中 ${hits.map((h) => h.id).join(' / ')}`);
  }

  if (docPresent) {
    check(docProblems.length === 0, `${t.topic} · 承诺原文与豁免边界在场`, docProblems.join('；'));
  } else {
    skip(`${t.topic} · 承诺原文与豁免边界在场`, '承诺真源缺席：本节未校验');
  }
  check(problems.length === 0, `${t.topic} · 数据层对齐（命中 ${hits.length} / allow ${t.allow.length} / hardZero ${t.hardZero ? '是' : '否'}）`,
    problems.join('；'));
}

// ---------- 附加：MMCSS 音频两类的 scope 必须写在承诺文档里 ----------
// 它们**不在**上面「游戏提优先级」主题的 matcher 里（那是刻意不匹配，避免误伤），
// 所以边界由这条断言单独钉：音频两项仍在活动清单时，承诺文档必须留着那句范围声明。
const audioIds = ['audio_mmcss_priority', 'audio_mmcss_schedule'];
const audioActive = optimizer.filter((o) => audioIds.includes(o.id)).map((o) => o.id);
if (audioActive.length) {
  if (docPresent) {
    check(
      claimsDoc.includes('音频任务调度**的两项不在本条范围内'),
      `MMCSS 音频两项仍在活动清单（${audioActive.join(' / ')}），承诺文档的范围声明必须在场`,
      '找不到「音频任务调度的两项不在本条范围内」这句 —— 撤掉声明就等于把承诺悄悄扩回音频面',
    );
  } else {
    skip('MMCSS 音频两项的范围声明', '承诺真源缺席：本节未校验');
  }
}

console.log('');
if (fail > 0) {
  console.error(`门禁失败：${fail} 条断言不通过（已执行断言 ${asserted} 条 / SKIP ${skipped} 节）`);
  process.exit(1);
}
if (!docPresent) {
  console.log(
    `check-readme-negative-claims: 数据层断言 ${asserted} 条通过；承诺文档侧 ${skipped} 节**未校验**` +
      '（SKIP，不是通过；给 --vault-root 或 TRIM_VAULT_ROOT 才执行文档段）',
  );
  process.exit(0);
}
console.log(`否定式承诺门禁全部通过（断言 ${asserted} 条）`);

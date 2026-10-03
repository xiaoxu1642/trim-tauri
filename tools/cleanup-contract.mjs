// cleanup-contract.mjs —— 清理规则库语义校验的**唯一 JS 实现**（V2 P1-B0 / P0-C1，2026-09-30）
//
// 为什么单独成文件：此前 `check-cleanup-rule-contract.mjs` 把断言直接写在流程里，
// 于是"判定器坏成永远放行"没法被测出来（真实规则库里没有反例 ⇒ 光跑数据永远绿，
// 本仓 A1 的注释里记过这个实测）。抽成纯函数后：
//   1. 夹具（tools/fixtures/cleanup-contract.json）可以用坏包逐条打它；
//   2. Rust 装载侧 `validate_cleanup_package` 读**同一份夹具**（uninstall.rs 同姿势），
//      两侧对同一个包必须给同一个结论 —— 不跨语言调用，靠同一组用例钉口径。
//
// 词汇与上限一律取自 `tools/rule-schema.json`（见 rule-schema.mjs 的头注释）；
// 本文件只写判定逻辑。**不做通用规则引擎**：条件必填这类语义直接写在代码里，
// 表只负责"哪些字段存在、取什么值、上限多少"。
'use strict';
import { list, number, tokens, crossTrack } from './rule-schema.mjs';
import { collectTokens, makeTokenChecker } from './rule-tokens.mjs';

/**
 * 断言登记表：每条都必须有至少一个夹具反例（门禁做双向核对）。
 * 新增断言而不配反例 = 门禁红，防的是"加了断言却永远不会响"。
 */
export const ASSERTIONS = {
  A1: '每个 %TOKEN% 都在契约表 cleanup.tokens 登记集内',
  A2: '扫描/执行口径一致的字段形态（/ 分隔符、? 通配、多星 pattern、excludePaths 的 :: 混用）',
  A3: '目标精确重复（file/reg 指纹去重）',
  A4: '已裁决移除的字段回潮（契约表 cleanup.itemBannedKeys）',
  A5: '根结构底线（rulesVersion 为正数、groups 非空、数量与深度上限）',
  A6: '准入必填字段与溯源形态（含 risk / sourceClass 枚举、布尔字段）',
  A7: 'fileKeys 显式布尔 recurse；进程约束字段写了就必须是非空数组',
  A9: '时效护栏字段形态（minAgeHours/minAgeDays 互斥且为正整数）',
  A10: '未知字段白名单（顶层 / 组 / 子组 / 条目 / fileKeys / regKeys / prov）',
  A11: '条目 id 字符集与非空唯一',
  A12: '条目级版本戳 ver 必须存在且等于顶层 rulesVersion（V2 P2-A1：报告要能回答"这条是哪一版规则判的"）',
  A13: '条目必须有**当前引擎真会读**的路径来源（活键清单见契约表 crossTrack.liveSourceKeys；D19 修复后 candidatesPs/globCandidatesPs 已是活键，一条来源都没有的条目仍必须拒）',
  A14: '可选贡献项 evidenceItems 必须是非空对象数组：text 非空、weight 为 0..契约上限的数字，且至少一项 weight>0（V2 P1-A3：0 分解释项只解释、不进求和）',
};

const itemLabel = (it, fallback) => {
  const id = it && typeof it === 'object' && typeof it.id === 'string' ? it.id : '';
  return id || fallback;
};

/** 收集一条规则里的所有目标指纹（与 A3 的口径一致：类型 + 可移植模板 + pattern + recurse + reg value） */
function targetFingerprints(it) {
  const fps = [];
  for (const fk of it.fileKeys ?? []) {
    if (!fk || typeof fk !== 'object') continue;
    fps.push(
      `file|${String(fk.path ?? '').toLowerCase()}|${fk.pattern ?? '*'}|${fk.recurse === false ? 'false' : 'true'}`,
    );
  }
  for (const rk of it.regKeys ?? []) {
    if (!rk || typeof rk !== 'object') continue;
    fps.push(`reg|${String(rk.path ?? '').toLowerCase()}|${rk.value ?? ''}`);
  }
  return fps;
}

/**
 * 整包语义校验。返回**错误数组**（空数组 = 通过）。
 * 不做"坏条目剔除、其余生效"：调用方要么整包接受要么整包拒绝（残留域 Q2 同口径）。
 */
export function validateCleanupPackage(pkg) {
  const errs = [];
  const say = (id, msg) => errs.push(`[${id}] ${msg}`);

  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) {
    return ['[A5] 规则包不是 JSON 对象'];
  }

  const topFields = list('cleanup', 'topFields');
  const topRequired = list('cleanup', 'topRequired');
  const groupFields = list('cleanup', 'groupFields');
  const groupRequired = list('cleanup', 'groupRequired');
  const subFields = list('cleanup', 'subGroupFields');
  const subRequired = list('cleanup', 'subGroupRequired');
  const itemFields = list('cleanup', 'itemFields');
  const itemRequired = list('cleanup', 'itemRequired');
  const bannedKeys = list('cleanup', 'itemBannedKeys');
  const fkFields = list('cleanup', 'fileKeyFields');
  const fkRequired = list('cleanup', 'fileKeyRequired');
  const rkFields = list('cleanup', 'regKeyFields');
  const rkRequired = list('cleanup', 'regKeyRequired');
  const provFields = list('cleanup', 'provFields');
  const provRequired = list('cleanup', 'provRequired');
  const riskLevels = new Set(list('cleanup', 'riskLevels'));
  const sourceClasses = new Set(list('cleanup', 'sourceClasses'));
  const nonEmptyArrays = list('cleanup', 'nonEmptyArrayFields');
  const positiveInts = list('cleanup', 'positiveIntFields');
  const exclusive = list('cleanup', 'exclusiveNumericFields');
  const maxText = number('cleanup', 'maxTextLen');
  const maxTarget = number('cleanup', 'maxTargetLen');
  const { allowed, caseInsensitive } = tokens('cleanup');
  const checkToken = makeTokenChecker(allowed, { caseInsensitive });

  // ---- A10 顶层未知字段 ----
  for (const k of Object.keys(pkg)) {
    if (!topFields.includes(k)) say('A10', `顶层未知字段 ${k}（新增字段要先接执行侧，再进契约表）`);
  }
  // ---- A5 / A6 根结构 ----
  for (const k of topRequired) {
    if (!(k in pkg)) say('A5', `顶层缺必填字段 ${k}`);
  }
  if (typeof pkg.rulesVersion !== 'number' || !Number.isFinite(pkg.rulesVersion) || pkg.rulesVersion <= 0) {
    say('A5', 'rulesVersion 缺失、非数字或非正数');
  }
  if (!Array.isArray(pkg.groups) || pkg.groups.length === 0) {
    say('A5', 'groups 缺失或为空数组');
    return errs;
  }
  if (pkg.groups.length > number('cleanup', 'maxGroups')) {
    say('A5', `组数 ${pkg.groups.length} 超上限 ${number('cleanup', 'maxGroups')}`);
  }

  const seenIds = new Map();
  const seenTargets = new Map();
  let itemCount = 0;

  const checkItem = (it, where) => {
    itemCount += 1;
    if (!it || typeof it !== 'object' || Array.isArray(it)) {
      say('A6', `${where}: 条目不是对象`);
      return;
    }
    const id = itemLabel(it, `${where} #${itemCount}`);
    // A10 条目未知字段（先报"已裁决移除"，再报未知 —— 前者才是可执行的结论）
    let bannedHit = false;
    for (const b of bannedKeys) {
      if (b in it) {
        say('A4', `规则 ${id}: 出现已裁决移除的字段 ${b}（该字段在 Rust/前端零消费方，禁止回潮）`);
        bannedHit = true;
      }
    }
    for (const k of Object.keys(it)) {
      if (!itemFields.includes(k) && !(bannedKeys.includes(k) && bannedHit)) {
        say('A10', `规则 ${id}: 未知字段 ${k}（新增字段要先接执行侧，再进契约表）`);
      }
    }
    // A6 必填
    for (const f of itemRequired) {
      if (it[f] === undefined) say('A6', `规则 ${id}: 缺必填字段 ${f}`);
    }
    // A11 id 形态与唯一
    if (typeof it.id !== 'string' || !it.id.trim()) {
      say('A11', `规则 ${id}: id 缺失或为空白`);
    } else {
      if (!/^[A-Za-z0-9._-]+$/.test(it.id)) say('A11', `规则 ${id}: id 含非 [A-Za-z0-9._-] 字符`);
      if ([...it.id].length > maxText) say('A11', `规则 ${id}: id 超长`);
      if (seenIds.has(it.id)) say('A11', `规则 ${id}: id 与 ${seenIds.get(it.id)} 重复`);
      else seenIds.set(it.id, where);
    }
    // A6 枚举与布尔
    if (it.risk !== undefined && !riskLevels.has(it.risk)) {
      say('A6', `规则 ${id}: risk「${it.risk}」不在 ${[...riskLevels].join('/')} 之内`);
    }
    for (const f of ['evidence', 'domain', 'group', 'nature', 'name']) {
      const v = it[f];
      if (v !== undefined && (typeof v !== 'string' || !v.trim() || [...v].length > maxText)) {
        say('A6', `规则 ${id}: ${f} 必须是非空字符串且不超 ${maxText} 字`);
      }
    }
    for (const f of ['recommended', 'regenerable']) {
      if (f in it && typeof it[f] !== 'boolean') {
        say('A6', `规则 ${id}: ${f} 必须是布尔（缺省即静默改变默认口径）`);
      }
    }
    // A7 进程约束非空
    for (const f of nonEmptyArrays) {
      if (f in it && (!Array.isArray(it[f]) || it[f].length === 0)) {
        say('A7', `规则 ${id}: ${f} 存在但不是非空数组（有约束却写空 = 静默失效）`);
      }
    }
    // A9 时效互斥 + 正整数
    const declaredExclusive = exclusive.filter((f) => f in it);
    if (declaredExclusive.length > 1) {
      say('A9', `规则 ${id}: ${declaredExclusive.join(' / ')} 互斥，不得同时声明`);
    }
    for (const f of positiveInts) {
      if (!(f in it)) continue;
      const v = it[f];
      if (typeof v !== 'number' || !Number.isInteger(v) || v <= 0) {
        say('A9', `规则 ${id}: ${f} 必须是正整数（当前 ${JSON.stringify(v)}）`);
      }
    }
    // A6 prov 溯源形态
    const prov = it.prov;
    if (!prov || typeof prov !== 'object' || Array.isArray(prov)) {
      say('A6', `规则 ${id}: prov 缺失或不是对象`);
    } else {
      for (const k of Object.keys(prov)) {
        if (!provFields.includes(k)) say('A10', `规则 ${id}: prov 未知字段 ${k}`);
      }
      for (const f of provRequired) {
        const v = prov[f];
        if (typeof v !== 'string' || !v.trim()) say('A6', `规则 ${id}: prov.${f} 缺失或为空`);
      }
      if (prov.sourceClass !== undefined && !sourceClasses.has(prov.sourceClass)) {
        say('A6', `规则 ${id}: prov.sourceClass「${prov.sourceClass}」不在 ${[...sourceClasses].join('/')} 之内`);
      }
    }
    // A12 条目级版本戳必须与顶层一致：不同版条目混在一包里 = "上次报这次没报"无从对齐
    if (!('ver' in it)) {
      say('A12', `规则 ${id}: 缺条目级版本戳 ver（跑 node tools/stamp-rule-ver.mjs --write 后重签）`);
    } else if (typeof it.ver !== 'number' || it.ver !== pkg.rulesVersion) {
      say('A12', `规则 ${id}: ver=${JSON.stringify(it.ver)} 与顶层 rulesVersion=${JSON.stringify(pkg.rulesVersion)} 不一致`);
    }
    // A14 贡献项（V2 P1-A3）：0 分解释项允许存在（BCU 口径：不进求和、只解释），
    // 但至少要有一个正分事实项——否则这条规则的"建议"没有任何事实支撑。
    // 与 Rust 装载侧同文案同口径，任一侧放宽另一侧红。
    if (it.evidenceItems !== undefined) {
      const evs = it.evidenceItems;
      if (!Array.isArray(evs)) {
        say('A14', `规则 ${id}: evidenceItems 必须是数组`);
      } else if (evs.length === 0) {
        say('A14', `规则 ${id}: evidenceItems 不能是空数组（没有贡献项就删掉该字段，用 evidence 单句）`);
      } else {
        const evFields = list('cleanup', 'evidenceItemFields') ?? [];
        const weightMax = number('cleanup', 'evidenceWeightMax') ?? 3;
        let positive = 0;
        evs.forEach((ev, i) => {
          if (!ev || typeof ev !== 'object' || Array.isArray(ev)) {
            say('A14', `规则 ${id}: evidenceItems[${i}] 必须是对象`);
            return;
          }
          for (const k of Object.keys(ev)) {
            if (!evFields.includes(k)) say('A14', `规则 ${id}: evidenceItems[${i}] 未知字段 ${k}`);
          }
          const text = typeof ev.text === 'string' ? ev.text : '';
          if (!text.trim()) say('A14', `规则 ${id}: evidenceItems[${i}] 缺 text 或为空白`);
          if (text.length > maxText) say('A14', `规则 ${id}: evidenceItems[${i}] text 超长（上限 ${maxText}）`);
          const w = ev.weight;
          if (typeof w !== 'number' || !Number.isFinite(w)) {
            say('A14', `规则 ${id}: evidenceItems[${i}] 缺 weight 或不是数字`);
          } else if (w < 0 || w > weightMax) {
            say('A14', `规则 ${id}: evidenceItems[${i}] weight=${w} 超出 0..=${weightMax}`);
          } else if (w > 0) {
            positive += 1;
          }
        });
        if (positive === 0) {
          say('A14', `规则 ${id}: evidenceItems 全是 0 分解释项——0 分项只解释不进求和，至少要有一个正分事实支撑这条建议`);
        }
      }
    }
    // A13 路径来源必须"活着"：活键清单取自契约表 crossTrack.liveSourceKeys（与扫描器、
    // 覆盖矩阵同一份定义，改键名先改契约表）。D19 键名缺陷修复（2026-10-01）后
    // candidatesPs/globCandidatesPs 已进活键清单，但"一条来源都没有"仍然必须拒。
    {
      const live = crossTrack('liveSourceKeys');
      const deadOnly = crossTrack('deadSourceKeys');
      const handlers = crossTrack('specialHandlers');
      const hasLive = live.some((k) => {
        const v = it[k];
        return v !== undefined && !(Array.isArray(v) && v.length === 0);
      });
      // 专用分流条目：必须有登记在案的 handler，且取值在消费方代码的字面量集合内
      const handled = handlers.find((h) => it[h.key] !== undefined);
      if (handled && !handled.values.includes(it[handled.key])) {
        say('A13', `规则 ${id}: ${handled.key}=${JSON.stringify(it[handled.key])} 不在已登记的取值域 [${handled.values.join('/')}] 内（先实测消费方再登记进契约表 crossTrack.specialHandlers）`);
      }
      if (!hasLive && !handled) {
        const hasDead = deadOnly.some((k) => Array.isArray(it[k]) && it[k].length > 0);
        if (hasDead) {
          say('A13', `规则 ${id}: 只有 ${deadOnly.filter((k) => Array.isArray(it[k]) && it[k].length).join('/')} 作为路径来源，清理域引擎不消费它（登记表见契约表 crossTrack），等于静默失效`);
        } else {
          say('A13', `规则 ${id}: 没有任何活路径来源（${live.join('/')} 全缺）`);
        }
      }
    }
    // A2 / A7 fileKeys 形态
    const fkList = Array.isArray(it.fileKeys) ? it.fileKeys : [];
    if ('fileKeys' in it && !Array.isArray(it.fileKeys)) say('A2', `规则 ${id}: fileKeys 必须是数组`);
    if (fkList.length > number('cleanup', 'maxFileKeysPerItem')) {
      say('A5', `规则 ${id}: fileKeys 条数 ${fkList.length} 超上限`);
    }
    for (const fk of fkList) {
      if (!fk || typeof fk !== 'object' || Array.isArray(fk)) {
        say('A2', `规则 ${id}: fileKeys 条目不是对象`);
        continue;
      }
      for (const k of Object.keys(fk)) {
        if (!fkFields.includes(k)) say('A10', `规则 ${id}: fileKeys 未知字段 ${k}`);
      }
      for (const f of fkRequired) {
        if (!(f in fk)) say('A7', `规则 ${id}: fileKeys 缺必填字段 ${f}（recurse 不得依赖缺省值）`);
      }
      const p = fk.path ?? '';
      if (typeof p !== 'string' || !p.trim()) {
        say('A2', `规则 ${id}: fileKeys.path 缺失或为空白`);
      } else {
        if ([...p].length > maxTarget) say('A2', `规则 ${id}: fileKeys.path 超长（${[...p].length} > ${maxTarget}）`);
        // 2026-10-04 磁盘清理审计 §3.1：设备/verbatim 前缀必须排在 `?` 之前判。
        // 两条含 `?` 的前缀若让通配检查先命中，理由会变成「含 ? 通配」——
        // 把安全语义问题报成 glob 能力问题，排查会被引到 expand_glob_dirs 上、
        // 找不到真正的防线。顺序与 reasons 与 Rust 侧 file_path_form_problem 逐字对齐
        // （check-cleanup-rule-contract 的共享夹具会因不一致判红）。
        const pt = p.trim();
        if (pt.startsWith('\\\\.\\') || pt.startsWith('\\??\\')) {
          say('A2', `规则 ${id}: fileKeys.path 是设备路径（Win32 跳过路径解析，无法判定保护归属）: ${p}`);
        }
        if (pt.startsWith('\\\\?\\')) {
          say('A2', `规则 ${id}: fileKeys.path 是 \\\\?\\ 长路径前缀（执行侧 expand_glob_dirs 不还原长路径，会扫描命中但执行漏删）: ${p}`);
        }
        if (p.includes('/')) say('A2', `规则 ${id}: fileKeys.path 含 / 分隔符（执行侧只按 \\ 切分）: ${p}`);
        if (p.includes('?')) say('A2', `规则 ${id}: fileKeys.path 含 ? 通配（执行侧 expand_glob_dirs 不支持）: ${p}`);
      }
      if ('recurse' in fk && typeof fk.recurse !== 'boolean') {
        say('A7', `规则 ${id}: fileKeys.recurse 必须是布尔`);
      }
      const pat = fk.pattern ?? '*';
      const stars = (pat.match(/\*/g) ?? []).length;
      if (typeof pat !== 'string' || (pat !== '*' && (stars !== 1 || pat.includes('?')))) {
        say('A2', `规则 ${id}: pattern「${pat}」超出执行侧 glob_match 的单星能力（只支持 * / 前缀* / *后缀 / 前缀*后缀）`);
      }
    }
    // A2 regKeys
    const rkList = Array.isArray(it.regKeys) ? it.regKeys : [];
    if ('regKeys' in it && !Array.isArray(it.regKeys)) say('A2', `规则 ${id}: regKeys 必须是数组`);
    if (rkList.length > number('cleanup', 'maxRegKeysPerItem')) {
      say('A5', `规则 ${id}: regKeys 条数 ${rkList.length} 超上限`);
    }
    for (const rk of rkList) {
      if (!rk || typeof rk !== 'object' || Array.isArray(rk)) {
        say('A2', `规则 ${id}: regKeys 条目不是对象`);
        continue;
      }
      for (const k of Object.keys(rk)) {
        if (!rkFields.includes(k)) say('A10', `规则 ${id}: regKeys 未知字段 ${k}`);
      }
      for (const f of rkRequired) {
        const v = rk[f];
        if (typeof v !== 'string' || !v.trim()) say('A2', `规则 ${id}: regKeys.${f} 缺失或为空白`);
      }
    }
    // A2 excludePaths（C-2 开门的字段；:: 具名值排除只能配具名值 regKeys —— F-2）
    if ('excludePaths' in it) {
      const eps = it.excludePaths;
      if (!Array.isArray(eps)) say('A2', `规则 ${id}: excludePaths 必须是字符串数组`);
      else {
        if (eps.length > number('cleanup', 'maxExcludePathsPerItem')) {
          say('A5', `规则 ${id}: excludePaths 条数 ${eps.length} 超上限`);
        }
        let namedValueExclude = false;
        for (const t of eps) {
          if (typeof t !== 'string' || !t.trim()) say('A2', `规则 ${id}: excludePaths 含非字符串或空项`);
          else {
            if (t.includes('/')) say('A2', `规则 ${id}: excludePaths 含 / 分隔符（执行侧只按 \\ 归一）: ${t}`);
            if (t.includes('?')) say('A2', `规则 ${id}: excludePaths 含 ? 通配（执行侧不支持）: ${t}`);
            if (t.includes('::')) namedValueExclude = true;
          }
        }
        if (namedValueExclude) {
          const offenders = rkList.filter((rk) => rk && typeof rk === 'object' && (!rk.value || rk.value === '*'));
          if (offenders.length > 0) {
            say('A2', `规则 ${id}: excludePaths 含具名值排除（::），但 regKeys 存在删树/通配形态（无法保留个别值）`);
          }
        }
      }
    }
    // A3 目标精确重复
    for (const fp of targetFingerprints(it)) {
      if (seenTargets.has(fp)) {
        say('A3', `规则 ${id} 与 ${seenTargets.get(fp)} 重复定义 ${fp}`);
      } else {
        seenTargets.set(fp, id);
      }
    }
  };

  for (const g of pkg.groups) {
    if (!g || typeof g !== 'object' || Array.isArray(g)) {
      say('A5', 'groups 条目不是对象');
      continue;
    }
    for (const k of Object.keys(g)) {
      if (!groupFields.includes(k)) say('A10', `组未知字段 ${k}`);
    }
    for (const f of groupRequired) {
      const v = g[f];
      if (typeof v !== 'string' || !v.trim()) say('A6', `groups.${f} 缺失或为空（组 ${g.key ?? '?'}）`);
    }
    for (const it of g.items ?? []) checkItem(it, `组 ${g.key ?? '?'}`);
    const subs = g.subGroups ?? [];
    if (!Array.isArray(subs)) say('A5', `组 ${g.key ?? '?'} 的 subGroups 必须是数组`);
    else {
      if (subs.length > number('cleanup', 'maxSubGroupsPerGroup')) {
        say('A5', `组 ${g.key ?? '?'} 的 subGroups 数量 ${subs.length} 超上限`);
      }
      for (const sg of subs) {
        if (!sg || typeof sg !== 'object' || Array.isArray(sg)) {
          say('A5', 'subGroups 条目不是对象');
          continue;
        }
        for (const k of Object.keys(sg)) {
          if (!subFields.includes(k)) say('A10', `子组未知字段 ${k}`);
        }
        for (const f of subRequired) {
          const v = sg[f];
          if (typeof v !== 'string' || !v.trim()) say('A6', `subGroups.${f} 缺失或为空（子组 ${sg.id ?? sg.name ?? '?'}）`);
        }
        for (const it of sg.items ?? []) checkItem(it, `子组 ${sg.id ?? sg.name ?? '?'}`);
      }
    }
  }
  if (itemCount > number('cleanup', 'maxItems')) {
    say('A5', `条目数 ${itemCount} 超上限 ${number('cleanup', 'maxItems')}`);
  }
  // A1 token 登记集（对整包扫描，覆盖 path/pathPs/candidatesPs 等所有字符串面）
  for (const tok of collectTokens(pkg)) {
    const why = checkToken(tok);
    if (why) say('A1', `规则库出现${why}`);
  }
  return errs;
}

/**
 * 判定器自检：坏判定器（永远返回空数组）必须在这里被抓到。
 * 用一个"只违规 token"的包 + 一个"只缺必填"的包 + 一个合法包，三点定住判定方向。
 */
export function selfTest(validate) {
  const problems = [];
  const goodPkg = JSON.parse(
    JSON.stringify({
      version: 2,
      rulesVersion: 20260928,
      groups: [
        {
          key: 'g',
          title: '自检组',
          items: [
            {
              id: 'selftest-ok',
              ver: 20260928,
              name: '自检',
              risk: 'low',
              evidence: '只作用于测试目录',
              recommended: true,
              domain: 'system',
              group: 'g',
              nature: 'log',
              regenerable: true,
              prov: { source: 'builtin', sourceClass: 'independent', ref: 'selftest', reviewedAt: '2026-09-30' },
              fileKeys: [{ path: '%LOCALAPPDATA%\\SelfTest', pattern: '*', recurse: true }],
            },
          ],
        },
      ],
    }),
  );
  if (validate(goodPkg).length !== 0) problems.push('合法包被判红（判定器过严 ⇒ 会把功能打死）');
  const badToken = JSON.parse(JSON.stringify(goodPkg));
  badToken.groups[0].items[0].fileKeys[0].path = '%ZZ_NOT_A_REAL_TOKEN%\\x';
  if (!validate(badToken).some((e) => e.startsWith('[A1]'))) problems.push('未登记 token 未被 A1 判红（判定器坏成永远放行）');
  const missing = JSON.parse(JSON.stringify(goodPkg));
  delete missing.groups[0].items[0].evidence;
  if (!validate(missing).some((e) => e.startsWith('[A6]'))) problems.push('缺必填字段未被 A6 判红');
  // A12：条目级版本戳缺失 / 与顶层不等，两个方向都要能打红（V2 P2-A1）
  const noVer = JSON.parse(JSON.stringify(goodPkg));
  delete noVer.groups[0].items[0].ver;
  if (!validate(noVer).some((e) => e.startsWith('[A12]'))) problems.push('条目缺 ver 未被 A12 判红');
  const badVer = JSON.parse(JSON.stringify(goodPkg));
  badVer.groups[0].items[0].ver = 20260101;
  if (!validate(badVer).some((e) => e.startsWith('[A12]'))) problems.push('条目 ver 与顶层不等未被 A12 判红');
  return problems;
}

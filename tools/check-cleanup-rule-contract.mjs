#!/usr/bin/env node
// check-cleanup-rule-contract.mjs - 清理规则库契约门禁（P0，规则库最终优化方案 2026-09-27）
//
// 防三类问题复发：
//   1. 规则里的 %TOKEN% 展开器解析不了 → 「扫描命中、执行 0 删、状态成功」
//      （printSpoolCache 实锤：%WINDIR% 大写形态在旧执行侧白名单展开器下永远展不开）；
//   2. 扫描/执行两侧口径不一致的字段混进规则库（执行侧未实现的 excludeKeys、
//      扫描侧支持而执行侧不支持的 `?` 通配 / `/` 分隔符 / 多星 pattern）；
//   3. 精确重复规则与已裁决移除的 deleteMode 字段回潮。
//
// 可判红要求（AGENTS §4）：新增断言后至少人为破坏一次、确认退出码非 0、再恢复。
'use strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const RULES_REL = path.join('src-tauri', 'data', 'cleanup-rules.json');

// 展开器唯一实现 trim_finder::cleanup_scan::expand_env_path 用 env::var_os 逐变量解析，
// Windows 语义下大小写不敏感，理论上有值的环境变量都能展开。这里仍维护一张登记表：
// 规则库是签名发布物，token 必须显式登记才允许进入，防止「本机有值、别机没有」的
// 用户态变量（如 PATH 扩展、自定义变量）混进规则造成跨机器行为漂移。
// P0-2 基线：TEMP/TMP/PROGRAMDATA/SystemDrive 为后续扩库预留的最小变量集。
const RESOLVABLE_TOKENS = new Set([
  'LOCALAPPDATA', 'APPDATA', 'USERPROFILE', 'WINDIR', 'SystemRoot', 'SystemDrive',
  'PROGRAMDATA', 'TEMP', 'TMP', 'PUBLIC', 'ProgramFiles', 'ProgramFiles(x86)',
  'HOMEDRIVE', 'HOMEPATH',
]);

// P1-1 来源级别枚举（规则库最终优化方案 2026-09-27）。winapp2-clue 仅允许用于
// 「把 winapp2 当目录线索、文本独立重写」的规则；整库导入不存在，出现 imported 类即红。
const SOURCE_CLASSES = new Set(['windows-doc', 'vendor-doc', 'independent', 'winapp2-clue']);

// P1-3 准入必填字段（缺失即红；文件规则另须显式 recurse，见 A7）
const REQUIRED_FIELDS = ['id', 'name', 'risk', 'evidence', 'recommended', 'domain', 'group', 'nature', 'regenerable', 'prov'];
const RISK_LEVELS = new Set(['low', 'medium', 'high']);

// P1-4 winapp2Version 冻结棘轮：它只是历史素材基线，不再是扩库成果指标，
// 禁止随「计划同步」「看到新版库」抬值。确需抬值必须改这里并写明依据（版本、日期、决策）。
const WINAPP2_FROZEN = '260730';

const errors = [];
const warn = (msg) => errors.push(msg);

function fail(msg) {
  console.error(`✗ ${msg}`);
  errors.push(msg);
}

function walkRules(rule, cb) {
  for (const fk of rule.fileKeys ?? []) cb.fileKey?.(fk);
  for (const rk of rule.regKeys ?? []) cb.regKey?.(rk);
}

function main() {
  const file = path.join(ROOT, RULES_REL);
  let rules;
  try {
    rules = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    fail(`规则 JSON 不可读: ${e.message}`);
    return;
  }

  const items = [];
  for (const g of rules.groups ?? []) {
    for (const it of g.items ?? []) items.push(it);
    for (const sg of g.subGroups ?? []) for (const it of sg.items ?? []) items.push(it);
  }
  if (items.length === 0) fail('规则库没有任何条目（groups 结构异常？）');

  // ---- A1: 每个 %TOKEN% 都在登记表内（大小写不敏感，对齐 Windows 展开语义） ----
  let tokenCount = 0;
  for (const it of items) {
    const strings = [];
    const collect = (o) => {
      if (typeof o === 'string') strings.push(o);
      else if (Array.isArray(o)) o.forEach(collect);
      else if (o && typeof o === 'object') Object.values(o).forEach(collect);
    };
    collect(it);
    for (const s of strings) {
      for (const m of s.matchAll(/%([^%\s]+)%/g)) {
        tokenCount++;
        const tok = m[1];
        if (!RESOLVABLE_TOKENS.has(tok)) {
          fail(`[A1] 规则 ${it.id}：变量 %{tok}% 未登记（登记表见本文件头部 RESOLVABLE_TOKENS；先确认展开器可解析，再登记）`.replace('%{tok}%', `%${tok}%`));
        }
      }
    }
  }

  // ---- A2: 扫描/执行口径一致的字段形态 ----
  // 执行侧 expand_glob_dirs 只认 `*`、glob_match 只支持单星、分隔符只认 `\`；
  // 扫描侧（cleanup_scan.rs）支持 `?` 与 `/`。规则里出现这些形态 = 扫描命中、执行漏删。
  for (const it of items) {
    walkRules(it, {
      fileKey: (fk) => {
        const p = fk.path ?? '';
        if (p.includes('/')) fail(`[A2] 规则 ${it.id}：fileKeys.path 含 / 分隔符（执行侧只按 \\ 切分）: ${p}`);
        if (p.includes('?')) fail(`[A2] 规则 ${it.id}：fileKeys.path 含 ? 通配（执行侧 expand_glob_dirs 不支持）: ${p}`);
        if (typeof fk.recurse !== 'undefined' && typeof fk.recurse !== 'boolean') {
          fail(`[A2] 规则 ${it.id}：fileKeys.recurse 必须是布尔（两侧缺省口径都是 true，但非布尔值两侧判定路径不同）`);
        }
        const pat = fk.pattern ?? '*';
        const starCount = (pat.match(/\*/g) ?? []).length;
        if (pat !== '*' && (starCount !== 1 || pat.includes('?'))) {
          fail(`[A2] 规则 ${it.id}：pattern「${pat}」超出执行侧 glob_match 的单星能力（只支持 * / 前缀* / *后缀 / 前缀*后缀）`);
        }
      },
    });
    // excludeKeys（对象型、含 reg 面）执行侧无过滤逻辑：出现即「扫描排除、执行照删」，
    // 属于数据面放行越界删除的高危形态，回潮即红。
    if ((it.excludeKeys ?? []).length > 0) {
      fail(`[A2] 规则 ${it.id}：使用了 excludeKeys，但执行侧（native.rs cleanup_execute）未实现排除过滤——先实现执行侧再放行本断言`);
    }
    // excludePaths（C-2，2026-09-28 开门）：字符串数组，两侧已实现同口径过滤
    // （扫描 cleanup_scan.rs get_file_key_deletable / 执行 native.rs cleanup_execute，
    // 均按「%VAR% 展开 + 有扩展名=文件 + 否则=目录前缀」并入排除面）。形态约束与
    // fileKeys.path 同源：禁 / 分隔符与 ? 通配；%TOKEN% 由 A1 的全量字符串收集覆盖。
    const expaths = it.excludePaths ?? [];
    if (!Array.isArray(expaths)) {
      fail(`[A2] 规则 ${it.id}：excludePaths 必须是字符串数组`);
    } else {
      for (const t of expaths) {
        if (typeof t !== 'string' || !t.trim()) {
          fail(`[A2] 规则 ${it.id}：excludePaths 含非字符串或空项`);
        } else {
          if (t.includes('/')) fail(`[A2] 规则 ${it.id}：excludePaths 含 / 分隔符（执行侧只按 \\ 归一）: ${t}`);
          if (t.includes('?')) fail(`[A2] 规则 ${it.id}：excludePaths 含 ? 通配（执行侧不支持）: ${t}`);
        }
      }
      // F-2（2026-09-28）：excludePaths 的注册表形态（`HIVE\KEY::VALUE` 具名值排除）
      // 只对具名值 regKeys 目标可兑现——树删除（无 value）与 value:"*"（清全部值）都是
      // 原子操作，无法在删的过程中保留个别值。混用 = 扫描排除了执行删不掉的语义缺口。
      const hasRegValueExclude = expaths.some((t) => typeof t === 'string' && t.includes('::'));
      if (hasRegValueExclude) {
        const regKeys = it.regKeys ?? [];
        const offenders = regKeys.filter((rk) => !rk.value || rk.value === '*');
        if (offenders.length > 0) {
          fail(`[A2] 规则 ${it.id}：excludePaths 含具名值排除（::），但 regKeys 存在删树/通配形态（无法保留个别值）——把排除写成整键形态或改目标为具名值`);
        }
      }
    }
  }

  // ---- A3: 精确重复规则（指纹 = 目标类型 + 可移植路径模板 + pattern + recurse + reg value） ----
  const seen = new Map();
  for (const it of items) {
    const fps = [];
    for (const fk of it.fileKeys ?? []) {
      fps.push(`file|${(fk.path ?? '').toLowerCase()}|${fk.pattern ?? '*'}|${fk.recurse === false ? 'false' : 'true'}`);
    }
    for (const rk of it.regKeys ?? []) {
      fps.push(`reg|${(rk.path ?? '').toLowerCase()}|${rk.value ?? ''}`);
    }
    for (const fp of fps) {
      if (seen.has(fp)) {
        fail(`[A3] 精确重复：规则 ${it.id} 与 ${seen.get(fp)} 重复定义 ${fp}`);
      } else {
        seen.set(fp, it.id);
      }
    }
  }

  // ---- A4: deleteMode 已裁决移除（P0-5），回潮即红 ----
  const raw = fs.readFileSync(file, 'utf8');
  const dm = (raw.match(/"deleteMode"/g) ?? []).length;
  if (dm > 0) fail(`[A4] deleteMode 出现 ${dm} 次——该字段在 Rust/前端零消费方，P0-5 已裁决移除，禁止回潮`);

  // ---- A5: 结构底线（验签与对拍另有专门门禁，这里只做形状自检） ----
  if (typeof rules.rulesVersion !== 'number') fail('[A5] rulesVersion 必须是数字');
  if ('winapp2Version' in rules && String(rules.winapp2Version) !== WINAPP2_FROZEN) {
    fail(`[A5] winapp2Version=${rules.winapp2Version} 与冻结值 ${WINAPP2_FROZEN} 不符——P1-4 已裁决它只是历史素材基线，禁止随「计划同步」抬值；确需变动请修改本门禁 WINAPP2_FROZEN 并写明依据`);
  }

  // ---- A6: 准入必填字段与溯源形态（P1-3） ----
  for (const it of items) {
    for (const f of REQUIRED_FIELDS) {
      if (it[f] === undefined) fail(`[A6] 规则 ${it.id}：缺必填字段 ${f}`);
    }
    if (it.risk !== undefined && !RISK_LEVELS.has(it.risk)) {
      fail(`[A6] 规则 ${it.id}：risk「${it.risk}」不在 ${[...RISK_LEVELS].join('/')} 之内`);
    }
    const prov = it.prov ?? {};
    if (typeof prov.source !== 'string' || !prov.source) fail(`[A6] 规则 ${it.id}：prov.source 缺失或为空`);
    if (!SOURCE_CLASSES.has(prov.sourceClass)) {
      fail(`[A6] 规则 ${it.id}：prov.sourceClass「${prov.sourceClass ?? '缺失'}」不在来源级别枚举内（${[...SOURCE_CLASSES].join('/')}）`);
    }
    if (typeof prov.ref !== 'string' || !prov.ref) fail(`[A6] 规则 ${it.id}：prov.ref 缺失或为空`);
    if (!prov.reviewedAt) fail(`[A6] 规则 ${it.id}：prov.reviewedAt 缺失（治理批次日期，格式 YYYY-MM-DD）`);
  }

  // ---- A7: 文件规则必须显式写 recurse（P1-3：不得依赖缺省值，两侧口径由数据钉死） ----
  for (const it of items) {
    for (const fk of it.fileKeys ?? []) {
      if (typeof fk.recurse !== 'boolean') {
        fail(`[A7] 规则 ${it.id}：fileKeys.path「${fk.path ?? ''}」缺显式布尔 recurse`);
      }
    }
    // 进程约束字段出现时必须是非空数组（有约束却写空 = 静默失效）
    for (const f of ['restartProcesses', 'requiredStoppedProcesses']) {
      if (f in it && (!Array.isArray(it[f]) || it[f].length === 0)) {
        fail(`[A7] 规则 ${it.id}：${f} 存在但不是非空数组`);
      }
    }
  }

  // ---- A8: 父子路径重叠 → 人工复核清单（非致命，P1-2）----
  // 精确重复在 A3 判红；父子重叠（一条规则的目标目录是另一条的前缀）不禁止，
  // 但必须显式列进人工复核清单，由开发者确认「合并 / 排除 / 保持共存」三选一。
  const filePaths = [];
  for (const it of items) {
    for (const fk of it.fileKeys ?? []) {
      filePaths.push({ id: it.id, path: (fk.path ?? '').toLowerCase().replace(/\/+$/, '') });
    }
  }
  const overlaps = [];
  for (let i = 0; i < filePaths.length; i++) {
    for (let j = 0; j < filePaths.length; j++) {
      if (i === j) continue;
      const a = filePaths[i];
      const b = filePaths[j];
      if (a.id === b.id || !a.path || !b.path || a.path.includes('*') || b.path.includes('*')) continue;
      if (b.path.startsWith(a.path + '\\')) overlaps.push([a, b]);
    }
  }
  if (overlaps.length > 0) {
    console.log(`\n〔人工复核清单〕父子路径重叠 ${overlaps.length} 组（不判红，但每批发布前须有明确合并/排除/共存结论，记录见 docs/规则库审核记录-*.md）：`);
    for (const [parent, child] of overlaps) {
      console.log(`  · ${parent.id}（${parent.path}）⊃ ${child.id}（${child.path}）`);
    }
  }

  // ---- A9: 时效护栏字段形态（P0-M5，竞品借鉴落地方案 §5）----
  // minAgeHours / minAgeDays 互斥（两侧解析器对双声明取更严格值，但数据面禁止含糊）；
  // 必须是正整数；年龄语义 = 文件修改时间，扫描与执行两侧同谓词（cleanup_scan.rs）。
  for (const it of items) {
    const hasH = 'minAgeHours' in it;
    const hasD = 'minAgeDays' in it;
    if (hasH && hasD) {
      fail(`[A9] 规则 ${it.id}：minAgeHours 与 minAgeDays 互斥，不得同时声明`);
    }
    for (const f of ['minAgeHours', 'minAgeDays']) {
      if (!(f in it)) continue;
      const v = it[f];
      if (typeof v !== 'number' || !Number.isInteger(v) || v <= 0) {
        fail(`[A9] 规则 ${it.id}：${f} 必须是正整数（当前 ${JSON.stringify(v)}）`);
      }
    }
  }

  if (errors.length > 0) {
    console.error(`\n清理规则契约门禁：${errors.length} 处违约（共检查 ${items.length} 条规则 / ${tokenCount} 个 token 引用）`);
    process.exit(1);
  }
  console.log(`✓ 清理规则契约门禁通过：${items.length} 条规则 / ${tokenCount} 个 token 引用全部可解析、口径一致、无重复`);
}

main();

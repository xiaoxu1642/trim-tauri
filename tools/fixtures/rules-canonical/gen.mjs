// tools/fixtures/rules-canonical/gen.mjs —— 签名规范化跨语言共享夹具的生成器（T1c-U02）
//
// 为什么需要：规则库签名对象是「规则 JSON 去掉 _sig 后的紧凑 JSON 文本」，而算这段文本的
// 是**两套独立实现**——Node 侧 tools/sign-cleanup-rules.mjs 的 canonicalBodyText、Rust 侧
// src-tauri/src/engine/rules_signature.rs 的 canonical_body_text / canonical_array_text。
// 两套实现分叉的症状是「发布前 Node 门禁全绿、用户装上后装载侧拒收」，且没有任何信号。
//
// 跨语言只共享**字节**、不共享判定：本文件把输入原文与期望规范化文本冻结成 expected
// 字面量，Node 门禁（check-data-signatures 第 4 段）与 Rust 测试（rules_signature.rs 的
// canonical_fixture_cross_language_parity）各自用自己的实现重算再与 expected 逐字节比。
// expected 是**手写字面量**、不是运行期从某一侧实现算出来的——否则就是用被测实现给自己
// 出题，永远绿。手改本文件后必须重跑本生成器，否则 check-fixture-freshness 判红。
//
// 覆盖形态：对象内联 _sig / 对象缺 _sig / 只有 _sig（剥完是空对象）/ 空对象 /
// 裸数组（含元素内 _sig，数组形态**不**逐元素剥离）/ 空数组 / 中文与 \u 转义与
// 控制字符 / 多层嵌套。数值只放整数与 1.5：serde 与 JS 的浮点格式化不同源
// （1.0、1e10、超过 2^53 的整数会各写各的），这类数值不该进规则库，另行判定。
//
// 用法：node tools/fixtures/rules-canonical/gen.mjs        # 重算并落盘 cases.json
//       node tools/fixtures/rules-canonical/gen.mjs --check # 只读校验（手改夹具即红）

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const OUT = join(ROOT, 'tools', 'fixtures', 'rules-canonical', 'cases.json');

/** 夹具用例（唯一实现）。input 是**文件原文**，两侧各自解析；expected 是规范化后的完整文本。 */
export const CANONICAL_CASES = [
  {
    name: 'object-inline-sig-middle',
    form: 'object',
    input: String.raw`{
  "rulesVersion": 12,
  "groups": [
    {
      "id": "temp",
      "paths": ["C:\\Windows\\Temp", "C:\\Users\\Public\\Temp"]
    }
  ],
  "_sig": {
    "alg": "ed25519",
    "sig": "AAAA"
  },
  "tail": true
}`,
    expected: String.raw`{"rulesVersion":12,"groups":[{"id":"temp","paths":["C:\\Windows\\Temp","C:\\Users\\Public\\Temp"]}],"tail":true}`,
  },
  {
    name: 'object-without-sig',
    form: 'object',
    input: String.raw`{"schemaVer": 2,   "entryId": "nara", "enabled": false, "ratio": 1.5}`,
    expected: String.raw`{"schemaVer":2,"entryId":"nara","enabled":false,"ratio":1.5}`,
  },
  {
    name: 'object-unicode-and-escapes',
    form: 'object',
    input: String.raw`{"name":"\u4e2d\u6587","note":"line\nbreak\ttab","quote":"a\"b","back":"c\\d","slash":"e\/f","ctrl":"\u0001","raw":"中文"}`,
    expected: String.raw`{"name":"中文","note":"line\nbreak\ttab","quote":"a\"b","back":"c\\d","slash":"e/f","ctrl":"\u0001","raw":"中文"}`,
  },
  {
    name: 'object-nested',
    form: 'object',
    input: String.raw`{
  "sections": [
    {"title": "隐私", "items": [{"key": "a", "on": true}, {"key": "b", "on": null}]},
    []
  ],
  "meta": {"deep": {"deeper": {"n": 0}}}
}`,
    expected: String.raw`{"sections":[{"title":"隐私","items":[{"key":"a","on":true},{"key":"b","on":null}]},[]],"meta":{"deep":{"deeper":{"n":0}}}}`,
  },
  {
    name: 'object-empty',
    form: 'object',
    input: '{  }',
    expected: '{}',
  },
  {
    name: 'object-sig-only',
    form: 'object',
    input: String.raw`{"_sig":{"alg":"ed25519","sig":"AAAA"}}`,
    expected: '{}',
  },
  {
    name: 'array-bare-with-inner-sig',
    form: 'array',
    // 数组形态的签名在 sidecar，正文原样序列化：元素里的 _sig 是普通数据，**不剥**。
    // 若有人把「剥顶层 _sig」的规则推广到数组元素，这条用例当场红。
    input: String.raw`[
  {"id": "a", "risk": "low", "_sig": {"sig": "inner-stays"}},
  {"id": "b", "risk": "high"}
]`,
    expected: String.raw`[{"id":"a","risk":"low","_sig":{"sig":"inner-stays"}},{"id":"b","risk":"high"}]`,
  },
  {
    name: 'array-empty',
    form: 'array',
    input: '[ ]',
    expected: '[]',
  },
];

/** 夹具全文（唯一实现）：check-fixture-freshness.mjs import 同一份做逐字节对拍。 */
export function buildDoc() {
  return `${JSON.stringify(
    {
      _comment:
        '签名规范化跨语言共享夹具（T1c-U02）：input 是规则文件原文，expected 是「去掉顶层 _sig 后的紧凑 JSON 文本」' +
        '（数组形态原样序列化）。Node 与 Rust 各自用自己的实现重算，必须与 expected 逐字节相等。' +
        '由 tools/fixtures/rules-canonical/gen.mjs 生成，手改即被 check-fixture-freshness 判红。',
      schema: 1,
      cases: CANONICAL_CASES,
    },
    null,
    2,
  )}\n`;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.includes('--check')) {
    let have = '';
    try {
      have = readFileSync(OUT, 'utf8');
    } catch (e) {
      console.error(`✗ 夹具不可读：${e.message}`);
      process.exit(1);
    }
    if (have !== buildDoc()) {
      console.error(
        '✗ 盘上 rules-canonical/cases.json 与构造不一致——夹具被手改或 CANONICAL_CASES 改后未重跑。重跑：node tools/fixtures/rules-canonical/gen.mjs',
      );
      process.exit(1);
    }
    console.log(`✓ rules-canonical/cases.json 与构造逐字节一致（${CANONICAL_CASES.length} 例）`);
    process.exit(0);
  }
  writeFileSync(OUT, buildDoc(), 'utf8');
  console.log(`✓ 已落盘 ${OUT}（${CANONICAL_CASES.length} 例）`);
}

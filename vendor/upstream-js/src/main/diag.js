// diag.js - 失败诊断四元组（P1-11）
// 参考 MangoDisk 审计模型：failure_stage / mutation_state / diagnostic_digest / native_error_code
// PS 侧：脚本内 Write-TFDiag 输出 @@DIAG@@{json} 行；JS 侧：parseDiagLine 解析、formatDiag 格式化、
// jsDiag 供主进程原生操作（fs.unlink 等）直接构造。所有诊断统一经 writeLog 写入操作日志。

// 诊断行前缀（PS Write-Output 与 JS 解析共用）
const DIAG_PREFIX = '@@DIAG@@';

// 注入到各 PowerShell 脚本头部的诊断函数（含 trap 兜底）。
// 依赖脚本已设置 $ErrorActionPreference = 'SilentlyContinue'：
// trap 仅捕获终止性错误，非终止错误仍按原逻辑静默继续，行为兼容。
const PS_PREAMBLE = `
# ---- Trim 诊断四元组 (P1-11) ----
function Write-TFDiag {
  param([string]$Stage, [string]$Mutation, [string]$Detail)
  try {
    $native = 0
    try { $native = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() } catch { }
    if ($native -eq 0 -and $null -ne $LASTEXITCODE) { $native = $LASTEXITCODE }
    $key = $Stage + '|' + $Mutation + '|' + $Detail
    $digest = '{0:X8}' -f [Math]::Abs($key.GetHashCode())
    $o = [ordered]@{
      failure_stage = $Stage
      mutation_state = $Mutation
      diagnostic_digest = $digest
      native_error_code = [int64]$native
      detail = [string]$Detail
    }
    Write-Output ('${DIAG_PREFIX}' + ($o | ConvertTo-Json -Compress))
  } catch { }
}
trap {
  Write-TFDiag -Stage 'script' -Mutation 'unknown' -Detail $_.Exception.Message
  continue
}
`;

// 解析一行 stdout：命中诊断行返回对象，否则返回 null
function parseDiagLine(line) {
  if (!line || !line.startsWith(DIAG_PREFIX)) return null;
  try {
    const o = JSON.parse(line.slice(DIAG_PREFIX.length));
    if (!o || !o.failure_stage) return null;
    return o;
  } catch (e) {
    return null;
  }
}

// JS 侧字符串摘要（与 PS GetHashCode 不要求一致，仅作日志去重指纹）
function jsDigest(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  }
  return Math.abs(h).toString(16).toUpperCase().padStart(8, '0');
}

// 主进程原生操作（Node fs 等）直接构造四元组
function jsDiag(stage, mutation, errOrDetail) {
  const detail = typeof errOrDetail === 'string' ? errOrDetail : String(errOrDetail?.message || errOrDetail || '');
  const native = errOrDetail && typeof errOrDetail === 'object' && errOrDetail.errno ? Number(errOrDetail.errno) : 0;
  return {
    failure_stage: stage,
    mutation_state: mutation,
    diagnostic_digest: jsDigest(stage + '|' + mutation + '|' + detail),
    native_error_code: native,
    detail
  };
}

// 统一日志格式：[DIAG] op=<操作> stage=.. mutation=.. digest=.. native=.. detail=..
// 火眼眼审查 2026-09-14（LOW）：先剥离 C0 控制字符与 DEL（\s 只覆盖空白类，
// 其余 C0 可伪造日志行），再压空白，防日志注入。
function formatDiag(op, d) {
  const detail = String(d.detail || '')
    .replace(/[\u0000-\u001F\u007F]+/g, ' ')
    .replace(/\s+/g, ' ')
    .slice(0, 300);
  return `[DIAG] op=${op} stage=${d.failure_stage} mutation=${d.mutation_state} digest=${d.diagnostic_digest} native=${d.native_error_code} detail=${detail}`;
}

module.exports = { DIAG_PREFIX, PS_PREAMBLE, parseDiagLine, jsDiag, formatDiag };

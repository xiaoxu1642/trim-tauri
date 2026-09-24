// ps-rule-path-eval.js — 规则路径表达式「受限求值器」PowerShell 代码片段（单一来源）
//
// 谁在用：cleanup-scripts.js（SCAN 3 处 + DETAIL 1 处）、pathscan-scripts.js（规则候选 2 处）。
// 这些位置原本是 Invoke-Expression(规则字段)，本模块把它换成只认「拼路径」的递归下降求值器。
//
// 为什么必须换掉 Invoke-Expression：
//   规则库有两个不完全可信的来源——① 在线更新（ed25519 验签，但密钥轮换/防降级链路一旦出错即失守）；
//   ② 自定义规则目录 %APPDATA%\Trim\cleanup\custom\*.json（loadRules 直接合并，**不验签**）。
//   两者最终都作为 JSON 字面量注入 PowerShell，而 pathPs / candidatesPs / globCandidatesPs 曾被
//   Invoke-Expression 当作 PowerShell 代码执行 —— 等价于「谁能写那两个 json 文件，谁就拿到
//   以当前用户权限执行任意代码」。规则表达式的真实需求只有「环境变量 + 字面量拼路径」一种，
//   为此保留整个 PS 语言解释器完全不成比例。
//
// 受限语法（除此之外一律判失败）：
//     表达式 := '(' 表达式 ')' | 项 ('+' 项)*
//     项     := '$env:' 标识符 | 单引号字面量（'' 转义单个撇号）
//   方法调用、属性访问、双引号插值、子表达式 $()、${}、命令分隔符 ; 、&调用等全部拒绝。
//
// fail-closed 约定（调用方必须遵守）：ok=$false 时按「路径不可解析」处理（跳过 / 上报），
//   严禁回落到表达式原文 —— 旧 SCAN 代码的 `if (-not $path) { $path = [string]$rule.pathPs }`
//   就是把未求值的表达式字面量当路径用，v2.2 第 2 批已废除。
//
// 兼容性证据：内置规则库 49 条表达式（37 pathPs + 10 candidatesPs + 2 globCandidatesPs）
//   已逐条与 Invoke-Expression 结果对拍，零偏差；覆盖 'C:\$Recycle.Bin' 的 $、
//   'Dism++Backup' 的 + 号、'Windows Defender' 类空格、以及含 * 的通配候选段。
//
// 语义细节：未定义的 $env:X 取空串（与 PowerShell 原生一致），因此「求值成功但结果为空」
//   是合法态，由调用方按空路径处理，不当作解析失败。

const RULE_PATH_EVAL_PS = `
$RULE_PATH_MAX_DEPTH = 32
function Resolve-RulePrim {
  param($St)
  # 审查 L-7（2026-09-14）：嵌套括号深度上限，防止恶意/异常规则表达式让 PowerShell 栈递归爆掉。
  $St.depth = [int]$St.depth + 1
  if ($St.depth -gt $RULE_PATH_MAX_DEPTH) { $St.ok = $false; return }
  $ws = ' ' + [char]9
  while ($St.i -lt $St.s.Length -and $ws.Contains($St.s[$St.i])) { $St.i = $St.i + 1 }
  if ($St.i -ge $St.s.Length) { $St.ok = $false; return }
  $c = $St.s[$St.i]
  if ($c -eq '(') {
    $St.i = $St.i + 1
    Resolve-RuleConcat $St
    if (-not $St.ok) { return }
    while ($St.i -lt $St.s.Length -and $ws.Contains($St.s[$St.i])) { $St.i = $St.i + 1 }
    if ($St.i -ge $St.s.Length -or $St.s[$St.i] -ne ')') { $St.ok = $false; return }
    $St.i = $St.i + 1
    return
  }
  if ($c -eq "'") {
    $St.i = $St.i + 1
    $sb = New-Object System.Text.StringBuilder
    while ($true) {
      if ($St.i -ge $St.s.Length) { $St.ok = $false; return }
      $ch = $St.s[$St.i]
      if ($ch -eq "'") {
        if ($St.i + 1 -lt $St.s.Length -and $St.s[$St.i + 1] -eq "'") { [void]$sb.Append("'"); $St.i = $St.i + 2; continue }
        $St.i = $St.i + 1
        break
      }
      [void]$sb.Append($ch)
      $St.i = $St.i + 1
    }
    $St.val = $sb.ToString()
    return
  }
  if ($c -eq '$') {
    $rest = $St.s.Substring($St.i)
    if (-not $rest.StartsWith('$env:')) { $St.ok = $false; return }
    $St.i = $St.i + 5
    $start = $St.i
    while ($St.i -lt $St.s.Length -and $St.s[$St.i] -match '[A-Za-z0-9_]') { $St.i = $St.i + 1 }
    if ($St.i -eq $start) { $St.ok = $false; return }
    $name = $St.s.Substring($start, $St.i - $start)
    $v = [Environment]::GetEnvironmentVariable($name)
    if ($null -eq $v) { $v = '' }
    $St.val = [string]$v
    return
  }
  $St.ok = $false
}

function Resolve-RuleConcat {
  param($St)
  Resolve-RulePrim $St
  if (-not $St.ok) { return }
  $acc = [string]$St.val
  $ws = ' ' + [char]9
  while ($true) {
    $j = $St.i
    while ($j -lt $St.s.Length -and $ws.Contains($St.s[$j])) { $j = $j + 1 }
    if ($j -lt $St.s.Length -and $St.s[$j] -eq '+') {
      $St.i = $j + 1
      Resolve-RulePrim $St
      if (-not $St.ok) { return }
      $acc = $acc + [string]$St.val
    } else { break }
  }
  $St.val = $acc
}

# 返回 [pscustomobject]{ok, path}：ok=$false 表示表达式不符合受限语法（调用方须 fail-closed）。
# 注意：函数体内禁止 Write-Output / Write-TFDiag —— 任何意外管道输出都会污染返回值（既有陷阱）。
function Resolve-RulePath {
  param([string]$Expr)
  if ([string]::IsNullOrEmpty($Expr)) { return [pscustomobject]@{ ok = $false; path = '' } }
  $s = [string]$Expr
  $st = @{ s = $s; i = 0; ok = $true; val = ''; depth = 0 }
  Resolve-RuleConcat $st
  if (-not $st.ok) { return [pscustomobject]@{ ok = $false; path = '' } }
  $k = [int]$st.i
  $ws = ' ' + [char]9
  while ($k -lt $s.Length -and $ws.Contains($s[$k])) { $k = $k + 1 }
  if ($k -ne $s.Length) { return [pscustomobject]@{ ok = $false; path = '' } }
  return [pscustomobject]@{ ok = $true; path = [string]$st.val }
}
`;

module.exports = { RULE_PATH_EVAL_PS };

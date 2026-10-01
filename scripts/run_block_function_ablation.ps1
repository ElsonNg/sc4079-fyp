<#
.SYNOPSIS
Run only block+function, reusing completed controls without rescanning them.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 100)][int]$Repetitions = 3,
    [ValidateRange(1, 3600)][int]$HeartbeatSeconds = 30,
    [ValidateRange(1, 1200)][int]$SmokeLimit,
    [string]$Output,
    [string]$ReferenceOutput = 'eval/frozen/active-region-ablation-gpu-v1',
    [switch]$Plan,
    [switch]$CollectOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Plan -and $CollectOnly) { throw 'Choose either -Plan or -CollectOnly.' }
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$pythonPath = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) { throw "Python environment not found: $pythonPath" }
$runnerArguments = @('-m', 'eval.ablation.run_block_function', '--count', '1',
    '--repetitions', [string]$Repetitions, '--heartbeat-seconds', [string]$HeartbeatSeconds,
    '--reference-output', $ReferenceOutput)
if ($Output) { $runnerArguments += @('--output', $Output) }
if ($PSBoundParameters.ContainsKey('SmokeLimit')) { $runnerArguments += @('--smoke-limit', [string]$SmokeLimit) }
if ($Plan) { $runnerArguments += '--plan' }
if ($CollectOnly) { $runnerArguments += '--collect-only' }
Write-Host 'Only block + function: changed and context OFF; existing controls are reused.'
Write-Host 'K5/B10/R96/V3; 1,200 cases; CUDA FP32; hash and contrastive ON; LLM OFF.'
$runnerExitCode = 1
Push-Location -LiteralPath $repoRoot
try {
    & $pythonPath @runnerArguments
    $runnerExitCode = $LASTEXITCODE
} finally { Pop-Location }
exit $runnerExitCode

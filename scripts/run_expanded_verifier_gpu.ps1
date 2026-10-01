<#
.SYNOPSIS
Run fresh, resumable GPU detector passes with the promoted expanded verifier.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 100)][int]$Repetitions = 3,
    [ValidateRange(1, 3600)][int]$HeartbeatSeconds = 30,
    [ValidateRange(1, 1200)][int]$SmokeLimit,
    [string]$Output,
    [switch]$Plan,
    [switch]$CollectOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Plan -and $CollectOnly) { throw 'Choose either -Plan or -CollectOnly.' }
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$pythonPath = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) { throw "Python environment not found: $pythonPath" }
$runnerArguments = @('-m', 'eval.ablation.run_expanded_e2e', '--count', '1',
    '--repetitions', [string]$Repetitions, '--heartbeat-seconds', [string]$HeartbeatSeconds,
    '--manifest', (Join-Path $repoRoot 'eval\frozen\experiment-active-v2\manifest.json'))
if ($Output) { $runnerArguments += @('--output', $Output) }
if ($PSBoundParameters.ContainsKey('SmokeLimit')) { $runnerArguments += @('--smoke-limit', [string]$SmokeLimit) }
if ($Plan) { $runnerArguments += '--plan' }
if ($CollectOnly) { $runnerArguments += '--collect-only' }
Write-Host 'Expanded verifier ON; block + function only; hash and contrastive ON; LLM OFF.'
Write-Host 'Retrieval top-K 5; verification budget 10; R96/V3; S/T .70; edit .90; margin .10.'
Write-Host '1,200 cases in a full pass; CUDA FP32. Rerun the same command to resume.'
$runnerExitCode = 1
Push-Location -LiteralPath $repoRoot
try {
    & $pythonPath @runnerArguments
    $runnerExitCode = $LASTEXITCODE
} finally { Pop-Location }
exit $runnerExitCode

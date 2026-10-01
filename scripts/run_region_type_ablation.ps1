<#
.SYNOPSIS
Run/resume the six region-type settings on CUDA, using a new source lock.
.DESCRIPTION
Defaults to all 600 Tier 1 and 600 Tier 2 cases, three repetitions, all six arms.
Plan is read-only. Smoke runs automatically use a separate output directory.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 6)][int]$Count = 6,
    [ValidateRange(1, 100)][int]$Repetitions = 3,
    [ValidateRange(1, 3600)][int]$HeartbeatSeconds = 30,
    [ValidateSet('both', 'tier1', 'tier2')][string]$Tier = 'both',
    [ValidateSet('all', 'tuning', 'evaluation')][string]$Split = 'all',
    [ValidateRange(1, 1200)][int]$SmokeLimit,
    [string]$Manifest = 'eval/frozen/experiment-active-v2/manifest.json',
    [string]$Output,
    [switch]$Plan,
    [switch]$CollectOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Plan -and $CollectOnly) { throw 'Choose either -Plan or -CollectOnly.' }
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$pythonPath = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
    throw "Repository Python environment not found: $pythonPath"
}
$runnerArguments = @('-m', 'eval.ablation.run_region_types', '--manifest', $Manifest,
    '--count', [string]$Count, '--repetitions', [string]$Repetitions,
    '--heartbeat-seconds', [string]$HeartbeatSeconds, '--tier', $Tier, '--split', $Split)
if ($Output) { $runnerArguments += @('--output', $Output) }
if ($PSBoundParameters.ContainsKey('SmokeLimit')) { $runnerArguments += @('--smoke-limit', [string]$SmokeLimit) }
if ($Plan) { $runnerArguments += '--plan' }
if ($CollectOnly) { $runnerArguments += '--collect-only' }
Write-Host 'Region-type study: all four; remove changed/block/context/function; function only.'
Write-Host 'K5/B10/R96/V3; hash and contrastive ON; LLM OFF; CUDA FP32.'
$runnerExitCode = 1
Push-Location -LiteralPath $repoRoot
try {
    & $pythonPath @runnerArguments
    $runnerExitCode = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $runnerExitCode

#!/usr/bin/env pwsh
# Self-Improvement Loop Orchestrator for dsh-tool-codereview
# Manages the continuous improvement cycle

param(
    [switch]$CollectOnly,
    [switch]$AnalyzeOnly,
    [switch]$FullLoop,
    [switch]$DryRun
)

$ErrorActionPreference = "SilentlyContinue"

Write-Host "========================================"
Write-Host "  Self-Improvement Loop Orchestrator"
Write-Host "  dsh-tool-codereview v0.6.0-dev"
Write-Host "========================================"
Write-Host ""

$phases = @(
    "FeedbackCollection",
    "Analysis",
    "ImprovementGeneration",
    "Implementation",
    "Testing",
    "Release",
    "MetricsUpdate"
)

$startTime = Get-Date

# Phase 1: Feedback Collection
if ($FullLoop -or $CollectOnly -or -not $AnalyzeOnly) {
    Write-Host "[Phase 1/7] Feedback Collection"
    Write-Host "-------------------------------"
    try {
        & .self-improvement/feedback-collector.ps1
        Write-Host "[✓] Feedback collection complete"
    } catch {
        Write-Host "[✗] Feedback collection failed: $_"
    }
    Write-Host ""
    if ($CollectOnly) { return }
}

# Phase 2: Analysis
if ($FullLoop -or $AnalyzeOnly -or $CollectOnly) {
    Write-Host "[Phase 2/7] Analysis"
    Write-Host "---------------------"
    try {
        & .self-improvement/analysis-engine.ps1
        Write-Host "[✓] Analysis complete"
    } catch {
        Write-Host "[✗] Analysis failed: $_"
    }
    Write-Host ""
    if ($AnalyzeOnly) { return }
}

# Phase 3: Load recommendations
Write-Host "[Phase 3/7] Improvement Generation"
Write-Host "------------------------------------"
$reportPath = ".self-improvement/analysis-report.json"
if (Test-Path $reportPath) {
    $report = Get-Content $reportPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Write-Host "Loaded $($report.recommendations.Count) recommendations"
    foreach ($rec in $report.recommendations) {
        Write-Host "  [$($rec.id)] $($rec.title) [$($rec.priority)]"
    }
} else {
    Write-Host "[!] No analysis report found"
}
Write-Host ""

# Phase 4-7: Implementation, Testing, Release (manual for now)
Write-Host "[Phase 4-7] Implementation → Testing → Release → Metrics"
Write-Host "-----------------------------------------------------------"
Write-Host "These phases require manual implementation based on analysis results."
Write-Host ""

$endTime = Get-Date
$duration = ($endTime - $startTime).TotalSeconds

# Save loop metrics
$loopMetrics = @{
    last_run = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    duration_seconds = [math]::Round($duration, 2)
    phases_completed = 2
    total_phases = 7
    recommendations_count = if ($report) { $report.recommendations.Count } else { 0 }
}

$loopMetrics | ConvertTo-Json | Set-Content -Path ".self-improvement/loop-metrics.json" -Encoding UTF8

Write-Host "========================================"
Write-Host "  Loop completed in $([math]::Round($duration, 2))s"
Write-Host "========================================"

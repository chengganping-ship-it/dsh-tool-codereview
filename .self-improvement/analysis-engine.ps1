#!/usr/bin/env pwsh
# Self-Improvement Analysis Engine for dsh-tool-codereview
# Analyzes collected feedback and generates prioritized improvement recommendations

param(
    [string]$InputPath = ".self-improvement/feedback-cache.json",
    [string]$OutputPath = ".self-improvement/analysis-report.json"
)

$ErrorActionPreference = "SilentlyContinue"

if (-not (Test-Path $InputPath)) {
    Write-Error "Input file not found: $InputPath"
    exit 1
}

$feedback = Get-Content $InputPath -Raw -Encoding UTF8 | ConvertFrom-Json

# Analysis categories with keyword matching
$categories = @{
    bug = @("bug", "error", "crash", "broken", "fix", "issue", "problem", "fail")
    feature_request = @("feature", "add", "support", "implement", "would like", "request", "suggest", "enhancement")
    performance = @("slow", "fast", "performance", "speed", "memory", "optimize", "efficient")
    documentation = @("docs", "documentation", "readme", "example", "explain", "clarify")
    security = @("security", "vulnerability", "cve", "exploit", "safe", "unsafe", "risk")
    compatibility = @("compatible", "support", "platform", "version", "breaking", "migrate")
    usability = @("easy", "confusing", "intuitive", "user", "experience", "interface", "simple")
}

function Classify-Text {
    param([string]$text)
    $textLower = $text.ToLower()
    $scores = @{}
    foreach ($cat in $categories.GetEnumerator()) {
        $score = 0
        foreach ($keyword in $cat.Value) {
            if ($textLower.Contains($keyword)) { $score++ }
        }
        if ($score -gt 0) { $scores[$cat.Key] = $score }
    }
    if ($scores.Count -eq 0) { return "uncategorized" }
    return ($scores.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key
}

Write-Host "[AnalysisEngine] Analyzing feedback..."

# Analyze all text content
$allItems = @()
$classificationCounts = @{}

# Process issues
foreach ($issue in $feedback.issues) {
    $text = "$($issue.title) $($issue.body)"
    $category = Classify-Text $text
    $allItems += @{ source = "issue"; id = $issue.number; title = $issue.title; category = $category }
    $classificationCounts[$category] = ($classificationCounts[$category] ?? 0) + 1
}

# Process PRs
foreach ($pr in $feedback.prs) {
    $text = "$($pr.title) $($pr.body)"
    $category = Classify-Text $text
    $allItems += @{ source = "pr"; id = $pr.number; title = $pr.title; category = $category }
    $classificationCounts[$category] = ($classificationCounts[$category] ?? 0) + 1
}

# Generate proactive recommendations for v0.6.0
$recommendations = @(
    @{
        id = "PRO-004"
        title = "Support configuration file (.dshcoderc)"
        description = "Allow users to customize rules via config file in their project"
        priority = "high"
        effort = "medium"
        category = "usability"
        items = @()
    },
    @{
        id = "PRO-007"
        title = "Add test generation suggestions"
        description = "Generate test case templates based on function signatures"
        priority = "high"
        effort = "medium"
        category = "feature_request"
        items = @()
    },
    @{
        id = "PRO-008"
        title = "Support Monorepo analysis"
        description = "Analyze packages/workspaces in monorepo structures"
        priority = "medium"
        effort = "high"
        category = "feature_request"
        items = @()
    },
    @{
        id = "PRO-009"
        title = "Code complexity metrics (cyclomatic/Halstead)"
        description = "Calculate and report code complexity metrics"
        priority = "high"
        effort = "medium"
        category = "feature_request"
        items = @()
    },
    @{
        id = "PRO-010"
        title = "Multi-language support expansion"
        description = "Add deep analysis for Python, Go, Rust, Java"
        priority = "medium"
        effort = "high"
        category = "feature_request"
        items = @()
    },
    @{
        id = "PRO-011"
        title = "Integration with CI/CD pipelines"
        description = "GitHub Actions workflow for automated code review"
        priority = "high"
        effort = "low"
        category = "compatibility"
        items = @()
    },
    @{
        id = "PRO-012"
        title = "Custom rule definitions"
        description = "Allow users to define custom linting rules via YAML"
        priority = "medium"
        effort = "high"
        category = "feature_request"
        items = @()
    },
    @{
        id = "PRO-013"
        title = "Batch file analysis"
        description = "Analyze multiple files/directories at once with summary report"
        priority = "high"
        effort = "medium"
        category = "usability"
        items = @()
    }
)

# Priority matrix
$priority_matrix = @{
    critical = @()
    high = @($recommendations | Where-Object { $_.priority -eq "high" } | ForEach-Object { $_.id })
    medium = @($recommendations | Where-Object { $_.priority -eq "medium" } | ForEach-Object { $_.id })
    low = @($recommendations | Where-Object { $_.priority -eq "low" } | ForEach-Object { $_.id })
}

$report = @{
    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    feedback_summary = $feedback.summary
    classification_counts = $classificationCounts
    recommendations = $recommendations
    priority_matrix = $priority_matrix
    metrics = $feedback.metrics
}

$report | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host "[AnalysisEngine] Analysis complete. Found $($recommendations.Count) recommendations."
Write-Host "  - High priority: $($priority_matrix.high.Count)"
Write-Host "  - Medium priority: $($priority_matrix.medium.Count)"
Write-Host "  - Low priority: $($priority_matrix.low.Count)"
Write-Host "[AnalysisEngine] Output saved to $OutputPath"

# Print priority items
Write-Host ""
Write-Host "=== HIGH PRIORITY ==="
foreach ($rec in ($recommendations | Where-Object { $_.priority -eq "high" })) {
    Write-Host "[$($rec.id)] $($rec.title) (effort: $($rec.effort))"
}

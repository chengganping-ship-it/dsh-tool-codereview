#!/usr/bin/env pwsh
# Self-Improvement Feedback Collector for dsh-tool-codereview
# Collects feedback from GitHub Issues, PRs, Discussions, and external sources

param(
    [string]$Repo = "chengganping-ship-it/dsh-tool-codereview",
    [string]$OutputPath = ".self-improvement/feedback-cache.json"
)

$ErrorActionPreference = "SilentlyContinue"

function Collect-Issues {
    $issues = gh issue list --repo $Repo --state all --json number,title,body,labels,state,createdAt,comments 2>$null | ConvertFrom-Json
    return $issues
}

function Collect-PRs {
    $prs = gh pr list --repo $Repo --state all --json number,title,body,state,createdAt,mergedAt 2>$null | ConvertFrom-Json
    return $prs
}

function Collect-Discussions {
    # GitHub CLI doesn't have native discussion support, use API
    $discussions = gh api "repos/$Repo/discussions" --jq '.[] | {number, title, body, created_at}' 2>$null
    if ($discussions) { return $discussions } else { return @() }
}

function Collect-ReviewComments {
    $comments = gh api "repos/$Repo/pulls/comments" --jq '.[] | {id, body, path, line, created_at}' 2>$null
    if ($comments) { return $comments } else { return @() }
}

function Collect-Metrics {
    $repoInfo = gh repo view $Repo --json stars,forks,watchers,openIssues,createdAt,pushedAt,language,size 2>$null | ConvertFrom-Json
    return $repoInfo
}

Write-Host "[FeedbackCollector] Collecting feedback from $Repo..."

$metrics = Collect-Metrics

$feedback = @{
    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    repository = $Repo
    summary = @{
        total_items = 0
        issues = 0
        prs = 0
        discussions = 0
        review_comments = 0
        external_mentions = 0
    }
    issues = @()
    prs = @()
    discussions = @()
    review_comments = @()
    metrics = $metrics
}

# Collect issues
$issues = Collect-Issues
if ($issues) {
    $feedback.issues = $issues
    $feedback.summary.issues = $issues.Count
}

# Collect PRs
$prs = Collect-PRs
if ($prs) {
    $feedback.prs = $prs
    $feedback.summary.prs = $prs.Count
}

# Collect discussions
$discussions = Collect-Discussions
if ($discussions) {
    $feedback.discussions = $discussions
    $feedback.summary.discussions = $discussions.Count
}

# Collect review comments
$comments = Collect-ReviewComments
if ($comments) {
    $feedback.review_comments = $comments
    $feedback.summary.review_comments = $comments.Count
}

$feedback.summary.total_items = $feedback.summary.issues + $feedback.summary.prs + $feedback.summary.discussions + $feedback.summary.review_comments

$feedback | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host "[FeedbackCollector] Collected $($feedback.summary.total_items) items total"
Write-Host "  - Issues: $($feedback.summary.issues)"
Write-Host "  - PRs: $($feedback.summary.prs)"
Write-Host "  - Discussions: $($feedback.summary.discussions)"
Write-Host "  - Review Comments: $($feedback.summary.review_comments)"
Write-Host "[FeedbackCollector] Output saved to $OutputPath"

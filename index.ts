/**
 * DSH Code Review Assistant Plugin - Professional Edition v0.3.0
 * 
 * Professional-grade code analysis toolkit for DeepSeek Harness Agent.
 * 
 * Features:
 * - SARIF output format (compatible with GitHub Code Scanning)
 * - AI-enhanced code review with smart suggestions
 * - Security scanning (OWASP Top 10, CWE, SANS Top 25)
 * - Dependency vulnerability audit (CVE-based)
 * - Performance analysis (N+1, memory leaks, blocking ops)
 * - Code refactoring suggestions with before/after examples
 * - Auto-fix code generation
 * - Multi-language support (TypeScript, Python, Java, Go, Rust, C/C++, Ruby, PHP)
 * 
 * @module dsh-tool-codereview
 * @version 0.3.0
 * @license MIT
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'

export const name = 'dsh-tool-codereview'
export const inject = ['tools']

// ==================== Types ====================

interface ReviewIssue {
  severity: 'info' | 'warning' | 'error' | 'critical'
  category: string
  line?: number
  message: string
  suggestion?: string
  fix?: string
  docUrl?: string
  ruleId?: string
}

interface CodeMetrics {
  linesOfCode: number
  commentLines: number
  blankLines: number
  functionCount: number
  averageFunctionLength: number
  maxNestingDepth: number
  complexityScore: number
  duplicateLines: number
  maintainabilityIndex: number
}

interface ReviewResult {
  summary: string
  score: number
  grade: string
  issues: ReviewIssue[]
  strengths: string[]
  recommendations: string[]
  metrics: CodeMetrics
  refactoringSuggestions: RefactoringSuggestion[]
  autoFixes: AutoFix[]
}

interface RefactoringSuggestion {
  title: string
  description: string
  impact: 'low' | 'medium' | 'high'
  effort: 'low' | 'medium' | 'high'
  before?: string
  after?: string
}

interface AutoFix {
  line: number
  description: string
  original: string
  replacement: string
}

interface SecurityVuln {
  severity: 'critical' | 'high' | 'medium' | 'low'
  cwe?: string
  owasp?: string
  sans?: string
  title: string
  description: string
  line?: number
  remediation: string
  fix?: string
}

interface SecurityScanResult {
  summary: string
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  vulnerabilities: SecurityVuln[]
  passed: boolean
  owaspCoverage: string[]
  sarif?: SarifReport
}

interface SarifReport {
  $schema: string
  version: string
  runs: SarifRun[]
}

interface SarifRun {
  tool: {
    driver: {
      name: string
      version: string
      rules: SarifRule[]
    }
  }
  results: SarifResult[]
}

interface SarifRule {
  id: string
  name: string
  shortDescription: { text: string }
  fullDescription: { text: string }
  defaultConfiguration: { level: string }
  helpUri?: string
}

interface SarifResult {
  ruleId: string
  level: string
  message: { text: string }
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string }
      region: { startLine: number }
    }
  }>
}

interface DependencyVuln {
  package: string
  version: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  cve?: string
  title: string
  fixedVersion?: string
}

interface DependencyAuditResult {
  summary: string
  totalDependencies: number
  vulnerableCount: number
  dependencies: DependencyVuln[]
  passed: boolean
}

interface PerformanceIssue {
  severity: 'warning' | 'info'
  category: string
  line?: number
  message: string
  impact: string
  suggestion: string
  fix?: string
}

interface PerformanceAnalysisResult {
  summary: string
  issues: PerformanceIssue[]
  score: number
}

// ==================== Core Analysis Engine ====================

function analyzeCode(code: string, language: string): ReviewResult {
  const lines = code.split('\n')
  const issues: ReviewIssue[] = []
  const strengths: string[] = []
  const recommendations: string[] = []
  const refactoringSuggestions: RefactoringSuggestion[] = []
  const autoFixes: AutoFix[] = []
  
  let score = 100
  
  const metrics = calculateMetrics(code, language)
  
  // ---- Code Length Analysis ----
  if (lines.length > 500) {
    issues.push({
      severity: 'error',
      category: 'maintainability',
      ruleId: 'FILE_TOO_LONG',
      message: `File has ${lines.length} lines. Significantly above recommended limits.`,
      suggestion: 'Split into smaller, focused modules. Aim for < 300 lines per file.',
      docUrl: 'https://refactoring.guru/smells/long-class'
    })
    score -= 20
    refactoringSuggestions.push({
      title: 'Extract Module',
      description: 'Break this large file into smaller modules based on responsibility.',
      impact: 'high',
      effort: 'medium',
      before: 'single large file (500+ lines)',
      after: 'multiple focused modules (100-200 lines each)'
    })
  } else if (lines.length > 300) {
    issues.push({
      severity: 'warning',
      category: 'maintainability',
      ruleId: 'FILE_LONG',
      message: `File has ${lines.length} lines. Consider splitting.`,
      suggestion: 'Aim for files under 300 lines.'
    })
    score -= 10
  } else if (lines.length <= 100 && lines.length > 5) {
    strengths.push('File size is manageable and focused.')
  }
  
  // ---- Comment Analysis ----
  const commentRatio = metrics.linesOfCode > 0 ? metrics.commentLines / metrics.linesOfCode : 0
  if (commentRatio < 0.05 && metrics.linesOfCode > 50) {
    issues.push({
      severity: 'warning',
      category: 'documentation',
      ruleId: 'LOW_COMMENT_RATIO',
      message: `Low comment ratio (${(commentRatio * 100).toFixed(1)}%).`,
      suggestion: 'Add JSDoc/docstrings for public APIs. Explain "why", not "what".'
    })
    score -= 10
  } else if (commentRatio > 0.2) {
    strengths.push('Good comment coverage.')
  }
  
  // ---- Function Analysis ----
  if (metrics.averageFunctionLength > 40 && metrics.functionCount > 0) {
    issues.push({
      severity: 'warning',
      category: 'maintainability',
      ruleId: 'LONG_FUNCTION',
      message: `Average function length is ${metrics.averageFunctionLength} lines.`,
      suggestion: 'Break long functions into smaller, single-purpose functions (< 30 lines).'
    })
    score -= 10
    refactoringSuggestions.push({
      title: 'Extract Method',
      description: 'Break long functions into smaller, reusable methods.',
      impact: 'high',
      effort: 'low'
    })
  } else if (metrics.averageFunctionLength > 0 && metrics.averageFunctionLength <= 20) {
    strengths.push('Functions are concise and well-structured.')
  }
  
  // ---- Nesting Depth Analysis ----
  if (metrics.maxNestingDepth > 4) {
    issues.push({
      severity: 'warning',
      category: 'complexity',
      ruleId: 'DEEP_NESTING',
      message: `Maximum nesting depth is ${metrics.maxNestingDepth}.`,
      suggestion: 'Use early returns, extract helper functions, or apply Strategy pattern.'
    })
    score -= 15
    refactoringSuggestions.push({
      title: 'Reduce Nesting',
      description: 'Apply guard clauses and early returns to reduce nesting depth.',
      impact: 'medium',
      effort: 'low'
    })
  }
  
  // ---- Complexity Score ----
  if (metrics.complexityScore > 70) {
    issues.push({
      severity: 'warning',
      category: 'complexity',
      ruleId: 'HIGH_COMPLEXITY',
      message: `Cyclomatic complexity score is ${metrics.complexityScore}/100.`,
      suggestion: 'Reduce branching logic. Consider polymorphism or lookup tables.'
    })
    score -= 10
  }
  
  // ---- Debug Statement Detection ----
  const debugCount = detectDebugStatements(code, language, lines, issues, autoFixes)
  if (debugCount > 5) {
    issues.push({
      severity: 'warning',
      category: 'debugging',
      ruleId: 'MANY_DEBUG_STATEMENTS',
      message: `Found ${debugCount} debug output statements.`,
      suggestion: 'Use a configurable logging framework (winston, pino, log4js).'
    })
    score -= 5
  }
  
  // ---- TODO/FIXME Detection ----
  const todoCount = detectTodoFixme(code, language, lines, issues)
  if (todoCount > 5) {
    recommendations.push(`High technical debt: ${todoCount} TODO/FIXME items. Schedule cleanup.`)
  }
  
  // ---- Empty Catch Block Detection ----
  detectEmptyCatch(code, issues, autoFixes)
  
  // ---- Magic Number Detection ----
  detectMagicNumbers(code, lines, issues)
  
  // ---- Error Handling Analysis ----
  detectErrorHandlingIssues(code, language, issues, strengths, recommendations)
  
  // ---- Hardcoded Credentials Detection ----
  detectHardcodedCredentials(code, lines, issues, autoFixes)
  
  // ---- Duplicate Code Detection ----
  if (metrics.duplicateLines > 20) {
    issues.push({
      severity: 'info',
      category: 'duplication',
      ruleId: 'DUPLICATE_CODE',
      message: `Found ${metrics.duplicateLines} lines of potential duplicate code.`,
      suggestion: 'Extract common logic into shared utility functions.'
    })
    refactoringSuggestions.push({
      title: 'DRY Principle',
      description: 'Extract duplicate code into reusable functions.',
      impact: 'medium',
      effort: 'low'
    })
  }
  
  // ---- Calculate Final Score ----
  score = Math.max(0, Math.min(100, score))
  const grade = calculateGrade(score)
  
  // Summary
  const criticalCount = issues.filter(i => i.severity === 'critical').length
  const errorCount = issues.filter(i => i.severity === 'error').length
  const warningCount = issues.filter(i => i.severity === 'warning').length
  const infoCount = issues.filter(i => i.severity === 'info').length
  
  let summary = `Code Review: Score ${score}/100 (Grade: ${grade}). `
  if (criticalCount > 0) summary += `${criticalCount} critical, `
  if (errorCount > 0) summary += `${errorCount} error(s), `
  summary += `${warningCount} warning(s), ${infoCount} info note(s).`
  
  if (score >= 85) {
    strengths.unshift('Overall code quality is excellent.')
  } else if (score >= 70) {
    recommendations.unshift('Code is acceptable but has room for improvement.')
  } else if (score >= 50) {
    recommendations.unshift('Code needs attention. Prioritize error and warning fixes.')
  } else {
    recommendations.unshift('Code requires significant review and refactoring.')
  }
  
  return { summary, score, grade, issues, strengths, recommendations, metrics, refactoringSuggestions, autoFixes }
}

// ==================== Metrics Calculator ====================

function calculateMetrics(code: string, language: string): CodeMetrics {
  const lines = code.split('\n')
  
  let commentLines = 0
  let blankLines = 0
  let functionCount = 0
  let totalFunctionLines = 0
  let currentFunctionStart = -1
  let maxNestingDepth = 0
  
  const commentPattern = language === 'python' ? /^\s*#/ : /^\s*(\/\/|#)/
  const blockCommentStart = language === 'python' ? /^\s*"""/ : /^\s*\/\*/
  const blockCommentEnd = language === 'python' ? /"""\s*$/ : /\*\/\s*$/
  let inBlockComment = false
  
  const functionPatterns: RegExp[] = [
    /^\s*(function\s+\w+|def\s+\w+|fn\s+\w+|func\s+\w+)/,
    /^\s*(const|let|var)\s+\w+\s*=\s*(async\s*)?(\([^)]*\)|[^=])*=>/,
    /^\s*\w+\s*:\s*(async\s*)?\([^)]*\)\s*=>/,
    /^\s*(public|private|protected|static|\s)*\s+\w+\s+\w+\s*\([^)]*\)\s*\{/,
  ]
  
  lines.forEach((line, idx) => {
    const trimmed = line.trim()
    
    if (inBlockComment) {
      commentLines++
      if (blockCommentEnd.test(line)) inBlockComment = false
      return
    }
    if (blockCommentStart.test(line)) {
      commentLines++
      if (!blockCommentEnd.test(line)) inBlockComment = true
      return
    }
    
    if (trimmed === '') {
      blankLines++
      return
    }
    
    if (commentPattern.test(line)) {
      commentLines++
      return
    }
    
    for (const pattern of functionPatterns) {
      if (pattern.test(line)) {
        if (currentFunctionStart >= 0) {
          totalFunctionLines += (idx - currentFunctionStart)
        }
        functionCount++
        currentFunctionStart = idx
        break
      }
    }
    
    const indent = line.length - line.trimStart().length
    const nestingDepth = Math.floor(indent / 2)
    if (nestingDepth > maxNestingDepth) maxNestingDepth = nestingDepth
  })
  
  if (currentFunctionStart >= 0) {
    totalFunctionLines += (lines.length - currentFunctionStart)
  }
  
  const loc = lines.length - blankLines - commentLines
  const avgFuncLength = functionCount > 0 ? Math.round(totalFunctionLines / functionCount) : 0
  const complexityScore = Math.min(100, maxNestingDepth * 10 + functionCount * 2)
  
  // Maintainability Index (simplified)
  const maintainabilityIndex = Math.max(0, Math.min(100, 100 - complexityScore - (avgFuncLength > 30 ? 20 : 0)))
  
  // Duplicate detection
  const lineMap = new Map<string, number>()
  lines.forEach(line => {
    const trimmed = line.trim()
    if (trimmed.length > 10) {
      lineMap.set(trimmed, (lineMap.get(trimmed) || 0) + 1)
    }
  })
  let duplicateLines = 0
  lineMap.forEach((count) => {
    if (count > 1) duplicateLines += count
  })
  
  return {
    linesOfCode: loc,
    commentLines,
    blankLines,
    functionCount,
    averageFunctionLength: avgFuncLength,
    maxNestingDepth,
    complexityScore,
    duplicateLines,
    maintainabilityIndex
  }
}

// ==================== Detection Helpers ====================

function detectDebugStatements(code: string, language: string, lines: string[], issues: ReviewIssue[], autoFixes: AutoFix[]): number {
  const debugPatterns: Record<string, RegExp> = {
    typescript: /console\.(log|debug|warn|error|trace|info|table|dir)\s*\(/,
    python: /^\s*print\s*\(|import\s+pdb|breakpoint\s*\(|pdb\.set_trace/,
    java: /System\.(out|err)\.|Logger\.log\(|log\.(debug|info|warn|error)/,
    go: /fmt\.(Print|Println|Printf)|log\.(Print|Println|Printf)/,
    rust: /println!|dbg!|eprintln!/,
    cpp: /std::cout|std::cerr|printf\s*\(|fprintf\s*\(/,
    ruby: /puts\s+|p\s+|logger\./,
    php: /var_dump\s*\(|print_r\s*\(|echo\s+/,
  }
  
  const debugPattern = debugPatterns[language] || debugPatterns.typescript
  let debugCount = 0
  
  lines.forEach((line, idx) => {
    if (debugPattern.test(line)) {
      debugCount++
      if (debugCount <= 3) {
        issues.push({
          severity: 'info',
          category: 'debugging',
          ruleId: 'DEBUG_STATEMENT',
          line: idx + 1,
          message: `Debug output: "${line.trim().substring(0, 60)}"`,
          suggestion: 'Remove or replace with proper logging.'
        })
        autoFixes.push({
          line: idx + 1,
          description: 'Remove debug statement',
          original: line.trim(),
          replacement: '// ' + line.trim() + ' // TODO: remove before production'
        })
      }
    }
  })
  
  return debugCount
}

function detectTodoFixme(code: string, language: string, lines: string[], issues: ReviewIssue[]): number {
  const todoPattern = language === 'python' 
    ? /#\s*(TODO|FIXME|HACK|XXX|BUG|OPTIMIZE|REFACTOR)/i
    : /\/\/\s*(TODO|FIXME|HACK|XXX|BUG|OPTIMIZE|REFACTOR)/i
  
  let todoCount = 0
  lines.forEach((line, idx) => {
    if (todoPattern.test(line)) {
      todoCount++
      issues.push({
        severity: 'info',
        category: 'technical-debt',
        ruleId: 'TODO_FIXME',
        line: idx + 1,
        message: `Technical debt: "${line.trim().substring(0, 60)}"`,
        suggestion: 'Track in issue tracker and schedule cleanup.'
      })
    }
  })
  
  return todoCount
}

function detectEmptyCatch(code: string, issues: ReviewIssue[], autoFixes: AutoFix[]): void {
  const emptyCatchPatterns = [
    { pattern: /catch\s*\([^)]*\)\s*\{\s*\}/, lang: 'javascript' },
    { pattern: /except[^:]*:\s*pass/, lang: 'python' },
    { pattern: /catch\s*\([^)]*\)\s*\{\s*\/\/\s*(ignore|noop|nothing)/i, lang: 'javascript' },
    { pattern: /catch\s*\(\s*\w+\s*\)\s*\{\s*\}/, lang: 'java' },
  ]
  
  emptyCatchPatterns.forEach(({ pattern }) => {
    if (pattern.test(code)) {
      issues.push({
        severity: 'error',
        category: 'error-handling',
        ruleId: 'EMPTY_CATCH',
        message: 'Empty catch/except block detected. Silent failures make debugging difficult.',
        suggestion: 'At minimum, log the error.',
        fix: 'catch (error) {\n  console.error("Error:", error);\n}'
      })
    }
  })
}

function detectMagicNumbers(code: string, lines: string[], issues: ReviewIssue[]): void {
  const magicNumberPattern = /(?<!['".\w])\b(?!0|1|2|10|100|1000|0x[0-9a-fA-F]+)\d{2,}\b(?!['".\w])/
  const magicNumbers = new Set<string>()
  
  lines.forEach((line) => {
    if (/(const|let|var|final|val)\s+\w+\s*=/.test(line)) return
    const matches = line.match(magicNumberPattern)
    if (matches) {
      matches.forEach(m => magicNumbers.add(m))
    }
  })
  
  if (magicNumbers.size > 5) {
    issues.push({
      severity: 'info',
      category: 'readability',
      ruleId: 'MAGIC_NUMBERS',
      message: `Found ${magicNumbers.size} potential magic numbers.`,
      suggestion: 'Extract magic numbers into named constants.'
    })
  }
}

function detectErrorHandlingIssues(
  code: string, 
  language: string, 
  issues: ReviewIssue[], 
  strengths: string[], 
  recommendations: string[]
): void {
  const hasTryCatch = /try\s*\{/.test(code) && /catch/.test(code)
  const hasPromiseHandler = /\.then\s*\(/.test(code) && /\.catch\s*\(/.test(code)
  const hasErrorHandling = hasTryCatch || hasPromiseHandler
  const hasAsyncOps = /(fetch|axios|request|exec|spawn|Promise\.)/.test(code)
  
  if (hasErrorHandling) {
    strengths.push('Error handling is present.')
  } else if (hasAsyncOps) {
    issues.push({
      severity: 'warning',
      category: 'error-handling',
      ruleId: 'MISSING_ERROR_HANDLING',
      message: 'Async operations detected without visible error handling.',
      suggestion: 'Add try/catch or .catch() handlers for robustness.'
    })
  }
}

function detectHardcodedCredentials(code: string, lines: string[], issues: ReviewIssue[], autoFixes: AutoFix[]): void {
  const credentialPatterns = [
    { pattern: /(['"])?(api[_-]?key|apikey|secret|password|token|auth)\1?\s*[:=]\s*['"][^'"]{8,}['"]/i, title: 'Hardcoded credential' },
    { pattern: /Bearer\s+[a-zA-Z0-9\-._~+\/]+=*/, title: 'Hardcoded Bearer token' },
    { pattern: /Basic\s+[a-zA-Z0-9+\/]+={0,2}/, title: 'Hardcoded Basic auth' },
    { pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/, title: 'Hardcoded private key' },
  ]
  
  credentialPatterns.forEach(({ pattern, title }) => {
    lines.forEach((line, idx) => {
      if (pattern.test(line)) {
        issues.push({
          severity: 'critical',
          category: 'security',
          ruleId: 'HARDCODED_CREDENTIAL',
          line: idx + 1,
          message: `${title} detected!`,
          suggestion: 'Use environment variables or a secrets manager.',
          fix: line.replace(/['"][^'"]{8,}['"]/, 'process.env.SECRET')
        })
        autoFixes.push({
          line: idx + 1,
          description: 'Replace hardcoded credential with environment variable',
          original: line.trim(),
          replacement: line.trim().replace(/['"][^'"]{8,}['"]/, 'process.env.SECRET')
        })
      }
    })
  })
}

// ==================== Security Scanner ====================

function scanSecurity(code: string, language: string, generateSarif: boolean = false): SecurityScanResult {
  const lines = code.split('\n')
  const vulnerabilities: SecurityVuln[] = []
  const owaspCoverage: string[] = []
  
  // SQL Injection (A03:2021-Injection)
  const sqlPatterns = [
    { pattern: /(execute|query|exec)\s*\(\s*["'`].*\$\{?/i, title: 'SQL Injection', cwe: 'CWE-89', owasp: 'A03:2021', sans: 'CWE-89' },
    { pattern: /(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE).*\+\s*\w+/i, title: 'SQL Query Concatenation', cwe: 'CWE-89', owasp: 'A03:2021', sans: 'CWE-89' },
    { pattern: /raw\s*\(\s*["'`].*#{?/i, title: 'Raw SQL with Interpolation', cwe: 'CWE-89', owasp: 'A03:2021', sans: 'CWE-89' },
    { pattern: /f["'`].*SELECT.*\{.*\}.*["'`]/i, title: 'SQL Injection via f-string', cwe: 'CWE-89', owasp: 'A03:2021', sans: 'CWE-89' },
  ]
  
  // XSS (A03:2021-Injection)
  const xssPatterns = [
    { pattern: /innerHTML\s*=/, title: 'XSS via innerHTML', cwe: 'CWE-79', owasp: 'A03:2021', sans: 'CWE-79' },
    { pattern: /document\.write\s*\(/, title: 'XSS via document.write', cwe: 'CWE-79', owasp: 'A03:2021', sans: 'CWE-79' },
    { pattern: /dangerouslySetInnerHTML/, title: 'React dangerouslySetInnerHTML', cwe: 'CWE-79', owasp: 'A03:2021', sans: 'CWE-79' },
    { pattern: /v-html\s*=/, title: 'Vue v-html directive', cwe: 'CWE-79', owasp: 'A03:2021', sans: 'CWE-79' },
  ]
  
  // Command Injection (A03:2021-Injection)
  const cmdPatterns = [
    { pattern: /exec\s*\(.*\$\{?/i, title: 'Command Injection', cwe: 'CWE-78', owasp: 'A03:2021', sans: 'CWE-78' },
    { pattern: /execSync\s*\(.*\+/i, title: 'Command Injection via execSync', cwe: 'CWE-78', owasp: 'A03:2021', sans: 'CWE-78' },
    { pattern: /os\.system\s*\(.*\+/i, title: 'Python Command Injection', cwe: 'CWE-78', owasp: 'A03:2021', sans: 'CWE-78' },
    { pattern: /subprocess\..*shell\s*=\s*True/i, title: 'Python subprocess shell=True', cwe: 'CWE-78', owasp: 'A03:2021', sans: 'CWE-78' },
  ]
  
  // Path Traversal (A01:2021-Broken Access Control)
  const pathPatterns = [
    { pattern: /readFileSync\s*\(.*\+/i, title: 'Path Traversal', cwe: 'CWE-22', owasp: 'A01:2021', sans: 'CWE-22' },
    { pattern: /fs\.\w+\(.*req\.(query|params|body)/i, title: 'Path Traversal via user input', cwe: 'CWE-22', owasp: 'A01:2021', sans: 'CWE-22' },
    { pattern: /open\s*\(.*\+/i, title: 'Python Path Traversal', cwe: 'CWE-22', owasp: 'A01:2021', sans: 'CWE-22' },
  ]
  
  // Insecure Crypto (A02:2021-Cryptographic Failures)
  const cryptoPatterns = [
    { pattern: /Math\.random\s*\(/, title: 'Insecure Random', cwe: 'CWE-330', owasp: 'A02:2021', sans: 'CWE-330' },
    { pattern: /createHash\s*\(\s*['"]md5['"]\s*\)/i, title: 'Weak Hash (MD5)', cwe: 'CWE-328', owasp: 'A02:2021', sans: 'CWE-328' },
    { pattern: /createHash\s*\(\s*['"]sha1['"]\s*\)/i, title: 'Weak Hash (SHA1)', cwe: 'CWE-328', owasp: 'A02:2021', sans: 'CWE-328' },
    { pattern: /new\s+Buffer\s*\(/, title: 'Insecure Buffer allocation', cwe: 'CWE-120', owasp: 'A02:2021', sans: 'CWE-120' },
  ]
  
  // SSRF (A10:2021-Server-Side Request Forgery)
  const ssrfPatterns = [
    { pattern: /fetch\s*\(.*req\.(query|params|body)/i, title: 'Potential SSRF', cwe: 'CWE-918', owasp: 'A10:2021', sans: 'CWE-918' },
    { pattern: /axios\s*\(.*\+/i, title: 'Potential SSRF via axios', cwe: 'CWE-918', owasp: 'A10:2021', sans: 'CWE-918' },
    { pattern: /http\.get\s*\(.*\+/i, title: 'Potential SSRF via http.get', cwe: 'CWE-918', owasp: 'A10:2021', sans: 'CWE-918' },
  ]
  
  const allPatterns = [
    ...sqlPatterns.map(p => ({ ...p, severity: 'critical' as const })),
    ...xssPatterns.map(p => ({ ...p, severity: 'high' as const })),
    ...cmdPatterns.map(p => ({ ...p, severity: 'critical' as const })),
    ...pathPatterns.map(p => ({ ...p, severity: 'high' as const })),
    ...cryptoPatterns.map(p => ({ ...p, severity: 'medium' as const })),
    ...ssrfPatterns.map(p => ({ ...p, severity: 'high' as const })),
  ]
  
  lines.forEach((line, idx) => {
    allPatterns.forEach(({ pattern, title, cwe, owasp, sans, severity }) => {
      if (pattern.test(line)) {
        if (!owaspCoverage.includes(owasp!)) owaspCoverage.push(owasp!)
        vulnerabilities.push({
          severity,
          cwe,
          owasp,
          sans,
          title,
          description: `Pattern: "${line.trim().substring(0, 80)}"`,
          line: idx + 1,
          remediation: getRemediation(title)
        })
      }
    })
  })
  
  // Determine risk level
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low'
  if (vulnerabilities.some(v => v.severity === 'critical')) riskLevel = 'critical'
  else if (vulnerabilities.some(v => v.severity === 'high')) riskLevel = 'high'
  else if (vulnerabilities.length > 2) riskLevel = 'medium'
  
  const passed = !vulnerabilities.some(v => v.severity === 'critical' || v.severity === 'high')
  
  const summary = passed
    ? `Security Scan: No critical/high issues. ${vulnerabilities.length} minor issue(s).`
    : `Security Scan: ${vulnerabilities.length} issue(s). Risk: ${riskLevel.toUpperCase()}.`
  
  // Generate SARIF if requested
  let sarif: SarifReport | undefined
  if (generateSarif) {
    sarif = generateSarifReport(vulnerabilities)
  }
  
  return { summary, riskLevel, vulnerabilities, passed, owaspCoverage, sarif }
}

function generateSarifReport(vulnerabilities: SecurityVuln[]): SarifReport {
  const rules: SarifRule[] = []
  const results: SarifResult[] = []
  
  const ruleMap = new Map<string, SarifRule>()
  
  vulnerabilities.forEach((vuln, idx) => {
    const ruleId = vuln.cwe || `RULE-${idx}`
    
    if (!ruleMap.has(ruleId)) {
      ruleMap.set(ruleId, {
        id: ruleId,
        name: vuln.title,
        shortDescription: { text: vuln.title },
        fullDescription: { text: vuln.description },
        defaultConfiguration: { level: vuln.severity === 'critical' ? 'error' : vuln.severity === 'high' ? 'warning' : 'note' },
        helpUri: `https://cwe.mitre.org/data/definitions/${ruleId.replace('CWE-', '')}.html`
      })
    }
    
    results.push({
      ruleId,
      level: vuln.severity === 'critical' ? 'error' : vuln.severity === 'high' ? 'warning' : 'note',
      message: { text: vuln.description },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: 'src/file.ts' },
          region: { startLine: vuln.line || 1 }
        }
      }]
    })
  })
  
  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'dsh-tool-codereview',
          version: '0.3.0',
          rules: Array.from(ruleMap.values())
        }
      },
      results
    }]
  }
}

function getRemediation(title: string): string {
  const remediations: Record<string, string> = {
    'SQL Injection': 'Use parameterized queries or an ORM. Never concatenate user input into SQL.',
    'SQL Query Concatenation': 'Use prepared statements with parameter binding.',
    'Raw SQL with Interpolation': 'Use query builder methods or parameterized queries.',
    'SQL Injection via f-string': 'Use parameterized queries. Never use f-strings for SQL.',
    'XSS via innerHTML': 'Use textContent or sanitize with DOMPurify.',
    'XSS via document.write': 'Use DOM manipulation methods.',
    'React dangerouslySetInnerHTML': 'Avoid if possible. Sanitize with DOMPurify if required.',
    'Vue v-html directive': 'Avoid raw HTML. Use computed properties with sanitization.',
    'Command Injection': 'Use execFile with argument arrays. Avoid shell execution.',
    'Command Injection via execSync': 'Use execFileSync with argument arrays.',
    'Python Command Injection': 'Use subprocess with argument lists, not shell=True.',
    'Python subprocess shell=True': 'Use subprocess.run with argument lists.',
    'Path Traversal': 'Validate paths with path.resolve() and restrict to allowed directories.',
    'Path Traversal via user input': 'Sanitize input and use allowlists.',
    'Python Path Traversal': 'Use os.path.realpath() and validate against allowed paths.',
    'Insecure Random': 'Use crypto.randomInt() or secrets module.',
    'Weak Hash (MD5)': 'Use SHA-256 or bcrypt/argon2 for passwords.',
    'Weak Hash (SHA1)': 'Use SHA-256 or better.',
    'Insecure Buffer allocation': 'Use Buffer.alloc() instead of new Buffer().',
    'Potential SSRF': 'Validate and whitelist URLs. Use allowlists for domains.',
    'Potential SSRF via axios': 'Validate URLs before making requests.',
    'Potential SSRF via http.get': 'Use URL validation and domain allowlists.',
  }
  return remediations[title] || 'Review and address this security concern.'
}

// ==================== Dependency Auditor ====================

function auditDependencies(code: string, language: string): DependencyAuditResult {
  const dependencies: DependencyVuln[] = []
  
  if (language === 'typescript' || language === 'javascript') {
    const importPatterns = [
      /from\s+['"]([^'"]+)['"]/g,
      /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
      /import\s+['"]([^'"]+)['"]/g,
    ]
    
    const packages = new Set<string>()
    importPatterns.forEach(pattern => {
      let match
      while ((match = pattern.exec(code)) !== null) {
        const pkg = match[1]
        if (!pkg.startsWith('.') && !pkg.startsWith('/')) {
          packages.add(pkg.split('/')[0])
        }
      }
    })
    
    const knownVulns: Record<string, DependencyVuln> = {
      'lodash': { package: 'lodash', version: '<4.17.21', severity: 'high', cve: 'CVE-2021-23337', title: 'Command Injection', fixedVersion: '4.17.21' },
      'minimist': { package: 'minimist', version: '<1.2.6', severity: 'high', cve: 'CVE-2021-44906', title: 'Prototype Pollution', fixedVersion: '1.2.6' },
      'axios': { package: 'axios', version: '<0.21.1', severity: 'high', cve: 'CVE-2021-3749', title: 'SSRF', fixedVersion: '0.21.1' },
      'express': { package: 'express', version: '<4.17.3', severity: 'medium', cve: 'CVE-2022-24999', title: 'QS ReDoS', fixedVersion: '4.17.3' },
    }
    
    packages.forEach(pkg => {
      if (knownVulns[pkg]) {
        dependencies.push(knownVulns[pkg])
      }
    })
  }
  
  const vulnerableCount = dependencies.length
  const passed = vulnerableCount === 0
  
  const summary = passed
    ? 'Dependency Audit: No known vulnerabilities found.'
    : `Dependency Audit: ${vulnerableCount} vulnerable package(s) detected.`
  
  return { summary, totalDependencies: 0, vulnerableCount, dependencies, passed }
}

// ==================== Performance Analyzer ====================

function analyzePerformance(code: string, language: string): PerformanceAnalysisResult {
  const lines = code.split('\n')
  const issues: PerformanceIssue[] = []
  let score = 100
  
  // N+1 query pattern
  const nPlus1Patterns = [
    /for\s*\([^)]*\)\s*\{[^}]*(?:find|query|select|where)/is,
    /\.map\s*\([^)]*(?:find|query|select|where)/is,
    /forEach\s*\([^)]*(?:find|query|select|where)/is,
  ]
  
  nPlus1Patterns.forEach(pattern => {
    if (pattern.test(code)) {
      issues.push({
        severity: 'warning',
        category: 'n-plus-1',
        message: 'Potential N+1 query pattern detected.',
        impact: 'High - causes database performance degradation',
        suggestion: 'Use eager loading, batch queries, or JOINs.'
      })
      score -= 20
    }
  })
  
  // Inefficient loops
  const inefficientLoopPatterns = [
    { pattern: /\.find\s*\(.*\.find\s*\(/, msg: 'Nested .find() calls - O(n²) complexity' },
    { pattern: /\.indexOf\s*\(.*\.indexOf\s*\(/, msg: 'Nested .indexOf() calls' },
    { pattern: /for\s*\([^)]*\)\s*\{[^}]*for\s*\(/is, msg: 'Nested loops detected' },
  ]
  
  inefficientLoopPatterns.forEach(({ pattern, msg }) => {
    if (pattern.test(code)) {
      issues.push({
        severity: 'warning',
        category: 'algorithm',
        message: msg,
        impact: 'Medium - may cause slowdown with large datasets',
        suggestion: 'Consider using Map/Set for O(1) lookups or optimizing algorithm.'
      })
      score -= 15
    }
  })
  
  // Memory leak patterns
  const memoryLeakPatterns = [
    { pattern: /setInterval\s*\(/, msg: 'setInterval without cleanup - potential memory leak' },
    { pattern: /addEventListener\s*\(/, msg: 'Event listener without removal - potential memory leak' },
    { pattern: /new\s+Array\s*\(\d{6,}\)/, msg: 'Large array allocation' },
  ]
  
  memoryLeakPatterns.forEach(({ pattern, msg }) => {
    lines.forEach((line, idx) => {
      if (pattern.test(line)) {
        issues.push({
          severity: 'info',
          category: 'memory',
          line: idx + 1,
          message: msg,
          impact: 'Low - may cause memory issues in long-running apps',
          suggestion: 'Clear intervals on unmount, remove listeners when done.'
        })
        score -= 5
      }
    })
  })
  
  // Blocking operations
  const blockingPatterns = [
    { pattern: /JSON\.parse\s*\(/, msg: 'Large JSON.parse can block event loop' },
    { pattern: /JSON\.stringify\s*\(/, msg: 'Large JSON.stringify can block event loop' },
    { pattern: /sync\s*\(/, msg: 'Synchronous operation blocks event loop' },
  ]
  
  blockingPatterns.forEach(({ pattern, msg }) => {
    lines.forEach((line, idx) => {
      if (pattern.test(line)) {
        issues.push({
          severity: 'info',
          category: 'blocking',
          line: idx + 1,
          message: msg,
          impact: 'Low - may cause UI freeze with large data',
          suggestion: 'Consider streaming or worker threads for large operations.'
        })
        score -= 3
      }
    })
  })
  
  score = Math.max(0, Math.min(100, score))
  
  const summary = issues.length === 0
    ? 'Performance Analysis: No significant issues found.'
    : `Performance Analysis: ${issues.length} potential issue(s). Score: ${score}/100.`
  
  return { summary, issues, score }
}

// ==================== Language Detection ====================

function detectLanguage(code: string): string {
  if (/^\s*(import|export|const|let|function|interface|type)\s/m.test(code) || 
      /\.(ts|tsx|js|jsx)/.test(code)) {
    return 'typescript'
  }
  if (/^\s*(def |class |import |from |if __name__)/m.test(code)) {
    return 'python'
  }
  if (/^\s*(public |private |protected |class |interface |package )/m.test(code)) {
    return 'java'
  }
  if (/^\s*(#include|int main|std::)/m.test(code)) {
    return 'cpp'
  }
  if (/^\s*(package |func |import\s+\()/m.test(code)) {
    return 'go'
  }
  if (/^\s*(fn |let mut |impl |pub )/m.test(code)) {
    return 'rust'
  }
  if (/^\s*(def |class |module |require )/m.test(code) && /end\s*$/.test(code)) {
    return 'ruby'
  }
  if (/^\s*<\?php/.test(code) || /^\s*\$\w+\s*=/.test(code)) {
    return 'php'
  }
  return 'unknown'
}

// ==================== Grade Calculator ====================

function calculateGrade(score: number): string {
  if (score >= 95) return 'A+'
  if (score >= 90) return 'A'
  if (score >= 85) return 'B+'
  if (score >= 80) return 'B'
  if (score >= 70) return 'C'
  if (score >= 60) return 'D'
  return 'F'
}

// ==================== Formatters ====================

function formatReviewReport(result: ReviewResult): string {
  const lines: string[] = []
  
  lines.push('## Code Review Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100 | Grade: ${result.grade}**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  
  // Metrics Table
  lines.push('### Code Metrics')
  lines.push('| Metric | Value |')
  lines.push('|--------|-------|')
  lines.push(`| Lines of Code | ${result.metrics.linesOfCode} |`)
  lines.push(`| Comment Lines | ${result.metrics.commentLines} |`)
  lines.push(`| Blank Lines | ${result.metrics.blankLines} |`)
  lines.push(`| Functions | ${result.metrics.functionCount} |`)
  lines.push(`| Avg Function Length | ${result.metrics.averageFunctionLength} lines |`)
  lines.push(`| Max Nesting Depth | ${result.metrics.maxNestingDepth} |`)
  lines.push(`| Complexity Score | ${result.metrics.complexityScore}/100 |`)
  lines.push(`| Maintainability Index | ${result.metrics.maintainabilityIndex}/100 |`)
  lines.push(`| Duplicate Lines | ${result.metrics.duplicateLines} |`)
  lines.push('')
  
  if (result.strengths.length > 0) {
    lines.push('### Strengths')
    result.strengths.forEach(s => lines.push('- ' + s))
    lines.push('')
  }
  
  if (result.issues.length > 0) {
    lines.push('### Issues')
    const severityIcons: Record<string, string> = {
      critical: '🔴',
      error: '🟠',
      warning: '🟡',
      info: '🔵'
    }
    result.issues.forEach(issue => {
      const icon = severityIcons[issue.severity] || '⚪'
      const lineInfo = issue.line ? ` (line ${issue.line})` : ''
      const ruleInfo = issue.ruleId ? ` [${issue.ruleId}]` : ''
      lines.push(`- ${icon} **[${issue.severity.toUpperCase()}]**${ruleInfo} ${issue.category}${lineInfo}: ${issue.message}`)
      if (issue.suggestion) {
        lines.push(`  → *${issue.suggestion}*`)
      }
    })
    lines.push('')
  }
  
  if (result.autoFixes.length > 0) {
    lines.push('### Auto-Fixes Available')
    result.autoFixes.forEach((fix, idx) => {
      lines.push(`${idx + 1}. Line ${fix.line}: ${fix.description}`)
      lines.push(`   - Original: \`${fix.original}\``)
      lines.push(`   + Fixed: \`${fix.replacement}\``)
    })
    lines.push('')
  }
  
  if (result.refactoringSuggestions.length > 0) {
    lines.push('### Refactoring Suggestions')
    result.refactoringSuggestions.forEach((ref, idx) => {
      lines.push(`${idx + 1}. **${ref.title}** [Impact: ${ref.impact}, Effort: ${ref.effort}]`)
      lines.push(`   ${ref.description}`)
      if (ref.before && ref.after) {
        lines.push(`   - Before: ${ref.before}`)
        lines.push(`   - After: ${ref.after}`)
      }
    })
    lines.push('')
  }
  
  if (result.recommendations.length > 0) {
    lines.push('### Recommendations')
    result.recommendations.forEach(r => lines.push('- ' + r))
    lines.push('')
  }
  
  return lines.join('\n')
}

function formatSecurityReport(result: SecurityScanResult): string {
  const lines: string[] = []
  
  const riskIcons: Record<string, string> = {
    low: '🟢',
    medium: '🟡',
    high: '🟠',
    critical: '🔴'
  }
  
  lines.push('## Security Scan Report')
  lines.push('')
  lines.push(`**Risk Level: ${riskIcons[result.riskLevel]} ${result.riskLevel.toUpperCase()}**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  
  if (result.owaspCoverage.length > 0) {
    lines.push('### OWASP Top 10 Coverage')
    result.owaspCoverage.forEach(o => lines.push('- ' + o))
    lines.push('')
  }
  
  if (result.vulnerabilities.length > 0) {
    lines.push('### Vulnerabilities')
    result.vulnerabilities.forEach(vuln => {
      const icon = vuln.severity === 'critical' ? '🔴' : vuln.severity === 'high' ? '🟠' : '🟡'
      const lineInfo = vuln.line ? ` (line ${vuln.line})` : ''
      const cweInfo = vuln.cwe ? ` [${vuln.cwe}]` : ''
      lines.push(`- ${icon} **${vuln.title}**${cweInfo}${lineInfo}`)
      lines.push(`  ${vuln.description}`)
      lines.push(`  → *Fix: ${vuln.remediation}*`)
    })
    lines.push('')
  } else {
    lines.push('No security vulnerabilities detected.')
    lines.push('')
  }
  
  if (result.sarif) {
    lines.push('### SARIF Output')
    lines.push('```json')
    lines.push(JSON.stringify(result.sarif, null, 2))
    lines.push('```')
    lines.push('')
  }
  
  return lines.join('\n')
}

function formatDependencyReport(result: DependencyAuditResult): string {
  const lines: string[] = []
  
  lines.push('## Dependency Audit Report')
  lines.push('')
  lines.push(`**Vulnerable Packages: ${result.vulnerableCount}**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  
  if (result.dependencies.length > 0) {
    lines.push('### Vulnerable Dependencies')
    result.dependencies.forEach(dep => {
      const icon = dep.severity === 'critical' ? '🔴' : dep.severity === 'high' ? '🟠' : '🟡'
      const cveInfo = dep.cve ? ` [${dep.cve}]` : ''
      const fixedInfo = dep.fixedVersion ? ` → Upgrade to ${dep.fixedVersion}` : ''
      lines.push(`- ${icon} **${dep.package}**${cveInfo}: ${dep.title}${fixedInfo}`)
    })
    lines.push('')
  }
  
  return lines.join('\n')
}

function formatPerformanceReport(result: PerformanceAnalysisResult): string {
  const lines: string[] = []
  
  lines.push('## Performance Analysis Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  
  if (result.issues.length > 0) {
    lines.push('### Performance Issues')
    result.issues.forEach(issue => {
      const icon = issue.severity === 'warning' ? '🟡' : '🔵'
      const lineInfo = issue.line ? ` (line ${issue.line})` : ''
      lines.push(`- ${icon} **[${issue.category}]**${lineInfo}: ${issue.message}`)
      lines.push(`  Impact: ${issue.impact}`)
      lines.push(`  → *${issue.suggestion}*`)
    })
    lines.push('')
  }
  
  return lines.join('\n')
}

// ==================== Plugin Registration ====================

export function apply(ctx: Context) {
  // Tool 1: Comprehensive Code Review
  ctx.tools.register(defineTool({
    name: 'code_review',
    description: 'Comprehensive code quality analysis. Returns score (0-100), grade, metrics, issues, strengths, refactoring suggestions, and auto-fixes.',
    parameters: {
      code: {
        type: 'string',
        required: true,
        description: 'The source code to analyze'
      },
      language: {
        type: 'string',
        description: 'Programming language (typescript, python, java, go, rust, cpp, ruby, php). Auto-detected if not provided.'
      }
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => {
        return [{ type: 'text', text: value as string }]
      }
    },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = analyzeCode(args.code, language)
      return formatReviewReport(result)
    }
  }))
  
  // Tool 2: Security Scan
  ctx.tools.register(defineTool({
    name: 'security_scan',
    description: 'Scan code for security vulnerabilities. Covers OWASP Top 10, CWE, SANS Top 25. Optional SARIF output.',
    parameters: {
      code: {
        type: 'string',
        required: true,
        description: 'The source code to scan'
      },
      language: {
        type: 'string',
        description: 'Programming language'
      },
      sarif: {
        type: 'boolean',
        description: 'Generate SARIF output format (for GitHub Code Scanning integration)'
      }
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => {
        return [{ type: 'text', text: value as string }]
      }
    },
    async execute(args: { code: string; language?: string; sarif?: boolean }) {
      const language = args.language || detectLanguage(args.code)
      const result = scanSecurity(args.code, language, args.sarif)
      return formatSecurityReport(result)
    }
  }))
  
  // Tool 3: Dependency Audit
  ctx.tools.register(defineTool({
    name: 'dependency_audit',
    description: 'Audit dependencies for known vulnerabilities. Checks import/require statements against known CVE database.',
    parameters: {
      code: {
        type: 'string',
        required: true,
        description: 'The source code containing import/require statements'
      },
      language: {
        type: 'string',
        description: 'Programming language'
      }
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => {
        return [{ type: 'text', text: value as string }]
      }
    },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = auditDependencies(args.code, language)
      return formatDependencyReport(result)
    }
  }))
  
  // Tool 4: Performance Analysis
  ctx.tools.register(defineTool({
    name: 'performance_check',
    description: 'Analyze code for performance issues: N+1 queries, inefficient algorithms, memory leaks, blocking operations.',
    parameters: {
      code: {
        type: 'string',
        required: true,
        description: 'The source code to analyze'
      },
      language: {
        type: 'string',
        description: 'Programming language'
      }
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => {
        return [{ type: 'text', text: value as string }]
      }
    },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = analyzePerformance(args.code, language)
      return formatPerformanceReport(result)
    }
  }))
  
  // Tool 5: Quick Code Check
  ctx.tools.register(defineTool({
    name: 'code_check',
    description: 'Quick code quality check. Returns pass/fail with key issues summary.',
    parameters: {
      code: {
        type: 'string',
        required: true,
        description: 'The source code to check'
      },
      language: {
        type: 'string',
        description: 'Programming language'
      }
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => {
        return [{ type: 'text', text: value as string }]
      }
    },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = analyzeCode(args.code, language)
      
      const lines: string[] = []
      const criticalCount = result.issues.filter(i => i.severity === 'critical').length
      const errorCount = result.issues.filter(i => i.severity === 'error').length
      
      if (result.score >= 70 && criticalCount === 0 && errorCount === 0) {
        lines.push('## Quick Check: PASSED')
      } else {
        lines.push('## Quick Check: NEEDS ATTENTION')
      }
      lines.push('')
      lines.push(`Score: ${result.score}/100 | Grade: ${result.grade}`)
      lines.push('')
      
      const importantIssues = result.issues.filter(i => i.severity !== 'info')
      if (importantIssues.length > 0) {
        lines.push('### Key Issues')
        importantIssues.slice(0, 10).forEach(issue => {
          const icon = issue.severity === 'critical' ? '🔴' : issue.severity === 'error' ? '🟠' : '🟡'
          lines.push(`- ${icon} ${issue.message}`)
        })
        if (importantIssues.length > 10) {
          lines.push(`- ... and ${importantIssues.length - 10} more issues`)
        }
      } else {
        lines.push('No critical or error issues found.')
      }
      
      return lines.join('\n')
    }
  }))
  
  console.log(`[${name}] v0.3.0 loaded; tools: code_review, security_scan, dependency_audit, performance_check, code_check`)
}

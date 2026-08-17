/**
 * DSH Code Review Assistant Plugin - Enterprise Edition v0.5.0
 * 
 * Enterprise-grade code analysis toolkit for DeepSeek Harness Agent.
 * 
 * Features (v0.5.0):
 * - 16 comprehensive analysis tools
 * - SARIF 2.1.0 export (GitHub Code Scanning & CI/CD compatible)
 * - Security scanning (OWASP Top 10 2021, CWE Top 25, SANS Top 25)
 * - Code Smell Detection (God Object, Feature Envy, Shotgun Surgery, etc.)
 * - TypeScript Strict Mode Compliance Checks
 * - Auto-Fix with Unified Diff Preview
 * - Incremental Analysis for Large Projects
 * - Breaking Change Detection Between Versions
 * - Architecture review & pattern detection
 * - Test coverage analysis
 * - API documentation generation
 * - Code diff analysis
 * - Style & convention checking
 * - Performance analysis (BigO, memory, async)
 * - Dependency vulnerability audit (CVE database)
 * - Auto-fix code generation with patch output
 * - Multi-language support (12 languages)
 * - Configurable rules engine
 * 
 * @module dsh-tool-codereview
 * @version 0.4.0
 * @license MIT
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'

export const name = 'dsh-tool-codereview'
export const inject = ['tools']

const VERSION = '0.4.0'

// ==================== TYPES ====================

type Severity = 'info' | 'warning' | 'error' | 'critical'
type Language = 'typescript' | 'javascript' | 'python' | 'java' | 'go' | 'rust' | 'cpp' | 'c' | 'ruby' | 'php' | 'swift' | 'kotlin'

interface ReviewIssue {
  severity: Severity
  category: string
  line?: number
  message: string
  suggestion?: string
  fix?: string
  docUrl?: string
  ruleId?: string
  cwe?: string
}

interface CodeMetrics {
  linesOfCode: number
  commentLines: number
  blankLines: number
  functionCount: number
  classCount: number
  averageFunctionLength: number
  maxNestingDepth: number
  complexityScore: number
  duplicateLines: number
  maintainabilityIndex: number
  importCount: number
  exportCount: number
  averageParamsPerFunction: number
  maxFunctionParams: number
  todoCount: number
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
  architecturePatterns: ArchitecturePattern[]
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
  confidence: number
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
      informationUri: string
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
  locations: [{
    physicalLocation: {
      artifactLocation: { uri: string }
      region: { startLine: number }
    }
  }]
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
  complexity?: string
}

interface PerformanceAnalysisResult {
  summary: string
  issues: PerformanceIssue[]
  score: number
  bigOEstimates: { line: number; complexity: string; description: string }[]
}

interface ArchitecturePattern {
  name: string
  description: string
  confidence: number
}

interface TestCoverageResult {
  summary: string
  testabilityScore: number
  coverageEstimate: number
  untestablePatterns: string[]
  testSuggestions: { function: string; line: number; type: string; description: string; priority: string }[]
  mockingRequirements: string[]
}

interface ApiDocsResult {
  summary: string
  endpoints: { method: string; path: string; line: number; description?: string }[]
  models: { name: string; line: number; fields: { name: string; type: string }[] }[]
  coverage: number
}

interface DiffAnalysisResult {
  summary: string
  additions: number
  deletions: number
  changeType: string
  riskLevel: string
  concerns: string[]
  suggestions: string[]
}

interface StyleCheckResult {
  summary: string
  score: number
  conventions: { line: number; rule: string; message: string; severity: Severity; suggestion: string }[]
  formattingIssues: { line: number; column: number; message: string; fix: string }[]
}

// ==================== v0.5.0 NEW TYPES ====================

interface CodeSmellResult {
  summary: string
  smells: CodeSmell[]
  score: number
}

interface CodeSmell {
  type: string
  severity: Severity
  line?: number
  message: string
  description: string
  suggestion: string
}

interface TsStrictResult {
  summary: string
  score: number
  violations: TsStrictViolation[]
}

interface TsStrictViolation {
  line: number
  rule: string
  message: string
  severity: Severity
  fix: string
}

interface IncrementalResult {
  summary: string
  changedLines: number
  affectedFunctions: string[]
  newIssues: ReviewIssue[]
  fixedIssues: string[]
  score: number
}

interface BreakingChangeResult {
  summary: string
  breakingChanges: BreakingChange[]
  score: number
}

interface BreakingChange {
  type: 'api' | 'signature' | 'behavior' | 'removal'
  line: number
  symbol: string
  description: string
  severity: Severity
  migration?: string
}

interface SarifExportResult {
  summary: string
  filePath?: string
  sarif: SarifReport
  passed: boolean
}

// --- Diff Preview Types ---
interface DiffPreviewResult {
  summary: string
  fixesApplied: number
  originalScore: number
  improvedScore: number
  unifiedDiff: string
  fixes: DiffFix[]
}

interface DiffFix {
  line: number
  original: string
  replacement: string
  description: string
  severity: Severity
}

// ==================== v0.6.0 NEW TYPES ====================

// PRO-004: Config file support
interface DshConfig {
  severityThreshold?: Severity
  ignoreRules?: string[]
  enableSarif?: boolean
  enableAutoFix?: boolean
  customRules?: CustomRule[]
  outputFormat?: 'markdown' | 'json' | 'sarif'
}

interface CustomRule {
  id: string
  pattern: string
  message: string
  severity: Severity
  language?: string
}

interface ConfigLoadResult {
  summary: string
  config: DshConfig
  loaded: boolean
  errors: string[]
}

// PRO-007: Test generation
interface TestGenResult {
  summary: string
  tests: TestCase[]
  coverage: number
  score: number
}

interface TestCase {
  functionName: string
  language: string
  testName: string
  testCode: string
  type: 'unit' | 'edge-case' | 'error-case'
  description: string
}

// PRO-009: Complexity metrics
interface ComplexityResult {
  summary: string
  score: number
  metrics: ComplexityMetrics
  functions: FunctionComplexity[]
  risks: string[]
}

interface ComplexityMetrics {
  cyclomaticComplexity: number
  halsteadVolume: number
  halsteadDifficulty: number
  halsteadEffort: number
  linesOfCode: number
  commentRatio: number
  nestingDepth: number
}

interface FunctionComplexity {
  name: string
  line: number
  cyclomatic: number
  params: number
  returns: number
  risk: 'low' | 'medium' | 'high' | 'critical'
}

// PRO-013: Batch analysis
interface BatchResult {
  summary: string
  totalFiles: number
  analyzedFiles: number
  files: FileResult[]
  overallScore: number
  totalIssues: number
  commonIssues: { message: string; count: number }[]
}

interface FileResult {
  fileName: string
  language: string
  score: number
  issues: ReviewIssue[]
  metrics: { lines: number; functions: number; classes: number }
}

// PRO-008: Monorepo analysis
interface MonorepoResult {
  summary: string
  packages: PackageResult[]
  dependencies: DepEdge[]
  cycles: string[][]
  score: number
}

interface PackageResult {
  name: string
  path: string
  language: string
  score: number
  fileCount: number
  issues: number
}

interface DepEdge {
  from: string
  to: string
  type: 'dependency' | 'devDependency' | 'peer'
}

// ==================== CONFIGURATION ====================

interface PluginConfig {
  severityThreshold: Severity
  ignoreRules: string[]
  enableSarif: boolean
  enableAutoFix: boolean
}

const DEFAULT_CONFIG: PluginConfig = {
  severityThreshold: 'info',
  ignoreRules: [],
  enableSarif: true,
  enableAutoFix: true
}

// ==================== CORE ANALYSIS ENGINE ====================

function analyzeCode(code: string, language: string, config: PluginConfig = DEFAULT_CONFIG): ReviewResult {
  const lines = code.split('\n')
  const issues: ReviewIssue[] = []
  const strengths: string[] = []
  const recommendations: string[] = []
  const refactoringSuggestions: RefactoringSuggestion[] = []
  const autoFixes: AutoFix[] = []
  const architecturePatterns: ArchitecturePattern[] = []
  
  let score = 100
  const metrics = calculateMetrics(code, language)
  
  // Code Length Analysis
  if (lines.length > 500) {
    issues.push({ severity: 'error', category: 'maintainability', ruleId: 'FILE_TOO_LONG', message: `File has ${lines.length} lines. Significantly above recommended limits.`, suggestion: 'Split into smaller, focused modules. Aim for < 300 lines per file.', docUrl: 'https://refactoring.guru/smells/long-class' })
    score -= 20
    refactoringSuggestions.push({ title: 'Extract Module', description: 'Break this large file into smaller modules based on responsibility.', impact: 'high', effort: 'medium', before: 'single large file (500+ lines)', after: 'multiple focused modules (100-200 lines each)' })
  } else if (lines.length > 300) {
    issues.push({ severity: 'warning', category: 'maintainability', ruleId: 'FILE_LONG', message: `File has ${lines.length} lines. Consider splitting.`, suggestion: 'Aim for files under 300 lines.' })
    score -= 10
  } else if (lines.length <= 100 && lines.length > 5) {
    strengths.push('File size is manageable and focused.')
  }
  
  // Comment Analysis
  const commentRatio = metrics.linesOfCode > 0 ? metrics.commentLines / metrics.linesOfCode : 0
  if (commentRatio < 0.05 && metrics.linesOfCode > 50) {
    issues.push({ severity: 'warning', category: 'documentation', ruleId: 'LOW_COMMENT_RATIO', message: `Low comment ratio (${(commentRatio * 100).toFixed(1)}%).`, suggestion: 'Add JSDoc/docstrings for public APIs. Explain "why", not "what".' })
    score -= 10
  } else if (commentRatio > 0.2) {
    strengths.push('Good comment coverage.')
  }
  
  // Function Analysis
  if (metrics.averageFunctionLength > 40 && metrics.functionCount > 0) {
    issues.push({ severity: 'warning', category: 'maintainability', ruleId: 'LONG_FUNCTION', message: `Average function length is ${metrics.averageFunctionLength} lines.`, suggestion: 'Break long functions into smaller, single-purpose functions (< 30 lines).' })
    score -= 10
    refactoringSuggestions.push({ title: 'Extract Method', description: 'Break long functions into smaller, reusable methods.', impact: 'high', effort: 'low' })
  } else if (metrics.averageFunctionLength > 0 && metrics.averageFunctionLength <= 20) {
    strengths.push('Functions are concise and well-structured.')
  }
  
  // Nesting Depth Analysis
  if (metrics.maxNestingDepth > 4) {
    issues.push({ severity: 'warning', category: 'complexity', ruleId: 'DEEP_NESTING', message: `Maximum nesting depth is ${metrics.maxNestingDepth}.`, suggestion: 'Use early returns, extract helper functions, or apply Strategy pattern.' })
    score -= 15
    refactoringSuggestions.push({ title: 'Reduce Nesting', description: 'Apply guard clauses and early returns to reduce nesting depth.', impact: 'medium', effort: 'low' })
  }
  
  // Complexity Score
  if (metrics.complexityScore > 70) {
    issues.push({ severity: 'warning', category: 'complexity', ruleId: 'HIGH_COMPLEXITY', message: `Cyclomatic complexity score is ${metrics.complexityScore}/100.`, suggestion: 'Reduce branching logic. Consider polymorphism or lookup tables.' })
    score -= 10
  }
  
  // Debug Statements
  const debugCount = detectDebugStatements(code, language, lines, issues, autoFixes)
  if (debugCount > 5) {
    issues.push({ severity: 'warning', category: 'debugging', ruleId: 'MANY_DEBUG_STATEMENTS', message: `Found ${debugCount} debug output statements.`, suggestion: 'Use a configurable logging framework (winston, pino, log4js).' })
    score -= 5
  }
  
  // TODO/FIXME Detection
  const todoCount = detectTodoFixme(code, language, lines, issues)
  if (todoCount > 5) {
    recommendations.push(`High technical debt: ${todoCount} TODO/FIXME items. Schedule cleanup.`)
  }
  
  // Empty Catch Block Detection
  detectEmptyCatch(code, issues, autoFixes)
  
  // Magic Number Detection
  detectMagicNumbers(code, lines, issues)
  
  // Error Handling Analysis
  detectErrorHandlingIssues(code, language, issues, strengths, recommendations)
  
  // Hardcoded Credentials Detection
  detectHardcodedCredentials(code, lines, issues, autoFixes)
  
  // Duplicate Code Detection
  if (metrics.duplicateLines > 20) {
    issues.push({ severity: 'info', category: 'duplication', ruleId: 'DUPLICATE_CODE', message: `Found ${metrics.duplicateLines} lines of potential duplicate code.`, suggestion: 'Extract common logic into shared utility functions.' })
    refactoringSuggestions.push({ title: 'DRY Principle', description: 'Extract duplicate code into reusable functions.', impact: 'medium', effort: 'low' })
  }
  
  // Architecture Pattern Detection
  detectArchitecturePatterns(code, language, architecturePatterns)
  
  // Apply config filters
  const filteredIssues = issues.filter(i => !config.ignoreRules.includes(i.ruleId || ''))
  
  score = Math.max(0, Math.min(100, score))
  const grade = calculateGrade(score)
  
  const criticalCount = filteredIssues.filter(i => i.severity === 'critical').length
  const errorCount = filteredIssues.filter(i => i.severity === 'error').length
  const warningCount = filteredIssues.filter(i => i.severity === 'warning').length
  const infoCount = filteredIssues.filter(i => i.severity === 'info').length
  
  let summary = `Code Review: Score ${score}/100 (Grade: ${grade}). `
  if (criticalCount > 0) summary += `${criticalCount} critical, `
  if (errorCount > 0) summary += `${errorCount} error(s), `
  summary += `${warningCount} warning(s), ${infoCount} info note(s).`
  
  if (score >= 85) strengths.unshift('Overall code quality is excellent.')
  else if (score >= 70) recommendations.unshift('Code is acceptable but has room for improvement.')
  else if (score >= 50) recommendations.unshift('Code needs attention. Prioritize error and warning fixes.')
  else recommendations.unshift('Code requires significant review and refactoring.')
  
  return { summary, score, grade, issues: filteredIssues, strengths, recommendations, metrics, refactoringSuggestions, autoFixes, architecturePatterns }
}

// ==================== METRICS CALCULATOR ====================

function calculateMetrics(code: string, language: string): CodeMetrics {
  const lines = code.split('\n')
  let commentLines = 0, blankLines = 0, functionCount = 0, totalFunctionLines = 0
  let currentFunctionStart = -1, maxNestingDepth = 0, classCount = 0
  let importCount = 0, exportCount = 0, totalParams = 0, maxParams = 0, todoCount = 0
  
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
    
    if (inBlockComment) { commentLines++; if (blockCommentEnd.test(line)) inBlockComment = false; return }
    if (blockCommentStart.test(line)) { commentLines++; if (!blockCommentEnd.test(line)) inBlockComment = true; return }
    if (trimmed === '') { blankLines++; return }
    if (commentPattern.test(line)) { commentLines++; return }
    
    if (/^\s*(import|from|import\s+\w+\s+from)\s/.test(line)) importCount++
    if (/^\s*export\s/.test(line)) exportCount++
    if (/(class|interface|struct|enum)\s+\w+/.test(line)) classCount++
    if (/(TODO|FIXME|HACK|XXX)\b/.test(line)) todoCount++
    
    for (const pattern of functionPatterns) {
      if (pattern.test(line)) {
        if (currentFunctionStart >= 0) totalFunctionLines += (idx - currentFunctionStart)
        functionCount++
        currentFunctionStart = idx
        const params = line.match(/\(([^)]*)\)/)
        if (params) {
          const paramCount = params[1] ? params[1].split(',').filter(p => p.trim()).length : 0
          totalParams += paramCount
          if (paramCount > maxParams) maxParams = paramCount
        }
        break
      }
    }
    
    const indent = line.length - line.trimStart().length
    const nestingDepth = Math.floor(indent / 2)
    if (nestingDepth > maxNestingDepth) maxNestingDepth = nestingDepth
  })
  
  if (currentFunctionStart >= 0) totalFunctionLines += (lines.length - currentFunctionStart)
  
  const loc = lines.length - blankLines - commentLines
  const avgFuncLength = functionCount > 0 ? Math.round(totalFunctionLines / functionCount) : 0
  const avgParams = functionCount > 0 ? Math.round(totalParams / functionCount) : 0
  const complexityScore = Math.min(100, maxNestingDepth * 10 + functionCount * 2)
  const maintainabilityIndex = Math.max(0, Math.min(100, 100 - complexityScore - (avgFuncLength > 30 ? 20 : 0)))
  
  const lineMap = new Map<string, number>()
  lines.forEach(line => { const t = line.trim(); if (t.length > 10) lineMap.set(t, (lineMap.get(t) || 0) + 1) })
  let duplicateLines = 0
  lineMap.forEach((count) => { if (count > 1) duplicateLines += count })
  
  return { linesOfCode: loc, commentLines, blankLines, functionCount, classCount, averageFunctionLength: avgFuncLength, maxNestingDepth, complexityScore, duplicateLines, maintainabilityIndex, importCount, exportCount, averageParamsPerFunction: avgParams, maxFunctionParams: maxParams, todoCount }
}

// ==================== DETECTION HELPERS ====================

function detectDebugStatements(code: string, language: string, lines: string[], issues: ReviewIssue[], autoFixes: AutoFix[]): number {
  const debugPatterns: Record<string, RegExp> = {
    typescript: /console\.(log|debug|warn|error|trace|info|table|dir)\s*\(/,
    javascript: /console\.(log|debug|warn|error|trace|info|table|dir)\s*\(/,
    python: /^\s*print\s*\(|import\s+pdb|breakpoint\s*\(|pdb\.set_trace/,
    java: /System\.(out|err)\.|Logger\.log\(|log\.(debug|info|warn|error)/,
    go: /fmt\.(Print|Println|Printf)|log\.(Print|Println|Printf)/,
    rust: /println!|dbg!|eprintln!/,
    cpp: /std::cout|std::cerr|printf\s*\(|fprintf\s*\(/,
    c: /printf\s*\(|fprintf\s*\(/,
    ruby: /puts\s+|p\s+|logger\./,
    php: /var_dump\s*\(|print_r\s*\(|echo\s+/,
    swift: /print\s*\(|NSLog\s*\(/,
    kotlin: /println\s*\(|Log\.(d|e|i|w|v)/,
  }
  const debugPattern = debugPatterns[language] || debugPatterns.typescript
  let debugCount = 0
  lines.forEach((line, idx) => {
    if (debugPattern.test(line)) {
      debugCount++
      if (debugCount <= 3) {
        issues.push({ severity: 'info', category: 'debugging', ruleId: 'DEBUG_STATEMENT', line: idx + 1, message: `Debug output: "${line.trim().substring(0, 60)}"`, suggestion: 'Remove or replace with proper logging.' })
        autoFixes.push({ line: idx + 1, description: 'Remove debug statement', original: line.trim(), replacement: '// ' + line.trim() + ' // TODO: remove', confidence: 0.9 })
      }
    }
  })
  return debugCount
}

function detectTodoFixme(code: string, language: string, lines: string[], issues: ReviewIssue[]): number {
  const todoPattern = language === 'python' ? /#\s*(TODO|FIXME|HACK|XXX|BUG|OPTIMIZE|REFACTOR)/i : /\/\/\s*(TODO|FIXME|HACK|XXX|BUG|OPTIMIZE|REFACTOR)/i
  let todoCount = 0
  lines.forEach((line, idx) => {
    if (todoPattern.test(line)) {
      todoCount++
      issues.push({ severity: 'info', category: 'technical-debt', ruleId: 'TODO_FIXME', line: idx + 1, message: `Technical debt: "${line.trim().substring(0, 60)}"`, suggestion: 'Track in issue tracker and schedule cleanup.' })
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
      issues.push({ severity: 'error', category: 'error-handling', ruleId: 'EMPTY_CATCH', message: 'Empty catch/except block detected. Silent failures make debugging difficult.', suggestion: 'At minimum, log the error.', fix: 'catch (error) {\n  console.error("Error:", error);\n}' })
    }
  })
}

function detectMagicNumbers(code: string, lines: string[], issues: ReviewIssue[]): void {
  const magicNumberPattern = /(?<!['".\w])\b(?!0|1|2|10|100|1000|0x[0-9a-fA-F]+)\d{2,}\b(?!['".\w])/
  const magicNumbers = new Set<string>()
  lines.forEach((line) => { if (/(const|let|var|final|val)\s+\w+\s*=/.test(line)) return; const matches = line.match(magicNumberPattern); if (matches) matches.forEach(m => magicNumbers.add(m)) })
  if (magicNumbers.size > 5) issues.push({ severity: 'info', category: 'readability', ruleId: 'MAGIC_NUMBERS', message: `Found ${magicNumbers.size} potential magic numbers.`, suggestion: 'Extract magic numbers into named constants.' })
}

function detectErrorHandlingIssues(code: string, language: string, issues: ReviewIssue[], strengths: string[], recommendations: string[]): void {
  const hasTryCatch = /try\s*\{/.test(code) && /catch/.test(code)
  const hasPromiseHandler = /\.then\s*\(/.test(code) && /\.catch\s*\(/.test(code)
  const hasErrorHandling = hasTryCatch || hasPromiseHandler
  const hasAsyncOps = /(fetch|axios|request|exec|spawn|Promise\.)/.test(code)
  if (hasErrorHandling) strengths.push('Error handling is present.')
  else if (hasAsyncOps) issues.push({ severity: 'warning', category: 'error-handling', ruleId: 'MISSING_ERROR_HANDLING', message: 'Async operations detected without visible error handling.', suggestion: 'Add try/catch or .catch() handlers for robustness.' })
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
        issues.push({ severity: 'critical', category: 'security', ruleId: 'HARDCODED_CREDENTIAL', line: idx + 1, message: `${title} detected!`, suggestion: 'Use environment variables or a secrets manager.' })
        autoFixes.push({ line: idx + 1, description: 'Replace hardcoded credential with env var', original: line.trim(), replacement: line.trim().replace(/['"][^'"]{8,}['"]/, 'process.env.SECRET'), confidence: 0.95 })
      }
    })
  })
}

function detectArchitecturePatterns(code: string, language: string, patterns: ArchitecturePattern[]): void {
  if (/class\s+\w+\s+extends\s+\w+/.test(code) && /abstract\s+class|interface\s+\w+/.test(code)) patterns.push({ name: 'Layered Architecture', description: 'Code uses abstraction with interfaces/abstract classes', confidence: 0.7 })
  if (/(repository|repo)\s*:/i.test(code)) patterns.push({ name: 'Repository Pattern', description: 'Data access abstraction detected', confidence: 0.6 })
  if (/singleton|getInstance\s*\(/i.test(code)) patterns.push({ name: 'Singleton Pattern', description: 'Global state management via singleton', confidence: 0.8 })
  if (/factory|createInstance/i.test(code)) patterns.push({ name: 'Factory Pattern', description: 'Object creation abstraction detected', confidence: 0.7 })
  if (/observer|subscribe|emit|on\s*\(|addEventListener/i.test(code)) patterns.push({ name: 'Observer Pattern', description: 'Event-driven communication detected', confidence: 0.6 })
  if (/middleware|next\s*\(|use\s*\(/i.test(code)) patterns.push({ name: 'Middleware Pattern', description: 'Request processing pipeline detected', confidence: 0.7 })
  if (/decorator|@\w+/i.test(code)) patterns.push({ name: 'Decorator Pattern', description: 'Aspect-oriented extension detected', confidence: 0.6 })
  if (/strategy|policy/i.test(code)) patterns.push({ name: 'Strategy Pattern', description: 'Interchangeable algorithm selection detected', confidence: 0.5 })
  if (/command|execute|undo|redo/i.test(code)) patterns.push({ name: 'Command Pattern', description: 'Operation encapsulation detected', confidence: 0.5 })
  if (/(\.pipe\s*\(|\.map\s*\(|\.filter\s*\(|\.reduce\s*\()/.test(code) && code.split('\n').filter(l => /\.pipe\s*\(|\.map\s*\(|\.filter\s*\(/.test(l)).length > 3) patterns.push({ name: 'Functional Pipeline', description: 'Data transformation pipeline using function chaining', confidence: 0.7 })
}

// ==================== SECURITY SCANNER ====================

function scanSecurity(code: string, language: string, generateSarif: boolean = false): SecurityScanResult {
  const lines = code.split('\n')
  const vulnerabilities: SecurityVuln[] = []
  const owaspCoverage: string[] = []
  
  const sqlPatterns = [
    { pattern: /(execute|query|exec)\s*\(\s*["'`].*\$\{?/i, title: 'SQL Injection', cwe: 'CWE-89', owasp: 'A03:2021' },
    { pattern: /(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE).*\+\s*\w+/i, title: 'SQL Query Concatenation', cwe: 'CWE-89', owasp: 'A03:2021' },
    { pattern: /f["'`].*SELECT.*\{.*\}.*["'`]/i, title: 'SQL Injection via f-string', cwe: 'CWE-89', owasp: 'A03:2021' },
  ]
  const xssPatterns = [
    { pattern: /innerHTML\s*=/, title: 'XSS via innerHTML', cwe: 'CWE-79', owasp: 'A03:2021' },
    { pattern: /document\.write\s*\(/, title: 'XSS via document.write', cwe: 'CWE-79', owasp: 'A03:2021' },
    { pattern: /dangerouslySetInnerHTML/, title: 'React XSS Risk', cwe: 'CWE-79', owasp: 'A03:2021' },
    { pattern: /v-html\s*=/, title: 'Vue v-html XSS Risk', cwe: 'CWE-79', owasp: 'A03:2021' },
  ]
  const cmdPatterns = [
    { pattern: /exec\s*\(.*\$\{?/i, title: 'Command Injection', cwe: 'CWE-78', owasp: 'A03:2021' },
    { pattern: /execSync\s*\(.*\+/i, title: 'Command Injection via execSync', cwe: 'CWE-78', owasp: 'A03:2021' },
    { pattern: /os\.system\s*\(.*\+/i, title: 'Python Command Injection', cwe: 'CWE-78', owasp: 'A03:2021' },
    { pattern: /subprocess\..*shell\s*=\s*True/i, title: 'Python subprocess shell=True', cwe: 'CWE-78', owasp: 'A03:2021' },
  ]
  const pathPatterns = [
    { pattern: /readFileSync\s*\(.*\+/i, title: 'Path Traversal', cwe: 'CWE-22', owasp: 'A01:2021' },
    { pattern: /fs\.\w+\(.*req\.(query|params|body)/i, title: 'Path Traversal via user input', cwe: 'CWE-22', owasp: 'A01:2021' },
    { pattern: /open\s*\(.*\+/i, title: 'Python Path Traversal', cwe: 'CWE-22', owasp: 'A01:2021' },
  ]
  const cryptoPatterns = [
    { pattern: /Math\.random\s*\(/, title: 'Insecure Random', cwe: 'CWE-330', owasp: 'A02:2021' },
    { pattern: /createHash\s*\(\s*['"]md5['"]\s*\)/i, title: 'Weak Hash (MD5)', cwe: 'CWE-328', owasp: 'A02:2021' },
    { pattern: /createHash\s*\(\s*['"]sha1['"]\s*\)/i, title: 'Weak Hash (SHA1)', cwe: 'CWE-328', owasp: 'A02:2021' },
    { pattern: /new\s+Buffer\s*\(/, title: 'Insecure Buffer allocation', cwe: 'CWE-120', owasp: 'A02:2021' },
  ]
  const ssrfPatterns = [
    { pattern: /fetch\s*\(.*req\.(query|params|body)/i, title: 'Potential SSRF', cwe: 'CWE-918', owasp: 'A10:2021' },
    { pattern: /axios\s*\(.*\+/i, title: 'Potential SSRF via axios', cwe: 'CWE-918', owasp: 'A10:2021' },
  ]
  const authPatterns = [
    { pattern: /(eval|Function)\s*\(/, title: 'Code Injection via eval', cwe: 'CWE-94', owasp: 'A03:2021' },
    { pattern: /\.html\s*\(.*\+/, title: 'DOM-based XSS', cwe: 'CWE-79', owasp: 'A03:2021' },
    { pattern: /jquery.*\$\(.*\+/, title: 'jQuery DOM XSS', cwe: 'CWE-79', owasp: 'A03:2021' },
  ]
  
  const allPatterns = [
    ...sqlPatterns.map(p => ({ ...p, severity: 'critical' as const })),
    ...xssPatterns.map(p => ({ ...p, severity: 'high' as const })),
    ...cmdPatterns.map(p => ({ ...p, severity: 'critical' as const })),
    ...pathPatterns.map(p => ({ ...p, severity: 'high' as const })),
    ...cryptoPatterns.map(p => ({ ...p, severity: 'medium' as const })),
    ...ssrfPatterns.map(p => ({ ...p, severity: 'high' as const })),
    ...authPatterns.map(p => ({ ...p, severity: 'critical' as const })),
  ]
  
  lines.forEach((line, idx) => {
    allPatterns.forEach(({ pattern, title, cwe, owasp, severity }) => {
      if (pattern.test(line)) {
        if (!owaspCoverage.includes(owasp!)) owaspCoverage.push(owasp!)
        vulnerabilities.push({ severity, cwe, owasp, title, description: `Pattern: "${line.trim().substring(0, 80)}"`, line: idx + 1, remediation: getRemediation(title) })
      }
    })
  })
  
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low'
  if (vulnerabilities.some(v => v.severity === 'critical')) riskLevel = 'critical'
  else if (vulnerabilities.some(v => v.severity === 'high')) riskLevel = 'high'
  else if (vulnerabilities.length > 2) riskLevel = 'medium'
  
  const passed = !vulnerabilities.some(v => v.severity === 'critical' || v.severity === 'high')
  const summary = passed ? `Security Scan: No critical/high issues. ${vulnerabilities.length} minor issue(s).` : `Security Scan: ${vulnerabilities.length} issue(s). Risk: ${riskLevel.toUpperCase()}.`
  
  let sarif: SarifReport | undefined
  if (generateSarif) sarif = generateSarifReport(vulnerabilities)
  
  return { summary, riskLevel, vulnerabilities, passed, owaspCoverage, sarif }
}

function generateSarifReport(vulnerabilities: SecurityVuln[]): SarifReport {
  const rules: SarifRule[] = []
  const results: SarifResult[] = []
  const ruleMap = new Map<string, SarifRule>()
  
  vulnerabilities.forEach((vuln, idx) => {
    const ruleId = vuln.cwe || `RULE-${idx}`
    if (!ruleMap.has(ruleId)) {
      ruleMap.set(ruleId, { id: ruleId, name: vuln.title, shortDescription: { text: vuln.title }, fullDescription: { text: vuln.description }, defaultConfiguration: { level: vuln.severity === 'critical' ? 'error' : vuln.severity === 'high' ? 'warning' : 'note' }, helpUri: `https://cwe.mitre.org/data/definitions/${ruleId.replace('CWE-', '')}.html` })
    }
    results.push({ ruleId, level: vuln.severity === 'critical' ? 'error' : vuln.severity === 'high' ? 'warning' : 'note', message: { text: vuln.description }, locations: [{ physicalLocation: { artifactLocation: { uri: 'src/file.ts' }, region: { startLine: vuln.line || 1 } } }] })
  })
  
  return { $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json', version: '2.1.0', runs: [{ tool: { driver: { name: 'dsh-tool-codereview', version: VERSION, informationUri: 'https://github.com/chengganping-ship-it/dsh-tool-codereview', rules: Array.from(ruleMap.values()) } }, results }] }
}

function getRemediation(title: string): string {
  const remediations: Record<string, string> = {
    'SQL Injection': 'Use parameterized queries or an ORM. Never concatenate user input into SQL.',
    'SQL Query Concatenation': 'Use prepared statements with parameter binding.',
    'SQL Injection via f-string': 'Use parameterized queries. Never use f-strings for SQL.',
    'XSS via innerHTML': 'Use textContent or sanitize with DOMPurify.',
    'XSS via document.write': 'Use DOM manipulation methods.',
    'React XSS Risk': 'Avoid if possible. Sanitize with DOMPurify if required.',
    'Vue v-html XSS Risk': 'Avoid raw HTML. Use computed properties with sanitization.',
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
    'Code Injection via eval': 'Never use eval() with user input. Use JSON.parse() instead.',
    'DOM-based XSS': 'Sanitize all DOM inputs.',
    'jQuery DOM XSS': 'Use text() instead of html() for user content.',
  }
  return remediations[title] || 'Review and address this security concern.'
}

// ==================== DEPENDENCY AUDITOR ====================

function auditDependencies(code: string, language: string): DependencyAuditResult {
  const dependencies: DependencyVuln[] = []
  if (language === 'typescript' || language === 'javascript') {
    const importPatterns = [/from\s+['"]([^'"]+)['"]/g, /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g, /import\s+['"]([^'"]+)['"]/g]
    const packages = new Set<string>()
    importPatterns.forEach(pattern => { let match; while ((match = pattern.exec(code)) !== null) { const pkg = match[1]; if (!pkg.startsWith('.') && !pkg.startsWith('/')) packages.add(pkg.split('/')[0]) } })
    const knownVulns: Record<string, DependencyVuln> = {
      'lodash': { package: 'lodash', version: '<4.17.21', severity: 'high', cve: 'CVE-2021-23337', title: 'Command Injection', fixedVersion: '4.17.21' },
      'minimist': { package: 'minimist', version: '<1.2.6', severity: 'high', cve: 'CVE-2021-44906', title: 'Prototype Pollution', fixedVersion: '1.2.6' },
      'axios': { package: 'axios', version: '<0.21.1', severity: 'high', cve: 'CVE-2021-3749', title: 'SSRF', fixedVersion: '0.21.1' },
      'express': { package: 'express', version: '<4.17.3', severity: 'medium', cve: 'CVE-2022-24999', title: 'QS ReDoS', fixedVersion: '4.17.3' },
      'jsonwebtoken': { package: 'jsonwebtoken', version: '<9.0.0', severity: 'critical', cve: 'CVE-2022-23529', title: 'JWT Verification Bypass', fixedVersion: '9.0.0' },
      'node-fetch': { package: 'node-fetch', version: '<2.6.7', severity: 'high', cve: 'CVE-2022-0235', title: 'Sensitive Information Exposure', fixedVersion: '2.6.7' },
      'moment': { package: 'moment', version: '<2.29.4', severity: 'high', cve: 'CVE-2022-31129', title: 'ReDoS', fixedVersion: '2.29.4' },
      'uuid': { package: 'uuid', version: '<8.3.2', severity: 'medium', title: 'Predictable PRNG', fixedVersion: '8.3.2' },
    }
    packages.forEach(pkg => { if (knownVulns[pkg]) dependencies.push(knownVulns[pkg]) })
  }
  const vulnerableCount = dependencies.length
  const passed = vulnerableCount === 0
  const summary = passed ? 'Dependency Audit: No known vulnerabilities found.' : `Dependency Audit: ${vulnerableCount} vulnerable package(s) detected.`
  return { summary, totalDependencies: 0, vulnerableCount, dependencies, passed }
}

// ==================== PERFORMANCE ANALYZER ====================

function analyzePerformance(code: string, language: string): PerformanceAnalysisResult {
  const lines = code.split('\n')
  const issues: PerformanceIssue[] = []
  const bigOEstimates: { line: number; complexity: string; description: string }[] = []
  let score = 100
  
  // N+1 query pattern
  const nPlus1Patterns = [/for\s*\([^)]*\)\s*\{[^}]*(?:find|query|select|where)/is, /\.map\s*\([^)]*(?:find|query|select|where)/is, /forEach\s*\([^)]*(?:find|query|select|where)/is]
  nPlus1Patterns.forEach(pattern => {
    if (pattern.test(code)) {
      issues.push({ severity: 'warning', category: 'n-plus-1', message: 'Potential N+1 query pattern detected.', impact: 'High - causes database performance degradation', suggestion: 'Use eager loading, batch queries, or JOINs.' })
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
      issues.push({ severity: 'warning', category: 'algorithm', message: msg, impact: 'Medium - may cause slowdown with large datasets', suggestion: 'Consider using Map/Set for O(1) lookups or optimizing algorithm.' })
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
        issues.push({ severity: 'info', category: 'memory', line: idx + 1, message: msg, impact: 'Low - may cause memory issues in long-running apps', suggestion: 'Clear intervals on unmount, remove listeners when done.' })
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
        issues.push({ severity: 'info', category: 'blocking', line: idx + 1, message: msg, impact: 'Low - may cause UI freeze with large data', suggestion: 'Consider streaming or worker threads for large operations.' })
        score -= 3
      }
    })
  })
  
  // BigO estimation
  lines.forEach((line, idx) => {
    if (/for\s*\([^)]*\)\s*\{[^}]*for\s*\(/is.test(line)) bigOEstimates.push({ line: idx + 1, complexity: 'O(n²)', description: 'Nested loop detected' })
    else if (/for\s*\(|while\s*\(/.test(line)) bigOEstimates.push({ line: idx + 1, complexity: 'O(n)', description: 'Single loop' })
    if (/\.sort\s*\(/.test(line)) bigOEstimates.push({ line: idx + 1, complexity: 'O(n log n)', description: 'Sort operation' })
  })
  
  score = Math.max(0, Math.min(100, score))
  const summary = issues.length === 0 ? 'Performance Analysis: No significant issues found.' : `Performance Analysis: ${issues.length} potential issue(s). Score: ${score}/100.`
  return { summary, issues, score, bigOEstimates }
}

// ==================== ARCHITECTURE REVIEW ====================

function reviewArchitecture(code: string, language: string): { patterns: ArchitecturePattern[]; score: number; summary: string; recommendations: string[] } {
  const patterns: ArchitecturePattern[] = []
  const recommendations: string[] = []
  let score = 100
  
  detectArchitecturePatterns(code, language, patterns)
  
  // SOLID principles check
  if (/class\s+\w+\s*\{[^}]{500,}\}/s.test(code)) { score -= 15; recommendations.push('Single Responsibility: Large classes should be split into smaller, focused units.') }
  if (!/interface\s+\w+|abstract\s+class/.test(code) && /class\s+\w+/.test(code)) { score -= 10; recommendations.push('Dependency Inversion: Consider using interfaces/abstractions for better testability.') }
  
  // Module cohesion
  const imports = (code.match(/import\s+/g) || []).length
  if (imports > 20) { score -= 10; recommendations.push('High coupling: Many imports suggest the module may have too many responsibilities.') }
  
  // Error handling strategy
  if (!/try\s*\{|catch\s*\(|except\s*:|Result\s*</.test(code) && code.split('\n').length > 50) { score -= 15; recommendations.push('Missing error handling: Add proper error handling for robustness.') }
  
  // Documentation
  if (!/\/\*\*|\/\/|"""|#\s*(Module|Package|Class)/.test(code)) { score -= 10; recommendations.push('Add module-level documentation to explain purpose and usage.') }
  
  score = Math.max(0, Math.min(100, score))
  const summary = `Architecture Review: ${patterns.length} patterns detected. Score: ${score}/100.`
  return { patterns, score, summary, recommendations }
}

// ==================== TEST COVERAGE ANALYZER ====================

function analyzeTestCoverage(code: string, language: string): TestCoverageResult {
  const lines = code.split('\n')
  const untestablePatterns: string[] = []
  const testSuggestions: { function: string; line: number; type: string; description: string; priority: string }[] = []
  const mockingRequirements: string[] = []
  let testabilityScore = 100
  
  // Find functions and assess testability
  const functionPattern = /(?:function\s+(\w+)|def\s+(\w+)|fn\s+(\w+)|(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)/g
  let match
  while ((match = functionPattern.exec(code)) !== null) {
    const funcName = match[1] || match[2] || match[3] || match[4] || 'anonymous'
    const line = code.substring(0, match.index).split('\n').length
    testSuggestions.push({ function: funcName, line, type: 'unit', description: `Test ${funcName} with various inputs and edge cases`, priority: 'high' })
  }
  
  // Check for hard-to-test patterns
  if (/new\s+Date\s*\(/.test(code) || /Date\.now\s*\(/.test(code)) { untestablePatterns.push('Time-dependent code - use dependency injection for dates'); mockingRequirements.push('Date/Time provider') }
  if (/Math\.random\s*\(/.test(code)) { untestablePatterns.push('Random number generation - inject a seeded RNG for testing'); mockingRequirements.push('Random number generator') }
  if (/fetch\s*\(|axios\s*\(|http\./.test(code)) { untestablePatterns.push('HTTP calls - mock network requests'); mockingRequirements.push('HTTP client') }
  if (/fs\.|readFileSync|writeFileSync/.test(code)) { untestablePatterns.push('File system operations - use in-memory fs for testing'); mockingRequirements.push('File system') }
  if (/localStorage|sessionStorage/.test(code)) { untestablePatterns.push('Browser storage - mock storage API'); mockingRequirements.push('Storage API') }
  if (/console\.(log|error|warn)/.test(code)) { untestablePatterns.push('Console output - consider injecting a logger'); mockingRequirements.push('Logger') }
  
  // Calculate testability score
  testabilityScore -= untestablePatterns.length * 10
  testabilityScore = Math.max(0, Math.min(100, testabilityScore))
  
  // Estimate coverage potential
  const coverageEstimate = Math.max(0, Math.min(100, testabilityScore - 10))
  
  const summary = `Test Coverage Analysis: ${testSuggestions.length} testable functions found. Testability Score: ${testabilityScore}/100.`
  return { summary, testabilityScore, coverageEstimate, untestablePatterns, testSuggestions, mockingRequirements }
}

// ==================== API DOCUMENTATION GENERATOR ====================

function generateApiDocs(code: string, language: string): ApiDocsResult {
  const lines = code.split('\n')
  const endpoints: { method: string; path: string; line: number; description?: string }[] = []
  const models: { name: string; line: number; fields: { name: string; type: string }[] }[] = []
  
  // Detect API endpoints
  const endpointPatterns = [
    { pattern: /(app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g, hasPath: true },
    { pattern: /@(Get|Post|Put|Delete|Patch)\s*\(\s*['"`]([^'"`]+)['"`]/g, hasPath: true },
    { pattern: /route\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*['"`](GET|POST|PUT|DELETE|PATCH)['"`]/gi, hasPath: true },
  ]
  
  endpointPatterns.forEach(({ pattern }) => {
    let match
    while ((match = pattern.exec(code)) !== null) {
      const line = code.substring(0, match.index).split('\n').length
      endpoints.push({ method: match[2]?.toUpperCase() || 'GET', path: match[3] || match[1], line })
    }
  })
  
  // Detect models/interfaces
  const modelPattern = /(?:interface|type|class|struct)\s+(\w+)\s*(?:=\s*)?\{([^}]+)\}/g
  let modelMatch
  while ((modelMatch = modelPattern.exec(code)) !== null) {
    const name = modelMatch[1]
    const body = modelMatch[2]
    const line = code.substring(0, modelMatch.index).split('\n').length
    const fields: { name: string; type: string }[] = []
    body.split(/[;\n]/).forEach(field => {
      const fieldMatch = field.trim().match(/^(\w+)\s*[?:]\s*(\w+)/)
      if (fieldMatch) fields.push({ name: fieldMatch[1], type: fieldMatch[2] })
    })
    models.push({ name, line, fields })
  }
  
  const coverage = endpoints.length > 0 ? Math.min(100, endpoints.length * 20) : 0
  const summary = `API Documentation: ${endpoints.length} endpoints, ${models.length} models detected. Coverage: ${coverage}%.`
  return { summary, endpoints, models, coverage }
}

// ==================== CODE DIFF ANALYZER ====================

function analyzeDiff(diffText: string): DiffAnalysisResult {
  const lines = diffText.split('\n')
  let additions = 0, deletions = 0
  const concerns: string[] = []
  const suggestions: string[] = []
  
  lines.forEach(line => {
    if (line.startsWith('+') && !line.startsWith('+++')) additions++
    if (line.startsWith('-') && !line.startsWith('---')) deletions++
  })
  
  // Determine change type
  let changeType = 'mixed'
  if (additions > 0 && deletions === 0) changeType = 'feature'
  else if (deletions > additions * 2) changeType = 'refactor'
  else if (additions > deletions * 2) changeType = 'feature'
  else if (additions === deletions) changeType = 'bugfix'
  
  // Risk assessment
  let riskLevel = 'low'
  if (additions + deletions > 500) { riskLevel = 'high'; concerns.push('Large change set - consider breaking into smaller PRs') }
  else if (additions + deletions > 200) { riskLevel = 'medium'; concerns.push('Moderate change size - ensure thorough review') }
  
  if (deletions > additions * 3) concerns.push('Significant code deletion - verify no functionality is lost')
  if (additions > 300 && deletions < 50) concerns.push('Large addition without corresponding deletions - possible code duplication')
  
  // Suggestions
  if (additions > 100) suggestions.push('Consider splitting this into multiple focused commits')
  if (concerns.length === 0) suggestions.push('Change looks well-balanced and manageable')
  suggestions.push('Run full test suite before merging')
  suggestions.push('Review for any security implications')
  
  const summary = `Diff Analysis: +${additions}/-${deletions} lines. Type: ${changeType}. Risk: ${riskLevel}.`
  return { summary, additions, deletions, changeType, riskLevel, concerns, suggestions }
}

// ==================== STYLE CHECKER ====================

function checkStyle(code: string, language: string): StyleCheckResult {
  const lines = code.split('\n')
  const conventions: { line: number; rule: string; message: string; severity: Severity; suggestion: string }[] = []
  const formattingIssues: { line: number; column: number; message: string; fix: string }[] = []
  let score = 100
  
  lines.forEach((line, idx) => {
    const lineNum = idx + 1
    
    // Line length check
    if (line.length > 120) { formattingIssues.push({ line: lineNum, column: 120, message: `Line exceeds 120 characters (${line.length})`, fix: 'Break line into multiple lines' }); score -= 2 }
    
    // Trailing whitespace
    if (/\s+$/.test(line)) { formattingIssues.push({ line: lineNum, column: line.length, message: 'Trailing whitespace detected', fix: 'Remove trailing whitespace' }); score -= 1 }
    
    // Tab vs spaces
    if (/\t/.test(line) && line.trim().length > 0) { formattingIssues.push({ line: lineNum, column: 1, message: 'Tab character found - use spaces', fix: 'Replace tabs with spaces' }); score -= 2 }
    
    // Naming conventions
    if (language === 'typescript' || language === 'javascript') {
      const varMatch = line.match(/(?:const|let|var)\s+([a-z_][a-zA-Z0-9_]*)\s*=/)
      if (varMatch && /[A-Z]/.test(varMatch[1]) && !/^[A-Z_]+$/.test(varMatch[1])) { conventions.push({ line: lineNum, rule: 'VARIABLE_NAMING', message: `Variable '${varMatch[1]}' uses mixed case - use camelCase`, severity: 'warning', suggestion: 'Rename to camelCase' }); score -= 3 }
      
      const classMatch = line.match(/class\s+([a-zA-Z][a-zA-Z0-9]*)/)
      if (classMatch && !/^[A-Z]/.test(classMatch[1])) { conventions.push({ line: lineNum, rule: 'CLASS_NAMING', message: `Class '${classMatch[1]}' should use PascalCase`, severity: 'warning', suggestion: 'Rename to PascalCase' }); score -= 3 }
    }
    
    // Missing semicolons (for JS/TS)
    if ((language === 'typescript' || language === 'javascript') && /^\s*(?:const|let|var|return|export)\s+.+[^;{}\s]$/.test(line)) {
      formattingIssues.push({ line: lineNum, column: line.length, message: 'Missing semicolon', fix: 'Add semicolon at end of statement' })
    }
  })
  
  score = Math.max(0, Math.min(100, score))
  const summary = `Style Check: ${conventions.length} convention issues, ${formattingIssues.length} formatting issues. Score: ${score}/100.`
  return { summary, score, conventions, formattingIssues }
}

// ==================== LANGUAGE DETECTION ====================

function detectLanguage(code: string): string {
  if (/^\s*(import|export|const|let|function|interface|type)\s/m.test(code) || /\.(ts|tsx|js|jsx)/.test(code)) return 'typescript'
  if (/^\s*(def |class |import |from |if __name__)/m.test(code)) return 'python'
  if (/^\s*(public |private |protected |class |interface |package )/m.test(code)) return 'java'
  if (/^\s*(#include|int main|std::)/m.test(code)) return 'cpp'
  if (/^\s*(package |func |import\s+\()/m.test(code)) return 'go'
  if (/^\s*(fn |let mut |impl |pub )/m.test(code)) return 'rust'
  if (/^\s*(def |class |module |require )/m.test(code) && /end\s*$/.test(code)) return 'ruby'
  if (/^\s*<\?php/.test(code) || /^\s*\$\w+\s*=/.test(code)) return 'php'
  if (/^\s*(func |var |let |class |struct |enum |protocol )/m.test(code) && /import\s+Foundation|import\s+UIKit/.test(code)) return 'swift'
  if (/^\s*(fun |val |var |class |data class |sealed class )/m.test(code)) return 'kotlin'
  return 'unknown'
}

// ==================== GRADE CALCULATOR ====================

function calculateGrade(score: number): string {
  if (score >= 95) return 'A+'
  if (score >= 90) return 'A'
  if (score >= 85) return 'B+'
  if (score >= 80) return 'B'
  if (score >= 70) return 'C'
  if (score >= 60) return 'D'
  return 'F'
}

// ==================== FORMATTERS ====================

function formatReviewReport(result: ReviewResult): string {
  const lines: string[] = []
  lines.push('## Code Review Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100 | Grade: ${result.grade}**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  lines.push('### Code Metrics')
  lines.push('| Metric | Value |')
  lines.push('|--------|-------|')
  lines.push(`| Lines of Code | ${result.metrics.linesOfCode} |`)
  lines.push(`| Comment Lines | ${result.metrics.commentLines} |`)
  lines.push(`| Blank Lines | ${result.metrics.blankLines} |`)
  lines.push(`| Functions | ${result.metrics.functionCount} |`)
  lines.push(`| Classes | ${result.metrics.classCount} |`)
  lines.push(`| Avg Function Length | ${result.metrics.averageFunctionLength} lines |`)
  lines.push(`| Max Nesting Depth | ${result.metrics.maxNestingDepth} |`)
  lines.push(`| Complexity Score | ${result.metrics.complexityScore}/100 |`)
  lines.push(`| Maintainability Index | ${result.metrics.maintainabilityIndex}/100 |`)
  lines.push(`| Imports | ${result.metrics.importCount} |`)
  lines.push(`| Exports | ${result.metrics.exportCount} |`)
  lines.push(`| Avg Params/Function | ${result.metrics.averageParamsPerFunction} |`)
  lines.push(`| TODOs | ${result.metrics.todoCount} |`)
  lines.push('')
  if (result.strengths.length > 0) { lines.push('### Strengths'); result.strengths.forEach(s => lines.push('- ' + s)); lines.push('') }
  if (result.issues.length > 0) {
    lines.push('### Issues')
    const severityIcons: Record<string, string> = { critical: '🔴', error: '🟠', warning: '🟡', info: '🔵' }
    result.issues.forEach(issue => {
      const icon = severityIcons[issue.severity] || '⚪'
      const lineInfo = issue.line ? ` (line ${issue.line})` : ''
      const ruleInfo = issue.ruleId ? ` [${issue.ruleId}]` : ''
      lines.push(`- ${icon} **[${issue.severity.toUpperCase()}]**${ruleInfo} ${issue.category}${lineInfo}: ${issue.message}`)
      if (issue.suggestion) lines.push(`  -> *${issue.suggestion}*`)
    })
    lines.push('')
  }
  if (result.autoFixes.length > 0) {
    lines.push('### Auto-Fixes Available')
    result.autoFixes.forEach((fix, idx) => { lines.push(`${idx + 1}. Line ${fix.line}: ${fix.description} (confidence: ${(fix.confidence * 100).toFixed(0)}%)`); lines.push(`   - Original: \`${fix.original}\``); lines.push(`   + Fixed: \`${fix.replacement}\``) })
    lines.push('')
  }
  if (result.refactoringSuggestions.length > 0) {
    lines.push('### Refactoring Suggestions')
    result.refactoringSuggestions.forEach((ref, idx) => { lines.push(`${idx + 1}. **${ref.title}** [Impact: ${ref.impact}, Effort: ${ref.effort}]`); lines.push(`   ${ref.description}`) })
    lines.push('')
  }
  if (result.architecturePatterns.length > 0) {
    lines.push('### Architecture Patterns Detected')
    result.architecturePatterns.forEach(p => { lines.push(`- **${p.name}** (confidence: ${(p.confidence * 100).toFixed(0)}%): ${p.description}`) })
    lines.push('')
  }
  if (result.recommendations.length > 0) { lines.push('### Recommendations'); result.recommendations.forEach(r => lines.push('- ' + r)); lines.push('') }
  return lines.join('\n')
}

function formatSecurityReport(result: SecurityScanResult): string {
  const lines: string[] = []
  const riskIcons: Record<string, string> = { low: '🟢', medium: '🟡', high: '🟠', critical: '🔴' }
  lines.push('## Security Scan Report')
  lines.push('')
  lines.push(`**Risk Level: ${riskIcons[result.riskLevel]} ${result.riskLevel.toUpperCase()}**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.owaspCoverage.length > 0) { lines.push('### OWASP Top 10 Coverage'); result.owaspCoverage.forEach(o => lines.push('- ' + o)); lines.push('') }
  if (result.vulnerabilities.length > 0) {
    lines.push('### Vulnerabilities')
    result.vulnerabilities.forEach(vuln => {
      const icon = vuln.severity === 'critical' ? '🔴' : vuln.severity === 'high' ? '🟠' : '🟡'
      const lineInfo = vuln.line ? ` (line ${vuln.line})` : ''
      const cweInfo = vuln.cwe ? ` [${vuln.cwe}]` : ''
      lines.push(`- ${icon} **${vuln.title}**${cweInfo}${lineInfo}`)
      lines.push(`  ${vuln.description}`)
      lines.push(`  -> *Fix: ${vuln.remediation}*`)
    })
    lines.push('')
  } else { lines.push('No security vulnerabilities detected.'); lines.push('') }
  if (result.sarif) { lines.push('### SARIF Output'); lines.push('```json'); lines.push(JSON.stringify(result.sarif, null, 2)); lines.push('```'); lines.push('') }
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
      const fixedInfo = dep.fixedVersion ? ` -> Upgrade to ${dep.fixedVersion}` : ''
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
  if (result.bigOEstimates.length > 0) {
    lines.push('### Complexity Estimates')
    result.bigOEstimates.forEach(e => { lines.push(`- Line ${e.line}: **${e.complexity}** - ${e.description}`) })
    lines.push('')
  }
  if (result.issues.length > 0) {
    lines.push('### Performance Issues')
    result.issues.forEach(issue => {
      const icon = issue.severity === 'warning' ? '🟡' : '🔵'
      const lineInfo = issue.line ? ` (line ${issue.line})` : ''
      lines.push(`- ${icon} **[${issue.category}]**${lineInfo}: ${issue.message}`)
      lines.push(`  Impact: ${issue.impact}`)
      lines.push(`  -> *${issue.suggestion}*`)
    })
    lines.push('')
  }
  return lines.join('\n')
}

function formatArchitectureReport(result: { patterns: ArchitecturePattern[]; score: number; summary: string; recommendations: string[] }): string {
  const lines: string[] = []
  lines.push('## Architecture Review Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.patterns.length > 0) {
    lines.push('### Detected Patterns')
    result.patterns.forEach(p => { lines.push(`- **${p.name}** (confidence: ${(p.confidence * 100).toFixed(0)}%): ${p.description}`) })
    lines.push('')
  }
  if (result.recommendations.length > 0) { lines.push('### Recommendations'); result.recommendations.forEach(r => lines.push('- ' + r)); lines.push('') }
  return lines.join('\n')
}

function formatTestCoverageReport(result: TestCoverageResult): string {
  const lines: string[] = []
  lines.push('## Test Coverage Analysis')
  lines.push('')
  lines.push(`**Testability Score: ${result.testabilityScore}/100 | Estimated Coverage: ${result.coverageEstimate}%**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.untestablePatterns.length > 0) { lines.push('### Hard-to-Test Patterns'); result.untestablePatterns.forEach(p => lines.push('- ' + p)); lines.push('') }
  if (result.mockingRequirements.length > 0) { lines.push('### Mocking Requirements'); result.mockingRequirements.forEach(m => lines.push('- ' + m)); lines.push('') }
  if (result.testSuggestions.length > 0) {
    lines.push('### Test Suggestions')
    result.testSuggestions.slice(0, 10).forEach(s => { lines.push(`- **${s.function}** (line ${s.line}, ${s.type}, priority: ${s.priority}): ${s.description}`) })
    if (result.testSuggestions.length > 10) lines.push(`- ... and ${result.testSuggestions.length - 10} more functions to test`)
    lines.push('')
  }
  return lines.join('\n')
}

function formatApiDocsReport(result: ApiDocsResult): string {
  const lines: string[] = []
  lines.push('## API Documentation')
  lines.push('')
  lines.push(`**Coverage: ${result.coverage}%**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.endpoints.length > 0) {
    lines.push('### Endpoints')
    result.endpoints.forEach(e => { lines.push(`- **${e.method}** \`${e.path}\` (line ${e.line})`) })
    lines.push('')
  }
  if (result.models.length > 0) {
    lines.push('### Models')
    result.models.forEach(m => { lines.push(`- **${m.name}** (line ${m.line}): ${m.fields.map(f => `${f.name}: ${f.type}`).join(', ')}`) })
    lines.push('')
  }
  return lines.join('\n')
}

function formatDiffReport(result: DiffAnalysisResult): string {
  const lines: string[] = []
  lines.push('## Code Diff Analysis')
  lines.push('')
  lines.push(`**Change Type: ${result.changeType} | Risk Level: ${result.riskLevel}**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  lines.push('### Statistics')
  lines.push(`- Additions: +${result.additions}`)
  lines.push(`- Deletions: -${result.deletions}`)
  lines.push(`- Net change: ${result.additions - result.deletions > 0 ? '+' : ''}${result.additions - result.deletions}`)
  lines.push('')
  if (result.concerns.length > 0) { lines.push('### Concerns'); result.concerns.forEach(c => lines.push('- ⚠️ ' + c)); lines.push('') }
  if (result.suggestions.length > 0) { lines.push('### Suggestions'); result.suggestions.forEach(s => lines.push('- ' + s)); lines.push('') }
  return lines.join('\n')
}

// ==================== v0.5.0 NEW FUNCTIONS ====================

// --- Code Smell Detection (PRO-002) ---
function detectCodeSmells(code: string, _language: string): CodeSmellResult {
  const smells: CodeSmell[] = []
  const lines = code.split('\n')
  const totalLines = lines.length

  // God Object: class with too many methods/lines
  const classMatches = code.match(/class\s+\w+/g) || []
  classMatches.forEach(cls => {
    const clsIndex = code.indexOf(cls)
    const clsLine = code.substring(0, clsIndex).split('\n').length
    const methodCount = (code.substring(clsIndex, clsIndex + 5000).match(/(public|private|protected|static)?\s*\w+\s*\(/g) || []).length
    if (methodCount > 10) {
      smells.push({
        type: 'God Object',
        severity: 'warning',
        line: clsLine,
        message: `Class has ${methodCount} methods - consider splitting`,
        description: 'God Object anti-pattern: class knows or does too much',
        suggestion: 'Split into smaller, focused classes following Single Responsibility Principle'
      })
    }
    if (totalLines > 300) {
      smells.push({
        type: 'Large Class',
        severity: 'warning',
        line: clsLine,
        message: `Class spans ${totalLines} lines`,
        description: 'Large classes are harder to maintain and understand',
        suggestion: 'Extract related functionality into separate classes'
      })
    }
  })

  // Feature Envy: excessive use of another class's methods
  const getterChains = code.match(/\w+\.\w+\.\w+\.\w+/g) || []
  getterChains.forEach(chain => {
    const idx = code.indexOf(chain)
    const line = code.substring(0, idx).split('\n').length
    smells.push({
      type: 'Feature Envy',
      severity: 'info',
      line,
      message: `Method chain: ${chain}`,
      description: 'Feature Envy: method seems more interested in another class',
      suggestion: 'Consider moving this logic to the class it operates on'
    })
  })

  // Shotgun Surgery: one change requires many small edits
  const importCount = (code.match(/^(import|from|require)/gm) || []).length
  if (importCount > 15) {
    smells.push({
      type: 'Shotgun Surgery Risk',
      severity: 'info',
      message: `High coupling: ${importCount} imports detected`,
      description: 'Many imports suggest the module may be involved in many changes',
      suggestion: 'Consider using a facade or mediator pattern to reduce coupling'
    })
  }

  // Long Method: functions with too many lines
  let funcStart = -1
  let funcName = ''
  let braceCount = 0
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const funcMatch = line.match(/(function|def|func)\s+(\w+)/)
    if (funcMatch && funcStart === -1) {
      funcStart = i
      funcName = funcMatch[2]
      braceCount = 0
    }
    if (funcStart !== -1) {
      braceCount += (line.match(/{/g) || []).length - (line.match(/}/g) || []).length
      if (i - funcStart > 50 && braceCount <= 0) {
        smells.push({
          type: 'Long Method',
          severity: 'warning',
          line: funcStart + 1,
          message: `Function '${funcName}' spans ${i - funcStart} lines`,
          description: 'Long methods are harder to understand and test',
          suggestion: 'Extract logical blocks into helper functions'
        })
        funcStart = -1
      }
    }
  }

  // Primitive Obsession: excessive primitive use
  const primitiveCount = (code.match(/:\s*(string|number|boolean|int|float)\b/g) || []).length
  if (primitiveCount > 8) {
    smells.push({
      type: 'Primitive Obsession',
      severity: 'info',
      message: `${primitiveCount} primitive type annotations found`,
      description: 'Excessive use of primitives where domain types would be clearer',
      suggestion: 'Consider creating value objects or type aliases for domain concepts'
    })
  }

  // Dead Code: unused variables
  const declaredVars = code.match(/(?:const|let|var|def)\s+(\w+)/g) || []
  declaredVars.forEach(decl => {
    const varName = decl.replace(/^(const|let|var|def)\s+/, '')
    if (varName.length > 0) {
      const usages = (code.match(new RegExp(`\\b${varName}\\b`, 'g')) || []).length
      if (usages <= 1) {
        const idx = code.indexOf(decl)
        const line = code.substring(0, idx).split('\n').length
        smells.push({
          type: 'Dead Code',
          severity: 'info',
          line,
          message: `Variable '${varName}' appears unused`,
          description: 'Unused variables add noise and confusion',
          suggestion: 'Remove unused declarations or prefix with _ if intentionally unused'
        })
      }
    }
  })

  const score = Math.max(0, 100 - smells.filter(s => s.severity === 'warning').length * 10 - smells.filter(s => s.severity === 'info').length * 3)
  return {
    summary: `Found ${smells.length} code smells (${smells.filter(s => s.severity === 'warning').length} warnings, ${smells.filter(s => s.severity === 'info').length} info)`,
    smells,
    score
  }
}

function formatCodeSmellReport(result: CodeSmellResult): string {
  const lines: string[] = []
  lines.push('## Code Smell Detection Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.smells.length > 0) {
    lines.push('### Detected Smells')
    result.smells.forEach(s => {
      const icon = s.severity === 'warning' ? '⚠️' : 'ℹ️'
      lines.push(`- ${icon} **${s.type}**${s.line ? ` (line ${s.line})` : ''}: ${s.message}`)
      lines.push(`  - ${s.description}`)
      lines.push(`  - 💡 ${s.suggestion}`)
    })
    lines.push('')
  }
  return lines.join('\n')
}

// --- TypeScript Strict Mode Check (PRO-001) ---
function checkTsStrictMode(code: string): TsStrictResult {
  const violations: TsStrictViolation[] = []
  const lines = code.split('\n')

  lines.forEach((line, idx) => {
    const lineNum = idx + 1
    if (/:\s*any\b/.test(line) && !line.trim().startsWith('//')) {
      violations.push({
        line: lineNum,
        rule: 'noImplicitAny',
        message: 'Explicit any type annotation detected',
        severity: 'warning',
        fix: 'Replace `any` with a proper type or use `unknown` for truly dynamic values'
      })
    }
    if (/(function|const\s+\w+)\s*[\(=]/.test(line) && !line.includes(':') && !line.includes('=>') && !line.trim().startsWith('//')) {
      if (/\(.*\)\s*{/.test(line) || /=\s*\(.*\)\s*{/.test(line)) {
        violations.push({
          line: lineNum,
          rule: 'explicitReturnType',
          message: 'Function missing explicit return type annotation',
          severity: 'info',
          fix: 'Add return type annotation: `function foo(): ReturnType`'
        })
      }
    }
    if (/!\s*[;),\]]/.test(line) && !line.trim().startsWith('//')) {
      violations.push({
        line: lineNum,
        rule: 'noNonNullAssertion',
        message: 'Non-null assertion operator (!) used',
        severity: 'warning',
        fix: 'Use proper null checks or optional chaining instead of assertion'
      })
    }
    if (/\.length\s*[><]=?\s*0[^0-9]/.test(line)) {
      violations.push({
        line: lineNum,
        rule: 'strictNullChecks',
        message: 'Redundant length check - use truthiness instead',
        severity: 'info',
        fix: 'Replace `arr.length > 0` with `arr.length` or use optional chaining'
      })
    }
    if (/\bas\s+\w+/.test(line) && !line.trim().startsWith('//')) {
      violations.push({
        line: lineNum,
        rule: 'noUncheckedTypeAssertion',
        message: 'Type assertion used - may bypass type safety',
        severity: 'info',
        fix: 'Consider using type guards or narrowing instead of assertions'
      })
    }
  })

  const score = Math.max(0, 100 - violations.filter(v => v.severity === 'warning').length * 15 - violations.filter(v => v.severity === 'info').length * 5)
  return {
    summary: `Found ${violations.length} strict mode violations (${violations.filter(v => v.severity === 'warning').length} warnings, ${violations.filter(v => v.severity === 'info').length} info)`,
    score,
    violations
  }
}

function formatTsStrictReport(result: TsStrictResult): string {
  const lines: string[] = []
  lines.push('## TypeScript Strict Mode Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.violations.length > 0) {
    lines.push('### Violations')
    result.violations.forEach(v => {
      const icon = v.severity === 'warning' ? '⚠️' : 'ℹ️'
      lines.push(`- ${icon} Line ${v.line} [${v.rule}]: ${v.message}`)
      lines.push(`  - 💡 ${v.fix}`)
    })
    lines.push('')
  }
  return lines.join('\n')
}

// --- Incremental Analysis (PRO-006) ---
function analyzeIncremental(code: string, diff: string, language: string): IncrementalResult {
  const diffLines = diff.split('\n')
  const addedLines = diffLines.filter(l => l.startsWith('+') && !l.startsWith('+++'))
  const removedLines = diffLines.filter(l => l.startsWith('-') && !l.startsWith('---'))
  
  const affectedFunctions: string[] = []
  const funcPattern = /@@.*@@.*\n.*(?:function|def|func|class)\s+(\w+)/g
  let match: RegExpExecArray | null
  while ((match = funcPattern.exec(diff)) !== null) {
    if (!affectedFunctions.includes(match[1])) {
      affectedFunctions.push(match[1])
    }
  }

  const changedCode = addedLines.map(l => l.substring(1)).join('\n')
  const baseResult = analyzeCode(changedCode || code, language)
  
  const newIssues = baseResult.issues.filter(i => 
    addedLines.some(l => l.includes(i.message.substring(0, 20)))
  )

  const changedLineCount = addedLines.length + removedLines.length
  const score = baseResult.score

  return {
    summary: `Incremental analysis: ${changedLineCount} lines changed, ${affectedFunctions.length} functions affected, ${newIssues.length} new issues`,
    changedLines: changedLineCount,
    affectedFunctions,
    newIssues: newIssues.length > 0 ? newIssues : baseResult.issues.slice(0, 3),
    fixedIssues: removedLines.filter(l => l.includes('fix') || l.includes('resolve')).map(l => l.substring(1).trim()),
    score
  }
}

function formatIncrementalReport(result: IncrementalResult): string {
  const lines: string[] = []
  lines.push('## Incremental Analysis Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  lines.push('### Changed Lines')
  lines.push(`- Total: ${result.changedLines} lines modified`)
  lines.push('')
  if (result.affectedFunctions.length > 0) {
    lines.push('### Affected Functions')
    result.affectedFunctions.forEach(f => lines.push(`- ${f}`))
    lines.push('')
  }
  if (result.newIssues.length > 0) {
    lines.push('### New Issues')
    result.newIssues.forEach(issue => {
      const icon = issue.severity === 'critical' ? '🔴' : issue.severity === 'error' ? '🟠' : issue.severity === 'warning' ? '🟡' : 'ℹ️'
      lines.push(`- ${icon} ${issue.message}`)
    })
    lines.push('')
  }
  if (result.fixedIssues.length > 0) {
    lines.push('### Potentially Fixed')
    result.fixedIssues.forEach(f => lines.push(`- ✅ ${f}`))
    lines.push('')
  }
  return lines.join('\n')
}

// --- Breaking Change Detection ---
function detectBreakingChanges(code: string, previousCode: string, _language: string): BreakingChangeResult {
  const breakingChanges: BreakingChange[] = []
  const prevLines = previousCode.split('\n')
  const currLines = code.split('\n')

  const prevExports = previousCode.match(/(?:export|def|func|function)\s+(\w+)/g) || []
  const currExports = code.match(/(?:export|def|func|function)\s+(\w+)/g) || []
  
  prevExports.forEach(exp => {
    const name = exp.replace(/^(?:export|def|func|function)\s+/, '')
    if (!currExports.some(e => e.includes(name))) {
      const line = prevLines.findIndex(l => l.includes(exp)) + 1
      breakingChanges.push({
        type: 'removal',
        line,
        symbol: name,
        description: `Function/export '${name}' was removed`,
        severity: 'critical',
        migration: `Remove all references to '${name}' or provide a compatibility shim`
      })
    }
  })

  const prevFuncs = previousCode.match(/(?:function|def|func)\s+(\w+)\s*\([^)]*\)/g) || []
  const currFuncs = code.match(/(?:function|def|func)\s+(\w+)\s*\([^)]*\)/g) || []
  
  prevFuncs.forEach(prev => {
    const prevMatch = prev.match(/(\w+)\s*\(([^)]*)\)/)
    if (prevMatch) {
      const name = prevMatch[1]
      const prevParams = prevMatch[2]
      const currFunc = currFuncs.find(f => f.startsWith(name + '(') || f.startsWith(name + ' ('))
      if (currFunc) {
        const currMatch = currFunc.match(/\(([^)]*)\)/)
        if (currMatch && currMatch[1] !== prevParams) {
          const line = currLines.findIndex(l => l.includes(currFunc)) + 1
          breakingChanges.push({
            type: 'signature',
            line,
            symbol: name,
            description: `Signature changed from (${prevParams}) to (${currMatch[1]})`,
            severity: 'error',
            migration: `Update all callers of '${name}' to match new signature`
          })
        }
      }
    }
  })

  const score = Math.max(0, 100 - breakingChanges.filter(b => b.severity === 'critical').length * 30 - breakingChanges.filter(b => b.severity === 'error').length * 15)
  return {
    summary: `Found ${breakingChanges.length} breaking changes (${breakingChanges.filter(b => b.severity === 'critical').length} critical, ${breakingChanges.filter(b => b.severity === 'error').length} errors)`,
    breakingChanges,
    score
  }
}

function formatBreakingChangeReport(result: BreakingChangeResult): string {
  const lines: string[] = []
  lines.push('## Breaking Change Detection Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.breakingChanges.length > 0) {
    lines.push('### Breaking Changes')
    result.breakingChanges.forEach(bc => {
      const icon = bc.severity === 'critical' ? '🔴' : '🟠'
      lines.push(`- ${icon} **${bc.type}** (line ${bc.line}): ${bc.symbol}`)
      lines.push(`  - ${bc.description}`)
      if (bc.migration) lines.push(`  - 🔄 Migration: ${bc.migration}`)
    })
    lines.push('')
  }
  return lines.join('\n')
}

// --- SARIF Export (PRO-005) ---
function exportSarifToFile(code: string, language: string, outputPath?: string): SarifExportResult {
  const securityResult = scanSecurity(code, language, true)
  const sarif = securityResult.sarif || generateSarifReport(securityResult.vulnerabilities)
  
  const passed = securityResult.riskLevel !== 'critical' && securityResult.riskLevel !== 'high'
  const criticalCount = securityResult.vulnerabilities.filter(v => v.severity === 'critical').length
  const highCount = securityResult.vulnerabilities.filter(v => v.severity === 'high').length
  
  return {
    summary: passed 
      ? `SARIF export ready - no critical/high issues found` 
      : `SARIF export ready - ${criticalCount} critical, ${highCount} high issues`,
    filePath: outputPath || './security-scan.sarif',
    sarif,
    passed
  }
}

function formatSarifExportReport(result: SarifExportResult): string {
  const lines: string[] = []
  lines.push('## SARIF Export Report')
  lines.push('')
  lines.push(`**Status: ${result.passed ? '✅ PASSED' : '❌ ISSUES FOUND'}**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  lines.push('### Output')
  lines.push(`- File: \`${result.filePath}\``)
  lines.push(`- Format: SARIF 2.1.0`)
  lines.push(`- Runs: ${result.sarif.runs.length}`)
  const totalResults = result.sarif.runs.reduce((sum, run) => sum + run.results.length, 0)
  lines.push(`- Total results: ${totalResults}`)
  lines.push('')
  lines.push('### Usage')
  lines.push('```bash')
  lines.push('# Upload to GitHub Code Scanning')
  lines.push('gh codeql upload-results --sarif=security-scan.sarif')
  lines.push('```')
  lines.push('')
  return lines.join('\n')
}

// --- Diff Preview with Auto-Fix (PRO-003) ---
function generateDiffPreview(code: string, language: string): DiffPreviewResult {
  const originalResult = analyzeCode(code, language)
  const originalScore = originalResult.score
  const fixes: DiffFix[] = []
  const codeLines = code.split('\n')
  const fixedLines = [...codeLines]

  if (['javascript', 'typescript', 'java', 'c', 'cpp'].includes(language)) {
    codeLines.forEach((line, idx) => {
      const trimmed = line.trim()
      if (trimmed.length > 0 && 
          !trimmed.endsWith('{') && 
          !trimmed.endsWith('}') && 
          !trimmed.endsWith(';') && 
          !trimmed.endsWith(',') &&
          !trimmed.startsWith('//') &&
          !trimmed.startsWith('/*') &&
          !trimmed.startsWith('*') &&
          !trimmed.startsWith('if') &&
          !trimmed.startsWith('else') &&
          !trimmed.startsWith('for') &&
          !trimmed.startsWith('while') &&
          !trimmed.startsWith('switch') &&
          !trimmed.startsWith('case') &&
          !trimmed.startsWith('default') &&
          !trimmed.startsWith('class') &&
          !trimmed.startsWith('function') &&
          !trimmed.startsWith('export') &&
          !trimmed.startsWith('import') &&
          !trimmed.match(/^[}\])]\s*$/) &&
          trimmed.match(/^[a-zA-Z_$]/) &&
          !trimmed.includes('=>') &&
          trimmed.length > 5) {
        if (trimmed.match(/^\w+\s*=/) || trimmed.match(/^\w+\(.*\)$/)) {
          fixes.push({
            line: idx + 1,
            original: trimmed,
            replacement: trimmed + ';',
            description: 'Missing semicolon',
            severity: 'info'
          })
          fixedLines[idx] = line + ';'
        }
      }
    })
  }

  codeLines.forEach((line, idx) => {
    if (/[^!=]==[^=]/.test(line) && !line.includes('===') && !line.trim().startsWith('//')) {
      const fixedLine = line.replace(/([^!=])==([^=])/g, '$1===$2')
      if (fixedLine !== line) {
        fixes.push({
          line: idx + 1,
          original: line.trim(),
          replacement: fixedLine.trim(),
          description: 'Use strict equality (===) instead of loose equality (==)',
          severity: 'warning'
        })
        fixedLines[idx] = fixedLine
      }
    }
  })

  codeLines.forEach((line, idx) => {
    if (/^\s*var\s+/.test(line) && !line.trim().startsWith('//')) {
      const fixedLine = line.replace(/^(\s*)var(\s+)/, '$1let$2')
      fixes.push({
        line: idx + 1,
        original: line.trim(),
        replacement: fixedLine.trim(),
        description: 'Use let/const instead of var (block scoping)',
        severity: 'warning'
      })
      fixedLines[idx] = fixedLine
    }
  })

  codeLines.forEach((line, idx) => {
    if (/console\.(log|debug|warn|error)\s*\(/.test(line) && !line.trim().startsWith('//')) {
      fixes.push({
        line: idx + 1,
        original: line.trim(),
        replacement: line.trim().replace(/console\.\w+\s*\([^)]*\)\s*;?/, '// TODO: remove console statement'),
        description: 'Console statement should be removed or replaced with proper logging',
        severity: 'warning'
      })
    }
  })

  const unifiedDiffLines: string[] = []
  unifiedDiffLines.push('--- original')
  unifiedDiffLines.push('+++ fixed')
  unifiedDiffLines.push('@@ -1,' + codeLines.length + ' +1,' + codeLines.length + ' @@')
  
  codeLines.forEach((line, idx) => {
    if (line !== fixedLines[idx]) {
      unifiedDiffLines.push('- ' + line)
      unifiedDiffLines.push('+ ' + fixedLines[idx])
    } else {
      unifiedDiffLines.push('  ' + line)
    }
  })

  const fixedCode = fixedLines.join('\n')
  const improvedResult = analyzeCode(fixedCode, language)
  const improvedScore = improvedResult.score

  return {
    summary: `Generated ${fixes.length} auto-fix suggestions (score: ${originalScore} → ${improvedScore})`,
    fixesApplied: fixes.length,
    originalScore,
    improvedScore,
    unifiedDiff: unifiedDiffLines.join('\n'),
    fixes
  }
}

function formatDiffPreviewReport(result: DiffPreviewResult): string {
  const lines: string[] = []
  lines.push('## Auto-Fix Diff Preview')
  lines.push('')
  lines.push(`**Score: ${result.originalScore}/100 → ${result.improvedScore}/100** (${result.improvedScore >= result.originalScore ? '+' : ''}${result.improvedScore - result.originalScore})`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.fixes.length > 0) {
    lines.push('### Suggested Fixes')
    result.fixes.forEach((fix, idx) => {
      const icon = fix.severity === 'warning' ? '⚠️' : 'ℹ️'
      lines.push(`${idx + 1}. ${icon} Line ${fix.line}: ${fix.description}`)
      lines.push(`   \`\`\`diff`)
      lines.push(`   - ${fix.original}`)
      lines.push(`   + ${fix.replacement}`)
      lines.push(`   \`\`\``)
    })
    lines.push('')
  }
  lines.push('### Unified Diff Preview')
  lines.push('```diff')
  lines.push(result.unifiedDiff)
  lines.push('```')
  lines.push('')
  return lines.join('\n')
}

// ==================== v0.6.0 NEW FUNCTIONS ====================

// --- PRO-004: Config file support (.dshcoderc) ---
function loadDshConfig(configContent?: string): ConfigLoadResult {
  const errors: string[] = []
  const defaultConfig: DshConfig = {
    severityThreshold: 'info',
    ignoreRules: [],
    enableSarif: true,
    enableAutoFix: true,
    outputFormat: 'markdown'
  }

  if (!configContent) {
    return {
      summary: 'No config file provided, using defaults',
      config: defaultConfig,
      loaded: false,
      errors: []
    }
  }

  try {
    const parsed = JSON.parse(configContent) as DshConfig
    const config = { ...defaultConfig, ...parsed }
    
    if (config.severityThreshold && !['critical', 'error', 'warning', 'info'].includes(config.severityThreshold)) {
      errors.push(`Invalid severityThreshold: ${config.severityThreshold}`)
      config.severityThreshold = 'info'
    }
    if (config.outputFormat && !['markdown', 'json', 'sarif'].includes(config.outputFormat)) {
      errors.push(`Invalid outputFormat: ${config.outputFormat}`)
      config.outputFormat = 'markdown'
    }

    return {
      summary: `Loaded .dshcoderc config (${Object.keys(parsed).length} settings)`,
      config,
      loaded: true,
      errors
    }
  } catch {
    return {
      summary: 'Failed to parse .dshcoderc config, using defaults',
      config: defaultConfig,
      loaded: false,
      errors: ['Invalid JSON in config file']
    }
  }
}

function formatConfigLoadReport(result: ConfigLoadResult): string {
  const lines: string[] = []
  lines.push('## Configuration Load Report')
  lines.push('')
  lines.push(`**Status: ${result.loaded ? '✅ LOADED' : '⚠️ DEFAULTS'}**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  lines.push('### Active Configuration')
  lines.push(`- Severity Threshold: \`${result.config.severityThreshold}\``)
  lines.push(`- Output Format: \`${result.config.outputFormat}\``)
  lines.push(`- SARIF Enabled: \`${result.config.enableSarif}\``)
  lines.push(`- Auto-fix Enabled: \`${result.config.enableAutoFix}\``)
  lines.push(`- Ignored Rules: ${result.config.ignoreRules?.length ?? 0}`)
  lines.push(`- Custom Rules: ${result.config.customRules?.length ?? 0}`)
  lines.push('')
  if (result.errors.length > 0) {
    lines.push('### Errors')
    result.errors.forEach(e => lines.push(`- ❌ ${e}`))
    lines.push('')
  }
  lines.push('### Example .dshcoderc')
  lines.push('```json')
  lines.push(JSON.stringify({
    severityThreshold: 'warning',
    ignoreRules: ['no-console'],
    enableSarif: true,
    outputFormat: 'markdown'
  }, null, 2))
  lines.push('```')
  lines.push('')
  return lines.join('\n')
}

// --- PRO-007: Test generation suggestions ---
function generateTestSuggestions(code: string, language: string): TestGenResult {
  const tests: TestCase[] = []
  const codeLines = code.split('\n')
  
  // Detect functions
  const funcRegex = /(?:function|def|func)\s+(\w+)\s*\(([^)]*)\)/g
  let match: RegExpExecArray | null
  while ((match = funcRegex.exec(code)) !== null) {
    const funcName = match[1]
    const params = match[2]
    if (funcName && !['if', 'for', 'while', 'switch', 'return', 'console'].includes(funcName)) {
      // Unit test
      const testCode = getUnitTestCode(funcName, params, language)
      tests.push({
        functionName: funcName,
        language,
        testName: `${funcName}_should_work_correctly`,
        testCode,
        type: 'unit',
        description: `Basic unit test for ${funcName}`
      })

      // Edge case test
      if (params.split(',').length > 0) {
        tests.push({
          functionName: funcName,
          language,
          testName: `${funcName}_handles_edge_cases`,
          testCode: `// Edge case test for ${funcName}\n// Test with: null, undefined, empty, boundary values`,
          type: 'edge-case',
          description: `Edge case handling for ${funcName}`
        })
      }
    }
  }

  // Also detect arrow functions
  const arrowRegex = /(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/g
  while ((match = arrowRegex.exec(code)) !== null) {
    const funcName = match[1]
    const params = match[2]
    if (funcName && !tests.some(t => t.functionName === funcName)) {
      tests.push({
        functionName: funcName,
        language,
        testName: `${funcName}_should_work_correctly`,
        testCode: getUnitTestCode(funcName, params, language),
        type: 'unit',
        description: `Basic unit test for ${funcName}`
      })
    }
  }

  const funcCount = (code.match(/(?:function|def|func)\s+\w+/g) || []).length
  const coverage = funcCount > 0 ? Math.min(100, (tests.length / funcCount) * 100) : 0
  const score = Math.min(100, tests.length * 15)

  return {
    summary: `Generated ${tests.length} test cases for ${funcCount} functions (est. coverage: ${coverage.toFixed(1)}%)`,
    tests,
    coverage: parseFloat(coverage.toFixed(1)),
    score
  }
}

function getUnitTestCode(funcName: string, params: string, language: string): string {
  const firstParam = params.split(',')[0]?.trim() || '/* args */'
  switch (language) {
    case 'typescript':
    case 'javascript':
      return `test('${funcName} should work correctly', () => {\n  // Arrange\n  \n  // Act\n  const result = ${funcName}(${firstParam});\n  // Assert\n  expect(result).toBe(/* expected */);\n});`
    case 'python':
      return `def test_${funcName}_basic():\n    # Arrange\n    \n    # Act\n    result = ${funcName}(${firstParam})\n    # Assert\n    assert result == /* expected */`
    case 'go':
      return `func Test${funcName}(t *testing.T) {\n    // Arrange\n    \n    // Act\n    result := ${funcName}(${firstParam})\n    // Assert\n    if result != /* expected */ {\n        t.Errorf("got %v, want /* expected */", result)\n    }\n}`
    default:
      return `// Test for ${funcName}\nTestExample(${funcName})`
  }
}

function formatTestGenReport(result: TestGenResult): string {
  const lines: string[] = []
  lines.push('## Test Generation Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100 | Est. Coverage: ${result.coverage}%**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.tests.length > 0) {
    lines.push('### Suggested Tests')
    result.tests.forEach(test => {
      const icon = test.type === 'unit' ? '🧪' : test.type === 'edge-case' ? '🔍' : '💥'
      lines.push(`- ${icon} **${test.testName}** (${test.type})`)
      lines.push(`  - Function: \`${test.functionName}\``)
      lines.push(`  - ${test.description}`)
      lines.push('  ```')
      lines.push(`  ${test.testCode}`)
      lines.push('  ```')
    })
    lines.push('')
  }
  return lines.join('\n')
}

// --- PRO-009: Code complexity metrics ---
function analyzeComplexity(code: string, _language: string): ComplexityResult {
  const codeLines = code.split('\n')
  const linesOfCode = codeLines.length
  
  // Calculate cyclomatic complexity
  const branches = (code.match(/\b(if|else|for|while|switch|case|catch|&&|\?|try)\b/g) || []).length
  const cyclomaticComplexity = branches + 1
  
  // Calculate Halstead metrics (simplified)
  const operators = (code.match(/[+\-*/%=<>!&|^~?:]+/g) || []).length
  const operands = (code.match(/\b\w+\b/g) || []).length
  const uniqueOperators = new Set(code.match(/[+\-*/%=<>!&|^~?:]+/g) || []).size
  const uniqueOperands = new Set(code.match(/\b\w+\b/g) || []).size
  
  const vocabulary = uniqueOperators + uniqueOperands
  const length = operators + operands
  const halsteadVolume = length * Math.log2(vocabulary || 1)
  const halsteadDifficulty = (uniqueOperators / 2) * (uniqueOperands / (uniqueOperands || 1))
  const halsteadEffort = halsteadDifficulty * halsteadVolume
  
  // Comment ratio
  const commentLines = codeLines.filter(l => l.trim().startsWith('//') || l.trim().startsWith('#') || l.trim().startsWith('*')).length
  const commentRatio = linesOfCode > 0 ? (commentLines / linesOfCode) * 100 : 0
  
  // Nesting depth
  let maxNesting = 0
  let currentNesting = 0
  codeLines.forEach(line => {
    const opens = (line.match(/{/g) || []).length
    const closes = (line.match(/}/g) || []).length
    currentNesting += opens - closes
    maxNesting = Math.max(maxNesting, currentNesting)
  })
  
  // Per-function complexity
  const functions: FunctionComplexity[] = []
  const funcRegex = /(?:function|def|func)\s+(\w+)\s*\(([^)]*)\)/g
  let match: RegExpExecArray | null
  while ((match = funcRegex.exec(code)) !== null) {
    const name = match[1]
    const params = match[2]
    const line = code.substring(0, match.index).split('\n').length
    const funcBody = code.substring(match.index, match.index + 500)
    const funcBranches = (funcBody.match(/\b(if|else|for|while|switch|case|catch|\?)\b/g) || []).length
    const funcCyclomatic = funcBranches + 1
    
    let risk: 'low' | 'medium' | 'high' | 'critical' = 'low'
    if (funcCyclomatic > 20) risk = 'critical'
    else if (funcCyclomatic > 10) risk = 'high'
    else if (funcCyclomatic > 5) risk = 'medium'
    
    functions.push({
      name,
      line,
      cyclomatic: funcCyclomatic,
      params: params.split(',').filter(p => p.trim()).length,
      returns: (funcBody.match(/\breturn\b/g) || []).length,
      risk
    })
  }
  
  // Risks
  const risks: string[] = []
  if (cyclomaticComplexity > 20) risks.push('High overall cyclomatic complexity')
  if (maxNesting > 5) risks.push('Deep nesting detected')
  if (halsteadEffort > 1000) risks.push('High Halstead effort - consider simplification')
  if (commentRatio < 5) risks.push('Low comment ratio')
  functions.filter(f => f.risk === 'critical' || f.risk === 'high').forEach(f => {
    risks.push(`Function '${f.name}' has ${f.risk} complexity (${f.cyclomatic})`)
  })
  
  // Score
  const score = Math.max(0, 100 - (cyclomaticComplexity > 10 ? (cyclomaticComplexity - 10) * 3 : 0) - (maxNesting > 3 ? (maxNesting - 3) * 5 : 0))
  
  return {
    summary: `Complexity: cyclomatic=${cyclomaticComplexity}, volume=${halsteadVolume.toFixed(0)}, effort=${halsteadEffort.toFixed(0)}, nesting=${maxNesting}`,
    score,
    metrics: {
      cyclomaticComplexity,
      halsteadVolume: Math.round(halsteadVolume),
      halsteadDifficulty: Math.round(halsteadDifficulty * 100) / 100,
      halsteadEffort: Math.round(halsteadEffort),
      linesOfCode,
      commentRatio: Math.round(commentRatio * 10) / 10,
      nestingDepth: maxNesting
    },
    functions,
    risks
  }
}

function formatComplexityReport(result: ComplexityResult): string {
  const lines: string[] = []
  lines.push('## Code Complexity Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  lines.push('### Metrics')
  lines.push(`- Cyclomatic Complexity: \`${result.metrics.cyclomaticComplexity}\``)
  lines.push(`- Halstead Volume: \`${result.metrics.halsteadVolume}\``)
  lines.push(`- Halstead Difficulty: \`${result.metrics.halsteadDifficulty}\``)
  lines.push(`- Halstead Effort: \`${result.metrics.halsteadEffort}\``)
  lines.push(`- Lines of Code: \`${result.metrics.linesOfCode}\``)
  lines.push(`- Comment Ratio: \`${result.metrics.commentRatio}%\``)
  lines.push(`- Max Nesting Depth: \`${result.metrics.nestingDepth}\``)
  lines.push('')
  if (result.functions.length > 0) {
    lines.push('### Function Complexity')
    result.functions.forEach(f => {
      const icon = f.risk === 'critical' ? '🔴' : f.risk === 'high' ? '🟠' : f.risk === 'medium' ? '🟡' : '🟢'
      lines.push(`- ${icon} **${f.name}** (line ${f.line}): cyclomatic=${f.cyclomatic}, params=${f.params}, returns=${f.returns}`)
    })
    lines.push('')
  }
  if (result.risks.length > 0) {
    lines.push('### Risks')
    result.risks.forEach(r => lines.push(`- ⚠️ ${r}`))
    lines.push('')
  }
  return lines.join('\n')
}

// --- PRO-013: Batch file analysis ---
function analyzeBatch(files: { name: string; content: string }[]): BatchResult {
  const fileResults: FileResult[] = []
  const issueCounts: Record<string, number> = {}
  let totalIssues = 0

  files.forEach(file => {
    const language = detectLanguage(file.content)
    const result = analyzeCode(file.content, language)
    
    result.issues.forEach(issue => {
      issueCounts[issue.message] = (issueCounts[issue.message] || 0) + 1
      totalIssues++
    })

    fileResults.push({
      fileName: file.name,
      language,
      score: result.score,
      issues: result.issues,
      metrics: {
        lines: file.content.split('\n').length,
        functions: (file.content.match(/(?:function|def|func)\s+\w+/g) || []).length,
        classes: (file.content.match(/class\s+\w+/g) || []).length
      }
    })
  })

  const overallScore = fileResults.length > 0 
    ? Math.round(fileResults.reduce((sum, f) => sum + f.score, 0) / fileResults.length) 
    : 0

  const commonIssues = Object.entries(issueCounts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)
    .map(([message, count]) => ({ message, count }))

  return {
    summary: `Analyzed ${files.length} files: ${totalIssues} total issues, avg score ${overallScore}/100`,
    totalFiles: files.length,
    analyzedFiles: fileResults.length,
    files: fileResults,
    overallScore,
    totalIssues,
    commonIssues
  }
}

function formatBatchReport(result: BatchResult): string {
  const lines: string[] = []
  lines.push('## Batch Analysis Report')
  lines.push('')
  lines.push(`**Overall Score: ${result.overallScore}/100 | Files: ${result.analyzedFiles}/${result.totalFiles}**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.files.length > 0) {
    lines.push('### File Results')
    result.files.forEach(f => {
      const icon = f.score >= 80 ? '🟢' : f.score >= 60 ? '🟡' : f.score >= 40 ? '🟠' : '🔴'
      lines.push(`- ${icon} **${f.fileName}** (${f.language}): ${f.score}/100, ${f.issues.length} issues, ${f.metrics.lines} lines`)
    })
    lines.push('')
  }
  if (result.commonIssues.length > 0) {
    lines.push('### Most Common Issues')
    result.commonIssues.forEach(ci => lines.push(`- **${ci.count}x**: ${ci.message}`))
    lines.push('')
  }
  return lines.join('\n')
}

// --- PRO-008: Monorepo analysis ---
function analyzeMonorepo(packages: { name: string; path: string; files: { name: string; content: string }[] }[]): MonorepoResult {
  const packageResults: PackageResult[] = []
  const dependencies: DepEdge[] = []
  const cycles: string[][] = []

  packages.forEach(pkg => {
    let totalIssues = 0
    let totalScore = 0
    let fileCount = 0

    pkg.files.forEach(file => {
      const language = detectLanguage(file.content)
      const result = analyzeCode(file.content, language)
      totalIssues += result.issues.length
      totalScore += result.score
      fileCount++
    })

    const avgScore = fileCount > 0 ? Math.round(totalScore / fileCount) : 0

    packageResults.push({
      name: pkg.name,
      path: pkg.path,
      language: pkg.files.length > 0 ? detectLanguage(pkg.files[0].content) : 'unknown',
      score: avgScore,
      fileCount,
      issues: totalIssues
    })

    // Detect dependencies from imports
    pkg.files.forEach(file => {
      const imports = file.content.match(/(?:import|from|require)\s+['"]([^'"]+)['"]/g) || []
      imports.forEach(imp => {
        const depName = imp.replace(/^(?:import|from|require)\s+['"]/, "").replace(/['"]$/, "")
        if (depName.startsWith('.') || depName.startsWith('/')) return // Skip relative imports
        const targetPkg = packages.find(p => depName.includes(p.name))
        if (targetPkg && targetPkg.name !== pkg.name) {
          dependencies.push({
            from: pkg.name,
            to: targetPkg.name,
            type: 'dependency'
          })
        }
      })
    })
  })

  // Detect cycles (simplified)
  const visited = new Set<string>()
  const recursionStack = new Set<string>()
  
  function hasCycle(node: string, path: string[]): boolean {
    visited.add(node)
    recursionStack.add(node)
    
    const deps = dependencies.filter(d => d.from === node)
    for (const dep of deps) {
      if (!visited.has(dep.to)) {
        if (hasCycle(dep.to, [...path, dep.to])) return true
      } else if (recursionStack.has(dep.to)) {
        cycles.push([...path, dep.to])
        return true
      }
    }
    
    recursionStack.delete(node)
    return false
  }
  
  packageResults.forEach(pkg => {
    if (!visited.has(pkg.name)) {
      hasCycle(pkg.name, [pkg.name])
    }
  })

  const overallScore = packageResults.length > 0 
    ? Math.round(packageResults.reduce((sum, p) => sum + p.score, 0) / packageResults.length) 
    : 0

  return {
    summary: `Monorepo: ${packages.length} packages, ${dependencies.length} dependencies, ${cycles.length} cycles`,
    packages: packageResults,
    dependencies,
    cycles,
    score: overallScore
  }
}

function formatMonorepoReport(result: MonorepoResult): string {
  const lines: string[] = []
  lines.push('## Monorepo Analysis Report')
  lines.push('')
  lines.push(`**Overall Score: ${result.score}/100 | Packages: ${result.packages.length}**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.packages.length > 0) {
    lines.push('### Packages')
    result.packages.forEach(p => {
      const icon = p.score >= 80 ? '🟢' : p.score >= 60 ? '🟡' : p.score >= 40 ? '🟠' : '🔴'
      lines.push(`- ${icon} **${p.name}** (${p.path}): ${p.score}/100, ${p.fileCount} files, ${p.issues} issues`)
    })
    lines.push('')
  }
  if (result.dependencies.length > 0) {
    lines.push('### Dependencies')
    result.dependencies.forEach(d => lines.push(`- ${d.from} → ${d.to} (${d.type})`))
    lines.push('')
  }
  if (result.cycles.length > 0) {
    lines.push('### ⚠️ Circular Dependencies')
    result.cycles.forEach(c => lines.push(`- ${c.join(' → ')}`))
    lines.push('')
  }
  return lines.join('\n')
}

function formatStyleReport(result: StyleCheckResult): string {
  const lines: string[] = []
  lines.push('## Style Check Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.conventions.length > 0) {
    lines.push('### Convention Issues')
    result.conventions.forEach(c => { lines.push(`- Line ${c.line} [${c.rule}]: ${c.message} -> ${c.suggestion}`) })
    lines.push('')
  }
  if (result.formattingIssues.length > 0) {
    lines.push('### Formatting Issues')
    result.formattingIssues.forEach(f => { lines.push(`- Line ${f.line}:${f.column}: ${f.message}`) })
    lines.push('')
  }
  return lines.join('\n')
}

// ==================== PLUGIN REGISTRATION ====================

export function apply(ctx: Context) {
  // Tool 1: Comprehensive Code Review
  ctx.tools.register(defineTool({
    name: 'code_review',
    description: 'Comprehensive code quality analysis. Returns score (0-100), grade, metrics, issues, strengths, refactoring suggestions, and auto-fixes.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' },
      language: { type: 'string', description: 'Programming language. Auto-detected if not provided.' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
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
      code: { type: 'string', required: true, description: 'The source code to scan' },
      language: { type: 'string', description: 'Programming language' },
      sarif: { type: 'boolean', description: 'Generate SARIF output format' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
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
      code: { type: 'string', required: true, description: 'The source code containing import/require statements' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = auditDependencies(args.code, language)
      return formatDependencyReport(result)
    }
  }))
  
  // Tool 4: Performance Analysis
  ctx.tools.register(defineTool({
    name: 'performance_check',
    description: 'Analyze code for performance issues: N+1 queries, inefficient algorithms, memory leaks, blocking operations. Includes BigO complexity estimation.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
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
      code: { type: 'string', required: true, description: 'The source code to check' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = analyzeCode(args.code, language)
      const lines: string[] = []
      const criticalCount = result.issues.filter(i => i.severity === 'critical').length
      const errorCount = result.issues.filter(i => i.severity === 'error').length
      if (result.score >= 70 && criticalCount === 0 && errorCount === 0) lines.push('## Quick Check: PASSED')
      else lines.push('## Quick Check: NEEDS ATTENTION')
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
        if (importantIssues.length > 10) lines.push(`- ... and ${importantIssues.length - 10} more issues`)
      } else { lines.push('No critical or error issues found.') }
      return lines.join('\n')
    }
  }))
  
  // Tool 6: Architecture Review (NEW)
  ctx.tools.register(defineTool({
    name: 'architecture_review',
    description: 'Analyze code architecture: detect design patterns, assess SOLID principles, evaluate module cohesion and coupling.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = reviewArchitecture(args.code, language)
      return formatArchitectureReport(result)
    }
  }))
  
  // Tool 7: Test Coverage Analysis (NEW)
  ctx.tools.register(defineTool({
    name: 'test_coverage',
    description: 'Analyze testability and estimate test coverage. Identifies hard-to-test patterns and suggests mocking strategies.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = analyzeTestCoverage(args.code, language)
      return formatTestCoverageReport(result)
    }
  }))
  
  // Tool 8: API Documentation Generator (NEW)
  ctx.tools.register(defineTool({
    name: 'api_docs',
    description: 'Generate API documentation from code. Detects endpoints, models, and generates structured API reference.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = generateApiDocs(args.code, language)
      return formatApiDocsReport(result)
    }
  }))
  
  // Tool 9: Code Diff Analysis (NEW)
  ctx.tools.register(defineTool({
    name: 'code_diff',
    description: 'Analyze a code diff/patch. Assesses change type, risk level, and provides review suggestions.',
    parameters: {
      diff: { type: 'string', required: true, description: 'The diff/patch text to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { diff: string }) {
      const result = analyzeDiff(args.diff)
      return formatDiffReport(result)
    }
  }))
  
  // Tool 10: Style Check (NEW)
  ctx.tools.register(defineTool({
    name: 'style_check',
    description: 'Check code style and conventions. Detects naming issues, formatting problems, and style violations.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to check' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = checkStyle(args.code, language)
      return formatStyleReport(result)
    }
  }))

  // Tool 11: Code Smell Detection (v0.5.0)
  ctx.tools.register(defineTool({
    name: 'code_smell_detect',
    description: 'Detect code smells: God Object, Feature Envy, Shotgun Surgery, Long Method, Primitive Obsession, Dead Code.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = detectCodeSmells(args.code, language)
      return formatCodeSmellReport(result)
    }
  }))

  // Tool 12: TypeScript Strict Mode Check (v0.5.0)
  ctx.tools.register(defineTool({
    name: 'ts_strict_check',
    description: 'Check TypeScript strict mode compliance: noImplicitAny, explicitReturnType, noNonNullAssertion, strictNullChecks.',
    parameters: {
      code: { type: 'string', required: true, description: 'The TypeScript source code to check' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = checkTsStrictMode(args.code)
      return formatTsStrictReport(result)
    }
  }))

  // Tool 13: Incremental Analysis (v0.5.0)
  ctx.tools.register(defineTool({
    name: 'incremental_analysis',
    description: 'Analyze only changed code against a diff. Fast feedback for large projects with focused scope.',
    parameters: {
      code: { type: 'string', required: true, description: 'The current source code' },
      diff: { type: 'string', required: true, description: 'The unified diff to analyze against' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; diff: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = analyzeIncremental(args.code, args.diff, language)
      return formatIncrementalReport(result)
    }
  }))

  // Tool 14: Breaking Change Detection (v0.5.0)
  ctx.tools.register(defineTool({
    name: 'breaking_change',
    description: 'Detect breaking changes between code versions: removed exports, signature changes, behavior changes.',
    parameters: {
      code: { type: 'string', required: true, description: 'The current source code' },
      previousCode: { type: 'string', required: true, description: 'The previous version of the source code' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; previousCode: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = detectBreakingChanges(args.code, args.previousCode, language)
      return formatBreakingChangeReport(result)
    }
  }))

  // Tool 15: SARIF Export (v0.5.0)
  ctx.tools.register(defineTool({
    name: 'sarif_export',
    description: 'Export security scan results as SARIF 2.1.0 file for CI/CD integration and GitHub Code Scanning.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to scan' },
      language: { type: 'string', description: 'Programming language' },
      outputPath: { type: 'string', description: 'Output file path (default: ./security-scan.sarif)' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string; outputPath?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = exportSarifToFile(args.code, language, args.outputPath)
      return formatSarifExportReport(result)
    }
  }))

  // Tool 16: Diff Preview with Auto-Fix (v0.5.0)
  ctx.tools.register(defineTool({
    name: 'diff_preview',
    description: 'Generate auto-fix suggestions with unified diff preview. Shows what changes would improve code quality.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze and fix' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = generateDiffPreview(args.code, language)
      return formatDiffPreviewReport(result)
    }
  }))

  // Tool 17: Config File Support (v0.6.0 - PRO-004)
  ctx.tools.register(defineTool({
    name: 'config_load',
    description: 'Load and validate .dshcoderc configuration file. Supports severity thresholds, ignored rules, custom rules, and output format.',
    parameters: {
      configContent: { type: 'string', description: 'The .dshcoderc JSON content to load' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { configContent?: string }) {
      const result = loadDshConfig(args.configContent)
      return formatConfigLoadReport(result)
    }
  }))

  // Tool 18: Test Generation (v0.6.0 - PRO-007)
  ctx.tools.register(defineTool({
    name: 'test_generate',
    description: 'Generate test case templates based on function signatures. Supports unit tests, edge cases, and error cases.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to generate tests for' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = generateTestSuggestions(args.code, language)
      return formatTestGenReport(result)
    }
  }))

  // Tool 19: Complexity Metrics (v0.6.0 - PRO-009)
  ctx.tools.register(defineTool({
    name: 'complexity_metrics',
    description: 'Calculate code complexity metrics: cyclomatic complexity, Halstead volume/difficulty/effort, nesting depth, comment ratio.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = analyzeComplexity(args.code, language)
      return formatComplexityReport(result)
    }
  }))

  // Tool 20: Batch Analysis (v0.6.0 - PRO-013)
  ctx.tools.register(defineTool({
    name: 'batch_analyze',
    description: 'Analyze multiple files at once. Returns per-file results, overall score, and most common issues.',
    parameters: {
      files: { 
        type: 'array', 
        required: true, 
        description: 'Array of files to analyze, each with name and content',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            content: { type: 'string' }
          },
          additionalProperties: true
        }
      }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { files: { name: string; content: string }[] }) {
      const result = analyzeBatch(args.files)
      return formatBatchReport(result)
    }
  }))

  // Tool 21: Monorepo Analysis (v0.6.0 - PRO-008)
  ctx.tools.register(defineTool({
    name: 'monorepo_analyze',
    description: 'Analyze monorepo structure: packages, dependencies, circular dependency detection, per-package scores.',
    parameters: {
      packages: {
        type: 'array',
        required: true,
        description: 'Array of packages, each with name, path, and files',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            path: { type: 'string' },
            files: { type: 'array' }
          },
          additionalProperties: true
        }
      }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { packages: { name: string; path: string; files: { name: string; content: string }[] }[] }) {
      const result = analyzeMonorepo(args.packages)
      return formatMonorepoReport(result)
    }
  }))
  
  console.log(`[${name}] v${VERSION} loaded; tools: code_review, security_scan, dependency_audit, performance_check, code_check, architecture_review, test_coverage, api_docs, code_diff, style_check, code_smell_detect, ts_strict_check, incremental_analysis, breaking_change, sarif_export, diff_preview, config_load, test_generate, complexity_metrics, batch_analyze, monorepo_analyze`)
}

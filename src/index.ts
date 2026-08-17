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

// ==================== v0.7.0 NEW TYPES ====================

// PRO-010: Multi-language support
interface MultiLangResult {
  summary: string
  language: string
  confidence: number
  features: LanguageFeature[]
  issues: LanguageSpecificIssue[]
  score: number
}

interface LanguageFeature {
  name: string
  supported: boolean
  description: string
}

interface LanguageSpecificIssue {
  line: number
  rule: string
  message: string
  severity: Severity
  fix: string
  docs?: string
}

// PRO-011: CI/CD integration
interface CiCdResult {
  summary: string
  workflow: string
  triggers: string[]
  steps: WorkflowStep[]
  filename: string
}

interface WorkflowStep {
  name: string
  action?: string
  with?: Record<string, string>
  run?: string
  uses?: string
}

// PRO-012: Custom rule engine
interface CustomRuleResult {
  summary: string
  rulesLoaded: number
  matches: RuleMatch[]
  errors: string[]
}

interface RuleMatch {
  ruleId: string
  line: number
  message: string
  severity: Severity
  context: string
}

// Code duplication detection
interface DuplicationResult {
  summary: string
  duplications: CodeDuplicate[]
  score: number
  linesWasted: number
}

interface CodeDuplicate {
  type: 'exact' | 'similar' | 'structural'
  sourceFile: string
  sourceLine: number
  targetFile: string
  targetLine: number
  lines: number
  similarity: number
  suggestion: string
}

// Refactoring suggestions
interface RefactorResult {
  summary: string
  refactorings: Refactoring[]
  score: number
  potentialImprovement: number
}

interface Refactoring {
  type: 'extract-method' | 'extract-class' | 'inline' | 'move-method' | 'rename' | 'split' | 'merge'
  line: number
  target: string
  description: string
  effort: 'low' | 'medium' | 'high'
  impact: 'low' | 'medium' | 'high'
  suggestion: string
}

// Naming convention check
interface NamingResult {
  summary: string
  score: number
  conventions: NamingConvention[]
  violations: NamingViolation[]
}

interface NamingConvention {
  type: string
  pattern: string
  description: string
  examples: string[]
}

interface NamingViolation {
  line: number
  symbol: string
  convention: string
  message: string
  suggestion: string
  severity: Severity
}

// ==================== v0.8.0 NEW TYPES ====================

// Security patterns (deep detection)
interface SecurityPatternResult {
  summary: string
  score: number
  vulnerabilities: SecurityPattern[]
  owaspMapping: Record<string, string>
}

interface SecurityPattern {
  type: 'sqli' | 'xss' | 'csrf' | 'path-traversal' | 'command-injection' | 'ssrf' | 'idor' | 'secrets'
  line: number
  message: string
  severity: Severity
  cwe: string
  owasp: string
  fix: string
  context: string
}

// Performance tips
interface PerformanceTipResult {
  summary: string
  score: number
  tips: PerformanceTip[]
  bottlenecks: string[]
}

interface PerformanceTip {
  line: number
  type: 'algorithm' | 'io' | 'memory' | 'caching' | 'lazy' | 'batch' | 'concurrency'
  message: string
  severity: Severity
  impact: 'low' | 'medium' | 'high'
  suggestion: string
  example?: string
}

// Documentation check
interface DocumentationResult {
  summary: string
  score: number
  coverage: DocCoverage[]
  missing: string[]
  suggestions: string[]
}

interface DocCoverage {
  symbol: string
  line: number
  hasDoc: boolean
  paramsDocumented: boolean
  returnsDocumented: boolean
  examplesProvided: boolean
}

// Import organization
interface ImportOrganizeResult {
  summary: string
  score: number
  current: string[]
  organized: string[]
  groups: ImportGroup[]
  removals: string[]
}

interface ImportGroup {
  name: string
  imports: string[]
  order: number
}

// Error handling patterns
interface ErrorHandlingResult {
  summary: string
  score: number
  patterns: ErrorPattern[]
  coverage: number
  suggestions: string[]
}

interface ErrorPattern {
  line: number
  type: 'missing-catch' | 'swallowed' | 'generic' | 'no-fallback' | 'incomplete' | 'proper'
  message: string
  severity: Severity
  fix: string
}

// API design review
interface ApiDesignResult {
  summary: string
  score: number
  endpoints: EndpointDesign[]
  restfulness: number
  consistency: number
  suggestions: string[]
}

interface EndpointDesign {
  name: string
  line: number
  method: string
  path: string
  hasValidation: boolean
  hasErrorHandling: boolean
  hasPagination: boolean
  hasAuth: boolean
  score: number
}

// ==================== v0.9.0 NEW TYPES ====================

// Code coverage estimation
interface CoverageResult {
  summary: string
  score: number
  estimatedCoverage: number
  testableUnits: TestableUnit[]
  uncoveredRisks: string[]
}

interface TestableUnit {
  name: string
  line: number
  type: 'function' | 'class' | 'branch' | 'loop'
  complexity: number
  testable: boolean
}

// Dependency version check
interface DepVersionResult {
  summary: string
  score: number
  dependencies: DepVersion[]
  outdated: DepVersion[]
  vulnerable: DepVersion[]
}

interface DepVersion {
  name: string
  current: string
  latest?: string
  status: 'up-to-date' | 'outdated' | 'vulnerable' | 'unknown'
  vulnerabilities: string[]
}

// Code style enforcement
interface StyleEnforceResult {
  summary: string
  score: number
  indentSize: number
  lineLength: number
  violations: StyleViolation[]
}

interface StyleViolation {
  line: number
  type: 'indentation' | 'line-length' | 'trailing-whitespace' | 'missing-newline' | 'tabs'
  message: string
  severity: Severity
  fix: string
}

// Function length analysis
interface FuncLengthResult {
  summary: string
  score: number
  functions: FuncLength[]
  average: number
  max: number
}

interface FuncLength {
  name: string
  line: number
  length: number
  params: number
  status: 'good' | 'warning' | 'critical'
}

// Class cohesion analysis
interface CohesionResult {
  summary: string
  score: number
  classes: ClassCohesion[]
}

interface ClassCohesion {
  name: string
  line: number
  methods: number
  fields: number
  cohesion: number
  status: 'high' | 'medium' | 'low'
  suggestion: string
}

// Comment quality analysis
interface CommentQualityResult {
  summary: string
  score: number
  comments: CommentQuality[]
  ratio: number
  quality: 'excellent' | 'good' | 'fair' | 'poor'
}

interface CommentQuality {
  line: number
  type: 'doc' | 'inline' | 'todo' | 'hack' | 'redundant'
  content: string
  quality: 'useful' | 'redundant' | 'outdated' | 'noise'
}

// Type safety scoring
interface TypeSafetyResult {
  summary: string
  score: number
  anyCount: number
  implicitAny: number
  missingReturns: number
  typeAssertions: number
  issues: TypeSafetyIssue[]
}

interface TypeSafetyIssue {
  line: number
  type: 'any' | 'implicit-any' | 'missing-return' | 'assertion' | 'cast'
  message: string
  severity: Severity
  fix: string
}

// Async pattern detection
interface AsyncPatternResult {
  summary: string
  score: number
  patterns: AsyncPattern[]
  antiPatterns: string[]
}

interface AsyncPattern {
  line: number
  type: 'async-await' | 'promise-chain' | 'callback' | 'promise-all' | 'race' | 'settled'
  message: string
  quality: 'good' | 'warning' | 'anti-pattern'
  suggestion: string
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

// ==================== v0.7.0 NEW FUNCTIONS ====================

// --- PRO-010: Multi-language deep analysis ---
function analyzeMultiLanguage(code: string, language: string): MultiLangResult {
  const features: LanguageFeature[] = []
  const issues: LanguageSpecificIssue[] = []
  let confidence = 0.9

  switch (language) {
    case 'python':
      features.push(
        { name: 'type-hints', supported: true, description: 'PEP 484 type annotations' },
        { name: 'f-strings', supported: true, description: 'Python 3.6+ formatted strings' },
        { name: 'list-comprehensions', supported: true, description: 'Pythonic iteration patterns' },
        { name: 'decorators', supported: true, description: '@decorator syntax support' },
        { name: 'context-managers', supported: true, description: 'with statement patterns' },
        { name: 'async-await', supported: true, description: 'Asynchronous programming' }
      )
      // Check for Python-specific issues
      if (code.includes('except:')) {
        issues.push({ line: 1, rule: 'bare-except', message: 'Bare except clause - catch specific exceptions', severity: 'warning', fix: 'Use `except Exception as e:` instead', docs: 'https://peps.python.org/pep-0008/' })
      }
      if (/print\s+\(/.test(code) && !code.includes('from __future__')) {
        issues.push({ line: 1, rule: 'print-statement', message: 'Consider using logging instead of print', severity: 'info', fix: 'Use `import logging; logger = logging.getLogger(__name__)`' })
      }
      if (/==\s*(True|False|None)/.test(code)) {
        issues.push({ line: 1, rule: 'comparison-to-singleton', message: 'Use `is` for None/True/False comparisons', severity: 'warning', fix: 'Replace `== None` with `is None`' })
      }
      break

    case 'go':
      features.push(
        { name: 'goroutines', supported: true, description: 'go func() concurrency' },
        { name: 'interfaces', supported: true, description: 'Implicit interface satisfaction' },
        { name: 'defer', supported: true, description: 'Deferred execution' },
        { name: 'channels', supported: true, description: 'CSP-style communication' },
        { name: 'struct-tags', supported: true, description: 'Reflection metadata' },
        { name: 'error-handling', supported: true, description: 'Explicit error returns' }
      )
      if (code.includes('panic(')) {
        issues.push({ line: 1, rule: 'panic-usage', message: 'Avoid panic in production code - return errors instead', severity: 'warning', fix: 'Return error values instead of panicking' })
      }
      break

    case 'rust':
      features.push(
        { name: 'ownership', supported: true, description: 'Borrow checker system' },
        { name: 'lifetimes', supported: true, description: 'Explicit lifetime annotations' },
        { name: 'pattern-matching', supported: true, description: 'match expressions' },
        { name: 'traits', supported: true, description: 'Type class polymorphism' },
        { name: 'Option-Result', supported: true, description: 'Error handling types' },
        { name: 'macros', supported: true, description: 'Macro by example' }
      )
      if (code.includes('unwrap()')) {
        issues.push({ line: 1, rule: 'unwrap-usage', message: 'Avoid unwrap() - handle None/Err cases properly', severity: 'warning', fix: 'Use `?` operator or `match` instead' })
      }
      if (/mut\s+/.test(code) && code.match(/mut\s+/g)!.length > 5) {
        issues.push({ line: 1, rule: 'excessive-mutability', message: 'High mutability - consider restructuring for immutability', severity: 'info', fix: 'Use references or functional patterns' })
      }
      break

    case 'java':
      features.push(
        { name: 'generics', supported: true, description: 'Type parameterization' },
        { name: 'streams', supported: true, description: 'Functional stream API' },
        { name: 'lombok', supported: false, description: 'Boilerplate reduction (requires dependency)' },
        { name: 'records', supported: true, description: 'Java 14+ immutable data classes' },
        { name: 'sealed-classes', supported: true, description: 'Java 17+ restricted inheritance' },
        { name: 'pattern-matching', supported: true, description: 'Java 16+ instanceof patterns' }
      )
      if (/catch\s*\(/.test(code) && code.includes('Exception')) {
        issues.push({ line: 1, rule: 'catch-generic', message: 'Avoid catching generic Exception', severity: 'warning', fix: 'Catch specific exception types' })
      }
      break

    default:
      confidence = 0.7
      features.push(
        { name: 'basic-analysis', supported: true, description: 'Generic code analysis' },
        { name: 'pattern-detection', supported: true, description: 'Common anti-patterns' }
      )
  }

  const score = Math.max(0, 100 - issues.filter(i => i.severity === 'warning').length * 15 - issues.filter(i => i.severity === 'info').length * 5)

  return {
    summary: `${language} analysis: ${features.length} features detected, ${issues.length} language-specific issues`,
    language,
    confidence,
    features,
    issues,
    score
  }
}

function formatMultiLangReport(result: MultiLangResult): string {
  const lines: string[] = []
  lines.push('## Multi-Language Analysis Report')
  lines.push('')
  lines.push(`**Language: ${result.language} | Confidence: ${(result.confidence * 100).toFixed(0)}% | Score: ${result.score}/100**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.features.length > 0) {
    lines.push('### Language Features')
    result.features.forEach(f => {
      const icon = f.supported ? '✅' : '❌'
      lines.push(`- ${icon} **${f.name}**: ${f.description}`)
    })
    lines.push('')
  }
  if (result.issues.length > 0) {
    lines.push('### Language-Specific Issues')
    result.issues.forEach(issue => {
      const icon = issue.severity === 'warning' ? '⚠️' : 'ℹ️'
      lines.push(`- ${icon} [${issue.rule}]: ${issue.message}`)
      lines.push(`  - 💡 ${issue.fix}`)
    })
    lines.push('')
  }
  return lines.join('\n')
}

// --- PRO-011: CI/CD integration ---
function generateCiCdWorkflow(language: string): CiCdResult {
  const steps: WorkflowStep[] = []

  steps.push({ name: 'Checkout', action: 'actions/checkout@v4' })

  switch (language) {
    case 'typescript':
    case 'javascript':
      steps.push({ name: 'Setup Node', action: 'actions/setup-node@v4', with: { 'node-version': '20' } })
      steps.push({ name: 'Install', run: 'npm ci' })
      steps.push({ name: 'Review', run: 'npx dsh review --ci' })
      break
    case 'python':
      steps.push({ name: 'Setup Python', action: 'actions/setup-python@v5', with: { 'python-version': '3.11' } })
      steps.push({ name: 'Install', run: 'pip install -r requirements.txt' })
      steps.push({ name: 'Review', run: 'dsh review --ci' })
      break
    case 'go':
      steps.push({ name: 'Setup Go', action: 'actions/setup-go@v5', with: { 'go-version': '1.21' } })
      steps.push({ name: 'Review', run: 'dsh review --ci' })
      break
    default:
      steps.push({ name: 'Review', run: 'dsh review --ci' })
  }

  steps.push({ name: 'Upload SARIF', uses: 'github/codeql-action/upload-sarif@v3' })

  const workflow = `name: Code Review\non:\n  push:\n    branches: [main]\n  pull_request:\n    branches: [main]\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n${steps.map(s => `      - name: ${s.name}\n${s.action ? `        uses: ${s.action}\n` : ''}${s.with ? `        with:\n${Object.entries(s.with).map(([k, v]) => `          ${k}: ${v}`).join('\n')}\n` : ''}${s.run ? `        run: ${s.run}\n` : ''}`).join('\n')}`

  return {
    summary: `Generated GitHub Actions workflow for ${language}`,
    workflow,
    triggers: ['push to main', 'pull_request to main'],
    steps,
    filename: '.github/workflows/code-review.yml'
  }
}

function formatCiCdReport(result: CiCdResult): string {
  const lines: string[] = []
  lines.push('## CI/CD Integration Report')
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  lines.push('### Workflow File')
  lines.push(`- Filename: \`${result.filename}\``)
  lines.push(`- Triggers: ${result.triggers.join(', ')}`)
  lines.push('')
  lines.push('### Steps')
  result.steps.forEach((step, idx) => {
    lines.push(`${idx + 1}. **${step.name}**`)
    if (step.action) lines.push(`   - Action: \`${step.action}\``)
    if (step.run) lines.push(`   - Run: \`${step.run}\``)
    if (step.with) lines.push(`   - With: ${JSON.stringify(step.with)}`)
  })
  lines.push('')
  lines.push('### Workflow YAML')
  lines.push('```yaml')
  lines.push(result.workflow)
  lines.push('```')
  lines.push('')
  lines.push('### Usage')
  lines.push('1. Save the workflow to `.github/workflows/code-review.yml`')
  lines.push('2. Push to your repository')
  lines.push('3. The workflow runs automatically on every PR')
  lines.push('')
  return lines.join('\n')
}

// --- PRO-012: Custom rule engine ---
function runCustomRules(code: string, rulesYaml: string): CustomRuleResult {
  const matches: RuleMatch[] = []
  const errors: string[] = []
  let rulesLoaded = 0

  try {
    const lines = code.split('\n')
    // Simple YAML parser (works for flat rule definitions)
    const ruleBlocks = rulesYaml.split(/^- /m).filter(b => b.trim())
    
    ruleBlocks.forEach(block => {
      const rule: Record<string, string> = {}
      block.split('\n').forEach(line => {
        const colonIdx = line.indexOf(':')
        if (colonIdx > 0) {
          const key = line.substring(0, colonIdx).trim()
          const value = line.substring(colonIdx + 1).trim().replace(/^["']|["']$/g, '')
          rule[key] = value
        }
      })

      if (rule.id && rule.pattern) {
        rulesLoaded++
        const regex = new RegExp(rule.pattern, 'gi')
        lines.forEach((line, idx) => {
          if (regex.test(line)) {
            matches.push({
              ruleId: rule.id,
              line: idx + 1,
              message: rule.message || `Custom rule '${rule.id}' matched`,
              severity: (rule.severity as Severity) || 'warning',
              context: line.trim().substring(0, 80)
            })
          }
        })
      }
    })
  } catch (e) {
    errors.push(`Failed to parse rules: ${e}`)
  }

  return {
    summary: `Loaded ${rulesLoaded} custom rules, ${matches.length} matches found`,
    rulesLoaded,
    matches,
    errors
  }
}

function formatCustomRuleReport(result: CustomRuleResult): string {
  const lines: string[] = []
  lines.push('## Custom Rule Engine Report')
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.matches.length > 0) {
    lines.push('### Matches')
    result.matches.forEach(m => {
      const icon = m.severity === 'critical' ? '🔴' : m.severity === 'error' ? '🟠' : m.severity === 'warning' ? '🟡' : 'ℹ️'
      lines.push(`- ${icon} **${m.ruleId}** (line ${m.line}): ${m.message}`)
      lines.push(`  - Context: \`${m.context}\``)
    })
    lines.push('')
  }
  if (result.errors.length > 0) {
    lines.push('### Errors')
    result.errors.forEach(e => lines.push(`- ❌ ${e}`))
    lines.push('')
  }
  lines.push('### Example Rules YAML')
  lines.push('```yaml')
  lines.push('- id: no-console-log')
  lines.push('  pattern: "console\\\\.log"')
  lines.push('  message: "Avoid console.log in production"')
  lines.push('  severity: warning')
  lines.push('')
  lines.push('- id: require-error-handling')
  lines.push('  pattern: "async\\\\s+function"')
  lines.push('  message: "Async functions should have try-catch"')
  lines.push('  severity: error')
  lines.push('```')
  lines.push('')
  return lines.join('\n')
}

// --- Code duplication detection ---
function detectDuplication(code: string, _filename?: string): DuplicationResult {
  const duplications: CodeDuplicate[] = []
  const lines = code.split('\n')
  const minDuplicateLength = 4

  // Find consecutive similar blocks
  for (let i = 0; i < lines.length - minDuplicateLength; i++) {
    const block = lines.slice(i, i + minDuplicateLength).join('\n')
    const blockTrimmed = block.trim()
    
    if (blockTrimmed.length < 20) continue

    for (let j = i + minDuplicateLength; j < lines.length - minDuplicateLength; j++) {
      const compareBlock = lines.slice(j, j + minDuplicateLength).join('\n')
      const similarity = calculateSimilarity(blockTrimmed, compareBlock.trim())
      
      if (similarity > 0.85) {
        const existing = duplications.find(d => d.sourceLine === i + 1 && d.targetLine === j + 1)
        if (!existing) {
          duplications.push({
            type: similarity === 1 ? 'exact' : 'similar',
            sourceFile: 'current',
            sourceLine: i + 1,
            targetFile: 'current',
            targetLine: j + 1,
            lines: minDuplicateLength,
            similarity: Math.round(similarity * 100) / 100,
            suggestion: similarity === 1 ? 'Extract identical block into a function' : 'Consider consolidating similar logic'
          })
        }
      }
    }
  }

  const linesWasted = duplications.reduce((sum, d) => sum + d.lines, 0)
  const score = Math.max(0, 100 - duplications.length * 10 - linesWasted * 2)

  return {
    summary: `Found ${duplications.length} code duplications (${linesWasted} lines wasted)`,
    duplications,
    score,
    linesWasted
  }
}

function calculateSimilarity(a: string, b: string): number {
  if (a === b) return 1
  if (a.length === 0 || b.length === 0) return 0
  
  const longer = a.length > b.length ? a : b
  const shorter = a.length > b.length ? b : a
  
  // Simple Levenshtein-based similarity
  const editDistance = levenshteinDistance(longer, shorter)
  return (longer.length - editDistance) / longer.length
}

function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = []
  
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i]
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j
  }
  
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1]
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        )
      }
    }
  }
  
  return matrix[b.length][a.length]
}

function formatDuplicationReport(result: DuplicationResult): string {
  const lines: string[] = []
  lines.push('## Code Duplication Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100 | Wasted Lines: ${result.linesWasted}**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.duplications.length > 0) {
    lines.push('### Duplications')
    result.duplications.forEach((d, idx) => {
      const icon = d.type === 'exact' ? '🔴' : '🟡'
      lines.push(`${idx + 1}. ${icon} Lines ${d.sourceLine}-${d.sourceLine + d.lines - 1} ↔ ${d.targetLine}-${d.targetLine + d.lines - 1}`)
      lines.push(`   - Type: ${d.type} | Similarity: ${(d.similarity * 100).toFixed(0)}%`)
      lines.push(`   - 💡 ${d.suggestion}`)
    })
    lines.push('')
  }
  return lines.join('\n')
}

// --- Refactoring suggestions ---
function suggestRefactoring(code: string, language: string): RefactorResult {
  const refactorings: Refactoring[] = []
  const lines = code.split('\n')

  // Long method detection -> suggest extract
  let funcStart = -1
  let funcName = ''
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(/(?:function|def|func)\s+(\w+)/)
    if (match && funcStart === -1) {
      funcStart = i
      funcName = match[1]
    }
    if (funcStart !== -1 && i - funcStart > 30) {
      refactorings.push({
        type: 'extract-method',
        line: funcStart + 1,
        target: funcName,
        description: `Function '${funcName}' is too long (${i - funcStart} lines)`,
        effort: 'medium',
        impact: 'high',
        suggestion: 'Extract logical blocks into separate functions'
      })
      funcStart = -1
    }
  }

  // Large class detection -> suggest extract-class
  const classMatches = code.match(/class\s+\w+/g) || []
  classMatches.forEach(cls => {
    const clsIdx = code.indexOf(cls)
    const clsLine = code.substring(0, clsIdx).split('\n').length
    const methodCount = (code.substring(clsIdx, clsIdx + 5000).match(/(?:public|private|protected|static)?\s*\w+\s*\(/g) || []).length
    if (methodCount > 8) {
      refactorings.push({
        type: 'extract-class',
        line: clsLine,
        target: cls.replace('class ', ''),
        description: `Class has ${methodCount} methods - violates SRP`,
        effort: 'high',
        impact: 'high',
        suggestion: 'Split into smaller, focused classes'
      })
    }
  })

  // Duplicated logic -> suggest extract
  const dupResult = detectDuplication(code)
  if (dupResult.duplications.length > 0) {
    refactorings.push({
      type: 'extract-method',
      line: dupResult.duplications[0].sourceLine,
      target: 'duplicated block',
      description: `${dupResult.duplications.length} duplicated code blocks found`,
      effort: 'medium',
      impact: 'medium',
      suggestion: 'Extract duplicated code into a reusable function'
    })
  }

  // Variables that could be inlined
  const varDeclarations = code.match(/(?:const|let|var)\s+(\w+)\s*=\s*[^;]+;/g) || []
  varDeclarations.forEach(decl => {
    const varName = decl.match(/(?:const|let|var)\s+(\w+)/)?.[1]
    if (varName) {
      const usages = (code.match(new RegExp(`\\b${varName}\\b`, 'g')) || []).length
      if (usages === 2 && !decl.includes('function') && !decl.includes('=>')) {
        const line = code.split('\n').findIndex(l => l.includes(decl)) + 1
        refactorings.push({
          type: 'inline',
          line,
          target: varName,
          description: `Variable '${varName}' used only once - could be inlined`,
          effort: 'low',
          impact: 'low',
          suggestion: `Inline the value directly where '${varName}' is used`
        })
      }
    }
  })

  const potentialImprovement = Math.min(30, refactorings.filter(r => r.impact === 'high').length * 10 + refactorings.filter(r => r.impact === 'medium').length * 5)
  const score = Math.max(0, 100 - refactorings.filter(r => r.impact === 'high').length * 15)

  return {
    summary: `Found ${refactorings.length} refactoring opportunities (potential improvement: +${potentialImprovement}pts)`,
    refactorings,
    score,
    potentialImprovement
  }
}

function formatRefactorReport(result: RefactorResult): string {
  const lines: string[] = []
  lines.push('## Refactoring Suggestions Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100 | Potential Improvement: +${result.potentialImprovement}pts**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.refactorings.length > 0) {
    lines.push('### Suggested Refactorings')
    result.refactorings.forEach((r, idx) => {
      const effortIcon = r.effort === 'low' ? '🟢' : r.effort === 'medium' ? '🟡' : '🔴'
      const impactIcon = r.impact === 'low' ? '⚪' : r.impact === 'medium' ? '🟡' : '🔴'
      lines.push(`${idx + 1}. **${r.type}** → \`${r.target}\` (line ${r.line})`)
      lines.push(`   - ${r.description}`)
      lines.push(`   - Effort: ${effortIcon} | Impact: ${impactIcon}`)
      lines.push(`   - 💡 ${r.suggestion}`)
    })
    lines.push('')
  }
  return lines.join('\n')
}

// --- Naming convention check ---
function checkNamingConventions(code: string, language: string): NamingResult {
  const conventions: NamingConvention[] = []
  const violations: NamingViolation[] = []
  const lines = code.split('\n')

  // Define conventions per language
  const namingRules: Record<string, { type: string; pattern: RegExp; description: string; examples: string[] }[]> = {
    typescript: [
      { type: 'variable', pattern: /^[a-z][a-zA-Z0-9]*$/, description: 'camelCase for variables', examples: ['userName', 'totalCount'] },
      { type: 'function', pattern: /^[a-z][a-zA-Z0-9]*$/, description: 'camelCase for functions', examples: ['getUser', 'calculateTotal'] },
      { type: 'class', pattern: /^[A-Z][a-zA-Z0-9]*$/, description: 'PascalCase for classes', examples: ['UserService', 'HttpClient'] },
      { type: 'constant', pattern: /^[A-Z][A-Z0-9_]*$/, description: 'SCREAMING_SNAKE_CASE for constants', examples: ['MAX_SIZE', 'API_KEY'] },
      { type: 'interface', pattern: /^[A-Z][a-zA-Z0-9]*$/, description: 'PascalCase for interfaces', examples: ['User', 'ApiResponse'] },
      { type: 'private', pattern: /^_[a-z][a-zA-Z0-9]*$/, description: 'Leading underscore for private', examples: ['_internal', '_cache'] }
    ],
    javascript: [
      { type: 'variable', pattern: /^[a-z][a-zA-Z0-9]*$/, description: 'camelCase for variables', examples: ['userName', 'isActive'] },
      { type: 'function', pattern: /^[a-z][a-zA-Z0-9]*$/, description: 'camelCase for functions', examples: ['handleClick', 'getData'] },
      { type: 'constant', pattern: /^[A-Z][A-Z0-9_]*$/, description: 'SCREAMING_SNAKE_CASE for constants', examples: ['MAX_COUNT', 'BASE_URL'] }
    ],
    python: [
      { type: 'variable', pattern: /^[a-z][a-z0-9_]*$/, description: 'snake_case for variables', examples: ['user_name', 'total_count'] },
      { type: 'function', pattern: /^[a-z][a-z0-9_]*$/, description: 'snake_case for functions', examples: ['get_user', 'calculate_total'] },
      { type: 'class', pattern: /^[A-Z][a-zA-Z0-9]*$/, description: 'PascalCase for classes', examples: ['UserService', 'HttpClient'] },
      { type: 'constant', pattern: /^[A-Z][A-Z0-9_]*$/, description: 'SCREAMING_SNAKE_CASE for constants', examples: ['MAX_SIZE', 'API_KEY'] },
      { type: 'private', pattern: /^_[a-z][a-z0-9_]*$/, description: 'Leading underscore for private', examples: ['_internal', '_cache'] }
    ],
    go: [
      { type: 'variable', pattern: /^[a-z][a-zA-Z0-9]*$/, description: 'camelCase for variables', examples: ['userName', 'totalCount'] },
      { type: 'exported', pattern: /^[A-Z][a-zA-Z0-9]*$/, description: 'PascalCase for exported', examples: ['GetUser', 'HttpClient'] },
      { type: 'acronym', pattern: /^[A-Z]+$/, description: 'All caps for acronyms', examples: ['ID', 'URL', 'HTTP'] }
    ],
    rust: [
      { type: 'variable', pattern: /^[a-z][a-z0-9_]*$/, description: 'snake_case for variables', examples: ['user_name', 'total_count'] },
      { type: 'function', pattern: /^[a-z][a-z0-9_]*$/, description: 'snake_case for functions', examples: ['get_user', 'calculate_total'] },
      { type: 'type', pattern: /^[A-Z][a-zA-Z0-9]*$/, description: 'PascalCase for types', examples: ['UserService', 'HttpClient'] },
      { type: 'constant', pattern: /^[A-Z][A-Z0-9_]*$/, description: 'SCREAMING_SNAKE_CASE for constants', examples: ['MAX_SIZE', 'API_KEY'] }
    ]
  }

  const rules = namingRules[language] || namingRules.typescript
  
  rules.forEach(rule => {
    conventions.push({
      type: rule.type,
      pattern: rule.pattern.source,
      description: rule.description,
      examples: rule.examples
    })
  })

  // Check variable declarations, function declarations, class declarations
  lines.forEach((line, idx) => {
    const lineNum = idx + 1

    // Check const/let/var declarations
    const varMatch = line.match(/(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/)
    if (varMatch && !line.trim().startsWith('//')) {
      const varName = varMatch[1]
      const isConst = line.includes('const')
      if (isConst && !/^[A-Z][A-Z0-9_]*$/.test(varName) && !/^[a-z][a-zA-Z0-9]*$/.test(varName)) {
        violations.push({
          line: lineNum,
          symbol: varName,
          convention: 'constant naming',
          message: `Constant '${varName}' should be SCREAMING_SNAKE_CASE`,
          suggestion: `Rename to '${varName.replace(/([A-Z])/g, '_$1').toUpperCase().replace(/^_/, '')}'`,
          severity: 'warning'
        })
      }
    }

    // Check function declarations
    const funcMatch = line.match(/(?:function|def|func)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/)
    if (funcMatch && !line.trim().startsWith('//')) {
      const funcName = funcMatch[1]
      if (language === 'python' || language === 'rust') {
        if (!/^[a-z][a-z0-9_]*$/.test(funcName) && !/^_[a-z]/.test(funcName)) {
          violations.push({
            line: lineNum,
            symbol: funcName,
            convention: 'function naming',
            message: `Function '${funcName}' should be snake_case`,
            suggestion: `Rename to '${funcName.replace(/([A-Z])/g, '_$1').toLowerCase().replace(/^_/, '')}'`,
            severity: 'warning'
          })
        }
      }
    }
  })

  const score = Math.max(0, 100 - violations.filter(v => v.severity === 'warning').length * 10)

  return {
    summary: `Checked ${conventions.length} naming conventions, found ${violations.length} violations`,
    score,
    conventions,
    violations
  }
}

function formatNamingReport(result: NamingResult): string {
  const lines: string[] = []
  lines.push('## Naming Convention Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.conventions.length > 0) {
    lines.push('### Active Conventions')
    result.conventions.forEach(c => {
      lines.push(`- **${c.type}**: ${c.description} (${c.examples.join(', ')})`)
    })
    lines.push('')
  }
  if (result.violations.length > 0) {
    lines.push('### Violations')
    result.violations.forEach(v => {
      lines.push(`- ⚠️ Line ${v.line}: **${v.symbol}** - ${v.message}`)
      lines.push(`  - 💡 ${v.suggestion}`)
    })
    lines.push('')
  }
  return lines.join('\n')
}

// ==================== v0.8.0 NEW FUNCTIONS ====================

// --- Security Pattern Detection (deep) ---
function detectSecurityPatterns(code: string, language: string): SecurityPatternResult {
  const vulnerabilities: SecurityPatternResult['vulnerabilities'] = []
  const lines = code.split('\n')
  const owaspMapping: Record<string, string> = {}

  // SQL Injection
  if (/(?:query|execute|sql)\s*\(\s*["'`].*\$\{|"SELECT.*\+|'SELECT.*\+/.test(code)) {
    lines.forEach((line, idx) => {
      if (/(?:query|execute|sql)\s*\(/.test(line) && (line.includes('+') || line.includes('$') || line.includes('`'))) {
        vulnerabilities.push({
          type: 'sqli',
          line: idx + 1,
          message: 'Potential SQL injection - string concatenation in query',
          severity: 'critical',
          cwe: 'CWE-89',
          owasp: 'A03:2021',
          fix: 'Use parameterized queries or prepared statements',
          context: line.trim().substring(0, 60)
        })
        owaspMapping['sqli'] = 'A03:2021 - Injection'
      }
    })
  }

  // XSS
  if (/innerHTML|document\.write|dangerouslySetHTML|\.html\(/.test(code)) {
    lines.forEach((line, idx) => {
      if (/innerHTML|document\.write|\.html\(/.test(line)) {
        vulnerabilities.push({
          type: 'xss',
          line: idx + 1,
          message: 'Potential XSS - unsafe HTML injection',
          severity: 'error',
          cwe: 'CWE-79',
          owasp: 'A03:2021',
          fix: 'Use textContent, sanitization, or framework escaping',
          context: line.trim().substring(0, 60)
        })
        owaspMapping['xss'] = 'A03:2021 - Injection'
      }
    })
  }

  // Command Injection
  if (/(?:exec|execSync|spawn|system|passthru)\s*\(/.test(code)) {
    lines.forEach((line, idx) => {
      if (/(?:exec|execSync|spawn|system)\s*\(/.test(line) && (line.includes('+') || line.includes('$') || line.includes('`'))) {
        vulnerabilities.push({
          type: 'command-injection',
          line: idx + 1,
          message: 'Potential command injection - unsanitized input to shell',
          severity: 'critical',
          cwe: 'CWE-78',
          owasp: 'A03:2021',
          fix: 'Use execFile with argument arrays instead of shell strings',
          context: line.trim().substring(0, 60)
        })
        owaspMapping['command-injection'] = 'A03:2021 - Injection'
      }
    })
  }

  // Path Traversal
  if (/(?:readFile|writeFile|fs\.|open)\s*\(/.test(code)) {
    lines.forEach((line, idx) => {
      if (/(?:readFile|writeFile|fs\.|open)\s*\(/.test(line) && (line.includes('+') || line.includes('$'))) {
        vulnerabilities.push({
          type: 'path-traversal',
          line: idx + 1,
          message: 'Potential path traversal - unsanitized file path',
          severity: 'error',
          cwe: 'CWE-22',
          owasp: 'A01:2021',
          fix: 'Validate and sanitize file paths, use path.resolve()',
          context: line.trim().substring(0, 60)
        })
        owaspMapping['path-traversal'] = 'A01:2021 - Broken Access Control'
      }
    })
  }

  // Hardcoded Secrets
  const secretPatterns = [
    { pattern: /(?:api[_-]?key|apikey|secret|password|token)\s*[:=]\s*['"][^'"]{8,}['"]/gi, type: 'secrets' as const }
  ]
  secretPatterns.forEach(sp => {
    let match: RegExpExecArray | null
    while ((match = sp.pattern.exec(code)) !== null) {
      const line = code.substring(0, match.index).split('\n').length
      vulnerabilities.push({
        type: 'secrets',
        line,
        message: 'Hardcoded secret detected',
        severity: 'critical',
        cwe: 'CWE-798',
        owasp: 'A07:2021',
        fix: 'Use environment variables or a secrets manager',
        context: match[0].substring(0, 40) + '...'
      })
      owaspMapping['secrets'] = 'A07:2021 - Identification and Authentication Failures'
    }
  })

  // SSRF
  if (/(?:fetch|axios|request|http\.get)\s*\(/.test(code)) {
    lines.forEach((line, idx) => {
      if (/(?:fetch|axios|http\.get)\s*\(/.test(line) && (line.includes('+') || line.includes('$'))) {
        vulnerabilities.push({
          type: 'ssrf',
          line: idx + 1,
          message: 'Potential SSRF - user-controlled URL',
          severity: 'error',
          cwe: 'CWE-918',
          owasp: 'A10:2021',
          fix: 'Validate and whitelist URLs, use allowlists',
          context: line.trim().substring(0, 60)
        })
        owaspMapping['ssrf'] = 'A10:2021 - Server-Side Request Forgery'
      }
    })
  }

  const score = Math.max(0, 100 - vulnerabilities.filter(v => v.severity === 'critical').length * 25 - vulnerabilities.filter(v => v.severity === 'error').length * 15)

  return {
    summary: `Found ${vulnerabilities.length} security patterns (${Object.keys(owaspMapping).length} OWASP categories)`,
    score,
    vulnerabilities,
    owaspMapping
  }
}

function formatSecurityPatternReport(result: SecurityPatternResult): string {
  const lines: string[] = []
  lines.push('## Security Pattern Detection Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100 | OWASP Categories: ${Object.keys(result.owaspMapping).length}**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.vulnerabilities.length > 0) {
    lines.push('### Vulnerabilities')
    result.vulnerabilities.forEach(v => {
      const icon = v.severity === 'critical' ? '🔴' : '🟠'
      lines.push(`- ${icon} **[${v.type}]** (line ${v.line}) [${v.cwe}] ${v.message}`)
      lines.push(`  - OWASP: ${v.owasp}`)
      lines.push(`  - 💡 ${v.fix}`)
      lines.push(`  - Context: \`${v.context}\``)
    })
    lines.push('')
  }
  if (Object.keys(result.owaspMapping).length > 0) {
    lines.push('### OWASP Mapping')
    Object.entries(result.owaspMapping).forEach(([type, mapping]) => {
      lines.push(`- **${type}**: ${mapping}`)
    })
    lines.push('')
  }
  return lines.join('\n')
}

// --- Performance optimization tips ---
function generatePerformanceTips(code: string, language: string): PerformanceTipResult {
  const tips: PerformanceTip[] = []
  const bottlenecks: string[] = []
  const lines = code.split('\n')

  // N+1 query detection
  if (/(?:for|while|forEach|map)\s*\(/.test(code) && /(?:query|find|get|fetch)\s*\(/.test(code)) {
    lines.forEach((line, idx) => {
      if (/(?:for|forEach|map)/.test(line) && /(?:find|get|fetch|query)/.test(code.split('\n').slice(idx, idx + 5).join('\n'))) {
        tips.push({
          line: idx + 1,
          type: 'io',
          message: 'Potential N+1 query in loop',
          severity: 'warning',
          impact: 'high',
          suggestion: 'Batch queries using WHERE IN or JOIN',
          example: 'const ids = items.map(i => i.id); const results = await db.query("SELECT * FROM t WHERE id IN (?)", [ids]);'
        })
      }
    })
  }

  // Memory leak detection
  if (/(?:setInterval|addEventListener|subscribe)\s*\(/.test(code) && !/clearInterval|removeEventListener|unsubscribe/.test(code)) {
    bottlenecks.push('Potential memory leak - event listeners/subscriptions not cleaned up')
    tips.push({
      line: 1,
      type: 'memory',
      message: 'Event listeners/subscriptions without cleanup',
      severity: 'warning',
      impact: 'medium',
      suggestion: 'Use useEffect cleanup, unsubscribe, or AbortController'
    })
  }

  // Inefficient loops
  lines.forEach((line, idx) => {
    if (/for\s*\(\s*let.*\.length/.test(line)) {
      tips.push({
        line: idx + 1,
        type: 'algorithm',
        message: 'Cache array length for better performance',
        severity: 'info',
        impact: 'low',
        suggestion: 'const len = arr.length; for (let i = 0; i < len; i++)',
        example: 'const len = arr.length; for (let i = 0; i < len; i++) { ... }'
      })
    }
  })

  // String concatenation in loops
  lines.forEach((line, idx) => {
    if (/for.*\{[\s\S]*?[\w+]\s*\+=\s*["'`]/.test(line + (lines[idx + 1] || ''))) {
      tips.push({
        line: idx + 1,
        type: 'memory',
        message: 'String concatenation in loop - use array join',
        severity: 'info',
        impact: 'medium',
        suggestion: 'Use array.push() + join() instead of += in loops'
      })
    }
  })

  // Missing caching
  if (/fetch|axios|http/.test(code) && !/cache|Cache/.test(code)) {
    tips.push({
      line: 1,
      type: 'caching',
      message: 'No caching mechanism detected for HTTP requests',
      severity: 'info',
      impact: 'medium',
      suggestion: 'Implement request caching with TTL or use React Query/SWR'
    })
  }

  // Large array operations
  if (/\.(map|filter|reduce)\s*\(/.test(code) && code.includes('.map') && code.includes('.filter')) {
    tips.push({
      line: 1,
      type: 'algorithm',
      message: 'Chained array operations - consider single iteration',
      severity: 'info',
      impact: 'low',
      suggestion: 'Combine map+filter into reduce or use for loop for large arrays'
    })
  }

  const score = Math.max(0, 100 - tips.filter(t => t.impact === 'high').length * 20 - tips.filter(t => t.impact === 'medium').length * 10)

  return {
    summary: `Found ${tips.length} performance tips (${bottlenecks.length} bottlenecks)`,
    score,
    tips,
    bottlenecks
  }
}

function formatPerformanceTipReport(result: PerformanceTipResult): string {
  const lines: string[] = []
  lines.push('## Performance Optimization Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.bottlenecks.length > 0) {
    lines.push('### ⚠️ Bottlenecks')
    result.bottlenecks.forEach(b => lines.push(`- 🐌 ${b}`))
    lines.push('')
  }
  if (result.tips.length > 0) {
    lines.push('### Tips')
    result.tips.forEach((tip, idx) => {
      const icon = tip.impact === 'high' ? '🔴' : tip.impact === 'medium' ? '🟡' : '🟢'
      lines.push(`${idx + 1}. ${icon} [${tip.type}] (line ${tip.line}): ${tip.message}`)
      lines.push(`   - 💡 ${tip.suggestion}`)
      if (tip.example) lines.push(`   - Example: \`${tip.example}\``)
    })
    lines.push('')
  }
  return lines.join('\n')
}

// --- Documentation completeness check ---
function checkDocumentation(code: string, language: string): DocumentationResult {
  const coverage: DocCoverage[] = []
  const missing: string[] = []
  const suggestions: string[] = []
  const lines = code.split('\n')

  // Find function/class declarations and check for preceding comments
  const funcRegex = /(?:function|def|func|class)\s+(\w+)/g
  const docCommentRegex = language === 'python' ? /^\s*"""/ : /^\s*\/\*\*|\^\s*\/\/\//

  let match: RegExpExecArray | null
  while ((match = funcRegex.exec(code)) !== null) {
    const symbol = match[1]
    const lineIdx = code.substring(0, match.index).split('\n').length - 1
    
    // Check if previous lines have documentation
    let hasDoc = false
    let paramsDocumented = false
    let returnsDocumented = false
    let examplesProvided = false

    for (let i = Math.max(0, lineIdx - 5); i < lineIdx; i++) {
      if (docCommentRegex.test(lines[i])) hasDoc = true
      if (/@param|@argument|Args:/.test(lines[i])) paramsDocumented = true
      if (/@returns|@return|Returns:/.test(lines[i])) returnsDocumented = true
      if (/@example|Example:/.test(lines[i])) examplesProvided = true
    }

    coverage.push({
      symbol,
      line: lineIdx + 1,
      hasDoc,
      paramsDocumented,
      returnsDocumented,
      examplesProvided
    })

    if (!hasDoc) missing.push(symbol)
  }

  if (missing.length > 0) {
    suggestions.push(`${missing.length} symbols missing documentation: ${missing.slice(0, 5).join(', ')}`)
  }

  const docRate = coverage.length > 0 ? ((coverage.length - missing.length) / coverage.length) * 100 : 100
  const score = Math.round(docRate)

  return {
    summary: `Documentation coverage: ${coverage.length - missing.length}/${coverage.length} symbols (${score}%)`,
    score,
    coverage,
    missing,
    suggestions
  }
}

function formatDocumentationReport(result: DocumentationResult): string {
  const lines: string[] = []
  lines.push('## Documentation Completeness Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100 | Coverage: ${result.coverage.length - result.missing.length}/${result.coverage.length} symbols**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.coverage.length > 0) {
    lines.push('### Coverage Details')
    result.coverage.forEach(c => {
      const icon = c.hasDoc ? '✅' : '❌'
      lines.push(`- ${icon} **${c.symbol}** (line ${c.line})`)
      lines.push(`   - Params: ${c.paramsDocumented ? '✓' : '✗'} | Returns: ${c.returnsDocumented ? '✓' : '✗'} | Examples: ${c.examplesProvided ? '✓' : '✗'}`)
    })
    lines.push('')
  }
  if (result.missing.length > 0) {
    lines.push('### Missing Documentation')
    result.missing.forEach(m => lines.push(`- ❌ **${m}**`))
    lines.push('')
  }
  if (result.suggestions.length > 0) {
    lines.push('### Suggestions')
    result.suggestions.forEach(s => lines.push(`- 💡 ${s}`))
    lines.push('')
  }
  return lines.join('\n')
}

// --- Import organization ---
function organizeImports(code: string, language: string): ImportOrganizeResult {
  const current = code.match(/^(?:import|from|require|use)\s+['"]?[^\s'"]+['"]?/gm) || []
  const groups: ImportGroup[] = []
  const removals: string[] = []

  // Categorize imports
  const categories: Record<string, string[]> = {
    'node-builtins': [],
    'external': [],
    'internal': [],
    'relative': []
  }

  current.forEach(imp => {
    const cleaned = imp.replace(/^(?:import|from|require|use)\s+/, '').replace(/['"]/g, '')
    if (/^(?:fs|path|http|https|os|util|crypto|stream|url|events)/.test(cleaned)) {
      categories['node-builtins'].push(imp)
    } else if (cleaned.startsWith('.') || cleaned.startsWith('/')) {
      categories['relative'].push(imp)
    } else if (cleaned.startsWith('@') || /^[a-z]/.test(cleaned)) {
      categories['external'].push(imp)
    } else {
      categories['internal'].push(imp)
    }
  })

  // Check for duplicates
  const seen = new Set<string>()
  current.forEach(imp => {
    const cleaned = imp.replace(/^(?:import|from|require|use)\s+/, '').replace(/['"]/g, '')
    if (seen.has(cleaned)) removals.push(imp)
    seen.add(cleaned)
  })

  // Sort within groups
  let order = 1
  Object.entries(categories).forEach(([name, imports]) => {
    if (imports.length > 0) {
      groups.push({
        name,
        imports: imports.sort(),
        order: order++
      })
    }
  })

  // Build organized import list
  const organized: string[] = []
  groups.forEach(g => {
    organized.push(...g.imports)
  })

  const isOrganized = JSON.stringify(current) === JSON.stringify(organized)
  const score = isOrganized ? 100 : Math.max(0, 100 - removals.length * 10)

  return {
    summary: `${current.length} imports in ${groups.length} groups${removals.length > 0 ? `, ${removals.length} duplicates` : ''}`,
    score,
    current,
    organized,
    groups,
    removals
  }
}

function formatImportOrganizeReport(result: ImportOrganizeResult): string {
  const lines: string[] = []
  lines.push('## Import Organization Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100 | Imports: ${result.current.length}**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.groups.length > 0) {
    lines.push('### Grouped Imports')
    result.groups.forEach(g => {
      lines.push(`#### ${g.name}`)
      g.imports.forEach(imp => lines.push(`- \`${imp}\``))
      lines.push('')
    })
  }
  if (result.removals.length > 0) {
    lines.push('### ⚠️ Duplicates')
    result.removals.forEach(r => lines.push(`- \`${r}\``))
    lines.push('')
  }
  return lines.join('\n')
}

// --- Error handling patterns ---
function analyzeErrorHandling(code: string, language: string): ErrorHandlingResult {
  const patterns: ErrorPattern[] = []
  const suggestions: string[] = []
  const lines = code.split('\n')

  // Missing try-catch around async
  const asyncFuncRegex = /(?:async\s+function|async\s*\(|async\s+\w+\s*=>)/g
  let match: RegExpExecArray | null
  while ((match = asyncFuncRegex.exec(code)) !== null) {
    const context = code.substring(match.index, match.index + 200)
    const line = code.substring(0, match.index).split('\n').length
    if (!context.includes('try')) {
      patterns.push({
        line,
        type: 'missing-catch',
        message: 'Async function without try-catch',
        severity: 'warning',
        fix: 'Wrap async operations in try-catch block'
      })
    }
  }

  // Empty catch blocks
  lines.forEach((line, idx) => {
    if (/catch\s*\([^)]*\)\s*\{\s*\}/.test(line)) {
      patterns.push({
        line: idx + 1,
        type: 'swallowed',
        message: 'Empty catch block - error swallowed',
        severity: 'error',
        fix: 'Log the error or rethrow it'
      })
    }
  })

  // Generic catch (.catch(), try-catch with only console.log)
  if (/\.catch\s*\(\s*(?:err|error|e)\s*=>\s*\{\s*console/.test(code)) {
    patterns.push({
      line: 1,
      type: 'generic',
      message: 'Error only logged, not properly handled',
      severity: 'warning',
      fix: 'Implement proper error recovery or user notification'
    })
  }

  // No return in catch
  const catchWithReturn = (code.match(/catch[\s\S]*?return/g) || []).length
  const totalCatch = (code.match(/catch\s*\(/g) || []).length
  if (totalCatch > 0 && catchWithReturn === 0) {
    patterns.push({
      line: 1,
      type: 'no-fallback',
      message: 'No fallback return value in catch blocks',
      severity: 'info',
      fix: 'Consider returning a default value in catch block'
    })
  }

  // Calculate coverage
  const totalTry = (code.match(/try\s*\{/g) || []).length
  const totalAsync = (code.match(/async\s+/g) || []).length
  const coverage = totalAsync > 0 ? Math.min(100, (totalTry / totalAsync) * 100) : 100

  if (coverage < 50) suggestions.push('Less than 50% of async operations have error handling')
  if (patterns.some(p => p.type === 'swallowed')) suggestions.push('Avoid empty catch blocks - log or handle errors')

  const score = Math.max(0, 100 - patterns.filter(p => p.severity === 'error').length * 20 - patterns.filter(p => p.severity === 'warning').length * 10)

  return {
    summary: `Error handling coverage: ${coverage.toFixed(0)}% (${patterns.length} issues)`,
    score,
    patterns,
    coverage: Math.round(coverage),
    suggestions
  }
}

function formatErrorHandlingReport(result: ErrorHandlingResult): string {
  const lines: string[] = []
  lines.push('## Error Handling Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100 | Coverage: ${result.coverage}%**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.patterns.length > 0) {
    lines.push('### Patterns')
    result.patterns.forEach(p => {
      const icon = p.severity === 'error' ? '🔴' : p.severity === 'warning' ? '🟡' : 'ℹ️'
      lines.push(`- ${icon} [${p.type}] (line ${p.line}): ${p.message}`)
      lines.push(`  - 💡 ${p.fix}`)
    })
    lines.push('')
  }
  if (result.suggestions.length > 0) {
    lines.push('### Suggestions')
    result.suggestions.forEach(s => lines.push(`- 💡 ${s}`))
    lines.push('')
  }
  return lines.join('\n')
}

// --- API design review ---
function reviewApiDesign(code: string, language: string): ApiDesignResult {
  const endpoints: EndpointDesign[] = []
  const suggestions: string[] = []
  const lines = code.split('\n')

  // Detect API endpoints (Express, FastAPI, Spring patterns)
  const endpointPatterns = [
    { regex: /(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g, framework: 'express' },
    { regex: /@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g, framework: 'fastapi' },
    { regex: /@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*\(\s*['"`]([^'"`]+)['"`]?/g, framework: 'spring' }
  ]

  endpointPatterns.forEach(ep => {
    let match: RegExpExecArray | null
    while ((match = ep.regex.exec(code)) !== null) {
      const method = match[1].toUpperCase()
      const path = match[2] || '/'
      const line = code.substring(0, match.index).split('\n').length
      const context = code.substring(match.index, match.index + 300)

      const hasValidation = /validate|schema|joi|yup|class-validator|@Is/.test(context)
      const hasErrorHandling = /try|catch|error|Error/.test(context)
      const hasPagination = /page|limit|offset|skip|take|cursor/.test(context)
      const hasAuth = /auth|jwt|token|middleware|guard|@PreAuthorize/.test(context)

      let score = 100
      if (!hasValidation) score -= 20
      if (!hasErrorHandling) score -= 20
      if (!hasPagination && method === 'GET') score -= 10
      if (!hasAuth) score -= 15

      endpoints.push({
        name: `${method} ${path}`,
        line,
        method,
        path,
        hasValidation,
        hasErrorHandling,
        hasPagination,
        hasAuth,
        score: Math.max(0, score)
      })
    }
  })

  // Calculate RESTfulness
  const methods = endpoints.map(e => e.method)
  const hasCRUD = ['GET', 'POST', 'PUT', 'DELETE'].every(m => methods.includes(m))
  const restfulness = hasCRUD ? 100 : Math.round((new Set(methods).size / 4) * 100)

  // Consistency check
  const paths = endpoints.map(e => e.path)
  const consistentPaths = paths.every(p => p.startsWith('/api') || p.startsWith('/v'))
  const consistency = consistentPaths ? 100 : 70

  if (!hasCRUD) suggestions.push('Missing CRUD operations - consider implementing full REST')
  if (!consistentPaths) suggestions.push('Inconsistent API path prefix - use /api/v1 prefix')
  endpoints.filter(e => !e.hasValidation).forEach(e => {
    suggestions.push(`Endpoint '${e.name}' missing input validation`)
  })
  endpoints.filter(e => !e.hasAuth).forEach(e => {
    suggestions.push(`Endpoint '${e.name}' missing authentication`)
  })

  const avgScore = endpoints.length > 0 ? Math.round(endpoints.reduce((s, e) => s + e.score, 0) / endpoints.length) : 100

  return {
    summary: `${endpoints.length} endpoints detected (RESTfulness: ${restfulness}%, consistency: ${consistency}%)`,
    score: avgScore,
    endpoints,
    restfulness,
    consistency,
    suggestions
  }
}

function formatApiDesignReport(result: ApiDesignResult): string {
  const lines: string[] = []
  lines.push('## API Design Review Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100 | RESTfulness: ${result.restfulness}% | Consistency: ${result.consistency}%**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.endpoints.length > 0) {
    lines.push('### Endpoints')
    result.endpoints.forEach(e => {
      const icon = e.score >= 80 ? '🟢' : e.score >= 60 ? '🟡' : '🔴'
      lines.push(`- ${icon} **${e.name}** (line ${e.line}): ${e.score}/100`)
      lines.push(`   - Validation: ${e.hasValidation ? '✓' : '✗'} | Error Handling: ${e.hasErrorHandling ? '✓' : '✗'}`)
      lines.push(`   - Pagination: ${e.hasPagination ? '✓' : '✗'} | Auth: ${e.hasAuth ? '✓' : '✗'}`)
    })
    lines.push('')
  }
  if (result.suggestions.length > 0) {
    lines.push('### Suggestions')
    result.suggestions.forEach(s => lines.push(`- 💡 ${s}`))
    lines.push('')
  }
  return lines.join('\n')
}

// ==================== v0.9.0 NEW FUNCTIONS ====================

// --- Code coverage estimation ---
function estimateCoverage(code: string, language: string): CoverageResult {
  const testableUnits: TestableUnit[] = []
  const uncoveredRisks: string[] = []
  const lines = code.split('\n')

  // Detect functions as testable units
  const funcRegex = /(?:function|def|func)\s+(\w+)\s*\(([^)]*)\)/g
  let match: RegExpExecArray | null
  while ((match = funcRegex.exec(code)) !== null) {
    const name = match[1]
    const params = match[2].split(',').filter(p => p.trim()).length
    const line = code.substring(0, match.index).split('\n').length
    const funcBody = code.substring(match.index, match.index + 500)
    const branches = (funcBody.match(/\b(if|else|switch|case|catch|\?)\b/g) || []).length
    
    testableUnits.push({
      name,
      line,
      type: 'function',
      complexity: branches + 1,
      testable: params >= 0
    })
    
    if (branches > 3) {
      uncoveredRisks.push(`Function '${name}' has ${branches} branches - needs ${(branches + 1) * 2}+ test cases`)
    }
  }

  // Detect classes
  const classRegex = /class\s+(\w+)/g
  while ((match = classRegex.exec(code)) !== null) {
    const name = match[1]
    const line = code.substring(0, match.index).split('\n').length
    testableUnits.push({ name, line, type: 'class', complexity: 1, testable: true })
  }

  // Estimate coverage based on complexity
  const totalComplexity = testableUnits.reduce((sum, u) => sum + u.complexity, 0)
  const estimatedCoverage = testableUnits.length > 0 
    ? Math.max(0, 100 - totalComplexity * 2) 
    : 0
  const score = Math.round(estimatedCoverage)

  return {
    summary: `${testableUnits.length} testable units, estimated ${estimatedCoverage.toFixed(0)}% coverage`,
    score,
    estimatedCoverage: Math.round(estimatedCoverage),
    testableUnits,
    uncoveredRisks
  }
}

function formatCoverageReport(result: CoverageResult): string {
  const lines: string[] = []
  lines.push('## Code Coverage Estimation Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100 | Est. Coverage: ${result.estimatedCoverage}%**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.testableUnits.length > 0) {
    lines.push('### Testable Units')
    result.testableUnits.slice(0, 15).forEach(u => {
      const icon = u.type === 'function' ? '⚡' : '📦'
      lines.push(`- ${icon} **${u.name}** (line ${u.line}): complexity=${u.complexity}`)
    })
    if (result.testableUnits.length > 15) lines.push(`  ... and ${result.testableUnits.length - 15} more`)
    lines.push('')
  }
  if (result.uncoveredRisks.length > 0) {
    lines.push('### ⚠️ Coverage Risks')
    result.uncoveredRisks.forEach(r => lines.push(`- 🔍 ${r}`))
    lines.push('')
  }
  return lines.join('\n')
}

// --- Dependency version check ---
function checkDepVersions(code: string, language: string): DepVersionResult {
  const dependencies: DepVersion[] = []
  const importRegex = /(?:import|from|require|use)\s+['"]([^'"]+)['"]/g
  let match: RegExpExecArray | null

  while ((match = importRegex.exec(code)) !== null) {
    const name = match[1]
    if (name.startsWith('.') || name.startsWith('/')) continue
    
    // Parse version from comments or detect common patterns
    const hasVersion = /@\d+\.\d+/.test(match[0])
    const version = hasVersion ? match[0].match(/@(\d+\.\d+\.\d+)/)?.[1] ?? '0.0.0' : '0.0.0'
    
    dependencies.push({
      name,
      current: version,
      status: 'unknown',
      vulnerabilities: []
    })
  }

  // Check for known vulnerable patterns
  const vulnerablePatterns = [
    { pattern: /lodash/, name: 'lodash', vuln: 'Prototype pollution in older versions' },
    { pattern: /axios/, name: 'axios', vuln: 'SSRF in < 1.0.0' },
    { pattern: /minimatch/, name: 'minimatch', vuln: 'ReDoS in < 3.0.5' }
  ]

  vulnerablePatterns.forEach(vp => {
    if (vp.pattern.test(code)) {
      const dep = dependencies.find(d => d.name.includes(vp.name))
      if (dep) {
        dep.status = 'vulnerable'
        dep.vulnerabilities.push(vp.vuln)
      }
    }
  })

  const outdated = dependencies.filter(d => d.status === 'outdated' || d.status === 'vulnerable')
  const score = Math.max(0, 100 - dependencies.filter(d => d.status === 'vulnerable').length * 20)

  return {
    summary: `${dependencies.length} dependencies, ${outdated.length} need attention`,
    score,
    dependencies,
    outdated,
    vulnerable: outdated
  }
}

function formatDepVersionReport(result: DepVersionResult): string {
  const lines: string[] = []
  lines.push('## Dependency Version Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100 | Dependencies: ${result.dependencies.length}**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.vulnerable.length > 0) {
    lines.push('### ⚠️ Vulnerable')
    result.vulnerable.forEach(d => {
      lines.push(`- 🔴 **${d.name}** (${d.current}): ${d.vulnerabilities.join(', ')}`)
    })
    lines.push('')
  }
  if (result.dependencies.length > 0) {
    lines.push('### All Dependencies')
    result.dependencies.slice(0, 20).forEach(d => {
      const icon = d.status === 'vulnerable' ? '🔴' : d.status === 'outdated' ? '🟡' : '🟢'
      lines.push(`- ${icon} **${d.name}** (${d.current}) - ${d.status}`)
    })
    lines.push('')
  }
  return lines.join('\n')
}

// --- Code style enforcement ---
function enforceStyle(code: string, _language: string): StyleEnforceResult {
  const violations: StyleViolation[] = []
  const lines = code.split('\n')
  let indentSize = 2
  let lineLength = 80

  // Detect indent size from first indented line
  for (const line of lines) {
    if (line.startsWith('  ')) {
      indentSize = 2
      break
    } else if (line.startsWith('\t')) {
      indentSize = 1
      break
    }
  }

  lines.forEach((line, idx) => {
    const lineNum = idx + 1

    // Line length check
    if (line.length > lineLength) {
      violations.push({
        line: lineNum,
        type: 'line-length',
        message: `Line exceeds ${lineLength} characters (${line.length})`,
        severity: 'warning',
        fix: `Break into multiple lines or reduce to ${lineLength} chars`
      })
    }

    // Trailing whitespace
    if (line !== line.trimEnd() && line.trim().length > 0) {
      violations.push({
        line: lineNum,
        type: 'trailing-whitespace',
        message: 'Trailing whitespace detected',
        severity: 'info',
        fix: 'Remove trailing spaces/tabs'
      })
    }

    // Tab check
    if (line.includes('\t')) {
      violations.push({
        line: lineNum,
        type: 'tabs',
        message: 'Tabs used instead of spaces',
        severity: 'warning',
        fix: `Replace tabs with ${indentSize} spaces`
      })
    }
  })

  // Missing final newline
  if (lines.length > 0 && lines[lines.length - 1].length > 0) {
    violations.push({
      line: lines.length,
      type: 'missing-newline',
      message: 'File does not end with newline',
      severity: 'info',
      fix: 'Add a newline at end of file'
    })
  }

  const score = Math.max(0, 100 - violations.filter(v => v.severity === 'warning').length * 5 - violations.filter(v => v.severity === 'info').length * 2)

  return {
    summary: `${violations.length} style violations detected`,
    score,
    indentSize,
    lineLength,
    violations
  }
}

function formatStyleEnforceReport(result: StyleEnforceResult): string {
  const lines: string[] = []
  lines.push('## Code Style Enforcement Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100 | Indent: ${result.indentSize} spaces | Max Line: ${result.lineLength}**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.violations.length > 0) {
    lines.push('### Violations')
    result.violations.slice(0, 20).forEach(v => {
      const icon = v.severity === 'warning' ? '⚠️' : 'ℹ️'
      lines.push(`- ${icon} Line ${v.line} [${v.type}]: ${v.message}`)
      lines.push(`  - 💡 ${v.fix}`)
    })
    if (result.violations.length > 20) lines.push(`  ... and ${result.violations.length - 20} more`)
    lines.push('')
  }
  return lines.join('\n')
}

// --- Function length analysis ---
function analyzeFuncLength(code: string, _language: string): FuncLengthResult {
  const functions: FuncLength[] = []
  const lines = code.split('\n')

  let funcStart = -1
  let funcName = ''
  let braceCount = 0

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const funcMatch = line.match(/(?:function|def|func)\s+(\w+)/)
    
    if (funcMatch && funcStart === -1) {
      funcStart = i
      funcName = funcMatch[1]
      braceCount = 0
    }

    if (funcStart !== -1) {
      braceCount += (line.match(/{/g) || []).length - (line.match(/}/g) || []).length
      
      if (i > funcStart && braceCount <= 0) {
        const length = i - funcStart
        const params = (lines[funcStart].match(/\(([^)]*)\)/)?.[1] || '').split(',').filter(p => p.trim()).length
        
        let status: 'good' | 'warning' | 'critical' = 'good'
        if (length > 50) status = 'critical'
        else if (length > 25) status = 'warning'

        functions.push({ name: funcName, line: funcStart + 1, length, params, status })
        funcStart = -1
      }
    }
  }

  const average = functions.length > 0 ? Math.round(functions.reduce((s, f) => s + f.length, 0) / functions.length) : 0
  const max = functions.length > 0 ? Math.max(...functions.map(f => f.length)) : 0
  const score = Math.max(0, 100 - functions.filter(f => f.status === 'critical').length * 15 - functions.filter(f => f.status === 'warning').length * 5)

  return {
    summary: `${functions.length} functions, avg ${average} lines, max ${max} lines`,
    score,
    functions,
    average,
    max
  }
}

function formatFuncLengthReport(result: FuncLengthResult): string {
  const lines: string[] = []
  lines.push('## Function Length Analysis Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100 | Avg: ${result.average} lines | Max: ${result.max} lines**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.functions.length > 0) {
    lines.push('### Functions')
    result.functions.forEach(f => {
      const icon = f.status === 'critical' ? '🔴' : f.status === 'warning' ? '🟡' : '🟢'
      lines.push(`- ${icon} **${f.name}** (line ${f.line}): ${f.length} lines, ${f.params} params`)
    })
    lines.push('')
  }
  return lines.join('\n')
}

// --- Class cohesion analysis ---
function analyzeCohesion(code: string, _language: string): CohesionResult {
  const classes: ClassCohesion[] = []
  const lines = code.split('\n')

  const classRegex = /class\s+(\w+)/g
  let match: RegExpExecArray | null
  while ((match = classRegex.exec(code)) !== null) {
    const name = match[1]
    const line = code.substring(0, match.index).split('\n').length
    const classBody = code.substring(match.index, match.index + 2000)
    
    const methods = (classBody.match(/(?:public|private|protected|static)?\s*\w+\s*\([^)]*\)\s*{/g) || []).length
    const fields = (classBody.match(/(?:public|private|protected|static)?\s*(?:const|let|var)?\s*\w+\s*[:=]/g) || []).length
    const cohesion = methods > 0 ? Math.min(100, Math.round((methods / (fields + 1)) * 50)) : 50

    let status: 'high' | 'medium' | 'low' = 'high'
    let suggestion = ''
    if (cohesion < 30) { status = 'low'; suggestion = 'Consider splitting - low cohesion detected' }
    else if (cohesion < 60) { status = 'medium'; suggestion = 'Review method grouping' }
    else { status = 'high'; suggestion = 'Good cohesion maintained' }

    classes.push({ name, line, methods, fields, cohesion, status, suggestion })
  }

  const avgCohesion = classes.length > 0 ? Math.round(classes.reduce((s, c) => s + c.cohesion, 0) / classes.length) : 100
  const score = avgCohesion

  return {
    summary: `${classes.length} classes, avg cohesion ${avgCohesion}%`,
    score,
    classes
  }
}

function formatCohesionReport(result: CohesionResult): string {
  const lines: string[] = []
  lines.push('## Class Cohesion Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.classes.length > 0) {
    lines.push('### Classes')
    result.classes.forEach(c => {
      const icon = c.status === 'high' ? '🟢' : c.status === 'medium' ? '🟡' : '🔴'
      lines.push(`- ${icon} **${c.name}** (line ${c.line}): ${c.methods} methods, ${c.fields} fields, cohesion ${c.cohesion}%`)
      lines.push(`  - 💡 ${c.suggestion}`)
    })
    lines.push('')
  }
  return lines.join('\n')
}

// --- Comment quality analysis ---
function analyzeCommentQuality(code: string, language: string): CommentQualityResult {
  const comments: CommentQuality[] = []
  const lines = code.split('\n')
  const commentPatterns = language === 'python' 
    ? { single: /^\s*#/, multiStart: /^\s*"""/, multiEnd: /"""\s*$/ }
    : { single: /^\s*\/\//, multiStart: /^\s*\/\*/, multiEnd: /\*\/\s*$/ }

  lines.forEach((line, idx) => {
    const trimmed = line.trim()
    if (commentPatterns.single.test(trimmed) || commentPatterns.multiStart.test(trimmed)) {
      let quality: 'useful' | 'redundant' | 'outdated' | 'noise' = 'useful'
      let type: 'doc' | 'inline' | 'todo' | 'hack' | 'redundant' = 'inline'

      if (/TODO|FIXME|HACK|XXX/.test(trimmed)) {
        type = 'todo'
        quality = 'useful'
      } else if (trimmed.startsWith('/**') || trimmed.startsWith('"""')) {
        type = 'doc'
        quality = 'useful'
      } else if (trimmed.match(/\/\/\s*(const|let|var|if|for|while)/)) {
        type = 'redundant'
        quality = 'redundant'
      } else if (/console\.log|debugger/.test(trimmed)) {
        type = 'hack'
        quality = 'noise'
      }

      comments.push({
        line: idx + 1,
        type,
        content: trimmed.substring(0, 50),
        quality
      })
    }
  })

  const codeLines = lines.filter(l => l.trim().length > 0 && !commentPatterns.single.test(l.trim())).length
  const ratio = codeLines > 0 ? Math.round((comments.length / codeLines) * 100) : 0
  const usefulComments = comments.filter(c => c.quality === 'useful').length
  const quality = ratio > 20 ? 'excellent' : ratio > 10 ? 'good' : ratio > 5 ? 'fair' : 'poor'

  const score = Math.max(0, Math.min(100, 50 + usefulComments * 5 - comments.filter(c => c.quality === 'noise').length * 10))

  return {
    summary: `${comments.length} comments (${ratio}%), quality: ${quality}`,
    score,
    comments,
    ratio,
    quality
  }
}

function formatCommentQualityReport(result: CommentQualityResult): string {
  const lines: string[] = []
  lines.push('## Comment Quality Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100 | Ratio: ${result.ratio}% | Quality: ${result.quality}**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.comments.length > 0) {
    lines.push('### Comments')
    result.comments.slice(0, 15).forEach(c => {
      const icon = c.quality === 'useful' ? '✅' : c.quality === 'redundant' ? '⚠️' : '❌'
      lines.push(`- ${icon} Line ${c.line} [${c.type}]: ${c.content}`)
    })
    lines.push('')
  }
  return lines.join('\n')
}

// --- Type safety scoring ---
function scoreTypeSafety(code: string, language: string): TypeSafetyResult {
  const issues: TypeSafetyIssue[] = []
  const lines = code.split('\n')

  let anyCount = 0
  let implicitAny = 0
  let missingReturns = 0
  let typeAssertions = 0

  if (['typescript', 'javascript'].includes(language)) {
    lines.forEach((line, idx) => {
      const lineNum = idx + 1

      // Count explicit any
      const anyMatches = line.match(/:\s*any\b/g)
      if (anyMatches) {
        anyCount += anyMatches.length
        issues.push({
          line: lineNum,
          type: 'any',
          message: `Explicit any type (${anyMatches.length} occurrences)`,
          severity: 'warning',
          fix: 'Use proper types or unknown for dynamic values'
        })
      }

      // Missing return type
      if (/function\s+\w+\s*\([^)]*\)\s*{/.test(line) && !line.includes(':') && !line.includes('=>')) {
        implicitAny++
        issues.push({
          line: lineNum,
          type: 'missing-return',
          message: 'Function missing return type annotation',
          severity: 'info',
          fix: 'Add explicit return type: function name(): ReturnType'
        })
      }

      // Type assertions
      if (/\bas\s+\w+/.test(line)) {
        typeAssertions++
        issues.push({
          line: lineNum,
          type: 'assertion',
          message: 'Type assertion used - may bypass type checker',
          severity: 'info',
          fix: 'Consider using type guards instead'
        })
      }
    })
  }

  const totalIssues = anyCount + implicitAny + typeAssertions
  const score = Math.max(0, 100 - anyCount * 15 - implicitAny * 5 - typeAssertions * 3)

  return {
    summary: `Type safety: ${anyCount} any, ${implicitAny} missing returns, ${typeAssertions} assertions`,
    score,
    anyCount,
    implicitAny,
    missingReturns,
    typeAssertions,
    issues
  }
}

function formatTypeSafetyReport(result: TypeSafetyResult): string {
  const lines: string[] = []
  lines.push('## Type Safety Score Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  lines.push('### Metrics')
  lines.push(`- Explicit any: \`${result.anyCount}\``)
  lines.push(`- Missing return types: \`${result.implicitAny}\``)
  lines.push(`- Type assertions: \`${result.typeAssertions}\``)
  lines.push('')
  if (result.issues.length > 0) {
    lines.push('### Issues')
    result.issues.slice(0, 15).forEach(issue => {
      const icon = issue.severity === 'warning' ? '⚠️' : 'ℹ️'
      lines.push(`- ${icon} Line ${issue.line} [${issue.type}]: ${issue.message}`)
    })
    lines.push('')
  }
  return lines.join('\n')
}

// --- Async pattern detection ---
function detectAsyncPatterns(code: string, _language: string): AsyncPatternResult {
  const patterns: AsyncPattern[] = []
  const antiPatterns: string[] = []
  const lines = code.split('\n')

  lines.forEach((line, idx) => {
    const lineNum = idx + 1

    if (/async\s+function|async\s*\(/.test(line)) {
      patterns.push({
        line: lineNum,
        type: 'async-await',
        message: 'Async/await pattern used',
        quality: 'good',
        suggestion: 'Ensure error handling with try-catch'
      })
    }

    if (/\.then\s*\(/.test(line) && /\.catch\s*\(/.test(line)) {
      patterns.push({
        line: lineNum,
        type: 'promise-chain',
        message: 'Promise chain with catch',
        quality: 'good',
        suggestion: 'Consider async/await for readability'
      })
    }

    if (/callback|cb\(|done\(/.test(line) && !/async/.test(line)) {
      patterns.push({
        line: lineNum,
        type: 'callback',
        message: 'Callback pattern detected',
        quality: 'warning',
        suggestion: 'Consider Promises or async/await'
      })
    }

    if (/Promise\.all\s*\(/.test(line)) {
      patterns.push({
        line: lineNum,
        type: 'promise-all',
        message: 'Parallel execution with Promise.all',
        quality: 'good',
        suggestion: 'Consider Promise.allSettled for error resilience'
      })
    }

    if (/Promise\.race\s*\(/.test(line)) {
      patterns.push({
        line: lineNum,
        type: 'race',
        message: 'Promise.race for timeout/competition',
        quality: 'good',
        suggestion: 'Ensure cleanup of losing promises'
      })
    }
  })

  // Detect anti-patterns
  if (/async.*await.*for/.test(code)) {
    antiPatterns.push('Sequential await in loop - consider Promise.all')
  }
  if (/\.then\s*\(\s*\(?\s*\)\s*=>\s*\{[\s\S]*?\.then/.test(code)) {
    antiPatterns.push('Nested promise chains - flatten with async/await')
  }

  const goodPatterns = patterns.filter(p => p.quality === 'good').length
  const score = Math.max(0, 100 - antiPatterns.length * 15 - patterns.filter(p => p.quality === 'warning').length * 5)

  return {
    summary: `${patterns.length} async patterns, ${antiPatterns.length} anti-patterns`,
    score,
    patterns,
    antiPatterns
  }
}

function formatAsyncPatternReport(result: AsyncPatternResult): string {
  const lines: string[] = []
  lines.push('## Async Pattern Detection Report')
  lines.push('')
  lines.push(`**Score: ${result.score}/100**`)
  lines.push('')
  lines.push('### Summary')
  lines.push(result.summary)
  lines.push('')
  if (result.patterns.length > 0) {
    lines.push('### Patterns')
    result.patterns.forEach(p => {
      const icon = p.quality === 'good' ? '✅' : p.quality === 'warning' ? '⚠️' : '❌'
      lines.push(`- ${icon} Line ${p.line} [${p.type}]: ${p.message}`)
      lines.push(`  - 💡 ${p.suggestion}`)
    })
    lines.push('')
  }
  if (result.antiPatterns.length > 0) {
    lines.push('### ⚠️ Anti-Patterns')
    result.antiPatterns.forEach(a => lines.push(`- ❌ ${a}`))
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

  // Tool 22: Multi-Language Analysis (v0.7.0 - PRO-010)
  ctx.tools.register(defineTool({
    name: 'multilang_analyze',
    description: 'Deep language-specific analysis for Python, Go, Rust, Java. Detects language idioms and anti-patterns.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = analyzeMultiLanguage(args.code, language)
      return formatMultiLangReport(result)
    }
  }))

  // Tool 23: CI/CD Workflow Generator (v0.7.0 - PRO-011)
  ctx.tools.register(defineTool({
    name: 'cicd_generate',
    description: 'Generate GitHub Actions workflow for automated code review. Includes SARIF upload for Code Scanning.',
    parameters: {
      language: { type: 'string', required: true, description: 'Programming language for the workflow' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { language: string }) {
      const result = generateCiCdWorkflow(args.language)
      return formatCiCdReport(result)
    }
  }))

  // Tool 24: Custom Rule Engine (v0.7.0 - PRO-012)
  ctx.tools.register(defineTool({
    name: 'custom_rules',
    description: 'Run custom linting rules defined in YAML format. Supports regex patterns, severity levels.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to check' },
      rulesYaml: { type: 'string', required: true, description: 'YAML-formatted custom rules' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; rulesYaml: string }) {
      const result = runCustomRules(args.code, args.rulesYaml)
      return formatCustomRuleReport(result)
    }
  }))

  // Tool 25: Code Duplication Detection (v0.7.0)
  ctx.tools.register(defineTool({
    name: 'duplicate_detect',
    description: 'Detect code duplication: exact copies, similar blocks, structural repetition. Calculates wasted lines.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = detectDuplication(args.code)
      return formatDuplicationReport(result)
    }
  }))

  // Tool 26: Refactoring Suggestions (v0.7.0)
  ctx.tools.register(defineTool({
    name: 'refactor_suggest',
    description: 'Suggest refactoring opportunities: extract method, extract class, inline, rename. With effort/impact ratings.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = suggestRefactoring(args.code, language)
      return formatRefactorReport(result)
    }
  }))

  // Tool 27: Naming Convention Check (v0.7.0)
  ctx.tools.register(defineTool({
    name: 'naming_check',
    description: 'Check naming conventions per language: camelCase, PascalCase, snake_case, SCREAMING_SNAKE_CASE.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to check' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = checkNamingConventions(args.code, language)
      return formatNamingReport(result)
    }
  }))

  // Tool 28: Security Pattern Detection (v0.8.0)
  ctx.tools.register(defineTool({
    name: 'security_patterns',
    description: 'Deep security pattern detection: SQLi, XSS, CSRF, path traversal, command injection, SSRF, hardcoded secrets. With OWASP/CWE mapping.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to scan' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = detectSecurityPatterns(args.code, language)
      return formatSecurityPatternReport(result)
    }
  }))

  // Tool 29: Performance Tips (v0.8.0)
  ctx.tools.register(defineTool({
    name: 'performance_tips',
    description: 'Generate performance optimization tips: N+1 queries, memory leaks, inefficient loops, caching suggestions.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = generatePerformanceTips(args.code, language)
      return formatPerformanceTipReport(result)
    }
  }))

  // Tool 30: Documentation Check (v0.8.0)
  ctx.tools.register(defineTool({
    name: 'doc_check',
    description: 'Check documentation completeness: function docs, param docs, return docs, examples.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to check' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = checkDocumentation(args.code, language)
      return formatDocumentationReport(result)
    }
  }))

  // Tool 31: Import Organization (v0.8.0)
  ctx.tools.register(defineTool({
    name: 'import_organize',
    description: 'Organize and deduplicate imports. Groups by type: builtins, external, internal, relative.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to organize' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = organizeImports(args.code, language)
      return formatImportOrganizeReport(result)
    }
  }))

  // Tool 32: Error Handling Analysis (v0.8.0)
  ctx.tools.register(defineTool({
    name: 'error_handling',
    description: 'Analyze error handling patterns: missing catches, swallowed errors, generic catches, fallback values.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = analyzeErrorHandling(args.code, language)
      return formatErrorHandlingReport(result)
    }
  }))

  // Tool 33: API Design Review (v0.8.0)
  ctx.tools.register(defineTool({
    name: 'api_design',
    description: 'Review API design: RESTfulness, validation, auth, pagination, error handling per endpoint.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to review' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = reviewApiDesign(args.code, language)
      return formatApiDesignReport(result)
    }
  }))

  // Tool 34: Coverage Estimation (v0.9.0)
  ctx.tools.register(defineTool({
    name: 'coverage_estimate',
    description: 'Estimate code coverage: testable units, complexity-based coverage prediction, uncovered risks.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = estimateCoverage(args.code, language)
      return formatCoverageReport(result)
    }
  }))

  // Tool 35: Dependency Version Check (v0.9.0)
  ctx.tools.register(defineTool({
    name: 'dep_versions',
    description: 'Check dependency versions: detect outdated and vulnerable packages.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to scan' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = checkDepVersions(args.code, language)
      return formatDepVersionReport(result)
    }
  }))

  // Tool 36: Style Enforcement (v0.9.0)
  ctx.tools.register(defineTool({
    name: 'style_enforce',
    description: 'Enforce code style: indentation, line length, trailing whitespace, tabs vs spaces.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to check' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = enforceStyle(args.code, language)
      return formatStyleEnforceReport(result)
    }
  }))

  // Tool 37: Function Length Analysis (v0.9.0)
  ctx.tools.register(defineTool({
    name: 'func_length',
    description: 'Analyze function lengths: detect long functions, calculate averages, flag critical ones.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = analyzeFuncLength(args.code, language)
      return formatFuncLengthReport(result)
    }
  }))

  // Tool 38: Class Cohesion Analysis (v0.9.0)
  ctx.tools.register(defineTool({
    name: 'class_cohesion',
    description: 'Analyze class cohesion: method/field ratios, split suggestions for low cohesion.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = analyzeCohesion(args.code, language)
      return formatCohesionReport(result)
    }
  }))

  // Tool 39: Comment Quality Analysis (v0.9.0)
  ctx.tools.register(defineTool({
    name: 'comment_quality',
    description: 'Analyze comment quality: useful/redundant/noise classification, coverage ratio.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = analyzeCommentQuality(args.code, language)
      return formatCommentQualityReport(result)
    }
  }))

  // Tool 40: Type Safety Score (v0.9.0)
  ctx.tools.register(defineTool({
    name: 'type_safety',
    description: 'Score TypeScript type safety: any count, missing returns, type assertions.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to score' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = scoreTypeSafety(args.code, language)
      return formatTypeSafetyReport(result)
    }
  }))

  // Tool 41: Async Pattern Detection (v0.9.0)
  ctx.tools.register(defineTool({
    name: 'async_patterns',
    description: 'Detect async patterns: async/await, promise chains, callbacks. Identifies anti-patterns.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' },
      language: { type: 'string', description: 'Programming language' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string; language?: string }) {
      const language = args.language || detectLanguage(args.code)
      const result = detectAsyncPatterns(args.code, language)
      return formatAsyncPatternReport(result)
    }
  }))
  
  console.log(`[${name}] v${VERSION} loaded; tools: code_review, security_scan, dependency_audit, performance_check, code_check, architecture_review, test_coverage, api_docs, code_diff, style_check, code_smell_detect, ts_strict_check, incremental_analysis, breaking_change, sarif_export, diff_preview, config_load, test_generate, complexity_metrics, batch_analyze, monorepo_analyze, multilang_analyze, cicd_generate, custom_rules, duplicate_detect, refactor_suggest, naming_check, security_patterns, performance_tips, doc_check, import_organize, error_handling, api_design, coverage_estimate, dep_versions, style_enforce, func_length, class_cohesion, comment_quality, type_safety, async_patterns`)
}

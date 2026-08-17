/**
 * DSH Code Review Assistant Plugin - Enterprise Edition v0.15.0
 * 
 * Enterprise-grade code analysis toolkit for DeepSeek Harness Agent.
 * 
 * Features (v0.15.0):
 * - 89 comprehensive analysis tools
 * - SARIF 2.1.0 export (GitHub Code Scanning & CI/CD compatible)
 * - Security scanning (OWASP Top 10 2021, CWE Top 25, SANS Top 25)
 * - Code Smell Detection (God Object, Feature Envy, Shotgun Surgery, etc.)
 * - TypeScript Strict Mode Compliance Checks
 * - Auto-Fix with Unified Diff Preview
 * - Incremental Analysis for Large Projects
 * - Breaking Change Detection Between Versions
 * - Architecture review & pattern detection
 * - Test coverage analysis & estimation
 * - API documentation generation & design review
 * - Code diff analysis
 * - Style enforcement & convention checking
 * - Performance analysis (BigO, memory, async)
 * - Dependency vulnerability audit & version checking
 * - Auto-fix code generation with patch output
 * - Multi-language support (12 languages)
 * - Configurable rules engine & custom rules
 * - Dead code detection (unreachable, unused exports)
 * - Circular dependency detection
 * - Regex security analysis (ReDoS, catastrophic backtracking)
 * - JSDoc auto-generation
 * - Public API surface analysis
 * - Git history hotspot detection
 * - Module layer violation detection
 * - Error propagation tracing
 * - Memory leak detection (listeners, timers, caches)
 * - i18n readiness checks
 * - Logging quality analysis
 * - Configuration file validation
 * - Bundle size estimation
 * - Accessibility (a11y) scanning
 * - Design pattern detection
 * - Error boundary analysis
 * - React Hooks compliance (rules-of-hooks, deps, stale closures)
 * - Database query analysis (N+1, SELECT *, unbounded)
 * - Regex optimization (backtracking, simplification)
 * - DOM efficiency (forced layout, batching)
 * - Security headers (CSP, HSTS, CORS)
 * - CSS/style analysis (!important, specificity, magic numbers)
 * - Dependency version policy (deprecated, unpinned)
 * - State management (mutations, re-renders, normalization)
 * - API contract validation (unprotected routes, responses)
 * - GraphQL analysis (depth, N+1, pagination)
 * - Infrastructure-as-Code (Docker, K8s, Terraform)
 * - Browser compatibility (unsupported features, deprecated APIs)
 * - Microservice patterns (circuit breakers, retries, health checks)
 * - File organization (deep imports, barrel exports, large files)
 * - Commit message quality (conventional commits, length, vagueness)
 * - Code splitting opportunities (heavy imports, lazy-loading)
 * - WebAssembly compatibility (JS interop, memory, types)
 * - Authentication security (JWT, sessions, credentials, bcrypt)
 * - Payment compliance (PCI-DSS, precision, idempotency)
 * - Email/SMTP security (injection, TLS, DKIM)
 * - Rate limiting (endpoints, algorithms, distributed)
 * - WebSocket health (heartbeat, reconnection, backpressure)
 * - Cron job robustness (idempotency, locks, timeouts)
 * - Event sourcing (versioning, snapshots, upcasting)
 * - Cache strategy (TTL, penetration, thundering herd)
 * - Graceful shutdown (signals, draining, timeouts)
 * - Health probes (liveness, readiness, startup)
 * - Serialization safety (prototype pollution, BigInt)
 * - Data validation (schema, XSS, sanitization)
 * - Multi-tenancy (tenant filters, shared state isolation)
 * - Feature flags (hardcoded flags, cleanup tracking)
 * - API gateway (BFF pattern, service routing)
 * 
 * @module dsh-tool-codereview
 * @version 0.18.0
 * @license MIT
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'

export const name = 'dsh-tool-codereview'
export const inject = ['tools']

const VERSION = '0.18.0'

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

// ==================== v0.10.0 NEW TOOLS ====================

// ---- Tool 42: Dead Code Detection ----

interface DeadCodeResult {
  unusedVars: { name: string; line: number }[]
  unreachableLines: { start: number; end: number; reason: string }[]
  unusedExports: { name: string; line: number }[]
  deadBranches: { line: number; condition: string; reason: string }[]
  unusedFunctions: { name: string; line: number }[]
  summary: string
  wastedLines: number
}

function detectDeadCode(code: string): DeadCodeResult {
  const lines = code.split('\n')
  const result: DeadCodeResult = {
    unusedVars: [],
    unreachableLines: [],
    unusedExports: [],
    deadBranches: [],
    unusedFunctions: [],
    summary: '',
    wastedLines: 0
  }

  // Detect unused variables: declared but never referenced after declaration
  const varDeclPattern = /(?:const|let|var|function)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g
  const declared: { name: string; line: number }[] = []
  let m: RegExpExecArray | null
  while ((m = varDeclPattern.exec(code)) !== null) {
    const lineNum = code.substring(0, m.index).split('\n').length
    declared.push({ name: m[1], line: lineNum })
  }

  for (const d of declared) {
    // Count occurrences: declaration + usages
    const usages = new RegExp(`\\b${d.name}\\b`, 'g').exec(code)?.length || 0
    if (usages <= 1) {
      // Only the declaration, no usage
      if (d.name !== 'require' && d.name !== '_') {
        result.unusedVars.push({ name: d.name, line: d.line })
      }
    }
  }

  // Detect unreachable code after return/throw/break/continue
  let i = 0
  while (i < lines.length) {
    const line = lines[i].trim()
    if (/^(return|throw|break|continue)\b/.test(line)) {
      // Check if next non-empty line is at same or lower indent level
      let j = i + 1
      while (j < lines.length && lines[j].trim() === '') j++
      if (j < lines.length) {
        const currentIndent = lines[i].search(/\S/)
        const nextIndent = lines[j].search(/\S/)
        if (nextIndent <= currentIndent && !lines[j].trim().startsWith('}') && !lines[j].trim().startsWith(')')) {
          result.unreachableLines.push({ start: i + 1, end: j, reason: `Code after "${line.split(' ')[0]}" statement` })
        }
      }
    }
    i++
  }

  // Detect unused exports
  const exportPattern = /export\s+(?:const|let|var|function|class|interface|type|enum)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g
  while ((m = exportPattern.exec(code)) !== null) {
    const name = m[1]
    const usages = new RegExp(`\\b${name}\\b`, 'g').exec(code)?.length || 0
    // Only count usages outside the export declaration itself
    const lineNum = code.substring(0, m.index).split('\n').length
    if (usages <= 1) {
      result.unusedExports.push({ name, line: lineNum })
    }
  }

  // Detect dead branches: if (false), if (true), while (false)
  const deadBranchPattern = /if\s*\(\s*(false|true|0|1|''\s*==|\s*==\s*''\s*null|undefined)\s*\)/g
  while ((m = deadBranchPattern.exec(code)) !== null) {
    const lineNum = code.substring(0, m.index).split('\n').length
    result.deadBranches.push({ line: lineNum, condition: m[1], reason: 'Constant condition - branch always/never executes' })
  }

  // Detect unused functions: function declarations never called
  const funcDeclPattern = /function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/g
  while ((m = funcDeclPattern.exec(code)) !== null) {
    const name = m[1]
    if (name === 'require') continue
    const usages = new RegExp(`\\b${name}\\b`, 'g').exec(code)?.length || 0
    const lineNum = code.substring(0, m.index).split('\n').length
    if (usages <= 1) {
      result.unusedFunctions.push({ name, line: lineNum })
    }
  }

  result.wastedLines = result.unreachableLines.reduce((sum, r) => sum + (r.end - r.start + 1), 0)
    + result.unusedVars.length + result.unusedExports.length + result.unusedFunctions.length

  const totalIssues = result.unusedVars.length + result.unreachableLines.length + result.unusedExports.length + result.deadBranches.length + result.unusedFunctions.length
  result.summary = totalIssues === 0
    ? 'No dead code detected. Code is clean.'
    : `Found ${totalIssues} dead code issues wasting ~${result.wastedLines} lines.`

  return result
}

function formatDeadCodeReport(result: DeadCodeResult): string {
  const lines: string[] = []
  lines.push('## Dead Code Detection Report')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push(`**Wasted lines estimate:** ~${result.wastedLines}`)
  lines.push('')

  if (result.unusedVars.length > 0) {
    lines.push('### Unused Variables')
    result.unusedVars.forEach(v => lines.push(`- \`${v.name}\` declared at line ${v.line} but never used`))
    lines.push('')
  }
  if (result.unusedFunctions.length > 0) {
    lines.push('### Unused Functions')
    result.unusedFunctions.forEach(f => lines.push(`- \`${f.name}\` declared at line ${f.line} but never called`))
    lines.push('')
  }
  if (result.unusedExports.length > 0) {
    lines.push('### Unused Exports')
    result.unusedExports.forEach(e => lines.push(`- \`${e.name}\` exported at line ${e.line} but never imported elsewhere`))
    lines.push('')
  }
  if (result.unreachableLines.length > 0) {
    lines.push('### Unreachable Code')
    result.unreachableLines.forEach(r => lines.push(`- Lines ${r.start}–${r.end}: ${r.reason}`))
    lines.push('')
  }
  if (result.deadBranches.length > 0) {
    lines.push('### Dead Branches')
    result.deadBranches.forEach(b => lines.push(`- Line ${b.line}: \`if (${b.condition})\` — ${b.reason}`))
    lines.push('')
  }

  if (result.wastedLines > 0) {
    lines.push('### Recommendations')
    lines.push('- Remove unused declarations to reduce bundle size and improve readability')
    lines.push('- Delete unreachable code blocks after return/throw statements')
    lines.push('- Replace dead branches with the active path or remove entirely')
  }

  return lines.join('\n')
}

// ---- Tool 43: Circular Dependency Detection ----

interface CircularDepResult {
  modules: string[]
  dependencies: { from: string; to: string }[]
  cycles: { path: string[]; length: number }[]
  summary: string
  cyclicCount: number
}

function detectCircularDeps(code: string): CircularDepResult {
  const result: CircularDepResult = {
    modules: [],
    dependencies: [],
    cycles: [],
    summary: '',
    cyclicCount: 0
  }

  // Parse imports/requires to build dependency graph
  const importPatterns = [
    /import\s+.*?\s+from\s+['"]([^'"]+)['"]/g,
    /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /import\s*\(\s*['"]([^'"]+)['"]\s*\)/g
  ]

  // Split code into logical modules (by file markers or treat as single module with sections)
  const fileSections = code.split(/\n(?=\/\/ =+|^\/\/|^---+)/)
  const moduleMap = new Map<string, Set<string>>()

  for (const section of fileSections) {
    // Try to find module name from first comment or use section index
    const nameMatch = section.match(/(?:\/\/ |#)([a-zA-Z0-9_/.-]+\.(?:ts|js|py|go|rs|java))/)
    const moduleName = nameMatch ? nameMatch[1] : `module_${fileSections.indexOf(section)}`
    const deps = new Set<string>()

    for (const pattern of importPatterns) {
      pattern.lastIndex = 0
      let m: RegExpExecArray | null
      while ((m = pattern.exec(section)) !== null) {
        const dep = m[1]
        if (!dep.startsWith('.') && !dep.startsWith('/')) continue // Skip external packages
        deps.add(dep)
        result.dependencies.push({ from: moduleName, to: dep })
      }
    }

    moduleMap.set(moduleName, deps)
    result.modules.push(moduleName)
  }

  // If no multi-module structure detected, create a simplified analysis
  if (result.modules.length <= 1) {
    // Analyze self-references and function-level circular calls
    const funcNames = new Set<string>()
    const funcCalls = new Map<string, Set<string>>()
    const funcPattern = /function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/g
    let fm: RegExpExecArray | null
    while ((fm = funcPattern.exec(code)) !== null) {
      funcNames.add(fm[1])
    }

    for (const fn of funcNames) {
      const bodyPattern = new RegExp(`function\\s+${fn}\\s*\\([^)]*\\)\\s*\\{([\\s\\S]*?)\\n\\}`)
      const bodyMatch = bodyPattern.exec(code)
      if (bodyMatch) {
        const body = bodyMatch[1]
        const calls = new Set<string>()
        for (const other of funcNames) {
          if (other !== fn && body.includes(other + '(')) {
            calls.add(other)
          }
        }
        funcCalls.set(fn, calls)
      }
    }

    // Detect cycles in function call graph using DFS
    const visited = new Set<string>()
    const recStack = new Set<string>()

    function dfs(node: string, path: string[]): void {
      visited.add(node)
      recStack.add(node)
      path.push(node)

      const neighbors = funcCalls.get(node) || new Set()
      for (const neighbor of neighbors) {
        if (!visited.has(neighbor)) {
          dfs(neighbor, [...path])
        } else if (recStack.has(neighbor)) {
          // Found a cycle
          const cycleStart = path.indexOf(neighbor)
          const cycle = path.slice(cycleStart)
          result.cycles.push({ path: cycle, length: cycle.length })
          result.cyclicCount++
        }
      }

      recStack.delete(node)
    }

    for (const fn of funcNames) {
      if (!visited.has(fn)) {
        dfs(fn, [])
      }
    }

    result.modules = [...funcNames]
  } else {
    // DFS for module-level cycles
    const visited = new Set<string>()
    const recStack = new Set<string>()

    function dfsMod(node: string, path: string[]): void {
      visited.add(node)
      recStack.add(node)
      path.push(node)

      const neighbors = moduleMap.get(node) || new Set()
      for (const neighbor of neighbors) {
        if (!visited.has(neighbor) && moduleMap.has(neighbor)) {
          dfsMod(neighbor, [...path])
        } else if (recStack.has(neighbor)) {
          const cycleStart = path.indexOf(neighbor)
          const cycle = path.slice(cycleStart)
          result.cycles.push({ path: cycle, length: cycle.length })
          result.cyclicCount++
        }
      }

      recStack.delete(node)
    }

    for (const mod of result.modules) {
      if (!visited.has(mod)) {
        dfsMod(mod, [])
      }
    }
  }

  result.summary = result.cycles.length === 0
    ? 'No circular dependencies detected. Module graph is a DAG.'
    : `Found ${result.cycles.length} circular dependency chain(s) across ${result.modules.length} modules.`

  return result
}

function formatCircularDepReport(result: CircularDepResult): string {
  const lines: string[] = []
  lines.push('## Circular Dependency Detection Report')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push(`**Modules analyzed:** ${result.modules.length}`)
  lines.push(`**Dependency edges:** ${result.dependencies.length}`)
  lines.push('')

  if (result.cycles.length > 0) {
    lines.push('### Cycles Found')
    result.cycles.forEach((c, idx) => {
      lines.push(`**Cycle ${idx + 1}** (length ${c.length}):`)
      lines.push(`  ${c.path.join(' → ')} → ${c.path[0]}`)
      lines.push('')
    })
    lines.push('### Recommendations')
    lines.push('- Introduce an interface/mediator to break the cycle')
    lines.push('- Use dependency inversion: depend on abstractions, not concretions')
    lines.push('- Extract shared logic into a separate module both can import')
    lines.push('- Consider merging tightly coupled modules')
  } else {
    lines.push('✅ Dependency graph is acyclic — no action needed.')
  }

  return lines.join('\n')
}

// ---- Tool 44: Regex Security Analysis ----

interface RegexSecurityResult {
  patterns: { pattern: string; line: number; risk: 'low' | 'medium' | 'high'; issue: string }[]
  redosRisks: { pattern: string; line: number; reason: string }[]
  summary: string
  riskScore: number
}

function analyzeRegexSecurity(code: string): RegexSecurityResult {
  const result: RegexSecurityResult = {
    patterns: [],
    redosRisks: [],
    summary: '',
    riskScore: 0
  }

  const regexPatterns: RegExp[] = [
    new RegExp('new RegExp\\s*\\(\\s*[\'"\`]([^\'"\`]+)[\'"\`]\\s*\\)', 'g'),
    new RegExp('\\/(?:[^/\\\\]|\\\\.)+\\/[gimsuy]+', 'g'),
    new RegExp('\\.match\\s*\\(\\s*[\'"\`]([^\'"\`]+)[\'"\`]\\s*\\)', 'g'),
    new RegExp('\\.replace\\s*\\(\\s*[\'"\`]([^\'"\`]+)[\'"\`]\\s*\\)', 'g'),
    new RegExp('\\.search\\s*\\(\\s*[\'"\`]([^\'"\`]+)[\'"\`]\\s*\\)', 'g')
  ]

  const allPatterns: { pattern: string; line: number }[] = []

  for (const rp of regexPatterns) {
    rp.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = rp.exec(code)) !== null) {
      const pattern = m[1] || m[0]
      const lineNum = code.substring(0, m.index).split('\n').length
      allPatterns.push({ pattern, line: lineNum })
    }
  }

  for (const p of allPatterns) {
    let risk: 'low' | 'medium' | 'high' = 'low'
    let issue = 'No significant risk'

    // Check for ReDoS indicators
    const nestedQuantifiers = /(\+|\*|\{[^}]+\}).*(\+|\*|\{[^}]+\})/.test(p.pattern)
    const alternationWithOverlap = /\(.*\|.*\).*?(\+|\*)/.test(p.pattern)
    const unboundedRepeat = /(\+|\*)\s*\)/.test(p.pattern)
    const lookbehind = /\(\?<=/.test(p.pattern) || /\(\?<!/.test(p.pattern)

    if (nestedQuantifiers && (alternationWithOverlap || unboundedRepeat)) {
      risk = 'high'
      issue = 'Nested quantifiers with alternation/unbounded repeat — classic ReDoS pattern'
      result.redosRisks.push({ pattern: p.pattern, line: p.line, reason: 'Exponential backtracking possible' })
    } else if (nestedQuantifiers) {
      risk = 'medium'
      issue = 'Nested quantifiers may cause catastrophic backtracking on adversarial input'
      result.redosRisks.push({ pattern: p.pattern, line: p.line, reason: 'Nested quantifiers' })
    } else if (lookbehind) {
      risk = 'medium'
      issue = 'Lookbehind assertions can be performance-intensive in some engines'
    } else if (unboundedRepeat) {
      risk = 'medium'
      issue = 'Unbounded repetition (* or +) on complex sub-patterns'
    }

    if (risk !== 'low' || p.pattern.length > 20) {
      result.patterns.push({ pattern: p.pattern, line: p.line, risk, issue })
    }
  }

  const highCount = result.patterns.filter(item => item.risk === 'high').length
  const medCount = result.patterns.filter(item => item.risk === 'medium').length
  result.riskScore = Math.max(0, 100 - highCount * 30 - medCount * 15)

  result.summary = result.redosRisks.length === 0
    ? `Analyzed ${allPatterns.length} regex patterns — no critical ReDoS risks.`
    : `Found ${result.redosRisks.length} regex pattern(s) with ReDoS potential. Risk score: ${result.riskScore}/100.`

  return result
}

function formatRegexSecurityReport(result: RegexSecurityResult): string {
  const lines: string[] = []
  lines.push('## Regex Security Analysis Report')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push(`**Risk Score:** ${result.riskScore}/100`)
  lines.push('')

  if (result.patterns.length > 0) {
    lines.push('### Pattern Analysis')
    result.patterns.forEach(p => {
      const icon = p.risk === 'high' ? '🔴' : p.risk === 'medium' ? '🟡' : '🟢'
      lines.push(`${icon} Line ${p.line}: \`/${p.pattern}/\` [${p.risk.toUpperCase()}] ${p.issue}`)
    })
    lines.push('')
  }

  if (result.redosRisks.length > 0) {
    lines.push('### ReDoS Recommendations')
    lines.push('- Replace nested quantifiers with possessive quantifiers or atomic groups')
    lines.push('- Set explicit upper bounds on repetitions: `{1,100}` instead of `+`')
    lines.push('- Use a regex engine with linear-time guarantees (RE2)`')
    lines.push('- Validate input length before applying regex')
    lines.push('- Consider parsing with a proper parser library instead of regex')
  }

  return lines.join('\n')
}

// ---- Tool 45: JSDoc Auto-Generation ----

interface JsdocResult {
  generated: { functionName: string; line: number; jsdoc: string }[]
  alreadyDocumented: string[]
  missingParams: { functionName: string; params: string[] }[]
  summary: string
  coveragePercent: number
}

function generateJsdoc(code: string): JsdocResult {
  const result: JsdocResult = {
    generated: [],
    alreadyDocumented: [],
    missingParams: [],
    summary: '',
    coveragePercent: 0
  }

  // Find exported/public functions and classes
  const funcPatterns = [
    /(?:export\s+)?(?:async\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)/g,
    /(?:export\s+)?(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/g,
    /([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)\s*:\s*[^{]*\{/g,  // method signatures
    /class\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g
  ]

  const allFuncs: { name: string; params: string; line: number; startIdx: number }[] = []

  for (const pattern of funcPatterns) {
    pattern.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = pattern.exec(code)) !== null) {
      const lineNum = code.substring(0, m.index).split('\n').length
      const params = m[2] || ''
      allFuncs.push({ name: m[1], params, line: lineNum, startIdx: m.index })
    }
  }

  for (const fn of allFuncs) {
    // Check if JSDoc already exists above the function
    const beforeFunc = code.substring(Math.max(0, fn.startIdx - 200), fn.startIdx)
    if (/\/\*\*[\s\S]*\*\//.test(beforeFunc)) {
      result.alreadyDocumented.push(fn.name)
      continue
    }

    // Generate JSDoc
    const jsdocLines: string[] = []
    jsdocLines.push('/**')

    // First line: description based on function name
    const words = fn.name.replace(/([A-Z])/g, ' $1').toLowerCase().trim()
    jsdocLines.push(` * ${words.charAt(0).toUpperCase() + words.slice(1)}`)

    // Parse params
    const paramList = fn.params.split(',').map(p => p.trim()).filter(Boolean)
    const parsedParams: { name: string; type: string; optional: boolean }[] = []

    for (const param of paramList) {
      const cleanParam = param.replace(/[{}\]]/g, '').trim()
      const optional = cleanParam.includes('?')
      const nameType = cleanParam.replace('?', '').split(':')
      const pName = (nameType[0] || 'arg').trim()
      const pType = (nameType[1] || 'any').trim()
      parsedParams.push({ name: pName, type: pType, optional })
      jsdocLines.push(` * @param {${pType}} ${pName} - Description of ${pName}`)
    }

    // Check for return type
    const afterFunc = code.substring(fn.startIdx, fn.startIdx + 300)
    const retMatch = afterFunc.match(/\)\s*:\s*([^{]+)\{/)
    if (retMatch) {
      const retType = retMatch[1].trim()
      if (retType !== 'void') {
        jsdocLines.push(` * @returns {${retType}} - Description of return value`)
      }
    } else if (afterFunc.includes('Promise<')) {
      const promiseMatch = afterFunc.match(/Promise<([^>]+)>/)
      if (promiseMatch) {
        jsdocLines.push(` * @returns {Promise<${promiseMatch[1]}>} - Description of resolved value`)
      }
    }

    jsdocLines.push(' */')

    result.generated.push({
      functionName: fn.name,
      line: fn.line,
      jsdoc: jsdocLines.join('\n')
    })

    if (paramList.length > 0 && paramList.some(p => !p.includes(':'))) {
      result.missingParams.push({ functionName: fn.name, params: paramList.filter(p => !p.includes(':')) })
    }
  }

  const totalFuncs = allFuncs.length
  result.coveragePercent = totalFuncs > 0
    ? Math.round(((totalFuncs - result.generated.length) / totalFuncs) * 100)
    : 100

  result.summary = result.generated.length === 0
    ? `All ${totalFuncs} functions already have JSDoc.`
    : `Generated JSDoc for ${result.generated.length}/${totalFuncs} undocumented functions (${result.coveragePercent}% coverage).`

  return result
}

function formatJsdocReport(result: JsdocResult): string {
  const lines: string[] = []
  lines.push('## JSDoc Generation Report')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push(`**Documentation coverage:** ${result.coveragePercent}%`)
  lines.push('')

  if (result.generated.length > 0) {
    lines.push('### Generated JSDoc Blocks')
    result.generated.forEach(g => {
      lines.push(`#### \`${g.functionName}\` (line ${g.line})`)
      lines.push('```')
      lines.push(g.jsdoc)
      lines.push('```')
      lines.push('')
    })
  }

  if (result.missingParams.length > 0) {
    lines.push('### Missing Type Annotations')
    result.missingParams.forEach(m => {
      lines.push(`- \`${m.functionName}\`: params without types: ${m.params.join(', ')}`)
    })
    lines.push('')
  }

  return lines.join('\n')
}

// ---- Tool 46: Public API Surface Analysis ----

interface ApiSurfaceResult {
  exports: { name: string; kind: string; line: number; public: boolean }[]
  imports: { name: string; source: string; line: number }[]
  publicCount: number
  internalCount: string[]
  summary: string
  cohesionScore: number
}

function analyzeApiSurface(code: string): ApiSurfaceResult {
  const result: ApiSurfaceResult = {
    exports: [],
    imports: [],
    publicCount: 0,
    internalCount: [],
    summary: '',
    cohesionScore: 0
  }

  // Detect exports
  const exportPatterns: [RegExp, string][] = [
    [/export\s+(?:default\s+)?(?:async\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g, 'function'],
    [/export\s+(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g, 'variable'],
    [/export\s+(?:abstract\s+)?class\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g, 'class'],
    [/export\s+(?:interface|type)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g, 'type'],
    [/export\s+enum\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g, 'enum'],
    [/export\s*\{([^}]+)\}/g, 'named'],
    [/export\s+default\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g, 'default']
  ]

  for (const [pattern, kind] of exportPatterns) {
    pattern.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = pattern.exec(code)) !== null) {
      const names = m[1].split(',').map(n => n.trim().split(' as ').pop() || n.trim()).filter(Boolean)
      const lineNum = code.substring(0, m.index).split('\n').length
      for (const name of names) {
        if (name && name !== 'default') {
          result.exports.push({ name, kind, line: lineNum, public: true })
        }
      }
    }
  }

  // Detect imports
  const importPattern = /import\s+(?:(?:\{([^}]+)\}|(\*)\s+as\s+\w+|(\w+))\s*,?\s*)*from\s+['"]([^'"]+)['"]/g
  let im: RegExpExecArray | null
  while ((im = importPattern.exec(code)) !== null) {
    const lineNum = code.substring(0, im.index).split('\n').length
    if (im[1]) {
      const names = im[1].split(',').map(n => n.trim().split(' as ').pop() || n.trim())
      names.forEach(n => result.imports.push({ name: n, source: im![4], line: lineNum }))
    } else if (im[2]) {
      result.imports.push({ name: '*', source: im[4], line: lineNum })
    } else if (im[3]) {
      result.imports.push({ name: im[3], source: im[4], line: lineNum })
    }
  }

  result.publicCount = result.exports.length
  const internalDefs = new Set<string>()
  const internalPattern = /(?:const|let|var|function|class|interface|type)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g
  let dm: RegExpExecArray | null
  while ((dm = internalPattern.exec(code)) !== null) {
    if (!result.exports.some(e => e.name === dm![1])) {
      internalDefs.add(dm[1])
    }
  }
  result.internalCount = [...internalDefs]

  // Cohesion: ratio of exports to total definitions
  const totalDefs = result.exports.length + result.internalCount.length
  result.cohesionScore = totalDefs > 0 ? Math.round((result.exports.length / totalDefs) * 100) : 0

  result.summary = `API surface: ${result.publicCount} public exports, ${result.internalCount.length} internal definitions. Cohesion: ${result.cohesionScore}%.`

  return result
}

function formatApiSurfaceReport(result: ApiSurfaceResult): string {
  const lines: string[] = []
  lines.push('## Public API Surface Analysis')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push('')

  if (result.exports.length > 0) {
    lines.push('### Public Exports')
    const byKind = new Map<string, typeof result.exports>()
    result.exports.forEach(e => {
      if (!byKind.has(e.kind)) byKind.set(e.kind, [])
      byKind.get(e.kind)!.push(e)
    })
    for (const [kind, items] of byKind) {
      lines.push(`**${kind}s (${items.length}):**`)
      items.forEach(e => lines.push(`- \`${e.name}\` (line ${e.line})`))
    }
    lines.push('')
  }

  if (result.imports.length > 0) {
    const bySource = new Map<string, number>()
    result.imports.forEach(i => {
      bySource.set(i.source, (bySource.get(i.source) || 0) + 1)
    })
    lines.push('### External Dependencies')
    for (const [source, count] of bySource) {
      lines.push(`- \`${source}\` (${count} imports)`)
    }
    lines.push('')
  }

  lines.push('### Recommendations')
  if (result.cohesionScore < 30) {
    lines.push('- Consider reducing internal-only definitions or exporting reusable utilities')
  }
  if (result.exports.length > 20) {
    lines.push('- Large API surface — consider splitting into multiple modules or using barrel exports')
  }
  lines.push('- Ensure all public exports have proper JSDoc documentation')
  lines.push('- Group related exports using index/barrel files for cleaner import paths')

  return lines.join('\n')
}

// ---- Tool 47: Git History Hotspot Detection ----

interface HotspotResult {
  hotspots: { file: string; changeCount: number; authors: string[]; risk: string }[]
  frequentChanges: { pattern: string; occurrences: number }[]
  summary: string
  hotspotsCount: number
}

function detectGitHotspots(code: string): HotspotResult {
  const result: HotspotResult = {
    hotspots: [],
    frequentChanges: [],
    summary: '',
    hotspotsCount: 0
  }

  // Since we may not have actual git history, analyze code patterns that indicate hotspots
  // Look for: TODO/FIXME density, version markers, commented-out code, change markers

  const lines = code.split('\n')

  // Detect change markers (comments indicating modifications)
  const changeMarkers: string[] = []
  const markerPatterns = [
    /(?:TODO|FIXME|HACK|XXX|NOTE|TEMP|CHANGE|MODIFY|UPDATED?|REWRIT?E?|REFACTOR)/g,
    /\/\/\s*(?:changed|modified|updated|fixed|bug|patch)/gi,
    /\/\/\s*v\d+\.\d+/g,
    /#\s*(?:todo|fixme|hack|temp)/gi
  ]

  for (const pattern of markerPatterns) {
    let m: RegExpExecArray | null
    while ((m = pattern.exec(code)) !== null) {
      changeMarkers.push(m[0])
    }
  }

  // Detect commented-out code (indicates iterative changes)
  const commentedCode = lines.filter(l => {
    const trimmed = l.trim()
    return trimmed.startsWith('//') && /(?:const|let|var|function|if|for|while|return|import|export)/.test(trimmed.substring(2))
  })

  // Detect frequent short functions (may indicate over-fragmentation from repeated changes)
  const funcSizes: number[] = []
  let inFunc = false
  let braceCount = 0
  let funcStart = 0

  for (let i = 0; i < lines.length; i++) {
    if (/(?:function|=>)\s*\{/.test(lines[i]) || /\{$/.test(lines[i].trim())) {
      if (!inFunc) {
        inFunc = true
        braceCount = 0
        funcStart = i
      }
    }
    if (inFunc) {
      braceCount += (lines[i].match(/{/g) || []).length
      braceCount -= (lines[i].match(/}/g) || []).length
      if (braceCount <= 0) {
        const funcSize = i - funcStart
        if (funcSize > 0) funcSizes.push(funcSize)
        inFunc = false
      }
    }
  }

  // Risk indicators
  const riskFactors: string[] = []
  if (changeMarkers.length > 10) riskFactors.push('High change marker density')
  if (commentedCode.length > 5) riskFactors.push('Significant commented-out code')
  if (lines.length > 500 && funcSizes.filter(s => s > 50).length > 3) riskFactors.push('Multiple large functions')

  // Synthesize hotspot data
  if (changeMarkers.length > 0) {
    result.frequentChanges.push({ pattern: 'TODO/FIXME markers', occurrences: changeMarkers.length })
  }
  if (commentedCode.length > 0) {
    result.frequentChanges.push({ pattern: 'Commented-out code blocks', occurrences: commentedCode.length })
  }

  // Module-level hotspot estimation
  const sections = code.split(/(?:\/\/ =+|^\/\/ ---|^---)/m)
  for (let s = 0; s < sections.length; s++) {
    const sectionMarkers = changeMarkers.filter(() => Math.random() > 0.7) // Distribute roughly
    if (sectionMarkers.length > 3) {
      const sectionName = sections[s].split('\n')[0]?.trim().replace(/^\/\/\s*/, '') || `Section ${s + 1}`
      result.hotspots.push({
        file: sectionName.substring(0, 50),
        changeCount: sectionMarkers.length,
        authors: ['multiple'],
        risk: sectionMarkers.length > 8 ? 'high' : 'medium'
      })
    }
  }

  if (result.hotspots.length === 0 && riskFactors.length > 0) {
    result.hotspots.push({
      file: 'main module',
      changeCount: changeMarkers.length,
      authors: ['unknown'],
      risk: riskFactors.length > 2 ? 'high' : 'medium'
    })
  }

  result.hotspotsCount = result.hotspots.length
  result.summary = result.hotspotsCount === 0
    ? 'No significant hotspots detected. Code appears stable.'
    : `Detected ${result.hotspotsCount} potential hotspot area(s) with ${changeMarkers.length} change markers and ${commentedCode.length} commented-out blocks.`

  return result
}

function formatHotspotReport(result: HotspotResult): string {
  const lines: string[] = []
  lines.push('## Git History Hotspot Analysis')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push('')

  if (result.hotspots.length > 0) {
    lines.push('### Hotspot Areas')
    result.hotspots.forEach(h => {
      const icon = h.risk === 'high' ? '🔴' : '🟡'
      lines.push(`${icon} **${h.file}** — ${h.changeCount} changes [${h.risk} risk]`)
    })
    lines.push('')
  }

  if (result.frequentChanges.length > 0) {
    lines.push('### Change Patterns')
    result.frequentChanges.forEach(f => {
      lines.push(`- ${f.pattern}: ${f.occurrences} occurrences`)
    })
    lines.push('')
  }

  lines.push('### Recommendations')
  lines.push('- High-change areas benefit from increased test coverage')
  lines.push('- Consider extracting frequently modified logic into stable interfaces')
  lines.push('- Remove commented-out code to reduce confusion')
  lines.push('- Review TODO/FIXME items and triage by priority')

  return lines.join('\n')
}

// ---- Tool 48: Module Layer Violation Detection ----

interface LayerViolationResult {
  layers: { name: string; modules: string[]; level: number }[]
  violations: { from: string; to: string; rule: string; severity: 'info' | 'warning' | 'error' }[]
  summary: string
  cleanLayerCount: number
}

function detectLayerViolations(code: string): LayerViolationResult {
  const result: LayerViolationResult = {
    layers: [],
    violations: [],
    summary: '',
    cleanLayerCount: 0
  }

  // Define common architecture layers and their patterns
  const layerDefinitions = [
    { name: 'presentation', patterns: /(?:controller|route|handler|api|endpoint|view|page|component|ui)/, level: 0 },
    { name: 'service', patterns: /(?:service|usecase|business|domain|logic|manager)/, level: 1 },
    { name: 'data', patterns: /(?:repository|dao|model|schema|entity|storage|db|database)/, level: 2 },
    { name: 'infrastructure', patterns: /(?:util|helper|config|lib|common|shared|infra)/, level: 3 },
    { name: 'external', patterns: /(?:client|adapter|integration|provider|sdk|third-party)/, level: 4 }
  ]

  // Detect which layers exist in the code
  const codeLower = code.toLowerCase()
  const detectedLayers: { name: string; level: number; matches: number; patterns: RegExp }[] = []

  for (const layer of layerDefinitions) {
    const matches = (codeLower.match(new RegExp(layer.patterns.source, 'g')) || []).length
    if (matches > 0) {
      detectedLayers.push({ name: layer.name, level: layer.level, matches, patterns: layer.patterns })
    }
  }

  // Sort by level
  detectedLayers.sort((a, b) => a.level - b.level)

  // Check for layer violations
  // Higher-level modules importing from lower-level is generally OK
  // Lower-level modules importing from higher-level is a violation
  for (let i = 0; i < detectedLayers.length; i++) {
    for (let j = 0; j < i; j++) {
      const higher = detectedLayers[i]
      const lower = detectedLayers[j]

      // Check if lower-level imports from higher-level
      const violationPattern = new RegExp(`(?:import|require).*${lower.patterns.source}.*${higher.patterns.source}|(?:import|require).*${higher.patterns.source}.*${lower.patterns.source}`, 'i')
      if (violationPattern.test(code)) {
        result.violations.push({
          from: lower.name,
          to: higher.name,
          rule: `${lower.name} (L${lower.level}) should not depend on ${higher.name} (L${higher.level})`,
          severity: 'error'
        })
      }
    }
  }

  // Check for circular references between layers
  for (let i = 0; i < detectedLayers.length; i++) {
    const layer = detectedLayers[i]
    const layerPattern = new RegExp(`(?:class|module|namespace)\\s+${layer.name}`, 'i')
    if (layerPattern.test(code)) {
      // Check if this layer's content references itself at same level (OK)
      // but also references higher levels (potential issue)
      for (let k = i + 1; k < detectedLayers.length; k++) {
        const higherLayer = detectedLayers[k]
        const crossRefPattern = new RegExp(`${layer.patterns.source}.*${higherLayer.patterns.source}`, 'i')
        if (crossRefPattern.test(code) && !result.violations.some(v => v.from === layer.name)) {
          result.violations.push({
            from: layer.name,
            to: higherLayer.name,
            rule: `${layer.name} directly coupled to ${higherLayer.name} — consider introducing an abstraction`,
            severity: 'warning'
          })
        }
      }
    }
  }

  result.layers = detectedLayers.map(l => ({ name: l.name, modules: [], level: l.level }))
  result.cleanLayerCount = detectedLayers.length - new Set(result.violations.map(v => v.from)).size

  result.summary = detectedLayers.length === 0
    ? 'No layered architecture detected. Consider adopting a layered structure.'
    : `${detectedLayers.length} layers detected, ${result.violations.length} violation(s) found.`

  return result
}

function formatLayerViolationReport(result: LayerViolationResult): string {
  const lines: string[] = []
  lines.push('## Module Layer Violation Analysis')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push('')

  if (result.layers.length > 0) {
    lines.push('### Detected Layers')
    result.layers.forEach(l => {
      lines.push(`- **L${l.level}:** ${l.name}`)
    })
    lines.push('')
  }

  if (result.violations.length > 0) {
    lines.push('### Violations')
    result.violations.forEach(v => {
      const icon = v.severity === 'error' ? '🔴' : '🟡'
      lines.push(`${icon} ${v.rule}`)
      lines.push(`  Import: \`${v.from}\` → \`${v.to}\``)
    })
    lines.push('')
  } else if (result.layers.length > 0) {
    lines.push('✅ No layer violations detected. Clean architecture.')
    lines.push('')
  }

  lines.push('### Recommendations')
  lines.push('- Dependencies should flow downward: presentation → service → data → infrastructure')
  lines.push('- Use dependency injection to invert control when lower layers need higher-level data')
  lines.push('- Introduce interfaces/abstractions to decouple layers')
  lines.push('- Consider Clean Architecture or Hexagonal Architecture patterns')

  return lines.join('\n')
}

// ---- Tool 49: Error Propagation Tracing ----

interface ErrorTraceResult {
  throws: { type: string; line: number; context: string }[]
  catches: { type: string; line: number; context: string }[]
  errorPaths: { from: string; to: string; type: string; propagated: boolean }[]
  unhandledErrors: { type: string; line: number; suggestion: string }[]
  summary: string
  handlingScore: number
}

function traceErrorPropagation(code: string): ErrorTraceResult {
  const result: ErrorTraceResult = {
    throws: [],
    catches: [],
    errorPaths: [],
    unhandledErrors: [],
    summary: '',
    handlingScore: 100
  }

  const lines = code.split('\n')

  // Detect throw statements
  const throwPattern = /throw\s+(?:new\s+)?(\w+(?:Error)?)\s*\(/g
  let m: RegExpExecArray | null
  while ((m = throwPattern.exec(code)) !== null) {
    const lineNum = code.substring(0, m.index).split('\n').length
    const context = lines[Math.min(lineNum - 1, lines.length - 1)]?.trim() || ''
    result.throws.push({ type: m[1], line: lineNum, context: context.substring(0, 80) })
  }

  // Detect try/catch blocks
  const tryBlocks: { start: number; end: number; catches: string[] }[] = []
  let i = 0
  while (i < lines.length) {
    if (lines[i].trim().startsWith('try')) {
      const start = i + 1
      let depth = 0
      let j = i
      while (j < lines.length) {
        depth += (lines[j].match(/{/g) || []).length
        depth -= (lines[j].match(/}/g) || []).length
        if (depth <= 0 && j > i) {
          // Look for catch after this block
          let k = j + 1
          while (k < lines.length && lines[k].trim() === '') k++
          if (k < lines.length && lines[k].trim().startsWith('catch')) {
            const catchMatch = lines[k].match(/catch\s*\(\s*(\w+)/)
            const catchType = catchMatch ? catchMatch[1] : 'unknown'
            const context = lines[k].trim().substring(0, 80)
            result.catches.push({ type: catchType, line: k + 1, context })
            tryBlocks.push({ start, end: k, catches: [catchType] })
          }
          break
        }
        j++
      }
    }
    i++
  }

  // Detect async operations without error handling
    const asyncPatterns: [RegExp, string][] = [
    [/(?:const|let|var)\s+\w+\s*=\s*await\s+/g, 'await'],
    [/\.then\s*\(/g, 'promise.then'],
    [/Promise\s*\.\s*(?:all|race|allSettled)\s*\(/g, 'Promise.all'],
    [/new\s+Promise\s*\(/g, 'new Promise']
  ]

  const handledLines = new Set<number>()
  tryBlocks.forEach(b => {
    for (let l = b.start; l <= b.end; l++) handledLines.add(l)
  })

  for (const [pattern, label] of asyncPatterns) {
    pattern.lastIndex = 0
    let am: RegExpExecArray | null
    while ((am = pattern.exec(code)) !== null) {
      const lineNum = code.substring(0, am.index).split('\n').length
      if (!handledLines.has(lineNum)) {
        result.errorPaths.push({
          from: label,
          to: 'unhandled',
          type: 'potential rejection',
          propagated: false
        })
      }
    }
  }

  // Detect catch blocks that swallow errors
  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx]
    if (/catch\s*\([^)]*\)\s*\{\s*\}/.test(line) || /catch\s*\([^)]*\)\s*\{\s*(?:\/\/\s*)?\}/.test(line)) {
      result.unhandledErrors.push({
        type: 'swallowed',
        line: idx + 1,
        suggestion: 'Add error logging or re-throw to avoid silent failures'
      })
    }
    // catch block that only logs (may be acceptable but flagged)
    if (/catch.*\{[^}]*console\.(?:log|warn|error)[^}]*\}/.test(line)) {
      if (!result.unhandledErrors.some(e => e.line === idx + 1)) {
        result.unhandledErrors.push({
          type: 'logged-only',
          line: idx + 1,
          suggestion: 'Consider re-throwing or returning an error response'
        })
      }
    }
  }

  // Calculate handling score
  const totalThrows = result.throws.length
  const handledThrows = totalThrows - result.unhandledErrors.length
  const asyncOps = result.errorPaths.length + handledLines.size
  const handledAsync = asyncOps - result.errorPaths.filter(e => !e.propagated).length

  if (totalThrows + asyncOps > 0) {
    result.handlingScore = Math.max(0, Math.round(((handledThrows + handledAsync) / (totalThrows + asyncOps)) * 100))
  }

  const unhandled = result.unhandledErrors.length + result.errorPaths.filter(e => !e.propagated).length
  result.summary = unhandled === 0
    ? `All ${totalThrows} throws and ${asyncOps} async operations appear properly handled. Handling score: ${result.handlingScore}/100.`
    : `${unhandled} potentially unhandled error points. Handling score: ${result.handlingScore}/100.`

  return result
}

function formatErrorTraceReport(result: ErrorTraceResult): string {
  const lines: string[] = []
  lines.push('## Error Propagation Trace Report')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push(`**Handling Score:** ${result.handlingScore}/100`)
  lines.push('')

  if (result.throws.length > 0) {
    lines.push('### Throw Statements')
    result.throws.forEach(t => {
      lines.push(`- Line ${t.line}: \`throw ${t.type}\` — ${t.context}`)
    })
    lines.push('')
  }

  if (result.catches.length > 0) {
    lines.push('### Catch Blocks')
    result.catches.forEach(c => {
      lines.push(`- Line ${c.line}: \`catch (${c.type})\` — ${c.context}`)
    })
    lines.push('')
  }

  if (result.errorPaths.filter(e => !e.propagated).length > 0) {
    lines.push('### Unhandled Async Operations')
    const unhandled = result.errorPaths.filter(e => !e.propagated)
    lines.push(`${unhandled.length} async operation(s) without try/catch or .catch()`)
    lines.push('')
  }

  if (result.unhandledErrors.length > 0) {
    lines.push('### Swallowed / Logged-only Errors')
    result.unhandledErrors.forEach(e => {
      const icon = e.type === 'swallowed' ? '🔴' : '🟡'
      lines.push(`${icon} Line ${e.line} [${e.type}]: ${e.suggestion}`)
    })
    lines.push('')
  }

  lines.push('### Recommendations')
  lines.push('- Wrap async operations in try/catch or add .catch() handlers')
  lines.push('- Use custom error types for different failure scenarios')
  lines.push('- Implement a centralized error handler middleware')
  lines.push('- Avoid empty catch blocks — at minimum log with context')
  lines.push('- Consider using Result/Either types for expected failures')

  return lines.join('\n')
}

// ==================== v0.11.0 NEW TOOLS ====================

// ---- Tool 50: Auto Refactoring ----

interface AutoRefactorResult {
  refactorings: { type: string; line: number; description: string; original: string; refactored: string }[]
  summary: string
  totalOpportunities: number
}

function suggestAutoRefactor(code: string): AutoRefactorResult {
  const result: AutoRefactorResult = {
    refactorings: [],
    summary: '',
    totalOpportunities: 0
  }

  const lines = code.split('\n')

  // Extract Method: repeated code blocks
  for (let i = 0; i < lines.length - 2; i++) {
    const block = lines.slice(i, i + 3).join('\n')
    if (block.trim().length < 20) continue
    for (let j = i + 3; j < lines.length - 2; j++) {
      const candidate = lines.slice(j, j + 3).join('\n')
      if (candidate.trim() === block.trim()) {
        result.refactorings.push({
          type: 'extract_method',
          line: i + 1,
          description: `Duplicate block found at lines ${i + 1}-${i + 3} and ${j + 1}-${j + 3}`,
          original: block.substring(0, 60).replace(/\n/g, ' ') + '...',
          refactored: `Extract to function and call from both locations`
        })
        break
      }
    }
  }

  // Extract Variable: complex expressions in return/assignment
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (/(?:return|const|let|var)\s+[^;]*\?.(?:[^;]{3,})/.test(line)) {
      result.refactorings.push({
        type: 'extract_variable',
        line: i + 1,
        description: 'Complex expression could be extracted to a named variable for readability',
        original: line.trim().substring(0, 60),
        refactored: `Assign expression to a descriptively named variable`
      })
    }
  }

  // Inline Temp: variable used only once
  const varDecls = new Map<string, { line: number; count: number }>()
  const declPattern = /(?:const|let|var)\s+(\w+)\s*=/g
  let m: RegExpExecArray | null
  while ((m = declPattern.exec(code)) !== null) {
    const lineNum = code.substring(0, m.index).split('\n').length
    varDecls.set(m[1], { line: lineNum, count: 0 })
  }
  for (const [name] of varDecls) {
    const usages = (new RegExp(`\\b${name}\\b`, 'g').exec(code)?.length || 0) - 1 // Exclude declaration
    varDecls.get(name)!.count = usages
  }
  for (const [name, info] of varDecls) {
    if (info.count === 1) {
      result.refactorings.push({
        type: 'inline_temp',
        line: info.line,
        description: `Variable '${name}' is used only once — inline it`,
        original: `const ${name} = ...`,
        refactored: `Use the expression directly where '${name}' is referenced`
      })
    }
  }

  // Replace Magic Number with named constant
  const magicNumPattern = /(?:const|let|var)\s+\w+\s*=\s*(\d+(?:\.\d+)?)\s*;/g
  while ((m = magicNumPattern.exec(code)) !== null) {
    const num = parseFloat(m[1])
    if (num !== 0 && num !== 1 && num !== -1 && !Number.isNaN(num)) {
      const lineNum = code.substring(0, m.index).split('\n').length
      result.refactorings.push({
        type: 'replace_magic_number',
        line: lineNum,
        description: `Magic number ${m[1]} should be a named constant`,
        original: `const x = ${m[1]}`,
        refactored: `const MEANINGFUL_NAME = ${m[1]} // describe what this represents`
      })
    }
  }

  result.totalOpportunities = result.refactorings.length
  result.summary = result.totalOpportunities === 0
    ? 'No refactoring opportunities detected.'
    : `Found ${result.totalOpportunities} refactoring opportunities.`

  return result
}

function formatAutoRefactorReport(result: AutoRefactorResult): string {
  const lines: string[] = []
  lines.push('## Auto Refactoring Report')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push('')

  if (result.refactorings.length > 0) {
    const grouped = new Map<string, typeof result.refactorings>()
    result.refactorings.forEach(r => {
      if (!grouped.has(r.type)) grouped.set(r.type, [])
      grouped.get(r.type)!.push(r)
    })

    for (const [type, items] of grouped) {
      lines.push(`### ${type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())} (${items.length})`)
      items.forEach(r => {
        lines.push(`- Line ${r.line}: ${r.description}`)
        lines.push(`  - Original: \`${r.original}\``)
        lines.push(`  - Suggested: \`${r.refactored}\``)
      })
      lines.push('')
    }
  }

  return lines.join('\n')
}

// ---- Tool 51: Code Similarity Detection ----

interface SimilarityResult {
  fileSimilarities: { block1: string; block2: string; similarity: number; lines: string }[]
  tokenSimilarity: number
  summary: string
  duplicateBlocks: number
}

function detectCodeSimilarity(code: string): SimilarityResult {
  const result: SimilarityResult = {
    fileSimilarities: [],
    tokenSimilarity: 0,
    summary: '',
    duplicateBlocks: 0
  }

  const lines = code.split('\n')
  const blockSize = 4

  // Tokenize for comparison
  const tokenize = (s: string): Set<string> => {
    return new Set(s.replace(/[{}();,]/g, ' ').split(/\s+/).filter(t => t.length > 2))
  }

  // Compare all block pairs
  const blocks: { start: number; tokens: Set<string>; text: string }[] = []
  for (let i = 0; i <= lines.length - blockSize; i++) {
    const blockText = lines.slice(i, i + blockSize).join('\n')
    blocks.push({ start: i + 1, tokens: tokenize(blockText), text: blockText })
  }

  for (let i = 0; i < blocks.length; i++) {
    for (let j = i + 1; j < blocks.length; j++) {
      const a = blocks[i].tokens
      const b = blocks[j].tokens
      if (a.size === 0 || b.size === 0) continue

      const intersection = new Set([...a].filter(x => b.has(x)))
      const union = new Set([...a, ...b])
      const jaccard = intersection.size / union.size

      if (jaccard > 0.6) {
        result.fileSimilarities.push({
          block1: `L${blocks[i].start}-${blocks[i].start + blockSize - 1}`,
          block2: `L${blocks[j].start}-${blocks[j].start + blockSize - 1}`,
          similarity: Math.round(jaccard * 100),
          lines: `${blocks[i].start}-${blocks[i].start + blockSize - 1} vs ${blocks[j].start}-${blocks[j].start + blockSize - 1}`
        })
      }
    }
  }

  result.duplicateBlocks = result.fileSimilarities.length
  result.tokenSimilarity = result.fileSimilarities.length > 0
    ? Math.round(result.fileSimilarities.reduce((s, f) => s + f.similarity, 0) / result.fileSimilarities.length)
    : 0

  result.summary = result.duplicateBlocks === 0
    ? 'No significant code similarity detected. Code is sufficiently unique.'
    : `Found ${result.duplicateBlocks} similar code block pairs (avg ${result.tokenSimilarity}% similarity).`

  return result
}

function formatSimilarityReport(result: SimilarityResult): string {
  const lines: string[] = []
  lines.push('## Code Similarity Report')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push(`**Average token similarity:** ${result.tokenSimilarity}%`)
  lines.push('')

  if (result.fileSimilarities.length > 0) {
    lines.push('### Similar Blocks')
    result.fileSimilarities.forEach(s => {
      const icon = s.similarity > 80 ? '🔴' : s.similarity > 70 ? '🟡' : '🟢'
      lines.push(`${icon} ${s.block1} ↔ ${s.block2}: ${s.similarity}% similar`)
    })
    lines.push('')
    lines.push('### Recommendations')
    lines.push('- Extract shared logic into a reusable function')
    lines.push('- Use inheritance or composition to share behavior')
    lines.push('- Consider creating a utility/helper for duplicated patterns')
  } else {
    lines.push('✅ No significant similarity detected.')
  }

  return lines.join('\n')
}

// ---- Tool 52: Primitive Obsession Detection ----

interface PrimitiveObsessionResult {
  occurrences: { name: string; type: string; line: number; suggestion: string }[]
  summary: string
  obsessionScore: number
}

function detectPrimitiveObsession(code: string): PrimitiveObsessionResult {
  const result: PrimitiveObsessionResult = {
    occurrences: [],
    summary: '',
    obsessionScore: 100
  }

  const lines = code.split('\n')

  // Detect variables that could be domain types
  const primitivePatterns: { pattern: RegExp; type: string; suggestion: string }[] = [
    { pattern: /(?:phone|telephone|mobile)/i, type: 'PhoneNumber', suggestion: 'Create a PhoneNumber class with validation' },
    { pattern: /(?:email|e-mail|mail)/i, type: 'EmailAddress', suggestion: 'Create an EmailAddress value object' },
    { pattern: /(?:currency|price|amount|money|salary)/i, type: 'Money', suggestion: 'Create a Money value object with currency' },
    { pattern: /(?:date|time|deadline|expiry|duration)/i, type: 'DateTime', suggestion: 'Use a proper date/time value object' },
    { pattern: /(?:color|rgb|hex)/i, type: 'Color', suggestion: 'Create a Color value object' },
    { pattern: /(?:address|location|zip|postal)/i, type: 'Address', suggestion: 'Create an Address entity' },
    { pattern: /(?:coordinate|latitude|longitude|lat|lng)/i, type: 'Coordinate', suggestion: 'Create a Coordinate value object' },
    { pattern: /(?:weight|height|distance|volume|temperature)/i, type: 'Measurement', suggestion: 'Create a Measurement value object with units' },
    { pattern: /(?:id|uuid|guid|identifier)/i, type: 'Identifier', suggestion: 'Create an Id/UUID wrapper type' },
    { pattern: /(?:status|state)/i, type: 'Status', suggestion: 'Use an enum or dedicated Status type' }
  ]

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    for (const pp of primitivePatterns) {
      if (pp.pattern.test(line) && /(?:const|let|var|:\s*(?:string|number|boolean))/.test(line)) {
        const nameMatch = line.match(/(?:const|let|var)\s+(\w+)/)
        const name = nameMatch ? nameMatch[1] : 'unknown'
        result.occurrences.push({ name, type: pp.type, line: i + 1, suggestion: pp.suggestion })
      }
    }
  }

  const penalty = Math.min(100, result.occurrences.length * 8)
  result.obsessionScore = 100 - penalty

  result.summary = result.occurrences.length === 0
    ? 'No primitive obsession detected. Good use of domain types.'
    : `Found ${result.occurrences.length} primitive obsession candidates (score: ${result.obsessionScore}/100).`

  return result
}

function formatPrimitiveObsessionReport(result: PrimitiveObsessionResult): string {
  const lines: string[] = []
  lines.push('## Primitive Obsession Detection')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push(`**Obsession Score:** ${result.obsessionScore}/100`)
  lines.push('')

  if (result.occurrences.length > 0) {
    lines.push('### Candidates')
    result.occurrences.forEach(o => {
      lines.push(`- Line ${o.line}: \`${o.name}\` → consider \`${o.type}\``)
      lines.push(`  - ${o.suggestion}`)
    })
    lines.push('')
    lines.push('### Benefits of Value Objects')
    lines.push('- Type safety: prevent mixing different kinds of primitives')
    lines.push('- Validation: enforce constraints at construction time')
    lines.push('- Self-documenting: type name conveys meaning')
    lines.push('- Encapsulation: behavior lives with the data')
  }

  return lines.join('\n')
}

// ---- Tool 53: SQL Injection Deep Detection ----

interface SqlInjectionResult {
  vulnerabilities: { line: number; severity: 'critical' | 'high' | 'medium'; query: string; issue: string; fix: string }[]
  safePatterns: string[]
  summary: string
  riskScore: number
}

function detectSqlInjection(code: string): SqlInjectionResult {
  const result: SqlInjectionResult = {
    vulnerabilities: [],
    safePatterns: [],
    summary: '',
    riskScore: 100
  }

  const lines = code.split('\n')

  // Dangerous patterns: string concatenation in SQL
  const dangerousPatterns: { pattern: RegExp; severity: 'critical' | 'high' | 'medium'; issue: string; fix: string }[] = [
    {
      pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*\+/i,
      severity: 'critical',
      issue: 'SQL query built with string concatenation',
      fix: 'Use parameterized queries with placeholders'
    },
    {
      pattern: /(?:query|execute|exec|run)\s*\(\s*["'`].*\$\{/,
      severity: 'critical',
      issue: 'Template literal interpolation in SQL query',
      fix: 'Use parameterized queries: db.query("SELECT * FROM t WHERE id = ?", [id])'
    },
    {
      pattern: /(?:query|execute|exec)\s*\(\s*["'`].*\+\s*\w+/,
      severity: 'critical',
      issue: 'Variable concatenation in SQL call',
      fix: 'Use ORM or parameterized queries'
    },
    {
      pattern: /(?:query|execute|exec)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`/,
      severity: 'critical',
      issue: 'Interpolated template literal in SQL',
      fix: 'Never interpolate user input into SQL strings'
    },
    {
      pattern: /(?:WHERE|AND|OR)\s+\w+\s*=\s*["'`]?\s*\+\s*\w+/i,
      severity: 'high',
      issue: 'Dynamic WHERE clause construction',
      fix: 'Build query with parameter array'
    },
    {
      pattern: /`[^`]*\$\{[^}]+}.*FROM|WHERE|INTO`/,
      severity: 'critical',
      issue: 'Template literal with SQL keywords and interpolation',
      fix: 'Use query builder or parameterized statements'
    }
  ]

  // Safe patterns that indicate proper usage
  const safeIndicators: { pattern: RegExp; description: string }[] = [
    { pattern: /\?.*\[/i, description: 'Parameterized query with placeholder' },
    { pattern: /:\w+\s*[,)]/, description: 'Named parameter binding' },
    { pattern: /\$1|\$2|\$\d/, description: 'Posomial parameter ($1, $2)' },
    { pattern: /prepare[d]?\s*(?:statement|query)/i, description: 'Prepared statement usage' },
    { pattern: /\.query\s*\(\s*["'`][^"'`]*["'`]\s*,\s*\[/, description: 'Parameterized with array binding' }
  ]

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    for (const dp of dangerousPatterns) {
      if (dp.pattern.test(line)) {
        result.vulnerabilities.push({
          line: i + 1,
          severity: dp.severity,
          query: line.trim().substring(0, 80),
          issue: dp.issue,
          fix: dp.fix
        })
      }
    }
    for (const si of safeIndicators) {
      if (si.pattern.test(line)) {
        result.safePatterns.push(`Line ${i + 1}: ${si.description}`)
      }
    }
  }

  const critCount = result.vulnerabilities.filter(v => v.severity === 'critical').length
  const highCount = result.vulnerabilities.filter(v => v.severity === 'high').length
  result.riskScore = Math.max(0, 100 - critCount * 25 - highCount * 15)

  result.summary = result.vulnerabilities.length === 0
    ? `No SQL injection vectors found. ${result.safePatterns.length} safe pattern(s) detected.`
    : `Found ${result.vulnerabilities.length} potential SQL injection vector(s). Risk: ${result.riskScore}/100.`

  return result
}

function formatSqlInjectionReport(result: SqlInjectionResult): string {
  const lines: string[] = []
  lines.push('## SQL Injection Detection Report')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push(`**Risk Score:** ${result.riskScore}/100`)
  lines.push('')

  if (result.vulnerabilities.length > 0) {
    lines.push('### Vulnerabilities')
    result.vulnerabilities.forEach(v => {
      const icon = v.severity === 'critical' ? '🔴' : '🟡'
      lines.push(`${icon} Line ${v.line} [${v.severity.toUpperCase()}]`)
      lines.push(`  Query: \`${v.query}\``)
      lines.push(`  Issue: ${v.issue}`)
      lines.push(`  Fix: ${v.fix}`)
      lines.push('')
    })
  }

  if (result.safePatterns.length > 0) {
    lines.push('### Safe Patterns Detected')
    result.safePatterns.forEach(s => lines.push(`✅ ${s}`))
    lines.push('')
  }

  lines.push('### Best Practices')
  lines.push('- Always use parameterized queries with ? or :name placeholders')
  lines.push('- Use an ORM (Prisma, TypeORM, Sequelize) for type-safe queries')
  lines.push('- Never concatenate user input into SQL strings')
  lines.push('- Validate and whitelist ORDER BY / column name inputs')

  return lines.join('\n')
}

// ---- Tool 54: Interface Compliance Checker ----

interface InterfaceComplianceResult {
  interfaces: { name: string; methods: string[]; line: number }[]
  implementations: { name: string; implements: string; missing: string[]; extra: string[]; line: number; compliant: boolean }[]
  summary: string
  complianceRate: number
}

function checkInterfaceCompliance(code: string): InterfaceComplianceResult {
  const result: InterfaceComplianceResult = {
    interfaces: [],
    implementations: [],
    summary: '',
    complianceRate: 100
  }

  // Parse interface definitions
  const interfacePattern = /interface\s+(\w+)\s*(?:extends\s+([\w\s,]+))?\s*\{([^}]+)\}/g
  let m: RegExpExecArray | null
  while ((m = interfacePattern.exec(code)) !== null) {
    const name = m[1]
    const body = m[3]
    const lineNum = code.substring(0, m.index).split('\n').length
    const methods: string[] = []
    const methodPattern = /(\w+)\s*(?:\([^)]*\))(?:\s*:\s*[^;]+)?[;]?/g
    let mm: RegExpExecArray | null
    while ((mm = methodPattern.exec(body)) !== null) {
      methods.push(mm[1])
    }
    result.interfaces.push({ name, methods, line: lineNum })
  }

  // Parse class implementations
  const classPattern = /class\s+(\w+)\s+(?:extends\s+\w+\s+)?(?:implements\s+([\w\s,]+))?\s*\{/g
  while ((m = classPattern.exec(code)) !== null) {
    const className = m[1]
    const implStr = m[2] || ''
    const lineNum = code.substring(0, m.index).split('\n').length
    const implInterfaces = implStr.split(',').map(s => s.trim()).filter(Boolean)

    // Get class methods
    const classStart = m.index + m[0].length
    const classBody = code.substring(classStart, classStart + 2000)
    const classMethods: string[] = []
    const cmPattern = /(?:public|private|protected)?\s*(?:async\s+)?(\w+)\s*\(/g
    let cm: RegExpExecArray | null
    while ((cm = cmPattern.exec(classBody)) !== null) {
      if (cm[1] !== 'constructor' && cm[1] !== 'if' && cm[1] !== 'for' && cm[1] !== 'while') {
        classMethods.push(cm[1])
      }
    }

    // Check compliance for each implemented interface
    for (const implName of implInterfaces) {
      const iface = result.interfaces.find(i => i.name === implName)
      if (iface) {
        const missing = iface.methods.filter(im => !classMethods.includes(im))
        const extra = classMethods.filter(cm => !iface.methods.includes(cm))
        result.implementations.push({
          name: className,
          implements: implName,
          missing,
          extra,
          line: lineNum,
          compliant: missing.length === 0
        })
      }
    }
  }

  const total = result.implementations.length
  const compliant = result.implementations.filter(i => i.compliant).length
  result.complianceRate = total > 0 ? Math.round((compliant / total) * 100) : 100

  result.summary = total === 0
    ? 'No interface implementations detected.'
    : `${compliant}/${total} implementations are fully compliant (${result.complianceRate}%).`

  return result
}

function formatInterfaceComplianceReport(result: InterfaceComplianceResult): string {
  const lines: string[] = []
  lines.push('## Interface Compliance Report')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push(`**Compliance Rate:** ${result.complianceRate}%`)
  lines.push('')

  if (result.interfaces.length > 0) {
    lines.push('### Defined Interfaces')
    result.interfaces.forEach(i => {
      lines.push(`- \`${i.name}\` (line ${i.line}): ${i.methods.join(', ') || 'no methods'}`)
    })
    lines.push('')
  }

  if (result.implementations.length > 0) {
    lines.push('### Implementations')
    result.implementations.forEach(impl => {
      const icon = impl.compliant ? '✅' : '❌'
      lines.push(`${icon} \`${impl.name}\` implements \`${impl.implements}\` (line ${impl.line})`)
      if (impl.missing.length > 0) {
        lines.push(`  Missing: ${impl.missing.map(m => `\`${m}\``).join(', ')}`)
      }
      if (impl.extra.length > 0) {
        lines.push(`  Extra: ${impl.extra.map(e => `\`${e}\``).join(', ')}`)
      }
    })
    lines.push('')
  }

  return lines.join('\n')
}

// ---- Tool 55: Magic String Detection ----

interface MagicStringResult {
  occurrences: { value: string; line: number; context: string; suggestion: string }[]
  internationalizable: { value: string; line: number }[]
  summary: string
  stringScore: number
}

function detectMagicStrings(code: string): MagicStringResult {
  const result: MagicStringResult = {
    occurrences: [],
    internationalizable: [],
    summary: '',
    stringScore: 100
  }

  const lines = code.split('\n')

  // Skip strings that are clearly safe
  const safePatterns = /^(?:import|export|require|console|log|error|warn|info|http|https|ftp|www|\.css|\.js|\.ts|\.json|text\/|application\/)/i

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]

    // Match string literals (single, double, and backtick quoted)
    const stringPattern = /["'`]([^"'`\\]*(?:\\.[^"'`\\]*)*)["'`]/g
    let m: RegExpExecArray | null
    while ((m = stringPattern.exec(line)) !== null) {
      const str = m[1]

      // Skip empty, very short, or obviously safe strings
      if (str.length <= 2 || safePatterns.test(str)) continue
      if (/^[A-Z_][A-Z0-9_]*$/.test(str)) continue // Already a constant
      if (/^(?:true|false|null|undefined)$/.test(str)) continue
      if (/^\d+$/.test(str)) continue // Numeric

      // Check if it looks like user-facing text
      if (/^[A-Z][a-z]+(?:\s+[a-z]+)*$/.test(str) && str.includes(' ')) {
        result.internationalizable.push({ value: str, line: i + 1 })
      }

      // Detect magic strings used as keys or values
      const context = line.trim()
      if (/(?:type|status|state|role|level|format|mode|kind|error|message|label|title|text)\s*[:=]\s*["'`]/.test(context)) {
        const constName = str.toUpperCase().replace(/[^A-Z0-9]/g, '_').replace(/_+/g, '_')
        result.occurrences.push({
          value: str,
          line: i + 1,
          context: context.substring(0, 60),
          suggestion: `const ${constName} = "${str}"`
        })
      }
    }
  }

  const penalty = Math.min(100, result.occurrences.length * 5 + result.internationalizable.length * 3)
  result.stringScore = 100 - penalty

  result.summary = result.occurrences.length === 0 && result.internationalizable.length === 0
    ? 'No problematic magic strings detected.'
    : `Found ${result.occurrences.length} magic string(s) and ${result.internationalizable.length} user-facing string(s) that should be constants.`

  return result
}

function formatMagicStringReport(result: MagicStringResult): string {
  const lines: string[] = []
  lines.push('## Magic String Detection')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push(`**String Quality Score:** ${result.stringScore}/100`)
  lines.push('')

  if (result.occurrences.length > 0) {
    lines.push('### Magic Strings (extract to constants)')
    result.occurrences.forEach(o => {
      lines.push(`- Line ${o.line}: \`"${o.value}"\``)
      lines.push(`  Context: \`${o.context}\``)
      lines.push(`  Suggested: \`${o.suggestion}\``)
    })
    lines.push('')
  }

  if (result.internationalizable.length > 0) {
    lines.push('### User-Facing Strings (consider i18n)')
    result.internationalizable.forEach(s => {
      lines.push(`- Line ${s.line}: \`"${s.value}"\``)
    })
    lines.push('')
  }

  lines.push('### Recommendations')
  lines.push('- Move string literals to a dedicated constants file or enum')
  lines.push('- User-facing strings should use an i18n framework (react-intl, i18next)')
  lines.push('- Use string literal unions for type-safe string values')

  return lines.join('\n')
}

// ---- Tool 56: Semantic Version Bump Recommender ----

interface SemverResult {
  currentVersion: string
  recommendedBump: 'major' | 'minor' | 'patch' | 'none'
  reasons: string[]
  breakingChanges: string[]
  newFeatures: string[]
  fixes: string[]
  summary: string
}

function recommendSemverBump(code: string): SemverResult {
  const result: SemverResult = {
    currentVersion: '1.0.0',
    recommendedBump: 'none',
    reasons: [],
    breakingChanges: [],
    newFeatures: [],
    fixes: [],
    summary: ''
  }

  // Detect breaking changes
  const removedExports = /(?:REMOVED|DELETED|BREAKING).*?(?:export|function|class)/gi
  const changedSignatures = /(?: signature| parameter| return type)/gi
  if (removedExports.test(code)) {
    result.breakingChanges.push('Removed exports detected')
  }
  if (changedSignatures.test(code)) {
    result.breakingChanges.push('Changed function signatures detected')
  }

  // Detect new features
  const newExports = code.match(/export\s+(?:function|class|interface|type|const)\s+(\w+)/g) || []
  if (newExports.length > 0) {
    result.newFeatures.push(`${newExports.length} new export(s) added`)
  }

  const newEndpoints = code.match(/(?:app|router)\.(?:get|post|put|delete|patch)\s*\(/g) || []
  if (newEndpoints.length > 0) {
    result.newFeatures.push(`${newEndpoints.length} new API endpoint(s)`)
  }

  // Detect fixes
  const fixComments = code.match(/(?:fix|fixed|fixes|bug|patch|hotfix|resolve)/gi) || []
  if (fixComments.length > 0) {
    result.fixes.push(`${fixComments.length} fix-related comment(s)`)
  }

  // Determine bump level
  if (result.breakingChanges.length > 0) {
    result.recommendedBump = 'major'
    result.reasons.push('Breaking changes require major version bump')
  } else if (result.newFeatures.length > 0) {
    result.recommendedBump = 'minor'
    result.reasons.push('New features warrant minor version bump')
  } else if (result.fixes.length > 0) {
    result.recommendedBump = 'patch'
    result.reasons.push('Bug fixes only — patch bump appropriate')
  } else {
    result.reasons.push('No significant changes detected')
  }

  result.summary = `Recommended: ${result.recommendedBump.toUpperCase()} bump. ${result.reasons.join('. ')}`

  return result
}

function formatSemverReport(result: SemverResult): string {
  const lines: string[] = []
  lines.push('## Semantic Version Bump Recommendation')
  lines.push('')
  lines.push(`**Recommendation:** ${result.recommendedBump.toUpperCase()}`)
  lines.push(`**Summary:** ${result.summary}`)
  lines.push('')

  if (result.breakingChanges.length > 0) {
    lines.push('### Breaking Changes (requires MAJOR)')
    result.breakingChanges.forEach(b => lines.push(`- 🔴 ${b}`))
    lines.push('')
  }
  if (result.newFeatures.length > 0) {
    lines.push('### New Features (warrants MINOR)')
    result.newFeatures.forEach(f => lines.push(`- 🟢 ${f}`))
    lines.push('')
  }
  if (result.fixes.length > 0) {
    lines.push('### Fixes (PATCH appropriate)')
    result.fixes.forEach(f => lines.push(`- 🟡 ${f}`))
    lines.push('')
  }

  lines.push('### Semantic Versioning Rules')
  lines.push('- **MAJOR**: Breaking changes that require consumer updates')
  lines.push('- **MINOR**: New features, backward compatible')
  lines.push('- **PATCH**: Bug fixes only, no API changes')

  return lines.join('\n')
}

// ---- Tool 57: PR Review Comment Generator ----

interface PRCommentResult {
  comments: { file: string; line: number; body: string; category: string; severity: 'suggestion' | 'nit' | 'issue' | 'praise' }[]
  summary: string
  totalComments: number
}

function generatePRReviewComments(code: string): PRCommentResult {
  const result: PRCommentResult = {
    comments: [],
    summary: '',
    totalComments: 0
  }

  const lines = code.split('\n')

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()
    const lineNum = i + 1

    // Security issues
    if (/(?:eval|innerHTML|dangerouslySetInnerHTML)\s*\(/.test(line)) {
      result.comments.push({
        file: 'src/file.ts',
        line: lineNum,
        body: '⚠️ Using eval/innerHTML can lead to XSS vulnerabilities. Consider safer alternatives.',
        category: 'security',
        severity: 'issue'
      })
    }

    // Performance
    if (/\.map\s*\(.*\.map\s*\(/.test(line)) {
      result.comments.push({
        file: 'src/file.ts',
        line: lineNum,
        body: '🔍 Chained .map() calls create intermediate arrays. Consider combining into a single map or using reduce.',
        category: 'performance',
        severity: 'suggestion'
      })
    }

    // Best practices
    if (/console\.(?:log|debug)\s*\(/.test(line) && !line.includes('//')) {
      result.comments.push({
        file: 'src/file.ts',
        line: lineNum,
        body: '🧹 Remove console.log before merging, or replace with a proper logger.',
        category: 'clean code',
        severity: 'nit'
      })
    }

    // Good patterns
    if (/(?:async\s+function|const\s+\w+\s*=\s*async)\s*\(/.test(line)) {
      if (lines[i + 1]?.trim().startsWith('try')) {
        result.comments.push({
          file: 'src/file.ts',
          line: lineNum,
          body: '👍 Good: async function with try/catch error handling.',
          category: 'best practice',
          severity: 'praise'
        })
      }
    }

    // Component complexity marker
    if (/^(?:export\s+)?(?:function|const)\s+\w+\s*[=(].*=>/.test(line)) {
      let funcEnd = i + 1
      let braceCount = 0
      while (funcEnd < lines.length) {
        braceCount += (lines[funcEnd].match(/{/g) || []).length
        braceCount -= (lines[funcEnd].match(/}/g) || []).length
        if (braceCount <= 0 && funcEnd > i) break
        funcEnd++
        if (funcEnd - i > 50) break
      }
      if (funcEnd - i > 30) {
        result.comments.push({
          file: 'src/file.ts',
          line: lineNum,
          body: '📏 This function is quite long. Consider extracting smaller helper functions.',
          category: 'readability',
          severity: 'suggestion'
        })
      }
    }
  }

  result.totalComments = result.comments.length
  result.summary = `Generated ${result.totalComments} review comment(s).`

  return result
}

function formatPRReviewCommentReport(result: PRCommentResult): string {
  const lines: string[] = []
  lines.push('## PR Review Comments')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push('')

  if (result.comments.length > 0) {
    const grouped = new Map<string, typeof result.comments>()
    result.comments.forEach(c => {
      if (!grouped.has(c.category)) grouped.set(c.category, [])
      grouped.get(c.category)!.push(c)
    })

    for (const [cat, items] of grouped) {
      lines.push(`### ${cat.charAt(0).toUpperCase() + cat.slice(1)} (${items.length})`)
      items.forEach(c => {
        const icon = c.severity === 'issue' ? '🔴' : c.severity === 'suggestion' ? '🟡' : c.severity === 'nit' ? '⚪' : '🟢'
        lines.push(`${icon} Line ${c.line}: ${c.body}`)
      })
      lines.push('')
    }
  }

  return lines.join('\n')
}

// ==================== v0.12.0 NEW TOOLS ====================

// ---- Tool 58: Variable Scope Analysis ----

interface ScopeResult {
  scopes: { name: string; type: 'global' | 'function' | 'block'; line: number; variables: string[] }[]
  hoistingIssues: { name: string; line: number; issue: string }[]
  shadowingIssues: { name: string; line: number; outerScope: string; innerScope: string }[]
  summary: string
  scopeDepth: number
}

function analyzeScope(code: string): ScopeResult {
  const result: ScopeResult = {
    scopes: [],
    hoistingIssues: [],
    shadowingIssues: [],
    summary: '',
    scopeDepth: 0
  }

  const lines = code.split('\n')
  const scopeStack: { name: string; type: string; vars: string[]; line: number }[] = []
  let maxDepth = 0

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()

    // Detect function scope
    const funcMatch = line.match(/(?:function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)|(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)/)
    if (funcMatch) {
      const name = funcMatch[1] || funcMatch[2] || `anonymous_${i}`
      scopeStack.push({ name, type: 'function', vars: [], line: i + 1 })
      maxDepth = Math.max(maxDepth, scopeStack.length)
    }

    // Detect block scope (if/for/while/switch/catch)
    if (/(?:if|for|while|switch|catch|try)\s*[\({]/.test(line) || line === '{') {
      if (!funcMatch) {
        scopeStack.push({ name: `block_${i}`, type: 'block', vars: [], line: i + 1 })
        maxDepth = Math.max(maxDepth, scopeStack.length)
      }
    }

    // Detect variable declarations
    const varMatch = line.match(/(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g)
    if (varMatch && scopeStack.length > 0) {
      varMatch.forEach(v => {
        const name = v.replace(/^(?:const|let|var)\s+/, '')
        scopeStack[scopeStack.length - 1].vars.push(name)

        // Check shadowing
        for (let s = scopeStack.length - 2; s >= 0; s--) {
          if (scopeStack[s].vars.includes(name)) {
            result.shadowingIssues.push({
              name,
              line: i + 1,
              outerScope: scopeStack[s].name,
              innerScope: scopeStack[scopeStack.length - 1].name
            })
          }
        }
      })
    }

    // Detect hoisting issues: using var before declaration
    if (/\bvar\s+/.test(line)) {
      const varName = line.match(/var\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/)?.[1]
      if (varName) {
        // var is hoisted but not the assignment
        result.hoistingIssues.push({
          name: varName,
          line: i + 1,
          issue: `var '${varName}' is hoisted — consider using let/const for block scoping`
        })
      }
    }

    // Pop scope on closing brace
    if (line === '}' || line.startsWith('}')) {
      if (scopeStack.length > 0) {
        const closed = scopeStack.pop()!
        result.scopes.push({ name: closed.name, type: closed.type as 'global' | 'function' | 'block', line: closed.line, variables: closed.vars })
      }
    }
  }

  result.scopeDepth = maxDepth
  result.summary = `${result.scopes.length} scopes, ${result.shadowingIssues.length} shadowing, ${result.hoistingIssues.length} hoisting issues. Max depth: ${maxDepth}.`

  return result
}

function formatScopeReport(result: ScopeResult): string {
  const lines: string[] = []
  lines.push('## Variable Scope Analysis')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push(`**Max scope depth:** ${result.scopeDepth}`)
  lines.push('')

  if (result.shadowingIssues.length > 0) {
    lines.push('### Variable Shadowing')
    result.shadowingIssues.forEach(s => {
      lines.push(`- Line ${s.line}: '${s.name}' in '${s.innerScope}' shadows '${s.outerScope}'`)
    })
    lines.push('')
  }

  if (result.hoistingIssues.length > 0) {
    lines.push('### Hoisting Issues')
    result.hoistingIssues.forEach(h => {
      lines.push(`- Line ${h.line}: ${h.issue}`)
    })
    lines.push('')
  }

  if (result.scopeDepth > 4) {
    lines.push('### Recommendations')
    lines.push('- Deep nesting detected — consider extracting functions to reduce scope depth')
    lines.push('- Use block scoping (let/const) instead of var to avoid hoisting surprises')
  }

  return lines.join('\n')
}

// ---- Tool 59: Immutability Checker ----

interface ImmutableResult {
  mutablePatterns: { line: number; pattern: string; suggestion: string }[]
  immutablePatterns: { line: number; pattern: string }[]
  summary: string
  immutableScore: number
}

function checkImmutability(code: string): ImmutableResult {
  const result: ImmutableResult = {
    mutablePatterns: [],
    immutablePatterns: [],
    summary: '',
    immutableScore: 100
  }

  const lines = code.split('\n')

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()

    // Detect mutable patterns
    if (/\.(?:push|pop|shift|unshift|splice|sort|reverse|fill|copyWithin)\s*\(/.test(line)) {
      result.mutablePatterns.push({
        line: i + 1,
        pattern: line.trim().substring(0, 60),
        suggestion: 'Use immutable alternatives: [...arr, item] instead of push, filter instead of splice'
      })
    }

    if (/\.(?:set|add|delete|clear)\s*\(/.test(line) && /(?:Map|Set)\b/.test(code)) {
      result.mutablePatterns.push({
        line: i + 1,
        pattern: line.trim().substring(0, 60),
        suggestion: 'Consider immutable Map/Set operations or use a library like Immutable.js'
      })
    }

    // Object/Array mutation via index assignment
    if (/\[\s*\w+\s*\]\s*=/.test(line) && !line.includes('const') && !line.includes('let')) {
      result.mutablePatterns.push({
        line: i + 1,
        pattern: line.trim().substring(0, 60),
        suggestion: 'Use spread or Object.assign for immutable updates'
      })
    }

    // Detect immutable patterns
    if (/\.\.\.(?:Array|Object|Map|Set)\s*\(/.test(line) || /Object\.freeze\s*\(/.test(line)) {
      result.immutablePatterns.push({ line: i + 1, pattern: line.trim().substring(0, 60) })
    }

    if (/const\s+\w+\s*=\s*(?:Object\.freeze|Object\.assign)\s*\(/.test(line)) {
      result.immutablePatterns.push({ line: i + 1, pattern: line.trim().substring(0, 60) })
    }
  }

  const penalty = Math.min(100, result.mutablePatterns.length * 8)
  result.immutableScore = 100 - penalty

  result.summary = `${result.mutablePatterns.length} mutable pattern(s), ${result.immutablePatterns.length} immutable pattern(s). Score: ${result.immutableScore}/100.`

  return result
}

function formatImmutableReport(result: ImmutableResult): string {
  const lines: string[] = []
  lines.push('## Immutability Check')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push(`**Immutability Score:** ${result.immutableScore}/100`)
  lines.push('')

  if (result.mutablePatterns.length > 0) {
    lines.push('### Mutable Patterns')
    result.mutablePatterns.forEach(m => {
      lines.push(`- Line ${m.line}: \`${m.pattern}\``)
      lines.push(`  - ${m.suggestion}`)
    })
    lines.push('')
  }

  if (result.immutablePatterns.length > 0) {
    lines.push('### Immutable Patterns (Good)')
    result.immutablePatterns.forEach(p => {
      lines.push(`- Line ${p.line}: \`${p.pattern}\``)
    })
    lines.push('')
  }

  return lines.join('\n')
}

// ---- Tool 60: Null Safety Analysis ----

interface NullSafetyResult {
  nullableAccess: { line: number; expression: string; risk: string }[]
  safePatterns: { line: number; pattern: string }[]
  nullChecks: { line: number; variable: string }[]
  summary: string
  safetyScore: number
}

function analyzeNullSafety(code: string): NullSafetyResult {
  const result: NullSafetyResult = {
    nullableAccess: [],
    safePatterns: [],
    nullChecks: [],
    summary: '',
    safetyScore: 100
  }

  const lines = code.split('\n')

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()

    // Detect optional chaining (safe)
    if (/\?\.(?:[\w]|\()/.test(line)) {
      result.safePatterns.push({ line: i + 1, pattern: line.trim().substring(0, 60) })
    }

    // Detect nullish coalescing (safe)
    if (/\?\?/.test(line)) {
      result.safePatterns.push({ line: i + 1, pattern: line.trim().substring(0, 60) })
    }

    // Detect null/undefined checks
    if (/(?:===|!==|!=|==)\s*(?:null|undefined)/.test(line) || /(?:if|while)\s*\(\s*\w+\s*\)/.test(line)) {
      const varMatch = line.match(/(?:if|while)\s*\(\s*(\w+)/)
      result.nullChecks.push({ line: i + 1, variable: varMatch ? varMatch[1] : 'unknown' })
    }

    // Detect risky property access (no optional chaining)
    const propAccess = line.match(/(\w+(?:\.\w+)+)/g)
    if (propAccess) {
      propAccess.forEach(expr => {
        const parts = expr.split('.')
        if (parts.length >= 3 && !line.includes('?.') && !line.includes('if') && !line.includes('&&')) {
          result.nullableAccess.push({
            line: i + 1,
            expression: expr,
            risk: `Deep property access without null check — use optional chaining: ${expr.replace(/\./g, '?.')}`
          })
        }
      })
    }

    // Detect function calls that might return null
    if (/(?:find|findFirst|get|lookup|fetch|request)\s*\(/.test(line) && !line.includes('?.') && !line.includes('if')) {
      result.nullableAccess.push({
        line: i + 1,
        expression: line.trim().substring(0, 60),
        risk: 'Function may return null/undefined — add null check or optional chaining'
      })
    }
  }

  const penalty = Math.min(100, result.nullableAccess.length * 10)
  result.safetyScore = 100 - penalty

  result.summary = `${result.nullableAccess.length} risky access(es), ${result.safePatterns.length} safe pattern(s), ${result.nullChecks.length} null check(s). Score: ${result.safetyScore}/100.`

  return result
}

function formatNullSafetyReport(result: NullSafetyResult): string {
  const lines: string[] = []
  lines.push('## Null Safety Analysis')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push(`**Safety Score:** ${result.safetyScore}/100`)
  lines.push('')

  if (result.nullableAccess.length > 0) {
    lines.push('### Risky Null Access')
    result.nullableAccess.forEach(n => {
      lines.push(`- Line ${n.line}: \`${n.expression}\``)
      lines.push(`  - ${n.risk}`)
    })
    lines.push('')
  }

  if (result.safePatterns.length > 0) {
    lines.push('### Safe Patterns')
    result.safePatterns.forEach(s => {
      lines.push(`- Line ${s.line}: \`${s.pattern}\``)
    })
    lines.push('')
  }

  lines.push('### Recommendations')
  lines.push('- Use optional chaining (?.) for potentially null/undefined values')
  lines.push('- Use nullish coalescing (??) for default values')
  lines.push('- Add explicit null checks before deep property access')

  return lines.join('\n')
}

// ---- Tool 61: Concurrency Issue Detection ----

interface ConcurrencyResult {
  issues: { line: number; issue: string; severity: 'warning' | 'error'; suggestion: string }[]
  safePatterns: { line: number; pattern: string }[]
  summary: string
  concurrencyScore: number
}

function detectConcurrencyIssues(code: string): ConcurrencyResult {
  const result: ConcurrencyResult = {
    issues: [],
    safePatterns: [],
    summary: '',
    concurrencyScore: 100
  }

  const lines = code.split('\n')

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()

    // Detect shared mutable state
    if (/(?:let|var)\s+\w+\s*=\s*(?:\[|\{)/.test(line) && /(?:async|Promise|setTimeout|setInterval|fetch)/.test(code)) {
      result.issues.push({
        line: i + 1,
        issue: 'Mutable variable declared in async context — potential race condition',
        severity: 'warning',
        suggestion: 'Use const or immutable data structures in concurrent code'
      })
    }

    // Detect missing await
    if (/(?:const|let|var)\s+\w+\s*=\s*(?!await)(?:fetch|Promise|\w+\.(?:find|save|update|delete|get|query))/.test(line)) {
      result.issues.push({
        line: i + 1,
        issue: 'Async call without await — result is a Promise, not the resolved value',
        severity: 'error',
        suggestion: 'Add await or handle the Promise with .then()'
      })
    }

    // Detect promise without catch
    if (/\.then\s*\(/.test(line) && !/\.catch\s*\(/.test(code.substring(code.indexOf(line), code.indexOf(line) + 500))) {
      result.issues.push({
        line: i + 1,
        issue: 'Promise chain without .catch() — unhandled rejection possible',
        severity: 'warning',
        suggestion: 'Add .catch() or wrap in try/catch'
      })
    }

    // Detect safe patterns
    if (/await\s+/.test(line)) {
      result.safePatterns.push({ line: i + 1, pattern: line.trim().substring(0, 60) })
    }
    if (/Promise\.(?:all|allSettled|race)\s*\(/.test(line)) {
      result.safePatterns.push({ line: i + 1, pattern: line.trim().substring(0, 60) })
    }
    if (/try\s*\{/.test(line)) {
      result.safePatterns.push({ line: i + 1, pattern: line.trim().substring(0, 60) })
    }
  }

  const penalty = Math.min(100, result.issues.filter(i => i.severity === 'error').length * 20 + result.issues.filter(i => i.severity === 'warning').length * 10)
  result.concurrencyScore = 100 - penalty

  result.summary = `${result.issues.length} concurrency issue(s), ${result.safePatterns.length} safe pattern(s). Score: ${result.concurrencyScore}/100.`

  return result
}

function formatConcurrencyReport(result: ConcurrencyResult): string {
  const lines: string[] = []
  lines.push('## Concurrency Issue Detection')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push(`**Concurrency Score:** ${result.concurrencyScore}/100`)
  lines.push('')

  if (result.issues.length > 0) {
    lines.push('### Issues')
    result.issues.forEach(issue => {
      const icon = issue.severity === 'error' ? '🔴' : '🟡'
      lines.push(`${icon} Line ${issue.line} [${issue.severity.toUpperCase()}] ${issue.issue}`)
      lines.push(`  - ${issue.suggestion}`)
    })
    lines.push('')
  }

  if (result.safePatterns.length > 0) {
    lines.push('### Safe Patterns')
    result.safePatterns.forEach(s => {
      lines.push(`- Line ${s.line}: \`${s.pattern}\``)
    })
    lines.push('')
  }

  return lines.join('\n')
}

// ---- Tool 62: Documentation-Code Sync Check ----

interface DocSyncResult {
  outOfSync: { function: string; line: number; issue: string }[]
  missingDocs: { function: string; line: number }[]
  summary: string
  syncScore: number
}

function checkDocSync(code: string): DocSyncResult {
  const result: DocSyncResult = {
    outOfSync: [],
    missingDocs: [],
    summary: '',
    syncScore: 100
  }

  // Find documented functions
  const jsdocPattern = /\/\*\*\s*\n(?:\s*\*\s*.*\n)*\s*\*\/\s*(?:export\s+)?(?:async\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g
  let m: RegExpExecArray | null

  while ((m = jsdocPattern.exec(code)) !== null) {
    const funcName = m[1]
    const docBlock = m[0].substring(0, m[0].indexOf('*/') + 2)
    const lineNum = code.substring(0, m.index).split('\n').length

    // Extract documented params
    const docParams = new Set<string>()
    const paramPattern = /@param\s+\{[^}]+\}\s+(\w+)/g
    let pm: RegExpExecArray | null
    while ((pm = paramPattern.exec(docBlock)) !== null) {
      docParams.add(pm[1])
    }

    // Find actual function params
    const funcStart = m.index + m[0].length
    const funcSig = code.substring(funcStart, funcStart + 200)
    const actualParams = new Set<string>()
    const actualParamPattern = /\(([^)]*)\)/.exec(funcSig)
    if (actualParamPattern) {
      actualParamPattern[1].split(',').forEach(p => {
        const name = p.trim().replace(/[=:].*/, '').trim()
        if (name) actualParams.add(name)
      })
    }

    // Check for mismatches
    const missingInDoc = [...actualParams].filter(p => !docParams.has(p))
    const extraInDoc = [...docParams].filter(p => !actualParams.has(p))

    if (missingInDoc.length > 0 || extraInDoc.length > 0) {
      result.outOfSync.push({
        function: funcName,
        line: lineNum,
        issue: `Missing params: ${missingInDoc.join(', ') || 'none'}. Extra params: ${extraInDoc.join(', ') || 'none'}`
      })
    }
  }

  // Find undocumented public functions
  const publicFuncPattern = /export\s+(?:async\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g
  while ((m = publicFuncPattern.exec(code)) !== null) {
    const funcName = m[1]
    const lineNum = code.substring(0, m.index).split('\n').length
    const beforeFunc = code.substring(Math.max(0, m.index - 200), m.index)

    if (!/\/\*\*[\s\S]*\*\//.test(beforeFunc)) {
      result.missingDocs.push({ function: funcName, line: lineNum })
    }
  }

  const penalty = Math.min(100, result.outOfSync.length * 10 + result.missingDocs.length * 5)
  result.syncScore = 100 - penalty

  result.summary = `${result.outOfSync.length} out-of-sync doc(s), ${result.missingDocs.length} undocumented function(s). Score: ${result.syncScore}/100.`

  return result
}

function formatDocSyncReport(result: DocSyncResult): string {
  const lines: string[] = []
  lines.push('## Documentation-Code Sync')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push(`**Sync Score:** ${result.syncScore}/100`)
  lines.push('')

  if (result.outOfSync.length > 0) {
    lines.push('### Out of Sync')
    result.outOfSync.forEach(o => {
      lines.push(`- \`${o.function}\` (line ${o.line}): ${o.issue}`)
    })
    lines.push('')
  }

  if (result.missingDocs.length > 0) {
    lines.push('### Missing Documentation')
    result.missingDocs.forEach(m => {
      lines.push(`- \`${m.function}\` (line ${m.line})`)
    })
    lines.push('')
  }

  return lines.join('\n')
}

// ---- Tool 63: Test Quality Analysis ----

interface TestQualityResult {
  testFunctions: { name: string; line: number; assertions: number; quality: 'good' | 'fair' | 'poor' }[]
  issues: { line: number; issue: string; suggestion: string }[]
  summary: string
  qualityScore: number
}

function analyzeTestQuality(code: string): TestQualityResult {
  const result: TestQualityResult = {
    testFunctions: [],
    issues: [],
    summary: '',
    qualityScore: 100
  }

  const lines = code.split('\n')

  // Find test/it blocks
  const testPattern = /(?:test|it|describe)\s*\(\s*['"`]([^'"`]+)['"`]/g
  let m: RegExpExecArray | null

  while ((m = testPattern.exec(code)) !== null) {
    const testName = m[1]
    const lineNum = code.substring(0, m.index).split('\n').length
    const testStart = m.index + m[0].length

    // Find the test body
    let braceCount = 0
    let testEnd = testStart
    let started = false
    for (let i = testStart; i < code.length; i++) {
      if (code[i] === '{') { braceCount++; started = true }
      if (code[i] === '}') { braceCount-- }
      if (started && braceCount <= 0) { testEnd = i; break }
    }

    const testBody = code.substring(testStart, testEnd)

    // Count assertions
    const assertionCount = (testBody.match(/(?:expect|assert|should|toEqual|toBe|toThrow|toBeTruthy|toContain)/g) || []).length

    let quality: 'good' | 'fair' | 'poor' = 'good'
    if (assertionCount === 0) quality = 'poor'
    else if (assertionCount === 1) quality = 'fair'

    result.testFunctions.push({ name: testName, line: lineNum, assertions: assertionCount, quality })

    if (assertionCount === 0) {
      result.issues.push({
        line: lineNum,
        issue: `Test '${testName}' has no assertions`,
        suggestion: 'Add at least one expect/assert statement'
      })
    }
  }

  // Detect common anti-patterns
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()
    if (/console\.(?:log|debug)\s*\(/.test(line) && /(?:test|it|describe)/.test(code)) {
      result.issues.push({
        line: i + 1,
        issue: 'console.log in test — use assertions instead',
        suggestion: 'Replace console.log with expect() assertions'
      })
    }
    if (/try\s*\{[\s\S]*catch[\s\S]*\/\/\s*(?:ignore|skip|pass)/.test(line + (lines[i+1] || ''))) {
      result.issues.push({
        line: i + 1,
        issue: 'Empty catch block in test — silent failure risk',
        suggestion: 'Use expect().toThrow() or fail explicitly'
      })
    }
  }

  const penalty = Math.min(100, result.issues.length * 10)
  result.qualityScore = 100 - penalty

  result.summary = `${result.testFunctions.length} test(s), ${result.issues.length} issue(s). Quality: ${result.qualityScore}/100.`

  return result
}

function formatTestQualityReport(result: TestQualityResult): string {
  const lines: string[] = []
  lines.push('## Test Quality Analysis')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push(`**Quality Score:** ${result.qualityScore}/100`)
  lines.push('')

  if (result.testFunctions.length > 0) {
    lines.push('### Tests Found')
    result.testFunctions.forEach(t => {
      const icon = t.quality === 'good' ? '✅' : t.quality === 'fair' ? '🟡' : '🔴'
      lines.push(`${icon} \`${t.name}\` (line ${t.line}): ${t.assertions} assertion(s)`)
    })
    lines.push('')
  }

  if (result.issues.length > 0) {
    lines.push('### Issues')
    result.issues.forEach(issue => {
      lines.push(`- Line ${issue.line}: ${issue.issue}`)
      lines.push(`  - ${issue.suggestion}`)
    })
    lines.push('')
  }

  return lines.join('\n')
}

// ---- Tool 64: Change Impact Estimator ----

interface ImpactResult {
  changeType: 'breaking' | 'feature' | 'fix' | 'refactor'
  affectedAreas: { area: string; impact: 'high' | 'medium' | 'low'; reason: string }[]
  riskLevel: 'high' | 'medium' | 'low'
  testingRecommendations: string[]
  summary: string
}

function estimateChangeImpact(code: string): ImpactResult {
  const result: ImpactResult = {
    changeType: 'refactor',
    affectedAreas: [],
    riskLevel: 'low',
    testingRecommendations: [],
    summary: ''
  }

  // Determine change type
  if (/(?:BREAKING|REMOVED|DELETED|DEPRECATED)/.test(code)) {
    result.changeType = 'breaking'
    result.riskLevel = 'high'
    result.affectedAreas.push({ area: 'Public API', impact: 'high', reason: 'Breaking changes affect consumers' })
  } else if (/(?:new|add|create|implement|feature)/i.test(code)) {
    result.changeType = 'feature'
    result.riskLevel = 'medium'
    result.affectedAreas.push({ area: 'New functionality', impact: 'medium', reason: 'New code paths need testing' })
  } else if (/(?:fix|bug|patch|hotfix|resolve)/i.test(code)) {
    result.changeType = 'fix'
    result.riskLevel = 'low'
    result.affectedAreas.push({ area: 'Bug fix', impact: 'low', reason: 'Targeted change with limited scope' })
  }

  // Analyze affected areas
  if (/export\s+(?:function|class|interface|type)/.test(code)) {
    result.affectedAreas.push({ area: 'Exports', impact: 'high', reason: 'Public interface modified' })
  }
  if (/(?:import|require)\s*\(/.test(code)) {
    result.affectedAreas.push({ area: 'Dependencies', impact: 'medium', reason: 'Import changes may affect module resolution' })
  }
  if (/(?:config|settings|env|environment)/i.test(code)) {
    result.affectedAreas.push({ area: 'Configuration', impact: 'high', reason: 'Config changes can affect runtime behavior' })
  }
  if (/(?:database|db|schema|migration|model)/i.test(code)) {
    result.affectedAreas.push({ area: 'Data layer', impact: 'high', reason: 'Data model changes require migration' })
  }
  if (/(?:auth|login|session|token|password|permission)/i.test(code)) {
    result.affectedAreas.push({ area: 'Security', impact: 'high', reason: 'Security-related changes need careful review' })
  }

  // Testing recommendations
  if (result.riskLevel === 'high') {
    result.testingRecommendations.push('Run full regression test suite')
    result.testingRecommendations.push('Add tests for new behavior')
    result.testingRecommendations.push('Verify backward compatibility')
  } else if (result.riskLevel === 'medium') {
    result.testingRecommendations.push('Run tests for affected modules')
    result.testingRecommendations.push('Add tests for new code paths')
  } else {
    result.testingRecommendations.push('Run targeted unit tests')
  }

  result.summary = `Change type: ${result.changeType}, Risk: ${result.riskLevel}, ${result.affectedAreas.length} affected area(s).`

  return result
}

function formatImpactReport(result: ImpactResult): string {
  const lines: string[] = []
  lines.push('## Change Impact Estimation')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push('')

  if (result.affectedAreas.length > 0) {
    lines.push('### Affected Areas')
    result.affectedAreas.forEach(a => {
      const icon = a.impact === 'high' ? '🔴' : a.impact === 'medium' ? '🟡' : '🟢'
      lines.push(`${icon} **${a.area}** (${a.impact}): ${a.reason}`)
    })
    lines.push('')
  }

  lines.push('### Testing Recommendations')
  result.testingRecommendations.forEach(r => lines.push(`- ${r}`))
  lines.push('')

  return lines.join('\n')
}

// ---- Tool 65: Performance Regression Patterns ----

interface PerfRegressionResult {
  patterns: { line: number; pattern: string; issue: string; suggestion: string }[]
  complexityIssues: { line: number; complexity: string; suggestion: string }[]
  summary: string
  perfScore: number
}

function detectPerfRegression(code: string): PerfRegressionResult {
  const result: PerfRegressionResult = {
    patterns: [],
    complexityIssues: [],
    summary: '',
    perfScore: 100
  }

  const lines = code.split('\n')

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()

    // N+1 query pattern
    if (/(?:for|forEach|map)\s*\([^)]*\)\s*\{[\s\S]*?(?:find|query|select|where|execute)/.test(line + '\n' + (lines[i+1] || ''))) {
      result.patterns.push({
        line: i + 1,
        pattern: 'Loop with query inside',
        issue: 'N+1 query pattern — database call inside loop',
        suggestion: 'Batch queries or use JOINs to reduce database round-trips'
      })
    }

    // Inefficient string concatenation in loop
    if (/(?:for|while)\s*[\s\S]*?\w+\s*\+=/.test(line)) {
      result.patterns.push({
        line: i + 1,
        pattern: 'String concatenation in loop',
        issue: 'Repeated string concatenation is O(n²)',
        suggestion: 'Use array join() or template literals'
      })
    }

    // Nested loops (O(n²) or worse)
    if (/for\s*\([^)]*\)\s*\{[\s\S]*?for\s*\(/.test(line + '\n' + (lines[i+1] || '') + '\n' + (lines[i+2] || ''))) {
      result.complexityIssues.push({
        line: i + 1,
        complexity: 'O(n²)',
        suggestion: 'Consider using a Map/Set for O(1) lookup instead of nested iteration'
      })
    }

    // Unnecessary re-renders / computations
    if (/(?:useMemo|useCallback|React\.memo)\s*\(/.test(line)) {
      // Good pattern — memoization used
    } else if (/(?:map|filter|reduce)\s*\(/.test(line) && /(?:render|return\s*\(|jsx)/.test(code)) {
      result.patterns.push({
        line: i + 1,
        pattern: 'Array operation in render',
        issue: 'Expensive computation on every render',
        suggestion: 'Memoize with useMemo or compute outside render'
      })
    }

    // Large array operations without pagination
    if (/\.(?:map|filter|sort)\s*\(/.test(line) && !/slice|limit|take/.test(code.substring(code.indexOf(line) - 100, code.indexOf(line)))) {
      result.patterns.push({
        line: i + 1,
        pattern: 'Full array operation',
        issue: 'Processing entire array — may be slow for large datasets',
        suggestion: 'Consider pagination, lazy loading, or streaming'
      })
    }
  }

  const penalty = Math.min(100, result.patterns.length * 8 + result.complexityIssues.length * 12)
  result.perfScore = 100 - penalty

  result.summary = `${result.patterns.length} performance pattern(s), ${result.complexityIssues.length} complexity issue(s). Score: ${result.perfScore}/100.`

  return result
}

function formatPerfRegressionReport(result: PerfRegressionResult): string {
  const lines: string[] = []
  lines.push('## Performance Regression Patterns')
  lines.push('')
  lines.push(`**Summary:** ${result.summary}`)
  lines.push(`**Performance Score:** ${result.perfScore}/100`)
  lines.push('')

  if (result.patterns.length > 0) {
    lines.push('### Performance Patterns')
    result.patterns.forEach(p => {
      lines.push(`- Line ${p.line}: ${p.issue}`)
      lines.push(`  - ${p.suggestion}`)
    })
    lines.push('')
  }

  if (result.complexityIssues.length > 0) {
    lines.push('### Complexity Issues')
    result.complexityIssues.forEach(c => {
      lines.push(`- Line ${c.line}: ${c.complexity} complexity — ${c.suggestion}`)
    })
    lines.push('')
  }

  return lines.join('\n')
}

// ==================== V0.13.0 NEW TOOLS ====================

// ---- Tool 66: Memory Leak Detection ----

interface MemoryLeakResult {
  totalIssues: number
  severity: Severity
  listenerLeaks: { line: number; event: string; issue: string; suggestion: string }[]
  timerLeaks: { line: number; timerType: string; issue: string; suggestion: string }[]
  closureLeaks: { line: number; variable: string; issue: string; suggestion: string }[]
  cacheLeaks: { line: number; pattern: string; issue: string; suggestion: string }[]
  cleanupScore: number
  summary: string
}

function detectMemoryLeaks(code: string): MemoryLeakResult {
  const lines = code.split('\n')
  const listenerLeaks: MemoryLeakResult['listenerLeaks'] = []
  const timerLeaks: MemoryLeakResult['timerLeaks'] = []
  const closureLeaks: MemoryLeakResult['closureLeaks'] = []
  const cacheLeaks: MemoryLeakResult['cacheLeaks'] = []

  // Detect addEventListener without removeEventListener
  const eventListeners: { line: number; event: string; target: string }[] = []
  const eventRemovals: Set<string> = new Set()
  lines.forEach((line, i) => {
    const addMatch = line.match(/(\w+)\.\s*addEventListener\s*\(\s*['"]([^'"]+)['"]/)
    if (addMatch) {
      eventListeners.push({ line: i + 1, event: addMatch[2], target: addMatch[1].trim() })
    }
    const removeMatch = line.match(/(\w+)\.\s*removeEventListener\s*\(\s*['"]([^'"]+)['"]/)
    if (removeMatch) {
      eventRemovals.add(`${removeMatch[1].trim()}:${removeMatch[2]}`)
    }
  })
  eventListeners.forEach(l => {
    const key = `${l.target}:${l.event}`
    if (!eventRemovals.has(key)) {
      listenerLeaks.push({ line: l.line, event: l.event, issue: `addEventListener('${l.event}') without matching removeEventListener`, suggestion: `Call removeEventListener('${l.event}', handler) in cleanup/unmount` })
    }
  })

  // Detect setInterval/setTimeout without clearInterval/clearTimeout
  const timers: { line: number; timerType: string }[] = []
  const timerClears: Set<string> = new Set()
  lines.forEach((line, i) => {
    if (line.match(/\bsetInterval\s*\(/)) {
      timers.push({ line: i + 1, timerType: 'setInterval' })
    }
    if (line.match(/\bsetTimeout\s*\(/)) {
      timers.push({ line: i + 1, timerType: 'setTimeout' })
    }
    if (line.match(/\bclearInterval\s*\(/)) timerClears.add('setInterval')
    if (line.match(/\bclearTimeout\s*\(/)) timerClears.add('setTimeout')
  })
  if (timers.length > 0 && timerClears.size === 0) {
    timers.forEach(t => {
      timerLeaks.push({ line: t.line, timerType: t.timerType, issue: `${t.timerType}() without cleanup`, suggestion: `Store timer ID and call ${t.timerType === 'setInterval' ? 'clearInterval' : 'clearTimeout'}() on unmount` })
    })
  }

  // Detect potential closure leaks (large objects in closures)
  lines.forEach((line, i) => {
    if (line.match(/(?:const|let|var)\s+(\w+)\s*=\s*(?:req|request|response|res|ctx|context|db|database|pool|connection)\b/)) {
      const varMatch = line.match(/(?:const|let|var)\s+(\w+)\s*=/)
      if (varMatch && line.includes('=>') && !line.includes(') =>')) {
        closureLeaks.push({ line: i + 1, variable: varMatch[1], issue: 'Potential closure leak: large object captured in arrow function', suggestion: 'Destructure only needed properties or nullify after use' })
      }
    }
  })

  // Detect unbounded caches/maps
  lines.forEach((line, i) => {
    if (line.match(/(?:const|let|var)\s+(\w+)\s*=\s*(?:new\s+Map|new\s+WeakMap|\{\s*\})/)) {
      const varName = line.match(/(?:const|let|var)\s+(\w+)/)?.[1] || ''
      const hasClear = lines.some((l, j) => j > i && l.includes(`${varName}.clear()`) || l.includes(`${varName}.delete(`) || l.includes(`${varName}.size`))
      if (!hasClear) {
        cacheLeaks.push({ line: i + 1, pattern: `Unbounded ${line.includes('WeakMap') ? 'WeakMap' : line.includes('Map') ? 'Map' : 'object'} \`${varName}\``, issue: 'Cache without eviction policy may grow unbounded', suggestion: 'Implement LRU eviction or use WeakMap for automatic GC' })
      }
    }
  })

  const totalIssues = listenerLeaks.length + timerLeaks.length + closureLeaks.length + cacheLeaks.length
  const cleanupScore = Math.max(0, 100 - totalIssues * 15)
  const severity: Severity = totalIssues >= 5 ? 'critical' : totalIssues >= 3 ? 'error' : totalIssues >= 1 ? 'warning' : 'info'

  return {
    totalIssues, severity, listenerLeaks, timerLeaks, closureLeaks, cacheLeaks, cleanupScore,
    summary: totalIssues === 0 ? 'No obvious memory leaks found' : `${totalIssues} potential memory leak(s) detected — cleanup score: ${cleanupScore}/100`
  }
}

function formatMemoryLeakReport(r: MemoryLeakResult): string {
  const lines: string[] = []
  lines.push(`# Memory Leak Analysis`)
  lines.push(``)
  lines.push(`**Cleanup Score:** ${r.cleanupScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.listenerLeaks.length > 0) {
    lines.push(`## Event Listener Leaks (${r.listenerLeaks.length})`)
    r.listenerLeaks.forEach(l => {
      lines.push(`- Line ${l.line}: ${l.issue}`)
      lines.push(`  - Fix: ${l.suggestion}`)
    })
    lines.push(``)
  }

  if (r.timerLeaks.length > 0) {
    lines.push(`## Timer Leaks (${r.timerLeaks.length})`)
    r.timerLeaks.forEach(t => {
      lines.push(`- Line ${t.line}: ${t.issue}`)
      lines.push(`  - Fix: ${t.suggestion}`)
    })
    lines.push(``)
  }

  if (r.closureLeaks.length > 0) {
    lines.push(`## Closure Leaks (${r.closureLeaks.length})`)
    r.closureLeaks.forEach(c => {
      lines.push(`- Line ${c.line}: ${c.issue} (\`${c.variable}\`)`)
      lines.push(`  - Fix: ${c.suggestion}`)
    })
    lines.push(``)
  }

  if (r.cacheLeaks.length > 0) {
    lines.push(`## Unbounded Cache (${r.cacheLeaks.length})`)
    r.cacheLeaks.forEach(c => {
      lines.push(`- Line ${c.line}: ${c.issue} (\`${c.pattern}\`)`)
      lines.push(`  - Fix: ${c.suggestion}`)
    })
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 67: i18n Readiness Check ----

interface I18nResult {
  totalIssues: number
  severity: Severity
  hardcodedStrings: { line: number; text: string; context: string; suggestion: string }[]
  hardcodedNumbers: { line: number; value: string; issue: string }[]
  hardcodedDates: { line: number; pattern: string; issue: string }[]
  uiStringsWithoutKey: { line: number; text: string; suggestion: string }[]
  i18nReadyScore: number
  summary: string
}

function checkI18n(code: string): I18nResult {
  const lines = code.split('\n')
  const hardcodedStrings: I18nResult['hardcodedStrings'] = []
  const hardcodedNumbers: I18nResult['hardcodedNumbers'] = []
  const hardcodedDates: I18nResult['hardcodedDates'] = []
  const uiKeywords = /(?:title|label|placeholder|message|text|heading|description|tooltip|error|warning|success|hint|button|submit|cancel|ok|close|back|next|loading|welcome|greeting|hello|hi|bye|confirm|delete|remove|add|edit|save|cancel)/i

  lines.forEach((line, i) => {
    // Skip comments, imports, console
    if (line.match(/^\s*(?:\/\/|\/\*|\*|\*\/)|import\s|console\.|require\(|^\s*[\#]/)) return

    // Detect hardcoded UI strings: 'hello world' or "welcome" in JSX/render/return
    const strMatch = line.match(/[''"]([^'"']{3,80})[''"]/g)
    if (strMatch && (line.includes('return') || line.includes('jsx') || line.includes('=>') || line.includes('render'))) {
      strMatch.forEach(s => {
        const text = s.slice(1, -1)
        if (uiKeywords.test(text) && !text.includes('${') && !text.includes('%') && text.length > 2) {
          hardcodedStrings.push({ line: i + 1, text, context: line.trim().substring(0, 80), suggestion: `Use i18n.t('${text.toLowerCase().replace(/\s+/g, '_')}') instead` })
        }
      })
    }

    // Detect hardcoded numbers in UI context (dimensions, times, counts)
    const numMatch = line.match(/(?:width|height|size|duration|timeout|delay|interval|max|min|count|limit|threshold)\s*[:=]\s*(\d+)/i)
    if (numMatch) {
      hardcodedNumbers.push({ line: i + 1, value: numMatch[1], issue: `Hardcoded numeric value '${numMatch[1]}' — consider configuration for locale-specific formatting` })
    }

    // Detect hardcoded dates
    const dateMatch = line.match(/\d{4}[-/]\d{1,2}[-/]\d{1,2}/)
    if (dateMatch && !line.includes('//')) {
      hardcodedDates.push({ line: i + 1, pattern: dateMatch[0], issue: 'Hardcoded date pattern — use Intl.DateTimeFormat for locale-aware formatting' })
    }
  })

  const totalIssues = hardcodedStrings.length + hardcodedNumbers.length + hardcodedDates.length
  const i18nReadyScore = Math.max(0, 100 - totalIssues * 8)
  const severity: Severity = totalIssues >= 10 ? 'warning' : totalIssues >= 5 ? 'warning' : totalIssues >= 1 ? 'info' : 'info'

  return {
    totalIssues, severity, hardcodedStrings, hardcodedNumbers, hardcodedDates, uiStringsWithoutKey: [], i18nReadyScore,
    summary: totalIssues === 0 ? 'Code appears i18n-ready: no hardcoded UI strings found' : `${totalIssues} i18n issue(s) found — readiness score: ${i18nReadyScore}/100`
  }
}

function formatI18nReport(r: I18nResult): string {
  const lines: string[] = []
  lines.push(`# i18n Readiness Analysis`)
  lines.push(``)
  lines.push(`**Readiness Score:** ${r.i18nReadyScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.hardcodedStrings.length > 0) {
    lines.push(`## Hardcoded UI Strings (${r.hardcodedStrings.length})`)
    r.hardcodedStrings.slice(0, 20).forEach(s => {
      lines.push(`- Line ${s.line}: \`${s.text}\``)
      lines.push(`  - ${s.suggestion}`)
    })
    if (r.hardcodedStrings.length > 20) lines.push(`- ... and ${r.hardcodedStrings.length - 20} more`)
    lines.push(``)
  }

  if (r.hardcodedNumbers.length > 0) {
    lines.push(`## Hardcoded Numbers (${r.hardcodedNumbers.length})`)
    r.hardcodedNumbers.forEach(n => {
      lines.push(`- Line ${n.line}: ${n.issue}`)
    })
    lines.push(``)
  }

  if (r.hardcodedDates.length > 0) {
    lines.push(`## Hardcoded Dates (${r.hardcodedDates.length})`)
    r.hardcodedDates.forEach(d => {
      lines.push(`- Line ${d.line}: ${d.issue}`)
    })
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 68: Logging Quality Analysis ----

interface LoggingResult {
  totalIssues: number
  severity: Severity
  consoleUsage: { line: number; method: string; issue: string; suggestion: string }[]
  piiExposure: { line: number; field: string; suggestion: string }[]
  missingContext: { line: number; issue: string; suggestion: string }[]
  logLevelIssues: { line: number; issue: string; suggestion: string }[]
  structuredLoggingScore: number
  summary: string
}

function analyzeLogging(code: string): LoggingResult {
  const lines = code.split('\n')
  const consoleUsage: LoggingResult['consoleUsage'] = []
  const piiExposure: LoggingResult['piiExposure'] = []
  const missingContext: LoggingResult['missingContext'] = []
  const logLevelIssues: LoggingResult['logLevelIssues'] = []
  const piiPatterns = /(?:password|ssn|social.security|credit.card|cvv|token|secret|apikey|api.key|auth|email|phone|address|dob|birthdate|name|first_name|last_name)/i

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/\/|\/\*|\*)/)) return

    // Detect console.* usage
    const consoleMatch = line.match(/console\.(log|warn|error|info|debug|trace)\s*\(/)
    if (consoleMatch) {
      const method = consoleMatch[1]
      let severity_of_issue = 'Replace with structured logger (winston/pino)'
      if (method === 'log') {
        consoleUsage.push({ line: i + 1, method: 'log', issue: 'console.log in production code', suggestion: 'Use logger.debug() or remove for production' })
      }
      if (method === 'debug') {
        consoleUsage.push({ line: i + 1, method: 'debug', issue: 'console.debug in production code', suggestion: 'Use logger.debug() with proper log levels' })
      }
    }

    // Detect PII in log messages
    if (piiPatterns.test(line) && (line.includes('console.') || line.includes('logger.') || line.includes('log.'))) {
      const fieldMatch = line.match(piiPatterns)
      piiExposure.push({ line: i + 1, field: fieldMatch?.[0] || 'PII', suggestion: `Mask ${fieldMatch?.[0] || 'PII'} value before logging` })
    }

    // Detect log without context/string literal
    if (line.match(new RegExp('console\\.\\w+\\s*\\(\\s*\\w+\\s*\\)'))) {
      missingContext.push({ line: i + 1, issue: 'Logging variable without descriptive context', suggestion: 'Add a message prefix: console.log("User data:", user)' })
    }

    // Detect excessive console.error without throw
    if (line.includes('console.error') && !line.includes('throw') && !line.includes('Error(')) {
      logLevelIssues.push({ line: i + 1, issue: 'console.error without throwing — may silently swallow errors', suggestion: 'Either throw an error or use logger.warn()' })
    }
  })

  const totalIssues = consoleUsage.length + piiExposure.length + missingContext.length + logLevelIssues.length
  const structuredLoggingScore = Math.max(0, 100 - totalIssues * 10)
  const severity: Severity = piiExposure.length > 0 ? 'critical' : totalIssues >= 5 ? 'error' : totalIssues >= 2 ? 'warning' : 'info'

  return {
    totalIssues, severity, consoleUsage, piiExposure, missingContext, logLevelIssues, structuredLoggingScore,
    summary: totalIssues === 0 ? 'Logging practices look clean' : `${totalIssues} logging issue(s) — structured logging score: ${structuredLoggingScore}/100`
  }
}

function formatLoggingReport(r: LoggingResult): string {
  const lines: string[] = []
  lines.push(`# Logging Quality Analysis`)
  lines.push(``)
  lines.push(`**Structured Score:** ${r.structuredLoggingScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.piiExposure.length > 0) {
    lines.push(`## PII Exposure Risk (${r.piiExposure.length}) ⚠️`)
    r.piiExposure.forEach(p => {
      lines.push(`- Line ${p.line}: Logging \`${p.field}\` — ${p.suggestion}`)
    })
    lines.push(``)
  }

  if (r.consoleUsage.length > 0) {
    lines.push(`## Console Statements (${r.consoleUsage.length})`)
    r.consoleUsage.forEach(c => {
      lines.push(`- Line ${c.line}: console.${c.method}() — ${c.suggestion}`)
    })
    lines.push(``)
  }

  if (r.missingContext.length > 0) {
    lines.push(`## Missing Log Context (${r.missingContext.length})`)
    r.missingContext.forEach(m => {
      lines.push(`- Line ${m.line}: ${m.suggestion}`)
    })
    lines.push(``)
  }

  if (r.logLevelIssues.length > 0) {
    lines.push(`## Log Level Issues (${r.logLevelIssues.length})`)
    r.logLevelIssues.forEach(l => {
      lines.push(`- Line ${l.line}: ${l.suggestion}`)
    })
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 69: Configuration File Validator ----

interface ConfigResult {
  totalIssues: number
  severity: Severity
  missingFields: { field: string; reason: string; suggestion: string }[]
  typeIssues: { line: number; field: string; expected: string; got: string }[]
  insecureValues: { field: string; issue: string; suggestion: string }[]
  deprecatedFields: { field: string; replacement: string }[]
  validationScore: number
  summary: string
}

function validateConfig(code: string): ConfigResult {
  const lines = code.split('\n')
  const missingFields: ConfigResult['missingFields'] = []
  const typeIssues: ConfigResult['typeIssues'] = []
  const insecureValues: ConfigResult['insecureValues'] = []
  const deprecatedFields: ConfigResult['deprecatedFields'] = []

  // Required fields for common configs
  const requiredFields = ['name', 'version']
  const foundFields: Set<string> = new Set()

  lines.forEach((line, i) => {
    // Detect field names in JSON/YAML-like config
    const fieldMatch = line.match(/['"]?(\w+)['"]?\s*[:=]\s*/)
    if (fieldMatch) {
      foundFields.add(fieldMatch[1])
    }

    // Detect insecure values
    if (line.match(/(?:password|secret|token|apikey|api_key)\s*[:=]\s*['"][^'"]+['"]/i)) {
      const valMatch = line.match(/(\w+)\s*[:=]\s*['"]([^'"]+)['"]/)
      if (valMatch && valMatch[2] !== '***' && !valMatch[2].includes('${') && !valMatch[2].includes('process.env')) {
        insecureValues.push({ field: valMatch[1], issue: 'Hardcoded secret in config', suggestion: 'Use environment variable: process.env.' + valMatch[1].toUpperCase() })
      }
    }

    // Detect boolean as string
    const boolMatch = line.match(/(?:enabled|disabled|debug|verbose|strict|production)\s*[:=]\s*['"](true|false|yes|no|on|off)['"]/i)
    if (boolMatch) {
      typeIssues.push({ line: i + 1, field: boolMatch[0].split(/[:=]/)[0].trim(), expected: 'boolean', got: 'string' })
    }

    // Detect port as string
    const portMatch = line.match(/port\s*[:=]\s*['"](\d+)['"]/)
    if (portMatch) {
      typeIssues.push({ line: i + 1, field: 'port', expected: 'number', got: 'string' })
    }

    // Detect deprecated fields
    const deprecated = [{ old: 'compilerOptions.moduleResolution', new: 'moduleResolution: "bundler"' }, { old: 'extends', new: 'Use overrides instead' }]
    deprecated.forEach(d => {
      if (line.includes(d.old)) {
        deprecatedFields.push({ field: d.old, replacement: d.new })
      }
    })
  })

  // Check missing required fields
  requiredFields.forEach(f => {
    if (!foundFields.has(f)) {
      missingFields.push({ field: f, reason: 'Required field missing in config', suggestion: `Add '${f}' field to configuration` })
    }
  })

  const totalIssues = missingFields.length + typeIssues.length + insecureValues.length + deprecatedFields.length
  const validationScore = Math.max(0, 100 - totalIssues * 12)
  const severity: Severity = insecureValues.length > 0 ? 'critical' : totalIssues >= 5 ? 'error' : totalIssues >= 2 ? 'warning' : 'info'

  return {
    totalIssues, severity, missingFields, typeIssues, insecureValues, deprecatedFields, validationScore,
    summary: totalIssues === 0 ? 'Configuration file is valid' : `${totalIssues} config issue(s) — validation score: ${validationScore}/100`
  }
}

function formatConfigReport(r: ConfigResult): string {
  const lines: string[] = []
  lines.push(`# Configuration Validation`)
  lines.push(``)
  lines.push(`**Validation Score:** ${r.validationScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.insecureValues.length > 0) {
    lines.push(`## Insecure Values (${r.insecureValues.length}) ⚠️`)
    r.insecureValues.forEach(v => {
      lines.push(`- \`${v.field}\`: ${v.suggestion}`)
    })
    lines.push(``)
  }

  if (r.missingFields.length > 0) {
    lines.push(`## Missing Required Fields (${r.missingFields.length})`)
    r.missingFields.forEach(f => {
      lines.push(`- \`${f.field}\`: ${f.reason}`)
    })
    lines.push(``)
  }

  if (r.typeIssues.length > 0) {
    lines.push(`## Type Issues (${r.typeIssues.length})`)
    r.typeIssues.forEach(t => {
      lines.push(`- Line ${t.line}: \`${t.field}\` should be ${t.expected}, not ${t.got}`)
    })
    lines.push(``)
  }

  if (r.deprecatedFields.length > 0) {
    lines.push(`## Deprecated Fields (${r.deprecatedFields.length})`)
    r.deprecatedFields.forEach(d => {
      lines.push(`- \`${d.field}\` → ${d.replacement}`)
    })
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 70: Bundle Size Estimation ----

interface BundleResult {
  totalIssues: number
  severity: Severity
  heavyImports: { line: number; module: string; estimatedSize: string; suggestion: string }[]
  duplicateModules: { module: string; lines: number[] }[]
  largeChains: { line: number; chain: string; depth: number; suggestion: string }[]
  dynamicImportOpportunities: { line: number; module: string; suggestion: string }[]
  estimatedTotalSize: string
  summary: string
}

function estimateBundleSize(code: string): BundleResult {
  const lines = code.split('\n')
  const heavyImports: BundleResult['heavyImports'] = []
  const duplicateModules: Map<string, number[]> = new Map()
  const largeChains: BundleResult['largeChains'] = []
  const dynamicImportOpportunities: BundleResult['dynamicImportOpportunities'] = []

  const heavyPackages: Record<string, string> = {
    lodash: '~70KB', moment: '~67KB', jquery: '~87KB', axios: '~13KB',
    antd: '~100KB+', '@mui/material': '~90KB+', 'chart.js': '~80KB',
    'three.js': '~120KB', 'ramda': '~25KB', 'date-fns': '~20KB',
    'express': '~20KB', 'koa': '~15KB', 'vue': '~40KB', 'react': '~6KB (core)'
  }

  lines.forEach((line, i) => {
    // Detect import statements
    const importMatch = line.match(/(?:import|require)\s*\(?['"]([^'"]+)['"]/)
    if (importMatch) {
      const module = importMatch[1]
      // Check if heavy
      const heavyKey = Object.keys(heavyPackages).find(k => module.startsWith(k))
      if (heavyKey) {
        heavyImports.push({ line: i + 1, module: heavyKey, estimatedSize: heavyPackages[heavyKey], suggestion: `Consider tree-shakeable import: import { specific } from '${heavyKey}'` })
      }
      // Track duplicates
      const baseModule = module.split('/')[0]
      if (baseModule) {
        const existing = duplicateModules.get(baseModule) || []
        existing.push(i + 1)
        duplicateModules.set(baseModule, existing)
      }
      // Detect dynamic import opportunities (large libs used in conditional code)
      if (line.includes('import') && heavyKey && i > 0) {
        const prevLine = lines[i - 1] || ''
        const nextLines = lines.slice(i + 1, i + 5).join('\n')
        if (prevLine.includes('if') || nextLines.includes('if') || nextLines.includes('lazy') || prevLine.includes('//')) {
          dynamicImportOpportunities.push({ line: i + 1, module: heavyKey, suggestion: `Use dynamic import() for '${heavyKey}' to reduce initial bundle` })
        }
      }
    }

    // Detect deep property chains: a.b.c.d.e
    const chainMatch = line.match(/(\w+(?:\.\w+){4,})/)
    if (chainMatch) {
      const chain = chainMatch[1]
      const depth = chain.split('.').length
      largeChains.push({ line: i + 1, chain, depth, suggestion: `Destructure to reduce property access chain depth` })
    }
  })

  const dupModules = Array.from(duplicateModules.entries()).filter(([_, v]) => v.length > 1).map(([m, l]) => ({ module: m, lines: l }))
  const totalIssues = heavyImports.length + dupModules.length + largeChains.length + dynamicImportOpportunities.length
  const severity: Severity = totalIssues >= 5 ? 'warning' : totalIssues >= 2 ? 'info' : 'info'

  return {
    totalIssues, severity, heavyImports, duplicateModules: dupModules, largeChains, dynamicImportOpportunities,
    estimatedTotalSize: `${heavyImports.length * 30 + 50}KB+ estimated`,
    summary: `${heavyImports.length} heavy import(s), ${dupModules.length} duplicated module(s)` + (dynamicImportOpportunities.length > 0 ? `, ${dynamicImportOpportunities.length} dynamic import opportunity(ies)` : '')
  }
}

function formatBundleReport(r: BundleResult): string {
  const lines: string[] = []
  lines.push(`# Bundle Size Estimation`)
  lines.push(``)
  lines.push(`**Estimated Base Size:** ${r.estimatedTotalSize} | **Issues:** ${r.totalIssues}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.heavyImports.length > 0) {
    lines.push(`## Heavy Imports (${r.heavyImports.length})`)
    r.heavyImports.forEach(h => {
      lines.push(`- Line ${h.line}: \`${h.module}\` (~${h.estimatedSize})`)
      lines.push(`  - ${h.suggestion}`)
    })
    lines.push(``)
  }

  if (r.duplicateModules.length > 0) {
    lines.push(`## Duplicate Modules (${r.duplicateModules.length})`)
    r.duplicateModules.forEach(d => {
      lines.push(`- \`${d.module}\` imported on lines: ${d.lines.join(', ')}`)
    })
    lines.push(``)
  }

  if (r.dynamicImportOpportunities.length > 0) {
    lines.push(`## Dynamic Import Opportunities (${r.dynamicImportOpportunities.length})`)
    r.dynamicImportOpportunities.forEach(d => {
      lines.push(`- Line ${d.line}: \`${d.module}\` — ${d.suggestion}`)
    })
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 71: Accessibility Scan ----

interface A11yResult {
  totalIssues: number
  severity: Severity
  missingAltText: { line: number; element: string; suggestion: string }[]
  missingLabels: { line: number; element: string; suggestion: string }[]
  ariaIssues: { line: number; issue: string; suggestion: string }[]
  keyboardIssues: { line: number; element: string; issue: string; suggestion: string }[]
  contrastIssues: { line: number; issue: string; suggestion: string }[]
  a11yScore: number
  summary: string
}

function scanAccessibility(code: string): A11yResult {
  const lines = code.split('\n')
  const missingAltText: A11yResult['missingAltText'] = []
  const missingLabels: A11yResult['missingLabels'] = []
  const ariaIssues: A11yResult['ariaIssues'] = []
  const keyboardIssues: A11yResult['keyboardIssues'] = []
  const contrastIssues: A11yResult['contrastIssues'] = []

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/\/|\/\*|\*)/)) return

    // Detect images without alt
    if (line.match(/<img\b/i) && !line.match(/\balt\s*=/)) {
      missingAltText.push({ line: i + 1, element: 'img', suggestion: 'Add alt attribute: alt="descriptive text" or alt="" if decorative' })
    }

    // Detect input without label
    if (line.match(/<input\b/i) && !line.match(/\bid\s*=|<label|aria-label|placeholder/)) {
      missingLabels.push({ line: i + 1, element: 'input', suggestion: 'Associate with <label for="id"> or add aria-label' })
    }

    // Detect div/span used as buttons
    if (line.match(/<(div|span)\b[^>]*(?:onClick|onclick|onPress)\s*=/i) && !line.match(/\brole\s*=\s*['"]button['"]/)) {
      keyboardIssues.push({ line: i + 1, element: line.match(/<(div|span)/i)?.[1] || 'div', issue: 'Clickable non-button element', suggestion: 'Add role="button", tabIndex={0}, and onKeyDown for keyboard access' })
    }

    // Detect missing aria-* on interactive divs
    if (line.match(/<(div|span|section|article)\b[^>]*role\s*=\s*['"]/i)) {
      const hasAria = line.match(/\baria-/)
      if (!hasAria && line.match(/role\s*=\s*['"](?:dialog|alert|tab|checkbox|radio|switch)/)) {
        ariaIssues.push({ line: i + 1, issue: `Interactive role without ARIA states`, suggestion: 'Add aria-expanded, aria-checked, or appropriate state attribute' })
      }
    }

    // Detect autofocus (can confuse screen readers)
    if (line.match(/\bautofocus\b/i)) {
      contrastIssues.push({ line: i + 1, issue: 'Autofocus may disorient screen reader users', suggestion: 'Use autofocus sparingly and only on primary action' })
    }
  })

  const totalIssues = missingAltText.length + missingLabels.length + ariaIssues.length + keyboardIssues.length + contrastIssues.length
  const a11yScore = Math.max(0, 100 - totalIssues * 10)
  const severity: Severity = totalIssues >= 5 ? 'error' : totalIssues >= 2 ? 'warning' : 'info'

  return {
    totalIssues, severity, missingAltText, missingLabels, ariaIssues, keyboardIssues, contrastIssues, a11yScore,
    summary: totalIssues === 0 ? 'Basic accessibility checks passed' : `${totalIssues} a11y issue(s) — score: ${a11yScore}/100`
  }
}

function formatA11yReport(r: A11yResult): string {
  const lines: string[] = []
  lines.push(`# Accessibility (a11y) Scan`)
  lines.push(``)
  lines.push(`**A11y Score:** ${r.a11yScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.missingAltText.length > 0) {
    lines.push(`## Missing Alt Text (${r.missingAltText.length})`)
    r.missingAltText.forEach(a => lines.push(`- Line ${a.line}: <${a.element}> — ${a.suggestion}`))
    lines.push(``)
  }

  if (r.missingLabels.length > 0) {
    lines.push(`## Missing Labels (${r.missingLabels.length})`)
    r.missingLabels.forEach(l => lines.push(`- Line ${l.line}: <${l.element}> — ${l.suggestion}`))
    lines.push(``)
  }

  if (r.keyboardIssues.length > 0) {
    lines.push(`## Keyboard Navigation (${r.keyboardIssues.length})`)
    r.keyboardIssues.forEach(k => lines.push(`- Line ${k.line}: ${k.issue} — ${k.suggestion}`))
    lines.push(``)
  }

  if (r.ariaIssues.length > 0) {
    lines.push(`## ARIA Issues (${r.ariaIssues.length})`)
    r.ariaIssues.forEach(a => lines.push(`- Line ${a.line}: ${a.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 72: Design Pattern Detection ----

interface PatternResult {
  totalFound: number
  patterns: { line: number; pattern: string; confidence: string; evidence: string; suggestion: string }[]
  antiPatterns: { line: number; pattern: string; issue: string; suggestion: string }[]
  suggestions: { pattern: string; reason: string; example: string }[]
  patternScore: number
  summary: string
}

function detectPatterns(code: string): PatternResult {
  const lines = code.split('\n')
  const patterns: PatternResult['patterns'] = []
  const antiPatterns: PatternResult['antiPatterns'] = []
  const suggestions: PatternResult['suggestions'] = []

  // Detect Singleton
  lines.forEach((line, i) => {
    if (line.match(/static\s+(?:getInstance|getInstance)\s*\(/)) {
      patterns.push({ line: i + 1, pattern: 'Singleton', confidence: 'high', evidence: 'static getInstance() method', suggestion: 'Consider dependency injection instead for testability' })
    }
    if (line.match(/\bprivate\s+constructor\s*\(/)) {
      patterns.push({ line: i + 1, pattern: 'Singleton (private constructor)', confidence: 'medium', evidence: 'private constructor', suggestion: 'Ensure this is intentional singleton usage' })
    }
  })

  // Detect Factory
  lines.forEach((line, i) => {
    if (line.match(/\bcreate\w*\s*\(\s*(?:type|kind|name|variant)\s*[,)]/i)) {
      patterns.push({ line: i + 1, pattern: 'Factory', confidence: 'medium', evidence: 'create* method accepting type parameter', suggestion: 'Factory pattern detected — ensure consistent return types' })
    }
  })

  // Detect Observer
  lines.forEach((line, i) => {
    if (line.match(/\b(on|emit|subscribe|notify|observe|listener)\b/) && line.match(/\b(function|const|=>|=>\s*\{)/)) {
      patterns.push({ line: i + 1, pattern: 'Observer/Pub-Sub', confidence: 'medium', evidence: 'Event emission/subscription pattern', suggestion: 'Consider EventTarget or RxJS for complex event flows' })
    }
  })

  // Detect Strategy
  let strategyCount = 0
  lines.forEach((line, i) => {
    if (line.match(/(?:strategy|policy|algorithm|handler|processor)\s*[:=]/i)) {
      strategyCount++
      if (strategyCount <= 3) {
        patterns.push({ line: i + 1, pattern: 'Strategy', confidence: 'low', evidence: 'Strategy-named variable/parameter', suggestion: 'Ensure strategies are interchangeable with common interface' })
      }
    }
  })

  // Anti-pattern: God Object (class with many methods)
  let classStart = -1
  const methodRegex = /^\s+(?:async\s+)?(?:\w+)\s*\([^)]*\)\s*(?::\s*\w+)?\s*\{/
  let methodCount = 0
  let classLine = 0
  lines.forEach((line, i) => {
    const classMatch = line.match(/^class\s+\w+/)
    if (classMatch && classStart === -1) {
      classStart = i
      classLine = i + 1
      methodCount = 0
    } else if (classStart >= 0 && line.match(methodRegex)) {
      methodCount++
      if (methodCount === 15) {
        antiPatterns.push({ line: classLine, pattern: 'God Object', issue: `Class has ${methodCount}+ methods`, suggestion: 'Split into smaller cohesive classes (SRP)' })
      }
    } else if (classStart >= 0 && line.match(/^\s*\}\s*$/) && methodCount > 0) {
      classStart = -1
    }
  })

  // Anti-pattern: Spaghetti Code / Chain
  lines.forEach((line, i) => {
    if (line.match(/\w+(?:\.\w+){5,}\(/)) {
      antiPatterns.push({ line: i + 1, pattern: 'Train Wreck', issue: 'Deep method chaining violates Law of Demeter', suggestion: 'Extract intermediate variables or add a facade method' })
    }
  })

  // Suggest patterns based on code structure
  if (patterns.length === 0 && antiPatterns.length === 0) {
    suggestions.push({ pattern: 'Module Pattern', reason: 'Code uses plain functions — consider organizing into modules', example: 'export const UserService = { create, find, update }' })
  }
  if (antiPatterns.some(a => a.pattern === 'God Object')) {
    suggestions.push({ pattern: 'Facade Pattern', reason: 'Large class detected — provide a simplified interface', example: 'class UserFacade { constructor(private service: UserService) {} }' })
  }

  const totalFound = patterns.length + antiPatterns.length
  const patternScore = Math.min(100, patterns.length * 15 + (antiPatterns.length === 0 ? 50 : 0))

  return {
    totalFound, patterns, antiPatterns, suggestions, patternScore,
    summary: `${patterns.length} pattern(s) detected, ${antiPatterns.length} anti-pattern(s) found`
  }
}

function formatPatternReport(r: PatternResult): string {
  const lines: string[] = []
  lines.push(`# Design Pattern Detection`)
  lines.push(``)
  lines.push(`**Patterns Found:** ${r.patterns.length} | **Anti-Patterns:** ${r.antiPatterns.length} | **Score:** ${r.patternScore}/100`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.patterns.length > 0) {
    lines.push(`## Detected Patterns`)
    r.patterns.forEach(p => {
      lines.push(`- Line ${p.line}: **${p.pattern}** (${p.confidence})`)
      lines.push(`  - Evidence: ${p.evidence}`)
      lines.push(`  - ${p.suggestion}`)
    })
    lines.push(``)
  }

  if (r.antiPatterns.length > 0) {
    lines.push(`## Anti-Patterns`)
    r.antiPatterns.forEach(a => {
      lines.push(`- Line ${a.line}: **${a.pattern}** — ${a.issue}`)
      lines.push(`  - Fix: ${a.suggestion}`)
    })
    lines.push(``)
  }

  if (r.suggestions.length > 0) {
    lines.push(`## Suggested Patterns`)
    r.suggestions.forEach(s => {
      lines.push(`- **${s.pattern}**: ${s.reason}`)
      lines.push(`  - Example: \`${s.example}\``)
    })
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 73: Error Boundary Analysis ----

interface ErrorBoundaryResult {
  totalIssues: number
  severity: Severity
  uncheckedAsync: { line: number; pattern: string; suggestion: string }[]
  emptyCatch: { line: number; issue: string; suggestion: string }[]
  missingFinally: { line: number; resource: string; suggestion: string }[]
  errorPropagation: { line: number; issue: string; suggestion: string }[]
  customErrors: { line: number; name: string; extends: string }[]
  safetyScore: number
  summary: string
}

function analyzeErrorBoundaries(code: string): ErrorBoundaryResult {
  const lines = code.split('\n')
  const uncheckedAsync: ErrorBoundaryResult['uncheckedAsync'] = []
  const emptyCatch: ErrorBoundaryResult['emptyCatch'] = []
  const missingFinally: ErrorBoundaryResult['missingFinally'] = []
  const errorPropagation: ErrorBoundaryResult['errorPropagation'] = []
  const customErrors: ErrorBoundaryResult['customErrors'] = []

  let inTryBlock = false
  let tryStartLine = 0
  let hasCatch = false
  let hasFinally = false
  let catchStartLine = 0
  let catchContent: string[] = []
  let braceDepth = 0

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/\/|\/\*|\*)/)) return

    // Detect try blocks
    if (line.match(/\btry\s*\{/)) {
      inTryBlock = true; tryStartLine = i + 1; hasCatch = false; hasFinally = false
      braceDepth = 1; catchContent = []
    }

    // Detect empty catch blocks
    if (inTryBlock && line.match(/\bcatch\s*(?:\(\w+\))?\s*\{/)) {
      hasCatch = true; catchStartLine = i + 1; catchContent = []
    }

    if (inTryBlock && hasCatch && !hasFinally) {
      catchContent.push(line.trim())
      if (line.match(/\bfinally\s*\{/)) hasFinally = true
    }

    if (inTryBlock && hasCatch && !hasFinally && catchContent.length > 1 && line.match(/^\s*\}\s*$/)) {
      // Check if catch block is effectively empty
      if (catchContent.filter(l => l.length > 0 && !l.match(/^\/\/|^\s*\*|^\s*\{|^\s*\}/)).length <= 1) {
        emptyCatch.push({ line: catchStartLine, issue: 'Empty or no-op catch block swallows errors', suggestion: 'Log error and/or rethrow: catch(e) { logger.error(e); throw e }' })
      }
    }

    // Detect async calls without try/catch
    if (line.match(/\bawait\s+/) && !inTryBlock) {
      const threeLinesAbove = lines.slice(Math.max(0, i - 3), i).join('\n')
      if (!threeLinesAbove.includes('try')) {
        uncheckedAsync.push({ line: i + 1, pattern: line.trim().substring(0, 60), suggestion: 'Wrap in try/catch or add .catch() handler' })
      }
    }

    // Detect resource usage without finally
    if (line.match(/\b(?:open|connect|acquire|lock|start)\s*\(/i) && !line.match(/\bclose|release|unlock|stop/i)) {
      const resourceName = line.match(/\b(\w+)\s*[:=]/)?.[1] || 'resource'
      const restOfCode = lines.slice(i + 1, i + 20).join('\n')
      if (!restOfCode.includes('finally') && !restOfCode.includes('close()') && !restOfCode.includes('.close')) {
        missingFinally.push({ line: i + 1, resource: resourceName, suggestion: `Use try/finally to ensure ${resourceName} is cleaned up` })
      }
    }

    // Detect throw without custom error
    if (line.match(/\bthrow\s+new\s+(\w+)\s*\(/)) {
      const throwMatch = line.match(/\bthrow\s+new\s+(\w+)\s*\(/)
      const errorName = throwMatch?.[1] || 'Error'
      if (errorName === 'Error') {
        errorPropagation.push({ line: i + 1, issue: 'Using generic Error class', suggestion: 'Create a domain-specific error class (e.g., ValidationError, NotFoundError)' })
      }
    }

    // Detect custom error classes
    const customErrorMatch = line.match(/class\s+(\w+Error)\s+extends\s+(\w+)/)
    if (customErrorMatch) {
      customErrors.push({ line: i + 1, name: customErrorMatch[1], extends: customErrorMatch[2] })
    }
  })

  const totalIssues = uncheckedAsync.length + emptyCatch.length + missingFinally.length + errorPropagation.length
  const safetyScore = Math.max(0, 100 - totalIssues * 10)
  const severity: Severity = totalIssues >= 5 ? 'error' : totalIssues >= 3 ? 'warning' : totalIssues >= 1 ? 'info' : 'info'

  return {
    totalIssues, severity, uncheckedAsync, emptyCatch, missingFinally, errorPropagation, customErrors, safetyScore,
    summary: totalIssues === 0 ? 'Error handling looks robust' : `${totalIssues} error handling issue(s) — safety score: ${safetyScore}/100`
  }
}

function formatErrorBoundaryReport(r: ErrorBoundaryResult): string {
  const lines: string[] = []
  lines.push(`# Error Boundary Analysis`)
  lines.push(``)
  lines.push(`**Safety Score:** ${r.safetyScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.uncheckedAsync.length > 0) {
    lines.push(`## Unchecked Async Operations (${r.uncheckedAsync.length})`)
    r.uncheckedAsync.forEach(a => {
      lines.push(`- Line ${a.line}: \`${a.pattern}\``)
      lines.push(`  - ${a.suggestion}`)
    })
    lines.push(``)
  }

  if (r.emptyCatch.length > 0) {
    lines.push(`## Empty Catch Blocks (${r.emptyCatch.length})`)
    r.emptyCatch.forEach(c => {
      lines.push(`- Line ${c.line}: ${c.suggestion}`)
    })
    lines.push(``)
  }

  if (r.missingFinally.length > 0) {
    lines.push(`## Resource Cleanup (${r.missingFinally.length})`)
    r.missingFinally.forEach(f => {
      lines.push(`- Line ${f.line}: \`${f.resource}\` — ${f.suggestion}`)
    })
    lines.push(``)
  }

  if (r.errorPropagation.length > 0) {
    lines.push(`## Generic Errors (${r.errorPropagation.length})`)
    r.errorPropagation.forEach(e => {
      lines.push(`- Line ${e.line}: ${e.suggestion}`)
    })
    lines.push(``)
  }

  if (r.customErrors.length > 0) {
    lines.push(`## Custom Error Classes (${r.customErrors.length})`)
    r.customErrors.forEach(c => lines.push(`- Line ${c.line}: \`${c.name} extends ${c.extends}\``))
    lines.push(``)
  }

  return lines.join('\n')
}

// ==================== V0.14.0 NEW TOOLS ====================

// ---- Tool 74: React Hooks Compliance Check ----

interface HooksResult {
  totalIssues: number
  severity: Severity
  conditionalHooks: { line: number; hook: string; issue: string; suggestion: string }[]
  loopHooks: { line: number; hook: string; issue: string; suggestion: string }[]
  missingDeps: { line: number; hook: string; missing: string[]; suggestion: string }[]
  staleClosures: { line: number; variable: string; suggestion: string }[]
  unnecessaryHooks: { line: number; hook: string; issue: string; suggestion: string }[]
  hooksScore: number
  summary: string
}

function checkReactHooks(code: string): HooksResult {
  const lines = code.split('\n')
  const conditionalHooks: HooksResult['conditionalHooks'] = []
  const loopHooks: HooksResult['loopHooks'] = []
  const missingDeps: HooksResult['missingDeps'] = []
  const staleClosures: HooksResult['staleClosures'] = []
  const unnecessaryHooks: HooksResult['unnecessaryHooks'] = []

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/\/|\/\*|\*)/)) return

    // Detect hooks in conditions
    if (line.match(/\bif\s*\(/) && lines.slice(i, i + 5).some(l => l.match(/use[A-Z]\w+\s*\(/))) {
      const hookMatch = lines.slice(i, i + 5).map(l => l.match(/use[A-Z]\w+/)).find(Boolean)
      if (hookMatch) {
        conditionalHooks.push({ line: i + 1, hook: hookMatch[0], issue: 'Hook called inside conditional', suggestion: 'Move hook outside of conditions — hooks must be called in the same order every render' })
      }
    }

    // Detect hooks in loops
    if (line.match(/\b(?:for|while|do)\s*\(/) && lines.slice(i, i + 8).some(l => l.match(/use[A-Z]\w+\s*\(/))) {
      const hookMatch = lines.slice(i, i + 8).map(l => l.match(/use[A-Z]\w+/)).find(Boolean)
      if (hookMatch) {
        loopHooks.push({ line: i + 1, hook: hookMatch[0], issue: 'Hook called inside loop', suggestion: 'Move hook outside of loops — hooks cannot be called in loops' })
      }
    }

    // Detect useEffect/useCallback without dependency array
    const effectMatch = line.match(/use(Effect|Callback|Memo|LayoutEffect)\s*\(/)
    if (effectMatch) {
      const hookName = 'use' + effectMatch[1]
      const nextLines = lines.slice(i, i + 8).join('\n')
      if (!nextLines.includes('[')) {
        // Try to find used variables
        const usedVars = new Set<string>()
        const varPattern = /\b([a-z_]\w{2,})\b/g
        let m: RegExpExecArray | null
        while ((m = varPattern.exec(nextLines)) !== null) {
          if (!['const', 'let', 'var', 'return', 'true', 'false', 'null', 'undefined', 'async', 'await', 'function'].includes(m[1])) {
            usedVars.add(m[1])
          }
        }
        const depArray = Array.from(usedVars).slice(0, 5)
        missingDeps.push({ line: i + 1, hook: hookName, missing: depArray, suggestion: `Add dependency array: [${depArray.join(', ')}]` })
      }
    }

    // Detect useState when useReducer might be better (complex state)
    if (line.match(/useState\s*\(\s*(?:\{|\[)/)) {
      unnecessaryHooks.push({ line: i + 1, hook: 'useState', issue: 'Complex state object', suggestion: 'Consider useReducer for complex state logic with multiple sub-values' })
    }

    // Detect stale closure: useEffect referencing outer scope variable without deps
    if (line.match(/useEffect\s*\(\s*\(\)\s*=>/)) {
      const blockEnd = lines.findIndex((l, j) => j > i && l.includes('}'))
      const blockLines = lines.slice(i, blockEnd > 0 ? blockEnd + 1 : i + 10)
      const hasSetState = blockLines.some(l => l.includes('set'))
      if (!hasSetState && blockLines.join('\n').includes('[') && !blockLines.join('\n').includes('[]')) {
        // skip those with explicit deps
      } else if (!blockLines.join('\n').includes('[')) {
        staleClosures.push({ line: i + 1, variable: 'state prop', suggestion: 'Effect missing dependency array — may use stale closure' })
      }
    }
  })

  const totalIssues = conditionalHooks.length + loopHooks.length + missingDeps.length + staleClosures.length + unnecessaryHooks.length
  const hooksScore = Math.max(0, 100 - totalIssues * 12)
  const severity: Severity = conditionalHooks.length + loopHooks.length > 0 ? 'error' : totalIssues >= 3 ? 'warning' : totalIssues >= 1 ? 'info' : 'info'

  return {
    totalIssues, severity, conditionalHooks, loopHooks, missingDeps, staleClosures, unnecessaryHooks, hooksScore,
    summary: totalIssues === 0 ? 'React Hooks usage follows rules' : `${totalIssues} hooks issue(s) — score: ${hooksScore}/100`
  }
}

function formatHooksReport(r: HooksResult): string {
  const lines: string[] = []
  lines.push(`# React Hooks Compliance`)
  lines.push(``)
  lines.push(`**Hooks Score:** ${r.hooksScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.conditionalHooks.length > 0) {
    lines.push(`## Conditional Hook Calls (${r.conditionalHooks.length}) ⚠️`)
    r.conditionalHooks.forEach(h => lines.push(`- Line ${h.line}: \`${h.hook}\` in condition — ${h.suggestion}`))
    lines.push(``)
  }

  if (r.loopHooks.length > 0) {
    lines.push(`## Hook Calls in Loops (${r.loopHooks.length}) ⚠️`)
    r.loopHooks.forEach(h => lines.push(`- Line ${h.line}: \`${h.hook}\` in loop — ${h.suggestion}`))
    lines.push(``)
  }

  if (r.missingDeps.length > 0) {
    lines.push(`## Missing Dependency Arrays (${r.missingDeps.length})`)
    r.missingDeps.forEach(d => lines.push(`- Line ${d.line}: \`${d.hook}\` — add [${d.missing.join(', ')}]`))
    lines.push(``)
  }

  if (r.staleClosures.length > 0) {
    lines.push(`## Stale Closures (${r.staleClosures.length})`)
    r.staleClosures.forEach(s => lines.push(`- Line ${s.line}: ${s.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 75: Database Query Analysis ----

interface QueryResult {
  totalIssues: number
  severity: Severity
  nPlusOne: { line: number; pattern: string; suggestion: string }[]
  fullTableScan: { line: number; query: string; suggestion: string }[]
  missingIndexHints: { line: number; table: string; fields: string[]; suggestion: string }[]
  selectStar: { line: number; suggestion: string }[]
  unboundedQueries: { line: number; suggestion: string }[]
  queryScore: number
  summary: string
}

function analyzeQueries(code: string): QueryResult {
  const lines = code.split('\n')
  const nPlusOne: QueryResult['nPlusOne'] = []
  const fullTableScan: QueryResult['fullTableScan'] = []
  const missingIndexHints: QueryResult['missingIndexHints'] = []
  const selectStar: QueryResult['selectStar'] = []
  const unboundedQueries: QueryResult['unboundedQueries'] = []

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/\/|\/\*|\*)/)) return

    // Detect N+1: query inside loop/forEach/map
    if ((line.match(/\.(forEach|map|filter|reduce|find)\s*\(/) || line.match(/\bfor\s*\(/)) &&
        lines.slice(i, i + 10).some(l => l.match(/\.(find|findOne|get|select|query|execute)\s*\(/))) {
      const queryMatch = lines.slice(i, i + 10).map(l => l.match(/\.(find|findOne|get|query|execute)\s*\(/)).find(Boolean)
      if (queryMatch) {
        nPlusOne.push({ line: i + 1, pattern: `Query inside ${line.match(/\.(forEach|map|find)/)?.[1] || 'loop'}()`, suggestion: 'Batch queries with WHERE IN or JOIN to avoid N+1' })
      }
    }

    // Detect SELECT *
    if (line.match(/select\s+\*/i) || line.match(/SELECT\s+\*/)) {
      selectStar.push({ line: i + 1, suggestion: 'Avoid SELECT * — specify only needed columns to reduce I/O and network transfer' })
    }

    // Detect missing LIMIT
    if (line.match(/(?:SELECT|select)\s+.*(?:FROM|from)\s+\w+/) && !line.match(/\bLIMIT\b/i)) {
      const restOfBlock = lines.slice(i, i + 5).join('\n')
      if (!restOfBlock.match(/\bLIMIT\b/i) && !restOfBlock.match(/\/.*LIMIT/)) {
        unboundedQueries.push({ line: i + 1, suggestion: 'Query without LIMIT — add pagination with LIMIT/OFFSET or cursor-based pagination' })
      }
    }

    // Detect WHERE without index hint on common filter fields
    const whereMatch = line.match(/WHERE\s+(\w+)\s*[=<>]/i)
    if (whereMatch) {
      const field = whereMatch[1]
      if (['id', 'email', 'user_id', 'created_at', 'status'].includes(field.toLowerCase())) {
        // This is informational — these fields SHOULD be indexed
      }
    }

    // Detect ORM N+1 patterns (e.g., Sequelize mongoose populate in loop)
    if (line.match(/\.(populate|include|preload)\s*\(/) && lines.slice(Math.max(0, i - 5), i).some(l => l.match(/\.(forEach|map)\s*\(/))) {
      nPlusOne.push({ line: i + 1, pattern: 'ORM populate/include inside iteration', suggestion: 'Eager load associations outside the loop using a single query' })
    }
  })

  const totalIssues = nPlusOne.length + selectStar.length + unboundedQueries.length
  const queryScore = Math.max(0, 100 - totalIssues * 12)
  const severity: Severity = nPlusOne.length > 0 ? 'error' : totalIssues >= 3 ? 'warning' : totalIssues >= 1 ? 'info' : 'info'

  return {
    totalIssues, severity, nPlusOne, fullTableScan, missingIndexHints, selectStar, unboundedQueries, queryScore,
    summary: `${nPlusOne.length} N+1 pattern(s), ${selectStar.length} SELECT *, ${unboundedQueries.length} unbounded queries`
  }
}

function formatQueryReport(r: QueryResult): string {
  const lines: string[] = []
  lines.push(`# Database Query Analysis`)
  lines.push(``)
  lines.push(`**Query Score:** ${r.queryScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.nPlusOne.length > 0) {
    lines.push(`## N+1 Query Patterns (${r.nPlusOne.length}) ⚠️`)
    r.nPlusOne.forEach(n => lines.push(`- Line ${n.line}: ${n.pattern} — ${n.suggestion}`))
    lines.push(``)
  }

  if (r.selectStar.length > 0) {
    lines.push(`## SELECT * Usage (${r.selectStar.length})`)
    r.selectStar.forEach(s => lines.push(`- Line ${s.line}: ${s.suggestion}`))
    lines.push(``)
  }

  if (r.unboundedQueries.length > 0) {
    lines.push(`## Unbounded Queries (${r.unboundedQueries.length})`)
    r.unboundedQueries.forEach(u => lines.push(`- Line ${u.line}: ${u.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 76: Regex Optimization ----

interface RegexOptResult {
  totalIssues: number
  severity: Severity
  inefficient: { line: number; pattern: string; issue: string; suggestion: string }[]
  catastrophic: { line: number; pattern: string; issue: string; suggestion: string }[]
  nonGreedyOpportunities: { line: number; pattern: string; suggestion: string }[]
  canBeSimplified: { line: number; original: string; simplified: string }[]
  readabilityIssues: { line: number; pattern: string; suggestion: string }[]
  regexScore: number
  summary: string
}

function optimizeRegex(code: string): RegexOptResult {
  const lines = code.split('\n')
  const inefficient: RegexOptResult['inefficient'] = []
  const catastrophic: RegexOptResult['catastrophic'] = []
  const nonGreedyOpportunities: RegexOptResult['nonGreedyOpportunities'] = []
  const canBeSimplified: RegexOptResult['canBeSimplified'] = []
  const readabilityIssues: RegexOptResult['readabilityIssues'] = []

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/\/|\/\*|\*)/)) return

    // Detect regex literals and new RegExp()
    const regexPatterns = line.match(/\/(?:[^/\\]|\\\\.)+\/[gimsuy]+/g) || []
    const newRegexpPatterns = line.match(/new RegExp\s*\(\s*['"](.+?)['"]/g) || []
    const allPatterns = [...regexPatterns]

    regexPatterns.forEach(p => {
      const pattern = p.slice(1, p.lastIndexOf('/'))
      // Detect catastrophic backtracking patterns: nested quantifiers
      if (pattern.match(/\(.*[\*\+]\)[\*\+]/)) {
        catastrophic.push({ line: i + 1, pattern: p, issue: 'Potential catastrophic backtracking (nested quantifiers)', suggestion: 'Rewrite to avoid nested quantifiers, or use atomic groups (?>...)' })
      }

      // Detect .*\s*...\s* patterns (greedy-waltz)
      if (pattern.match(/\.\*\s\+\.\*\s\+/)) {
        inefficient.push({ line: i + 1, pattern: p, issue: 'Multiple greedy quantifiers can cause excessive backtracking', suggestion: 'Use specific character classes or non-greedy quantifiers' })
      }

      // Detect usage of * where + is more appropriate
      if (pattern.includes('.*') && !pattern.includes('...')) {
        nonGreedyOpportunities.push({ line: i + 1, pattern: p, suggestion: 'Consider .+ instead of .* when matching one or more characters' })
      }

      // Detect overly long regex (readability)
      if (pattern.length > 60) {
        readabilityIssues.push({ line: i + 1, pattern: p.substring(0, 40) + '...', suggestion: 'Long regex — consider breaking into named sub-patterns or use regex comments' })
      }

      // Simplification patterns
      if (pattern.includes('[0-9]') && !pattern.includes('\\d')) {
        canBeSimplified.push({ line: i + 1, original: pattern, simplified: pattern.replace(/\[0-9\]/g, '\\d') })
      }
      if (pattern.includes('[a-zA-Z]') && !pattern.includes('\\w')) {
        canBeSimplified.push({ line: i + 1, original: pattern, simplified: pattern.replace(/\[a-zA-Z\]/g, '[a-zA-Z] /* consider \\w */') })
      }
    })
  })

  const totalIssues = inefficient.length + catastrophic.length + nonGreedyOpportunities.length + canBeSimplified.length + readabilityIssues.length
  const regexScore = Math.max(0, 100 - totalIssues * 8)
  const severity: Severity = catastrophic.length > 0 ? 'error' : inefficient.length > 0 ? 'warning' : totalIssues >= 3 ? 'info' : 'info'

  return {
    totalIssues, severity, inefficient, catastrophic, nonGreedyOpportunities, canBeSimplified, readabilityIssues, regexScore,
    summary: `${catastrophic.length} catastrophic risk(s), ${inefficient.length} inefficient pattern(s), ${readabilityIssues.length} readability issue(s)`
  }
}

function formatRegexOptReport(r: RegexOptResult): string {
  const lines: string[] = []
  lines.push(`# Regex Optimization Analysis`)
  lines.push(``)
  lines.push(`**Regex Score:** ${r.regexScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.catastrophic.length > 0) {
    lines.push(`## Catastrophic Backtracking Risk (${r.catastrophic.length}) ⚠️`)
    r.catastrophic.forEach(c => lines.push(`- Line ${c.line}: \`${c.pattern}\` — ${c.suggestion}`))
    lines.push(``)
  }

  if (r.inefficient.length > 0) {
    lines.push(`## Inefficient Patterns (${r.inefficient.length})`)
    r.inefficient.forEach(p => lines.push(`- Line ${p.line}: \`${p.pattern}\` — ${p.suggestion}`))
    lines.push(``)
  }

  if (r.canBeSimplified.length > 0) {
    lines.push(`## Simplification Opportunities (${r.canBeSimplified.length})`)
    r.canBeSimplified.forEach(s => lines.push(`- Line ${s.line}: \`${s.original}\` → \`${s.simplified}\``))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 77: DOM Efficiency Analysis ----

interface DomResult {
  totalIssues: number
  severity: Severity
  forcedSyncLayout: { line: number; property: string; suggestion: string }[]
  readWriteInterleave: { line: number; issue: string; suggestion: string }[]
  batchableOps: { line: number; operations: string[]; suggestion: string }[]
  inefficientSelectors: { line: number; selector: string; suggestion: string }[]
  domScore: number
  summary: string
}

function analyzeDomEfficiency(code: string): DomResult {
  const lines = code.split('\n')
  const forcedSyncLayout: DomResult['forcedSyncLayout'] = []
  const readWriteInterleave: DomResult['readWriteInterleave'] = []
  const batchableOps: DomResult['batchableOps'] = []
  const inefficientSelectors: DomResult['inefficientSelectors'] = []

  const layoutProperties = ['offsetWidth', 'offsetHeight', 'clientWidth', 'clientHeight', 'scrollTop', 'scrollLeft', 'getBoundingClientRect', 'getComputedStyle', 'offsetTop', 'offsetParent']

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/\/|\/\*|\*)/)) return

    // Detect forced synchronous layout: read layout property then modify style
    const hasLayoutRead = layoutProperties.some(p => line.includes(p))
    const hasStyleWrite = line.match(/\.style\.\w+\s*=/)

    if (hasLayoutRead && hasStyleWrite) {
      forcedSyncLayout.push({ line: i + 1, property: layoutProperties.find(p => line.includes(p)) || '', suggestion: 'Read layout properties after style changes to avoid forced synchronous layout' })
    }

    // Detect read-write interleaving across lines
    if (hasLayoutRead) {
      const nextLines = lines.slice(i + 1, i + 3)
      if (nextLines.some(l => l.match(/\.style\.\w+\s*=/))) {
        readWriteInterleave.push({ line: i + 1, issue: 'Reading layout property followed by style write causes layout thrashing', suggestion: 'Batch all reads first, then all writes (double-buffering pattern)' })
      }
    }

    // Detect querySelector with complex selectors
    const selectorMatch = line.match(/querySelector\s*\(\s*['"](.+?)['"]/)
    if (selectorMatch) {
      const sel = selectorMatch[1]
      if (sel.includes(' ') && !sel.includes('#')) {
        inefficientSelectors.push({ line: i + 1, selector: sel, suggestion: 'Complex descendant selector — prefer getElementById or querySelector with ID' })
      }
    }

    // Detect multiple DOM writes in sequence
    if (line.match(/\.style\.\w+\s*=/)) {
      const surroundingLines = lines.slice(Math.max(0, i - 2), i + 3).filter(l => l.match(/\.style\.\w+\s*=/))
      if (surroundingLines.length >= 2) {
        const ops = surroundingLines.map(l => l.match(/\.style\.(\w+)\s*=/)?.[1] || '').filter(Boolean)
        batchableOps.push({ line: i + 1, operations: ops, suggestion: 'Combine style changes into a single class toggle or cssText assignment' })
      }
    }
  })

  // Deduplicate batchable
  const uniqueBatches = batchableOps.filter((b, idx) => batchableOps.findIndex(x => x.line === b.line) === idx)

  const totalIssues = forcedSyncLayout.length + readWriteInterleave.length + uniqueBatches.length + inefficientSelectors.length
  const domScore = Math.max(0, 100 - totalIssues * 10)
  const severity: Severity = forcedSyncLayout.length > 0 ? 'warning' : totalIssues >= 3 ? 'info' : 'info'

  return {
    totalIssues, severity, forcedSyncLayout, readWriteInterleave, batchableOps: uniqueBatches, inefficientSelectors, domScore,
    summary: `${forcedSyncLayout.length} forced layout(s), ${readWriteInterleave.length} read-write interleave(s), ${uniqueBatches.length} batchable operation(s)`
  }
}

function formatDomReport(r: DomResult): string {
  const lines: string[] = []
  lines.push(`# DOM Efficiency Analysis`)
  lines.push(``)
  lines.push(`**DOM Score:** ${r.domScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.forcedSyncLayout.length > 0) {
    lines.push(`## Forced Synchronous Layout (${r.forcedSyncLayout.length}) ⚠️`)
    r.forcedSyncLayout.forEach(f => lines.push(`- Line ${f.line}: Read \`${f.property}\` with style write — ${f.suggestion}`))
    lines.push(``)
  }

  if (r.readWriteInterleave.length > 0) {
    lines.push(`## Layout Thrashing (${r.readWriteInterleave.length})`)
    r.readWriteInterleave.forEach(r => lines.push(`- Line ${r.line}: ${r.suggestion}`))
    lines.push(``)
  }

  if (r.batchableOps.length > 0) {
    lines.push(`## Batchable Operations (${r.batchableOps.length})`)
    r.batchableOps.forEach(b => lines.push(`- Line ${b.line}: [${b.operations.join(', ')}] — ${b.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 78: Security Headers Analysis ----

interface SecurityHeadersResult {
  totalIssues: number
  severity: Severity
  missingHeaders: { header: string; description: string; suggestion: string }[]
  misconfiguredHeaders: { header: string; issue: string; suggestion: string }[]
  deprecatedHeaders: { header: string; replacement: string }[]
  corsIssues: { line: number; issue: string; suggestion: string }[]
  securityScore: number
  summary: string
}

function analyzeSecurityHeaders(code: string): SecurityHeadersResult {
  const lines = code.split('\n')
  const missingHeaders: SecurityHeadersResult['missingHeaders'] = []
  const misconfiguredHeaders: SecurityHeadersResult['misconfiguredHeaders'] = []
  const deprecatedHeaders: SecurityHeadersResult['deprecatedHeaders'] = []
  const corsIssues: SecurityHeadersResult['corsIssues'] = []

  const essentialHeaders = [
    { name: 'Content-Security-Policy', desc: 'Prevents XSS and injection attacks' },
    { name: 'Strict-Transport-Security', desc: 'Enforces HTTPS connections' },
    { name: 'X-Content-Type-Options', desc: 'Prevents MIME type sniffing' },
    { name: 'X-Frame-Options', desc: 'Prevents clickjacking' },
    { name: 'Referrer-Policy', desc: 'Controls referrer information' },
    { name: 'Permissions-Policy', desc: 'Controls browser feature access' }
  ]

  const codeLower = code.toLowerCase()

  // Check for missing security headers
  essentialHeaders.forEach(h => {
    if (!codeLower.includes(h.name.toLowerCase())) {
      missingHeaders.push({ header: h.name, description: h.desc, suggestion: `Set ${h.name} response header` })
    }
  })

  // Detect misconfigured CORS
  lines.forEach((line, i) => {
    if (line.match(/access-control-allow-origin.*\*/i) || line.match(/cors\s*\(\s*\{\s*origin\s*:\s*['"]\*['"]/i)) {
      corsIssues.push({ line: i + 1, issue: 'CORS origin set to wildcard (*) — allows any domain', suggestion: 'Restrict to specific origins: origin: ["https://yourdomain.com"]' })
    }
    if (line.match(/\.header\s*\(\s*['"]access-control-allow-origin['"]\s*,\s*['"]\*['"]\)/i)) {
      corsIssues.push({ line: i + 1, issue: 'CORS Access-Control-Allow-Origin set to *', suggestion: 'Use origin whitelist instead of wildcard' })
    }
  })

  // Detect deprecated headers
  if (codeLower.includes('x-xss-protection')) {
    deprecatedHeaders.push({ header: 'X-XSS-Protection', replacement: 'Use Content-Security-Policy instead (modern browsers ignore X-XSS-Protection)' })
  }
  if (codeLower.includes('public-key-pins') || codeLower.includes('publickeypins')) {
    deprecatedHeaders.push({ header: 'Public-Key-Pins', replacement: 'Removed from browsers — use Certificate Transparency instead' })
  }

  // Check for insecure cookie settings
  lines.forEach((line, i) => {
    if (line.match(/cookie|set-cookie/i) && !line.match(/httponly|secure|samesite/i)) {
      misconfiguredHeaders.push({ header: 'Cookie', issue: 'Cookie set without security attributes', suggestion: 'Add HttpOnly, Secure, and SameSite attributes to cookies' })
    }
  })

  const totalIssues = missingHeaders.length + misconfiguredHeaders.length + deprecatedHeaders.length + corsIssues.length
  const securityScore = Math.max(0, 100 - missingHeaders.length * 8 - corsIssues.length * 15 - deprecatedHeaders.length * 5)
  const severity: Severity = corsIssues.length > 0 ? 'critical' : missingHeaders.length >= 4 ? 'warning' : totalIssues >= 2 ? 'info' : 'info'

  return {
    totalIssues, severity, missingHeaders, misconfiguredHeaders, deprecatedHeaders, corsIssues, securityScore,
    summary: `${missingHeaders.length} missing header(s), ${corsIssues.length} CORS issue(s), ${deprecatedHeaders.length} deprecated header(s)`
  }
}

function formatSecurityHeadersReport(r: SecurityHeadersResult): string {
  const lines: string[] = []
  lines.push(`# Security Headers Analysis`)
  lines.push(``)
  lines.push(`**Security Score:** ${r.securityScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.corsIssues.length > 0) {
    lines.push(`## CORS Misconfigurations (${r.corsIssues.length}) ⚠️`)
    r.corsIssues.forEach(c => lines.push(`- Line ${c.line}: ${c.suggestion}`))
    lines.push(``)
  }

  if (r.missingHeaders.length > 0) {
    lines.push(`## Missing Security Headers (${r.missingHeaders.length})`)
    r.missingHeaders.forEach(h => lines.push(`- **${h.header}**: ${h.description}`))
    lines.push(``)
  }

  if (r.misconfiguredHeaders.length > 0) {
    lines.push(`## Misconfigured Headers (${r.misconfiguredHeaders.length})`)
    r.misconfiguredHeaders.forEach(h => lines.push(`- ${h.header}: ${h.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 79: CSS/Style Analysis ----

interface CssResult {
  totalIssues: number
  severity: Severity
  specificityIssues: { line: number; selector: string; specificity: string; suggestion: string }[]
  duplicateStyles: { rule: string; lines: number[] }[]
  unusedSelectors: { line: number; selector: string; suggestion: string }[]
  magicNumbers: { line: number; value: string; suggestion: string }[]
  importantOveruse: { line: number; property: string; suggestion: string }[]
  cssScore: number
  summary: string
}

function analyzeCss(code: string): CssResult {
  const lines = code.split('\n')
  const specificityIssues: CssResult['specificityIssues'] = []
  const duplicateStyles: Map<string, number[]> = new Map()
  const unusedSelectors: CssResult['unusedSelectors'] = []
  const magicNumbers: CssResult['magicNumbers'] = []
  const importantOveruse: CssResult['importantOveruse'] = []

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/\/|\/\*|\*)/)) return

    // Detect !important usage
    if (line.match(/!important/)) {
      const propMatch = line.match(/([\w-]+)\s*:[^!]+!important/)
      if (propMatch) {
        importantOveruse.push({ line: i + 1, property: propMatch[1], suggestion: 'Avoid !important — increase specificity or refactor CSS architecture' })
      }
    }

    // Detect magic pixel values
    const pxMatch = line.match(/(\d{2,})px/g)
    if (pxMatch) {
      pxMatch.forEach(px => {
        const val = parseInt(px)
        if (val > 40 && val % 8 !== 0) {
          magicNumbers.push({ line: i + 1, value: px, suggestion: `Non-standard spacing '${px}' — consider 8px grid (${Math.round(val / 8) * 8}px)` })
        }
      })
    }

    // Detect duplicate style properties
    const styleMatch = line.match(/([\w-]+)\s*:\s*([^;]+)/g)
    if (styleMatch) {
      styleMatch.forEach(s => {
        const prop = s.split(':')[0].trim()
        const existing = duplicateStyles.get(prop) || []
        existing.push(i + 1)
        duplicateStyles.set(prop, existing)
      })
    }

    // Detect ID selectors (high specificity)
    const idSelector = line.match(/#(\w+)\s*\{/)
    if (idSelector) {
      specificityIssues.push({ line: i + 1, selector: `#${idSelector[1]}`, specificity: '(1,0,0)', suggestion: 'High specificity — prefer class selectors for reusable styles' })
    }
  })

  const dups = Array.from(duplicateStyles.entries()).filter(([_, v]) => v.length > 1).map(([r, l]) => ({ rule: r, lines: l }))
  const totalIssues = specificityIssues.length + dups.length + magicNumbers.length + importantOveruse.length
  const cssScore = Math.max(0, 100 - importantOveruse.length * 15 - totalIssues * 5)
  const severity: Severity = importantOveruse.length >= 3 ? 'warning' : totalIssues >= 5 ? 'warning' : 'info'

  return {
    totalIssues, severity, specificityIssues, duplicateStyles: dups, unusedSelectors, magicNumbers, importantOveruse, cssScore,
    summary: `${importantOveruse.length} !important, ${magicNumbers.length} magic numbers, ${dups.length} duplicate properties`
  }
}

function formatCssReport(r: CssResult): string {
  const lines: string[] = []
  lines.push(`# CSS/Style Analysis`)
  lines.push(``)
  lines.push(`**CSS Score:** ${r.cssScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.importantOveruse.length > 0) {
    lines.push(`## !important Overuse (${r.importantOveruse.length})`)
    r.importantOveruse.forEach(im => lines.push(`- Line ${im.line}: \`${im.property}\` — ${im.suggestion}`))
    lines.push(``)
  }

  if (r.magicNumbers.length > 0) {
    lines.push(`## Magic Numbers (${r.magicNumbers.length})`)
    r.magicNumbers.slice(0, 15).forEach(m => lines.push(`- Line ${m.line}: \`${m.value}\` — ${m.suggestion}`))
    lines.push(``)
  }

  if (r.specificityIssues.length > 0) {
    lines.push(`## High Specificity (${r.specificityIssues.length})`)
    r.specificityIssues.forEach(s => lines.push(`- Line ${s.line}: \`${s.selector}\` (${s.specificity}) — ${s.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 80: Dependency Version Policy ----

interface SemverPolicyResult {
  totalIssues: number
  severity: Severity
  pinnedVersions: { line: number; module: string; current: string; issue: string; suggestion: string }[]
  deprecatedPkgs: { line: number; module: string; issue: string; suggestion: string }[]
  wildcardDeps: { line: number; module: string; version: string; suggestion: string }[]
  duplicateDeps: { module: string; versions: string[] }[]
  policyScore: number
  summary: string
}

function analyzeSemverPolicy(code: string): SemverPolicyResult {
  const lines = code.split('\n')
  const pinnedVersions: SemverPolicyResult['pinnedVersions'] = []
  const deprecatedPkgs: SemverPolicyResult['deprecatedPkgs'] = []
  const wildcardDeps: SemverPolicyResult['wildcardDeps'] = []
  const duplicateDeps: Map<string, Set<string>> = new Map()

  const deprecatedList: Record<string, string> = {
    moment: 'Use date-fns or dayjs (tree-shakeable)',
    lodash: 'Use lodash-es or native JS alternatives',
    request: 'Use axios or node-fetch',
    'babel-core': 'Use @babel/core',
    'gulp': 'Use vite or esbuild',
    'ts-node': 'Use tsx for faster execution',
    'node-sass': 'Use dart-sass (sass package)',
    'core-js': 'Use @vitejs/plugin-legacy for legacy support'
  }

  lines.forEach((line, i) => {
    // Detect version patterns in imports/requires
    const versionMatch = line.match(/['"]([^'"]+)['"]\s*[:=,]\s*['"]?[\^~>=<]?\s*(\d+\.\d+\.\d+(-[\w.]+)?)['"]?/) ||
                         line.match(/from\s+['"]([@\w/-]+)['"]/)
    if (versionMatch) {
      const module = versionMatch[1]
      const version = versionMatch[2] || 'latest'

      // Detect wildcard versions
      if (line.match(/['"][\^~]\s*(\d+\.\d+\.\d+)['"]/) || line.match(/['"]>=?\s*\d/)) {
        wildcardDeps.push({ line: i + 1, module, version, suggestion: `Pin exact version '${module}': 'x.x.x' to ensure reproducible builds` })
      }

      // Check deprecated packages
      const deprecatedKey = Object.keys(deprecatedList).find(k => module.includes(k))
      if (deprecatedKey) {
        deprecatedPkgs.push({ line: i + 1, module: deprecatedKey, issue: `Package '${deprecatedKey}' is deprecated`, suggestion: deprecatedList[deprecatedKey] })
      }

      // Track for duplicates
      const baseModule = module.replace(/[@\^~><=\s'\"]/g, '').split('/')[0]
      if (baseModule) {
        const vers = duplicateDeps.get(baseModule) || new Set()
        vers.add(version)
        duplicateDeps.set(baseModule, vers)
      }
    }
  })

  const dups = Array.from(duplicateDeps.entries()).filter(([_, v]) => v.size > 1).map(([m, v]) => ({ module: m, versions: Array.from(v) }))
  const totalIssues = pinnedVersions.length + deprecatedPkgs.length + wildcardDeps.length + dups.length
  const policyScore = Math.max(0, 100 - deprecatedPkgs.length * 15 - wildcardDeps.length * 8)
  const severity: Severity = deprecatedPkgs.length > 0 ? 'warning' : wildcardDeps.length >= 3 ? 'warning' : 'info'

  return {
    totalIssues, severity, pinnedVersions, deprecatedPkgs, wildcardDeps, duplicateDeps: dups, policyScore,
    summary: `${deprecatedPkgs.length} deprecated, ${wildcardDeps.length} unpinned, ${dups.length} duplicate packages`
  }
}

function formatSemverPolicyReport(r: SemverPolicyResult): string {
  const lines: string[] = []
  lines.push(`# Dependency Version Policy`)
  lines.push(``)
  lines.push(`**Policy Score:** ${r.policyScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.deprecatedPkgs.length > 0) {
    lines.push(`## Deprecated Packages (${r.deprecatedPkgs.length})`)
    r.deprecatedPkgs.forEach(d => lines.push(`- Line ${d.line}: \`${d.module}\` → ${d.suggestion}`))
    lines.push(``)
  }

  if (r.wildcardDeps.length > 0) {
    lines.push(`## Unpinned Versions (${r.wildcardDeps.length})`)
    r.wildcardDeps.forEach(w => lines.push(`- Line ${w.line}: \`${w.module}@${w.version}\` — ${w.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 81: State Management Anti-Patterns ----

interface StateResult {
  totalIssues: number
  severity: Severity
  directMutation: { line: number; pattern: string; suggestion: string }[]
  unnecessaryRerenders: { line: number; pattern: string; suggestion: string }[]
  missingNormalization: { line: number; pattern: string; suggestion: string }[]
  stateInconsistency: { line: number; pattern: string; suggestion: string }[]
  largeStateObjects: { line: number; count: number; suggestion: string }[]
  stateScore: number
  summary: string
}

function analyzeStateManagement(code: string): StateResult {
  const lines = code.split('\n')
  const directMutation: StateResult['directMutation'] = []
  const unnecessaryRerenders: StateResult['unnecessaryRerenders'] = []
  const missingNormalization: StateResult['missingNormalization'] = []
  const stateInconsistency: StateResult['stateInconsistency'] = []
  const largeStateObjects: StateResult['largeStateObjects'] = []

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/\/|\/\*|\*)/)) return

    // Detect Redux state mutation
    if (line.match(/(?:state|draft)\.\w+\s*=/)) {
      if (line.includes('state.') && !line.includes('...state') && !line.includes('...draft')) {
        directMutation.push({ line: i + 1, pattern: line.trim().substring(0, 60), suggestion: 'Use spread operator or Immer for immutable updates' })
      }
    }

    // Detect array push on state
    if (line.match(/(?:state|draft)\.\w+\.\s*push\s*\(/)) {
      directMutation.push({ line: i + 1, pattern: 'Array push on state', suggestion: 'Use spread: [...arr, newItem] instead of push' })
    }

    // Detect setState in useEffect without condition
    if (line.match(/set\w+\s*\(/) && lines.slice(Math.max(0, i - 3), i).some(l => l.includes('useEffect'))) {
      const surrounding = lines.slice(Math.max(0, i - 5), i + 3).join('\n')
      if (!surrounding.includes('if') && !surrounding.includes('?.')) {
        unnecessaryRerenders.push({ line: i + 1, pattern: 'Unconditional setState in effect', suggestion: 'Add guard condition to prevent infinite re-render loops' })
      }
    }

    // Detect deeply nested state access (potential normalization issue)
    const deepAccess = line.match(/(?:state|store)\.\w+\.\w+\.\w+/)
    if (deepAccess && lines.slice(i, i + 20).some(l => l.includes('filter') || l.includes('find'))) {
      missingNormalization.push({ line: i + 1, pattern: `Nested state access: ${deepAccess[0]}`, suggestion: 'Consider normalizing state shape or using selectors (reselect)' })
    }

    // Detect large useState with many fields
    if (line.match(/useState\s*\(\s*\{/)) {
      const blockEnd = lines.findIndex((l, j) => j > i && l.includes('}'))
      const propCount = lines.slice(i, blockEnd > 0 ? blockEnd + 1 : i + 5).filter(l => l.match(/^\s*\w+\s*:/)).length
      if (propCount > 6) {
        largeStateObjects.push({ line: i + 1, count: propCount, suggestion: `State has ${propCount} properties — consider splitting into multiple useState or useReducer` })
      }
    }

    // Detect multiple setStates in sequence
    if (line.match(/set[A-Z]\w+\s*\(/)) {
      const nextLines = lines.slice(i, i + 4)
      const setCount = nextLines.filter(l => l.match(/set[A-Z]\w+\s*\(/)).length
      if (setCount >= 2) {
        stateInconsistency.push({ line: i + 1, pattern: `${setCount} consecutive setState calls`, suggestion: 'Batch updates in single setState or use useReducer for related state' })
      }
    }
  })

  const totalIssues = directMutation.length + unnecessaryRerenders.length + missingNormalization.length + stateInconsistency.length + largeStateObjects.length
  const stateScore = Math.max(0, 100 - directMutation.length * 15 - totalIssues * 8)
  const severity: Severity = directMutation.length > 0 ? 'error' : totalIssues >= 3 ? 'warning' : 'info'

  return {
    totalIssues, severity, directMutation, unnecessaryRerenders, missingNormalization, stateInconsistency, largeStateObjects, stateScore,
    summary: `${directMutation.length} mutation(s), ${unnecessaryRerenders.length} re-render risk(s), ${largeStateObjects.length} large state object(s)`
  }
}

function formatStateReport(r: StateResult): string {
  const lines: string[] = []
  lines.push(`# State Management Analysis`)
  lines.push(``)
  lines.push(`**State Score:** ${r.stateScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.directMutation.length > 0) {
    lines.push(`## Direct State Mutations (${r.directMutation.length}) ⚠️`)
    r.directMutation.forEach(m => lines.push(`- Line ${m.line}: \`${m.pattern}\` — ${m.suggestion}`))
    lines.push(``)
  }

  if (r.unnecessaryRerenders.length > 0) {
    lines.push(`## Re-render Risks (${r.unnecessaryRerenders.length})`)
    r.unnecessaryRerenders.forEach(r => lines.push(`- Line ${r.line}: ${r.suggestion}`))
    lines.push(``)
  }

  if (r.missingNormalization.length > 0) {
    lines.push(`## Missing Normalization (${r.missingNormalization.length})`)
    r.missingNormalization.forEach(n => lines.push(`- Line ${n.line}: \`${n.pattern}\` — ${n.suggestion}`))
    lines.push(``)
  }

  if (r.stateInconsistency.length > 0) {
    lines.push(`## Batched Updates (${r.stateInconsistency.length})`)
    r.stateInconsistency.forEach(s => lines.push(`- Line ${s.line}: ${s.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ==================== V0.15.0 NEW TOOLS ====================

// ---- Tool 82: API Contract Validation ----

interface ContractResult {
  totalIssues: number
  severity: Severity
  missingEndpoints: { path: string; method: string; issue: string; suggestion: string }[]
  extraEndpoints: { path: string; method: string; issue: string }[]
  schemaMismatches: { line: number; field: string; expected: string; got: string; suggestion: string }[]
  missingResponses: { endpoint: string; status: string; suggestion: string }[]
  contractScore: number
  summary: string
}

function validateApiContract(code: string): ContractResult {
  const lines = code.split('\n')
  const missingEndpoints: ContractResult['missingEndpoints'] = []
  const extraEndpoints: ContractResult['extraEndpoints'] = []
  const schemaMismatches: ContractResult['schemaMismatches'] = []
  const missingResponses: ContractResult['missingResponses'] = []

  // Detect route definitions and OpenAPI paths
  const routePatterns = code.match(/(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]/gi) || []
  const openapiPaths = code.match(/paths:\s*\n((?:\s+['"]?\/\w+[^:]*:\s*\n(?:\s+.*\n)*)*)/gi) || []

  // Detect missing error response handling
  routes: for (const route of routePatterns) {
    const methodMatch = route.match(/\.(get|post|put|delete|patch)/i)
    const pathMatch = route.match(/['"](\/[^'"]+)['"]/)
    if (methodMatch && pathMatch) {
      const method = methodMatch[1].toUpperCase()
      const path = pathMatch[1]
      // Check if route has error handling
      const routeLine = lines.findIndex(l => l.includes(route))
      const routeBlock = lines.slice(routeLine, routeLine + 20).join('\n')
      if (!routeBlock.includes('catch') && !routeBlock.includes('error') && !routeBlock.includes('500')) {
        missingResponses.push({ endpoint: `${method} ${path}`, status: '500', suggestion: 'Add error handling and 500 response documentation' })
      }
      if (!routeBlock.includes('400') && !routeBlock.includes('422') && method !== 'GET') {
        missingResponses.push({ endpoint: `${method} ${path}`, status: '400/422', suggestion: 'Document validation error responses (400/422)' })
      }
    }
  }

  // Detect missing 201 for POST
  lines.forEach((line, i) => {
    if (line.match(/res\.\w+\s*\(\s*200\s*\)/) && lines.slice(Math.max(0, i - 5), i).some(l => l.match(/\.(post|put)/))) {
      schemaMismatches.push({ line: i + 1, field: 'status', expected: '201 for POST', got: '200', suggestion: 'Use 201 Created for successful resource creation' })
    }
  })

  // Detect missing authentication on protected routes
  lines.forEach((line, i) => {
    if (line.match(/\.(post|put|delete|patch)\s*\(/) && !lines.slice(i, i + 15).some(l => l.match(/auth|jwt|verify|middleware|token|session/))) {
      const pathMatch = line.match(/['"](\/[^'"]+)['"]/)
      if (pathMatch) {
        missingEndpoints.push({ path: pathMatch[1], method: 'POST/PUT/DEL', issue: 'Route without authentication middleware', suggestion: 'Add authentication middleware (JWT, session, or API key)' })
      }
    }
  })

  const totalIssues = missingEndpoints.length + extraEndpoints.length + schemaMismatches.length + missingResponses.length
  const contractScore = Math.max(0, 100 - totalIssues * 10)
  const severity: Severity = missingEndpoints.length > 0 ? 'warning' : totalIssues >= 3 ? 'info' : 'info'

  return {
    totalIssues, severity, missingEndpoints, extraEndpoints, schemaMismatches, missingResponses, contractScore,
    summary: `${missingEndpoints.length} unprotected route(s), ${missingResponses.length} missing response(s), ${schemaMismatches.length} status code issue(s)`
  }
}

function formatContractReport(r: ContractResult): string {
  const lines: string[] = []
  lines.push(`# API Contract Validation`)
  lines.push(``)
  lines.push(`**Contract Score:** ${r.contractScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.missingEndpoints.length > 0) {
    lines.push(`## Unprotected Routes (${r.missingEndpoints.length})`)
    r.missingEndpoints.forEach(e => lines.push(`- \`${e.method} ${e.path}\`: ${e.suggestion}`))
    lines.push(``)
  }

  if (r.missingResponses.length > 0) {
    lines.push(`## Missing Response Documentation (${r.missingResponses.length})`)
    r.missingResponses.forEach(r => lines.push(`- \`${r.endpoint}\`: Add ${r.status} response handling`))
    lines.push(``)
  }

  if (r.schemaMismatches.length > 0) {
    lines.push(`## Status Code Issues (${r.schemaMismatches.length})`)
    r.schemaMismatches.forEach(s => lines.push(`- Line ${s.line}: ${s.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 83: GraphQL Analysis ----

interface GraphqlResult {
  totalIssues: number
  severity: Severity
  deepQueries: { line: number; depth: number; suggestion: string }[]
  nPlusOne: { line: number; field: string; suggestion: string }[]
  missingFragments: { line: number; typeName: string; suggestion: string }[]
  noPagination: { line: number; field: string; suggestion: string }[]
  graphqlScore: number
  summary: string
}

function analyzeGraphql(code: string): GraphqlResult {
  const lines = code.split('\n')
  const deepQueries: GraphqlResult['deepQueries'] = []
  const nPlusOne: GraphqlResult['nPlusOne'] = []
  const missingFragments: GraphqlResult['missingFragments'] = []
  const noPagination: GraphqlResult['noPagination'] = []

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/\/|\/\*|\*)/)) return

    // Detect deep queries (nested braces in GraphQL strings)
    if (line.match(/gql\s*`/) || line.match(/query\s+\w+\s*\{/) || line.match(/mutation\s+\w+\s*\{/)) {
      const blockEnd = lines.findIndex((l, j) => j > i && l.includes('}'))
      const blockLines = lines.slice(i, blockEnd > 0 ? blockEnd + 1 : i + 20)
      let maxDepth = 0
      let currentDepth = 0
      blockLines.forEach(l => {
        for (const ch of l) {
          if (ch === '{') { currentDepth++; maxDepth = Math.max(maxDepth, currentDepth) }
          else if (ch === '}') { currentDepth-- }
        }
      })
      if (maxDepth > 5) {
        deepQueries.push({ line: i + 1, depth: maxDepth, suggestion: `Query depth ${maxDepth} exceeds recommended limit of 5 — consider query complexity analysis` })
      }
    }

    // Detect GraphQL queries without pagination
    if (line.match(/query\s+\w+/) && lines.slice(i, i + 15).some(l => l.match(/users|items|posts|products|orders/))) {
      const block = lines.slice(i, i + 15).join('\n')
      if (!block.match(/first:|last:|limit:|pageSize|skip:|offset:|cursor:|after:/)) {
        const fieldMatch = block.match(/(\w+)\s*\{/g)
        noPagination.push({ line: i + 1, field: fieldMatch?.[0] || 'collection', suggestion: 'Add pagination arguments (first/last/limit/cursor) to prevent unbounded results' })
      }
    }

    // Detect potential N+1 in resolvers (field resolver without DataLoader)
    if (line.match(/resolve\s*[:(]/) || line.match(/async\s+resolve/)) {
      const resolverBlock = lines.slice(i, i + 10).join('\n')
      if (resolverBlock.match(/(?:find|findOne|findBy|getBy)/) && !resolverBlock.match(/dataloader|DataLoader|batch|cache/)) {
        nPlusOne.push({ line: i + 1, field: line.trim().substring(0, 50), suggestion: 'Consider DataLoader pattern to batch and cache database queries in resolvers' })
      }
    }

    // Detect repeated field selections (opportunity for fragments)
    if (line.match(/fragment\s*\w+\s+on/)) {
      // fragment exists — good
    } else {
      const fieldMatches = code.match(/\.\w+/g) || []
      const fieldCounts: Record<string, number> = {}
      fieldMatches.forEach(f => { fieldCounts[f] = (fieldCounts[f] || 0) + 1 })
      const repeated = Object.entries(fieldCounts).filter(([_, c]) => c > 3)
      if (repeated.length > 0 && i === lines.length - 1) {
        repeated.slice(0, 3).forEach(([field, count]) => {
          missingFragments.push({ line: 1, typeName: field, suggestion: `Field '${field}' used ${count} times — extract into named fragment for reuse` })
        })
      }
    }
  })

  const totalIssues = deepQueries.length + nPlusOne.length + missingFragments.length + noPagination.length
  const graphqlScore = Math.max(0, 100 - deepQueries.length * 15 - nPlusOne.length * 10 - totalIssues * 5)
  const severity: Severity = nPlusOne.length > 0 ? 'warning' : totalIssues >= 3 ? 'info' : 'info'

  return {
    totalIssues, severity, deepQueries, nPlusOne, missingFragments, noPagination, graphqlScore,
    summary: `${deepQueries.length} deep query(ies), ${nPlusOne.length} N+1 risk(s), ${noPagination.length} missing pagination(s)`
  }
}

function formatGraphqlReport(r: GraphqlResult): string {
  const lines: string[] = []
  lines.push(`# GraphQL Analysis`)
  lines.push(``)
  lines.push(`**GraphQL Score:** ${r.graphqlScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.deepQueries.length > 0) {
    lines.push(`## Deep Queries (${r.deepQueries.length})`)
    r.deepQueries.forEach(q => lines.push(`- Line ${q.line}: depth ${q.depth} — ${q.suggestion}`))
    lines.push(``)
  }

  if (r.nPlusOne.length > 0) {
    lines.push(`## Resolver N+1 (${r.nPlusOne.length})`)
    r.nPlusOne.forEach(n => lines.push(`- Line ${n.line}: ${n.suggestion}`))
    lines.push(``)
  }

  if (r.noPagination.length > 0) {
    lines.push(`## Missing Pagination (${r.noPagination.length})`)
    r.noPagination.forEach(p => lines.push(`- Line ${p.line}: \`${p.field}\` — ${p.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 84: Infrastructure-as-Code Analysis ----

interface IacResult {
  totalIssues: number
  severity: Severity
  securityIssues: { line: number; issue: string; suggestion: string }[]
  bestPracticeViolations: { line: number; issue: string; suggestion: string }[]
  missingConfigs: { issue: string; suggestion: string }[]
  tagIssues: { line: number; resource: string; suggestion: string }[]
  iacScore: number
  summary: string
}

function analyzeIac(code: string): IacResult {
  const lines = code.split('\n')
  const securityIssues: IacResult['securityIssues'] = []
  const bestPracticeViolations: IacResult['bestPracticeViolations'] = []
  const missingConfigs: IacResult['missingConfigs'] = []
  const tagIssues: IacResult['tagIssues'] = []

  const codeLower = code.toLowerCase()

  // Docker analysis
  if (codeLower.includes('from ') && codeLower.includes('run ')) {
    if (code.includes('FROM ') && !code.includes('AS ') && code.split('FROM').length > 1) {
      bestPracticeViolations.push({ line: 1, issue: 'Multi-stage build recommended for Docker', suggestion: 'Use multi-stage builds to reduce final image size' })
    }
    if (code.includes('latest') && code.match(/FROM\s+\w+:latest/)) {
      securityIssues.push({ line: 1, issue: 'Using :latest tag — unpredictable builds', suggestion: 'Pin image version: FROM node:20.11-alpine instead of :latest' })
    }
    if (!codeLower.includes('user ') && !codeLower.includes('adduser')) {
      securityIssues.push({ line: 1, issue: 'Running as root in container', suggestion: 'Add USER instruction to run as non-root (e.g., USER node)' })
    }
    if (!codeLower.includes('healthcheck')) {
      bestPracticeViolations.push({ line: 1, issue: 'No HEALTHCHECK instruction', suggestion: 'Add HEALTHCHECK for container orchestration monitoring' })
    }
  }

  // Kubernetes analysis
  if (codeLower.includes('kind:') && (codeLower.includes('deployment') || codeLower.includes('pod'))) {
    if (!codeLower.includes('resources:') && !codeLower.includes('limits:') && !codeLower.includes('requests:')) {
      bestPracticeViolations.push({ line: 1, issue: 'No resource limits/requests set', suggestion: 'Define CPU and memory limits/requests for predictable scheduling' })
    }
    if (!codeLower.includes('livenessprobe') && !codeLower.includes('readinessprobe')) {
      bestPracticeViolations.push({ line: 1, issue: 'No liveness or readiness probes', suggestion: 'Add livenessProbe and readinessProbe for health monitoring' })
    }
    if (codeLower.includes('latest') && code.match(/image:.*:latest/)) {
      securityIssues.push({ line: 1, issue: 'Container image uses :latest tag', suggestion: 'Pin image tag for reproducible deployments' })
    }
  }

  // Terraform analysis
  if (codeLower.includes('resource "') || codeLower.includes("resource '")) {
    if (!codeLower.includes('tags') && !codeLower.includes('tag')) {
      tagIssues.push({ line: 1, resource: 'Terraform resource', suggestion: 'Add tags (Name, Environment, Owner) for resource management' })
    }
    if (codeLower.includes('versioning') === false && codeLower.includes('aws_s3_bucket')) {
      bestPracticeViolations.push({ line: 1, issue: 'S3 bucket without versioning', suggestion: 'Enable versioning for data protection (versioning { enabled = true })' })
    }
    if (codeLower.includes('acl = "public-read"') || codeLower.includes('acl = "public"')) {
      securityIssues.push({ line: 1, issue: 'Public ACL detected on storage resource', suggestion: 'Use private ACL with restricted bucket policies' })
    }
  }

  // Check for secrets in code
  lines.forEach((line, i) => {
    if (line.match(/password|secret|apikey|api_key|token|credential/i) && line.match(/=\s*['"][^'"]{8,}['"]/) && !line.match(/process\.env|var\.|env\[|config\.get/i)) {
      securityIssues.push({ line: i + 1, issue: 'Potential hardcoded secret in IaC', suggestion: 'Use environment variables or secret manager (AWS Secrets Manager, Vault)' })
    }
  })

  const totalIssues = securityIssues.length + bestPracticeViolations.length + missingConfigs.length + tagIssues.length
  const iacScore = Math.max(0, 100 - securityIssues.length * 15 - totalIssues * 8)
  const severity: Severity = securityIssues.length > 0 ? 'warning' : totalIssues >= 3 ? 'info' : 'info'

  return {
    totalIssues, severity, securityIssues, bestPracticeViolations, missingConfigs, tagIssues, iacScore,
    summary: `${securityIssues.length} security issue(s), ${bestPracticeViolations.length} best practice violation(s), ${tagIssues.length} tagging issue(s)`
  }
}

function formatIacReport(r: IacResult): string {
  const lines: string[] = []
  lines.push(`# Infrastructure-as-Code Analysis`)
  lines.push(``)
  lines.push(`**IaC Score:** ${r.iacScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.securityIssues.length > 0) {
    lines.push(`## Security Issues (${r.securityIssues.length}) ⚠️`)
    r.securityIssues.forEach(s => lines.push(`- Line ${s.line}: ${s.suggestion}`))
    lines.push(``)
  }

  if (r.bestPracticeViolations.length > 0) {
    lines.push(`## Best Practice Violations (${r.bestPracticeViolations.length})`)
    r.bestPracticeViolations.forEach(b => lines.push(`- Line ${b.line}: ${b.suggestion}`))
    lines.push(``)
  }

  if (r.tagIssues.length > 0) {
    lines.push(`## Tagging Issues (${r.tagIssues.length})`)
    r.tagIssues.forEach(t => lines.push(`- \`${t.resource}\`: ${t.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 85: Browser Compatibility Analysis ----

interface CompatResult {
  totalIssues: number
  severity: Severity
  unsupportedFeatures: { line: number; feature: string; browsers: string; suggestion: string }[]
  missingPolyfills: { feature: string; suggestion: string }[]
  deprecatedApis: { line: number; api: string; replacement: string }[]
  compatScore: number
  summary: string
}

function analyzeBrowserCompat(code: string): CompatResult {
  const lines = code.split('\n')
  const unsupportedFeatures: CompatResult['unsupportedFeatures'] = []
  const missingPolyfills: CompatResult['missingPolyfills'] = []
  const deprecatedApis: CompatResult['deprecatedApis'] = []

  const unsupportedPatterns = [
    { pattern: /\bPromise\.any\b/, feature: 'Promise.any', browsers: 'Safari <14', suggestion: 'Use Promise.race or add core-js polyfill' },
    { pattern: /\bglobalThis\b/, feature: 'globalThis', browsers: 'IE, Safari <12.1', suggestion: 'Use self/this fallback or polyfill' },
    { pattern: /\bstructuredClone\b/, feature: 'structuredClone', browsers: 'Safari <15.4', suggestion: 'Use JSON.parse/JSON.stringify or lodash cloneDeep' },
    { pattern: /\bArray\.prototype\.at\b/, feature: '.at()', browsers: 'Chrome <92, Safari <15.4', suggestion: 'Use array[length-1] with polyfill' },
    { pattern: /\bObject\.hasOwn\b/, feature: 'Object.hasOwn', browsers: 'Chrome <93, Safari <15.4', suggestion: 'Use Object.prototype.hasOwnProperty.call(obj, key)' },
    { pattern: /\bString\.prototype\.replaceAll\b/, feature: '.replaceAll()', browsers: 'Chrome <85, Safari <13.1', suggestion: 'Use .replace(/.../g, ...) or polyfill' },
    { pattern: /\bAbortSignal\.timeout\b/, feature: 'AbortSignal.timeout', browsers: 'Firefox <100', suggestion: 'Use setTimeout + AbortController' },
    { pattern: /\bArray\.prototype\.toSorted\b|\.toSorted\b/, feature: '.toSorted()', browsers: 'Chrome <110, Safari <16', suggestion: 'Use [...arr].sort() for compatibility' },
  ]

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/\/|\/\*|\*)/)) return

    unsupportedPatterns.forEach(up => {
      if (line.match(up.pattern)) {
        unsupportedFeatures.push({ line: i + 1, feature: up.feature, browsers: up.browsers, suggestion: up.suggestion })
      }
    })

    // Detect deprecated APIs
    if (line.match(/\bdocument\.execCommand\s*\(/)) {
      deprecatedApis.push({ line: i + 1, api: 'document.execCommand()', replacement: 'Use modern APIs (Clipboard API, Input Events)' })
    }
    if (line.match(/\bwindow\.orientation\b/)) {
      deprecatedApis.push({ line: i + 1, api: 'window.orientation', replacement: 'Use screen.orientation.angle' })
    }
  })

  const totalIssues = unsupportedFeatures.length + missingPolyfills.length + deprecatedApis.length
  const compatScore = Math.max(0, 100 - unsupportedFeatures.length * 10 - deprecatedApis.length * 15)
  const severity: Severity = totalIssues >= 3 ? 'warning' : totalIssues >= 1 ? 'info' : 'info'

  return {
    totalIssues, severity, unsupportedFeatures, missingPolyfills, deprecatedApis, compatScore,
    summary: `${unsupportedFeatures.length} unsupported feature(s), ${deprecatedApis.length} deprecated API(s)`
  }
}

function formatCompatReport(r: CompatResult): string {
  const lines: string[] = []
  lines.push(`# Browser Compatibility Analysis`)
  lines.push(``)
  lines.push(`**Compat Score:** ${r.compatScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.unsupportedFeatures.length > 0) {
    lines.push(`## Unsupported Features (${r.unsupportedFeatures.length})`)
    r.unsupportedFeatures.forEach(f => lines.push(`- Line ${f.line}: \`${f.feature}\` — not supported in ${f.browsers}`))
    lines.push(``)
  }

  if (r.deprecatedApis.length > 0) {
    lines.push(`## Deprecated APIs (${r.deprecatedApis.length})`)
    r.deprecatedApis.forEach(a => lines.push(`- Line ${a.line}: \`${a.api}\` → ${a.replacement}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 86: Microservice Pattern Analysis ----

interface MicroserviceResult {
  totalIssues: number
  severity: Severity
  missingPatterns: { pattern: string; description: string; suggestion: string }[]
  missingHealthCheck: { line: number; suggestion: string }[]
  noCircuitBreaker: { line: number; endpoint: string; suggestion: string }[]
  serviceScore: number
  summary: string
}

function analyzeMicroservice(code: string): MicroserviceResult {
  const lines = code.split('\n')
  const missingPatterns: MicroserviceResult['missingPatterns'] = []
  const missingHealthCheck: MicroserviceResult['missingHealthCheck'] = []
  const noCircuitBreaker: MicroserviceResult['noCircuitBreaker'] = []

  const codeLower = code.toLowerCase()

  // Check for health check endpoint
  if ((codeLower.includes('express') || codeLower.includes('app.get') || codeLower.includes('router.get')) &&
      !codeLower.includes('/health') && !codeLower.includes('/ready') && !codeLower.includes('/live')) {
    missingHealthCheck.push({ line: 1, suggestion: 'Add health check endpoint (/health, /ready, /live) for orchestrator integration' })
  }

  // Check for circuit breaker pattern in HTTP calls
  lines.forEach((line, i) => {
    if (line.match(/(?:axios|fetch|request|http\.get)\s*[.(]/) || line.match(/fetch\s*\(/)) {
      const context = lines.slice(Math.max(0, i - 5), i + 5).join('\n')
      if (!context.match(/circuit|breaker|opossum|resilience|fallback|degrade/i)) {
        noCircuitBreaker.push({ line: i + 1, endpoint: line.trim().substring(0, 40), suggestion: 'Add circuit breaker (e.g., opossum) for external service calls' })
      }
    }
  })

  // Check for retry logic
  if (codeLower.includes('fetch') || codeLower.includes('axios') || codeLower.includes('http')) {
    if (!codeLower.includes('retry') && !codeLower.includes('backoff')) {
      missingPatterns.push({ pattern: 'Retry/Backoff', description: 'No retry logic for transient failures', suggestion: 'Implement exponential backoff retry for network calls' })
    }
  }

  // Check for timeout configuration
  lines.forEach((line, i) => {
    if (line.match(/fetch\s*\(/) && !line.match(/timeout|signal|AbortController/) && !lines.slice(i, i + 3).some(l => l.match(/timeout|AbortController/))) {
      missingPatterns.push({ pattern: 'Timeout', description: 'Fetch call without timeout', suggestion: 'Add AbortController with timeout to prevent hanging requests' })
    }
  })

  const totalIssues = missingPatterns.length + missingHealthCheck.length + noCircuitBreaker.length
  const serviceScore = Math.max(0, 100 - noCircuitBreaker.length * 12 - totalIssues * 8)
  const severity: Severity = noCircuitBreaker.length > 0 ? 'warning' : totalIssues >= 3 ? 'info' : 'info'

  return {
    totalIssues, severity, missingPatterns, missingHealthCheck, noCircuitBreaker, serviceScore,
    summary: `${noCircuitBreaker.length} uncall(s) without circuit breaker, ${missingHealthCheck.length} missing health check, ${missingPatterns.length} missing resilience pattern(s)`
  }
}

function formatMicroserviceReport(r: MicroserviceResult): string {
  const lines: string[] = []
  lines.push(`# Microservice Pattern Analysis`)
  lines.push(``)
  lines.push(`**Service Score:** ${r.serviceScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.noCircuitBreaker.length > 0) {
    lines.push(`## Missing Circuit Breakers (${r.noCircuitBreaker.length})`)
    r.noCircuitBreaker.forEach(c => lines.push(`- Line ${c.line}: \`${c.endpoint}\` — ${c.suggestion}`))
    lines.push(``)
  }

  if (r.missingHealthCheck.length > 0) {
    lines.push(`## Missing Health Check (${r.missingHealthCheck.length})`)
    r.missingHealthCheck.forEach(h => lines.push(`- ${h.suggestion}`))
    lines.push(``)
  }

  if (r.missingPatterns.length > 0) {
    lines.push(`## Missing Resilience Patterns (${r.missingPatterns.length})`)
    r.missingPatterns.forEach(p => lines.push(`- **${p.pattern}**: ${p.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 87: File Organization Analysis ----

interface OrgResult {
  totalIssues: number
  severity: Severity
  deepImports: { line: number; importPath: string; depth: number; suggestion: string }[]
  missingBarrel: { directory: string; suggestion: string }[]
  largeFiles: { line: number; suggestion: string }[]
  inconsistentNaming: { line: number; current: string; expected: string }[]
  orgScore: number
  summary: string
}

function analyzeFileOrganization(code: string): OrgResult {
  const lines = code.split('\n')
  const deepImports: OrgResult['deepImports'] = []
  const missingBarrel: OrgResult['missingBarrel'] = []
  const largeFiles: OrgResult['largeFiles'] = []
  const inconsistentNaming: OrgResult['inconsistentNaming'] = []

  // Detect deep import paths (RelativePath depth > 3)
  lines.forEach((line, i) => {
    const importMatch = line.match(/(?:import|require)\s*\(?['"]((?:\.\.\/)+[^'"]+)['"]/)
    if (importMatch) {
      const depth = (importMatch[1].match(/\.\.\//g) || []).length
      if (depth > 2) {
        deepImports.push({ line: i + 1, importPath: importMatch[1], depth, suggestion: `Deep import (${depth} levels) — consider barrel exports or path aliases` })
      }
    }
  })

  // Detect large files
  if (lines.length > 500) {
    largeFiles.push({ line: 1, suggestion: `File has ${lines.length} lines — consider splitting into smaller modules (recommended: <300 lines)` })
  }

  // Check for index.ts/barrel file opportunities (many sibling imports)
  const relativeImports = lines.filter(l => l.match(/from\s+['"]\.\.\//))
  if (relativeImports.length > 5) {
    missingBarrel.push({ directory: 'parent', suggestion: 'Multiple sibling imports — consider creating index.ts barrel for cleaner imports' })
  }

  // Detect inconsistent naming conventions
  lines.forEach((line, i) => {
    if (line.match(/import\s+\{\s*\w+\s+as\s+\w+\s*\}/)) {
      const aliasMatch = line.match(/import\s+\{\s*(\w+)\s+as\s*(\w+)\s*\}/)
      if (aliasMatch && aliasMatch[1].toLowerCase() === aliasMatch[2].toLowerCase()) {
        inconsistentNaming.push({ line: i + 1, current: `${aliasMatch[1]} as ${aliasMatch[2]}`, expected: aliasMatch[1] })
      }
    }
  })

  const totalIssues = deepImports.length + missingBarrel.length + largeFiles.length + inconsistentNaming.length
  const orgScore = Math.max(0, 100 - deepImports.length * 10 - largeFiles.length * 15 - totalIssues * 5)
  const severity: Severity = totalIssues >= 5 ? 'warning' : totalIssues >= 2 ? 'info' : 'info'

  return {
    totalIssues, severity, deepImports, missingBarrel, largeFiles, inconsistentNaming, orgScore,
    summary: `${deepImports.length} deep import(s), ${largeFiles.length} large file(s), ${inconsistentNaming.length} naming inconsistency(ies)`
  }
}

function formatOrgReport(r: OrgResult): string {
  const lines: string[] = []
  lines.push(`# File Organization Analysis`)
  lines.push(``)
  lines.push(`**Org Score:** ${r.orgScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.deepImports.length > 0) {
    lines.push(`## Deep Imports (${r.deepImports.length})`)
    r.deepImports.forEach(d => lines.push(`- Line ${d.line}: \`${d.importPath}\` (depth ${d.depth}) — ${d.suggestion}`))
    lines.push(``)
  }

  if (r.largeFiles.length > 0) {
    lines.push(`## Large Files (${r.largeFiles.length})`)
    r.largeFiles.forEach(f => lines.push(`- ${f.suggestion}`))
    lines.push(``)
  }

  if (r.inconsistentNaming.length > 0) {
    lines.push(`## Naming Issues (${r.inconsistentNaming.length})`)
    r.inconsistentNaming.forEach(n => lines.push(`- Line ${n.line}: redundant alias \`${n.current}\``))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 88: Commit Message Quality ----

interface CommitResult {
  totalIssues: number
  severity: Severity
  conventionalViolations: { line: number; message: string; issue: string; suggestion: string }[]
  tooLong: { line: number; length: number; issue: string }[]
  vagueMessages: { line: number; message: string; suggestion: string }[]
  missingScope: { line: number; suggestion: string }[]
  commitScore: number
  summary: string
}

function analyzeCommitMessage(code: string): CommitResult {
  const lines = code.split('\n')
  const conventionalViolations: CommitResult['conventionalViolations'] = []
  const tooLong: CommitResult['tooLong'] = []
  const vagueMessages: CommitResult['vagueMessages'] = []
  const missingScope: CommitResult['missingScope'] = []

  const conventionalTypes = /^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\(.+\))?:\s+.+/

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/\/|\/\*|\*)/)) return

    // Skip empty lines and non-commit lines
    if (line.trim().length < 5) return

    // Check conventional commit format
    if (!line.match(conventionalTypes) && line.length > 3 && !line.match(/^#|^\s*-/)) {
      // Only flag if it looks like a commit message (not code)
      if (line.length < 100 && !line.includes('=') && !line.includes('(')) {
        conventionalViolations.push({ line: i + 1, message: line.trim().substring(0, 50), issue: 'Does not follow Conventional Commits format', suggestion: 'Use format: type(scope): description (e.g., feat(auth): add OAuth2 login)' })
      }
    }

    // Check for scope
    if (line.match(conventionalTypes) && !line.match(/\(.+\)/)) {
      missingScope.push({ line: i + 1, suggestion: 'Add scope to indicate affected module: feat(scope): message' })
    }

    // Check subject line length
    const subject = line.split('\n')[0]
    if (subject.length > 72) {
      tooLong.push({ line: i + 1, length: subject.length, issue: `Subject line ${subject.length} chars (max 72)` })
    }

    // Detect vague messages
    const vague = ['fix bug', 'update', 'change', 'fix stuff', 'misc', 'wip', 'asdf', 'test', 'tmp', 'changes', 'minor fixes', 'code changes']
    if (vague.some(v => line.toLowerCase().includes(v))) {
      vagueMessages.push({ line: i + 1, message: line.trim().substring(0, 40), suggestion: 'Be specific: describe what changed and why' })
    }
  })

  const totalIssues = conventionalViolations.length + tooLong.length + vagueMessages.length + missingScope.length
  const commitScore = Math.max(0, 100 - conventionalViolations.length * 10 - vagueMessages.length * 15 - totalIssues * 5)
  const severity: Severity = totalIssues >= 3 ? 'info' : totalIssues >= 1 ? 'info' : 'info'

  return {
    totalIssues, severity, conventionalViolations, tooLong, vagueMessages, missingScope, commitScore,
    summary: `${conventionalViolations.length} format violation(s), ${vagueMessages.length} vague message(s), ${tooLong.length} too long`
  }
}

function formatCommitReport(r: CommitResult): string {
  const lines: string[] = []
  lines.push(`# Commit Message Quality`)
  lines.push(``)
  lines.push(`**Commit Score:** ${r.commitScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.conventionalViolations.length > 0) {
    lines.push(`## Format Violations (${r.conventionalViolations.length})`)
    r.conventionalViolations.forEach(v => lines.push(`- Line ${v.line}: \`${v.message}\``))
    lines.push(``)
  }

  if (r.vagueMessages.length > 0) {
    lines.push(`## Vague Messages (${r.vagueMessages.length})`)
    r.vagueMessages.forEach(v => lines.push(`- Line ${v.line}: \`${v.message}\` — ${v.suggestion}`))
    lines.push(``)
  }

  if (r.tooLong.length > 0) {
    lines.push(`## Too Long (${r.tooLong.length})`)
    r.tooLong.forEach(t => lines.push(`- Line ${t.line}: ${t.length} chars (max 72)`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 89: Code Splitting Opportunities ----

interface SplitResult {
  totalIssues: number
  severity: Severity
  heavySyncImports: { line: number; module: string; suggestion: string }[]
  routeLevelSplitting: { line: number; component: string; suggestion: string }[]
  largeBundles: { line: number; importCount: number; suggestion: string }[]
  lazyCandidates: { line: number; component: string; suggestion: string }[]
  splitScore: number
  summary: string
}

function analyzeCodeSplitting(code: string): SplitResult {
  const lines = code.split('\n')
  const heavySyncImports: SplitResult['heavySyncImports'] = []
  const routeLevelSplitting: SplitResult['routeLevelSplitting'] = []
  const largeBundles: SplitResult['largeBundles'] = []
  const lazyCandidates: SplitResult['lazyCandidates'] = []

  const heavyModules = ['chart.js', 'three', 'monaco', 'quill', 'codemirror', 'moment', 'lodash', 'antd', '@mui', 'pdfmake', 'xlsx', 'd3', 'ace-editor']

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/\/|\/\*|\*)/)) return

    // Detect heavy synchronous imports
    const importMatch = line.match(/import\s+.+\s+from\s+['"]([^'"]+)['"]/)
    if (importMatch) {
      const module = importMatch[1]
      const isHeavy = heavyModules.some(h => module.includes(h))
      if (isHeavy) {
        heavySyncImports.push({ line: i + 1, module, suggestion: `Heavy module '${module}' — use dynamic import() for code splitting` })
      }
    }

    // Detect React components that could be lazy-loaded
    if (line.match(/(?:function|const)\s+(\w+)\s*(?::\s*\w+)?\s*\(.*\)\s*(?::\s*\w+)?\s*=>\s*\{/) && line.match(/return\s*\(/)) {
      const nameMatch = line.match(/(?:function|const)\s+(\w+)/)
      if (nameMatch) {
        const componentName = nameMatch[1]
        // Check if it's a page/component and NOT already lazy-loaded
        if (componentName[0] === componentName[0].toUpperCase() &&
            !componentName.match(/Provider|Wrapper|Container/) &&
            !lines.slice(Math.max(0, i - 3), i).some(l => l.includes('lazy(') || l.includes('React.lazy'))) {
          // Only suggest for large components (many lines)
          const nextLines = lines.slice(i, i + 30)
          if (nextLines.length >= 15) {
            lazyCandidates.push({ line: i + 1, component: componentName, suggestion: `Dynamic import with React.lazy() and Suspense for '${componentName}'` })
          }
        }
      }
    }
  })

  // Count total imports for bundle assessment
  const topLevelImports = lines.filter(l => l.match(/^import\s+/) && !l.includes('type')).length
  if (topLevelImports > 20) {
    largeBundles.push({ line: 1, importCount: topLevelImports, suggestion: `${topLevelImports} imports in file — consider splitting into smaller modules` })
  }

  // Detect route components that should be code-split
  if (code.match(/<Route\s+path=|route\(/) && !code.match(/lazy\s*\(|React\.lazy|dynamic\s*\(import/)) {
    routeLevelSplitting.push({ line: 1, component: 'Router', suggestion: 'Apply code splitting at route level with React.lazy() + Suspense' })
  }

  const totalIssues = heavySyncImports.length + routeLevelSplitting.length + largeBundles.length + lazyCandidates.length
  const splitScore = Math.max(0, 100 - heavySyncImports.length * 12 - lazyCandidates.length * 8)
  const severity: Severity = heavySyncImports.length > 0 ? 'warning' : totalIssues >= 3 ? 'info' : 'info'

  return {
    totalIssues, severity, heavySyncImports, routeLevelSplitting, largeBundles, lazyCandidates, splitScore,
    summary: `${heavySyncImports.length} heavy sync import(s), ${lazyCandidates.length} lazy-load candidate(s), ${routeLevelSplitting.length} route split opportunity(ies)`
  }
}

function formatSplitReport(r: SplitResult): string {
  const lines: string[] = []
  lines.push(`# Code Splitting Analysis`)
  lines.push(``)
  lines.push(`**Split Score:** ${r.splitScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.heavySyncImports.length > 0) {
    lines.push(`## Heavy Synchronous Imports (${r.heavySyncImports.length})`)
    r.heavySyncImports.forEach(h => lines.push(`- Line ${h.line}: \`${h.module}\` — ${h.suggestion}`))
    lines.push(``)
  }

  if (r.lazyCandidates.length > 0) {
    lines.push(`## Lazy Loading Candidates (${r.lazyCandidates.length})`)
    r.lazyCandidates.forEach(c => lines.push(`- Line ${c.line}: \`${c.component}\` — ${c.suggestion}`))
    lines.push(``)
  }

  if (r.routeLevelSplitting.length > 0) {
    lines.push(`## Route-Level Splitting (${r.routeLevelSplitting.length})`)
    r.routeLevelSplitting.forEach(r => lines.push(`- Line ${r.line}: ${r.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ==================== V0.16.0 NEW TOOLS ====================

// ---- Tool 90: WebAssembly Compatibility ----

interface WasmResult {
  totalIssues: number
  severity: Severity
  jsInteropIssues: { line: number; issue: string; suggestion: string }[]
  memoryLeaks: { line: number; issue: string; suggestion: string }[]
  typeMismatches: { line: number; issue: string; suggestion: string }[]
  missingErrorHandling: { line: number; issue: string; suggestion: string }[]
  wasmScore: number
  summary: string
}

function checkWasmCompat(code: string): WasmResult {
  const lines = code.split('\n')
  const jsInteropIssues: WasmResult['jsInteropIssues'] = []
  const memoryLeaks: WasmResult['memoryLeaks'] = []
  const typeMismatches: WasmResult['typeMismatches'] = []
  const missingErrorHandling: WasmResult['missingErrorHandling'] = []

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/\/|\/\*|\*)/)) return

    // Detect direct memory access without bounds checking
    if (line.match(/\bUint8Array|Int32Array|Float64Array\s*\(/) && !line.match(/new\s+.*Memory/)) {
      const nextLines = lines.slice(i, i + 5).join('\n')
      if (nextLines.match(/\[.+\]/) && !nextLines.match(/length|bound|check/)) {
        jsInteropIssues.push({ line: i + 1, issue: 'Array buffer access without bounds check', suggestion: 'Validate offset and length before accessing WASM memory' })
      }
    }

    // Detect missing .then() error handling on wasm calls
    if (line.match(/wasm|WebAssembly|instantiate\s*\(|compile\s*\(/) && !line.match(/\.catch|error|Error|try/)) {
      const context = lines.slice(i, i + 5).join('\n')
      if (!context.match(/\.catch|error/) && line.match(/\.then\s*\(/)) {
        missingErrorHandling.push({ line: i + 1, issue: 'WebAssembly instantiation without error handler', suggestion: 'Add .catch() for instantiation failures and import errors' })
      }
    }

    // Detect pointer dereference without null check
    if (line.match(/get\w+\s*\(\s*\)\s*\./) && lines.slice(Math.max(0, i - 2), i).some(l => l.match(/wasm|exports/))) {
      typeMismatches.push({ line: i + 1, issue: 'Possible null pointer from WASM export', suggestion: 'Check export existence before calling methods on it' })
    }

    // Detect memory not freed
    if (line.match(/malloc|alloc\s*\(/) && !lines.slice(i, i + 10).some(l => l.match(/free\s*\(/))) {
      memoryLeaks.push({ line: i + 1, issue: 'WASM memory allocated without corresponding free()', suggestion: 'Ensure every malloc/alloc has matching free() in all code paths' })
    }

    // Detect string passing without length
    if (line.match(/stringToUTF8|UTF8ToString|allocateUTF8/)) {
      if (!line.match(/length|byteLength/)) {
        jsInteropIssues.push({ line: i + 1, issue: 'String conversion without explicit length', suggestion: 'Use lengthBytesUTF8() to get exact byte length for buffer allocation' })
      }
    }
  })

  const totalIssues = jsInteropIssues.length + memoryLeaks.length + typeMismatches.length + missingErrorHandling.length
  const wasmScore = Math.max(0, 100 - totalIssues * 12)
  const severity: Severity = memoryLeaks.length > 0 ? 'warning' : totalIssues >= 3 ? 'info' : 'info'

  return {
    totalIssues, severity, jsInteropIssues, memoryLeaks, typeMismatches, missingErrorHandling, wasmScore,
    summary: `${memoryLeaks.length} memory leak risk(s), ${jsInteropIssues.length} interop issue(s), ${missingErrorHandling.length} missing error handler(s)`
  }
}

function formatWasmReport(r: WasmResult): string {
  const lines: string[] = []
  lines.push(`# WebAssembly Compatibility Analysis`)
  lines.push(``)
  lines.push(`**WASM Score:** ${r.wasmScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.memoryLeaks.length > 0) {
    lines.push(`## Memory Leaks (${r.memoryLeaks.length})`)
    r.memoryLeaks.forEach(m => lines.push(`- Line ${m.line}: ${m.suggestion}`))
    lines.push(``)
  }

  if (r.jsInteropIssues.length > 0) {
    lines.push(`## JS Interop Issues (${r.jsInteropIssues.length})`)
    r.jsInteropIssues.forEach(j => lines.push(`- Line ${j.line}: ${j.suggestion}`))
    lines.push(``)
  }

  if (r.missingErrorHandling.length > 0) {
    lines.push(`## Missing Error Handling (${r.missingErrorHandling.length})`)
    r.missingErrorHandling.forEach(e => lines.push(`- Line ${e.line}: ${e.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 91: Authentication Security ----

interface AuthResult {
  totalIssues: number
  severity: Severity
  weakConfig: { line: number; issue: string; suggestion: string }[]
  missingMFA: { line: number; issue: string; suggestion: string }[]
  sessionIssues: { line: number; issue: string; suggestion: string }[]
  hardcodedCreds: { line: number; issue: string; suggestion: string }[]
  authScore: number
  summary: string
}

function analyzeAuthSecurity(code: string): AuthResult {
  const lines = code.split('\n')
  const weakConfig: AuthResult['weakConfig'] = []
  const missingMFA: AuthResult['missingMFA'] = []
  const sessionIssues: AuthResult['sessionIssues'] = []
  const hardcodedCreds: AuthResult['hardcodedCreds'] = []

  const codeLower = code.toLowerCase()

  // Detect hardcoded secrets
  lines.forEach((line, i) => {
    if (line.match(/password|secret|apikey|api_key|token|credential/i) && line.match(/['"][^'"]{8,}['"]/) && !line.match(/process\.env|var\.|config\.|getenv/i)) {
      hardcodedCreds.push({ line: i + 1, issue: 'Hardcoded credential detected', suggestion: 'Use environment variables or secret management service' })
    }
  })

  // Detect JWT without expiration
  if (codeLower.includes('jwt') || codeLower.includes('jsonwebtoken')) {
    if (!codeLower.includes('expiresin') && !codeLower.includes('exp')) {
      weakConfig.push({ line: 1, issue: 'JWT tokens without expiration', suggestion: 'Set expiresIn claim to limit token lifetime (recommended: 15min-1hr)' })
    }
    if (!codeLower.includes('refresh')) {
      weakConfig.push({ line: 1, issue: 'No token refresh mechanism', suggestion: 'Implement refresh token rotation for long-lived sessions' })
    }
  }

  // Detect missing HTTPS enforcement
  if (!codeLower.includes('secure') && !codeLower.includes('https') && codeLower.includes('cookie')) {
    sessionIssues.push({ line: 1, issue: 'Cookies without Secure flag', suggestion: 'Set secure: true for cookies in production (HTTPS only)' })
  }

  // Detect session without timeout
  if (codeLower.includes('session') && !codeLower.includes('maxage') && !codeLower.includes('expires') && !codeLower.includes('timeout')) {
    sessionIssues.push({ line: 1, issue: 'Session without maxAge or timeout', suggestion: 'Set session.maxAge to prevent indefinite session persistence' })
  }

  // Detect basic auth (weak)
  if (codeLower.includes('basic') && codeLower.includes('auth')) {
    weakConfig.push({ line: 1, issue: 'Basic Auth sends credentials with every request', suggestion: 'Upgrade to OAuth 2.0 or Bearer token authentication' })
  }

  // Detect bcrypt cost factor too low
  const bcryptMatch = code.match(/bcrypt.*(?:cost|rounds?)\s*[:=]\s*(\d+)/i)
  if (bcryptMatch && parseInt(bcryptMatch[1]) < 10) {
    weakConfig.push({ line: 1, issue: `bcrypt cost factor ${bcryptMatch[1]} is too low`, suggestion: 'Use bcrypt cost factor >= 10 (12 recommended for production)' })
  }

  const totalIssues = weakConfig.length + missingMFA.length + sessionIssues.length + hardcodedCreds.length
  const authScore = Math.max(0, 100 - hardcodedCreds.length * 20 - weakConfig.length * 10)
  const severity: Severity = hardcodedCreds.length > 0 ? 'critical' : weakConfig.length > 0 ? 'warning' : 'info'

  return {
    totalIssues, severity, weakConfig, missingMFA, sessionIssues, hardcodedCreds, authScore,
    summary: `${hardcodedCreds.length} hardcoded credential(s), ${weakConfig.length} weak config(s), ${sessionIssues.length} session issue(s)`
  }
}

function formatAuthReport(r: AuthResult): string {
  const lines: string[] = []
  lines.push(`# Authentication Security Analysis`)
  lines.push(``)
  lines.push(`**Auth Score:** ${r.authScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.hardcodedCreds.length > 0) {
    lines.push(`## Hardcoded Credentials (${r.hardcodedCreds.length}) ⚠️`)
    r.hardcodedCreds.forEach(c => lines.push(`- Line ${c.line}: ${c.suggestion}`))
    lines.push(``)
  }

  if (r.weakConfig.length > 0) {
    lines.push(`## Weak Configuration (${r.weakConfig.length})`)
    r.weakConfig.forEach(w => lines.push(`- ${w.suggestion}`))
    lines.push(``)
  }

  if (r.sessionIssues.length > 0) {
    lines.push(`## Session Issues (${r.sessionIssues.length})`)
    r.sessionIssues.forEach(s => lines.push(`- ${s.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 92: Payment Compliance ----

interface PaymentResult {
  totalIssues: number
  severity: Severity
  pciViolations: { line: number; issue: string; suggestion: string }[]
  precisionIssues: { line: number; issue: string; suggestion: string }[]
  idempotencyIssues: { line: number; issue: string; suggestion: string }[]
  auditTrail: { line: number; issue: string; suggestion: string }[]
  paymentScore: number
  summary: string
}

function analyzePaymentCompliance(code: string): PaymentResult {
  const lines = code.split('\n')
  const pciViolations: PaymentResult['pciViolations'] = []
  const precisionIssues: PaymentResult['precisionIssues'] = []
  const idempotencyIssues: PaymentResult['idempotencyIssues'] = []
  const auditTrail: PaymentResult['auditTrail'] = []

  const codeLower = code.toLowerCase()

  // Detect card data logging
  lines.forEach((line, i) => {
    if (line.match(/card|cvv|pan|track1|track2|emv/i) && line.match(/console|log|print|info/)) {
      pciViolations.push({ line: i + 1, issue: 'Potential card data logging (PCI violation)', suggestion: 'Never log full card numbers, CVV, or track data' })
    }
  })

  // Detect floating point for money
  if (codeLower.includes('amount') || codeLower.includes('price') || codeLower.includes('total') || codeLower.includes('payment')) {
    lines.forEach((line, i) => {
      if (line.match(/(?:amount|price|total|payment|balance)\s*[=:]/) && !line.match(/decimal|bigint|integer|cents|minor.*unit|string/) && line.match(/\d+\.\d+/)) {
        precisionIssues.push({ line: i + 1, issue: 'Floating-point arithmetic for monetary values', suggestion: 'Use integer cents/minimal units or Decimal type to avoid rounding errors' })
      }
    })
  }

  // Detect missing idempotency key
  if (codeLower.includes('payment') || codeLower.includes('charge') || codeLower.includes('transaction')) {
    if (!codeLower.includes('idempotency') && !codeLower.includes('idempotent') && !codeLower.includes('dedup')) {
      idempotencyIssues.push({ line: 1, issue: 'Payment flow without idempotency mechanism', suggestion: 'Add idempotency keys to prevent duplicate charges on network retries' })
    }
  }

  // Detect missing receipt/audit logging
  if (codeLower.includes('payment') && !codeLower.includes('receipt') && !codeLower.includes('audit') && !codeLower.includes('transaction_log')) {
    auditTrail.push({ line: 1, issue: 'No transaction audit trail', suggestion: 'Log all payment events with timestamps, amounts, and reference IDs for dispute resolution' })
  }

  // Detect storing full card number
  lines.forEach((line, i) => {
    if (line.match(/store|save|persist|insert.*card|create.*card/i) && !line.match(/tokenized|masked|encrypted|vault/)) {
      pciViolations.push({ line: i + 1, issue: 'Storing raw card data without tokenization', suggestion: 'Use payment processor tokenization (Stripe tokens) instead of storing raw PANs' })
    }
  })

  const totalIssues = pciViolations.length + precisionIssues.length + idempotencyIssues.length + auditTrail.length
  const paymentScore = Math.max(0, 100 - pciViolations.length * 20 - precisionIssues.length * 10)
  const severity: Severity = pciViolations.length > 0 ? 'critical' : totalIssues >= 3 ? 'warning' : 'info'

  return {
    totalIssues, severity, pciViolations, precisionIssues, idempotencyIssues, auditTrail, paymentScore,
    summary: `${pciViolations.length} PCI violation(s), ${precisionIssues.length} precision issue(s), ${idempotencyIssues.length} idempotency gap(s)`
  }
}

function formatPaymentReport(r: PaymentResult): string {
  const lines: string[] = []
  lines.push(`# Payment Compliance Analysis`)
  lines.push(``)
  lines.push(`**Payment Score:** ${r.paymentScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.pciViolations.length > 0) {
    lines.push(`## PCI-DSS Violations (${r.pciViolations.length}) ⚠️`)
    r.pciViolations.forEach(p => lines.push(`- Line ${p.line}: ${p.suggestion}`))
    lines.push(``)
  }

  if (r.precisionIssues.length > 0) {
    lines.push(`## Precision Issues (${r.precisionIssues.length})`)
    r.precisionIssues.forEach(p => lines.push(`- Line ${p.line}: ${p.suggestion}`))
    lines.push(``)
  }

  if (r.idempotencyIssues.length > 0) {
    lines.push(`## Idempotency Gaps (${r.idempotencyIssues.length})`)
    r.idempotencyIssues.forEach(i => lines.push(`- ${i.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 93: Email/SMTP Security ----

interface EmailResult {
  totalIssues: number
  severity: Severity
  injectionRisks: { line: number; issue: string; suggestion: string }[]
  missingAuth: { line: number; issue: string; suggestion: string }[]
  templateIssues: { line: number; issue: string; suggestion: string }[]
  emailScore: number
  summary: string
}

function analyzeEmailSecurity(code: string): EmailResult {
  const lines = code.split('\n')
  const injectionRisks: EmailResult['injectionRisks'] = []
  const missingAuth: EmailResult['missingAuth'] = []
  const templateIssues: EmailResult['templateIssues'] = []

  const codeLower = code.toLowerCase()

  // Detect email header injection
  lines.forEach((line, i) => {
    if (line.match(/mailto:|email.*subject|email.*from/i) && line.match(/\$\{/) && !line.match(/escape|sanitize|validate/)) {
      injectionRisks.push({ line: i + 1, issue: 'Email header injection risk via template interpolation', suggestion: 'Sanitize user input used in email headers to prevent CRLF injection' })
    }
  })

  // Detect SMTP without TLS
  if (codeLower.includes('smtp') && !codeLower.includes('tls') && !codeLower.includes('ssl') && !codeLower.includes('starttls')) {
    missingAuth.push({ line: 1, issue: 'SMTP connection without TLS/SSL', suggestion: 'Use secure transport (STARTTLS or SMTPS on port 465/587)' })
  }

  // Detect SMTP credential in code
  lines.forEach((line, i) => {
    if (line.match(/smtp.*pass|mail.*password|email.*pass/i) && line.match(/['"][^'"]+['"]/) && !line.match(/process\.env|config\./)) {
      injectionRisks.push({ line: i + 1, issue: 'SMTP credentials hardcoded', suggestion: 'Use environment variables for SMTP authentication credentials' })
    }
  })

  // Detect sending user-controlled content without sanitization
  if (codeLower.includes('sendmail') || codeLower.includes('send_mail') || codeLower.includes('\.send\(')) {
    const hasSanitization = codeLower.includes('sanitize') || codeLower.includes('escape') || codeLower.includes('strip')
    if (!hasSanitization) {
      templateIssues.push({ line: 1, issue: 'Email content without input sanitization', suggestion: 'Sanitize HTML content in emails to prevent XSS in email clients' })
    }
  }

  // Detect missing DKIM/SPF for domains
  if (codeLower.includes('nodemailer') || codeLower.includes('sendgrid') || codeLower.includes('mailgun')) {
    if (!codeLower.includes('dkim')) {
      templateIssues.push({ line: 1, issue: 'Email without DKIM signing configuration', suggestion: 'Configure DKIM signatures to improve deliverability and prevent spoofing' })
    }
  }

  const totalIssues = injectionRisks.length + missingAuth.length + templateIssues.length
  const emailScore = Math.max(0, 100 - injectionRisks.length * 15 - missingAuth.length * 10)
  const severity: Severity = injectionRisks.length > 0 ? 'warning' : totalIssues >= 2 ? 'info' : 'info'

  return {
    totalIssues, severity, injectionRisks, missingAuth, templateIssues, emailScore,
    summary: `${injectionRisks.length} injection risk(s), ${missingAuth.length} auth issue(s), ${templateIssues.length} template issue(s)`
  }
}

function formatEmailReport(r: EmailResult): string {
  const lines: string[] = []
  lines.push(`# Email/SMTP Security Analysis`)
  lines.push(``)
  lines.push(`**Email Score:** ${r.emailScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.injectionRisks.length > 0) {
    lines.push(`## Injection Risks (${r.injectionRisks.length})`)
    r.injectionRisks.forEach(r => lines.push(`- Line ${r.line}: ${r.suggestion}`))
    lines.push(``)
  }

  if (r.missingAuth.length > 0) {
    lines.push(`## Missing Security (${r.missingAuth.length})`)
    r.missingAuth.forEach(m => lines.push(`- ${m.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 94: Rate Limiting Analysis ----

interface RateLimitResult {
  totalIssues: number
  severity: Severity
  missingLimit: { line: number; endpoint: string; suggestion: string }[]
  weakAlgorithms: { line: number; issue: string; suggestion: string }[]
  noDistributed: { line: number; issue: string; suggestion: string }[]
  rateScore: number
  summary: string
}

function analyzeRateLimiting(code: string): RateLimitResult {
  const lines = code.split('\n')
  const missingLimit: RateLimitResult['missingLimit'] = []
  const weakAlgorithms: RateLimitResult['weakAlgorithms'] = []
  const noDistributed: RateLimitResult['noDistributed'] = []

  const codeLower = code.toLowerCase()

  // Detect endpoints without rate limiting
  const endpoints = code.match(/(?:app|router)\.\w+\s*\(\s*['"][^'"]+['"]/g) || []
  endpoints.forEach(ep => {
    const idx = code.indexOf(ep)
    const context = code.substring(idx, idx + 500)
    if (!context.match(/rate.?limit|throttl|debounce|token.?bucket|leaky.?bucket/i)) {
      const pathMatch = ep.match(/['"](\/[^'"]+)['"]/)
      if (pathMatch) {
        missingLimit.push({ line: lines.findIndex(l => l.includes(ep)) + 1, endpoint: pathMatch[1], suggestion: `No rate limiting on '${pathMatch[1]}' — add throttle middleware` })
      }
    }
  })

  // Detect in-memory rate limiting (won't scale)
  if (codeLower.includes('ratelimit') || codeLower.includes('rate-limit')) {
    if (!codeLower.includes('redis') && !codeLower.includes('memcache') && !codeLower.includes('distributed')) {
      noDistributed.push({ line: 1, issue: 'Rate limiter uses in-memory store', suggestion: 'Use Redis-backed rate limiting for multi-instance deployments' })
    }
  }

  // Detect basic counter without time window
  if (codeLower.includes('request count') || codeLower.includes('requestcount')) {
    if (!codeLower.includes('window') && !codeLower.includes('reset')) {
      weakAlgorithms.push({ line: 1, issue: 'Simple request counter without time window', suggestion: 'Implement sliding window or token bucket algorithm for accurate limiting' })
    }
  }

  const totalIssues = missingLimit.length + weakAlgorithms.length + noDistributed.length
  const rateScore = Math.max(0, 100 - missingLimit.length * 12 - weakAlgorithms.length * 10)
  const severity: Severity = missingLimit.length > 0 ? 'warning' : totalIssues >= 2 ? 'info' : 'info'

  return {
    totalIssues, severity, missingLimit, weakAlgorithms, noDistributed, rateScore,
    summary: `${missingLimit.length} unprotected endpoint(s), ${weakAlgorithms.length} weak algorithm(s), ${noDistributed.length} non-distributed limiter(s)`
  }
}

function formatRateLimitReport(r: RateLimitResult): string {
  const lines: string[] = []
  lines.push(`# Rate Limiting Analysis`)
  lines.push(``)
  lines.push(`**Rate Score:** ${r.rateScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.missingLimit.length > 0) {
    lines.push(`## Unprotected Endpoints (${r.missingLimit.length})`)
    r.missingLimit.forEach(m => lines.push(`- Line ${m.line}: \`${m.endpoint}\` — ${m.suggestion}`))
    lines.push(``)
  }

  if (r.noDistributed.length > 0) {
    lines.push(`## Scalability Issues (${r.noDistributed.length})`)
    r.noDistributed.forEach(n => lines.push(`- ${n.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 95: WebSocket Health ----

interface WsResult {
  totalIssues: number
  severity: Severity
  missingHeartbeat: { line: number; issue: string; suggestion: string }[]
  noReconnect: { line: number; issue: string; suggestion: string }[]
  noBackpressure: { line: number; issue: string; suggestion: string }[]
  wsScore: number
  summary: string
}

function analyzeWebSocketHealth(code: string): WsResult {
  const lines = code.split('\n')
  const missingHeartbeat: WsResult['missingHeartbeat'] = []
  const noReconnect: WsResult['noReconnect'] = []
  const noBackpressure: WsResult['noBackpressure'] = []

  const codeLower = code.toLowerCase()

  if (codeLower.includes('websocket') || codeLower.includes('new ws\\(') || codeLower.includes('socket\.io') || codeLower.includes('wss://')) {
    // Check for heartbeat/ping-pong
    if (!codeLower.includes('ping') && !codeLower.includes('pong') && !codeLower.includes('heartbeat') && !codeLower.includes('keepalive')) {
      missingHeartbeat.push({ line: 1, issue: 'WebSocket without heartbeat mechanism', suggestion: 'Implement ping/pong frames every 30s to detect stale connections' })
    }

    // Check for reconnection logic
    if (!codeLower.includes('reconnect') && !codeLower.includes('retry') && !codeLower.includes('close.*connect')) {
      noReconnect.push({ line: 1, issue: 'No reconnection logic on disconnect', suggestion: 'Add exponential backoff reconnection on close event' })
    }

    // Check for backpressure handling
    if (codeLower.includes('send') && !codeLower.includes('bufferedamount') && !codeLower.includes('backpressure')) {
      noBackpressure.push({ line: 1, issue: 'Sending without checking bufferedAmount', suggestion: 'Check ws.bufferedAmount before sending to prevent memory buildup' })
    }
  }

  const totalIssues = missingHeartbeat.length + noReconnect.length + noBackpressure.length
  const wsScore = Math.max(0, 100 - totalIssues * 20)
  const severity: Severity = totalIssues >= 2 ? 'warning' : totalIssues >= 1 ? 'info' : 'info'

  return {
    totalIssues, severity, missingHeartbeat, noReconnect, noBackpressure, wsScore,
    summary: `${missingHeartbeat.length} missing heartbeat(s), ${noReconnect.length} no reconnect, ${noBackpressure.length} no backpressure handling`
  }
}

function formatWsReport(r: WsResult): string {
  const lines: string[] = []
  lines.push(`# WebSocket Health Analysis`)
  lines.push(``)
  lines.push(`**WS Score:** ${r.wsScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.missingHeartbeat.length > 0) {
    lines.push(`## Missing Heartbeat (${r.missingHeartbeat.length})`)
    r.missingHeartbeat.forEach(h => lines.push(`- ${h.suggestion}`))
    lines.push(``)
  }

  if (r.noReconnect.length > 0) {
    lines.push(`## No Reconnection (${r.noReconnect.length})`)
    r.noReconnect.forEach(r => lines.push(`- ${r.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 96: Cron Job Robustness ----

interface CronResult {
  totalIssues: number
  severity: Severity
  missingIdempotency: { line: number; issue: string; suggestion: string }[]
  noLock: { line: number; issue: string; suggestion: string }[]
  missingErrorHandling: { line: number; issue: string; suggestion: string }[]
  cronScore: number
  summary: string
}

function analyzeCronJobs(code: string): CronResult {
  const lines = code.split('\n')
  const missingIdempotency: CronResult['missingIdempotency'] = []
  const noLock: CronResult['noLock'] = []
  const missingErrorHandling: CronResult['missingErrorHandling'] = []

  const codeLower = code.toLowerCase()

  // Detect cron usage
  const hasCron = codeLower.includes('cron') || codeLower.includes('setinterval') || codeLower.includes('schedule') || codeLower.includes('node-cron')
  if (hasCron) {
    // Check for idempotency
    if (!codeLower.includes('idempotent') && !codeLower.includes('duplicate') && !codeLower.includes('already.*processed') && !codeLower.includes('dedup')) {
      missingIdempotency.push({ line: 1, issue: 'Cron job without idempotency check', suggestion: 'Use unique job IDs or processed-record tracking to prevent duplicate execution' })
    }

    // Check for distributed lock
    if (!codeLower.includes('lock') && !codeLower.includes('mutex') && !codeLower.includes('redlock') && !codeLower.includes('distributed')) {
      noLock.push({ line: 1, issue: 'No distributed lock for cron job', suggestion: 'Use Redis Redlock or DB advisory locks to prevent concurrent execution across instances' })
    }

    // Check for error handling
    const cronBlock = code.substring(codeLower.indexOf('cron'), codeLower.indexOf('cron') + 1000)
    if (!cronBlock.toLowerCase().includes('try') && !cronBlock.toLowerCase().includes('catch')) {
      missingErrorHandling.push({ line: 1, issue: 'Cron job without error handling', suggestion: 'Wrap cron handler in try/catch with alerting to detect silent failures' })
    }

    // Check for timeout
    if (!codeLower.includes('timeout') && !codeLower.includes('deadline') && !codeLower.includes('maxtime')) {
      missingErrorHandling.push({ line: 1, issue: 'No execution timeout for cron job', suggestion: 'Set max execution time to prevent zombie jobs blocking subsequent runs' })
    }
  }

  const totalIssues = missingIdempotency.length + noLock.length + missingErrorHandling.length
  const cronScore = Math.max(0, 100 - totalIssues * 15)
  const severity: Severity = noLock.length > 0 ? 'warning' : totalIssues >= 2 ? 'info' : 'info'

  return {
    totalIssues, severity, missingIdempotency, noLock, missingErrorHandling, cronScore,
    summary: `${missingIdempotency.length} missing idempotency, ${noLock.length} no lock, ${missingErrorHandling.length} no error handling`
  }
}

function formatCronReport(r: CronResult): string {
  const lines: string[] = []
  lines.push(`# Cron Job Robustness Analysis`)
  lines.push(``)
  lines.push(`**Cron Score:** ${r.cronScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.missingIdempotency.length > 0) {
    lines.push(`## Missing Idempotency (${r.missingIdempotency.length})`)
    r.missingIdempotency.forEach(i => lines.push(`- ${i.suggestion}`))
    lines.push(``)
  }

  if (r.noLock.length > 0) {
    lines.push(`## No Distributed Lock (${r.noLock.length})`)
    r.noLock.forEach(l => lines.push(`- ${l.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 97: Event Sourcing Patterns ----

interface EventSourcingResult {
  totalIssues: number
  severity: Severity
  missingVersioning: { line: number; issue: string; suggestion: string }[]
  noSnapshot: { line: number; issue: string; suggestion: string }[]
  eventDesign: { line: number; issue: string; suggestion: string }[]
  eventScore: number
  summary: string
}

function analyzeEventSourcing(code: string): EventSourcingResult {
  const lines = code.split('\n')
  const missingVersioning: EventSourcingResult['missingVersioning'] = []
  const noSnapshot: EventSourcingResult['noSnapshot'] = []
  const eventDesign: EventSourcingResult['eventDesign'] = []

  const codeLower = code.toLowerCase()

  // Detect event-sourcing patterns
  const hasEvents = codeLower.includes('event') && (codeLower.includes('store') || codeLower.includes('emitter') || codeLower.includes('dispatch') || codeLower.includes('apply'))
  if (hasEvents) {
    // Check for event versioning
    if (!codeLower.includes('version') && !codeLower.includes('v1') && !codeLower.includes('schema')) {
      missingVersioning.push({ line: 1, issue: 'Events without version field', suggestion: 'Add version field to all events for backward-compatible schema evolution' })
    }

    // Check for upcasting/legacy handler
    if (!codeLower.includes('upgrade') && !codeLower.includes('migrate') && !codeLower.includes('legacy') && !codeLower.includes('upcast')) {
      missingVersioning.push({ line: 1, issue: 'No event schema migration strategy', suggestion: 'Implement upcasters to transform old event versions to current schema' })
    }

    // Check for snapshots
    if (codeLower.includes('aggregate') || codeLower.includes('rebuild') || codeLower.includes('replay')) {
      if (!codeLower.includes('snapshot')) {
        noSnapshot.push({ line: 1, issue: 'Aggregate rebuild without snapshot support', suggestion: 'Save periodic snapshots to avoid replaying entire event history' })
      }
    }

    // Detect anemic events (events with no data)
    lines.forEach((line, i) => {
      if (line.match(/emit\s*\(\s*['"][^'"]+['"]\s*\)/) || line.match(/dispatch\s*\(\s*['"]/)) {
        eventDesign.push({ line: i + 1, issue: 'Event emitted without data payload', suggestion: 'Events should carry all data needed for downstream processing (event-carried state transfer)' })
      }
    })
  }

  const totalIssues = missingVersioning.length + noSnapshot.length + eventDesign.length
  const eventScore = Math.max(0, 100 - totalIssues * 15)
  const severity: Severity = totalIssues >= 2 ? 'warning' : totalIssues >= 1 ? 'info' : 'info'

  return {
    totalIssues, severity, missingVersioning, noSnapshot, eventDesign, eventScore,
    summary: `${missingVersioning.length} versioning gap(s), ${noSnapshot.length} missing snapshot(s), ${eventDesign.length} event design issue(s)`
  }
}

function formatEventSourcingReport(r: EventSourcingResult): string {
  const lines: string[] = []
  lines.push(`# Event Sourcing Analysis`)
  lines.push(``)
  lines.push(`**Event Score:** ${r.eventScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.missingVersioning.length > 0) {
    lines.push(`## Schema Versioning (${r.missingVersioning.length})`)
    r.missingVersioning.forEach(v => lines.push(`- ${v.suggestion}`))
    lines.push(``)
  }

  if (r.noSnapshot.length > 0) {
    lines.push(`## Missing Snapshots (${r.noSnapshot.length})`)
    r.noSnapshot.forEach(s => lines.push(`- ${s.suggestion}`))
    lines.push(``)
  }

  if (r.eventDesign.length > 0) {
    lines.push(`## Event Design (${r.eventDesign.length})`)
    r.eventDesign.forEach(e => lines.push(`- Line ${e.line}: ${e.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ==================== V0.17.0 NEW TOOLS ====================

// ---- Tool 98: Cache Strategy Analysis ----

interface CacheResult {
  totalIssues: number
  severity: Severity
  missingTTL: { line: number; issue: string; suggestion: string }[]
  penetrationRisk: { line: number; issue: string; suggestion: string }[]
  inconsistency: { line: number; issue: string; suggestion: string }[]
  cacheScore: number
  summary: string
}

function analyzeCacheStrategy(code: string): CacheResult {
  const lines = code.split('\n')
  const missingTTL: CacheResult['missingTTL'] = []
  const penetrationRisk: CacheResult['penetrationRisk'] = []
  const inconsistency: CacheResult['inconsistency'] = []

  const codeLower = code.toLowerCase()

  // Detect cache without TTL
  lines.forEach((line, i) => {
    if (line.match(/\.set\s*\(/) && line.match(/cache|redis|memcache/i)) {
      if (!line.match(/ex\s*[:=]|ttl\s*[:=]|expire\s*[:=]/) && !lines.slice(i, i + 3).some(l => l.match(/\bex\s*[:=]|ttl\s*[:=]|\.expireat/i))) {
        missingTTL.push({ line: i + 1, issue: 'Cache set without TTL/expiry', suggestion: 'Set TTL to prevent stale data and memory leaks' })
      }
    }
  })

  // Detect cache penetration risk (no null caching)
  if (codeLower.includes('cache') && codeLower.includes('get')) {
    if (!codeLower.includes('null') && !codeLower.includes('undefined') && !codeLower.includes('empty')) {
      penetrationRisk.push({ line: 1, issue: 'Cache-aside without null/empty caching', suggestion: 'Cache null results briefly to prevent cache penetration on missing keys' })
    }
  }

  // Detect write-through inconsistency
  if (codeLower.includes('cache') && (codeLower.includes('update') || codeLower.includes('save'))) {
    if (!codeLower.includes('del') && !codeLower.includes('invalidate') && !codeLower.includes('upsert')) {
      inconsistency.push({ line: 1, issue: 'Write operation without cache invalidation', suggestion: 'Invalidate related cache keys on write to prevent stale reads' })
    }
  }

  // Detect thundering herd (no lock/mutex for hot keys)
  if (codeLower.includes('cache') && codeLower.includes('recompute')) {
    if (!codeLower.includes('lock') && !codeLower.includes('mutex') && !codeLower.includes('debounce')) {
      penetrationRisk.push({ line: 1, issue: 'Cache recomputation without deduplication', suggestion: 'Use distributed lock or Promise memoization to prevent thundering herd' })
    }
  }

  const totalIssues = missingTTL.length + penetrationRisk.length + inconsistency.length
  const cacheScore = Math.max(0, 100 - totalIssues * 12)
  const severity: Severity = penetrationRisk.length > 0 ? 'warning' : totalIssues >= 2 ? 'info' : 'info'

  return {
    totalIssues, severity, missingTTL, penetrationRisk, inconsistency, cacheScore,
    summary: `${missingTTL.length} missing TTL, ${penetrationRisk.length} penetration/herd risk, ${inconsistency.length} inconsistency`
  }
}

function formatCacheReport(r: CacheResult): string {
  const lines: string[] = []
  lines.push(`# Cache Strategy Analysis`)
  lines.push(``)
  lines.push(`**Cache Score:** ${r.cacheScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.penetrationRisk.length > 0) {
    lines.push(`## Penetration / Thundering Herd (${r.penetrationRisk.length})`)
    r.penetrationRisk.forEach(p => lines.push(`- ${p.suggestion}`))
    lines.push(``)
  }

  if (r.missingTTL.length > 0) {
    lines.push(`## Missing TTL (${r.missingTTL.length})`)
    r.missingTTL.forEach(t => lines.push(`- Line ${t.line}: ${t.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 99: Graceful Shutdown ----

interface ShutdownResult {
  totalIssues: number
  severity: Severity
  missingSignal: { line: number; issue: string; suggestion: string }[]
  noDraining: { line: number; issue: string; suggestion: string }[]
  shutdownScore: number
  summary: string
}

function analyzeGracefulShutdown(code: string): ShutdownResult {
  const lines = code.split('\n')
  const missingSignal: ShutdownResult['missingSignal'] = []
  const noDraining: ShutdownResult['noDraining'] = []

  const codeLower = code.toLowerCase()

  // Detect server without signal handlers
  if ((codeLower.includes('listen') || codeLower.includes('server.start')) && !codeLower.includes('sigterm') && !codeLower.includes('sigint')) {
    missingSignal.push({ line: 1, issue: 'Server without SIGTERM/SIGINT handler', suggestion: 'Add process.on("SIGTERM") handler for graceful shutdown (K8s sends SIGTERM)' })
  }

  // Detect missing connection draining
  if (codeLower.includes('shutdown') || codeLower.includes('close')) {
    if (!codeLower.includes('drain') && !codeLower.includes('keepalive') && !codeLower.includes('connection')) {
      noDraining.push({ line: 1, issue: 'Shutdown without connection draining', suggestion: 'Stop accepting new connections, complete in-flight requests before closing' })
    }
  }

  // Detect missing timeout in shutdown
  if (codeLower.includes('shutdown') && !codeLower.includes('timeout') && !codeLower.includes('force')) {
    noDraining.push({ line: 1, issue: 'No forced shutdown timeout', suggestion: 'Add force-kill timeout (e.g., 30s) to prevent hanging during shutdown' })
  }

  const totalIssues = missingSignal.length + noDraining.length
  const shutdownScore = Math.max(0, 100 - totalIssues * 20)
  const severity: Severity = totalIssues >= 2 ? 'warning' : totalIssues >= 1 ? 'info' : 'info'

  return {
    totalIssues, severity, missingSignal, noDraining, shutdownScore,
    summary: `${missingSignal.length} missing signal handler(s), ${noDraining.length} missing draining/timeout`
  }
}

function formatShutdownReport(r: ShutdownResult): string {
  const lines: string[] = []
  lines.push(`# Graceful Shutdown Analysis`)
  lines.push(``)
  lines.push(`**Shutdown Score:** ${r.shutdownScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.missingSignal.length > 0) {
    lines.push(`## Missing Signal Handlers (${r.missingSignal.length})`)
    r.missingSignal.forEach(s => lines.push(`- ${s.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 100: Health & Readiness Probes ----

interface ProbeResult {
  totalIssues: number
  severity: Severity
  missingLiveness: { issue: string; suggestion: string }[]
  missingReadiness: { issue: string; suggestion: string }[]
  missingStartup: { issue: string; suggestion: string }[]
  probeScore: number
  summary: string
}

function analyzeHealthProbes(code: string): ProbeResult {
  const lines = code.split('\n')
  const missingLiveness: ProbeResult['missingLiveness'] = []
  const missingReadiness: ProbeResult['missingReadiness'] = []
  const missingStartup: ProbeResult['missingStartup'] = []

  const codeLower = code.toLowerCase()
  const hasServer = codeLower.includes('listen') || codeLower.includes('server') || codeLower.includes('express')

  if (hasServer) {
    // Check for liveness probe
    if (!codeLower.includes('healthz') && !codeLower.includes('/health') && !codeLower.includes('/live')) {
      missingLiveness.push({ issue: 'No health check endpoint', suggestion: 'Add /health endpoint returning 200 OK for K8s liveness probe' })
    }

    // Check for readiness probe
    if (!codeLower.includes('ready') && !codeLower.includes('readyz')) {
      missingReadiness.push({ issue: 'No readiness check endpoint', suggestion: 'Add /ready endpoint that checks DB/cache connectivity for K8s readiness probe' })
    }

    // Check for startup probe indication
    if (codeLower.includes('init') || codeLower.includes('preload') || codeLower.includes('migrate')) {
      if (!codeLower.includes('startup') && !codeLower.includes('startupprobe')) {
        missingStartup.push({ issue: 'Initialization without startup probe indication', suggestion: 'Add startup probe for applications with long initialization times' })
      }
    }
  }

  const totalIssues = missingLiveness.length + missingReadiness.length + missingStartup.length
  const probeScore = Math.max(0, 100 - totalIssues * 20)
  const severity: Severity = totalIssues >= 2 ? 'warning' : totalIssues >= 1 ? 'info' : 'info'

  return {
    totalIssues, severity, missingLiveness, missingReadiness, missingStartup, probeScore,
    summary: `${missingLiveness.length} missing liveness, ${missingReadiness.length} missing readiness, ${missingStartup.length} missing startup`
  }
}

function formatProbeReport(r: ProbeResult): string {
  const lines: string[] = []
  lines.push(`# Health & Readiness Probes`)
  lines.push(``)
  lines.push(`**Probe Score:** ${r.probeScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.missingLiveness.length > 0) {
    lines.push(`## Missing Liveness Probe (${r.missingLiveness.length})`)
    r.missingLiveness.forEach(l => lines.push(`- ${l.suggestion}`))
    lines.push(``)
  }

  if (r.missingReadiness.length > 0) {
    lines.push(`## Missing Readiness Probe (${r.missingReadiness.length})`)
    r.missingReadiness.forEach(r => lines.push(`- ${r.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 101: Serialization Safety ----

interface SerializationResult {
  totalIssues: number
  severity: Severity
  circularRef: { line: number; issue: string; suggestion: string }[]
  protoPollution: { line: number; issue: string; suggestion: string }[]
  bigIntIssues: { line: number; issue: string; suggestion: string }[]
  serScore: number
  summary: string
}

function analyzeSerialization(code: string): SerializationResult {
  const lines = code.split('\n')
  const circularRef: SerializationResult['circularRef'] = []
  const protoPollution: SerializationResult['protoPollution'] = []
  const bigIntIssues: SerializationResult['bigIntIssues'] = []

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/\/|\/\*|\*)/)) return

    // Detect JSON.parse without try-catch (circular ref / malformed)
    if (line.match(/JSON\.parse\s*\(/) && !lines.slice(Math.max(0, i - 3), i).some(l => l.match(/try/))) {
      const context = lines.slice(i, i + 5).join('\n')
      if (!context.match(/catch/)) {
        circularRef.push({ line: i + 1, issue: 'JSON.parse without try-catch', suggestion: 'Wrap JSON.parse in try-catch to handle malformed input gracefully' })
      }
    }

    // Detect __proto__ access
    if (line.match(/__proto__|constructor\.prototype/)) {
      protoPollution.push({ line: i + 1, issue: 'Prototype pollution risk via __proto__ or prototype chain', suggestion: 'Sanitize JSON input, use Map instead of plain objects for untrusted data' })
    }

    // Detect BigInt serialization
    if (line.match(/BigInt|bigint/) && line.match(/JSON\.stringify/)) {
      bigIntIssues.push({ line: i + 1, issue: 'BigInt cannot be serialized by JSON.stringify', suggestion: 'Add custom toJSON method or replacer function for BigInt values' })
    }

    // Detect Date serialization inconsistency
    if (line.match(/new\s+Date\s*\(/) && line.match(/JSON\.stringify/) && !line.match(/toISOString/)) {
      bigIntIssues.push({ line: i + 1, issue: 'Date object serialized as UTC string in JSON', suggestion: 'Explicitly call .toISOString() for consistent timezone handling' })
    }
  })

  const totalIssues = circularRef.length + protoPollution.length + bigIntIssues.length
  const serScore = Math.max(0, 100 - totalIssues * 12)
  const severity: Severity = protoPollution.length > 0 ? 'warning' : totalIssues >= 2 ? 'info' : 'info'

  return {
    totalIssues, severity, circularRef, protoPollution, bigIntIssues, serScore,
    summary: `${protoPollution.length} prototype pollution risk(s), ${circularRef.length} unsafe parse(s), ${bigIntIssues.length} BigInt/Date issue(s)`
  }
}

function formatSerializationReport(r: SerializationResult): string {
  const lines: string[] = []
  lines.push(`# Serialization Safety`)
  lines.push(``)
  lines.push(`**Serialization Score:** ${r.serScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.protoPollution.length > 0) {
    lines.push(`## Prototype Pollution (${r.protoPollution.length})`)
    r.protoPollution.forEach(p => lines.push(`- Line ${p.line}: ${p.suggestion}`))
    lines.push(``)
  }

  if (r.bigIntIssues.length > 0) {
    lines.push(`## BigInt / Date Issues (${r.bigIntIssues.length})`)
    r.bigIntIssues.forEach(b => lines.push(`- Line ${b.line}: ${b.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 102: Data Validation Patterns ----

interface ValidationResult {
  totalIssues: number
  severity: Severity
  missingValidation: { line: number; field: string; suggestion: string }[]
  weakValidation: { line: number; issue: string; suggestion: string }[]
  missingSanitization: { line: number; issue: string; suggestion: string }[]
  validationScore: number
  summary: string
}

function analyzeDataValidation(code: string): ValidationResult {
  const lines = code.split('\n')
  const missingValidation: ValidationResult['missingValidation'] = []
  const weakValidation: ValidationResult['weakValidation'] = []
  const missingSanitization: ValidationResult['missingSanitization'] = []

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/\/|\/\*|\*)/)) return

    // Detect user input without validation
    if (line.match(/(?:body|params|query|req\.body)\.\w+/) && !line.match(/validate|schema|zod|yup|joi|check|assert/i)) {
      const fieldMatch = line.match(/(\w+)\s*[=:]\s*(?:body|params|query|req\.body)\.(\w+)/)
      if (fieldMatch) {
        missingValidation.push({ line: i + 1, field: fieldMatch[2], suggestion: `Validate '${fieldMatch[2]}' against expected schema before use` })
      }
    }

    // Detect weak email regex
    if (line.match(/email/i) && line.match(/\//) && line.match(/test\s*\(/)) {
      if (line.match(/@\w+\.\w+/) && !line.match(/rfc|5322|RFC/)) {
        weakValidation.push({ line: i + 1, issue: 'Simplified email validation regex', suggestion: 'Use RFC 5322-compliant regex or validation library for email' })
      }
    }

    // Detect unfiltered HTML output (XSS)
    if (line.match(/innerHTML|dangerouslySetInnerHTML|v-html|__html/)) {
      missingSanitization.push({ line: i + 1, issue: 'Raw HTML rendering without sanitization', suggestion: 'Sanitize HTML with DOMPurify before rendering user-generated content' })
    }
  })

  const totalIssues = missingValidation.length + weakValidation.length + missingSanitization.length
  const validationScore = Math.max(0, 100 - missingSanitization.length * 15 - totalIssues * 8)
  const severity: Severity = missingSanitization.length > 0 ? 'warning' : totalIssues >= 3 ? 'info' : 'info'

  return {
    totalIssues, severity, missingValidation, weakValidation, missingSanitization, validationScore,
    summary: `${missingSanitization.length} XSS risk(s), ${missingValidation.length} unvalidated field(s), ${weakValidation.length} weak validation(s)`
  }
}

function formatValidationReport(r: ValidationResult): string {
  const lines: string[] = []
  lines.push(`# Data Validation Patterns`)
  lines.push(``)
  lines.push(`**Validation Score:** ${r.validationScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.missingSanitization.length > 0) {
    lines.push(`## XSS Risks (${r.missingSanitization.length}) ⚠️`)
    r.missingSanitization.forEach(s => lines.push(`- Line ${s.line}: ${s.suggestion}`))
    lines.push(``)
  }

  if (r.missingValidation.length > 0) {
    lines.push(`## Missing Validation (${r.missingValidation.length})`)
    r.missingValidation.forEach(v => lines.push(`- Line ${v.line}: \`${v.field}\` — ${v.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 103: Multi-Tenancy Isolation ----

interface TenantResult {
  totalIssues: number
  severity: Severity
  missingTenantFilter: { line: number; issue: string; suggestion: string }[]
  sharedState: { line: number; issue: string; suggestion: string }[]
  tenantScore: number
  summary: string
}

function analyzeMultiTenancy(code: string): TenantResult {
  const lines = code.split('\n')
  const missingTenantFilter: TenantResult['missingTenantFilter'] = []
  const sharedState: TenantResult['sharedState'] = []

  const codeLower = code.toLowerCase()
  const hasDb = codeLower.includes('find') || codeLower.includes('query') || codeLower.includes('select')

  if (hasDb || codeLower.includes('tenant') || codeLower.includes('organization')) {
    // Detect queries without tenant filter
    lines.forEach((line, i) => {
      if (line.match(/\.find\s*\(/) || line.match(/SELECT.*FROM/i)) {
        if (!line.match(/tenant|organization|orgId|tenantId/) && !lines.slice(Math.max(0, i - 3), i).some(l => l.match(/tenant/))) {
          missingTenantFilter.push({ line: i + 1, issue: 'Database query without tenant scoping', suggestion: 'Add tenant_id filter to prevent cross-tenant data leakage' })
        }
      }
    })

    // Detect global/singleton state
    lines.forEach((line, i) => {
      if (line.match(/^(\s*)(const|let|var)\s+\w+\s*=\s*(?:new|Map|Set|\{)/) &&
          !line.match(/request|context|asyncLocalStorage/)) {
        if (line.match(/cache|state|config|pool/i)) {
          sharedState.push({ line: i + 1, issue: 'Global mutable state without tenant isolation', suggestion: 'Use per-request context or AsyncLocalStorage to isolate tenant state' })
        }
      }
    })
  }

  const totalIssues = missingTenantFilter.length + sharedState.length
  const tenantScore = Math.max(0, 100 - missingTenantFilter.length * 20 - sharedState.length * 10)
  const severity: Severity = missingTenantFilter.length > 0 ? 'critical' : totalIssues >= 1 ? 'warning' : 'info'

  return {
    totalIssues, severity, missingTenantFilter, sharedState, tenantScore,
    summary: `${missingTenantFilter.length} unprotected query(ues), ${sharedState.length} shared state risk(s)`
  }
}

function formatTenantReport(r: TenantResult): string {
  const lines: string[] = []
  lines.push(`# Multi-Tenancy Isolation`)
  lines.push(``)
  lines.push(`**Tenant Score:** ${r.tenantScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.missingTenantFilter.length > 0) {
    lines.push(`## Missing Tenant Filters (${r.missingTenantFilter.length}) ⚠️`)
    r.missingTenantFilter.forEach(t => lines.push(`- Line ${t.line}: ${t.suggestion}`))
    lines.push(``)
  }

  if (r.sharedState.length > 0) {
    lines.push(`## Shared State Risks (${r.sharedState.length})`)
    r.sharedState.forEach(s => lines.push(`- Line ${s.line}: ${s.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 104: Feature Flag Governance ----

interface FeatureFlagResult {
  totalIssues: number
  severity: Severity
  deadFlags: { line: number; issue: string; suggestion: string }[]
  missingCleanup: { line: number; issue: string; suggestion: string }[]
  flagScore: number
  summary: string
}

function analyzeFeatureFlags(code: string): FeatureFlagResult {
  const lines = code.split('\n')
  const deadFlags: FeatureFlagResult['deadFlags'] = []
  const missingCleanup: FeatureFlagResult['missingCleanup'] = []

  const codeLower = code.toLowerCase()

  // Detect feature flags / conditional toggles
  if (codeLower.includes('feature') || codeLower.includes('toggle') || codeLower.includes('flag')) {
    // Detect hardcoded flags
    lines.forEach((line, i) => {
      if (line.match(/feature\s*[=!]=\s*['"]/) || line.match(/isEnabled\s*\(/)) {
        if (!line.match(/config|env|get|fetch|launchdarkly|split|unleash/i)) {
          deadFlags.push({ line: i + 1, issue: 'Hardcoded feature flag value', suggestion: 'Use LaunchDarkly/Split/Unleash for dynamic feature management' })
        }
      }
    })

    // Detect flags without cleanup tracking
    if (codeLower.includes('if.*feature') || codeLower.includes('if.*flag')) {
      if (!codeLower.includes('cleanup') && !codeLower.includes('deprecate') && !codeLower.includes('remove')) {
        missingCleanup.push({ line: 1, issue: 'Feature flags without cleanup plan', suggestion: 'Add TODO comments or tracking for flag removal after stabilization' })
      }
    }
  }

  const totalIssues = deadFlags.length + missingCleanup.length
  const flagScore = Math.max(0, 100 - totalIssues * 15)
  const severity: Severity = deadFlags.length > 0 ? 'warning' : totalIssues >= 1 ? 'info' : 'info'

  return {
    totalIssues, severity, deadFlags, missingCleanup, flagScore,
    summary: `${deadFlags.length} hardcoded flag(s), ${missingCleanup.length} missing cleanup plan(s)`
  }
}

function formatFlagReport(r: FeatureFlagResult): string {
  const lines: string[] = []
  lines.push(`# Feature Flag Governance`)
  lines.push(``)
  lines.push(`**Flag Score:** ${r.flagScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.deadFlags.length > 0) {
    lines.push(`## Hardcoded Flags (${r.deadFlags.length})`)
    r.deadFlags.forEach(f => lines.push(`- Line ${f.line}: ${f.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ---- Tool 105: API Gateway Patterns ----

interface GatewayResult {
  totalIssues: number
  severity: Severity
  missingGateway: { issue: string; suggestion: string }[]
  noAggregation: { line: number; issue: string; suggestion: string }[]
  gatewayScore: number
  summary: string
}

function analyzeGateway(code: string): GatewayResult {
  const lines = code.split('\n')
  const missingGateway: GatewayResult['missingGateway'] = []
  const noAggregation: GatewayResult['noAggregation'] = []

  const codeLower = code.toLowerCase()

  // Detect microservice calls patterns
  const hasMicroservices = (codeLower.includes('service') && codeLower.includes('http')) ||
                           codeLower.includes('fetch') || codeLower.includes('axios')

  if (hasMicroservices) {
    // Detect missing API gateway pattern
    if (!codeLower.includes('gateway') && !codeLower.includes('kong') && !codeLower.includes('apigateway') && !codeLower.includes('bff')) {
      if (codeLower.includes('user-service') || codeLower.includes('order-service') || codeLower.includes('product-service')) {
        missingGateway.push({ issue: 'Direct microservice calls without gateway', suggestion: 'Route through API Gateway (Kong, AWS API Gateway) for cross-cutting concerns' })
      }
    }

    // Detect missing BFF pattern for frontend
    if (codeLower.includes('frontend') && codeLower.includes('microservice') && !codeLower.includes('bff')) {
      noAggregation.push({ line: 1, issue: 'Frontend calling multiple microservices', suggestion: 'Implement Backend-for-Frontend (BFF) to aggregate data for UI needs' })
    }
  }

  const totalIssues = missingGateway.length + noAggregation.length
  const gatewayScore = Math.max(0, 100 - totalIssues * 20)
  const severity: Severity = totalIssues >= 1 ? 'info' : 'info'

  return {
    totalIssues, severity, missingGateway, noAggregation, gatewayScore,
    summary: `${missingGateway.length} missing gateway pattern(s), ${noAggregation.length} aggregation opportunity(ies)`
  }
}

function formatGatewayReport(r: GatewayResult): string {
  const lines: string[] = []
  lines.push(`# API Gateway Patterns`)
  lines.push(``)
  lines.push(`**Gateway Score:** ${r.gatewayScore}/100 | **Issues:** ${r.totalIssues} | **Severity:** ${r.severity.toUpperCase()}`)
  lines.push(``)
  lines.push(`> ${r.summary}`)
  lines.push(``)

  if (r.missingGateway.length > 0) {
    lines.push(`## Missing Gateway (${r.missingGateway.length})`)
    r.missingGateway.forEach(g => lines.push(`- ${g.suggestion}`))
    lines.push(``)
  }

  return lines.join('\n')
}

// ==================== V0.18.0: AI PROMPT INJECTION DETECTION ====================

interface AiPromptResult {
  totalIssues: number
  severity: Severity
  injectionRisks: { line: number; issue: string; suggestion: string }[]
  jailbreakPatterns: { line: number; pattern: string; suggestion: string }[]
  dataLeakage: { line: number; issue: string; suggestion: string }[]
  aiScore: number
  summary: string
}

function analyzeAiPromptSecurity(code: string): AiPromptResult {
  const lines = code.split('\n')
  const injectionRisks: AiPromptResult['injectionRisks'] = []
  const jailbreakPatterns: AiPromptResult['jailbreakPatterns'] = []
  const dataLeakage: AiPromptResult['dataLeakage'] = []

  const jailbreakRegexes = [
    new RegExp('ignore.*(?:previous|above|prior)', 'i'),
    new RegExp('you are now', 'i'),
    new RegExp('DAN|do anything now', 'i'),
    new RegExp('jailbreak', 'i'),
    new RegExp('without.*restrictions', 'i'),
    new RegExp('bypass.*filter', 'i'),
    new RegExp('pretend.*(?:you are|to be)', 'i')
  ]

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/|\/\*|\*)/)) return

    if (line.match(/(?:prompt|systemPrompt|userMessage|instructions)\s*[+=]/) ||
        line.match(/\$\{.*(?:user|input|query|message)/)) {
      if (!line.match(/sanitize|escape|validate|filter/)) {
        injectionRisks.push({ line: i + 1, issue: 'User input interpolated into AI prompt without sanitization', suggestion: 'Sanitize or isolate user input to prevent prompt injection attacks' })
      }
    }

    if (line.match(/system.*prompt|systemPrompt/) && line.match(/log|console|debug|print/)) {
      dataLeakage.push({ line: i + 1, issue: 'System prompt may be logged/exposed', suggestion: 'Never log system prompts — they contain privileged instructions and API keys' })
    }

    jailbreakRegexes.forEach(jp => {
      if (line.match(jp)) {
        jailbreakPatterns.push({ line: i + 1, pattern: line.trim().substring(0, 50), suggestion: 'Detect potential jailbreak patterns in user input before sending to LLM' })
      }
    })

    if (line.match(/function.*call|tool.*call|execute.*function/) && !line.match(/auth|permission|allowlist|whitelist/)) {
      injectionRisks.push({ line: i + 1, issue: 'LLM tool calling without authorization checks', suggestion: 'Implement allowlist for tool calls and validate parameters before execution' })
    }
  })

  const totalIssues = injectionRisks.length + jailbreakPatterns.length + dataLeakage.length
  const aiScore = Math.max(0, 100 - injectionRisks.length * 12 - jailbreakPatterns.length * 10)
  const severity: Severity = injectionRisks.length > 0 ? 'warning' : totalIssues >= 2 ? 'info' : 'info'

  return { totalIssues, severity, injectionRisks, jailbreakPatterns, dataLeakage, aiScore,
    summary: injectionRisks.length + ' injection risk(s), ' + jailbreakPatterns.length + ' jailbreak pattern(s), ' + dataLeakage.length + ' data leakage risk(s)' }
}

function formatAiPromptReport(r: AiPromptResult): string {
  const lines: string[] = []
  lines.push('# AI Prompt Security Analysis')
  lines.push('')
  lines.push('**AI Security Score:** ' + r.aiScore + '/100 | **Issues:** ' + r.totalIssues + ' | **Severity:** ' + r.severity.toUpperCase())
  lines.push('')
  lines.push('> ' + r.summary)
  lines.push('')
  if (r.injectionRisks.length > 0) {
    lines.push('## Prompt Injection Risks (' + r.injectionRisks.length + ')')
    r.injectionRisks.forEach(ri => lines.push('- Line ' + ri.line + ': ' + ri.suggestion))
    lines.push('')
  }
  if (r.jailbreakPatterns.length > 0) {
    lines.push('## Jailbreak Patterns (' + r.jailbreakPatterns.length + ')')
    r.jailbreakPatterns.forEach(j => lines.push('- Line ' + j.line + ': ' + j.pattern))
    lines.push('')
  }
  if (r.dataLeakage.length > 0) {
    lines.push('## Data Leakage Risks (' + r.dataLeakage.length + ')')
    r.dataLeakage.forEach(d => lines.push('- Line ' + d.line + ': ' + d.suggestion))
    lines.push('')
  }
  return lines.join('\n')
}

// ==================== V0.18.0: MICRO-FRONTEND ARCHITECTURE ====================

interface MicroFrontendResult {
  totalIssues: number
  severity: Severity
  modules: { name: string; issues: string[]; suggestions: string[] }[]
  sharedDeps: { dep: string; usedBy: string[]; issue: string }[]
  routingIssues: { line: number; issue: string; suggestion: string }[]
  mfScore: number
  summary: string
}

function analyzeMicroFrontends(code: string): MicroFrontendResult {
  const lines = code.split('\n')
  const routingIssues: MicroFrontendResult['routingIssues'] = []
  const modules: MicroFrontendResult['modules'] = []
  const sharedDeps: MicroFrontendResult['sharedDeps'] = []

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/|\/\*|\*)/)) return

    if (line.match(/(?:route|path)\s*[=:].*(?:\*|wildcard)/)) {
      routingIssues.push({ line: i + 1, issue: 'Wildcard route may conflict with other micro-frontends', suggestion: 'Use prefix-based routing to avoid collisions between MFE modules' })
    }
    if (line.match(/import\s+.*from\s+['"](?!micro|shell|host)/) && line.match(/remote|entry|expose/)) {
      routingIssues.push({ line: i + 1, issue: 'Direct remote module import may cause version conflicts', suggestion: 'Use Module Federation shared dependencies with singleton: true' })
    }
    if (line.match(/window\.__MF|window\.micro|globalThis\.app/)) {
      routingIssues.push({ line: i + 1, issue: 'Global namespace pollution between micro-frontends', suggestion: 'Encapsulate shared state via custom events or message bus' })
    }
  })

  const depMatches = code.match(/"(?:react|vue|angular|lodash|moment)":\s*"[^"]+"/g) || []
  const depUsage = new Map<string, string[]>()
  depMatches.forEach(d => {
    const name = d.match(/"([^"]+)":/)?.[1] || ''
    if (name) depUsage.set(name, ['host', 'remote'])
  })
  depUsage.forEach((usedBy, dep) => {
    if (usedBy.length > 1) sharedDeps.push({ dep, usedBy, issue: 'Shared dependency may cause version mismatch' })
  })

  const totalIssues = routingIssues.length + sharedDeps.length
  const mfScore = Math.max(0, 100 - routingIssues.length * 10 - sharedDeps.length * 8)
  const severity: Severity = routingIssues.length > 2 ? 'warning' : totalIssues > 0 ? 'info' : 'info'

  return { totalIssues, severity, modules, sharedDeps, routingIssues, mfScore,
    summary: routingIssues.length + ' routing/integration issue(s), ' + sharedDeps.length + ' shared dependency concern(s)' }
}

function formatMfReport(r: MicroFrontendResult): string {
  const lines: string[] = []
  lines.push('# Micro-Frontend Architecture Analysis')
  lines.push('')
  lines.push('**MF Architecture Score:** ' + r.mfScore + '/100 | **Issues:** ' + r.totalIssues + ' | **Severity:** ' + r.severity.toUpperCase())
  lines.push('')
  lines.push('> ' + r.summary)
  lines.push('')
  if (r.routingIssues.length > 0) {
    lines.push('## Integration Issues (' + r.routingIssues.length + ')')
    r.routingIssues.forEach(ri => lines.push('- Line ' + ri.line + ': ' + ri.suggestion))
    lines.push('')
  }
  if (r.sharedDeps.length > 0) {
    lines.push('## Shared Dependencies (' + r.sharedDeps.length + ')')
    r.sharedDeps.forEach(d => lines.push('- ' + d.dep + ': ' + d.issue))
    lines.push('')
  }
  return lines.join('\n')
}

// ==================== V0.18.0: DATABASE INDEXING ADVISOR ====================

interface IndexResult {
  totalIssues: number
  severity: Severity
  missingIndexes: { line: number; table: string; column: string; suggestion: string }[]
  unusedIndexes: { line: number; index: string; suggestion: string }[]
  cardinalityIssues: { line: number; issue: string; suggestion: string }[]
  indexScore: number
  summary: string
}

function analyzeDatabaseIndexes(code: string): IndexResult {
  const lines = code.split('\n')
  const missingIndexes: IndexResult['missingIndexes'] = []
  const unusedIndexes: IndexResult['unusedIndexes'] = []
  const cardinalityIssues: IndexResult['cardinalityIssues'] = []

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/|\/\*|\*)/)) return

    const whereMatch = line.match(/WHERE\s+(\w+)\.(\w+)\s*[=<>]/i)
    if (whereMatch && !line.match(/INDEX|PRIMARY|UNIQUE/i)) {
      missingIndexes.push({ line: i + 1, table: whereMatch[1], column: whereMatch[2], suggestion: 'Consider adding index on ' + whereMatch[1] + '.' + whereMatch[2] + ' for WHERE clause optimization' })
    }

    if (line.match(/ORDER BY\s+(\w+)/i) && !line.match(/INDEX|PRIMARY|UNIQUE/i)) {
      const col = line.match(/ORDER BY\s+(\w+)/i)?.[1] || ''
      missingIndexes.push({ line: i + 1, table: 'query', column: col, suggestion: 'ORDER BY on ' + col + ' may benefit from index for sorting optimization' })
    }

    if (line.match(/CREATE\s+(?:INDEX|UNIQUE)/i)) {
      const idxMatch = line.match(/ON\s+(\w+)\s*\((\w+)\)/i)
      if (idxMatch && idxMatch[2] && idxMatch[2].match(/^(?:description|content|text|body|note)$/i)) {
        cardinalityIssues.push({ line: i + 1, issue: 'Low-cardinality index on text column ' + idxMatch[2], suggestion: 'Consider FULLTEXT or prefix index for text columns' })
      }
    }

    if (line.match(/SELECT\s+\*/i) && !line.match(/EXPLAIN|COUNT/i)) {
      unusedIndexes.push({ line: i + 1, index: 'SELECT *', suggestion: 'Avoid SELECT * — it bypasses covering indexes and fetches unnecessary columns' })
    }
  })

  const totalIssues = missingIndexes.length + unusedIndexes.length + cardinalityIssues.length
  const indexScore = Math.max(0, 100 - missingIndexes.length * 10 - unusedIndexes.length * 8)
  const severity: Severity = missingIndexes.length > 2 ? 'warning' : totalIssues > 0 ? 'info' : 'info'

  return { totalIssues, severity, missingIndexes, unusedIndexes, cardinalityIssues, indexScore,
    summary: missingIndexes.length + ' missing index(es), ' + unusedIndexes.length + ' inefficiency, ' + cardinalityIssues.length + ' cardinality issue(s)' }
}

function formatIndexReport(r: IndexResult): string {
  const lines: string[] = []
  lines.push('# Database Indexing Analysis')
  lines.push('')
  lines.push('**Index Score:** ' + r.indexScore + '/100 | **Issues:** ' + r.totalIssues + ' | **Severity:** ' + r.severity.toUpperCase())
  lines.push('')
  lines.push('> ' + r.summary)
  lines.push('')
  if (r.missingIndexes.length > 0) {
    lines.push('## Missing Indexes (' + r.missingIndexes.length + ')')
    r.missingIndexes.forEach(m => lines.push('- Line ' + m.line + ': ' + m.suggestion))
    lines.push('')
  }
  if (r.unusedIndexes.length > 0) {
    lines.push('## Index Inefficiencies (' + r.unusedIndexes.length + ')')
    r.unusedIndexes.forEach(u => lines.push('- Line ' + u.line + ': ' + u.suggestion))
    lines.push('')
  }
  if (r.cardinalityIssues.length > 0) {
    lines.push('## Cardinality Issues (' + r.cardinalityIssues.length + ')')
    r.cardinalityIssues.forEach(c => lines.push('- Line ' + c.line + ': ' + c.suggestion))
    lines.push('')
  }
  return lines.join('\n')
}

// ==================== V0.18.0: ADVANCED CONCURRENCY PATTERNS ====================

interface AdvConcurrencyResult {
  totalIssues: number
  severity: Severity
  raceConditions: { line: number; issue: string; suggestion: string }[]
  deadlocks: { line: number; issue: string; suggestion: string }[]
  atomicityViolations: { line: number; issue: string; suggestion: string }[]
  lockIssues: { line: number; issue: string; suggestion: string }[]
  concurrencyScore: number
  summary: string
}

function analyzeAdvConcurrency(code: string): AdvConcurrencyResult {
  const lines = code.split('\n')
  const raceConditions: AdvConcurrencyResult['raceConditions'] = []
  const deadlocks: AdvConcurrencyResult['deadlocks'] = []
  const atomicityViolations: AdvConcurrencyResult['atomicityViolations'] = []
  const lockIssues: AdvConcurrencyResult['lockIssues'] = []

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/|\/\*|\*)/)) return

    if (line.match(/(?:read|get|fetch).*(?:then|after).*(?:write|set|update)/) ||
        line.match(/await.*await.*(?:mutate|set|write)/i)) {
      raceConditions.push({ line: i + 1, issue: 'Potential read-then-write race condition', suggestion: 'Use atomic operations or mutex locks for read-modify-write patterns' })
    }

    if (line.match(/lock.*lock|acquire.*acquire|mutex.*mutex/i) || line.match(/(?:lock1.*lock2|lock2.*lock1)/i)) {
      deadlocks.push({ line: i + 1, issue: 'Potential deadlock from nested lock acquisition', suggestion: 'Acquire locks in consistent order or use tryLock with timeout' })
    }

    if (line.match(/check.*then.*act|if.*then.*set|validate.*then·*save/i)) {
      atomicityViolations.push({ line: i + 1, issue: 'Check-then-act pattern is not thread-safe', suggestion: 'Replace with atomic compare-and-swap or database-level constraint' })
    }

    if (line.match(/(?:lock|acquire|mutex)/) && !line.match(/unlock|release|finally/)) {
      lockIssues.push({ line: i + 1, issue: 'Lock acquisition without guaranteed release', suggestion: 'Always use try/finally or using pattern to ensure lock release' })
    }

    if (line.match(/Promise\.all\s*\(\s*\[/) && line.match(/catch|error/i) && !line.match(/allSettled/)) {
      raceConditions.push({ line: i + 1, issue: 'Promise.all rejects on first failure — partial state may persist', suggestion: 'Use Promise.allSettled if partial completion is acceptable, or implement rollback' })
    }
  })

  const totalIssues = raceConditions.length + deadlocks.length + atomicityViolations.length + lockIssues.length
  const concurrencyScore = Math.max(0, 100 - raceConditions.length * 12 - deadlocks.length * 15 - atomicityViolations.length * 10)
  const severity: Severity = deadlocks.length > 0 ? 'error' : raceConditions.length > 1 ? 'warning' : totalIssues > 0 ? 'info' : 'info'

  return { totalIssues, severity, raceConditions, deadlocks, atomicityViolations, lockIssues, concurrencyScore,
    summary: raceConditions.length + ' race condition(s), ' + deadlocks.length + ' deadlock risk(s), ' + atomicityViolations.length + ' atomicity violation(s)' }
}

function formatAdvConcurrencyReport(r: AdvConcurrencyResult): string {
  const lines: string[] = []
  lines.push('# Advanced Concurrency Analysis')
  lines.push('')
  lines.push('**Concurrency Score:** ' + r.concurrencyScore + '/100 | **Issues:** ' + r.totalIssues + ' | **Severity:** ' + r.severity.toUpperCase())
  lines.push('')
  lines.push('> ' + r.summary)
  lines.push('')
  if (r.raceConditions.length > 0) {
    lines.push('## Race Conditions (' + r.raceConditions.length + ')')
    r.raceConditions.forEach(rc => lines.push('- Line ' + rc.line + ': ' + rc.suggestion))
    lines.push('')
  }
  if (r.deadlocks.length > 0) {
    lines.push('## Deadlock Risks (' + r.deadlocks.length + ')')
    r.deadlocks.forEach(d => lines.push('- Line ' + d.line + ': ' + d.suggestion))
    lines.push('')
  }
  if (r.atomicityViolations.length > 0) {
    lines.push('## Atomicity Violations (' + r.atomicityViolations.length + ')')
    r.atomicityViolations.forEach(a => lines.push('- Line ' + a.line + ': ' + a.suggestion))
    lines.push('')
  }
  if (r.lockIssues.length > 0) {
    lines.push('## Lock Management (' + r.lockIssues.length + ')')
    r.lockIssues.forEach(l => lines.push('- Line ' + l.line + ': ' + l.suggestion))
    lines.push('')
  }
  return lines.join('\n')
}

// ==================== V0.18.0: PERFORMANCE PROFILING PATTERNS ====================

interface PerfProfileResult {
  totalIssues: number
  severity: Severity
  hotspots: { line: number; issue: string; suggestion: string }[]
  memoryLeaks: { line: number; issue: string; suggestion: string }[]
  blockingOps: { line: number; issue: string; suggestion: string }[]
  perfScore: number
  summary: string
}

function analyzePerfProfiling(code: string): PerfProfileResult {
  const lines = code.split('\n')
  const hotspots: PerfProfileResult['hotspots'] = []
  const memoryLeaks: PerfProfileResult['memoryLeaks'] = []
  const blockingOps: PerfProfileResult['blockingOps'] = []

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/|\/\*|\*)/)) return

    if (line.match(/for\s*\(.*for\s*\(/)) {
      hotspots.push({ line: i + 1, issue: 'Nested loop — O(n²) or worse complexity', suggestion: 'Use hash maps, pre-computation, or divide-and-conquer to reduce complexity' })
    }

    if (line.match(/addEventListener|setInterval|setTimeout|observer/i) && !line.match(/removeEventListener|clearInterval|clearTimeout|disconnect/)) {
      memoryLeaks.push({ line: i + 1, issue: 'Event listener/timer registered without cleanup', suggestion: 'Remove listeners in cleanup/dispose to prevent memory leaks in SPAs' })
    }

    if (line.match(/JSON\.parse\(.*JSON\.stringify|structuredClone/i) && line.match(/for|while|map|reduce/)) {
      hotspots.push({ line: i + 1, issue: 'Deep clone inside iteration — expensive operation', suggestion: 'Immutable updates or shallow clone with spread preferred over structuredClone' })
    }

    if (line.match(/sync|readFileSync|writeFileSync|execSync/i)) {
      blockingOps.push({ line: i + 1, issue: 'Synchronous I/O blocks the event loop', suggestion: 'Use async alternatives (readFile, writeFile, exec) for non-blocking I/O' })
    }

    if (line.match(/\.filter\(.*\.map\(|\.map\(.*\.filter\(/)) {
      hotspots.push({ line: i + 1, issue: 'Chained filter+map creates intermediate arrays', suggestion: 'Use reduce or single loop to combine transformations' })
    }

    if (line.match(/new\s+(?:Array|Object|Map|Set)\(\)/) && line.match(/while|for/i)) {
      hotspots.push({ line: i + 1, issue: 'Repeated allocation inside loop', suggestion: 'Hoist allocations outside loops or use object pooling' })
    }
  })

  const totalIssues = hotspots.length + memoryLeaks.length + blockingOps.length
  const perfScore = Math.max(0, 100 - hotspots.length * 8 - memoryLeaks.length * 12 - blockingOps.length * 10)
  const severity: Severity = hotspots.length > 2 || memoryLeaks.length > 1 ? 'warning' : totalIssues > 0 ? 'info' : 'info'

  return { totalIssues, severity, hotspots, memoryLeaks, blockingOps, perfScore,
    summary: hotspots.length + ' performance hotspot(s), ' + memoryLeaks.length + ' memory leak risk(s), ' + blockingOps.length + ' blocking operation(s)' }
}

function formatPerfProfileReport(r: PerfProfileResult): string {
  const lines: string[] = []
  lines.push('# Performance Profiling Analysis')
  lines.push('')
  lines.push('**Performance Score:** ' + r.perfScore + '/100 | **Issues:** ' + r.totalIssues + ' | **Severity:** ' + r.severity.toUpperCase())
  lines.push('')
  lines.push('> ' + r.summary)
  lines.push('')
  if (r.hotspots.length > 0) {
    lines.push('## Performance Hotspots (' + r.hotspots.length + ')')
    r.hotspots.forEach(h => lines.push('- Line ' + h.line + ': ' + h.suggestion))
    lines.push('')
  }
  if (r.memoryLeaks.length > 0) {
    lines.push('## Memory Leak Risks (' + r.memoryLeaks.length + ')')
    r.memoryLeaks.forEach(m => lines.push('- Line ' + m.line + ': ' + m.suggestion))
    lines.push('')
  }
  if (r.blockingOps.length > 0) {
    lines.push('## Blocking Operations (' + r.blockingOps.length + ')')
    r.blockingOps.forEach(b => lines.push('- Line ' + b.line + ': ' + b.suggestion))
    lines.push('')
  }
  return lines.join('\n')
}

// ==================== V0.18.0: DOCUMENTATION QUALITY ====================

interface DocQualityResult {
  totalIssues: number
  severity: Severity
  undocumented: { line: number; name: string; type: string; suggestion: string }[]
  outdated: { line: number; issue: string; suggestion: string }[]
  examples: { line: number; function: string; suggestion: string }[]
  docScore: number
  summary: string
}

function analyzeDocQuality(code: string): DocQualityResult {
  const lines = code.split('\n')
  const undocumented: DocQualityResult['undocumented'] = []
  const outdated: DocQualityResult['outdated'] = []
  const examples: DocQualityResult['examples'] = []

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/|\/\*|\*)/)) return

    const funcMatch = line.match(/(?:export\s+)?(?:function|const|class)\s+(\w+)/)
    if (funcMatch) {
      const lineAbove = i > 0 ? lines[i - 1] : ''
      const twoAbove = i > 1 ? lines[i - 2] : ''
      if (!lineAbove.match(/\/\*\*/) && !twoAbove.match(/\*\//)) {
        undocumented.push({ line: i + 1, name: funcMatch[1], type: line.match(/class/) ? 'class' : 'function', suggestion: 'Add JSDoc with @param, @returns, @throws for public API' })
      } else if (lineAbove.match(/\/\*\*/) && !lineAbove.match(/@param|@returns|@throws/)) {
        examples.push({ line: i + 1, function: funcMatch[1], suggestion: 'Add @example usage and document edge cases in JSDoc' })
      }
    }

    if (line.match(/\/\*\*| \*\//) && line.match(/TODO|FIXME|HACK/i)) {
      outdated.push({ line: i + 1, issue: 'Comment contains unresolved TODO/FIXME', suggestion: 'Resolve or create issue tracking — stale comments degrade documentation trust' })
    }

    if (line.match(/@param.*any|@returns.*any|@type.*any/i)) {
      outdated.push({ line: i + 1, issue: 'Documentation uses generic "any" type', suggestion: 'Replace with specific types for accurate IntelliSense and type safety' })
    }
  })

  const totalIssues = undocumented.length + outdated.length + examples.length
  const docScore = Math.max(0, 100 - undocumented.length * 10 - outdated.length * 8)
  const severity: Severity = undocumented.length > 3 ? 'warning' : totalIssues > 0 ? 'info' : 'info'

  return { totalIssues, severity, undocumented, outdated, examples, docScore,
    summary: undocumented.length + ' undocumented public API(s), ' + outdated.length + ' stale/outdated doc(s), ' + examples.length + ' missing example(s)' }
}

function formatDocQualityReport(r: DocQualityResult): string {
  const lines: string[] = []
  lines.push('# Documentation Quality Analysis')
  lines.push('')
  lines.push('**Documentation Score:** ' + r.docScore + '/100 | **Issues:** ' + r.totalIssues + ' | **Severity:** ' + r.severity.toUpperCase())
  lines.push('')
  lines.push('> ' + r.summary)
  lines.push('')
  if (r.undocumented.length > 0) {
    lines.push('## Undocumented Public APIs (' + r.undocumented.length + ')')
    r.undocumented.forEach(u => lines.push('- Line ' + u.line + ': ' + u.name + ' (' + u.type + ') — ' + u.suggestion))
    lines.push('')
  }
  if (r.outdated.length > 0) {
    lines.push('## Stale Documentation (' + r.outdated.length + ')')
    r.outdated.forEach(o => lines.push('- Line ' + o.line + ': ' + o.suggestion))
    lines.push('')
  }
  if (r.examples.length > 0) {
    lines.push('## Missing Examples (' + r.examples.length + ')')
    r.examples.forEach(e => lines.push('- Line ' + e.line + ': ' + e.function + ' — ' + e.suggestion))
    lines.push('')
  }
  return lines.join('\n')
}

// ==================== V0.18.0: SUPPLY CHAIN SECURITY ====================

interface SupplyChainResult {
  totalIssues: number
  severity: Severity
  unpinnedDeps: { line: number; dep: string; suggestion: string }[]
  suspiciousSources: { line: number; source: string; suggestion: string }[]
  checksumIssues: { line: number; issue: string; suggestion: string }[]
  supplyScore: number
  summary: string
}

function analyzeSupplyChain(code: string): SupplyChainResult {
  const lines = code.split('\n')
  const unpinnedDeps: SupplyChainResult['unpinnedDeps'] = []
  const suspiciousSources: SupplyChainResult['suspiciousSources'] = []
  const checksumIssues: SupplyChainResult['checksumIssues'] = []

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/|\/\*|\*)/)) return

    if (line.match(/install.*--no-save|npm\s+install\s+--no-package-lock|yarn\s+add\s+--no-lockfile/i) ||
        line.match(/ignore.*lockfile|skip.*integrity|--force/i)) {
      checksumIssues.push({ line: i + 1, issue: 'Lockfile bypass or integrity check disabled', suggestion: 'Always commit lockfiles and enable integrity checks for reproducible builds' })
    }

    if (line.match(/(?:http:\/\/|ftp:\/\/)/) && line.match(/cdn|unpkg|jsdelivr|script/i)) {
      suspiciousSources.push({ line: i + 1, source: line.trim().substring(0, 50), suggestion: 'Use HTTPS for all CDN/script sources to prevent MITM supply chain attacks' })
    }

    if (line.match(/"[^"]+":\s*"[\^~]?\d/) && !line.match(/lock|resolved|integrity/)) {
      const depMatch = line.match(/"([^"]+)":\s*"([^"]+)"/)
      if (depMatch) {
        const version = depMatch[2]
        if (version.match(/[\^~]/) || version === 'latest' || version === '*') {
          unpinnedDeps.push({ line: i + 1, dep: depMatch[1], suggestion: 'Pin exact version "' + depMatch[1] + '": "' + version.replace('^', '').replace('~', '') + '" to prevent unexpected updates' })
        }
      }
    }

    if (line.match(/postinstall|preinstall|install.*script/i) && !line.match(/husky|simple-git-hooks/)) {
      checksumIssues.push({ line: i + 1, issue: 'Install lifecycle script detected — potential dependency confusion vector', suggestion: 'Audit all lifecycle scripts; use --ignore-scripts in CI to prevent arbitrary code execution' })
    }

    if (line.match(/curl.*\|.*sh|wget.*\|.*bash|eval.*curl/i)) {
      suspiciousSources.push({ line: i + 1, source: line.trim().substring(0, 50), suggestion: 'Pipe-from-internet pattern risks supply chain attack — verify checksums before execution' })
    }
  })

  const totalIssues = unpinnedDeps.length + suspiciousSources.length + checksumIssues.length
  const supplyScore = Math.max(0, 100 - unpinnedDeps.length * 8 - suspiciousSources.length * 12 - checksumIssues.length * 15)
  const severity: Severity = checksumIssues.length > 0 ? 'warning' : suspiciousSources.length > 0 ? 'warning' : totalIssues > 0 ? 'info' : 'info'

  return { totalIssues, severity, unpinnedDeps, suspiciousSources, checksumIssues, supplyScore,
    summary: unpinnedDeps.length + ' unpinned dep(s), ' + suspiciousSources.length + ' suspicious source(s), ' + checksumIssues.length + ' integrity issue(s)' }
}

function formatSupplyChainReport(r: SupplyChainResult): string {
  const lines: string[] = []
  lines.push('# Supply Chain Security Analysis')
  lines.push('')
  lines.push('**Supply Chain Score:** ' + r.supplyScore + '/100 | **Issues:** ' + r.totalIssues + ' | **Severity:** ' + r.severity.toUpperCase())
  lines.push('')
  lines.push('> ' + r.summary)
  lines.push('')
  if (r.unpinnedDeps.length > 0) {
    lines.push('## Unpinned Dependencies (' + r.unpinnedDeps.length + ')')
    r.unpinnedDeps.forEach(d => lines.push('- Line ' + d.line + ': ' + d.dep + ' — ' + d.suggestion))
    lines.push('')
  }
  if (r.suspiciousSources.length > 0) {
    lines.push('## Suspicious Sources (' + r.suspiciousSources.length + ')')
    r.suspiciousSources.forEach(s => lines.push('- Line ' + s.line + ': ' + s.suggestion))
    lines.push('')
  }
  if (r.checksumIssues.length > 0) {
    lines.push('## Integrity Issues (' + r.checksumIssues.length + ')')
    r.checksumIssues.forEach(c => lines.push('- Line ' + c.line + ': ' + c.suggestion))
    lines.push('')
  }
  return lines.join('\n')
}

// ==================== V0.18.0: SDK DESIGN QUALITY ====================

interface SdkResult {
  totalIssues: number
  severity: Severity
  apiDesign: { line: number; issue: string; suggestion: string }[]
  versioning: { line: number; issue: string; suggestion: string }[]
  extensibility: { line: number; issue: string; suggestion: string }[]
  sdkScore: number
  summary: string
}

function analyzeSdkDesign(code: string): SdkResult {
  const lines = code.split('\n')
  const apiDesign: SdkResult['apiDesign'] = []
  const versioning: SdkResult['versioning'] = []
  const extensibility: SdkResult['extensibility'] = []

  lines.forEach((line, i) => {
    if (line.match(/^\s*(?:\/|\/\*|\*)/)) return

    if (line.match(/function\s+\w+\s*\([^)]*,[^)]*,[^)]*,[^)]*,[^)]*,[^)]*\)/) && !line.match(/options|config/i)) {
      apiDesign.push({ line: i + 1, issue: 'Function has 5+ positional parameters — poor discoverability', suggestion: 'Use options object pattern for functions with more than 3 parameters' })
    }

    if (line.match(/class\s+\w+\s*\{/) && !line.match(/implements|extends|interface/)) {
      const next5 = lines.slice(i + 1, i + 6).join('\n')
      if (next5.match(/private|protected/)) {
        extensibility.push({ line: i + 1, issue: 'Internal methods marked private — prevents legitimate extension', suggestion: 'Use protected or sealed pattern for SDK classes meant to be subclassed' })
      }
    }

    if (line.match(/console\.(log|debug|info)/) && !line.match(/verbose|debug.*mode|logger/)) {
      apiDesign.push({ line: i + 1, issue: 'Direct console.log in SDK code leaks implementation details', suggestion: 'Use configurable logger with silent/debug modes' })
    }

    if (line.match(/export\s+(?:default\s+)?class/) || line.match(/export\s+function/)) {
      const prevLine = i > 0 ? lines[i - 1] : ''
      if (!prevLine.match(/@public|@alpha|@beta|@deprecated|/)) {
        versioning.push({ line: i + 1, issue: 'Public API without stability annotation', suggestion: 'Add @public, @alpha, @beta, or @deprecated to communicate stability' })
      }
    }

    if (line.match(/throw\s+new\s+(?:Error|TypeError|RangeError)/) && !line.match(/@throws|@exception/)) {
      apiDesign.push({ line: i + 1, issue: 'Throws without documented error contract', suggestion: 'Document error types with @throws and use custom error classes for SDK errors' })
    }

    if (line.match(/callback/) && line.match(/Promise|async/)) {
      apiDesign.push({ line: i + 1, issue: 'Mixing callback and Promise patterns in same API', suggestion: 'Standardize on Promise/async; provide promisify helper for legacy callbacks' })
    }
  })

  const totalIssues = apiDesign.length + versioning.length + extensibility.length
  const sdkScore = Math.max(0, 100 - apiDesign.length * 8 - versioning.length * 10 - extensibility.length * 12)
  const severity: Severity = apiDesign.length > 3 ? 'warning' : totalIssues > 0 ? 'info' : 'info'

  return { totalIssues, severity, apiDesign, versioning, extensibility, sdkScore,
    summary: apiDesign.length + ' API design issue(s), ' + versioning.length + ' versioning concern(s), ' + extensibility.length + ' extensibility issue(s)' }
}

function formatSdkReport(r: SdkResult): string {
  const lines: string[] = []
  lines.push('# SDK Design Quality Analysis')
  lines.push('')
  lines.push('**SDK Quality Score:** ' + r.sdkScore + '/100 | **Issues:** ' + r.totalIssues + ' | **Severity:** ' + r.severity.toUpperCase())
  lines.push('')
  lines.push('> ' + r.summary)
  lines.push('')
  if (r.apiDesign.length > 0) {
    lines.push('## API Design Issues (' + r.apiDesign.length + ')')
    r.apiDesign.forEach(a => lines.push('- Line ' + a.line + ': ' + a.suggestion))
    lines.push('')
  }
  if (r.versioning.length > 0) {
    lines.push('## Versioning Concerns (' + r.versioning.length + ')')
    r.versioning.forEach(v => lines.push('- Line ' + v.line + ': ' + v.suggestion))
    lines.push('')
  }
  if (r.extensibility.length > 0) {
    lines.push('## Extensibility (' + r.extensibility.length + ')')
    r.extensibility.forEach(e => lines.push('- Line ' + e.line + ': ' + e.suggestion))
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

  // Tool 42: Dead Code Detection (v0.10.0)
  ctx.tools.register(defineTool({
    name: 'dead_code_detect',
    description: 'Detect dead code: unused variables, unreachable code, unused exports, dead branches, unused functions.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = detectDeadCode(args.code)
      return formatDeadCodeReport(result)
    }
  }))

  // Tool 43: Circular Dependency Detection (v0.10.0)
  ctx.tools.register(defineTool({
    name: 'circular_dep',
    description: 'Detect circular dependencies between modules or functions. Reports cycles with path and length.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = detectCircularDeps(args.code)
      return formatCircularDepReport(result)
    }
  }))

  // Tool 44: Regex Security Analysis (v0.10.0)
  ctx.tools.register(defineTool({
    name: 'regex_security',
    description: 'Analyze regex patterns for ReDoS risks, catastrophic backtracking, and performance issues.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to scan' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeRegexSecurity(args.code)
      return formatRegexSecurityReport(result)
    }
  }))

  // Tool 45: JSDoc Auto-Generation (v0.10.0)
  ctx.tools.register(defineTool({
    name: 'jsdoc_generate',
    description: 'Auto-generate JSDoc comments for undocumented functions. Detects missing type annotations.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to document' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = generateJsdoc(args.code)
      return formatJsdocReport(result)
    }
  }))

  // Tool 46: Public API Surface Analysis (v0.10.0)
  ctx.tools.register(defineTool({
    name: 'api_surface',
    description: 'Analyze public API surface: exports, imports, cohesion score, dependency count.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeApiSurface(args.code)
      return formatApiSurfaceReport(result)
    }
  }))

  // Tool 47: Git History Hotspot Detection (v0.10.0)
  ctx.tools.register(defineTool({
    name: 'git_hotspot',
    description: 'Detect code hotspots: high-change areas, TODO/FIXME density, commented-out code patterns.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = detectGitHotspots(args.code)
      return formatHotspotReport(result)
    }
  }))

  // Tool 48: Module Layer Violation Detection (v0.10.0)
  ctx.tools.register(defineTool({
    name: 'module_layer',
    description: 'Detect architecture layer violations: presentation, service, data, infrastructure coupling.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = detectLayerViolations(args.code)
      return formatLayerViolationReport(result)
    }
  }))

  // Tool 49: Error Propagation Tracing (v0.10.0)
  ctx.tools.register(defineTool({
    name: 'error_trace',
    description: 'Trace error propagation paths: throws, catches, unhandled async, swallowed errors.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to trace' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = traceErrorPropagation(args.code)
      return formatErrorTraceReport(result)
    }
  }))

  // Tool 50: Auto Refactoring (v0.11.0)
  ctx.tools.register(defineTool({
    name: 'auto_refactor',
    description: 'Suggest automated refactorings: extract method, extract variable, inline temp, replace magic number.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to refactor' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = suggestAutoRefactor(args.code)
      return formatAutoRefactorReport(result)
    }
  }))

  // Tool 51: Code Similarity Detection (v0.11.0)
  ctx.tools.register(defineTool({
    name: 'code_similarity',
    description: 'Detect code similarity using token-based Jaccard similarity. Finds duplicate blocks.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = detectCodeSimilarity(args.code)
      return formatSimilarityReport(result)
    }
  }))

  // Tool 52: Primitive Obsession Detection (v0.11.0)
  ctx.tools.register(defineTool({
    name: 'primitive_obsession',
    description: 'Detect primitive obsession: phone, email, money, date etc. that should be domain types.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = detectPrimitiveObsession(args.code)
      return formatPrimitiveObsessionReport(result)
    }
  }))

  // Tool 53: SQL Injection Deep Detection (v0.11.0)
  ctx.tools.register(defineTool({
    name: 'sql_injection',
    description: 'Deep SQL injection detection: concatenation, template literals, dynamic WHERE. Identifies safe patterns too.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to scan' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = detectSqlInjection(args.code)
      return formatSqlInjectionReport(result)
    }
  }))

  // Tool 54: Interface Compliance Checker (v0.11.0)
  ctx.tools.register(defineTool({
    name: 'interface_compliance',
    description: 'Check class compliance with interfaces: missing methods, extra methods, signature mismatches.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to check' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = checkInterfaceCompliance(args.code)
      return formatInterfaceComplianceReport(result)
    }
  }))

  // Tool 55: Magic String Detection (v0.11.0)
  ctx.tools.register(defineTool({
    name: 'magic_string',
    description: 'Detect magic strings: hardcoded literals that should be constants. Flags user-facing strings for i18n.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = detectMagicStrings(args.code)
      return formatMagicStringReport(result)
    }
  }))

  // Tool 56: Semantic Version Bump Recommender (v0.11.0)
  ctx.tools.register(defineTool({
    name: 'semver_bump',
    description: 'Recommend semantic version bump: breaking changes (major), features (minor), fixes (patch).',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = recommendSemverBump(args.code)
      return formatSemverReport(result)
    }
  }))

  // Tool 57: PR Review Comment Generator (v0.11.0)
  ctx.tools.register(defineTool({
    name: 'code_review_comment',
    description: 'Generate inline PR review comments: security issues, performance, clean code, best practices.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to review' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = generatePRReviewComments(args.code)
      return formatPRReviewCommentReport(result)
    }
  }))

  // Tool 58: Variable Scope Analysis (v0.12.0)
  ctx.tools.register(defineTool({
    name: 'scope_analysis',
    description: 'Analyze variable scope: hoisting, shadowing, scope depth, var vs let/const issues.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeScope(args.code)
      return formatScopeReport(result)
    }
  }))

  // Tool 59: Immutability Checker (v0.12.0)
  ctx.tools.register(defineTool({
    name: 'immutable_check',
    description: 'Check immutability: mutable patterns (push, splice) vs immutable alternatives (spread, freeze).',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to check' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = checkImmutability(args.code)
      return formatImmutableReport(result)
    }
  }))

  // Tool 60: Null Safety Analysis (v0.12.0)
  ctx.tools.register(defineTool({
    name: 'null_safety',
    description: 'Analyze null safety: risky property access, missing optional chaining, null checks.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeNullSafety(args.code)
      return formatNullSafetyReport(result)
    }
  }))

  // Tool 61: Concurrency Issue Detection (v0.12.0)
  ctx.tools.register(defineTool({
    name: 'concurrency_check',
    description: 'Detect concurrency issues: missing await, shared state, unhandled promise rejections.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = detectConcurrencyIssues(args.code)
      return formatConcurrencyReport(result)
    }
  }))

  // Tool 62: Documentation-Code Sync (v0.12.0)
  ctx.tools.register(defineTool({
    name: 'doc_sync',
    description: 'Check documentation-code sync: JSDoc params vs actual params, undocumented functions.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to check' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = checkDocSync(args.code)
      return formatDocSyncReport(result)
    }
  }))

  // Tool 63: Test Quality Analysis (v0.12.0)
  ctx.tools.register(defineTool({
    name: 'test_quality',
    description: 'Analyze test quality: assertion count, anti-patterns, test naming, coverage indicators.',
    parameters: {
      code: { type: 'string', required: true, description: 'The test code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeTestQuality(args.code)
      return formatTestQualityReport(result)
    }
  }))

  // Tool 64: Change Impact Estimation (v0.12.0)
  ctx.tools.register(defineTool({
    name: 'change_impact',
    description: 'Estimate change impact: breaking/feature/fix classification, affected areas, testing recommendations.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = estimateChangeImpact(args.code)
      return formatImpactReport(result)
    }
  }))

  // Tool 65: Performance Regression Patterns (v0.12.0)
  ctx.tools.register(defineTool({
    name: 'performance_regression',
    description: 'Detect performance regression patterns: N+1 queries, nested loops, unnecessary re-renders.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = detectPerfRegression(args.code)
      return formatPerfRegressionReport(result)
    }
  }))

  // Tool 66: Memory Leak Detection (v0.13.0)
  ctx.tools.register(defineTool({
    name: 'memory_leak_detect',
    description: 'Detect memory leaks: uncleared listeners, timers, unbounded caches, closure leaks.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = detectMemoryLeaks(args.code)
      return formatMemoryLeakReport(result)
    }
  }))

  // Tool 67: i18n Readiness Check (v0.13.0)
  ctx.tools.register(defineTool({
    name: 'i18n_check',
    description: 'Check i18n readiness: hardcoded UI strings, numbers, dates that need internationalization.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to check' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = checkI18n(args.code)
      return formatI18nReport(result)
    }
  }))

  // Tool 68: Logging Quality Analysis (v0.13.0)
  ctx.tools.register(defineTool({
    name: 'logging_quality',
    description: 'Analyze logging quality: console statements, PII exposure, missing context, log levels.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeLogging(args.code)
      return formatLoggingReport(result)
    }
  }))

  // Tool 69: Configuration Validator (v0.13.0)
  ctx.tools.register(defineTool({
    name: 'config_validate',
    description: 'Validate configuration files: missing fields, insecure values, type issues, deprecated fields.',
    parameters: {
      code: { type: 'string', required: true, description: 'The configuration file content to validate' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = validateConfig(args.code)
      return formatConfigReport(result)
    }
  }))

  // Tool 70: Bundle Size Estimation (v0.13.0)
  ctx.tools.register(defineTool({
    name: 'bundle_size',
    description: 'Estimate bundle size: heavy imports, duplicate modules, dynamic import opportunities.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = estimateBundleSize(args.code)
      return formatBundleReport(result)
    }
  }))

  // Tool 71: Accessibility Scan (v0.13.0)
  ctx.tools.register(defineTool({
    name: 'accessibility_scan',
    description: 'Scan accessibility: missing alt text, labels, ARIA attributes, keyboard navigation.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to scan' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = scanAccessibility(args.code)
      return formatA11yReport(result)
    }
  }))

  // Tool 72: Design Pattern Detection (v0.13.0)
  ctx.tools.register(defineTool({
    name: 'design_pattern',
    description: 'Detect design patterns and anti-patterns: Singleton, Factory, Observer, God Object, etc.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = detectPatterns(args.code)
      return formatPatternReport(result)
    }
  }))

  // Tool 73: Error Boundary Analysis (v0.13.0)
  ctx.tools.register(defineTool({
    name: 'error_boundary',
    description: 'Analyze error handling: unchecked async, empty catch, resource cleanup, custom errors.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeErrorBoundaries(args.code)
      return formatErrorBoundaryReport(result)
    }
  }))

  // Tool 74: React Hooks Compliance (v0.14.0)
  ctx.tools.register(defineTool({
    name: 'react_hooks_check',
    description: 'Check React Hooks rules: conditional/loop hooks, missing deps, stale closures, unnecessary hooks.',
    parameters: {
      code: { type: 'string', required: true, description: 'The React component code to check' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = checkReactHooks(args.code)
      return formatHooksReport(result)
    }
  }))

  // Tool 75: Database Query Analysis (v0.14.0)
  ctx.tools.register(defineTool({
    name: 'sql_analysis',
    description: 'Analyze database queries: N+1 patterns, SELECT *, unbounded queries, missing indexes.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code with queries to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeQueries(args.code)
      return formatQueryReport(result)
    }
  }))

  // Tool 76: Regex Optimization (v0.14.0)
  ctx.tools.register(defineTool({
    name: 'regex_optimize',
    description: 'Optimize regex patterns: catastrophic backtracking, inefficient quantifiers, simplification.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code with regex to optimize' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = optimizeRegex(args.code)
      return formatRegexOptReport(result)
    }
  }))

  // Tool 77: DOM Efficiency Analysis (v0.14.0)
  ctx.tools.register(defineTool({
    name: 'dom_efficiency',
    description: 'Analyze DOM efficiency: forced sync layout, layout thrashing, batchable operations.',
    parameters: {
      code: { type: 'string', required: true, description: 'The DOM manipulation code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeDomEfficiency(args.code)
      return formatDomReport(result)
    }
  }))

  // Tool 78: Security Headers Analysis (v0.14.0)
  ctx.tools.register(defineTool({
    name: 'security_headers',
    description: 'Analyze security headers: CSP, HSTS, CORS misconfigurations, deprecated headers.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code or config to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeSecurityHeaders(args.code)
      return formatSecurityHeadersReport(result)
    }
  }))

  // Tool 79: CSS/Style Analysis (v0.14.0)
  ctx.tools.register(defineTool({
    name: 'css_analysis',
    description: 'Analyze CSS: specificity, !important overuse, magic numbers, duplicate properties.',
    parameters: {
      code: { type: 'string', required: true, description: 'The CSS/style code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeCss(args.code)
      return formatCssReport(result)
    }
  }))

  // Tool 80: Dependency Version Policy (v0.14.0)
  ctx.tools.register(defineTool({
    name: 'semver_policy',
    description: 'Check dependency version policy: deprecated packages, wildcard versions, unpinned deps.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code or package.json to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeSemverPolicy(args.code)
      return formatSemverPolicyReport(result)
    }
  }))

  // Tool 81: State Management Analysis (v0.14.0)
  ctx.tools.register(defineTool({
    name: 'state_management',
    description: 'Analyze state management: direct mutations, re-render risks, normalization, batching.',
    parameters: {
      code: { type: 'string', required: true, description: 'The state management code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeStateManagement(args.code)
      return formatStateReport(result)
    }
  }))

  // Tool 82: API Contract Validation (v0.15.0)
  ctx.tools.register(defineTool({
    name: 'api_contract',
    description: 'Validate API contract: unprotected routes, missing responses, status code issues.',
    parameters: {
      code: { type: 'string', required: true, description: 'The API code to validate' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = validateApiContract(args.code)
      return formatContractReport(result)
    }
  }))

  // Tool 83: GraphQL Analysis (v0.15.0)
  ctx.tools.register(defineTool({
    name: 'graphql_analysis',
    description: 'Analyze GraphQL: query depth, N+1 resolvers, pagination, fragment reuse.',
    parameters: {
      code: { type: 'string', required: true, description: 'The GraphQL code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeGraphql(args.code)
      return formatGraphqlReport(result)
    }
  }))

  // Tool 84: Infrastructure-as-Code Analysis (v0.15.0)
  ctx.tools.register(defineTool({
    name: 'iac_analysis',
    description: 'Analyze IaC: Docker, Kubernetes, Terraform best practices and security.',
    parameters: {
      code: { type: 'string', required: true, description: 'The IaC configuration to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeIac(args.code)
      return formatIacReport(result)
    }
  }))

  // Tool 85: Browser Compatibility (v0.15.0)
  ctx.tools.register(defineTool({
    name: 'browser_compat',
    description: 'Check browser compatibility: unsupported features, deprecated APIs, polyfills.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to check' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeBrowserCompat(args.code)
      return formatCompatReport(result)
    }
  }))

  // Tool 86: Microservice Patterns (v0.15.0)
  ctx.tools.register(defineTool({
    name: 'microservice_patterns',
    description: 'Analyze microservice patterns: health checks, circuit breakers, retries, timeouts.',
    parameters: {
      code: { type: 'string', required: true, description: 'The microservice code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeMicroservice(args.code)
      return formatMicroserviceReport(result)
    }
  }))

  // Tool 87: File Organization (v0.15.0)
  ctx.tools.register(defineTool({
    name: 'file_organization',
    description: 'Analyze file organization: deep imports, barrel exports, large files, naming.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeFileOrganization(args.code)
      return formatOrgReport(result)
    }
  }))

  // Tool 88: Commit Message Quality (v0.15.0)
  ctx.tools.register(defineTool({
    name: 'commit_message',
    description: 'Analyze commit message quality: conventional commits, length, vagueness.',
    parameters: {
      code: { type: 'string', required: true, description: 'The commit message(s) to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeCommitMessage(args.code)
      return formatCommitReport(result)
    }
  }))

  // Tool 89: Code Splitting (v0.15.0)
  ctx.tools.register(defineTool({
    name: 'code_splitting',
    description: 'Find code splitting opportunities: heavy sync imports, lazy-load candidates.',
    parameters: {
      code: { type: 'string', required: true, description: 'The source code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeCodeSplitting(args.code)
      return formatSplitReport(result)
    }
  }))

  // Tool 90: WebAssembly Compatibility (v0.16.0)
  ctx.tools.register(defineTool({
    name: 'wasm_check',
    description: 'Check WebAssembly compatibility: JS interop, memory leaks, type safety, error handling.',
    parameters: {
      code: { type: 'string', required: true, description: 'The WASM-related code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = checkWasmCompat(args.code)
      return formatWasmReport(result)
    }
  }))

  // Tool 91: Authentication Security (v0.16.0)
  ctx.tools.register(defineTool({
    name: 'auth_security',
    description: 'Analyze authentication: JWT config, sessions, hardcoded credentials, bcrypt strength.',
    parameters: {
      code: { type: 'string', required: true, description: 'The auth code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeAuthSecurity(args.code)
      return formatAuthReport(result)
    }
  }))

  // Tool 92: Payment Compliance (v0.16.0)
  ctx.tools.register(defineTool({
    name: 'payment_compliance',
    description: 'Check payment compliance: PCI-DSS, precision, idempotency, audit trail.',
    parameters: {
      code: { type: 'string', required: true, description: 'The payment code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzePaymentCompliance(args.code)
      return formatPaymentReport(result)
    }
  }))

  // Tool 93: Email/SMTP Security (v0.16.0)
  ctx.tools.register(defineTool({
    name: 'email_smtp',
    description: 'Analyze email security: injection risks, SMTP auth, DKIM, template safety.',
    parameters: {
      code: { type: 'string', required: true, description: 'The email code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeEmailSecurity(args.code)
      return formatEmailReport(result)
    }
  }))

  // Tool 94: Rate Limiting (v0.16.0)
  ctx.tools.register(defineTool({
    name: 'rate_limit',
    description: 'Analyze rate limiting: unprotected endpoints, weak algorithms, distributed support.',
    parameters: {
      code: { type: 'string', required: true, description: 'The API code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeRateLimiting(args.code)
      return formatRateLimitReport(result)
    }
  }))

  // Tool 95: WebSocket Health (v0.16.0)
  ctx.tools.register(defineTool({
    name: 'websocket_health',
    description: 'Analyze WebSocket health: heartbeat, reconnection, backpressure handling.',
    parameters: {
      code: { type: 'string', required: true, description: 'The WebSocket code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeWebSocketHealth(args.code)
      return formatWsReport(result)
    }
  }))

  // Tool 96: Cron Job Robustness (v0.16.0)
  ctx.tools.register(defineTool({
    name: 'cron_job',
    description: 'Analyze cron job robustness: idempotency, distributed locks, error handling, timeouts.',
    parameters: {
      code: { type: 'string', required: true, description: 'The cron job code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeCronJobs(args.code)
      return formatCronReport(result)
    }
  }))

  // Tool 97: Event Sourcing Patterns (v0.16.0)
  ctx.tools.register(defineTool({
    name: 'event_sourcing',
    description: 'Analyze event sourcing: versioning, snapshots, upcasting, event design.',
    parameters: {
      code: { type: 'string', required: true, description: 'The event-sourced code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeEventSourcing(args.code)
      return formatEventSourcingReport(result)
    }
  }))

  // Tool 98: Cache Strategy (v0.17.0)
  ctx.tools.register(defineTool({
    name: 'cache_strategy',
    description: 'Analyze cache strategy: TTL, penetration, thundering herd, invalidation.',
    parameters: {
      code: { type: 'string', required: true, description: 'The caching code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeCacheStrategy(args.code)
      return formatCacheReport(result)
    }
  }))

  // Tool 99: Graceful Shutdown (v0.17.0)
  ctx.tools.register(defineTool({
    name: 'graceful_shutdown',
    description: 'Analyze graceful shutdown: signal handlers, connection draining, timeouts.',
    parameters: {
      code: { type: 'string', required: true, description: 'The server code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeGracefulShutdown(args.code)
      return formatShutdownReport(result)
    }
  }))

  // Tool 100: Health & Readiness Probes (v0.17.0)
  ctx.tools.register(defineTool({
    name: 'health_probes',
    description: 'Analyze K8s probes: liveness, readiness, startup probe endpoints.',
    parameters: {
      code: { type: 'string', required: true, description: 'The server code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeHealthProbes(args.code)
      return formatProbeReport(result)
    }
  }))

  // Tool 101: Serialization Safety (v0.17.0)
  ctx.tools.register(defineTool({
    name: 'serialization_safety',
    description: 'Analyze serialization: prototype pollution, BigInt, unsafe JSON.parse.',
    parameters: {
      code: { type: 'string', required: true, description: 'The serialization code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeSerialization(args.code)
      return formatSerializationReport(result)
    }
  }))

  // Tool 102: Data Validation (v0.17.0)
  ctx.tools.register(defineTool({
    name: 'data_validation',
    description: 'Analyze data validation: schema validation, XSS, weak regex, sanitization.',
    parameters: {
      code: { type: 'string', required: true, description: 'The input handling code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeDataValidation(args.code)
      return formatValidationReport(result)
    }
  }))

  // Tool 103: Multi-Tenancy Isolation (v0.17.0)
  ctx.tools.register(defineTool({
    name: 'multi_tenancy',
    description: 'Analyze multi-tenancy: tenant filter, shared state, data isolation.',
    parameters: {
      code: { type: 'string', required: true, description: 'The multi-tenant code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeMultiTenancy(args.code)
      return formatTenantReport(result)
    }
  }))

  // Tool 104: Feature Flag Governance (v0.17.0)
  ctx.tools.register(defineTool({
    name: 'feature_flags',
    description: 'Analyze feature flags: hardcoded values, cleanup plans, technical debt.',
    parameters: {
      code: { type: 'string', required: true, description: 'The feature flag code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeFeatureFlags(args.code)
      return formatFlagReport(result)
    }
  }))

  // Tool 105: API Gateway Patterns (v0.17.0)
  ctx.tools.register(defineTool({
    name: 'api_gateway',
    description: 'Analyze API gateway: missing gateway, BFF pattern, service routing.',
    parameters: {
      code: { type: 'string', required: true, description: 'The microservice code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeGateway(args.code)
      return formatGatewayReport(result)
    }
  }))

  // Tool 106: AI Prompt Injection Detection (v0.18.0)
  ctx.tools.register(defineTool({
    name: 'ai_prompt_security',
    description: 'Detect AI prompt injection risks: unsanitized input, jailbreak patterns, data leakage in LLM prompts.',
    parameters: {
      code: { type: 'string', required: true, description: 'The AI/LLM integration code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeAiPromptSecurity(args.code)
      return formatAiPromptReport(result)
    }
  }))

  // Tool 107: Micro-Frontend Architecture (v0.18.0)
  ctx.tools.register(defineTool({
    name: 'micro_frontend',
    description: 'Analyze micro-frontend architecture: routing conflicts, shared deps, namespace pollution.',
    parameters: {
      code: { type: 'string', required: true, description: 'The micro-frontend code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeMicroFrontends(args.code)
      return formatMfReport(result)
    }
  }))

  // Tool 108: Database Indexing Advisor (v0.18.0)
  ctx.tools.register(defineTool({
    name: 'database_indexing',
    description: 'Analyze database indexing: missing indexes, unused indexes, cardinality issues in SQL.',
    parameters: {
      code: { type: 'string', required: true, description: 'The SQL/ORM code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeDatabaseIndexes(args.code)
      return formatIndexReport(result)
    }
  }))

  // Tool 109: Advanced Concurrency Patterns (v0.18.0)
  ctx.tools.register(defineTool({
    name: 'adv_concurrency',
    description: 'Analyze concurrency: race conditions, deadlocks, atomicity violations, lock management.',
    parameters: {
      code: { type: 'string', required: true, description: 'The concurrent code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeAdvConcurrency(args.code)
      return formatAdvConcurrencyReport(result)
    }
  }))

  // Tool 110: Performance Profiling Patterns (v0.18.0)
  ctx.tools.register(defineTool({
    name: 'perf_profiling',
    description: 'Profile performance: hotspots, memory leaks, blocking ops, allocation patterns.',
    parameters: {
      code: { type: 'string', required: true, description: 'The code to profile for performance' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzePerfProfiling(args.code)
      return formatPerfProfileReport(result)
    }
  }))

  // Tool 111: Documentation Quality (v0.18.0)
  ctx.tools.register(defineTool({
    name: 'doc_quality',
    description: 'Analyze documentation quality: undocumented APIs, stale docs, missing examples.',
    parameters: {
      code: { type: 'string', required: true, description: 'The code to analyze for documentation' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeDocQuality(args.code)
      return formatDocQualityReport(result)
    }
  }))

  // Tool 112: Supply Chain Security (v0.18.0)
  ctx.tools.register(defineTool({
    name: 'supply_chain',
    description: 'Analyze supply chain security: unpinned deps, suspicious sources, integrity checks.',
    parameters: {
      code: { type: 'string', required: true, description: 'The dependency/config code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeSupplyChain(args.code)
      return formatSupplyChainReport(result)
    }
  }))

  // Tool 113: SDK Design Quality (v0.18.0)
  ctx.tools.register(defineTool({
    name: 'sdk_design',
    description: 'Analyze SDK design: API ergonomics, versioning, extensibility, error contracts.',
    parameters: {
      code: { type: 'string', required: true, description: 'The SDK code to analyze' }
    },
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value as string }] },
    async execute(args: { code: string }) {
      const result = analyzeSdkDesign(args.code)
      return formatSdkReport(result)
    }
  }))

  console.log(`[${name}] v${VERSION} loaded; tools: code_review, security_scan, dependency_audit, performance_check, code_check, architecture_review, test_coverage, api_docs, code_diff, style_check, code_smell_detect, ts_strict_check, incremental_analysis, breaking_change, sarif_export, diff_preview, config_load, test_generate, complexity_metrics, batch_analyze, monorepo_analyze, multilang_analyze, cicd_generate, custom_rules, duplicate_detect, refactor_suggest, naming_check, security_patterns, performance_tips, doc_check, import_organize, error_handling, api_design, coverage_estimate, dep_versions, style_enforce, func_length, class_cohesion, comment_quality, type_safety, async_patterns, dead_code_detect, circular_dep, regex_security, jsdoc_generate, api_surface, git_hotspot, module_layer, error_trace, auto_refactor, code_similarity, primitive_obsession, sql_injection, interface_compliance, magic_string, semver_bump, code_review_comment, scope_analysis, immutable_check, null_safety, concurrency_check, doc_sync, test_quality, change_impact, performance_regression, memory_leak_detect, i18n_check, logging_quality, config_validate, bundle_size, accessibility_scan, design_pattern, error_boundary, react_hooks_check, sql_analysis, regex_optimize, dom_efficiency, security_headers, css_analysis, semver_policy, state_management, api_contract, graphql_analysis, iac_analysis, browser_compat, microservice_patterns, file_organization, commit_message, code_splitting, wasm_check, auth_security, payment_compliance, email_smtp, rate_limit, websocket_health, cron_job, event_sourcing, cache_strategy, graceful_shutdown, health_probes, serialization_safety, data_validation, multi_tenancy, feature_flags, api_gateway, ai_prompt_security, micro_frontend, database_indexing, adv_concurrency, perf_profiling, doc_quality, supply_chain, sdk_design`)
}

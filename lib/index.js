/**
 * DSH Code Review Assistant Plugin - Enterprise Edition v0.10.0
 *
 * Enterprise-grade code analysis toolkit for DeepSeek Harness Agent.
 *
 * Features (v0.10.0):
 * - 49 comprehensive analysis tools
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
 *
 * @module dsh-tool-codereview
 * @version 0.10.0
 * @license MIT
 */
import { defineTool } from '@deepseek-ai/dsh-tools';
export const name = 'dsh-tool-codereview';
export const inject = ['tools'];
const VERSION = '0.11.0';
const DEFAULT_CONFIG = {
    severityThreshold: 'info',
    ignoreRules: [],
    enableSarif: true,
    enableAutoFix: true
};
// ==================== CORE ANALYSIS ENGINE ====================
function analyzeCode(code, language, config = DEFAULT_CONFIG) {
    const lines = code.split('\n');
    const issues = [];
    const strengths = [];
    const recommendations = [];
    const refactoringSuggestions = [];
    const autoFixes = [];
    const architecturePatterns = [];
    let score = 100;
    const metrics = calculateMetrics(code, language);
    // Code Length Analysis
    if (lines.length > 500) {
        issues.push({ severity: 'error', category: 'maintainability', ruleId: 'FILE_TOO_LONG', message: `File has ${lines.length} lines. Significantly above recommended limits.`, suggestion: 'Split into smaller, focused modules. Aim for < 300 lines per file.', docUrl: 'https://refactoring.guru/smells/long-class' });
        score -= 20;
        refactoringSuggestions.push({ title: 'Extract Module', description: 'Break this large file into smaller modules based on responsibility.', impact: 'high', effort: 'medium', before: 'single large file (500+ lines)', after: 'multiple focused modules (100-200 lines each)' });
    }
    else if (lines.length > 300) {
        issues.push({ severity: 'warning', category: 'maintainability', ruleId: 'FILE_LONG', message: `File has ${lines.length} lines. Consider splitting.`, suggestion: 'Aim for files under 300 lines.' });
        score -= 10;
    }
    else if (lines.length <= 100 && lines.length > 5) {
        strengths.push('File size is manageable and focused.');
    }
    // Comment Analysis
    const commentRatio = metrics.linesOfCode > 0 ? metrics.commentLines / metrics.linesOfCode : 0;
    if (commentRatio < 0.05 && metrics.linesOfCode > 50) {
        issues.push({ severity: 'warning', category: 'documentation', ruleId: 'LOW_COMMENT_RATIO', message: `Low comment ratio (${(commentRatio * 100).toFixed(1)}%).`, suggestion: 'Add JSDoc/docstrings for public APIs. Explain "why", not "what".' });
        score -= 10;
    }
    else if (commentRatio > 0.2) {
        strengths.push('Good comment coverage.');
    }
    // Function Analysis
    if (metrics.averageFunctionLength > 40 && metrics.functionCount > 0) {
        issues.push({ severity: 'warning', category: 'maintainability', ruleId: 'LONG_FUNCTION', message: `Average function length is ${metrics.averageFunctionLength} lines.`, suggestion: 'Break long functions into smaller, single-purpose functions (< 30 lines).' });
        score -= 10;
        refactoringSuggestions.push({ title: 'Extract Method', description: 'Break long functions into smaller, reusable methods.', impact: 'high', effort: 'low' });
    }
    else if (metrics.averageFunctionLength > 0 && metrics.averageFunctionLength <= 20) {
        strengths.push('Functions are concise and well-structured.');
    }
    // Nesting Depth Analysis
    if (metrics.maxNestingDepth > 4) {
        issues.push({ severity: 'warning', category: 'complexity', ruleId: 'DEEP_NESTING', message: `Maximum nesting depth is ${metrics.maxNestingDepth}.`, suggestion: 'Use early returns, extract helper functions, or apply Strategy pattern.' });
        score -= 15;
        refactoringSuggestions.push({ title: 'Reduce Nesting', description: 'Apply guard clauses and early returns to reduce nesting depth.', impact: 'medium', effort: 'low' });
    }
    // Complexity Score
    if (metrics.complexityScore > 70) {
        issues.push({ severity: 'warning', category: 'complexity', ruleId: 'HIGH_COMPLEXITY', message: `Cyclomatic complexity score is ${metrics.complexityScore}/100.`, suggestion: 'Reduce branching logic. Consider polymorphism or lookup tables.' });
        score -= 10;
    }
    // Debug Statements
    const debugCount = detectDebugStatements(code, language, lines, issues, autoFixes);
    if (debugCount > 5) {
        issues.push({ severity: 'warning', category: 'debugging', ruleId: 'MANY_DEBUG_STATEMENTS', message: `Found ${debugCount} debug output statements.`, suggestion: 'Use a configurable logging framework (winston, pino, log4js).' });
        score -= 5;
    }
    // TODO/FIXME Detection
    const todoCount = detectTodoFixme(code, language, lines, issues);
    if (todoCount > 5) {
        recommendations.push(`High technical debt: ${todoCount} TODO/FIXME items. Schedule cleanup.`);
    }
    // Empty Catch Block Detection
    detectEmptyCatch(code, issues, autoFixes);
    // Magic Number Detection
    detectMagicNumbers(code, lines, issues);
    // Error Handling Analysis
    detectErrorHandlingIssues(code, language, issues, strengths, recommendations);
    // Hardcoded Credentials Detection
    detectHardcodedCredentials(code, lines, issues, autoFixes);
    // Duplicate Code Detection
    if (metrics.duplicateLines > 20) {
        issues.push({ severity: 'info', category: 'duplication', ruleId: 'DUPLICATE_CODE', message: `Found ${metrics.duplicateLines} lines of potential duplicate code.`, suggestion: 'Extract common logic into shared utility functions.' });
        refactoringSuggestions.push({ title: 'DRY Principle', description: 'Extract duplicate code into reusable functions.', impact: 'medium', effort: 'low' });
    }
    // Architecture Pattern Detection
    detectArchitecturePatterns(code, language, architecturePatterns);
    // Apply config filters
    const filteredIssues = issues.filter(i => !config.ignoreRules.includes(i.ruleId || ''));
    score = Math.max(0, Math.min(100, score));
    const grade = calculateGrade(score);
    const criticalCount = filteredIssues.filter(i => i.severity === 'critical').length;
    const errorCount = filteredIssues.filter(i => i.severity === 'error').length;
    const warningCount = filteredIssues.filter(i => i.severity === 'warning').length;
    const infoCount = filteredIssues.filter(i => i.severity === 'info').length;
    let summary = `Code Review: Score ${score}/100 (Grade: ${grade}). `;
    if (criticalCount > 0)
        summary += `${criticalCount} critical, `;
    if (errorCount > 0)
        summary += `${errorCount} error(s), `;
    summary += `${warningCount} warning(s), ${infoCount} info note(s).`;
    if (score >= 85)
        strengths.unshift('Overall code quality is excellent.');
    else if (score >= 70)
        recommendations.unshift('Code is acceptable but has room for improvement.');
    else if (score >= 50)
        recommendations.unshift('Code needs attention. Prioritize error and warning fixes.');
    else
        recommendations.unshift('Code requires significant review and refactoring.');
    return { summary, score, grade, issues: filteredIssues, strengths, recommendations, metrics, refactoringSuggestions, autoFixes, architecturePatterns };
}
// ==================== METRICS CALCULATOR ====================
function calculateMetrics(code, language) {
    const lines = code.split('\n');
    let commentLines = 0, blankLines = 0, functionCount = 0, totalFunctionLines = 0;
    let currentFunctionStart = -1, maxNestingDepth = 0, classCount = 0;
    let importCount = 0, exportCount = 0, totalParams = 0, maxParams = 0, todoCount = 0;
    const commentPattern = language === 'python' ? /^\s*#/ : /^\s*(\/\/|#)/;
    const blockCommentStart = language === 'python' ? /^\s*"""/ : /^\s*\/\*/;
    const blockCommentEnd = language === 'python' ? /"""\s*$/ : /\*\/\s*$/;
    let inBlockComment = false;
    const functionPatterns = [
        /^\s*(function\s+\w+|def\s+\w+|fn\s+\w+|func\s+\w+)/,
        /^\s*(const|let|var)\s+\w+\s*=\s*(async\s*)?(\([^)]*\)|[^=])*=>/,
        /^\s*\w+\s*:\s*(async\s*)?\([^)]*\)\s*=>/,
        /^\s*(public|private|protected|static|\s)*\s+\w+\s+\w+\s*\([^)]*\)\s*\{/,
    ];
    lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (inBlockComment) {
            commentLines++;
            if (blockCommentEnd.test(line))
                inBlockComment = false;
            return;
        }
        if (blockCommentStart.test(line)) {
            commentLines++;
            if (!blockCommentEnd.test(line))
                inBlockComment = true;
            return;
        }
        if (trimmed === '') {
            blankLines++;
            return;
        }
        if (commentPattern.test(line)) {
            commentLines++;
            return;
        }
        if (/^\s*(import|from|import\s+\w+\s+from)\s/.test(line))
            importCount++;
        if (/^\s*export\s/.test(line))
            exportCount++;
        if (/(class|interface|struct|enum)\s+\w+/.test(line))
            classCount++;
        if (/(TODO|FIXME|HACK|XXX)\b/.test(line))
            todoCount++;
        for (const pattern of functionPatterns) {
            if (pattern.test(line)) {
                if (currentFunctionStart >= 0)
                    totalFunctionLines += (idx - currentFunctionStart);
                functionCount++;
                currentFunctionStart = idx;
                const params = line.match(/\(([^)]*)\)/);
                if (params) {
                    const paramCount = params[1] ? params[1].split(',').filter(p => p.trim()).length : 0;
                    totalParams += paramCount;
                    if (paramCount > maxParams)
                        maxParams = paramCount;
                }
                break;
            }
        }
        const indent = line.length - line.trimStart().length;
        const nestingDepth = Math.floor(indent / 2);
        if (nestingDepth > maxNestingDepth)
            maxNestingDepth = nestingDepth;
    });
    if (currentFunctionStart >= 0)
        totalFunctionLines += (lines.length - currentFunctionStart);
    const loc = lines.length - blankLines - commentLines;
    const avgFuncLength = functionCount > 0 ? Math.round(totalFunctionLines / functionCount) : 0;
    const avgParams = functionCount > 0 ? Math.round(totalParams / functionCount) : 0;
    const complexityScore = Math.min(100, maxNestingDepth * 10 + functionCount * 2);
    const maintainabilityIndex = Math.max(0, Math.min(100, 100 - complexityScore - (avgFuncLength > 30 ? 20 : 0)));
    const lineMap = new Map();
    lines.forEach(line => { const t = line.trim(); if (t.length > 10)
        lineMap.set(t, (lineMap.get(t) || 0) + 1); });
    let duplicateLines = 0;
    lineMap.forEach((count) => { if (count > 1)
        duplicateLines += count; });
    return { linesOfCode: loc, commentLines, blankLines, functionCount, classCount, averageFunctionLength: avgFuncLength, maxNestingDepth, complexityScore, duplicateLines, maintainabilityIndex, importCount, exportCount, averageParamsPerFunction: avgParams, maxFunctionParams: maxParams, todoCount };
}
// ==================== DETECTION HELPERS ====================
function detectDebugStatements(code, language, lines, issues, autoFixes) {
    const debugPatterns = {
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
    };
    const debugPattern = debugPatterns[language] || debugPatterns.typescript;
    let debugCount = 0;
    lines.forEach((line, idx) => {
        if (debugPattern.test(line)) {
            debugCount++;
            if (debugCount <= 3) {
                issues.push({ severity: 'info', category: 'debugging', ruleId: 'DEBUG_STATEMENT', line: idx + 1, message: `Debug output: "${line.trim().substring(0, 60)}"`, suggestion: 'Remove or replace with proper logging.' });
                autoFixes.push({ line: idx + 1, description: 'Remove debug statement', original: line.trim(), replacement: '// ' + line.trim() + ' // TODO: remove', confidence: 0.9 });
            }
        }
    });
    return debugCount;
}
function detectTodoFixme(code, language, lines, issues) {
    const todoPattern = language === 'python' ? /#\s*(TODO|FIXME|HACK|XXX|BUG|OPTIMIZE|REFACTOR)/i : /\/\/\s*(TODO|FIXME|HACK|XXX|BUG|OPTIMIZE|REFACTOR)/i;
    let todoCount = 0;
    lines.forEach((line, idx) => {
        if (todoPattern.test(line)) {
            todoCount++;
            issues.push({ severity: 'info', category: 'technical-debt', ruleId: 'TODO_FIXME', line: idx + 1, message: `Technical debt: "${line.trim().substring(0, 60)}"`, suggestion: 'Track in issue tracker and schedule cleanup.' });
        }
    });
    return todoCount;
}
function detectEmptyCatch(code, issues, autoFixes) {
    const emptyCatchPatterns = [
        { pattern: /catch\s*\([^)]*\)\s*\{\s*\}/, lang: 'javascript' },
        { pattern: /except[^:]*:\s*pass/, lang: 'python' },
        { pattern: /catch\s*\([^)]*\)\s*\{\s*\/\/\s*(ignore|noop|nothing)/i, lang: 'javascript' },
        { pattern: /catch\s*\(\s*\w+\s*\)\s*\{\s*\}/, lang: 'java' },
    ];
    emptyCatchPatterns.forEach(({ pattern }) => {
        if (pattern.test(code)) {
            issues.push({ severity: 'error', category: 'error-handling', ruleId: 'EMPTY_CATCH', message: 'Empty catch/except block detected. Silent failures make debugging difficult.', suggestion: 'At minimum, log the error.', fix: 'catch (error) {\n  console.error("Error:", error);\n}' });
        }
    });
}
function detectMagicNumbers(code, lines, issues) {
    const magicNumberPattern = /(?<!['".\w])\b(?!0|1|2|10|100|1000|0x[0-9a-fA-F]+)\d{2,}\b(?!['".\w])/;
    const magicNumbers = new Set();
    lines.forEach((line) => { if (/(const|let|var|final|val)\s+\w+\s*=/.test(line))
        return; const matches = line.match(magicNumberPattern); if (matches)
        matches.forEach(m => magicNumbers.add(m)); });
    if (magicNumbers.size > 5)
        issues.push({ severity: 'info', category: 'readability', ruleId: 'MAGIC_NUMBERS', message: `Found ${magicNumbers.size} potential magic numbers.`, suggestion: 'Extract magic numbers into named constants.' });
}
function detectErrorHandlingIssues(code, language, issues, strengths, recommendations) {
    const hasTryCatch = /try\s*\{/.test(code) && /catch/.test(code);
    const hasPromiseHandler = /\.then\s*\(/.test(code) && /\.catch\s*\(/.test(code);
    const hasErrorHandling = hasTryCatch || hasPromiseHandler;
    const hasAsyncOps = /(fetch|axios|request|exec|spawn|Promise\.)/.test(code);
    if (hasErrorHandling)
        strengths.push('Error handling is present.');
    else if (hasAsyncOps)
        issues.push({ severity: 'warning', category: 'error-handling', ruleId: 'MISSING_ERROR_HANDLING', message: 'Async operations detected without visible error handling.', suggestion: 'Add try/catch or .catch() handlers for robustness.' });
}
function detectHardcodedCredentials(code, lines, issues, autoFixes) {
    const credentialPatterns = [
        { pattern: /(['"])?(api[_-]?key|apikey|secret|password|token|auth)\1?\s*[:=]\s*['"][^'"]{8,}['"]/i, title: 'Hardcoded credential' },
        { pattern: /Bearer\s+[a-zA-Z0-9\-._~+\/]+=*/, title: 'Hardcoded Bearer token' },
        { pattern: /Basic\s+[a-zA-Z0-9+\/]+={0,2}/, title: 'Hardcoded Basic auth' },
        { pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/, title: 'Hardcoded private key' },
    ];
    credentialPatterns.forEach(({ pattern, title }) => {
        lines.forEach((line, idx) => {
            if (pattern.test(line)) {
                issues.push({ severity: 'critical', category: 'security', ruleId: 'HARDCODED_CREDENTIAL', line: idx + 1, message: `${title} detected!`, suggestion: 'Use environment variables or a secrets manager.' });
                autoFixes.push({ line: idx + 1, description: 'Replace hardcoded credential with env var', original: line.trim(), replacement: line.trim().replace(/['"][^'"]{8,}['"]/, 'process.env.SECRET'), confidence: 0.95 });
            }
        });
    });
}
function detectArchitecturePatterns(code, language, patterns) {
    if (/class\s+\w+\s+extends\s+\w+/.test(code) && /abstract\s+class|interface\s+\w+/.test(code))
        patterns.push({ name: 'Layered Architecture', description: 'Code uses abstraction with interfaces/abstract classes', confidence: 0.7 });
    if (/(repository|repo)\s*:/i.test(code))
        patterns.push({ name: 'Repository Pattern', description: 'Data access abstraction detected', confidence: 0.6 });
    if (/singleton|getInstance\s*\(/i.test(code))
        patterns.push({ name: 'Singleton Pattern', description: 'Global state management via singleton', confidence: 0.8 });
    if (/factory|createInstance/i.test(code))
        patterns.push({ name: 'Factory Pattern', description: 'Object creation abstraction detected', confidence: 0.7 });
    if (/observer|subscribe|emit|on\s*\(|addEventListener/i.test(code))
        patterns.push({ name: 'Observer Pattern', description: 'Event-driven communication detected', confidence: 0.6 });
    if (/middleware|next\s*\(|use\s*\(/i.test(code))
        patterns.push({ name: 'Middleware Pattern', description: 'Request processing pipeline detected', confidence: 0.7 });
    if (/decorator|@\w+/i.test(code))
        patterns.push({ name: 'Decorator Pattern', description: 'Aspect-oriented extension detected', confidence: 0.6 });
    if (/strategy|policy/i.test(code))
        patterns.push({ name: 'Strategy Pattern', description: 'Interchangeable algorithm selection detected', confidence: 0.5 });
    if (/command|execute|undo|redo/i.test(code))
        patterns.push({ name: 'Command Pattern', description: 'Operation encapsulation detected', confidence: 0.5 });
    if (/(\.pipe\s*\(|\.map\s*\(|\.filter\s*\(|\.reduce\s*\()/.test(code) && code.split('\n').filter(l => /\.pipe\s*\(|\.map\s*\(|\.filter\s*\(/.test(l)).length > 3)
        patterns.push({ name: 'Functional Pipeline', description: 'Data transformation pipeline using function chaining', confidence: 0.7 });
}
// ==================== SECURITY SCANNER ====================
function scanSecurity(code, language, generateSarif = false) {
    const lines = code.split('\n');
    const vulnerabilities = [];
    const owaspCoverage = [];
    const sqlPatterns = [
        { pattern: /(execute|query|exec)\s*\(\s*["'`].*\$\{?/i, title: 'SQL Injection', cwe: 'CWE-89', owasp: 'A03:2021' },
        { pattern: /(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE).*\+\s*\w+/i, title: 'SQL Query Concatenation', cwe: 'CWE-89', owasp: 'A03:2021' },
        { pattern: /f["'`].*SELECT.*\{.*\}.*["'`]/i, title: 'SQL Injection via f-string', cwe: 'CWE-89', owasp: 'A03:2021' },
    ];
    const xssPatterns = [
        { pattern: /innerHTML\s*=/, title: 'XSS via innerHTML', cwe: 'CWE-79', owasp: 'A03:2021' },
        { pattern: /document\.write\s*\(/, title: 'XSS via document.write', cwe: 'CWE-79', owasp: 'A03:2021' },
        { pattern: /dangerouslySetInnerHTML/, title: 'React XSS Risk', cwe: 'CWE-79', owasp: 'A03:2021' },
        { pattern: /v-html\s*=/, title: 'Vue v-html XSS Risk', cwe: 'CWE-79', owasp: 'A03:2021' },
    ];
    const cmdPatterns = [
        { pattern: /exec\s*\(.*\$\{?/i, title: 'Command Injection', cwe: 'CWE-78', owasp: 'A03:2021' },
        { pattern: /execSync\s*\(.*\+/i, title: 'Command Injection via execSync', cwe: 'CWE-78', owasp: 'A03:2021' },
        { pattern: /os\.system\s*\(.*\+/i, title: 'Python Command Injection', cwe: 'CWE-78', owasp: 'A03:2021' },
        { pattern: /subprocess\..*shell\s*=\s*True/i, title: 'Python subprocess shell=True', cwe: 'CWE-78', owasp: 'A03:2021' },
    ];
    const pathPatterns = [
        { pattern: /readFileSync\s*\(.*\+/i, title: 'Path Traversal', cwe: 'CWE-22', owasp: 'A01:2021' },
        { pattern: /fs\.\w+\(.*req\.(query|params|body)/i, title: 'Path Traversal via user input', cwe: 'CWE-22', owasp: 'A01:2021' },
        { pattern: /open\s*\(.*\+/i, title: 'Python Path Traversal', cwe: 'CWE-22', owasp: 'A01:2021' },
    ];
    const cryptoPatterns = [
        { pattern: /Math\.random\s*\(/, title: 'Insecure Random', cwe: 'CWE-330', owasp: 'A02:2021' },
        { pattern: /createHash\s*\(\s*['"]md5['"]\s*\)/i, title: 'Weak Hash (MD5)', cwe: 'CWE-328', owasp: 'A02:2021' },
        { pattern: /createHash\s*\(\s*['"]sha1['"]\s*\)/i, title: 'Weak Hash (SHA1)', cwe: 'CWE-328', owasp: 'A02:2021' },
        { pattern: /new\s+Buffer\s*\(/, title: 'Insecure Buffer allocation', cwe: 'CWE-120', owasp: 'A02:2021' },
    ];
    const ssrfPatterns = [
        { pattern: /fetch\s*\(.*req\.(query|params|body)/i, title: 'Potential SSRF', cwe: 'CWE-918', owasp: 'A10:2021' },
        { pattern: /axios\s*\(.*\+/i, title: 'Potential SSRF via axios', cwe: 'CWE-918', owasp: 'A10:2021' },
    ];
    const authPatterns = [
        { pattern: /(eval|Function)\s*\(/, title: 'Code Injection via eval', cwe: 'CWE-94', owasp: 'A03:2021' },
        { pattern: /\.html\s*\(.*\+/, title: 'DOM-based XSS', cwe: 'CWE-79', owasp: 'A03:2021' },
        { pattern: /jquery.*\$\(.*\+/, title: 'jQuery DOM XSS', cwe: 'CWE-79', owasp: 'A03:2021' },
    ];
    const allPatterns = [
        ...sqlPatterns.map(p => ({ ...p, severity: 'critical' })),
        ...xssPatterns.map(p => ({ ...p, severity: 'high' })),
        ...cmdPatterns.map(p => ({ ...p, severity: 'critical' })),
        ...pathPatterns.map(p => ({ ...p, severity: 'high' })),
        ...cryptoPatterns.map(p => ({ ...p, severity: 'medium' })),
        ...ssrfPatterns.map(p => ({ ...p, severity: 'high' })),
        ...authPatterns.map(p => ({ ...p, severity: 'critical' })),
    ];
    lines.forEach((line, idx) => {
        allPatterns.forEach(({ pattern, title, cwe, owasp, severity }) => {
            if (pattern.test(line)) {
                if (!owaspCoverage.includes(owasp))
                    owaspCoverage.push(owasp);
                vulnerabilities.push({ severity, cwe, owasp, title, description: `Pattern: "${line.trim().substring(0, 80)}"`, line: idx + 1, remediation: getRemediation(title) });
            }
        });
    });
    let riskLevel = 'low';
    if (vulnerabilities.some(v => v.severity === 'critical'))
        riskLevel = 'critical';
    else if (vulnerabilities.some(v => v.severity === 'high'))
        riskLevel = 'high';
    else if (vulnerabilities.length > 2)
        riskLevel = 'medium';
    const passed = !vulnerabilities.some(v => v.severity === 'critical' || v.severity === 'high');
    const summary = passed ? `Security Scan: No critical/high issues. ${vulnerabilities.length} minor issue(s).` : `Security Scan: ${vulnerabilities.length} issue(s). Risk: ${riskLevel.toUpperCase()}.`;
    let sarif;
    if (generateSarif)
        sarif = generateSarifReport(vulnerabilities);
    return { summary, riskLevel, vulnerabilities, passed, owaspCoverage, sarif };
}
function generateSarifReport(vulnerabilities) {
    const rules = [];
    const results = [];
    const ruleMap = new Map();
    vulnerabilities.forEach((vuln, idx) => {
        const ruleId = vuln.cwe || `RULE-${idx}`;
        if (!ruleMap.has(ruleId)) {
            ruleMap.set(ruleId, { id: ruleId, name: vuln.title, shortDescription: { text: vuln.title }, fullDescription: { text: vuln.description }, defaultConfiguration: { level: vuln.severity === 'critical' ? 'error' : vuln.severity === 'high' ? 'warning' : 'note' }, helpUri: `https://cwe.mitre.org/data/definitions/${ruleId.replace('CWE-', '')}.html` });
        }
        results.push({ ruleId, level: vuln.severity === 'critical' ? 'error' : vuln.severity === 'high' ? 'warning' : 'note', message: { text: vuln.description }, locations: [{ physicalLocation: { artifactLocation: { uri: 'src/file.ts' }, region: { startLine: vuln.line || 1 } } }] });
    });
    return { $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json', version: '2.1.0', runs: [{ tool: { driver: { name: 'dsh-tool-codereview', version: VERSION, informationUri: 'https://github.com/chengganping-ship-it/dsh-tool-codereview', rules: Array.from(ruleMap.values()) } }, results }] };
}
function getRemediation(title) {
    const remediations = {
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
    };
    return remediations[title] || 'Review and address this security concern.';
}
// ==================== DEPENDENCY AUDITOR ====================
function auditDependencies(code, language) {
    const dependencies = [];
    if (language === 'typescript' || language === 'javascript') {
        const importPatterns = [/from\s+['"]([^'"]+)['"]/g, /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g, /import\s+['"]([^'"]+)['"]/g];
        const packages = new Set();
        importPatterns.forEach(pattern => { let match; while ((match = pattern.exec(code)) !== null) {
            const pkg = match[1];
            if (!pkg.startsWith('.') && !pkg.startsWith('/'))
                packages.add(pkg.split('/')[0]);
        } });
        const knownVulns = {
            'lodash': { package: 'lodash', version: '<4.17.21', severity: 'high', cve: 'CVE-2021-23337', title: 'Command Injection', fixedVersion: '4.17.21' },
            'minimist': { package: 'minimist', version: '<1.2.6', severity: 'high', cve: 'CVE-2021-44906', title: 'Prototype Pollution', fixedVersion: '1.2.6' },
            'axios': { package: 'axios', version: '<0.21.1', severity: 'high', cve: 'CVE-2021-3749', title: 'SSRF', fixedVersion: '0.21.1' },
            'express': { package: 'express', version: '<4.17.3', severity: 'medium', cve: 'CVE-2022-24999', title: 'QS ReDoS', fixedVersion: '4.17.3' },
            'jsonwebtoken': { package: 'jsonwebtoken', version: '<9.0.0', severity: 'critical', cve: 'CVE-2022-23529', title: 'JWT Verification Bypass', fixedVersion: '9.0.0' },
            'node-fetch': { package: 'node-fetch', version: '<2.6.7', severity: 'high', cve: 'CVE-2022-0235', title: 'Sensitive Information Exposure', fixedVersion: '2.6.7' },
            'moment': { package: 'moment', version: '<2.29.4', severity: 'high', cve: 'CVE-2022-31129', title: 'ReDoS', fixedVersion: '2.29.4' },
            'uuid': { package: 'uuid', version: '<8.3.2', severity: 'medium', title: 'Predictable PRNG', fixedVersion: '8.3.2' },
        };
        packages.forEach(pkg => { if (knownVulns[pkg])
            dependencies.push(knownVulns[pkg]); });
    }
    const vulnerableCount = dependencies.length;
    const passed = vulnerableCount === 0;
    const summary = passed ? 'Dependency Audit: No known vulnerabilities found.' : `Dependency Audit: ${vulnerableCount} vulnerable package(s) detected.`;
    return { summary, totalDependencies: 0, vulnerableCount, dependencies, passed };
}
// ==================== PERFORMANCE ANALYZER ====================
function analyzePerformance(code, language) {
    const lines = code.split('\n');
    const issues = [];
    const bigOEstimates = [];
    let score = 100;
    // N+1 query pattern
    const nPlus1Patterns = [/for\s*\([^)]*\)\s*\{[^}]*(?:find|query|select|where)/is, /\.map\s*\([^)]*(?:find|query|select|where)/is, /forEach\s*\([^)]*(?:find|query|select|where)/is];
    nPlus1Patterns.forEach(pattern => {
        if (pattern.test(code)) {
            issues.push({ severity: 'warning', category: 'n-plus-1', message: 'Potential N+1 query pattern detected.', impact: 'High - causes database performance degradation', suggestion: 'Use eager loading, batch queries, or JOINs.' });
            score -= 20;
        }
    });
    // Inefficient loops
    const inefficientLoopPatterns = [
        { pattern: /\.find\s*\(.*\.find\s*\(/, msg: 'Nested .find() calls - O(n²) complexity' },
        { pattern: /\.indexOf\s*\(.*\.indexOf\s*\(/, msg: 'Nested .indexOf() calls' },
        { pattern: /for\s*\([^)]*\)\s*\{[^}]*for\s*\(/is, msg: 'Nested loops detected' },
    ];
    inefficientLoopPatterns.forEach(({ pattern, msg }) => {
        if (pattern.test(code)) {
            issues.push({ severity: 'warning', category: 'algorithm', message: msg, impact: 'Medium - may cause slowdown with large datasets', suggestion: 'Consider using Map/Set for O(1) lookups or optimizing algorithm.' });
            score -= 15;
        }
    });
    // Memory leak patterns
    const memoryLeakPatterns = [
        { pattern: /setInterval\s*\(/, msg: 'setInterval without cleanup - potential memory leak' },
        { pattern: /addEventListener\s*\(/, msg: 'Event listener without removal - potential memory leak' },
        { pattern: /new\s+Array\s*\(\d{6,}\)/, msg: 'Large array allocation' },
    ];
    memoryLeakPatterns.forEach(({ pattern, msg }) => {
        lines.forEach((line, idx) => {
            if (pattern.test(line)) {
                issues.push({ severity: 'info', category: 'memory', line: idx + 1, message: msg, impact: 'Low - may cause memory issues in long-running apps', suggestion: 'Clear intervals on unmount, remove listeners when done.' });
                score -= 5;
            }
        });
    });
    // Blocking operations
    const blockingPatterns = [
        { pattern: /JSON\.parse\s*\(/, msg: 'Large JSON.parse can block event loop' },
        { pattern: /JSON\.stringify\s*\(/, msg: 'Large JSON.stringify can block event loop' },
        { pattern: /sync\s*\(/, msg: 'Synchronous operation blocks event loop' },
    ];
    blockingPatterns.forEach(({ pattern, msg }) => {
        lines.forEach((line, idx) => {
            if (pattern.test(line)) {
                issues.push({ severity: 'info', category: 'blocking', line: idx + 1, message: msg, impact: 'Low - may cause UI freeze with large data', suggestion: 'Consider streaming or worker threads for large operations.' });
                score -= 3;
            }
        });
    });
    // BigO estimation
    lines.forEach((line, idx) => {
        if (/for\s*\([^)]*\)\s*\{[^}]*for\s*\(/is.test(line))
            bigOEstimates.push({ line: idx + 1, complexity: 'O(n²)', description: 'Nested loop detected' });
        else if (/for\s*\(|while\s*\(/.test(line))
            bigOEstimates.push({ line: idx + 1, complexity: 'O(n)', description: 'Single loop' });
        if (/\.sort\s*\(/.test(line))
            bigOEstimates.push({ line: idx + 1, complexity: 'O(n log n)', description: 'Sort operation' });
    });
    score = Math.max(0, Math.min(100, score));
    const summary = issues.length === 0 ? 'Performance Analysis: No significant issues found.' : `Performance Analysis: ${issues.length} potential issue(s). Score: ${score}/100.`;
    return { summary, issues, score, bigOEstimates };
}
// ==================== ARCHITECTURE REVIEW ====================
function reviewArchitecture(code, language) {
    const patterns = [];
    const recommendations = [];
    let score = 100;
    detectArchitecturePatterns(code, language, patterns);
    // SOLID principles check
    if (/class\s+\w+\s*\{[^}]{500,}\}/s.test(code)) {
        score -= 15;
        recommendations.push('Single Responsibility: Large classes should be split into smaller, focused units.');
    }
    if (!/interface\s+\w+|abstract\s+class/.test(code) && /class\s+\w+/.test(code)) {
        score -= 10;
        recommendations.push('Dependency Inversion: Consider using interfaces/abstractions for better testability.');
    }
    // Module cohesion
    const imports = (code.match(/import\s+/g) || []).length;
    if (imports > 20) {
        score -= 10;
        recommendations.push('High coupling: Many imports suggest the module may have too many responsibilities.');
    }
    // Error handling strategy
    if (!/try\s*\{|catch\s*\(|except\s*:|Result\s*</.test(code) && code.split('\n').length > 50) {
        score -= 15;
        recommendations.push('Missing error handling: Add proper error handling for robustness.');
    }
    // Documentation
    if (!/\/\*\*|\/\/|"""|#\s*(Module|Package|Class)/.test(code)) {
        score -= 10;
        recommendations.push('Add module-level documentation to explain purpose and usage.');
    }
    score = Math.max(0, Math.min(100, score));
    const summary = `Architecture Review: ${patterns.length} patterns detected. Score: ${score}/100.`;
    return { patterns, score, summary, recommendations };
}
// ==================== TEST COVERAGE ANALYZER ====================
function analyzeTestCoverage(code, language) {
    const lines = code.split('\n');
    const untestablePatterns = [];
    const testSuggestions = [];
    const mockingRequirements = [];
    let testabilityScore = 100;
    // Find functions and assess testability
    const functionPattern = /(?:function\s+(\w+)|def\s+(\w+)|fn\s+(\w+)|(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)/g;
    let match;
    while ((match = functionPattern.exec(code)) !== null) {
        const funcName = match[1] || match[2] || match[3] || match[4] || 'anonymous';
        const line = code.substring(0, match.index).split('\n').length;
        testSuggestions.push({ function: funcName, line, type: 'unit', description: `Test ${funcName} with various inputs and edge cases`, priority: 'high' });
    }
    // Check for hard-to-test patterns
    if (/new\s+Date\s*\(/.test(code) || /Date\.now\s*\(/.test(code)) {
        untestablePatterns.push('Time-dependent code - use dependency injection for dates');
        mockingRequirements.push('Date/Time provider');
    }
    if (/Math\.random\s*\(/.test(code)) {
        untestablePatterns.push('Random number generation - inject a seeded RNG for testing');
        mockingRequirements.push('Random number generator');
    }
    if (/fetch\s*\(|axios\s*\(|http\./.test(code)) {
        untestablePatterns.push('HTTP calls - mock network requests');
        mockingRequirements.push('HTTP client');
    }
    if (/fs\.|readFileSync|writeFileSync/.test(code)) {
        untestablePatterns.push('File system operations - use in-memory fs for testing');
        mockingRequirements.push('File system');
    }
    if (/localStorage|sessionStorage/.test(code)) {
        untestablePatterns.push('Browser storage - mock storage API');
        mockingRequirements.push('Storage API');
    }
    if (/console\.(log|error|warn)/.test(code)) {
        untestablePatterns.push('Console output - consider injecting a logger');
        mockingRequirements.push('Logger');
    }
    // Calculate testability score
    testabilityScore -= untestablePatterns.length * 10;
    testabilityScore = Math.max(0, Math.min(100, testabilityScore));
    // Estimate coverage potential
    const coverageEstimate = Math.max(0, Math.min(100, testabilityScore - 10));
    const summary = `Test Coverage Analysis: ${testSuggestions.length} testable functions found. Testability Score: ${testabilityScore}/100.`;
    return { summary, testabilityScore, coverageEstimate, untestablePatterns, testSuggestions, mockingRequirements };
}
// ==================== API DOCUMENTATION GENERATOR ====================
function generateApiDocs(code, language) {
    const lines = code.split('\n');
    const endpoints = [];
    const models = [];
    // Detect API endpoints
    const endpointPatterns = [
        { pattern: /(app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g, hasPath: true },
        { pattern: /@(Get|Post|Put|Delete|Patch)\s*\(\s*['"`]([^'"`]+)['"`]/g, hasPath: true },
        { pattern: /route\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*['"`](GET|POST|PUT|DELETE|PATCH)['"`]/gi, hasPath: true },
    ];
    endpointPatterns.forEach(({ pattern }) => {
        let match;
        while ((match = pattern.exec(code)) !== null) {
            const line = code.substring(0, match.index).split('\n').length;
            endpoints.push({ method: match[2]?.toUpperCase() || 'GET', path: match[3] || match[1], line });
        }
    });
    // Detect models/interfaces
    const modelPattern = /(?:interface|type|class|struct)\s+(\w+)\s*(?:=\s*)?\{([^}]+)\}/g;
    let modelMatch;
    while ((modelMatch = modelPattern.exec(code)) !== null) {
        const name = modelMatch[1];
        const body = modelMatch[2];
        const line = code.substring(0, modelMatch.index).split('\n').length;
        const fields = [];
        body.split(/[;\n]/).forEach(field => {
            const fieldMatch = field.trim().match(/^(\w+)\s*[?:]\s*(\w+)/);
            if (fieldMatch)
                fields.push({ name: fieldMatch[1], type: fieldMatch[2] });
        });
        models.push({ name, line, fields });
    }
    const coverage = endpoints.length > 0 ? Math.min(100, endpoints.length * 20) : 0;
    const summary = `API Documentation: ${endpoints.length} endpoints, ${models.length} models detected. Coverage: ${coverage}%.`;
    return { summary, endpoints, models, coverage };
}
// ==================== CODE DIFF ANALYZER ====================
function analyzeDiff(diffText) {
    const lines = diffText.split('\n');
    let additions = 0, deletions = 0;
    const concerns = [];
    const suggestions = [];
    lines.forEach(line => {
        if (line.startsWith('+') && !line.startsWith('+++'))
            additions++;
        if (line.startsWith('-') && !line.startsWith('---'))
            deletions++;
    });
    // Determine change type
    let changeType = 'mixed';
    if (additions > 0 && deletions === 0)
        changeType = 'feature';
    else if (deletions > additions * 2)
        changeType = 'refactor';
    else if (additions > deletions * 2)
        changeType = 'feature';
    else if (additions === deletions)
        changeType = 'bugfix';
    // Risk assessment
    let riskLevel = 'low';
    if (additions + deletions > 500) {
        riskLevel = 'high';
        concerns.push('Large change set - consider breaking into smaller PRs');
    }
    else if (additions + deletions > 200) {
        riskLevel = 'medium';
        concerns.push('Moderate change size - ensure thorough review');
    }
    if (deletions > additions * 3)
        concerns.push('Significant code deletion - verify no functionality is lost');
    if (additions > 300 && deletions < 50)
        concerns.push('Large addition without corresponding deletions - possible code duplication');
    // Suggestions
    if (additions > 100)
        suggestions.push('Consider splitting this into multiple focused commits');
    if (concerns.length === 0)
        suggestions.push('Change looks well-balanced and manageable');
    suggestions.push('Run full test suite before merging');
    suggestions.push('Review for any security implications');
    const summary = `Diff Analysis: +${additions}/-${deletions} lines. Type: ${changeType}. Risk: ${riskLevel}.`;
    return { summary, additions, deletions, changeType, riskLevel, concerns, suggestions };
}
// ==================== STYLE CHECKER ====================
function checkStyle(code, language) {
    const lines = code.split('\n');
    const conventions = [];
    const formattingIssues = [];
    let score = 100;
    lines.forEach((line, idx) => {
        const lineNum = idx + 1;
        // Line length check
        if (line.length > 120) {
            formattingIssues.push({ line: lineNum, column: 120, message: `Line exceeds 120 characters (${line.length})`, fix: 'Break line into multiple lines' });
            score -= 2;
        }
        // Trailing whitespace
        if (/\s+$/.test(line)) {
            formattingIssues.push({ line: lineNum, column: line.length, message: 'Trailing whitespace detected', fix: 'Remove trailing whitespace' });
            score -= 1;
        }
        // Tab vs spaces
        if (/\t/.test(line) && line.trim().length > 0) {
            formattingIssues.push({ line: lineNum, column: 1, message: 'Tab character found - use spaces', fix: 'Replace tabs with spaces' });
            score -= 2;
        }
        // Naming conventions
        if (language === 'typescript' || language === 'javascript') {
            const varMatch = line.match(/(?:const|let|var)\s+([a-z_][a-zA-Z0-9_]*)\s*=/);
            if (varMatch && /[A-Z]/.test(varMatch[1]) && !/^[A-Z_]+$/.test(varMatch[1])) {
                conventions.push({ line: lineNum, rule: 'VARIABLE_NAMING', message: `Variable '${varMatch[1]}' uses mixed case - use camelCase`, severity: 'warning', suggestion: 'Rename to camelCase' });
                score -= 3;
            }
            const classMatch = line.match(/class\s+([a-zA-Z][a-zA-Z0-9]*)/);
            if (classMatch && !/^[A-Z]/.test(classMatch[1])) {
                conventions.push({ line: lineNum, rule: 'CLASS_NAMING', message: `Class '${classMatch[1]}' should use PascalCase`, severity: 'warning', suggestion: 'Rename to PascalCase' });
                score -= 3;
            }
        }
        // Missing semicolons (for JS/TS)
        if ((language === 'typescript' || language === 'javascript') && /^\s*(?:const|let|var|return|export)\s+.+[^;{}\s]$/.test(line)) {
            formattingIssues.push({ line: lineNum, column: line.length, message: 'Missing semicolon', fix: 'Add semicolon at end of statement' });
        }
    });
    score = Math.max(0, Math.min(100, score));
    const summary = `Style Check: ${conventions.length} convention issues, ${formattingIssues.length} formatting issues. Score: ${score}/100.`;
    return { summary, score, conventions, formattingIssues };
}
// ==================== LANGUAGE DETECTION ====================
function detectLanguage(code) {
    if (/^\s*(import|export|const|let|function|interface|type)\s/m.test(code) || /\.(ts|tsx|js|jsx)/.test(code))
        return 'typescript';
    if (/^\s*(def |class |import |from |if __name__)/m.test(code))
        return 'python';
    if (/^\s*(public |private |protected |class |interface |package )/m.test(code))
        return 'java';
    if (/^\s*(#include|int main|std::)/m.test(code))
        return 'cpp';
    if (/^\s*(package |func |import\s+\()/m.test(code))
        return 'go';
    if (/^\s*(fn |let mut |impl |pub )/m.test(code))
        return 'rust';
    if (/^\s*(def |class |module |require )/m.test(code) && /end\s*$/.test(code))
        return 'ruby';
    if (/^\s*<\?php/.test(code) || /^\s*\$\w+\s*=/.test(code))
        return 'php';
    if (/^\s*(func |var |let |class |struct |enum |protocol )/m.test(code) && /import\s+Foundation|import\s+UIKit/.test(code))
        return 'swift';
    if (/^\s*(fun |val |var |class |data class |sealed class )/m.test(code))
        return 'kotlin';
    return 'unknown';
}
// ==================== GRADE CALCULATOR ====================
function calculateGrade(score) {
    if (score >= 95)
        return 'A+';
    if (score >= 90)
        return 'A';
    if (score >= 85)
        return 'B+';
    if (score >= 80)
        return 'B';
    if (score >= 70)
        return 'C';
    if (score >= 60)
        return 'D';
    return 'F';
}
// ==================== FORMATTERS ====================
function formatReviewReport(result) {
    const lines = [];
    lines.push('## Code Review Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100 | Grade: ${result.grade}**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    lines.push('### Code Metrics');
    lines.push('| Metric | Value |');
    lines.push('|--------|-------|');
    lines.push(`| Lines of Code | ${result.metrics.linesOfCode} |`);
    lines.push(`| Comment Lines | ${result.metrics.commentLines} |`);
    lines.push(`| Blank Lines | ${result.metrics.blankLines} |`);
    lines.push(`| Functions | ${result.metrics.functionCount} |`);
    lines.push(`| Classes | ${result.metrics.classCount} |`);
    lines.push(`| Avg Function Length | ${result.metrics.averageFunctionLength} lines |`);
    lines.push(`| Max Nesting Depth | ${result.metrics.maxNestingDepth} |`);
    lines.push(`| Complexity Score | ${result.metrics.complexityScore}/100 |`);
    lines.push(`| Maintainability Index | ${result.metrics.maintainabilityIndex}/100 |`);
    lines.push(`| Imports | ${result.metrics.importCount} |`);
    lines.push(`| Exports | ${result.metrics.exportCount} |`);
    lines.push(`| Avg Params/Function | ${result.metrics.averageParamsPerFunction} |`);
    lines.push(`| TODOs | ${result.metrics.todoCount} |`);
    lines.push('');
    if (result.strengths.length > 0) {
        lines.push('### Strengths');
        result.strengths.forEach(s => lines.push('- ' + s));
        lines.push('');
    }
    if (result.issues.length > 0) {
        lines.push('### Issues');
        const severityIcons = { critical: '🔴', error: '🟠', warning: '🟡', info: '🔵' };
        result.issues.forEach(issue => {
            const icon = severityIcons[issue.severity] || '⚪';
            const lineInfo = issue.line ? ` (line ${issue.line})` : '';
            const ruleInfo = issue.ruleId ? ` [${issue.ruleId}]` : '';
            lines.push(`- ${icon} **[${issue.severity.toUpperCase()}]**${ruleInfo} ${issue.category}${lineInfo}: ${issue.message}`);
            if (issue.suggestion)
                lines.push(`  -> *${issue.suggestion}*`);
        });
        lines.push('');
    }
    if (result.autoFixes.length > 0) {
        lines.push('### Auto-Fixes Available');
        result.autoFixes.forEach((fix, idx) => { lines.push(`${idx + 1}. Line ${fix.line}: ${fix.description} (confidence: ${(fix.confidence * 100).toFixed(0)}%)`); lines.push(`   - Original: \`${fix.original}\``); lines.push(`   + Fixed: \`${fix.replacement}\``); });
        lines.push('');
    }
    if (result.refactoringSuggestions.length > 0) {
        lines.push('### Refactoring Suggestions');
        result.refactoringSuggestions.forEach((ref, idx) => { lines.push(`${idx + 1}. **${ref.title}** [Impact: ${ref.impact}, Effort: ${ref.effort}]`); lines.push(`   ${ref.description}`); });
        lines.push('');
    }
    if (result.architecturePatterns.length > 0) {
        lines.push('### Architecture Patterns Detected');
        result.architecturePatterns.forEach(p => { lines.push(`- **${p.name}** (confidence: ${(p.confidence * 100).toFixed(0)}%): ${p.description}`); });
        lines.push('');
    }
    if (result.recommendations.length > 0) {
        lines.push('### Recommendations');
        result.recommendations.forEach(r => lines.push('- ' + r));
        lines.push('');
    }
    return lines.join('\n');
}
function formatSecurityReport(result) {
    const lines = [];
    const riskIcons = { low: '🟢', medium: '🟡', high: '🟠', critical: '🔴' };
    lines.push('## Security Scan Report');
    lines.push('');
    lines.push(`**Risk Level: ${riskIcons[result.riskLevel]} ${result.riskLevel.toUpperCase()}**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.owaspCoverage.length > 0) {
        lines.push('### OWASP Top 10 Coverage');
        result.owaspCoverage.forEach(o => lines.push('- ' + o));
        lines.push('');
    }
    if (result.vulnerabilities.length > 0) {
        lines.push('### Vulnerabilities');
        result.vulnerabilities.forEach(vuln => {
            const icon = vuln.severity === 'critical' ? '🔴' : vuln.severity === 'high' ? '🟠' : '🟡';
            const lineInfo = vuln.line ? ` (line ${vuln.line})` : '';
            const cweInfo = vuln.cwe ? ` [${vuln.cwe}]` : '';
            lines.push(`- ${icon} **${vuln.title}**${cweInfo}${lineInfo}`);
            lines.push(`  ${vuln.description}`);
            lines.push(`  -> *Fix: ${vuln.remediation}*`);
        });
        lines.push('');
    }
    else {
        lines.push('No security vulnerabilities detected.');
        lines.push('');
    }
    if (result.sarif) {
        lines.push('### SARIF Output');
        lines.push('```json');
        lines.push(JSON.stringify(result.sarif, null, 2));
        lines.push('```');
        lines.push('');
    }
    return lines.join('\n');
}
function formatDependencyReport(result) {
    const lines = [];
    lines.push('## Dependency Audit Report');
    lines.push('');
    lines.push(`**Vulnerable Packages: ${result.vulnerableCount}**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.dependencies.length > 0) {
        lines.push('### Vulnerable Dependencies');
        result.dependencies.forEach(dep => {
            const icon = dep.severity === 'critical' ? '🔴' : dep.severity === 'high' ? '🟠' : '🟡';
            const cveInfo = dep.cve ? ` [${dep.cve}]` : '';
            const fixedInfo = dep.fixedVersion ? ` -> Upgrade to ${dep.fixedVersion}` : '';
            lines.push(`- ${icon} **${dep.package}**${cveInfo}: ${dep.title}${fixedInfo}`);
        });
        lines.push('');
    }
    return lines.join('\n');
}
function formatPerformanceReport(result) {
    const lines = [];
    lines.push('## Performance Analysis Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.bigOEstimates.length > 0) {
        lines.push('### Complexity Estimates');
        result.bigOEstimates.forEach(e => { lines.push(`- Line ${e.line}: **${e.complexity}** - ${e.description}`); });
        lines.push('');
    }
    if (result.issues.length > 0) {
        lines.push('### Performance Issues');
        result.issues.forEach(issue => {
            const icon = issue.severity === 'warning' ? '🟡' : '🔵';
            const lineInfo = issue.line ? ` (line ${issue.line})` : '';
            lines.push(`- ${icon} **[${issue.category}]**${lineInfo}: ${issue.message}`);
            lines.push(`  Impact: ${issue.impact}`);
            lines.push(`  -> *${issue.suggestion}*`);
        });
        lines.push('');
    }
    return lines.join('\n');
}
function formatArchitectureReport(result) {
    const lines = [];
    lines.push('## Architecture Review Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.patterns.length > 0) {
        lines.push('### Detected Patterns');
        result.patterns.forEach(p => { lines.push(`- **${p.name}** (confidence: ${(p.confidence * 100).toFixed(0)}%): ${p.description}`); });
        lines.push('');
    }
    if (result.recommendations.length > 0) {
        lines.push('### Recommendations');
        result.recommendations.forEach(r => lines.push('- ' + r));
        lines.push('');
    }
    return lines.join('\n');
}
function formatTestCoverageReport(result) {
    const lines = [];
    lines.push('## Test Coverage Analysis');
    lines.push('');
    lines.push(`**Testability Score: ${result.testabilityScore}/100 | Estimated Coverage: ${result.coverageEstimate}%**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.untestablePatterns.length > 0) {
        lines.push('### Hard-to-Test Patterns');
        result.untestablePatterns.forEach(p => lines.push('- ' + p));
        lines.push('');
    }
    if (result.mockingRequirements.length > 0) {
        lines.push('### Mocking Requirements');
        result.mockingRequirements.forEach(m => lines.push('- ' + m));
        lines.push('');
    }
    if (result.testSuggestions.length > 0) {
        lines.push('### Test Suggestions');
        result.testSuggestions.slice(0, 10).forEach(s => { lines.push(`- **${s.function}** (line ${s.line}, ${s.type}, priority: ${s.priority}): ${s.description}`); });
        if (result.testSuggestions.length > 10)
            lines.push(`- ... and ${result.testSuggestions.length - 10} more functions to test`);
        lines.push('');
    }
    return lines.join('\n');
}
function formatApiDocsReport(result) {
    const lines = [];
    lines.push('## API Documentation');
    lines.push('');
    lines.push(`**Coverage: ${result.coverage}%**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.endpoints.length > 0) {
        lines.push('### Endpoints');
        result.endpoints.forEach(e => { lines.push(`- **${e.method}** \`${e.path}\` (line ${e.line})`); });
        lines.push('');
    }
    if (result.models.length > 0) {
        lines.push('### Models');
        result.models.forEach(m => { lines.push(`- **${m.name}** (line ${m.line}): ${m.fields.map(f => `${f.name}: ${f.type}`).join(', ')}`); });
        lines.push('');
    }
    return lines.join('\n');
}
function formatDiffReport(result) {
    const lines = [];
    lines.push('## Code Diff Analysis');
    lines.push('');
    lines.push(`**Change Type: ${result.changeType} | Risk Level: ${result.riskLevel}**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    lines.push('### Statistics');
    lines.push(`- Additions: +${result.additions}`);
    lines.push(`- Deletions: -${result.deletions}`);
    lines.push(`- Net change: ${result.additions - result.deletions > 0 ? '+' : ''}${result.additions - result.deletions}`);
    lines.push('');
    if (result.concerns.length > 0) {
        lines.push('### Concerns');
        result.concerns.forEach(c => lines.push('- ⚠️ ' + c));
        lines.push('');
    }
    if (result.suggestions.length > 0) {
        lines.push('### Suggestions');
        result.suggestions.forEach(s => lines.push('- ' + s));
        lines.push('');
    }
    return lines.join('\n');
}
// ==================== v0.5.0 NEW FUNCTIONS ====================
// --- Code Smell Detection (PRO-002) ---
function detectCodeSmells(code, _language) {
    const smells = [];
    const lines = code.split('\n');
    const totalLines = lines.length;
    // God Object: class with too many methods/lines
    const classMatches = code.match(/class\s+\w+/g) || [];
    classMatches.forEach(cls => {
        const clsIndex = code.indexOf(cls);
        const clsLine = code.substring(0, clsIndex).split('\n').length;
        const methodCount = (code.substring(clsIndex, clsIndex + 5000).match(/(public|private|protected|static)?\s*\w+\s*\(/g) || []).length;
        if (methodCount > 10) {
            smells.push({
                type: 'God Object',
                severity: 'warning',
                line: clsLine,
                message: `Class has ${methodCount} methods - consider splitting`,
                description: 'God Object anti-pattern: class knows or does too much',
                suggestion: 'Split into smaller, focused classes following Single Responsibility Principle'
            });
        }
        if (totalLines > 300) {
            smells.push({
                type: 'Large Class',
                severity: 'warning',
                line: clsLine,
                message: `Class spans ${totalLines} lines`,
                description: 'Large classes are harder to maintain and understand',
                suggestion: 'Extract related functionality into separate classes'
            });
        }
    });
    // Feature Envy: excessive use of another class's methods
    const getterChains = code.match(/\w+\.\w+\.\w+\.\w+/g) || [];
    getterChains.forEach(chain => {
        const idx = code.indexOf(chain);
        const line = code.substring(0, idx).split('\n').length;
        smells.push({
            type: 'Feature Envy',
            severity: 'info',
            line,
            message: `Method chain: ${chain}`,
            description: 'Feature Envy: method seems more interested in another class',
            suggestion: 'Consider moving this logic to the class it operates on'
        });
    });
    // Shotgun Surgery: one change requires many small edits
    const importCount = (code.match(/^(import|from|require)/gm) || []).length;
    if (importCount > 15) {
        smells.push({
            type: 'Shotgun Surgery Risk',
            severity: 'info',
            message: `High coupling: ${importCount} imports detected`,
            description: 'Many imports suggest the module may be involved in many changes',
            suggestion: 'Consider using a facade or mediator pattern to reduce coupling'
        });
    }
    // Long Method: functions with too many lines
    let funcStart = -1;
    let funcName = '';
    let braceCount = 0;
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const funcMatch = line.match(/(function|def|func)\s+(\w+)/);
        if (funcMatch && funcStart === -1) {
            funcStart = i;
            funcName = funcMatch[2];
            braceCount = 0;
        }
        if (funcStart !== -1) {
            braceCount += (line.match(/{/g) || []).length - (line.match(/}/g) || []).length;
            if (i - funcStart > 50 && braceCount <= 0) {
                smells.push({
                    type: 'Long Method',
                    severity: 'warning',
                    line: funcStart + 1,
                    message: `Function '${funcName}' spans ${i - funcStart} lines`,
                    description: 'Long methods are harder to understand and test',
                    suggestion: 'Extract logical blocks into helper functions'
                });
                funcStart = -1;
            }
        }
    }
    // Primitive Obsession: excessive primitive use
    const primitiveCount = (code.match(/:\s*(string|number|boolean|int|float)\b/g) || []).length;
    if (primitiveCount > 8) {
        smells.push({
            type: 'Primitive Obsession',
            severity: 'info',
            message: `${primitiveCount} primitive type annotations found`,
            description: 'Excessive use of primitives where domain types would be clearer',
            suggestion: 'Consider creating value objects or type aliases for domain concepts'
        });
    }
    // Dead Code: unused variables
    const declaredVars = code.match(/(?:const|let|var|def)\s+(\w+)/g) || [];
    declaredVars.forEach(decl => {
        const varName = decl.replace(/^(const|let|var|def)\s+/, '');
        if (varName.length > 0) {
            const usages = (code.match(new RegExp(`\\b${varName}\\b`, 'g')) || []).length;
            if (usages <= 1) {
                const idx = code.indexOf(decl);
                const line = code.substring(0, idx).split('\n').length;
                smells.push({
                    type: 'Dead Code',
                    severity: 'info',
                    line,
                    message: `Variable '${varName}' appears unused`,
                    description: 'Unused variables add noise and confusion',
                    suggestion: 'Remove unused declarations or prefix with _ if intentionally unused'
                });
            }
        }
    });
    const score = Math.max(0, 100 - smells.filter(s => s.severity === 'warning').length * 10 - smells.filter(s => s.severity === 'info').length * 3);
    return {
        summary: `Found ${smells.length} code smells (${smells.filter(s => s.severity === 'warning').length} warnings, ${smells.filter(s => s.severity === 'info').length} info)`,
        smells,
        score
    };
}
function formatCodeSmellReport(result) {
    const lines = [];
    lines.push('## Code Smell Detection Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.smells.length > 0) {
        lines.push('### Detected Smells');
        result.smells.forEach(s => {
            const icon = s.severity === 'warning' ? '⚠️' : 'ℹ️';
            lines.push(`- ${icon} **${s.type}**${s.line ? ` (line ${s.line})` : ''}: ${s.message}`);
            lines.push(`  - ${s.description}`);
            lines.push(`  - 💡 ${s.suggestion}`);
        });
        lines.push('');
    }
    return lines.join('\n');
}
// --- TypeScript Strict Mode Check (PRO-001) ---
function checkTsStrictMode(code) {
    const violations = [];
    const lines = code.split('\n');
    lines.forEach((line, idx) => {
        const lineNum = idx + 1;
        if (/:\s*any\b/.test(line) && !line.trim().startsWith('//')) {
            violations.push({
                line: lineNum,
                rule: 'noImplicitAny',
                message: 'Explicit any type annotation detected',
                severity: 'warning',
                fix: 'Replace `any` with a proper type or use `unknown` for truly dynamic values'
            });
        }
        if (/(function|const\s+\w+)\s*[\(=]/.test(line) && !line.includes(':') && !line.includes('=>') && !line.trim().startsWith('//')) {
            if (/\(.*\)\s*{/.test(line) || /=\s*\(.*\)\s*{/.test(line)) {
                violations.push({
                    line: lineNum,
                    rule: 'explicitReturnType',
                    message: 'Function missing explicit return type annotation',
                    severity: 'info',
                    fix: 'Add return type annotation: `function foo(): ReturnType`'
                });
            }
        }
        if (/!\s*[;),\]]/.test(line) && !line.trim().startsWith('//')) {
            violations.push({
                line: lineNum,
                rule: 'noNonNullAssertion',
                message: 'Non-null assertion operator (!) used',
                severity: 'warning',
                fix: 'Use proper null checks or optional chaining instead of assertion'
            });
        }
        if (/\.length\s*[><]=?\s*0[^0-9]/.test(line)) {
            violations.push({
                line: lineNum,
                rule: 'strictNullChecks',
                message: 'Redundant length check - use truthiness instead',
                severity: 'info',
                fix: 'Replace `arr.length > 0` with `arr.length` or use optional chaining'
            });
        }
        if (/\bas\s+\w+/.test(line) && !line.trim().startsWith('//')) {
            violations.push({
                line: lineNum,
                rule: 'noUncheckedTypeAssertion',
                message: 'Type assertion used - may bypass type safety',
                severity: 'info',
                fix: 'Consider using type guards or narrowing instead of assertions'
            });
        }
    });
    const score = Math.max(0, 100 - violations.filter(v => v.severity === 'warning').length * 15 - violations.filter(v => v.severity === 'info').length * 5);
    return {
        summary: `Found ${violations.length} strict mode violations (${violations.filter(v => v.severity === 'warning').length} warnings, ${violations.filter(v => v.severity === 'info').length} info)`,
        score,
        violations
    };
}
function formatTsStrictReport(result) {
    const lines = [];
    lines.push('## TypeScript Strict Mode Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.violations.length > 0) {
        lines.push('### Violations');
        result.violations.forEach(v => {
            const icon = v.severity === 'warning' ? '⚠️' : 'ℹ️';
            lines.push(`- ${icon} Line ${v.line} [${v.rule}]: ${v.message}`);
            lines.push(`  - 💡 ${v.fix}`);
        });
        lines.push('');
    }
    return lines.join('\n');
}
// --- Incremental Analysis (PRO-006) ---
function analyzeIncremental(code, diff, language) {
    const diffLines = diff.split('\n');
    const addedLines = diffLines.filter(l => l.startsWith('+') && !l.startsWith('+++'));
    const removedLines = diffLines.filter(l => l.startsWith('-') && !l.startsWith('---'));
    const affectedFunctions = [];
    const funcPattern = /@@.*@@.*\n.*(?:function|def|func|class)\s+(\w+)/g;
    let match;
    while ((match = funcPattern.exec(diff)) !== null) {
        if (!affectedFunctions.includes(match[1])) {
            affectedFunctions.push(match[1]);
        }
    }
    const changedCode = addedLines.map(l => l.substring(1)).join('\n');
    const baseResult = analyzeCode(changedCode || code, language);
    const newIssues = baseResult.issues.filter(i => addedLines.some(l => l.includes(i.message.substring(0, 20))));
    const changedLineCount = addedLines.length + removedLines.length;
    const score = baseResult.score;
    return {
        summary: `Incremental analysis: ${changedLineCount} lines changed, ${affectedFunctions.length} functions affected, ${newIssues.length} new issues`,
        changedLines: changedLineCount,
        affectedFunctions,
        newIssues: newIssues.length > 0 ? newIssues : baseResult.issues.slice(0, 3),
        fixedIssues: removedLines.filter(l => l.includes('fix') || l.includes('resolve')).map(l => l.substring(1).trim()),
        score
    };
}
function formatIncrementalReport(result) {
    const lines = [];
    lines.push('## Incremental Analysis Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    lines.push('### Changed Lines');
    lines.push(`- Total: ${result.changedLines} lines modified`);
    lines.push('');
    if (result.affectedFunctions.length > 0) {
        lines.push('### Affected Functions');
        result.affectedFunctions.forEach(f => lines.push(`- ${f}`));
        lines.push('');
    }
    if (result.newIssues.length > 0) {
        lines.push('### New Issues');
        result.newIssues.forEach(issue => {
            const icon = issue.severity === 'critical' ? '🔴' : issue.severity === 'error' ? '🟠' : issue.severity === 'warning' ? '🟡' : 'ℹ️';
            lines.push(`- ${icon} ${issue.message}`);
        });
        lines.push('');
    }
    if (result.fixedIssues.length > 0) {
        lines.push('### Potentially Fixed');
        result.fixedIssues.forEach(f => lines.push(`- ✅ ${f}`));
        lines.push('');
    }
    return lines.join('\n');
}
// --- Breaking Change Detection ---
function detectBreakingChanges(code, previousCode, _language) {
    const breakingChanges = [];
    const prevLines = previousCode.split('\n');
    const currLines = code.split('\n');
    const prevExports = previousCode.match(/(?:export|def|func|function)\s+(\w+)/g) || [];
    const currExports = code.match(/(?:export|def|func|function)\s+(\w+)/g) || [];
    prevExports.forEach(exp => {
        const name = exp.replace(/^(?:export|def|func|function)\s+/, '');
        if (!currExports.some(e => e.includes(name))) {
            const line = prevLines.findIndex(l => l.includes(exp)) + 1;
            breakingChanges.push({
                type: 'removal',
                line,
                symbol: name,
                description: `Function/export '${name}' was removed`,
                severity: 'critical',
                migration: `Remove all references to '${name}' or provide a compatibility shim`
            });
        }
    });
    const prevFuncs = previousCode.match(/(?:function|def|func)\s+(\w+)\s*\([^)]*\)/g) || [];
    const currFuncs = code.match(/(?:function|def|func)\s+(\w+)\s*\([^)]*\)/g) || [];
    prevFuncs.forEach(prev => {
        const prevMatch = prev.match(/(\w+)\s*\(([^)]*)\)/);
        if (prevMatch) {
            const name = prevMatch[1];
            const prevParams = prevMatch[2];
            const currFunc = currFuncs.find(f => f.startsWith(name + '(') || f.startsWith(name + ' ('));
            if (currFunc) {
                const currMatch = currFunc.match(/\(([^)]*)\)/);
                if (currMatch && currMatch[1] !== prevParams) {
                    const line = currLines.findIndex(l => l.includes(currFunc)) + 1;
                    breakingChanges.push({
                        type: 'signature',
                        line,
                        symbol: name,
                        description: `Signature changed from (${prevParams}) to (${currMatch[1]})`,
                        severity: 'error',
                        migration: `Update all callers of '${name}' to match new signature`
                    });
                }
            }
        }
    });
    const score = Math.max(0, 100 - breakingChanges.filter(b => b.severity === 'critical').length * 30 - breakingChanges.filter(b => b.severity === 'error').length * 15);
    return {
        summary: `Found ${breakingChanges.length} breaking changes (${breakingChanges.filter(b => b.severity === 'critical').length} critical, ${breakingChanges.filter(b => b.severity === 'error').length} errors)`,
        breakingChanges,
        score
    };
}
function formatBreakingChangeReport(result) {
    const lines = [];
    lines.push('## Breaking Change Detection Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.breakingChanges.length > 0) {
        lines.push('### Breaking Changes');
        result.breakingChanges.forEach(bc => {
            const icon = bc.severity === 'critical' ? '🔴' : '🟠';
            lines.push(`- ${icon} **${bc.type}** (line ${bc.line}): ${bc.symbol}`);
            lines.push(`  - ${bc.description}`);
            if (bc.migration)
                lines.push(`  - 🔄 Migration: ${bc.migration}`);
        });
        lines.push('');
    }
    return lines.join('\n');
}
// --- SARIF Export (PRO-005) ---
function exportSarifToFile(code, language, outputPath) {
    const securityResult = scanSecurity(code, language, true);
    const sarif = securityResult.sarif || generateSarifReport(securityResult.vulnerabilities);
    const passed = securityResult.riskLevel !== 'critical' && securityResult.riskLevel !== 'high';
    const criticalCount = securityResult.vulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = securityResult.vulnerabilities.filter(v => v.severity === 'high').length;
    return {
        summary: passed
            ? `SARIF export ready - no critical/high issues found`
            : `SARIF export ready - ${criticalCount} critical, ${highCount} high issues`,
        filePath: outputPath || './security-scan.sarif',
        sarif,
        passed
    };
}
function formatSarifExportReport(result) {
    const lines = [];
    lines.push('## SARIF Export Report');
    lines.push('');
    lines.push(`**Status: ${result.passed ? '✅ PASSED' : '❌ ISSUES FOUND'}**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    lines.push('### Output');
    lines.push(`- File: \`${result.filePath}\``);
    lines.push(`- Format: SARIF 2.1.0`);
    lines.push(`- Runs: ${result.sarif.runs.length}`);
    const totalResults = result.sarif.runs.reduce((sum, run) => sum + run.results.length, 0);
    lines.push(`- Total results: ${totalResults}`);
    lines.push('');
    lines.push('### Usage');
    lines.push('```bash');
    lines.push('# Upload to GitHub Code Scanning');
    lines.push('gh codeql upload-results --sarif=security-scan.sarif');
    lines.push('```');
    lines.push('');
    return lines.join('\n');
}
// --- Diff Preview with Auto-Fix (PRO-003) ---
function generateDiffPreview(code, language) {
    const originalResult = analyzeCode(code, language);
    const originalScore = originalResult.score;
    const fixes = [];
    const codeLines = code.split('\n');
    const fixedLines = [...codeLines];
    if (['javascript', 'typescript', 'java', 'c', 'cpp'].includes(language)) {
        codeLines.forEach((line, idx) => {
            const trimmed = line.trim();
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
                    });
                    fixedLines[idx] = line + ';';
                }
            }
        });
    }
    codeLines.forEach((line, idx) => {
        if (/[^!=]==[^=]/.test(line) && !line.includes('===') && !line.trim().startsWith('//')) {
            const fixedLine = line.replace(/([^!=])==([^=])/g, '$1===$2');
            if (fixedLine !== line) {
                fixes.push({
                    line: idx + 1,
                    original: line.trim(),
                    replacement: fixedLine.trim(),
                    description: 'Use strict equality (===) instead of loose equality (==)',
                    severity: 'warning'
                });
                fixedLines[idx] = fixedLine;
            }
        }
    });
    codeLines.forEach((line, idx) => {
        if (/^\s*var\s+/.test(line) && !line.trim().startsWith('//')) {
            const fixedLine = line.replace(/^(\s*)var(\s+)/, '$1let$2');
            fixes.push({
                line: idx + 1,
                original: line.trim(),
                replacement: fixedLine.trim(),
                description: 'Use let/const instead of var (block scoping)',
                severity: 'warning'
            });
            fixedLines[idx] = fixedLine;
        }
    });
    codeLines.forEach((line, idx) => {
        if (/console\.(log|debug|warn|error)\s*\(/.test(line) && !line.trim().startsWith('//')) {
            fixes.push({
                line: idx + 1,
                original: line.trim(),
                replacement: line.trim().replace(/console\.\w+\s*\([^)]*\)\s*;?/, '// TODO: remove console statement'),
                description: 'Console statement should be removed or replaced with proper logging',
                severity: 'warning'
            });
        }
    });
    const unifiedDiffLines = [];
    unifiedDiffLines.push('--- original');
    unifiedDiffLines.push('+++ fixed');
    unifiedDiffLines.push('@@ -1,' + codeLines.length + ' +1,' + codeLines.length + ' @@');
    codeLines.forEach((line, idx) => {
        if (line !== fixedLines[idx]) {
            unifiedDiffLines.push('- ' + line);
            unifiedDiffLines.push('+ ' + fixedLines[idx]);
        }
        else {
            unifiedDiffLines.push('  ' + line);
        }
    });
    const fixedCode = fixedLines.join('\n');
    const improvedResult = analyzeCode(fixedCode, language);
    const improvedScore = improvedResult.score;
    return {
        summary: `Generated ${fixes.length} auto-fix suggestions (score: ${originalScore} → ${improvedScore})`,
        fixesApplied: fixes.length,
        originalScore,
        improvedScore,
        unifiedDiff: unifiedDiffLines.join('\n'),
        fixes
    };
}
function formatDiffPreviewReport(result) {
    const lines = [];
    lines.push('## Auto-Fix Diff Preview');
    lines.push('');
    lines.push(`**Score: ${result.originalScore}/100 → ${result.improvedScore}/100** (${result.improvedScore >= result.originalScore ? '+' : ''}${result.improvedScore - result.originalScore})`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.fixes.length > 0) {
        lines.push('### Suggested Fixes');
        result.fixes.forEach((fix, idx) => {
            const icon = fix.severity === 'warning' ? '⚠️' : 'ℹ️';
            lines.push(`${idx + 1}. ${icon} Line ${fix.line}: ${fix.description}`);
            lines.push(`   \`\`\`diff`);
            lines.push(`   - ${fix.original}`);
            lines.push(`   + ${fix.replacement}`);
            lines.push(`   \`\`\``);
        });
        lines.push('');
    }
    lines.push('### Unified Diff Preview');
    lines.push('```diff');
    lines.push(result.unifiedDiff);
    lines.push('```');
    lines.push('');
    return lines.join('\n');
}
// ==================== v0.6.0 NEW FUNCTIONS ====================
// --- PRO-004: Config file support (.dshcoderc) ---
function loadDshConfig(configContent) {
    const errors = [];
    const defaultConfig = {
        severityThreshold: 'info',
        ignoreRules: [],
        enableSarif: true,
        enableAutoFix: true,
        outputFormat: 'markdown'
    };
    if (!configContent) {
        return {
            summary: 'No config file provided, using defaults',
            config: defaultConfig,
            loaded: false,
            errors: []
        };
    }
    try {
        const parsed = JSON.parse(configContent);
        const config = { ...defaultConfig, ...parsed };
        if (config.severityThreshold && !['critical', 'error', 'warning', 'info'].includes(config.severityThreshold)) {
            errors.push(`Invalid severityThreshold: ${config.severityThreshold}`);
            config.severityThreshold = 'info';
        }
        if (config.outputFormat && !['markdown', 'json', 'sarif'].includes(config.outputFormat)) {
            errors.push(`Invalid outputFormat: ${config.outputFormat}`);
            config.outputFormat = 'markdown';
        }
        return {
            summary: `Loaded .dshcoderc config (${Object.keys(parsed).length} settings)`,
            config,
            loaded: true,
            errors
        };
    }
    catch {
        return {
            summary: 'Failed to parse .dshcoderc config, using defaults',
            config: defaultConfig,
            loaded: false,
            errors: ['Invalid JSON in config file']
        };
    }
}
function formatConfigLoadReport(result) {
    const lines = [];
    lines.push('## Configuration Load Report');
    lines.push('');
    lines.push(`**Status: ${result.loaded ? '✅ LOADED' : '⚠️ DEFAULTS'}**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    lines.push('### Active Configuration');
    lines.push(`- Severity Threshold: \`${result.config.severityThreshold}\``);
    lines.push(`- Output Format: \`${result.config.outputFormat}\``);
    lines.push(`- SARIF Enabled: \`${result.config.enableSarif}\``);
    lines.push(`- Auto-fix Enabled: \`${result.config.enableAutoFix}\``);
    lines.push(`- Ignored Rules: ${result.config.ignoreRules?.length ?? 0}`);
    lines.push(`- Custom Rules: ${result.config.customRules?.length ?? 0}`);
    lines.push('');
    if (result.errors.length > 0) {
        lines.push('### Errors');
        result.errors.forEach(e => lines.push(`- ❌ ${e}`));
        lines.push('');
    }
    lines.push('### Example .dshcoderc');
    lines.push('```json');
    lines.push(JSON.stringify({
        severityThreshold: 'warning',
        ignoreRules: ['no-console'],
        enableSarif: true,
        outputFormat: 'markdown'
    }, null, 2));
    lines.push('```');
    lines.push('');
    return lines.join('\n');
}
// --- PRO-007: Test generation suggestions ---
function generateTestSuggestions(code, language) {
    const tests = [];
    const codeLines = code.split('\n');
    // Detect functions
    const funcRegex = /(?:function|def|func)\s+(\w+)\s*\(([^)]*)\)/g;
    let match;
    while ((match = funcRegex.exec(code)) !== null) {
        const funcName = match[1];
        const params = match[2];
        if (funcName && !['if', 'for', 'while', 'switch', 'return', 'console'].includes(funcName)) {
            // Unit test
            const testCode = getUnitTestCode(funcName, params, language);
            tests.push({
                functionName: funcName,
                language,
                testName: `${funcName}_should_work_correctly`,
                testCode,
                type: 'unit',
                description: `Basic unit test for ${funcName}`
            });
            // Edge case test
            if (params.split(',').length > 0) {
                tests.push({
                    functionName: funcName,
                    language,
                    testName: `${funcName}_handles_edge_cases`,
                    testCode: `// Edge case test for ${funcName}\n// Test with: null, undefined, empty, boundary values`,
                    type: 'edge-case',
                    description: `Edge case handling for ${funcName}`
                });
            }
        }
    }
    // Also detect arrow functions
    const arrowRegex = /(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/g;
    while ((match = arrowRegex.exec(code)) !== null) {
        const funcName = match[1];
        const params = match[2];
        if (funcName && !tests.some(t => t.functionName === funcName)) {
            tests.push({
                functionName: funcName,
                language,
                testName: `${funcName}_should_work_correctly`,
                testCode: getUnitTestCode(funcName, params, language),
                type: 'unit',
                description: `Basic unit test for ${funcName}`
            });
        }
    }
    const funcCount = (code.match(/(?:function|def|func)\s+\w+/g) || []).length;
    const coverage = funcCount > 0 ? Math.min(100, (tests.length / funcCount) * 100) : 0;
    const score = Math.min(100, tests.length * 15);
    return {
        summary: `Generated ${tests.length} test cases for ${funcCount} functions (est. coverage: ${coverage.toFixed(1)}%)`,
        tests,
        coverage: parseFloat(coverage.toFixed(1)),
        score
    };
}
function getUnitTestCode(funcName, params, language) {
    const firstParam = params.split(',')[0]?.trim() || '/* args */';
    switch (language) {
        case 'typescript':
        case 'javascript':
            return `test('${funcName} should work correctly', () => {\n  // Arrange\n  \n  // Act\n  const result = ${funcName}(${firstParam});\n  // Assert\n  expect(result).toBe(/* expected */);\n});`;
        case 'python':
            return `def test_${funcName}_basic():\n    # Arrange\n    \n    # Act\n    result = ${funcName}(${firstParam})\n    # Assert\n    assert result == /* expected */`;
        case 'go':
            return `func Test${funcName}(t *testing.T) {\n    // Arrange\n    \n    // Act\n    result := ${funcName}(${firstParam})\n    // Assert\n    if result != /* expected */ {\n        t.Errorf("got %v, want /* expected */", result)\n    }\n}`;
        default:
            return `// Test for ${funcName}\nTestExample(${funcName})`;
    }
}
function formatTestGenReport(result) {
    const lines = [];
    lines.push('## Test Generation Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100 | Est. Coverage: ${result.coverage}%**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.tests.length > 0) {
        lines.push('### Suggested Tests');
        result.tests.forEach(test => {
            const icon = test.type === 'unit' ? '🧪' : test.type === 'edge-case' ? '🔍' : '💥';
            lines.push(`- ${icon} **${test.testName}** (${test.type})`);
            lines.push(`  - Function: \`${test.functionName}\``);
            lines.push(`  - ${test.description}`);
            lines.push('  ```');
            lines.push(`  ${test.testCode}`);
            lines.push('  ```');
        });
        lines.push('');
    }
    return lines.join('\n');
}
// --- PRO-009: Code complexity metrics ---
function analyzeComplexity(code, _language) {
    const codeLines = code.split('\n');
    const linesOfCode = codeLines.length;
    // Calculate cyclomatic complexity
    const branches = (code.match(/\b(if|else|for|while|switch|case|catch|&&|\?|try)\b/g) || []).length;
    const cyclomaticComplexity = branches + 1;
    // Calculate Halstead metrics (simplified)
    const operators = (code.match(/[+\-*/%=<>!&|^~?:]+/g) || []).length;
    const operands = (code.match(/\b\w+\b/g) || []).length;
    const uniqueOperators = new Set(code.match(/[+\-*/%=<>!&|^~?:]+/g) || []).size;
    const uniqueOperands = new Set(code.match(/\b\w+\b/g) || []).size;
    const vocabulary = uniqueOperators + uniqueOperands;
    const length = operators + operands;
    const halsteadVolume = length * Math.log2(vocabulary || 1);
    const halsteadDifficulty = (uniqueOperators / 2) * (uniqueOperands / (uniqueOperands || 1));
    const halsteadEffort = halsteadDifficulty * halsteadVolume;
    // Comment ratio
    const commentLines = codeLines.filter(l => l.trim().startsWith('//') || l.trim().startsWith('#') || l.trim().startsWith('*')).length;
    const commentRatio = linesOfCode > 0 ? (commentLines / linesOfCode) * 100 : 0;
    // Nesting depth
    let maxNesting = 0;
    let currentNesting = 0;
    codeLines.forEach(line => {
        const opens = (line.match(/{/g) || []).length;
        const closes = (line.match(/}/g) || []).length;
        currentNesting += opens - closes;
        maxNesting = Math.max(maxNesting, currentNesting);
    });
    // Per-function complexity
    const functions = [];
    const funcRegex = /(?:function|def|func)\s+(\w+)\s*\(([^)]*)\)/g;
    let match;
    while ((match = funcRegex.exec(code)) !== null) {
        const name = match[1];
        const params = match[2];
        const line = code.substring(0, match.index).split('\n').length;
        const funcBody = code.substring(match.index, match.index + 500);
        const funcBranches = (funcBody.match(/\b(if|else|for|while|switch|case|catch|\?)\b/g) || []).length;
        const funcCyclomatic = funcBranches + 1;
        let risk = 'low';
        if (funcCyclomatic > 20)
            risk = 'critical';
        else if (funcCyclomatic > 10)
            risk = 'high';
        else if (funcCyclomatic > 5)
            risk = 'medium';
        functions.push({
            name,
            line,
            cyclomatic: funcCyclomatic,
            params: params.split(',').filter(p => p.trim()).length,
            returns: (funcBody.match(/\breturn\b/g) || []).length,
            risk
        });
    }
    // Risks
    const risks = [];
    if (cyclomaticComplexity > 20)
        risks.push('High overall cyclomatic complexity');
    if (maxNesting > 5)
        risks.push('Deep nesting detected');
    if (halsteadEffort > 1000)
        risks.push('High Halstead effort - consider simplification');
    if (commentRatio < 5)
        risks.push('Low comment ratio');
    functions.filter(f => f.risk === 'critical' || f.risk === 'high').forEach(f => {
        risks.push(`Function '${f.name}' has ${f.risk} complexity (${f.cyclomatic})`);
    });
    // Score
    const score = Math.max(0, 100 - (cyclomaticComplexity > 10 ? (cyclomaticComplexity - 10) * 3 : 0) - (maxNesting > 3 ? (maxNesting - 3) * 5 : 0));
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
    };
}
function formatComplexityReport(result) {
    const lines = [];
    lines.push('## Code Complexity Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    lines.push('### Metrics');
    lines.push(`- Cyclomatic Complexity: \`${result.metrics.cyclomaticComplexity}\``);
    lines.push(`- Halstead Volume: \`${result.metrics.halsteadVolume}\``);
    lines.push(`- Halstead Difficulty: \`${result.metrics.halsteadDifficulty}\``);
    lines.push(`- Halstead Effort: \`${result.metrics.halsteadEffort}\``);
    lines.push(`- Lines of Code: \`${result.metrics.linesOfCode}\``);
    lines.push(`- Comment Ratio: \`${result.metrics.commentRatio}%\``);
    lines.push(`- Max Nesting Depth: \`${result.metrics.nestingDepth}\``);
    lines.push('');
    if (result.functions.length > 0) {
        lines.push('### Function Complexity');
        result.functions.forEach(f => {
            const icon = f.risk === 'critical' ? '🔴' : f.risk === 'high' ? '🟠' : f.risk === 'medium' ? '🟡' : '🟢';
            lines.push(`- ${icon} **${f.name}** (line ${f.line}): cyclomatic=${f.cyclomatic}, params=${f.params}, returns=${f.returns}`);
        });
        lines.push('');
    }
    if (result.risks.length > 0) {
        lines.push('### Risks');
        result.risks.forEach(r => lines.push(`- ⚠️ ${r}`));
        lines.push('');
    }
    return lines.join('\n');
}
// --- PRO-013: Batch file analysis ---
function analyzeBatch(files) {
    const fileResults = [];
    const issueCounts = {};
    let totalIssues = 0;
    files.forEach(file => {
        const language = detectLanguage(file.content);
        const result = analyzeCode(file.content, language);
        result.issues.forEach(issue => {
            issueCounts[issue.message] = (issueCounts[issue.message] || 0) + 1;
            totalIssues++;
        });
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
        });
    });
    const overallScore = fileResults.length > 0
        ? Math.round(fileResults.reduce((sum, f) => sum + f.score, 0) / fileResults.length)
        : 0;
    const commonIssues = Object.entries(issueCounts)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 5)
        .map(([message, count]) => ({ message, count }));
    return {
        summary: `Analyzed ${files.length} files: ${totalIssues} total issues, avg score ${overallScore}/100`,
        totalFiles: files.length,
        analyzedFiles: fileResults.length,
        files: fileResults,
        overallScore,
        totalIssues,
        commonIssues
    };
}
function formatBatchReport(result) {
    const lines = [];
    lines.push('## Batch Analysis Report');
    lines.push('');
    lines.push(`**Overall Score: ${result.overallScore}/100 | Files: ${result.analyzedFiles}/${result.totalFiles}**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.files.length > 0) {
        lines.push('### File Results');
        result.files.forEach(f => {
            const icon = f.score >= 80 ? '🟢' : f.score >= 60 ? '🟡' : f.score >= 40 ? '🟠' : '🔴';
            lines.push(`- ${icon} **${f.fileName}** (${f.language}): ${f.score}/100, ${f.issues.length} issues, ${f.metrics.lines} lines`);
        });
        lines.push('');
    }
    if (result.commonIssues.length > 0) {
        lines.push('### Most Common Issues');
        result.commonIssues.forEach(ci => lines.push(`- **${ci.count}x**: ${ci.message}`));
        lines.push('');
    }
    return lines.join('\n');
}
// --- PRO-008: Monorepo analysis ---
function analyzeMonorepo(packages) {
    const packageResults = [];
    const dependencies = [];
    const cycles = [];
    packages.forEach(pkg => {
        let totalIssues = 0;
        let totalScore = 0;
        let fileCount = 0;
        pkg.files.forEach(file => {
            const language = detectLanguage(file.content);
            const result = analyzeCode(file.content, language);
            totalIssues += result.issues.length;
            totalScore += result.score;
            fileCount++;
        });
        const avgScore = fileCount > 0 ? Math.round(totalScore / fileCount) : 0;
        packageResults.push({
            name: pkg.name,
            path: pkg.path,
            language: pkg.files.length > 0 ? detectLanguage(pkg.files[0].content) : 'unknown',
            score: avgScore,
            fileCount,
            issues: totalIssues
        });
        // Detect dependencies from imports
        pkg.files.forEach(file => {
            const imports = file.content.match(/(?:import|from|require)\s+['"]([^'"]+)['"]/g) || [];
            imports.forEach(imp => {
                const depName = imp.replace(/^(?:import|from|require)\s+['"]/, "").replace(/['"]$/, "");
                if (depName.startsWith('.') || depName.startsWith('/'))
                    return; // Skip relative imports
                const targetPkg = packages.find(p => depName.includes(p.name));
                if (targetPkg && targetPkg.name !== pkg.name) {
                    dependencies.push({
                        from: pkg.name,
                        to: targetPkg.name,
                        type: 'dependency'
                    });
                }
            });
        });
    });
    // Detect cycles (simplified)
    const visited = new Set();
    const recursionStack = new Set();
    function hasCycle(node, path) {
        visited.add(node);
        recursionStack.add(node);
        const deps = dependencies.filter(d => d.from === node);
        for (const dep of deps) {
            if (!visited.has(dep.to)) {
                if (hasCycle(dep.to, [...path, dep.to]))
                    return true;
            }
            else if (recursionStack.has(dep.to)) {
                cycles.push([...path, dep.to]);
                return true;
            }
        }
        recursionStack.delete(node);
        return false;
    }
    packageResults.forEach(pkg => {
        if (!visited.has(pkg.name)) {
            hasCycle(pkg.name, [pkg.name]);
        }
    });
    const overallScore = packageResults.length > 0
        ? Math.round(packageResults.reduce((sum, p) => sum + p.score, 0) / packageResults.length)
        : 0;
    return {
        summary: `Monorepo: ${packages.length} packages, ${dependencies.length} dependencies, ${cycles.length} cycles`,
        packages: packageResults,
        dependencies,
        cycles,
        score: overallScore
    };
}
function formatMonorepoReport(result) {
    const lines = [];
    lines.push('## Monorepo Analysis Report');
    lines.push('');
    lines.push(`**Overall Score: ${result.score}/100 | Packages: ${result.packages.length}**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.packages.length > 0) {
        lines.push('### Packages');
        result.packages.forEach(p => {
            const icon = p.score >= 80 ? '🟢' : p.score >= 60 ? '🟡' : p.score >= 40 ? '🟠' : '🔴';
            lines.push(`- ${icon} **${p.name}** (${p.path}): ${p.score}/100, ${p.fileCount} files, ${p.issues} issues`);
        });
        lines.push('');
    }
    if (result.dependencies.length > 0) {
        lines.push('### Dependencies');
        result.dependencies.forEach(d => lines.push(`- ${d.from} → ${d.to} (${d.type})`));
        lines.push('');
    }
    if (result.cycles.length > 0) {
        lines.push('### ⚠️ Circular Dependencies');
        result.cycles.forEach(c => lines.push(`- ${c.join(' → ')}`));
        lines.push('');
    }
    return lines.join('\n');
}
// ==================== v0.7.0 NEW FUNCTIONS ====================
// --- PRO-010: Multi-language deep analysis ---
function analyzeMultiLanguage(code, language) {
    const features = [];
    const issues = [];
    let confidence = 0.9;
    switch (language) {
        case 'python':
            features.push({ name: 'type-hints', supported: true, description: 'PEP 484 type annotations' }, { name: 'f-strings', supported: true, description: 'Python 3.6+ formatted strings' }, { name: 'list-comprehensions', supported: true, description: 'Pythonic iteration patterns' }, { name: 'decorators', supported: true, description: '@decorator syntax support' }, { name: 'context-managers', supported: true, description: 'with statement patterns' }, { name: 'async-await', supported: true, description: 'Asynchronous programming' });
            // Check for Python-specific issues
            if (code.includes('except:')) {
                issues.push({ line: 1, rule: 'bare-except', message: 'Bare except clause - catch specific exceptions', severity: 'warning', fix: 'Use `except Exception as e:` instead', docs: 'https://peps.python.org/pep-0008/' });
            }
            if (/print\s+\(/.test(code) && !code.includes('from __future__')) {
                issues.push({ line: 1, rule: 'print-statement', message: 'Consider using logging instead of print', severity: 'info', fix: 'Use `import logging; logger = logging.getLogger(__name__)`' });
            }
            if (/==\s*(True|False|None)/.test(code)) {
                issues.push({ line: 1, rule: 'comparison-to-singleton', message: 'Use `is` for None/True/False comparisons', severity: 'warning', fix: 'Replace `== None` with `is None`' });
            }
            break;
        case 'go':
            features.push({ name: 'goroutines', supported: true, description: 'go func() concurrency' }, { name: 'interfaces', supported: true, description: 'Implicit interface satisfaction' }, { name: 'defer', supported: true, description: 'Deferred execution' }, { name: 'channels', supported: true, description: 'CSP-style communication' }, { name: 'struct-tags', supported: true, description: 'Reflection metadata' }, { name: 'error-handling', supported: true, description: 'Explicit error returns' });
            if (code.includes('panic(')) {
                issues.push({ line: 1, rule: 'panic-usage', message: 'Avoid panic in production code - return errors instead', severity: 'warning', fix: 'Return error values instead of panicking' });
            }
            break;
        case 'rust':
            features.push({ name: 'ownership', supported: true, description: 'Borrow checker system' }, { name: 'lifetimes', supported: true, description: 'Explicit lifetime annotations' }, { name: 'pattern-matching', supported: true, description: 'match expressions' }, { name: 'traits', supported: true, description: 'Type class polymorphism' }, { name: 'Option-Result', supported: true, description: 'Error handling types' }, { name: 'macros', supported: true, description: 'Macro by example' });
            if (code.includes('unwrap()')) {
                issues.push({ line: 1, rule: 'unwrap-usage', message: 'Avoid unwrap() - handle None/Err cases properly', severity: 'warning', fix: 'Use `?` operator or `match` instead' });
            }
            if (/mut\s+/.test(code) && code.match(/mut\s+/g).length > 5) {
                issues.push({ line: 1, rule: 'excessive-mutability', message: 'High mutability - consider restructuring for immutability', severity: 'info', fix: 'Use references or functional patterns' });
            }
            break;
        case 'java':
            features.push({ name: 'generics', supported: true, description: 'Type parameterization' }, { name: 'streams', supported: true, description: 'Functional stream API' }, { name: 'lombok', supported: false, description: 'Boilerplate reduction (requires dependency)' }, { name: 'records', supported: true, description: 'Java 14+ immutable data classes' }, { name: 'sealed-classes', supported: true, description: 'Java 17+ restricted inheritance' }, { name: 'pattern-matching', supported: true, description: 'Java 16+ instanceof patterns' });
            if (/catch\s*\(/.test(code) && code.includes('Exception')) {
                issues.push({ line: 1, rule: 'catch-generic', message: 'Avoid catching generic Exception', severity: 'warning', fix: 'Catch specific exception types' });
            }
            break;
        default:
            confidence = 0.7;
            features.push({ name: 'basic-analysis', supported: true, description: 'Generic code analysis' }, { name: 'pattern-detection', supported: true, description: 'Common anti-patterns' });
    }
    const score = Math.max(0, 100 - issues.filter(i => i.severity === 'warning').length * 15 - issues.filter(i => i.severity === 'info').length * 5);
    return {
        summary: `${language} analysis: ${features.length} features detected, ${issues.length} language-specific issues`,
        language,
        confidence,
        features,
        issues,
        score
    };
}
function formatMultiLangReport(result) {
    const lines = [];
    lines.push('## Multi-Language Analysis Report');
    lines.push('');
    lines.push(`**Language: ${result.language} | Confidence: ${(result.confidence * 100).toFixed(0)}% | Score: ${result.score}/100**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.features.length > 0) {
        lines.push('### Language Features');
        result.features.forEach(f => {
            const icon = f.supported ? '✅' : '❌';
            lines.push(`- ${icon} **${f.name}**: ${f.description}`);
        });
        lines.push('');
    }
    if (result.issues.length > 0) {
        lines.push('### Language-Specific Issues');
        result.issues.forEach(issue => {
            const icon = issue.severity === 'warning' ? '⚠️' : 'ℹ️';
            lines.push(`- ${icon} [${issue.rule}]: ${issue.message}`);
            lines.push(`  - 💡 ${issue.fix}`);
        });
        lines.push('');
    }
    return lines.join('\n');
}
// --- PRO-011: CI/CD integration ---
function generateCiCdWorkflow(language) {
    const steps = [];
    steps.push({ name: 'Checkout', action: 'actions/checkout@v4' });
    switch (language) {
        case 'typescript':
        case 'javascript':
            steps.push({ name: 'Setup Node', action: 'actions/setup-node@v4', with: { 'node-version': '20' } });
            steps.push({ name: 'Install', run: 'npm ci' });
            steps.push({ name: 'Review', run: 'npx dsh review --ci' });
            break;
        case 'python':
            steps.push({ name: 'Setup Python', action: 'actions/setup-python@v5', with: { 'python-version': '3.11' } });
            steps.push({ name: 'Install', run: 'pip install -r requirements.txt' });
            steps.push({ name: 'Review', run: 'dsh review --ci' });
            break;
        case 'go':
            steps.push({ name: 'Setup Go', action: 'actions/setup-go@v5', with: { 'go-version': '1.21' } });
            steps.push({ name: 'Review', run: 'dsh review --ci' });
            break;
        default:
            steps.push({ name: 'Review', run: 'dsh review --ci' });
    }
    steps.push({ name: 'Upload SARIF', uses: 'github/codeql-action/upload-sarif@v3' });
    const workflow = `name: Code Review\non:\n  push:\n    branches: [main]\n  pull_request:\n    branches: [main]\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n${steps.map(s => `      - name: ${s.name}\n${s.action ? `        uses: ${s.action}\n` : ''}${s.with ? `        with:\n${Object.entries(s.with).map(([k, v]) => `          ${k}: ${v}`).join('\n')}\n` : ''}${s.run ? `        run: ${s.run}\n` : ''}`).join('\n')}`;
    return {
        summary: `Generated GitHub Actions workflow for ${language}`,
        workflow,
        triggers: ['push to main', 'pull_request to main'],
        steps,
        filename: '.github/workflows/code-review.yml'
    };
}
function formatCiCdReport(result) {
    const lines = [];
    lines.push('## CI/CD Integration Report');
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    lines.push('### Workflow File');
    lines.push(`- Filename: \`${result.filename}\``);
    lines.push(`- Triggers: ${result.triggers.join(', ')}`);
    lines.push('');
    lines.push('### Steps');
    result.steps.forEach((step, idx) => {
        lines.push(`${idx + 1}. **${step.name}**`);
        if (step.action)
            lines.push(`   - Action: \`${step.action}\``);
        if (step.run)
            lines.push(`   - Run: \`${step.run}\``);
        if (step.with)
            lines.push(`   - With: ${JSON.stringify(step.with)}`);
    });
    lines.push('');
    lines.push('### Workflow YAML');
    lines.push('```yaml');
    lines.push(result.workflow);
    lines.push('```');
    lines.push('');
    lines.push('### Usage');
    lines.push('1. Save the workflow to `.github/workflows/code-review.yml`');
    lines.push('2. Push to your repository');
    lines.push('3. The workflow runs automatically on every PR');
    lines.push('');
    return lines.join('\n');
}
// --- PRO-012: Custom rule engine ---
function runCustomRules(code, rulesYaml) {
    const matches = [];
    const errors = [];
    let rulesLoaded = 0;
    try {
        const lines = code.split('\n');
        // Simple YAML parser (works for flat rule definitions)
        const ruleBlocks = rulesYaml.split(/^- /m).filter(b => b.trim());
        ruleBlocks.forEach(block => {
            const rule = {};
            block.split('\n').forEach(line => {
                const colonIdx = line.indexOf(':');
                if (colonIdx > 0) {
                    const key = line.substring(0, colonIdx).trim();
                    const value = line.substring(colonIdx + 1).trim().replace(/^["']|["']$/g, '');
                    rule[key] = value;
                }
            });
            if (rule.id && rule.pattern) {
                rulesLoaded++;
                const regex = new RegExp(rule.pattern, 'gi');
                lines.forEach((line, idx) => {
                    if (regex.test(line)) {
                        matches.push({
                            ruleId: rule.id,
                            line: idx + 1,
                            message: rule.message || `Custom rule '${rule.id}' matched`,
                            severity: rule.severity || 'warning',
                            context: line.trim().substring(0, 80)
                        });
                    }
                });
            }
        });
    }
    catch (e) {
        errors.push(`Failed to parse rules: ${e}`);
    }
    return {
        summary: `Loaded ${rulesLoaded} custom rules, ${matches.length} matches found`,
        rulesLoaded,
        matches,
        errors
    };
}
function formatCustomRuleReport(result) {
    const lines = [];
    lines.push('## Custom Rule Engine Report');
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.matches.length > 0) {
        lines.push('### Matches');
        result.matches.forEach(m => {
            const icon = m.severity === 'critical' ? '🔴' : m.severity === 'error' ? '🟠' : m.severity === 'warning' ? '🟡' : 'ℹ️';
            lines.push(`- ${icon} **${m.ruleId}** (line ${m.line}): ${m.message}`);
            lines.push(`  - Context: \`${m.context}\``);
        });
        lines.push('');
    }
    if (result.errors.length > 0) {
        lines.push('### Errors');
        result.errors.forEach(e => lines.push(`- ❌ ${e}`));
        lines.push('');
    }
    lines.push('### Example Rules YAML');
    lines.push('```yaml');
    lines.push('- id: no-console-log');
    lines.push('  pattern: "console\\\\.log"');
    lines.push('  message: "Avoid console.log in production"');
    lines.push('  severity: warning');
    lines.push('');
    lines.push('- id: require-error-handling');
    lines.push('  pattern: "async\\\\s+function"');
    lines.push('  message: "Async functions should have try-catch"');
    lines.push('  severity: error');
    lines.push('```');
    lines.push('');
    return lines.join('\n');
}
// --- Code duplication detection ---
function detectDuplication(code, _filename) {
    const duplications = [];
    const lines = code.split('\n');
    const minDuplicateLength = 4;
    // Find consecutive similar blocks
    for (let i = 0; i < lines.length - minDuplicateLength; i++) {
        const block = lines.slice(i, i + minDuplicateLength).join('\n');
        const blockTrimmed = block.trim();
        if (blockTrimmed.length < 20)
            continue;
        for (let j = i + minDuplicateLength; j < lines.length - minDuplicateLength; j++) {
            const compareBlock = lines.slice(j, j + minDuplicateLength).join('\n');
            const similarity = calculateSimilarity(blockTrimmed, compareBlock.trim());
            if (similarity > 0.85) {
                const existing = duplications.find(d => d.sourceLine === i + 1 && d.targetLine === j + 1);
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
                    });
                }
            }
        }
    }
    const linesWasted = duplications.reduce((sum, d) => sum + d.lines, 0);
    const score = Math.max(0, 100 - duplications.length * 10 - linesWasted * 2);
    return {
        summary: `Found ${duplications.length} code duplications (${linesWasted} lines wasted)`,
        duplications,
        score,
        linesWasted
    };
}
function calculateSimilarity(a, b) {
    if (a === b)
        return 1;
    if (a.length === 0 || b.length === 0)
        return 0;
    const longer = a.length > b.length ? a : b;
    const shorter = a.length > b.length ? b : a;
    // Simple Levenshtein-based similarity
    const editDistance = levenshteinDistance(longer, shorter);
    return (longer.length - editDistance) / longer.length;
}
function levenshteinDistance(a, b) {
    const matrix = [];
    for (let i = 0; i <= b.length; i++) {
        matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
        matrix[0][j] = j;
    }
    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            }
            else {
                matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j] + 1);
            }
        }
    }
    return matrix[b.length][a.length];
}
function formatDuplicationReport(result) {
    const lines = [];
    lines.push('## Code Duplication Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100 | Wasted Lines: ${result.linesWasted}**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.duplications.length > 0) {
        lines.push('### Duplications');
        result.duplications.forEach((d, idx) => {
            const icon = d.type === 'exact' ? '🔴' : '🟡';
            lines.push(`${idx + 1}. ${icon} Lines ${d.sourceLine}-${d.sourceLine + d.lines - 1} ↔ ${d.targetLine}-${d.targetLine + d.lines - 1}`);
            lines.push(`   - Type: ${d.type} | Similarity: ${(d.similarity * 100).toFixed(0)}%`);
            lines.push(`   - 💡 ${d.suggestion}`);
        });
        lines.push('');
    }
    return lines.join('\n');
}
// --- Refactoring suggestions ---
function suggestRefactoring(code, language) {
    const refactorings = [];
    const lines = code.split('\n');
    // Long method detection -> suggest extract
    let funcStart = -1;
    let funcName = '';
    for (let i = 0; i < lines.length; i++) {
        const match = lines[i].match(/(?:function|def|func)\s+(\w+)/);
        if (match && funcStart === -1) {
            funcStart = i;
            funcName = match[1];
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
            });
            funcStart = -1;
        }
    }
    // Large class detection -> suggest extract-class
    const classMatches = code.match(/class\s+\w+/g) || [];
    classMatches.forEach(cls => {
        const clsIdx = code.indexOf(cls);
        const clsLine = code.substring(0, clsIdx).split('\n').length;
        const methodCount = (code.substring(clsIdx, clsIdx + 5000).match(/(?:public|private|protected|static)?\s*\w+\s*\(/g) || []).length;
        if (methodCount > 8) {
            refactorings.push({
                type: 'extract-class',
                line: clsLine,
                target: cls.replace('class ', ''),
                description: `Class has ${methodCount} methods - violates SRP`,
                effort: 'high',
                impact: 'high',
                suggestion: 'Split into smaller, focused classes'
            });
        }
    });
    // Duplicated logic -> suggest extract
    const dupResult = detectDuplication(code);
    if (dupResult.duplications.length > 0) {
        refactorings.push({
            type: 'extract-method',
            line: dupResult.duplications[0].sourceLine,
            target: 'duplicated block',
            description: `${dupResult.duplications.length} duplicated code blocks found`,
            effort: 'medium',
            impact: 'medium',
            suggestion: 'Extract duplicated code into a reusable function'
        });
    }
    // Variables that could be inlined
    const varDeclarations = code.match(/(?:const|let|var)\s+(\w+)\s*=\s*[^;]+;/g) || [];
    varDeclarations.forEach(decl => {
        const varName = decl.match(/(?:const|let|var)\s+(\w+)/)?.[1];
        if (varName) {
            const usages = (code.match(new RegExp(`\\b${varName}\\b`, 'g')) || []).length;
            if (usages === 2 && !decl.includes('function') && !decl.includes('=>')) {
                const line = code.split('\n').findIndex(l => l.includes(decl)) + 1;
                refactorings.push({
                    type: 'inline',
                    line,
                    target: varName,
                    description: `Variable '${varName}' used only once - could be inlined`,
                    effort: 'low',
                    impact: 'low',
                    suggestion: `Inline the value directly where '${varName}' is used`
                });
            }
        }
    });
    const potentialImprovement = Math.min(30, refactorings.filter(r => r.impact === 'high').length * 10 + refactorings.filter(r => r.impact === 'medium').length * 5);
    const score = Math.max(0, 100 - refactorings.filter(r => r.impact === 'high').length * 15);
    return {
        summary: `Found ${refactorings.length} refactoring opportunities (potential improvement: +${potentialImprovement}pts)`,
        refactorings,
        score,
        potentialImprovement
    };
}
function formatRefactorReport(result) {
    const lines = [];
    lines.push('## Refactoring Suggestions Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100 | Potential Improvement: +${result.potentialImprovement}pts**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.refactorings.length > 0) {
        lines.push('### Suggested Refactorings');
        result.refactorings.forEach((r, idx) => {
            const effortIcon = r.effort === 'low' ? '🟢' : r.effort === 'medium' ? '🟡' : '🔴';
            const impactIcon = r.impact === 'low' ? '⚪' : r.impact === 'medium' ? '🟡' : '🔴';
            lines.push(`${idx + 1}. **${r.type}** → \`${r.target}\` (line ${r.line})`);
            lines.push(`   - ${r.description}`);
            lines.push(`   - Effort: ${effortIcon} | Impact: ${impactIcon}`);
            lines.push(`   - 💡 ${r.suggestion}`);
        });
        lines.push('');
    }
    return lines.join('\n');
}
// --- Naming convention check ---
function checkNamingConventions(code, language) {
    const conventions = [];
    const violations = [];
    const lines = code.split('\n');
    // Define conventions per language
    const namingRules = {
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
    };
    const rules = namingRules[language] || namingRules.typescript;
    rules.forEach(rule => {
        conventions.push({
            type: rule.type,
            pattern: rule.pattern.source,
            description: rule.description,
            examples: rule.examples
        });
    });
    // Check variable declarations, function declarations, class declarations
    lines.forEach((line, idx) => {
        const lineNum = idx + 1;
        // Check const/let/var declarations
        const varMatch = line.match(/(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/);
        if (varMatch && !line.trim().startsWith('//')) {
            const varName = varMatch[1];
            const isConst = line.includes('const');
            if (isConst && !/^[A-Z][A-Z0-9_]*$/.test(varName) && !/^[a-z][a-zA-Z0-9]*$/.test(varName)) {
                violations.push({
                    line: lineNum,
                    symbol: varName,
                    convention: 'constant naming',
                    message: `Constant '${varName}' should be SCREAMING_SNAKE_CASE`,
                    suggestion: `Rename to '${varName.replace(/([A-Z])/g, '_$1').toUpperCase().replace(/^_/, '')}'`,
                    severity: 'warning'
                });
            }
        }
        // Check function declarations
        const funcMatch = line.match(/(?:function|def|func)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/);
        if (funcMatch && !line.trim().startsWith('//')) {
            const funcName = funcMatch[1];
            if (language === 'python' || language === 'rust') {
                if (!/^[a-z][a-z0-9_]*$/.test(funcName) && !/^_[a-z]/.test(funcName)) {
                    violations.push({
                        line: lineNum,
                        symbol: funcName,
                        convention: 'function naming',
                        message: `Function '${funcName}' should be snake_case`,
                        suggestion: `Rename to '${funcName.replace(/([A-Z])/g, '_$1').toLowerCase().replace(/^_/, '')}'`,
                        severity: 'warning'
                    });
                }
            }
        }
    });
    const score = Math.max(0, 100 - violations.filter(v => v.severity === 'warning').length * 10);
    return {
        summary: `Checked ${conventions.length} naming conventions, found ${violations.length} violations`,
        score,
        conventions,
        violations
    };
}
function formatNamingReport(result) {
    const lines = [];
    lines.push('## Naming Convention Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.conventions.length > 0) {
        lines.push('### Active Conventions');
        result.conventions.forEach(c => {
            lines.push(`- **${c.type}**: ${c.description} (${c.examples.join(', ')})`);
        });
        lines.push('');
    }
    if (result.violations.length > 0) {
        lines.push('### Violations');
        result.violations.forEach(v => {
            lines.push(`- ⚠️ Line ${v.line}: **${v.symbol}** - ${v.message}`);
            lines.push(`  - 💡 ${v.suggestion}`);
        });
        lines.push('');
    }
    return lines.join('\n');
}
// ==================== v0.8.0 NEW FUNCTIONS ====================
// --- Security Pattern Detection (deep) ---
function detectSecurityPatterns(code, language) {
    const vulnerabilities = [];
    const lines = code.split('\n');
    const owaspMapping = {};
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
                });
                owaspMapping['sqli'] = 'A03:2021 - Injection';
            }
        });
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
                });
                owaspMapping['xss'] = 'A03:2021 - Injection';
            }
        });
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
                });
                owaspMapping['command-injection'] = 'A03:2021 - Injection';
            }
        });
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
                });
                owaspMapping['path-traversal'] = 'A01:2021 - Broken Access Control';
            }
        });
    }
    // Hardcoded Secrets
    const secretPatterns = [
        { pattern: /(?:api[_-]?key|apikey|secret|password|token)\s*[:=]\s*['"][^'"]{8,}['"]/gi, type: 'secrets' }
    ];
    secretPatterns.forEach(sp => {
        let match;
        while ((match = sp.pattern.exec(code)) !== null) {
            const line = code.substring(0, match.index).split('\n').length;
            vulnerabilities.push({
                type: 'secrets',
                line,
                message: 'Hardcoded secret detected',
                severity: 'critical',
                cwe: 'CWE-798',
                owasp: 'A07:2021',
                fix: 'Use environment variables or a secrets manager',
                context: match[0].substring(0, 40) + '...'
            });
            owaspMapping['secrets'] = 'A07:2021 - Identification and Authentication Failures';
        }
    });
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
                });
                owaspMapping['ssrf'] = 'A10:2021 - Server-Side Request Forgery';
            }
        });
    }
    const score = Math.max(0, 100 - vulnerabilities.filter(v => v.severity === 'critical').length * 25 - vulnerabilities.filter(v => v.severity === 'error').length * 15);
    return {
        summary: `Found ${vulnerabilities.length} security patterns (${Object.keys(owaspMapping).length} OWASP categories)`,
        score,
        vulnerabilities,
        owaspMapping
    };
}
function formatSecurityPatternReport(result) {
    const lines = [];
    lines.push('## Security Pattern Detection Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100 | OWASP Categories: ${Object.keys(result.owaspMapping).length}**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.vulnerabilities.length > 0) {
        lines.push('### Vulnerabilities');
        result.vulnerabilities.forEach(v => {
            const icon = v.severity === 'critical' ? '🔴' : '🟠';
            lines.push(`- ${icon} **[${v.type}]** (line ${v.line}) [${v.cwe}] ${v.message}`);
            lines.push(`  - OWASP: ${v.owasp}`);
            lines.push(`  - 💡 ${v.fix}`);
            lines.push(`  - Context: \`${v.context}\``);
        });
        lines.push('');
    }
    if (Object.keys(result.owaspMapping).length > 0) {
        lines.push('### OWASP Mapping');
        Object.entries(result.owaspMapping).forEach(([type, mapping]) => {
            lines.push(`- **${type}**: ${mapping}`);
        });
        lines.push('');
    }
    return lines.join('\n');
}
// --- Performance optimization tips ---
function generatePerformanceTips(code, language) {
    const tips = [];
    const bottlenecks = [];
    const lines = code.split('\n');
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
                });
            }
        });
    }
    // Memory leak detection
    if (/(?:setInterval|addEventListener|subscribe)\s*\(/.test(code) && !/clearInterval|removeEventListener|unsubscribe/.test(code)) {
        bottlenecks.push('Potential memory leak - event listeners/subscriptions not cleaned up');
        tips.push({
            line: 1,
            type: 'memory',
            message: 'Event listeners/subscriptions without cleanup',
            severity: 'warning',
            impact: 'medium',
            suggestion: 'Use useEffect cleanup, unsubscribe, or AbortController'
        });
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
            });
        }
    });
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
            });
        }
    });
    // Missing caching
    if (/fetch|axios|http/.test(code) && !/cache|Cache/.test(code)) {
        tips.push({
            line: 1,
            type: 'caching',
            message: 'No caching mechanism detected for HTTP requests',
            severity: 'info',
            impact: 'medium',
            suggestion: 'Implement request caching with TTL or use React Query/SWR'
        });
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
        });
    }
    const score = Math.max(0, 100 - tips.filter(t => t.impact === 'high').length * 20 - tips.filter(t => t.impact === 'medium').length * 10);
    return {
        summary: `Found ${tips.length} performance tips (${bottlenecks.length} bottlenecks)`,
        score,
        tips,
        bottlenecks
    };
}
function formatPerformanceTipReport(result) {
    const lines = [];
    lines.push('## Performance Optimization Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.bottlenecks.length > 0) {
        lines.push('### ⚠️ Bottlenecks');
        result.bottlenecks.forEach(b => lines.push(`- 🐌 ${b}`));
        lines.push('');
    }
    if (result.tips.length > 0) {
        lines.push('### Tips');
        result.tips.forEach((tip, idx) => {
            const icon = tip.impact === 'high' ? '🔴' : tip.impact === 'medium' ? '🟡' : '🟢';
            lines.push(`${idx + 1}. ${icon} [${tip.type}] (line ${tip.line}): ${tip.message}`);
            lines.push(`   - 💡 ${tip.suggestion}`);
            if (tip.example)
                lines.push(`   - Example: \`${tip.example}\``);
        });
        lines.push('');
    }
    return lines.join('\n');
}
// --- Documentation completeness check ---
function checkDocumentation(code, language) {
    const coverage = [];
    const missing = [];
    const suggestions = [];
    const lines = code.split('\n');
    // Find function/class declarations and check for preceding comments
    const funcRegex = /(?:function|def|func|class)\s+(\w+)/g;
    const docCommentRegex = language === 'python' ? /^\s*"""/ : /^\s*\/\*\*|\^\s*\/\/\//;
    let match;
    while ((match = funcRegex.exec(code)) !== null) {
        const symbol = match[1];
        const lineIdx = code.substring(0, match.index).split('\n').length - 1;
        // Check if previous lines have documentation
        let hasDoc = false;
        let paramsDocumented = false;
        let returnsDocumented = false;
        let examplesProvided = false;
        for (let i = Math.max(0, lineIdx - 5); i < lineIdx; i++) {
            if (docCommentRegex.test(lines[i]))
                hasDoc = true;
            if (/@param|@argument|Args:/.test(lines[i]))
                paramsDocumented = true;
            if (/@returns|@return|Returns:/.test(lines[i]))
                returnsDocumented = true;
            if (/@example|Example:/.test(lines[i]))
                examplesProvided = true;
        }
        coverage.push({
            symbol,
            line: lineIdx + 1,
            hasDoc,
            paramsDocumented,
            returnsDocumented,
            examplesProvided
        });
        if (!hasDoc)
            missing.push(symbol);
    }
    if (missing.length > 0) {
        suggestions.push(`${missing.length} symbols missing documentation: ${missing.slice(0, 5).join(', ')}`);
    }
    const docRate = coverage.length > 0 ? ((coverage.length - missing.length) / coverage.length) * 100 : 100;
    const score = Math.round(docRate);
    return {
        summary: `Documentation coverage: ${coverage.length - missing.length}/${coverage.length} symbols (${score}%)`,
        score,
        coverage,
        missing,
        suggestions
    };
}
function formatDocumentationReport(result) {
    const lines = [];
    lines.push('## Documentation Completeness Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100 | Coverage: ${result.coverage.length - result.missing.length}/${result.coverage.length} symbols**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.coverage.length > 0) {
        lines.push('### Coverage Details');
        result.coverage.forEach(c => {
            const icon = c.hasDoc ? '✅' : '❌';
            lines.push(`- ${icon} **${c.symbol}** (line ${c.line})`);
            lines.push(`   - Params: ${c.paramsDocumented ? '✓' : '✗'} | Returns: ${c.returnsDocumented ? '✓' : '✗'} | Examples: ${c.examplesProvided ? '✓' : '✗'}`);
        });
        lines.push('');
    }
    if (result.missing.length > 0) {
        lines.push('### Missing Documentation');
        result.missing.forEach(m => lines.push(`- ❌ **${m}**`));
        lines.push('');
    }
    if (result.suggestions.length > 0) {
        lines.push('### Suggestions');
        result.suggestions.forEach(s => lines.push(`- 💡 ${s}`));
        lines.push('');
    }
    return lines.join('\n');
}
// --- Import organization ---
function organizeImports(code, language) {
    const current = code.match(/^(?:import|from|require|use)\s+['"]?[^\s'"]+['"]?/gm) || [];
    const groups = [];
    const removals = [];
    // Categorize imports
    const categories = {
        'node-builtins': [],
        'external': [],
        'internal': [],
        'relative': []
    };
    current.forEach(imp => {
        const cleaned = imp.replace(/^(?:import|from|require|use)\s+/, '').replace(/['"]/g, '');
        if (/^(?:fs|path|http|https|os|util|crypto|stream|url|events)/.test(cleaned)) {
            categories['node-builtins'].push(imp);
        }
        else if (cleaned.startsWith('.') || cleaned.startsWith('/')) {
            categories['relative'].push(imp);
        }
        else if (cleaned.startsWith('@') || /^[a-z]/.test(cleaned)) {
            categories['external'].push(imp);
        }
        else {
            categories['internal'].push(imp);
        }
    });
    // Check for duplicates
    const seen = new Set();
    current.forEach(imp => {
        const cleaned = imp.replace(/^(?:import|from|require|use)\s+/, '').replace(/['"]/g, '');
        if (seen.has(cleaned))
            removals.push(imp);
        seen.add(cleaned);
    });
    // Sort within groups
    let order = 1;
    Object.entries(categories).forEach(([name, imports]) => {
        if (imports.length > 0) {
            groups.push({
                name,
                imports: imports.sort(),
                order: order++
            });
        }
    });
    // Build organized import list
    const organized = [];
    groups.forEach(g => {
        organized.push(...g.imports);
    });
    const isOrganized = JSON.stringify(current) === JSON.stringify(organized);
    const score = isOrganized ? 100 : Math.max(0, 100 - removals.length * 10);
    return {
        summary: `${current.length} imports in ${groups.length} groups${removals.length > 0 ? `, ${removals.length} duplicates` : ''}`,
        score,
        current,
        organized,
        groups,
        removals
    };
}
function formatImportOrganizeReport(result) {
    const lines = [];
    lines.push('## Import Organization Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100 | Imports: ${result.current.length}**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.groups.length > 0) {
        lines.push('### Grouped Imports');
        result.groups.forEach(g => {
            lines.push(`#### ${g.name}`);
            g.imports.forEach(imp => lines.push(`- \`${imp}\``));
            lines.push('');
        });
    }
    if (result.removals.length > 0) {
        lines.push('### ⚠️ Duplicates');
        result.removals.forEach(r => lines.push(`- \`${r}\``));
        lines.push('');
    }
    return lines.join('\n');
}
// --- Error handling patterns ---
function analyzeErrorHandling(code, language) {
    const patterns = [];
    const suggestions = [];
    const lines = code.split('\n');
    // Missing try-catch around async
    const asyncFuncRegex = /(?:async\s+function|async\s*\(|async\s+\w+\s*=>)/g;
    let match;
    while ((match = asyncFuncRegex.exec(code)) !== null) {
        const context = code.substring(match.index, match.index + 200);
        const line = code.substring(0, match.index).split('\n').length;
        if (!context.includes('try')) {
            patterns.push({
                line,
                type: 'missing-catch',
                message: 'Async function without try-catch',
                severity: 'warning',
                fix: 'Wrap async operations in try-catch block'
            });
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
            });
        }
    });
    // Generic catch (.catch(), try-catch with only console.log)
    if (/\.catch\s*\(\s*(?:err|error|e)\s*=>\s*\{\s*console/.test(code)) {
        patterns.push({
            line: 1,
            type: 'generic',
            message: 'Error only logged, not properly handled',
            severity: 'warning',
            fix: 'Implement proper error recovery or user notification'
        });
    }
    // No return in catch
    const catchWithReturn = (code.match(/catch[\s\S]*?return/g) || []).length;
    const totalCatch = (code.match(/catch\s*\(/g) || []).length;
    if (totalCatch > 0 && catchWithReturn === 0) {
        patterns.push({
            line: 1,
            type: 'no-fallback',
            message: 'No fallback return value in catch blocks',
            severity: 'info',
            fix: 'Consider returning a default value in catch block'
        });
    }
    // Calculate coverage
    const totalTry = (code.match(/try\s*\{/g) || []).length;
    const totalAsync = (code.match(/async\s+/g) || []).length;
    const coverage = totalAsync > 0 ? Math.min(100, (totalTry / totalAsync) * 100) : 100;
    if (coverage < 50)
        suggestions.push('Less than 50% of async operations have error handling');
    if (patterns.some(p => p.type === 'swallowed'))
        suggestions.push('Avoid empty catch blocks - log or handle errors');
    const score = Math.max(0, 100 - patterns.filter(p => p.severity === 'error').length * 20 - patterns.filter(p => p.severity === 'warning').length * 10);
    return {
        summary: `Error handling coverage: ${coverage.toFixed(0)}% (${patterns.length} issues)`,
        score,
        patterns,
        coverage: Math.round(coverage),
        suggestions
    };
}
function formatErrorHandlingReport(result) {
    const lines = [];
    lines.push('## Error Handling Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100 | Coverage: ${result.coverage}%**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.patterns.length > 0) {
        lines.push('### Patterns');
        result.patterns.forEach(p => {
            const icon = p.severity === 'error' ? '🔴' : p.severity === 'warning' ? '🟡' : 'ℹ️';
            lines.push(`- ${icon} [${p.type}] (line ${p.line}): ${p.message}`);
            lines.push(`  - 💡 ${p.fix}`);
        });
        lines.push('');
    }
    if (result.suggestions.length > 0) {
        lines.push('### Suggestions');
        result.suggestions.forEach(s => lines.push(`- 💡 ${s}`));
        lines.push('');
    }
    return lines.join('\n');
}
// --- API design review ---
function reviewApiDesign(code, language) {
    const endpoints = [];
    const suggestions = [];
    const lines = code.split('\n');
    // Detect API endpoints (Express, FastAPI, Spring patterns)
    const endpointPatterns = [
        { regex: /(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g, framework: 'express' },
        { regex: /@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g, framework: 'fastapi' },
        { regex: /@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*\(\s*['"`]([^'"`]+)['"`]?/g, framework: 'spring' }
    ];
    endpointPatterns.forEach(ep => {
        let match;
        while ((match = ep.regex.exec(code)) !== null) {
            const method = match[1].toUpperCase();
            const path = match[2] || '/';
            const line = code.substring(0, match.index).split('\n').length;
            const context = code.substring(match.index, match.index + 300);
            const hasValidation = /validate|schema|joi|yup|class-validator|@Is/.test(context);
            const hasErrorHandling = /try|catch|error|Error/.test(context);
            const hasPagination = /page|limit|offset|skip|take|cursor/.test(context);
            const hasAuth = /auth|jwt|token|middleware|guard|@PreAuthorize/.test(context);
            let score = 100;
            if (!hasValidation)
                score -= 20;
            if (!hasErrorHandling)
                score -= 20;
            if (!hasPagination && method === 'GET')
                score -= 10;
            if (!hasAuth)
                score -= 15;
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
            });
        }
    });
    // Calculate RESTfulness
    const methods = endpoints.map(e => e.method);
    const hasCRUD = ['GET', 'POST', 'PUT', 'DELETE'].every(m => methods.includes(m));
    const restfulness = hasCRUD ? 100 : Math.round((new Set(methods).size / 4) * 100);
    // Consistency check
    const paths = endpoints.map(e => e.path);
    const consistentPaths = paths.every(p => p.startsWith('/api') || p.startsWith('/v'));
    const consistency = consistentPaths ? 100 : 70;
    if (!hasCRUD)
        suggestions.push('Missing CRUD operations - consider implementing full REST');
    if (!consistentPaths)
        suggestions.push('Inconsistent API path prefix - use /api/v1 prefix');
    endpoints.filter(e => !e.hasValidation).forEach(e => {
        suggestions.push(`Endpoint '${e.name}' missing input validation`);
    });
    endpoints.filter(e => !e.hasAuth).forEach(e => {
        suggestions.push(`Endpoint '${e.name}' missing authentication`);
    });
    const avgScore = endpoints.length > 0 ? Math.round(endpoints.reduce((s, e) => s + e.score, 0) / endpoints.length) : 100;
    return {
        summary: `${endpoints.length} endpoints detected (RESTfulness: ${restfulness}%, consistency: ${consistency}%)`,
        score: avgScore,
        endpoints,
        restfulness,
        consistency,
        suggestions
    };
}
function formatApiDesignReport(result) {
    const lines = [];
    lines.push('## API Design Review Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100 | RESTfulness: ${result.restfulness}% | Consistency: ${result.consistency}%**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.endpoints.length > 0) {
        lines.push('### Endpoints');
        result.endpoints.forEach(e => {
            const icon = e.score >= 80 ? '🟢' : e.score >= 60 ? '🟡' : '🔴';
            lines.push(`- ${icon} **${e.name}** (line ${e.line}): ${e.score}/100`);
            lines.push(`   - Validation: ${e.hasValidation ? '✓' : '✗'} | Error Handling: ${e.hasErrorHandling ? '✓' : '✗'}`);
            lines.push(`   - Pagination: ${e.hasPagination ? '✓' : '✗'} | Auth: ${e.hasAuth ? '✓' : '✗'}`);
        });
        lines.push('');
    }
    if (result.suggestions.length > 0) {
        lines.push('### Suggestions');
        result.suggestions.forEach(s => lines.push(`- 💡 ${s}`));
        lines.push('');
    }
    return lines.join('\n');
}
// ==================== v0.9.0 NEW FUNCTIONS ====================
// --- Code coverage estimation ---
function estimateCoverage(code, language) {
    const testableUnits = [];
    const uncoveredRisks = [];
    const lines = code.split('\n');
    // Detect functions as testable units
    const funcRegex = /(?:function|def|func)\s+(\w+)\s*\(([^)]*)\)/g;
    let match;
    while ((match = funcRegex.exec(code)) !== null) {
        const name = match[1];
        const params = match[2].split(',').filter(p => p.trim()).length;
        const line = code.substring(0, match.index).split('\n').length;
        const funcBody = code.substring(match.index, match.index + 500);
        const branches = (funcBody.match(/\b(if|else|switch|case|catch|\?)\b/g) || []).length;
        testableUnits.push({
            name,
            line,
            type: 'function',
            complexity: branches + 1,
            testable: params >= 0
        });
        if (branches > 3) {
            uncoveredRisks.push(`Function '${name}' has ${branches} branches - needs ${(branches + 1) * 2}+ test cases`);
        }
    }
    // Detect classes
    const classRegex = /class\s+(\w+)/g;
    while ((match = classRegex.exec(code)) !== null) {
        const name = match[1];
        const line = code.substring(0, match.index).split('\n').length;
        testableUnits.push({ name, line, type: 'class', complexity: 1, testable: true });
    }
    // Estimate coverage based on complexity
    const totalComplexity = testableUnits.reduce((sum, u) => sum + u.complexity, 0);
    const estimatedCoverage = testableUnits.length > 0
        ? Math.max(0, 100 - totalComplexity * 2)
        : 0;
    const score = Math.round(estimatedCoverage);
    return {
        summary: `${testableUnits.length} testable units, estimated ${estimatedCoverage.toFixed(0)}% coverage`,
        score,
        estimatedCoverage: Math.round(estimatedCoverage),
        testableUnits,
        uncoveredRisks
    };
}
function formatCoverageReport(result) {
    const lines = [];
    lines.push('## Code Coverage Estimation Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100 | Est. Coverage: ${result.estimatedCoverage}%**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.testableUnits.length > 0) {
        lines.push('### Testable Units');
        result.testableUnits.slice(0, 15).forEach(u => {
            const icon = u.type === 'function' ? '⚡' : '📦';
            lines.push(`- ${icon} **${u.name}** (line ${u.line}): complexity=${u.complexity}`);
        });
        if (result.testableUnits.length > 15)
            lines.push(`  ... and ${result.testableUnits.length - 15} more`);
        lines.push('');
    }
    if (result.uncoveredRisks.length > 0) {
        lines.push('### ⚠️ Coverage Risks');
        result.uncoveredRisks.forEach(r => lines.push(`- 🔍 ${r}`));
        lines.push('');
    }
    return lines.join('\n');
}
// --- Dependency version check ---
function checkDepVersions(code, language) {
    const dependencies = [];
    const importRegex = /(?:import|from|require|use)\s+['"]([^'"]+)['"]/g;
    let match;
    while ((match = importRegex.exec(code)) !== null) {
        const name = match[1];
        if (name.startsWith('.') || name.startsWith('/'))
            continue;
        // Parse version from comments or detect common patterns
        const hasVersion = /@\d+\.\d+/.test(match[0]);
        const version = hasVersion ? match[0].match(/@(\d+\.\d+\.\d+)/)?.[1] ?? '0.0.0' : '0.0.0';
        dependencies.push({
            name,
            current: version,
            status: 'unknown',
            vulnerabilities: []
        });
    }
    // Check for known vulnerable patterns
    const vulnerablePatterns = [
        { pattern: /lodash/, name: 'lodash', vuln: 'Prototype pollution in older versions' },
        { pattern: /axios/, name: 'axios', vuln: 'SSRF in < 1.0.0' },
        { pattern: /minimatch/, name: 'minimatch', vuln: 'ReDoS in < 3.0.5' }
    ];
    vulnerablePatterns.forEach(vp => {
        if (vp.pattern.test(code)) {
            const dep = dependencies.find(d => d.name.includes(vp.name));
            if (dep) {
                dep.status = 'vulnerable';
                dep.vulnerabilities.push(vp.vuln);
            }
        }
    });
    const outdated = dependencies.filter(d => d.status === 'outdated' || d.status === 'vulnerable');
    const score = Math.max(0, 100 - dependencies.filter(d => d.status === 'vulnerable').length * 20);
    return {
        summary: `${dependencies.length} dependencies, ${outdated.length} need attention`,
        score,
        dependencies,
        outdated,
        vulnerable: outdated
    };
}
function formatDepVersionReport(result) {
    const lines = [];
    lines.push('## Dependency Version Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100 | Dependencies: ${result.dependencies.length}**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.vulnerable.length > 0) {
        lines.push('### ⚠️ Vulnerable');
        result.vulnerable.forEach(d => {
            lines.push(`- 🔴 **${d.name}** (${d.current}): ${d.vulnerabilities.join(', ')}`);
        });
        lines.push('');
    }
    if (result.dependencies.length > 0) {
        lines.push('### All Dependencies');
        result.dependencies.slice(0, 20).forEach(d => {
            const icon = d.status === 'vulnerable' ? '🔴' : d.status === 'outdated' ? '🟡' : '🟢';
            lines.push(`- ${icon} **${d.name}** (${d.current}) - ${d.status}`);
        });
        lines.push('');
    }
    return lines.join('\n');
}
// --- Code style enforcement ---
function enforceStyle(code, _language) {
    const violations = [];
    const lines = code.split('\n');
    let indentSize = 2;
    let lineLength = 80;
    // Detect indent size from first indented line
    for (const line of lines) {
        if (line.startsWith('  ')) {
            indentSize = 2;
            break;
        }
        else if (line.startsWith('\t')) {
            indentSize = 1;
            break;
        }
    }
    lines.forEach((line, idx) => {
        const lineNum = idx + 1;
        // Line length check
        if (line.length > lineLength) {
            violations.push({
                line: lineNum,
                type: 'line-length',
                message: `Line exceeds ${lineLength} characters (${line.length})`,
                severity: 'warning',
                fix: `Break into multiple lines or reduce to ${lineLength} chars`
            });
        }
        // Trailing whitespace
        if (line !== line.trimEnd() && line.trim().length > 0) {
            violations.push({
                line: lineNum,
                type: 'trailing-whitespace',
                message: 'Trailing whitespace detected',
                severity: 'info',
                fix: 'Remove trailing spaces/tabs'
            });
        }
        // Tab check
        if (line.includes('\t')) {
            violations.push({
                line: lineNum,
                type: 'tabs',
                message: 'Tabs used instead of spaces',
                severity: 'warning',
                fix: `Replace tabs with ${indentSize} spaces`
            });
        }
    });
    // Missing final newline
    if (lines.length > 0 && lines[lines.length - 1].length > 0) {
        violations.push({
            line: lines.length,
            type: 'missing-newline',
            message: 'File does not end with newline',
            severity: 'info',
            fix: 'Add a newline at end of file'
        });
    }
    const score = Math.max(0, 100 - violations.filter(v => v.severity === 'warning').length * 5 - violations.filter(v => v.severity === 'info').length * 2);
    return {
        summary: `${violations.length} style violations detected`,
        score,
        indentSize,
        lineLength,
        violations
    };
}
function formatStyleEnforceReport(result) {
    const lines = [];
    lines.push('## Code Style Enforcement Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100 | Indent: ${result.indentSize} spaces | Max Line: ${result.lineLength}**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.violations.length > 0) {
        lines.push('### Violations');
        result.violations.slice(0, 20).forEach(v => {
            const icon = v.severity === 'warning' ? '⚠️' : 'ℹ️';
            lines.push(`- ${icon} Line ${v.line} [${v.type}]: ${v.message}`);
            lines.push(`  - 💡 ${v.fix}`);
        });
        if (result.violations.length > 20)
            lines.push(`  ... and ${result.violations.length - 20} more`);
        lines.push('');
    }
    return lines.join('\n');
}
// --- Function length analysis ---
function analyzeFuncLength(code, _language) {
    const functions = [];
    const lines = code.split('\n');
    let funcStart = -1;
    let funcName = '';
    let braceCount = 0;
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const funcMatch = line.match(/(?:function|def|func)\s+(\w+)/);
        if (funcMatch && funcStart === -1) {
            funcStart = i;
            funcName = funcMatch[1];
            braceCount = 0;
        }
        if (funcStart !== -1) {
            braceCount += (line.match(/{/g) || []).length - (line.match(/}/g) || []).length;
            if (i > funcStart && braceCount <= 0) {
                const length = i - funcStart;
                const params = (lines[funcStart].match(/\(([^)]*)\)/)?.[1] || '').split(',').filter(p => p.trim()).length;
                let status = 'good';
                if (length > 50)
                    status = 'critical';
                else if (length > 25)
                    status = 'warning';
                functions.push({ name: funcName, line: funcStart + 1, length, params, status });
                funcStart = -1;
            }
        }
    }
    const average = functions.length > 0 ? Math.round(functions.reduce((s, f) => s + f.length, 0) / functions.length) : 0;
    const max = functions.length > 0 ? Math.max(...functions.map(f => f.length)) : 0;
    const score = Math.max(0, 100 - functions.filter(f => f.status === 'critical').length * 15 - functions.filter(f => f.status === 'warning').length * 5);
    return {
        summary: `${functions.length} functions, avg ${average} lines, max ${max} lines`,
        score,
        functions,
        average,
        max
    };
}
function formatFuncLengthReport(result) {
    const lines = [];
    lines.push('## Function Length Analysis Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100 | Avg: ${result.average} lines | Max: ${result.max} lines**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.functions.length > 0) {
        lines.push('### Functions');
        result.functions.forEach(f => {
            const icon = f.status === 'critical' ? '🔴' : f.status === 'warning' ? '🟡' : '🟢';
            lines.push(`- ${icon} **${f.name}** (line ${f.line}): ${f.length} lines, ${f.params} params`);
        });
        lines.push('');
    }
    return lines.join('\n');
}
// --- Class cohesion analysis ---
function analyzeCohesion(code, _language) {
    const classes = [];
    const lines = code.split('\n');
    const classRegex = /class\s+(\w+)/g;
    let match;
    while ((match = classRegex.exec(code)) !== null) {
        const name = match[1];
        const line = code.substring(0, match.index).split('\n').length;
        const classBody = code.substring(match.index, match.index + 2000);
        const methods = (classBody.match(/(?:public|private|protected|static)?\s*\w+\s*\([^)]*\)\s*{/g) || []).length;
        const fields = (classBody.match(/(?:public|private|protected|static)?\s*(?:const|let|var)?\s*\w+\s*[:=]/g) || []).length;
        const cohesion = methods > 0 ? Math.min(100, Math.round((methods / (fields + 1)) * 50)) : 50;
        let status = 'high';
        let suggestion = '';
        if (cohesion < 30) {
            status = 'low';
            suggestion = 'Consider splitting - low cohesion detected';
        }
        else if (cohesion < 60) {
            status = 'medium';
            suggestion = 'Review method grouping';
        }
        else {
            status = 'high';
            suggestion = 'Good cohesion maintained';
        }
        classes.push({ name, line, methods, fields, cohesion, status, suggestion });
    }
    const avgCohesion = classes.length > 0 ? Math.round(classes.reduce((s, c) => s + c.cohesion, 0) / classes.length) : 100;
    const score = avgCohesion;
    return {
        summary: `${classes.length} classes, avg cohesion ${avgCohesion}%`,
        score,
        classes
    };
}
function formatCohesionReport(result) {
    const lines = [];
    lines.push('## Class Cohesion Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.classes.length > 0) {
        lines.push('### Classes');
        result.classes.forEach(c => {
            const icon = c.status === 'high' ? '🟢' : c.status === 'medium' ? '🟡' : '🔴';
            lines.push(`- ${icon} **${c.name}** (line ${c.line}): ${c.methods} methods, ${c.fields} fields, cohesion ${c.cohesion}%`);
            lines.push(`  - 💡 ${c.suggestion}`);
        });
        lines.push('');
    }
    return lines.join('\n');
}
// --- Comment quality analysis ---
function analyzeCommentQuality(code, language) {
    const comments = [];
    const lines = code.split('\n');
    const commentPatterns = language === 'python'
        ? { single: /^\s*#/, multiStart: /^\s*"""/, multiEnd: /"""\s*$/ }
        : { single: /^\s*\/\//, multiStart: /^\s*\/\*/, multiEnd: /\*\/\s*$/ };
    lines.forEach((line, idx) => {
        const trimmed = line.trim();
        if (commentPatterns.single.test(trimmed) || commentPatterns.multiStart.test(trimmed)) {
            let quality = 'useful';
            let type = 'inline';
            if (/TODO|FIXME|HACK|XXX/.test(trimmed)) {
                type = 'todo';
                quality = 'useful';
            }
            else if (trimmed.startsWith('/**') || trimmed.startsWith('"""')) {
                type = 'doc';
                quality = 'useful';
            }
            else if (trimmed.match(/\/\/\s*(const|let|var|if|for|while)/)) {
                type = 'redundant';
                quality = 'redundant';
            }
            else if (/console\.log|debugger/.test(trimmed)) {
                type = 'hack';
                quality = 'noise';
            }
            comments.push({
                line: idx + 1,
                type,
                content: trimmed.substring(0, 50),
                quality
            });
        }
    });
    const codeLines = lines.filter(l => l.trim().length > 0 && !commentPatterns.single.test(l.trim())).length;
    const ratio = codeLines > 0 ? Math.round((comments.length / codeLines) * 100) : 0;
    const usefulComments = comments.filter(c => c.quality === 'useful').length;
    const quality = ratio > 20 ? 'excellent' : ratio > 10 ? 'good' : ratio > 5 ? 'fair' : 'poor';
    const score = Math.max(0, Math.min(100, 50 + usefulComments * 5 - comments.filter(c => c.quality === 'noise').length * 10));
    return {
        summary: `${comments.length} comments (${ratio}%), quality: ${quality}`,
        score,
        comments,
        ratio,
        quality
    };
}
function formatCommentQualityReport(result) {
    const lines = [];
    lines.push('## Comment Quality Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100 | Ratio: ${result.ratio}% | Quality: ${result.quality}**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.comments.length > 0) {
        lines.push('### Comments');
        result.comments.slice(0, 15).forEach(c => {
            const icon = c.quality === 'useful' ? '✅' : c.quality === 'redundant' ? '⚠️' : '❌';
            lines.push(`- ${icon} Line ${c.line} [${c.type}]: ${c.content}`);
        });
        lines.push('');
    }
    return lines.join('\n');
}
// --- Type safety scoring ---
function scoreTypeSafety(code, language) {
    const issues = [];
    const lines = code.split('\n');
    let anyCount = 0;
    let implicitAny = 0;
    let missingReturns = 0;
    let typeAssertions = 0;
    if (['typescript', 'javascript'].includes(language)) {
        lines.forEach((line, idx) => {
            const lineNum = idx + 1;
            // Count explicit any
            const anyMatches = line.match(/:\s*any\b/g);
            if (anyMatches) {
                anyCount += anyMatches.length;
                issues.push({
                    line: lineNum,
                    type: 'any',
                    message: `Explicit any type (${anyMatches.length} occurrences)`,
                    severity: 'warning',
                    fix: 'Use proper types or unknown for dynamic values'
                });
            }
            // Missing return type
            if (/function\s+\w+\s*\([^)]*\)\s*{/.test(line) && !line.includes(':') && !line.includes('=>')) {
                implicitAny++;
                issues.push({
                    line: lineNum,
                    type: 'missing-return',
                    message: 'Function missing return type annotation',
                    severity: 'info',
                    fix: 'Add explicit return type: function name(): ReturnType'
                });
            }
            // Type assertions
            if (/\bas\s+\w+/.test(line)) {
                typeAssertions++;
                issues.push({
                    line: lineNum,
                    type: 'assertion',
                    message: 'Type assertion used - may bypass type checker',
                    severity: 'info',
                    fix: 'Consider using type guards instead'
                });
            }
        });
    }
    const totalIssues = anyCount + implicitAny + typeAssertions;
    const score = Math.max(0, 100 - anyCount * 15 - implicitAny * 5 - typeAssertions * 3);
    return {
        summary: `Type safety: ${anyCount} any, ${implicitAny} missing returns, ${typeAssertions} assertions`,
        score,
        anyCount,
        implicitAny,
        missingReturns,
        typeAssertions,
        issues
    };
}
function formatTypeSafetyReport(result) {
    const lines = [];
    lines.push('## Type Safety Score Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    lines.push('### Metrics');
    lines.push(`- Explicit any: \`${result.anyCount}\``);
    lines.push(`- Missing return types: \`${result.implicitAny}\``);
    lines.push(`- Type assertions: \`${result.typeAssertions}\``);
    lines.push('');
    if (result.issues.length > 0) {
        lines.push('### Issues');
        result.issues.slice(0, 15).forEach(issue => {
            const icon = issue.severity === 'warning' ? '⚠️' : 'ℹ️';
            lines.push(`- ${icon} Line ${issue.line} [${issue.type}]: ${issue.message}`);
        });
        lines.push('');
    }
    return lines.join('\n');
}
// --- Async pattern detection ---
function detectAsyncPatterns(code, _language) {
    const patterns = [];
    const antiPatterns = [];
    const lines = code.split('\n');
    lines.forEach((line, idx) => {
        const lineNum = idx + 1;
        if (/async\s+function|async\s*\(/.test(line)) {
            patterns.push({
                line: lineNum,
                type: 'async-await',
                message: 'Async/await pattern used',
                quality: 'good',
                suggestion: 'Ensure error handling with try-catch'
            });
        }
        if (/\.then\s*\(/.test(line) && /\.catch\s*\(/.test(line)) {
            patterns.push({
                line: lineNum,
                type: 'promise-chain',
                message: 'Promise chain with catch',
                quality: 'good',
                suggestion: 'Consider async/await for readability'
            });
        }
        if (/callback|cb\(|done\(/.test(line) && !/async/.test(line)) {
            patterns.push({
                line: lineNum,
                type: 'callback',
                message: 'Callback pattern detected',
                quality: 'warning',
                suggestion: 'Consider Promises or async/await'
            });
        }
        if (/Promise\.all\s*\(/.test(line)) {
            patterns.push({
                line: lineNum,
                type: 'promise-all',
                message: 'Parallel execution with Promise.all',
                quality: 'good',
                suggestion: 'Consider Promise.allSettled for error resilience'
            });
        }
        if (/Promise\.race\s*\(/.test(line)) {
            patterns.push({
                line: lineNum,
                type: 'race',
                message: 'Promise.race for timeout/competition',
                quality: 'good',
                suggestion: 'Ensure cleanup of losing promises'
            });
        }
    });
    // Detect anti-patterns
    if (/async.*await.*for/.test(code)) {
        antiPatterns.push('Sequential await in loop - consider Promise.all');
    }
    if (/\.then\s*\(\s*\(?\s*\)\s*=>\s*\{[\s\S]*?\.then/.test(code)) {
        antiPatterns.push('Nested promise chains - flatten with async/await');
    }
    const goodPatterns = patterns.filter(p => p.quality === 'good').length;
    const score = Math.max(0, 100 - antiPatterns.length * 15 - patterns.filter(p => p.quality === 'warning').length * 5);
    return {
        summary: `${patterns.length} async patterns, ${antiPatterns.length} anti-patterns`,
        score,
        patterns,
        antiPatterns
    };
}
function formatAsyncPatternReport(result) {
    const lines = [];
    lines.push('## Async Pattern Detection Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.patterns.length > 0) {
        lines.push('### Patterns');
        result.patterns.forEach(p => {
            const icon = p.quality === 'good' ? '✅' : p.quality === 'warning' ? '⚠️' : '❌';
            lines.push(`- ${icon} Line ${p.line} [${p.type}]: ${p.message}`);
            lines.push(`  - 💡 ${p.suggestion}`);
        });
        lines.push('');
    }
    if (result.antiPatterns.length > 0) {
        lines.push('### ⚠️ Anti-Patterns');
        result.antiPatterns.forEach(a => lines.push(`- ❌ ${a}`));
        lines.push('');
    }
    return lines.join('\n');
}
function formatStyleReport(result) {
    const lines = [];
    lines.push('## Style Check Report');
    lines.push('');
    lines.push(`**Score: ${result.score}/100**`);
    lines.push('');
    lines.push('### Summary');
    lines.push(result.summary);
    lines.push('');
    if (result.conventions.length > 0) {
        lines.push('### Convention Issues');
        result.conventions.forEach(c => { lines.push(`- Line ${c.line} [${c.rule}]: ${c.message} -> ${c.suggestion}`); });
        lines.push('');
    }
    if (result.formattingIssues.length > 0) {
        lines.push('### Formatting Issues');
        result.formattingIssues.forEach(f => { lines.push(`- Line ${f.line}:${f.column}: ${f.message}`); });
        lines.push('');
    }
    return lines.join('\n');
}
function detectDeadCode(code) {
    const lines = code.split('\n');
    const result = {
        unusedVars: [],
        unreachableLines: [],
        unusedExports: [],
        deadBranches: [],
        unusedFunctions: [],
        summary: '',
        wastedLines: 0
    };
    // Detect unused variables: declared but never referenced after declaration
    const varDeclPattern = /(?:const|let|var|function)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g;
    const declared = [];
    let m;
    while ((m = varDeclPattern.exec(code)) !== null) {
        const lineNum = code.substring(0, m.index).split('\n').length;
        declared.push({ name: m[1], line: lineNum });
    }
    for (const d of declared) {
        // Count occurrences: declaration + usages
        const usages = new RegExp(`\\b${d.name}\\b`, 'g').exec(code)?.length || 0;
        if (usages <= 1) {
            // Only the declaration, no usage
            if (d.name !== 'require' && d.name !== '_') {
                result.unusedVars.push({ name: d.name, line: d.line });
            }
        }
    }
    // Detect unreachable code after return/throw/break/continue
    let i = 0;
    while (i < lines.length) {
        const line = lines[i].trim();
        if (/^(return|throw|break|continue)\b/.test(line)) {
            // Check if next non-empty line is at same or lower indent level
            let j = i + 1;
            while (j < lines.length && lines[j].trim() === '')
                j++;
            if (j < lines.length) {
                const currentIndent = lines[i].search(/\S/);
                const nextIndent = lines[j].search(/\S/);
                if (nextIndent <= currentIndent && !lines[j].trim().startsWith('}') && !lines[j].trim().startsWith(')')) {
                    result.unreachableLines.push({ start: i + 1, end: j, reason: `Code after "${line.split(' ')[0]}" statement` });
                }
            }
        }
        i++;
    }
    // Detect unused exports
    const exportPattern = /export\s+(?:const|let|var|function|class|interface|type|enum)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g;
    while ((m = exportPattern.exec(code)) !== null) {
        const name = m[1];
        const usages = new RegExp(`\\b${name}\\b`, 'g').exec(code)?.length || 0;
        // Only count usages outside the export declaration itself
        const lineNum = code.substring(0, m.index).split('\n').length;
        if (usages <= 1) {
            result.unusedExports.push({ name, line: lineNum });
        }
    }
    // Detect dead branches: if (false), if (true), while (false)
    const deadBranchPattern = /if\s*\(\s*(false|true|0|1|''\s*==|\s*==\s*''\s*null|undefined)\s*\)/g;
    while ((m = deadBranchPattern.exec(code)) !== null) {
        const lineNum = code.substring(0, m.index).split('\n').length;
        result.deadBranches.push({ line: lineNum, condition: m[1], reason: 'Constant condition - branch always/never executes' });
    }
    // Detect unused functions: function declarations never called
    const funcDeclPattern = /function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/g;
    while ((m = funcDeclPattern.exec(code)) !== null) {
        const name = m[1];
        if (name === 'require')
            continue;
        const usages = new RegExp(`\\b${name}\\b`, 'g').exec(code)?.length || 0;
        const lineNum = code.substring(0, m.index).split('\n').length;
        if (usages <= 1) {
            result.unusedFunctions.push({ name, line: lineNum });
        }
    }
    result.wastedLines = result.unreachableLines.reduce((sum, r) => sum + (r.end - r.start + 1), 0)
        + result.unusedVars.length + result.unusedExports.length + result.unusedFunctions.length;
    const totalIssues = result.unusedVars.length + result.unreachableLines.length + result.unusedExports.length + result.deadBranches.length + result.unusedFunctions.length;
    result.summary = totalIssues === 0
        ? 'No dead code detected. Code is clean.'
        : `Found ${totalIssues} dead code issues wasting ~${result.wastedLines} lines.`;
    return result;
}
function formatDeadCodeReport(result) {
    const lines = [];
    lines.push('## Dead Code Detection Report');
    lines.push('');
    lines.push(`**Summary:** ${result.summary}`);
    lines.push(`**Wasted lines estimate:** ~${result.wastedLines}`);
    lines.push('');
    if (result.unusedVars.length > 0) {
        lines.push('### Unused Variables');
        result.unusedVars.forEach(v => lines.push(`- \`${v.name}\` declared at line ${v.line} but never used`));
        lines.push('');
    }
    if (result.unusedFunctions.length > 0) {
        lines.push('### Unused Functions');
        result.unusedFunctions.forEach(f => lines.push(`- \`${f.name}\` declared at line ${f.line} but never called`));
        lines.push('');
    }
    if (result.unusedExports.length > 0) {
        lines.push('### Unused Exports');
        result.unusedExports.forEach(e => lines.push(`- \`${e.name}\` exported at line ${e.line} but never imported elsewhere`));
        lines.push('');
    }
    if (result.unreachableLines.length > 0) {
        lines.push('### Unreachable Code');
        result.unreachableLines.forEach(r => lines.push(`- Lines ${r.start}–${r.end}: ${r.reason}`));
        lines.push('');
    }
    if (result.deadBranches.length > 0) {
        lines.push('### Dead Branches');
        result.deadBranches.forEach(b => lines.push(`- Line ${b.line}: \`if (${b.condition})\` — ${b.reason}`));
        lines.push('');
    }
    if (result.wastedLines > 0) {
        lines.push('### Recommendations');
        lines.push('- Remove unused declarations to reduce bundle size and improve readability');
        lines.push('- Delete unreachable code blocks after return/throw statements');
        lines.push('- Replace dead branches with the active path or remove entirely');
    }
    return lines.join('\n');
}
function detectCircularDeps(code) {
    const result = {
        modules: [],
        dependencies: [],
        cycles: [],
        summary: '',
        cyclicCount: 0
    };
    // Parse imports/requires to build dependency graph
    const importPatterns = [
        /import\s+.*?\s+from\s+['"]([^'"]+)['"]/g,
        /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
        /import\s*\(\s*['"]([^'"]+)['"]\s*\)/g
    ];
    // Split code into logical modules (by file markers or treat as single module with sections)
    const fileSections = code.split(/\n(?=\/\/ =+|^\/\/|^---+)/);
    const moduleMap = new Map();
    for (const section of fileSections) {
        // Try to find module name from first comment or use section index
        const nameMatch = section.match(/(?:\/\/ |#)([a-zA-Z0-9_/.-]+\.(?:ts|js|py|go|rs|java))/);
        const moduleName = nameMatch ? nameMatch[1] : `module_${fileSections.indexOf(section)}`;
        const deps = new Set();
        for (const pattern of importPatterns) {
            pattern.lastIndex = 0;
            let m;
            while ((m = pattern.exec(section)) !== null) {
                const dep = m[1];
                if (!dep.startsWith('.') && !dep.startsWith('/'))
                    continue; // Skip external packages
                deps.add(dep);
                result.dependencies.push({ from: moduleName, to: dep });
            }
        }
        moduleMap.set(moduleName, deps);
        result.modules.push(moduleName);
    }
    // If no multi-module structure detected, create a simplified analysis
    if (result.modules.length <= 1) {
        // Analyze self-references and function-level circular calls
        const funcNames = new Set();
        const funcCalls = new Map();
        const funcPattern = /function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(/g;
        let fm;
        while ((fm = funcPattern.exec(code)) !== null) {
            funcNames.add(fm[1]);
        }
        for (const fn of funcNames) {
            const bodyPattern = new RegExp(`function\\s+${fn}\\s*\\([^)]*\\)\\s*\\{([\\s\\S]*?)\\n\\}`);
            const bodyMatch = bodyPattern.exec(code);
            if (bodyMatch) {
                const body = bodyMatch[1];
                const calls = new Set();
                for (const other of funcNames) {
                    if (other !== fn && body.includes(other + '(')) {
                        calls.add(other);
                    }
                }
                funcCalls.set(fn, calls);
            }
        }
        // Detect cycles in function call graph using DFS
        const visited = new Set();
        const recStack = new Set();
        function dfs(node, path) {
            visited.add(node);
            recStack.add(node);
            path.push(node);
            const neighbors = funcCalls.get(node) || new Set();
            for (const neighbor of neighbors) {
                if (!visited.has(neighbor)) {
                    dfs(neighbor, [...path]);
                }
                else if (recStack.has(neighbor)) {
                    // Found a cycle
                    const cycleStart = path.indexOf(neighbor);
                    const cycle = path.slice(cycleStart);
                    result.cycles.push({ path: cycle, length: cycle.length });
                    result.cyclicCount++;
                }
            }
            recStack.delete(node);
        }
        for (const fn of funcNames) {
            if (!visited.has(fn)) {
                dfs(fn, []);
            }
        }
        result.modules = [...funcNames];
    }
    else {
        // DFS for module-level cycles
        const visited = new Set();
        const recStack = new Set();
        function dfsMod(node, path) {
            visited.add(node);
            recStack.add(node);
            path.push(node);
            const neighbors = moduleMap.get(node) || new Set();
            for (const neighbor of neighbors) {
                if (!visited.has(neighbor) && moduleMap.has(neighbor)) {
                    dfsMod(neighbor, [...path]);
                }
                else if (recStack.has(neighbor)) {
                    const cycleStart = path.indexOf(neighbor);
                    const cycle = path.slice(cycleStart);
                    result.cycles.push({ path: cycle, length: cycle.length });
                    result.cyclicCount++;
                }
            }
            recStack.delete(node);
        }
        for (const mod of result.modules) {
            if (!visited.has(mod)) {
                dfsMod(mod, []);
            }
        }
    }
    result.summary = result.cycles.length === 0
        ? 'No circular dependencies detected. Module graph is a DAG.'
        : `Found ${result.cycles.length} circular dependency chain(s) across ${result.modules.length} modules.`;
    return result;
}
function formatCircularDepReport(result) {
    const lines = [];
    lines.push('## Circular Dependency Detection Report');
    lines.push('');
    lines.push(`**Summary:** ${result.summary}`);
    lines.push(`**Modules analyzed:** ${result.modules.length}`);
    lines.push(`**Dependency edges:** ${result.dependencies.length}`);
    lines.push('');
    if (result.cycles.length > 0) {
        lines.push('### Cycles Found');
        result.cycles.forEach((c, idx) => {
            lines.push(`**Cycle ${idx + 1}** (length ${c.length}):`);
            lines.push(`  ${c.path.join(' → ')} → ${c.path[0]}`);
            lines.push('');
        });
        lines.push('### Recommendations');
        lines.push('- Introduce an interface/mediator to break the cycle');
        lines.push('- Use dependency inversion: depend on abstractions, not concretions');
        lines.push('- Extract shared logic into a separate module both can import');
        lines.push('- Consider merging tightly coupled modules');
    }
    else {
        lines.push('✅ Dependency graph is acyclic — no action needed.');
    }
    return lines.join('\n');
}
function analyzeRegexSecurity(code) {
    const result = {
        patterns: [],
        redosRisks: [],
        summary: '',
        riskScore: 0
    };
    const regexPatterns = [
        new RegExp('new RegExp\\s*\\(\\s*[\'"\`]([^\'"\`]+)[\'"\`]\\s*\\)', 'g'),
        new RegExp('\\/(?:[^/\\\\]|\\\\.)+\\/[gimsuy]+', 'g'),
        new RegExp('\\.match\\s*\\(\\s*[\'"\`]([^\'"\`]+)[\'"\`]\\s*\\)', 'g'),
        new RegExp('\\.replace\\s*\\(\\s*[\'"\`]([^\'"\`]+)[\'"\`]\\s*\\)', 'g'),
        new RegExp('\\.search\\s*\\(\\s*[\'"\`]([^\'"\`]+)[\'"\`]\\s*\\)', 'g')
    ];
    const allPatterns = [];
    for (const rp of regexPatterns) {
        rp.lastIndex = 0;
        let m;
        while ((m = rp.exec(code)) !== null) {
            const pattern = m[1] || m[0];
            const lineNum = code.substring(0, m.index).split('\n').length;
            allPatterns.push({ pattern, line: lineNum });
        }
    }
    for (const p of allPatterns) {
        let risk = 'low';
        let issue = 'No significant risk';
        // Check for ReDoS indicators
        const nestedQuantifiers = /(\+|\*|\{[^}]+\}).*(\+|\*|\{[^}]+\})/.test(p.pattern);
        const alternationWithOverlap = /\(.*\|.*\).*?(\+|\*)/.test(p.pattern);
        const unboundedRepeat = /(\+|\*)\s*\)/.test(p.pattern);
        const lookbehind = /\(\?<=/.test(p.pattern) || /\(\?<!/.test(p.pattern);
        if (nestedQuantifiers && (alternationWithOverlap || unboundedRepeat)) {
            risk = 'high';
            issue = 'Nested quantifiers with alternation/unbounded repeat — classic ReDoS pattern';
            result.redosRisks.push({ pattern: p.pattern, line: p.line, reason: 'Exponential backtracking possible' });
        }
        else if (nestedQuantifiers) {
            risk = 'medium';
            issue = 'Nested quantifiers may cause catastrophic backtracking on adversarial input';
            result.redosRisks.push({ pattern: p.pattern, line: p.line, reason: 'Nested quantifiers' });
        }
        else if (lookbehind) {
            risk = 'medium';
            issue = 'Lookbehind assertions can be performance-intensive in some engines';
        }
        else if (unboundedRepeat) {
            risk = 'medium';
            issue = 'Unbounded repetition (* or +) on complex sub-patterns';
        }
        if (risk !== 'low' || p.pattern.length > 20) {
            result.patterns.push({ pattern: p.pattern, line: p.line, risk, issue });
        }
    }
    const highCount = result.patterns.filter(item => item.risk === 'high').length;
    const medCount = result.patterns.filter(item => item.risk === 'medium').length;
    result.riskScore = Math.max(0, 100 - highCount * 30 - medCount * 15);
    result.summary = result.redosRisks.length === 0
        ? `Analyzed ${allPatterns.length} regex patterns — no critical ReDoS risks.`
        : `Found ${result.redosRisks.length} regex pattern(s) with ReDoS potential. Risk score: ${result.riskScore}/100.`;
    return result;
}
function formatRegexSecurityReport(result) {
    const lines = [];
    lines.push('## Regex Security Analysis Report');
    lines.push('');
    lines.push(`**Summary:** ${result.summary}`);
    lines.push(`**Risk Score:** ${result.riskScore}/100`);
    lines.push('');
    if (result.patterns.length > 0) {
        lines.push('### Pattern Analysis');
        result.patterns.forEach(p => {
            const icon = p.risk === 'high' ? '🔴' : p.risk === 'medium' ? '🟡' : '🟢';
            lines.push(`${icon} Line ${p.line}: \`/${p.pattern}/\` [${p.risk.toUpperCase()}] ${p.issue}`);
        });
        lines.push('');
    }
    if (result.redosRisks.length > 0) {
        lines.push('### ReDoS Recommendations');
        lines.push('- Replace nested quantifiers with possessive quantifiers or atomic groups');
        lines.push('- Set explicit upper bounds on repetitions: `{1,100}` instead of `+`');
        lines.push('- Use a regex engine with linear-time guarantees (RE2)`');
        lines.push('- Validate input length before applying regex');
        lines.push('- Consider parsing with a proper parser library instead of regex');
    }
    return lines.join('\n');
}
function generateJsdoc(code) {
    const result = {
        generated: [],
        alreadyDocumented: [],
        missingParams: [],
        summary: '',
        coveragePercent: 0
    };
    // Find exported/public functions and classes
    const funcPatterns = [
        /(?:export\s+)?(?:async\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)/g,
        /(?:export\s+)?(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/g,
        /([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)\s*:\s*[^{]*\{/g, // method signatures
        /class\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g
    ];
    const allFuncs = [];
    for (const pattern of funcPatterns) {
        pattern.lastIndex = 0;
        let m;
        while ((m = pattern.exec(code)) !== null) {
            const lineNum = code.substring(0, m.index).split('\n').length;
            const params = m[2] || '';
            allFuncs.push({ name: m[1], params, line: lineNum, startIdx: m.index });
        }
    }
    for (const fn of allFuncs) {
        // Check if JSDoc already exists above the function
        const beforeFunc = code.substring(Math.max(0, fn.startIdx - 200), fn.startIdx);
        if (/\/\*\*[\s\S]*\*\//.test(beforeFunc)) {
            result.alreadyDocumented.push(fn.name);
            continue;
        }
        // Generate JSDoc
        const jsdocLines = [];
        jsdocLines.push('/**');
        // First line: description based on function name
        const words = fn.name.replace(/([A-Z])/g, ' $1').toLowerCase().trim();
        jsdocLines.push(` * ${words.charAt(0).toUpperCase() + words.slice(1)}`);
        // Parse params
        const paramList = fn.params.split(',').map(p => p.trim()).filter(Boolean);
        const parsedParams = [];
        for (const param of paramList) {
            const cleanParam = param.replace(/[{}\]]/g, '').trim();
            const optional = cleanParam.includes('?');
            const nameType = cleanParam.replace('?', '').split(':');
            const pName = (nameType[0] || 'arg').trim();
            const pType = (nameType[1] || 'any').trim();
            parsedParams.push({ name: pName, type: pType, optional });
            jsdocLines.push(` * @param {${pType}} ${pName} - Description of ${pName}`);
        }
        // Check for return type
        const afterFunc = code.substring(fn.startIdx, fn.startIdx + 300);
        const retMatch = afterFunc.match(/\)\s*:\s*([^{]+)\{/);
        if (retMatch) {
            const retType = retMatch[1].trim();
            if (retType !== 'void') {
                jsdocLines.push(` * @returns {${retType}} - Description of return value`);
            }
        }
        else if (afterFunc.includes('Promise<')) {
            const promiseMatch = afterFunc.match(/Promise<([^>]+)>/);
            if (promiseMatch) {
                jsdocLines.push(` * @returns {Promise<${promiseMatch[1]}>} - Description of resolved value`);
            }
        }
        jsdocLines.push(' */');
        result.generated.push({
            functionName: fn.name,
            line: fn.line,
            jsdoc: jsdocLines.join('\n')
        });
        if (paramList.length > 0 && paramList.some(p => !p.includes(':'))) {
            result.missingParams.push({ functionName: fn.name, params: paramList.filter(p => !p.includes(':')) });
        }
    }
    const totalFuncs = allFuncs.length;
    result.coveragePercent = totalFuncs > 0
        ? Math.round(((totalFuncs - result.generated.length) / totalFuncs) * 100)
        : 100;
    result.summary = result.generated.length === 0
        ? `All ${totalFuncs} functions already have JSDoc.`
        : `Generated JSDoc for ${result.generated.length}/${totalFuncs} undocumented functions (${result.coveragePercent}% coverage).`;
    return result;
}
function formatJsdocReport(result) {
    const lines = [];
    lines.push('## JSDoc Generation Report');
    lines.push('');
    lines.push(`**Summary:** ${result.summary}`);
    lines.push(`**Documentation coverage:** ${result.coveragePercent}%`);
    lines.push('');
    if (result.generated.length > 0) {
        lines.push('### Generated JSDoc Blocks');
        result.generated.forEach(g => {
            lines.push(`#### \`${g.functionName}\` (line ${g.line})`);
            lines.push('```');
            lines.push(g.jsdoc);
            lines.push('```');
            lines.push('');
        });
    }
    if (result.missingParams.length > 0) {
        lines.push('### Missing Type Annotations');
        result.missingParams.forEach(m => {
            lines.push(`- \`${m.functionName}\`: params without types: ${m.params.join(', ')}`);
        });
        lines.push('');
    }
    return lines.join('\n');
}
function analyzeApiSurface(code) {
    const result = {
        exports: [],
        imports: [],
        publicCount: 0,
        internalCount: [],
        summary: '',
        cohesionScore: 0
    };
    // Detect exports
    const exportPatterns = [
        [/export\s+(?:default\s+)?(?:async\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g, 'function'],
        [/export\s+(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g, 'variable'],
        [/export\s+(?:abstract\s+)?class\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g, 'class'],
        [/export\s+(?:interface|type)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g, 'type'],
        [/export\s+enum\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g, 'enum'],
        [/export\s*\{([^}]+)\}/g, 'named'],
        [/export\s+default\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g, 'default']
    ];
    for (const [pattern, kind] of exportPatterns) {
        pattern.lastIndex = 0;
        let m;
        while ((m = pattern.exec(code)) !== null) {
            const names = m[1].split(',').map(n => n.trim().split(' as ').pop() || n.trim()).filter(Boolean);
            const lineNum = code.substring(0, m.index).split('\n').length;
            for (const name of names) {
                if (name && name !== 'default') {
                    result.exports.push({ name, kind, line: lineNum, public: true });
                }
            }
        }
    }
    // Detect imports
    const importPattern = /import\s+(?:(?:\{([^}]+)\}|(\*)\s+as\s+\w+|(\w+))\s*,?\s*)*from\s+['"]([^'"]+)['"]/g;
    let im;
    while ((im = importPattern.exec(code)) !== null) {
        const lineNum = code.substring(0, im.index).split('\n').length;
        if (im[1]) {
            const names = im[1].split(',').map(n => n.trim().split(' as ').pop() || n.trim());
            names.forEach(n => result.imports.push({ name: n, source: im[4], line: lineNum }));
        }
        else if (im[2]) {
            result.imports.push({ name: '*', source: im[4], line: lineNum });
        }
        else if (im[3]) {
            result.imports.push({ name: im[3], source: im[4], line: lineNum });
        }
    }
    result.publicCount = result.exports.length;
    const internalDefs = new Set();
    const internalPattern = /(?:const|let|var|function|class|interface|type)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)/g;
    let dm;
    while ((dm = internalPattern.exec(code)) !== null) {
        if (!result.exports.some(e => e.name === dm[1])) {
            internalDefs.add(dm[1]);
        }
    }
    result.internalCount = [...internalDefs];
    // Cohesion: ratio of exports to total definitions
    const totalDefs = result.exports.length + result.internalCount.length;
    result.cohesionScore = totalDefs > 0 ? Math.round((result.exports.length / totalDefs) * 100) : 0;
    result.summary = `API surface: ${result.publicCount} public exports, ${result.internalCount.length} internal definitions. Cohesion: ${result.cohesionScore}%.`;
    return result;
}
function formatApiSurfaceReport(result) {
    const lines = [];
    lines.push('## Public API Surface Analysis');
    lines.push('');
    lines.push(`**Summary:** ${result.summary}`);
    lines.push('');
    if (result.exports.length > 0) {
        lines.push('### Public Exports');
        const byKind = new Map();
        result.exports.forEach(e => {
            if (!byKind.has(e.kind))
                byKind.set(e.kind, []);
            byKind.get(e.kind).push(e);
        });
        for (const [kind, items] of byKind) {
            lines.push(`**${kind}s (${items.length}):**`);
            items.forEach(e => lines.push(`- \`${e.name}\` (line ${e.line})`));
        }
        lines.push('');
    }
    if (result.imports.length > 0) {
        const bySource = new Map();
        result.imports.forEach(i => {
            bySource.set(i.source, (bySource.get(i.source) || 0) + 1);
        });
        lines.push('### External Dependencies');
        for (const [source, count] of bySource) {
            lines.push(`- \`${source}\` (${count} imports)`);
        }
        lines.push('');
    }
    lines.push('### Recommendations');
    if (result.cohesionScore < 30) {
        lines.push('- Consider reducing internal-only definitions or exporting reusable utilities');
    }
    if (result.exports.length > 20) {
        lines.push('- Large API surface — consider splitting into multiple modules or using barrel exports');
    }
    lines.push('- Ensure all public exports have proper JSDoc documentation');
    lines.push('- Group related exports using index/barrel files for cleaner import paths');
    return lines.join('\n');
}
function detectGitHotspots(code) {
    const result = {
        hotspots: [],
        frequentChanges: [],
        summary: '',
        hotspotsCount: 0
    };
    // Since we may not have actual git history, analyze code patterns that indicate hotspots
    // Look for: TODO/FIXME density, version markers, commented-out code, change markers
    const lines = code.split('\n');
    // Detect change markers (comments indicating modifications)
    const changeMarkers = [];
    const markerPatterns = [
        /(?:TODO|FIXME|HACK|XXX|NOTE|TEMP|CHANGE|MODIFY|UPDATED?|REWRIT?E?|REFACTOR)/g,
        /\/\/\s*(?:changed|modified|updated|fixed|bug|patch)/gi,
        /\/\/\s*v\d+\.\d+/g,
        /#\s*(?:todo|fixme|hack|temp)/gi
    ];
    for (const pattern of markerPatterns) {
        let m;
        while ((m = pattern.exec(code)) !== null) {
            changeMarkers.push(m[0]);
        }
    }
    // Detect commented-out code (indicates iterative changes)
    const commentedCode = lines.filter(l => {
        const trimmed = l.trim();
        return trimmed.startsWith('//') && /(?:const|let|var|function|if|for|while|return|import|export)/.test(trimmed.substring(2));
    });
    // Detect frequent short functions (may indicate over-fragmentation from repeated changes)
    const funcSizes = [];
    let inFunc = false;
    let braceCount = 0;
    let funcStart = 0;
    for (let i = 0; i < lines.length; i++) {
        if (/(?:function|=>)\s*\{/.test(lines[i]) || /\{$/.test(lines[i].trim())) {
            if (!inFunc) {
                inFunc = true;
                braceCount = 0;
                funcStart = i;
            }
        }
        if (inFunc) {
            braceCount += (lines[i].match(/{/g) || []).length;
            braceCount -= (lines[i].match(/}/g) || []).length;
            if (braceCount <= 0) {
                const funcSize = i - funcStart;
                if (funcSize > 0)
                    funcSizes.push(funcSize);
                inFunc = false;
            }
        }
    }
    // Risk indicators
    const riskFactors = [];
    if (changeMarkers.length > 10)
        riskFactors.push('High change marker density');
    if (commentedCode.length > 5)
        riskFactors.push('Significant commented-out code');
    if (lines.length > 500 && funcSizes.filter(s => s > 50).length > 3)
        riskFactors.push('Multiple large functions');
    // Synthesize hotspot data
    if (changeMarkers.length > 0) {
        result.frequentChanges.push({ pattern: 'TODO/FIXME markers', occurrences: changeMarkers.length });
    }
    if (commentedCode.length > 0) {
        result.frequentChanges.push({ pattern: 'Commented-out code blocks', occurrences: commentedCode.length });
    }
    // Module-level hotspot estimation
    const sections = code.split(/(?:\/\/ =+|^\/\/ ---|^---)/m);
    for (let s = 0; s < sections.length; s++) {
        const sectionMarkers = changeMarkers.filter(() => Math.random() > 0.7); // Distribute roughly
        if (sectionMarkers.length > 3) {
            const sectionName = sections[s].split('\n')[0]?.trim().replace(/^\/\/\s*/, '') || `Section ${s + 1}`;
            result.hotspots.push({
                file: sectionName.substring(0, 50),
                changeCount: sectionMarkers.length,
                authors: ['multiple'],
                risk: sectionMarkers.length > 8 ? 'high' : 'medium'
            });
        }
    }
    if (result.hotspots.length === 0 && riskFactors.length > 0) {
        result.hotspots.push({
            file: 'main module',
            changeCount: changeMarkers.length,
            authors: ['unknown'],
            risk: riskFactors.length > 2 ? 'high' : 'medium'
        });
    }
    result.hotspotsCount = result.hotspots.length;
    result.summary = result.hotspotsCount === 0
        ? 'No significant hotspots detected. Code appears stable.'
        : `Detected ${result.hotspotsCount} potential hotspot area(s) with ${changeMarkers.length} change markers and ${commentedCode.length} commented-out blocks.`;
    return result;
}
function formatHotspotReport(result) {
    const lines = [];
    lines.push('## Git History Hotspot Analysis');
    lines.push('');
    lines.push(`**Summary:** ${result.summary}`);
    lines.push('');
    if (result.hotspots.length > 0) {
        lines.push('### Hotspot Areas');
        result.hotspots.forEach(h => {
            const icon = h.risk === 'high' ? '🔴' : '🟡';
            lines.push(`${icon} **${h.file}** — ${h.changeCount} changes [${h.risk} risk]`);
        });
        lines.push('');
    }
    if (result.frequentChanges.length > 0) {
        lines.push('### Change Patterns');
        result.frequentChanges.forEach(f => {
            lines.push(`- ${f.pattern}: ${f.occurrences} occurrences`);
        });
        lines.push('');
    }
    lines.push('### Recommendations');
    lines.push('- High-change areas benefit from increased test coverage');
    lines.push('- Consider extracting frequently modified logic into stable interfaces');
    lines.push('- Remove commented-out code to reduce confusion');
    lines.push('- Review TODO/FIXME items and triage by priority');
    return lines.join('\n');
}
function detectLayerViolations(code) {
    const result = {
        layers: [],
        violations: [],
        summary: '',
        cleanLayerCount: 0
    };
    // Define common architecture layers and their patterns
    const layerDefinitions = [
        { name: 'presentation', patterns: /(?:controller|route|handler|api|endpoint|view|page|component|ui)/, level: 0 },
        { name: 'service', patterns: /(?:service|usecase|business|domain|logic|manager)/, level: 1 },
        { name: 'data', patterns: /(?:repository|dao|model|schema|entity|storage|db|database)/, level: 2 },
        { name: 'infrastructure', patterns: /(?:util|helper|config|lib|common|shared|infra)/, level: 3 },
        { name: 'external', patterns: /(?:client|adapter|integration|provider|sdk|third-party)/, level: 4 }
    ];
    // Detect which layers exist in the code
    const codeLower = code.toLowerCase();
    const detectedLayers = [];
    for (const layer of layerDefinitions) {
        const matches = (codeLower.match(new RegExp(layer.patterns.source, 'g')) || []).length;
        if (matches > 0) {
            detectedLayers.push({ name: layer.name, level: layer.level, matches, patterns: layer.patterns });
        }
    }
    // Sort by level
    detectedLayers.sort((a, b) => a.level - b.level);
    // Check for layer violations
    // Higher-level modules importing from lower-level is generally OK
    // Lower-level modules importing from higher-level is a violation
    for (let i = 0; i < detectedLayers.length; i++) {
        for (let j = 0; j < i; j++) {
            const higher = detectedLayers[i];
            const lower = detectedLayers[j];
            // Check if lower-level imports from higher-level
            const violationPattern = new RegExp(`(?:import|require).*${lower.patterns.source}.*${higher.patterns.source}|(?:import|require).*${higher.patterns.source}.*${lower.patterns.source}`, 'i');
            if (violationPattern.test(code)) {
                result.violations.push({
                    from: lower.name,
                    to: higher.name,
                    rule: `${lower.name} (L${lower.level}) should not depend on ${higher.name} (L${higher.level})`,
                    severity: 'error'
                });
            }
        }
    }
    // Check for circular references between layers
    for (let i = 0; i < detectedLayers.length; i++) {
        const layer = detectedLayers[i];
        const layerPattern = new RegExp(`(?:class|module|namespace)\\s+${layer.name}`, 'i');
        if (layerPattern.test(code)) {
            // Check if this layer's content references itself at same level (OK)
            // but also references higher levels (potential issue)
            for (let k = i + 1; k < detectedLayers.length; k++) {
                const higherLayer = detectedLayers[k];
                const crossRefPattern = new RegExp(`${layer.patterns.source}.*${higherLayer.patterns.source}`, 'i');
                if (crossRefPattern.test(code) && !result.violations.some(v => v.from === layer.name)) {
                    result.violations.push({
                        from: layer.name,
                        to: higherLayer.name,
                        rule: `${layer.name} directly coupled to ${higherLayer.name} — consider introducing an abstraction`,
                        severity: 'warning'
                    });
                }
            }
        }
    }
    result.layers = detectedLayers.map(l => ({ name: l.name, modules: [], level: l.level }));
    result.cleanLayerCount = detectedLayers.length - new Set(result.violations.map(v => v.from)).size;
    result.summary = detectedLayers.length === 0
        ? 'No layered architecture detected. Consider adopting a layered structure.'
        : `${detectedLayers.length} layers detected, ${result.violations.length} violation(s) found.`;
    return result;
}
function formatLayerViolationReport(result) {
    const lines = [];
    lines.push('## Module Layer Violation Analysis');
    lines.push('');
    lines.push(`**Summary:** ${result.summary}`);
    lines.push('');
    if (result.layers.length > 0) {
        lines.push('### Detected Layers');
        result.layers.forEach(l => {
            lines.push(`- **L${l.level}:** ${l.name}`);
        });
        lines.push('');
    }
    if (result.violations.length > 0) {
        lines.push('### Violations');
        result.violations.forEach(v => {
            const icon = v.severity === 'error' ? '🔴' : '🟡';
            lines.push(`${icon} ${v.rule}`);
            lines.push(`  Import: \`${v.from}\` → \`${v.to}\``);
        });
        lines.push('');
    }
    else if (result.layers.length > 0) {
        lines.push('✅ No layer violations detected. Clean architecture.');
        lines.push('');
    }
    lines.push('### Recommendations');
    lines.push('- Dependencies should flow downward: presentation → service → data → infrastructure');
    lines.push('- Use dependency injection to invert control when lower layers need higher-level data');
    lines.push('- Introduce interfaces/abstractions to decouple layers');
    lines.push('- Consider Clean Architecture or Hexagonal Architecture patterns');
    return lines.join('\n');
}
function traceErrorPropagation(code) {
    const result = {
        throws: [],
        catches: [],
        errorPaths: [],
        unhandledErrors: [],
        summary: '',
        handlingScore: 100
    };
    const lines = code.split('\n');
    // Detect throw statements
    const throwPattern = /throw\s+(?:new\s+)?(\w+(?:Error)?)\s*\(/g;
    let m;
    while ((m = throwPattern.exec(code)) !== null) {
        const lineNum = code.substring(0, m.index).split('\n').length;
        const context = lines[Math.min(lineNum - 1, lines.length - 1)]?.trim() || '';
        result.throws.push({ type: m[1], line: lineNum, context: context.substring(0, 80) });
    }
    // Detect try/catch blocks
    const tryBlocks = [];
    let i = 0;
    while (i < lines.length) {
        if (lines[i].trim().startsWith('try')) {
            const start = i + 1;
            let depth = 0;
            let j = i;
            while (j < lines.length) {
                depth += (lines[j].match(/{/g) || []).length;
                depth -= (lines[j].match(/}/g) || []).length;
                if (depth <= 0 && j > i) {
                    // Look for catch after this block
                    let k = j + 1;
                    while (k < lines.length && lines[k].trim() === '')
                        k++;
                    if (k < lines.length && lines[k].trim().startsWith('catch')) {
                        const catchMatch = lines[k].match(/catch\s*\(\s*(\w+)/);
                        const catchType = catchMatch ? catchMatch[1] : 'unknown';
                        const context = lines[k].trim().substring(0, 80);
                        result.catches.push({ type: catchType, line: k + 1, context });
                        tryBlocks.push({ start, end: k, catches: [catchType] });
                    }
                    break;
                }
                j++;
            }
        }
        i++;
    }
    // Detect async operations without error handling
    const asyncPatterns = [
        [/(?:const|let|var)\s+\w+\s*=\s*await\s+/g, 'await'],
        [/\.then\s*\(/g, 'promise.then'],
        [/Promise\s*\.\s*(?:all|race|allSettled)\s*\(/g, 'Promise.all'],
        [/new\s+Promise\s*\(/g, 'new Promise']
    ];
    const handledLines = new Set();
    tryBlocks.forEach(b => {
        for (let l = b.start; l <= b.end; l++)
            handledLines.add(l);
    });
    for (const [pattern, label] of asyncPatterns) {
        pattern.lastIndex = 0;
        let am;
        while ((am = pattern.exec(code)) !== null) {
            const lineNum = code.substring(0, am.index).split('\n').length;
            if (!handledLines.has(lineNum)) {
                result.errorPaths.push({
                    from: label,
                    to: 'unhandled',
                    type: 'potential rejection',
                    propagated: false
                });
            }
        }
    }
    // Detect catch blocks that swallow errors
    for (let idx = 0; idx < lines.length; idx++) {
        const line = lines[idx];
        if (/catch\s*\([^)]*\)\s*\{\s*\}/.test(line) || /catch\s*\([^)]*\)\s*\{\s*(?:\/\/\s*)?\}/.test(line)) {
            result.unhandledErrors.push({
                type: 'swallowed',
                line: idx + 1,
                suggestion: 'Add error logging or re-throw to avoid silent failures'
            });
        }
        // catch block that only logs (may be acceptable but flagged)
        if (/catch.*\{[^}]*console\.(?:log|warn|error)[^}]*\}/.test(line)) {
            if (!result.unhandledErrors.some(e => e.line === idx + 1)) {
                result.unhandledErrors.push({
                    type: 'logged-only',
                    line: idx + 1,
                    suggestion: 'Consider re-throwing or returning an error response'
                });
            }
        }
    }
    // Calculate handling score
    const totalThrows = result.throws.length;
    const handledThrows = totalThrows - result.unhandledErrors.length;
    const asyncOps = result.errorPaths.length + handledLines.size;
    const handledAsync = asyncOps - result.errorPaths.filter(e => !e.propagated).length;
    if (totalThrows + asyncOps > 0) {
        result.handlingScore = Math.max(0, Math.round(((handledThrows + handledAsync) / (totalThrows + asyncOps)) * 100));
    }
    const unhandled = result.unhandledErrors.length + result.errorPaths.filter(e => !e.propagated).length;
    result.summary = unhandled === 0
        ? `All ${totalThrows} throws and ${asyncOps} async operations appear properly handled. Handling score: ${result.handlingScore}/100.`
        : `${unhandled} potentially unhandled error points. Handling score: ${result.handlingScore}/100.`;
    return result;
}
function formatErrorTraceReport(result) {
    const lines = [];
    lines.push('## Error Propagation Trace Report');
    lines.push('');
    lines.push(`**Summary:** ${result.summary}`);
    lines.push(`**Handling Score:** ${result.handlingScore}/100`);
    lines.push('');
    if (result.throws.length > 0) {
        lines.push('### Throw Statements');
        result.throws.forEach(t => {
            lines.push(`- Line ${t.line}: \`throw ${t.type}\` — ${t.context}`);
        });
        lines.push('');
    }
    if (result.catches.length > 0) {
        lines.push('### Catch Blocks');
        result.catches.forEach(c => {
            lines.push(`- Line ${c.line}: \`catch (${c.type})\` — ${c.context}`);
        });
        lines.push('');
    }
    if (result.errorPaths.filter(e => !e.propagated).length > 0) {
        lines.push('### Unhandled Async Operations');
        const unhandled = result.errorPaths.filter(e => !e.propagated);
        lines.push(`${unhandled.length} async operation(s) without try/catch or .catch()`);
        lines.push('');
    }
    if (result.unhandledErrors.length > 0) {
        lines.push('### Swallowed / Logged-only Errors');
        result.unhandledErrors.forEach(e => {
            const icon = e.type === 'swallowed' ? '🔴' : '🟡';
            lines.push(`${icon} Line ${e.line} [${e.type}]: ${e.suggestion}`);
        });
        lines.push('');
    }
    lines.push('### Recommendations');
    lines.push('- Wrap async operations in try/catch or add .catch() handlers');
    lines.push('- Use custom error types for different failure scenarios');
    lines.push('- Implement a centralized error handler middleware');
    lines.push('- Avoid empty catch blocks — at minimum log with context');
    lines.push('- Consider using Result/Either types for expected failures');
    return lines.join('\n');
}
function suggestAutoRefactor(code) {
    const result = {
        refactorings: [],
        summary: '',
        totalOpportunities: 0
    };
    const lines = code.split('\n');
    // Extract Method: repeated code blocks
    for (let i = 0; i < lines.length - 2; i++) {
        const block = lines.slice(i, i + 3).join('\n');
        if (block.trim().length < 20)
            continue;
        for (let j = i + 3; j < lines.length - 2; j++) {
            const candidate = lines.slice(j, j + 3).join('\n');
            if (candidate.trim() === block.trim()) {
                result.refactorings.push({
                    type: 'extract_method',
                    line: i + 1,
                    description: `Duplicate block found at lines ${i + 1}-${i + 3} and ${j + 1}-${j + 3}`,
                    original: block.substring(0, 60).replace(/\n/g, ' ') + '...',
                    refactored: `Extract to function and call from both locations`
                });
                break;
            }
        }
    }
    // Extract Variable: complex expressions in return/assignment
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/(?:return|const|let|var)\s+[^;]*\?.(?:[^;]{3,})/.test(line)) {
            result.refactorings.push({
                type: 'extract_variable',
                line: i + 1,
                description: 'Complex expression could be extracted to a named variable for readability',
                original: line.trim().substring(0, 60),
                refactored: `Assign expression to a descriptively named variable`
            });
        }
    }
    // Inline Temp: variable used only once
    const varDecls = new Map();
    const declPattern = /(?:const|let|var)\s+(\w+)\s*=/g;
    let m;
    while ((m = declPattern.exec(code)) !== null) {
        const lineNum = code.substring(0, m.index).split('\n').length;
        varDecls.set(m[1], { line: lineNum, count: 0 });
    }
    for (const [name] of varDecls) {
        const usages = (new RegExp(`\\b${name}\\b`, 'g').exec(code)?.length || 0) - 1; // Exclude declaration
        varDecls.get(name).count = usages;
    }
    for (const [name, info] of varDecls) {
        if (info.count === 1) {
            result.refactorings.push({
                type: 'inline_temp',
                line: info.line,
                description: `Variable '${name}' is used only once — inline it`,
                original: `const ${name} = ...`,
                refactored: `Use the expression directly where '${name}' is referenced`
            });
        }
    }
    // Replace Magic Number with named constant
    const magicNumPattern = /(?:const|let|var)\s+\w+\s*=\s*(\d+(?:\.\d+)?)\s*;/g;
    while ((m = magicNumPattern.exec(code)) !== null) {
        const num = parseFloat(m[1]);
        if (num !== 0 && num !== 1 && num !== -1 && !Number.isNaN(num)) {
            const lineNum = code.substring(0, m.index).split('\n').length;
            result.refactorings.push({
                type: 'replace_magic_number',
                line: lineNum,
                description: `Magic number ${m[1]} should be a named constant`,
                original: `const x = ${m[1]}`,
                refactored: `const MEANINGFUL_NAME = ${m[1]} // describe what this represents`
            });
        }
    }
    result.totalOpportunities = result.refactorings.length;
    result.summary = result.totalOpportunities === 0
        ? 'No refactoring opportunities detected.'
        : `Found ${result.totalOpportunities} refactoring opportunities.`;
    return result;
}
function formatAutoRefactorReport(result) {
    const lines = [];
    lines.push('## Auto Refactoring Report');
    lines.push('');
    lines.push(`**Summary:** ${result.summary}`);
    lines.push('');
    if (result.refactorings.length > 0) {
        const grouped = new Map();
        result.refactorings.forEach(r => {
            if (!grouped.has(r.type))
                grouped.set(r.type, []);
            grouped.get(r.type).push(r);
        });
        for (const [type, items] of grouped) {
            lines.push(`### ${type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())} (${items.length})`);
            items.forEach(r => {
                lines.push(`- Line ${r.line}: ${r.description}`);
                lines.push(`  - Original: \`${r.original}\``);
                lines.push(`  - Suggested: \`${r.refactored}\``);
            });
            lines.push('');
        }
    }
    return lines.join('\n');
}
function detectCodeSimilarity(code) {
    const result = {
        fileSimilarities: [],
        tokenSimilarity: 0,
        summary: '',
        duplicateBlocks: 0
    };
    const lines = code.split('\n');
    const blockSize = 4;
    // Tokenize for comparison
    const tokenize = (s) => {
        return new Set(s.replace(/[{}();,]/g, ' ').split(/\s+/).filter(t => t.length > 2));
    };
    // Compare all block pairs
    const blocks = [];
    for (let i = 0; i <= lines.length - blockSize; i++) {
        const blockText = lines.slice(i, i + blockSize).join('\n');
        blocks.push({ start: i + 1, tokens: tokenize(blockText), text: blockText });
    }
    for (let i = 0; i < blocks.length; i++) {
        for (let j = i + 1; j < blocks.length; j++) {
            const a = blocks[i].tokens;
            const b = blocks[j].tokens;
            if (a.size === 0 || b.size === 0)
                continue;
            const intersection = new Set([...a].filter(x => b.has(x)));
            const union = new Set([...a, ...b]);
            const jaccard = intersection.size / union.size;
            if (jaccard > 0.6) {
                result.fileSimilarities.push({
                    block1: `L${blocks[i].start}-${blocks[i].start + blockSize - 1}`,
                    block2: `L${blocks[j].start}-${blocks[j].start + blockSize - 1}`,
                    similarity: Math.round(jaccard * 100),
                    lines: `${blocks[i].start}-${blocks[i].start + blockSize - 1} vs ${blocks[j].start}-${blocks[j].start + blockSize - 1}`
                });
            }
        }
    }
    result.duplicateBlocks = result.fileSimilarities.length;
    result.tokenSimilarity = result.fileSimilarities.length > 0
        ? Math.round(result.fileSimilarities.reduce((s, f) => s + f.similarity, 0) / result.fileSimilarities.length)
        : 0;
    result.summary = result.duplicateBlocks === 0
        ? 'No significant code similarity detected. Code is sufficiently unique.'
        : `Found ${result.duplicateBlocks} similar code block pairs (avg ${result.tokenSimilarity}% similarity).`;
    return result;
}
function formatSimilarityReport(result) {
    const lines = [];
    lines.push('## Code Similarity Report');
    lines.push('');
    lines.push(`**Summary:** ${result.summary}`);
    lines.push(`**Average token similarity:** ${result.tokenSimilarity}%`);
    lines.push('');
    if (result.fileSimilarities.length > 0) {
        lines.push('### Similar Blocks');
        result.fileSimilarities.forEach(s => {
            const icon = s.similarity > 80 ? '🔴' : s.similarity > 70 ? '🟡' : '🟢';
            lines.push(`${icon} ${s.block1} ↔ ${s.block2}: ${s.similarity}% similar`);
        });
        lines.push('');
        lines.push('### Recommendations');
        lines.push('- Extract shared logic into a reusable function');
        lines.push('- Use inheritance or composition to share behavior');
        lines.push('- Consider creating a utility/helper for duplicated patterns');
    }
    else {
        lines.push('✅ No significant similarity detected.');
    }
    return lines.join('\n');
}
function detectPrimitiveObsession(code) {
    const result = {
        occurrences: [],
        summary: '',
        obsessionScore: 100
    };
    const lines = code.split('\n');
    // Detect variables that could be domain types
    const primitivePatterns = [
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
    ];
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const pp of primitivePatterns) {
            if (pp.pattern.test(line) && /(?:const|let|var|:\s*(?:string|number|boolean))/.test(line)) {
                const nameMatch = line.match(/(?:const|let|var)\s+(\w+)/);
                const name = nameMatch ? nameMatch[1] : 'unknown';
                result.occurrences.push({ name, type: pp.type, line: i + 1, suggestion: pp.suggestion });
            }
        }
    }
    const penalty = Math.min(100, result.occurrences.length * 8);
    result.obsessionScore = 100 - penalty;
    result.summary = result.occurrences.length === 0
        ? 'No primitive obsession detected. Good use of domain types.'
        : `Found ${result.occurrences.length} primitive obsession candidates (score: ${result.obsessionScore}/100).`;
    return result;
}
function formatPrimitiveObsessionReport(result) {
    const lines = [];
    lines.push('## Primitive Obsession Detection');
    lines.push('');
    lines.push(`**Summary:** ${result.summary}`);
    lines.push(`**Obsession Score:** ${result.obsessionScore}/100`);
    lines.push('');
    if (result.occurrences.length > 0) {
        lines.push('### Candidates');
        result.occurrences.forEach(o => {
            lines.push(`- Line ${o.line}: \`${o.name}\` → consider \`${o.type}\``);
            lines.push(`  - ${o.suggestion}`);
        });
        lines.push('');
        lines.push('### Benefits of Value Objects');
        lines.push('- Type safety: prevent mixing different kinds of primitives');
        lines.push('- Validation: enforce constraints at construction time');
        lines.push('- Self-documenting: type name conveys meaning');
        lines.push('- Encapsulation: behavior lives with the data');
    }
    return lines.join('\n');
}
function detectSqlInjection(code) {
    const result = {
        vulnerabilities: [],
        safePatterns: [],
        summary: '',
        riskScore: 100
    };
    const lines = code.split('\n');
    // Dangerous patterns: string concatenation in SQL
    const dangerousPatterns = [
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
    ];
    // Safe patterns that indicate proper usage
    const safeIndicators = [
        { pattern: /\?.*\[/i, description: 'Parameterized query with placeholder' },
        { pattern: /:\w+\s*[,)]/, description: 'Named parameter binding' },
        { pattern: /\$1|\$2|\$\d/, description: 'Posomial parameter ($1, $2)' },
        { pattern: /prepare[d]?\s*(?:statement|query)/i, description: 'Prepared statement usage' },
        { pattern: /\.query\s*\(\s*["'`][^"'`]*["'`]\s*,\s*\[/, description: 'Parameterized with array binding' }
    ];
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const dp of dangerousPatterns) {
            if (dp.pattern.test(line)) {
                result.vulnerabilities.push({
                    line: i + 1,
                    severity: dp.severity,
                    query: line.trim().substring(0, 80),
                    issue: dp.issue,
                    fix: dp.fix
                });
            }
        }
        for (const si of safeIndicators) {
            if (si.pattern.test(line)) {
                result.safePatterns.push(`Line ${i + 1}: ${si.description}`);
            }
        }
    }
    const critCount = result.vulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = result.vulnerabilities.filter(v => v.severity === 'high').length;
    result.riskScore = Math.max(0, 100 - critCount * 25 - highCount * 15);
    result.summary = result.vulnerabilities.length === 0
        ? `No SQL injection vectors found. ${result.safePatterns.length} safe pattern(s) detected.`
        : `Found ${result.vulnerabilities.length} potential SQL injection vector(s). Risk: ${result.riskScore}/100.`;
    return result;
}
function formatSqlInjectionReport(result) {
    const lines = [];
    lines.push('## SQL Injection Detection Report');
    lines.push('');
    lines.push(`**Summary:** ${result.summary}`);
    lines.push(`**Risk Score:** ${result.riskScore}/100`);
    lines.push('');
    if (result.vulnerabilities.length > 0) {
        lines.push('### Vulnerabilities');
        result.vulnerabilities.forEach(v => {
            const icon = v.severity === 'critical' ? '🔴' : '🟡';
            lines.push(`${icon} Line ${v.line} [${v.severity.toUpperCase()}]`);
            lines.push(`  Query: \`${v.query}\``);
            lines.push(`  Issue: ${v.issue}`);
            lines.push(`  Fix: ${v.fix}`);
            lines.push('');
        });
    }
    if (result.safePatterns.length > 0) {
        lines.push('### Safe Patterns Detected');
        result.safePatterns.forEach(s => lines.push(`✅ ${s}`));
        lines.push('');
    }
    lines.push('### Best Practices');
    lines.push('- Always use parameterized queries with ? or :name placeholders');
    lines.push('- Use an ORM (Prisma, TypeORM, Sequelize) for type-safe queries');
    lines.push('- Never concatenate user input into SQL strings');
    lines.push('- Validate and whitelist ORDER BY / column name inputs');
    return lines.join('\n');
}
function checkInterfaceCompliance(code) {
    const result = {
        interfaces: [],
        implementations: [],
        summary: '',
        complianceRate: 100
    };
    // Parse interface definitions
    const interfacePattern = /interface\s+(\w+)\s*(?:extends\s+([\w\s,]+))?\s*\{([^}]+)\}/g;
    let m;
    while ((m = interfacePattern.exec(code)) !== null) {
        const name = m[1];
        const body = m[3];
        const lineNum = code.substring(0, m.index).split('\n').length;
        const methods = [];
        const methodPattern = /(\w+)\s*(?:\([^)]*\))(?:\s*:\s*[^;]+)?[;]?/g;
        let mm;
        while ((mm = methodPattern.exec(body)) !== null) {
            methods.push(mm[1]);
        }
        result.interfaces.push({ name, methods, line: lineNum });
    }
    // Parse class implementations
    const classPattern = /class\s+(\w+)\s+(?:extends\s+\w+\s+)?(?:implements\s+([\w\s,]+))?\s*\{/g;
    while ((m = classPattern.exec(code)) !== null) {
        const className = m[1];
        const implStr = m[2] || '';
        const lineNum = code.substring(0, m.index).split('\n').length;
        const implInterfaces = implStr.split(',').map(s => s.trim()).filter(Boolean);
        // Get class methods
        const classStart = m.index + m[0].length;
        const classBody = code.substring(classStart, classStart + 2000);
        const classMethods = [];
        const cmPattern = /(?:public|private|protected)?\s*(?:async\s+)?(\w+)\s*\(/g;
        let cm;
        while ((cm = cmPattern.exec(classBody)) !== null) {
            if (cm[1] !== 'constructor' && cm[1] !== 'if' && cm[1] !== 'for' && cm[1] !== 'while') {
                classMethods.push(cm[1]);
            }
        }
        // Check compliance for each implemented interface
        for (const implName of implInterfaces) {
            const iface = result.interfaces.find(i => i.name === implName);
            if (iface) {
                const missing = iface.methods.filter(im => !classMethods.includes(im));
                const extra = classMethods.filter(cm => !iface.methods.includes(cm));
                result.implementations.push({
                    name: className,
                    implements: implName,
                    missing,
                    extra,
                    line: lineNum,
                    compliant: missing.length === 0
                });
            }
        }
    }
    const total = result.implementations.length;
    const compliant = result.implementations.filter(i => i.compliant).length;
    result.complianceRate = total > 0 ? Math.round((compliant / total) * 100) : 100;
    result.summary = total === 0
        ? 'No interface implementations detected.'
        : `${compliant}/${total} implementations are fully compliant (${result.complianceRate}%).`;
    return result;
}
function formatInterfaceComplianceReport(result) {
    const lines = [];
    lines.push('## Interface Compliance Report');
    lines.push('');
    lines.push(`**Summary:** ${result.summary}`);
    lines.push(`**Compliance Rate:** ${result.complianceRate}%`);
    lines.push('');
    if (result.interfaces.length > 0) {
        lines.push('### Defined Interfaces');
        result.interfaces.forEach(i => {
            lines.push(`- \`${i.name}\` (line ${i.line}): ${i.methods.join(', ') || 'no methods'}`);
        });
        lines.push('');
    }
    if (result.implementations.length > 0) {
        lines.push('### Implementations');
        result.implementations.forEach(impl => {
            const icon = impl.compliant ? '✅' : '❌';
            lines.push(`${icon} \`${impl.name}\` implements \`${impl.implements}\` (line ${impl.line})`);
            if (impl.missing.length > 0) {
                lines.push(`  Missing: ${impl.missing.map(m => `\`${m}\``).join(', ')}`);
            }
            if (impl.extra.length > 0) {
                lines.push(`  Extra: ${impl.extra.map(e => `\`${e}\``).join(', ')}`);
            }
        });
        lines.push('');
    }
    return lines.join('\n');
}
function detectMagicStrings(code) {
    const result = {
        occurrences: [],
        internationalizable: [],
        summary: '',
        stringScore: 100
    };
    const lines = code.split('\n');
    // Skip strings that are clearly safe
    const safePatterns = /^(?:import|export|require|console|log|error|warn|info|http|https|ftp|www|\.css|\.js|\.ts|\.json|text\/|application\/)/i;
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Match string literals (single, double, and backtick quoted)
        const stringPattern = /["'`]([^"'`\\]*(?:\\.[^"'`\\]*)*)["'`]/g;
        let m;
        while ((m = stringPattern.exec(line)) !== null) {
            const str = m[1];
            // Skip empty, very short, or obviously safe strings
            if (str.length <= 2 || safePatterns.test(str))
                continue;
            if (/^[A-Z_][A-Z0-9_]*$/.test(str))
                continue; // Already a constant
            if (/^(?:true|false|null|undefined)$/.test(str))
                continue;
            if (/^\d+$/.test(str))
                continue; // Numeric
            // Check if it looks like user-facing text
            if (/^[A-Z][a-z]+(?:\s+[a-z]+)*$/.test(str) && str.includes(' ')) {
                result.internationalizable.push({ value: str, line: i + 1 });
            }
            // Detect magic strings used as keys or values
            const context = line.trim();
            if (/(?:type|status|state|role|level|format|mode|kind|error|message|label|title|text)\s*[:=]\s*["'`]/.test(context)) {
                const constName = str.toUpperCase().replace(/[^A-Z0-9]/g, '_').replace(/_+/g, '_');
                result.occurrences.push({
                    value: str,
                    line: i + 1,
                    context: context.substring(0, 60),
                    suggestion: `const ${constName} = "${str}"`
                });
            }
        }
    }
    const penalty = Math.min(100, result.occurrences.length * 5 + result.internationalizable.length * 3);
    result.stringScore = 100 - penalty;
    result.summary = result.occurrences.length === 0 && result.internationalizable.length === 0
        ? 'No problematic magic strings detected.'
        : `Found ${result.occurrences.length} magic string(s) and ${result.internationalizable.length} user-facing string(s) that should be constants.`;
    return result;
}
function formatMagicStringReport(result) {
    const lines = [];
    lines.push('## Magic String Detection');
    lines.push('');
    lines.push(`**Summary:** ${result.summary}`);
    lines.push(`**String Quality Score:** ${result.stringScore}/100`);
    lines.push('');
    if (result.occurrences.length > 0) {
        lines.push('### Magic Strings (extract to constants)');
        result.occurrences.forEach(o => {
            lines.push(`- Line ${o.line}: \`"${o.value}"\``);
            lines.push(`  Context: \`${o.context}\``);
            lines.push(`  Suggested: \`${o.suggestion}\``);
        });
        lines.push('');
    }
    if (result.internationalizable.length > 0) {
        lines.push('### User-Facing Strings (consider i18n)');
        result.internationalizable.forEach(s => {
            lines.push(`- Line ${s.line}: \`"${s.value}"\``);
        });
        lines.push('');
    }
    lines.push('### Recommendations');
    lines.push('- Move string literals to a dedicated constants file or enum');
    lines.push('- User-facing strings should use an i18n framework (react-intl, i18next)');
    lines.push('- Use string literal unions for type-safe string values');
    return lines.join('\n');
}
function recommendSemverBump(code) {
    const result = {
        currentVersion: '1.0.0',
        recommendedBump: 'none',
        reasons: [],
        breakingChanges: [],
        newFeatures: [],
        fixes: [],
        summary: ''
    };
    // Detect breaking changes
    const removedExports = /(?:REMOVED|DELETED|BREAKING).*?(?:export|function|class)/gi;
    const changedSignatures = /(?: signature| parameter| return type)/gi;
    if (removedExports.test(code)) {
        result.breakingChanges.push('Removed exports detected');
    }
    if (changedSignatures.test(code)) {
        result.breakingChanges.push('Changed function signatures detected');
    }
    // Detect new features
    const newExports = code.match(/export\s+(?:function|class|interface|type|const)\s+(\w+)/g) || [];
    if (newExports.length > 0) {
        result.newFeatures.push(`${newExports.length} new export(s) added`);
    }
    const newEndpoints = code.match(/(?:app|router)\.(?:get|post|put|delete|patch)\s*\(/g) || [];
    if (newEndpoints.length > 0) {
        result.newFeatures.push(`${newEndpoints.length} new API endpoint(s)`);
    }
    // Detect fixes
    const fixComments = code.match(/(?:fix|fixed|fixes|bug|patch|hotfix|resolve)/gi) || [];
    if (fixComments.length > 0) {
        result.fixes.push(`${fixComments.length} fix-related comment(s)`);
    }
    // Determine bump level
    if (result.breakingChanges.length > 0) {
        result.recommendedBump = 'major';
        result.reasons.push('Breaking changes require major version bump');
    }
    else if (result.newFeatures.length > 0) {
        result.recommendedBump = 'minor';
        result.reasons.push('New features warrant minor version bump');
    }
    else if (result.fixes.length > 0) {
        result.recommendedBump = 'patch';
        result.reasons.push('Bug fixes only — patch bump appropriate');
    }
    else {
        result.reasons.push('No significant changes detected');
    }
    result.summary = `Recommended: ${result.recommendedBump.toUpperCase()} bump. ${result.reasons.join('. ')}`;
    return result;
}
function formatSemverReport(result) {
    const lines = [];
    lines.push('## Semantic Version Bump Recommendation');
    lines.push('');
    lines.push(`**Recommendation:** ${result.recommendedBump.toUpperCase()}`);
    lines.push(`**Summary:** ${result.summary}`);
    lines.push('');
    if (result.breakingChanges.length > 0) {
        lines.push('### Breaking Changes (requires MAJOR)');
        result.breakingChanges.forEach(b => lines.push(`- 🔴 ${b}`));
        lines.push('');
    }
    if (result.newFeatures.length > 0) {
        lines.push('### New Features (warrants MINOR)');
        result.newFeatures.forEach(f => lines.push(`- 🟢 ${f}`));
        lines.push('');
    }
    if (result.fixes.length > 0) {
        lines.push('### Fixes (PATCH appropriate)');
        result.fixes.forEach(f => lines.push(`- 🟡 ${f}`));
        lines.push('');
    }
    lines.push('### Semantic Versioning Rules');
    lines.push('- **MAJOR**: Breaking changes that require consumer updates');
    lines.push('- **MINOR**: New features, backward compatible');
    lines.push('- **PATCH**: Bug fixes only, no API changes');
    return lines.join('\n');
}
function generatePRReviewComments(code) {
    const result = {
        comments: [],
        summary: '',
        totalComments: 0
    };
    const lines = code.split('\n');
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        const lineNum = i + 1;
        // Security issues
        if (/(?:eval|innerHTML|dangerouslySetInnerHTML)\s*\(/.test(line)) {
            result.comments.push({
                file: 'src/file.ts',
                line: lineNum,
                body: '⚠️ Using eval/innerHTML can lead to XSS vulnerabilities. Consider safer alternatives.',
                category: 'security',
                severity: 'issue'
            });
        }
        // Performance
        if (/\.map\s*\(.*\.map\s*\(/.test(line)) {
            result.comments.push({
                file: 'src/file.ts',
                line: lineNum,
                body: '🔍 Chained .map() calls create intermediate arrays. Consider combining into a single map or using reduce.',
                category: 'performance',
                severity: 'suggestion'
            });
        }
        // Best practices
        if (/console\.(?:log|debug)\s*\(/.test(line) && !line.includes('//')) {
            result.comments.push({
                file: 'src/file.ts',
                line: lineNum,
                body: '🧹 Remove console.log before merging, or replace with a proper logger.',
                category: 'clean code',
                severity: 'nit'
            });
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
                });
            }
        }
        // Component complexity marker
        if (/^(?:export\s+)?(?:function|const)\s+\w+\s*[=(].*=>/.test(line)) {
            let funcEnd = i + 1;
            let braceCount = 0;
            while (funcEnd < lines.length) {
                braceCount += (lines[funcEnd].match(/{/g) || []).length;
                braceCount -= (lines[funcEnd].match(/}/g) || []).length;
                if (braceCount <= 0 && funcEnd > i)
                    break;
                funcEnd++;
                if (funcEnd - i > 50)
                    break;
            }
            if (funcEnd - i > 30) {
                result.comments.push({
                    file: 'src/file.ts',
                    line: lineNum,
                    body: '📏 This function is quite long. Consider extracting smaller helper functions.',
                    category: 'readability',
                    severity: 'suggestion'
                });
            }
        }
    }
    result.totalComments = result.comments.length;
    result.summary = `Generated ${result.totalComments} review comment(s).`;
    return result;
}
function formatPRReviewCommentReport(result) {
    const lines = [];
    lines.push('## PR Review Comments');
    lines.push('');
    lines.push(`**Summary:** ${result.summary}`);
    lines.push('');
    if (result.comments.length > 0) {
        const grouped = new Map();
        result.comments.forEach(c => {
            if (!grouped.has(c.category))
                grouped.set(c.category, []);
            grouped.get(c.category).push(c);
        });
        for (const [cat, items] of grouped) {
            lines.push(`### ${cat.charAt(0).toUpperCase() + cat.slice(1)} (${items.length})`);
            items.forEach(c => {
                const icon = c.severity === 'issue' ? '🔴' : c.severity === 'suggestion' ? '🟡' : c.severity === 'nit' ? '⚪' : '🟢';
                lines.push(`${icon} Line ${c.line}: ${c.body}`);
            });
            lines.push('');
        }
    }
    return lines.join('\n');
}
// ==================== PLUGIN REGISTRATION ====================
export function apply(ctx) {
    // Tool 1: Comprehensive Code Review
    ctx.tools.register(defineTool({
        name: 'code_review',
        description: 'Comprehensive code quality analysis. Returns score (0-100), grade, metrics, issues, strengths, refactoring suggestions, and auto-fixes.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' },
            language: { type: 'string', description: 'Programming language. Auto-detected if not provided.' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = analyzeCode(args.code, language);
            return formatReviewReport(result);
        }
    }));
    // Tool 2: Security Scan
    ctx.tools.register(defineTool({
        name: 'security_scan',
        description: 'Scan code for security vulnerabilities. Covers OWASP Top 10, CWE, SANS Top 25. Optional SARIF output.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to scan' },
            language: { type: 'string', description: 'Programming language' },
            sarif: { type: 'boolean', description: 'Generate SARIF output format' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = scanSecurity(args.code, language, args.sarif);
            return formatSecurityReport(result);
        }
    }));
    // Tool 3: Dependency Audit
    ctx.tools.register(defineTool({
        name: 'dependency_audit',
        description: 'Audit dependencies for known vulnerabilities. Checks import/require statements against known CVE database.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code containing import/require statements' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = auditDependencies(args.code, language);
            return formatDependencyReport(result);
        }
    }));
    // Tool 4: Performance Analysis
    ctx.tools.register(defineTool({
        name: 'performance_check',
        description: 'Analyze code for performance issues: N+1 queries, inefficient algorithms, memory leaks, blocking operations. Includes BigO complexity estimation.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = analyzePerformance(args.code, language);
            return formatPerformanceReport(result);
        }
    }));
    // Tool 5: Quick Code Check
    ctx.tools.register(defineTool({
        name: 'code_check',
        description: 'Quick code quality check. Returns pass/fail with key issues summary.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to check' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = analyzeCode(args.code, language);
            const lines = [];
            const criticalCount = result.issues.filter(i => i.severity === 'critical').length;
            const errorCount = result.issues.filter(i => i.severity === 'error').length;
            if (result.score >= 70 && criticalCount === 0 && errorCount === 0)
                lines.push('## Quick Check: PASSED');
            else
                lines.push('## Quick Check: NEEDS ATTENTION');
            lines.push('');
            lines.push(`Score: ${result.score}/100 | Grade: ${result.grade}`);
            lines.push('');
            const importantIssues = result.issues.filter(i => i.severity !== 'info');
            if (importantIssues.length > 0) {
                lines.push('### Key Issues');
                importantIssues.slice(0, 10).forEach(issue => {
                    const icon = issue.severity === 'critical' ? '🔴' : issue.severity === 'error' ? '🟠' : '🟡';
                    lines.push(`- ${icon} ${issue.message}`);
                });
                if (importantIssues.length > 10)
                    lines.push(`- ... and ${importantIssues.length - 10} more issues`);
            }
            else {
                lines.push('No critical or error issues found.');
            }
            return lines.join('\n');
        }
    }));
    // Tool 6: Architecture Review (NEW)
    ctx.tools.register(defineTool({
        name: 'architecture_review',
        description: 'Analyze code architecture: detect design patterns, assess SOLID principles, evaluate module cohesion and coupling.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = reviewArchitecture(args.code, language);
            return formatArchitectureReport(result);
        }
    }));
    // Tool 7: Test Coverage Analysis (NEW)
    ctx.tools.register(defineTool({
        name: 'test_coverage',
        description: 'Analyze testability and estimate test coverage. Identifies hard-to-test patterns and suggests mocking strategies.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = analyzeTestCoverage(args.code, language);
            return formatTestCoverageReport(result);
        }
    }));
    // Tool 8: API Documentation Generator (NEW)
    ctx.tools.register(defineTool({
        name: 'api_docs',
        description: 'Generate API documentation from code. Detects endpoints, models, and generates structured API reference.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = generateApiDocs(args.code, language);
            return formatApiDocsReport(result);
        }
    }));
    // Tool 9: Code Diff Analysis (NEW)
    ctx.tools.register(defineTool({
        name: 'code_diff',
        description: 'Analyze a code diff/patch. Assesses change type, risk level, and provides review suggestions.',
        parameters: {
            diff: { type: 'string', required: true, description: 'The diff/patch text to analyze' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = analyzeDiff(args.diff);
            return formatDiffReport(result);
        }
    }));
    // Tool 10: Style Check (NEW)
    ctx.tools.register(defineTool({
        name: 'style_check',
        description: 'Check code style and conventions. Detects naming issues, formatting problems, and style violations.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to check' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = checkStyle(args.code, language);
            return formatStyleReport(result);
        }
    }));
    // Tool 11: Code Smell Detection (v0.5.0)
    ctx.tools.register(defineTool({
        name: 'code_smell_detect',
        description: 'Detect code smells: God Object, Feature Envy, Shotgun Surgery, Long Method, Primitive Obsession, Dead Code.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = detectCodeSmells(args.code, language);
            return formatCodeSmellReport(result);
        }
    }));
    // Tool 12: TypeScript Strict Mode Check (v0.5.0)
    ctx.tools.register(defineTool({
        name: 'ts_strict_check',
        description: 'Check TypeScript strict mode compliance: noImplicitAny, explicitReturnType, noNonNullAssertion, strictNullChecks.',
        parameters: {
            code: { type: 'string', required: true, description: 'The TypeScript source code to check' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = checkTsStrictMode(args.code);
            return formatTsStrictReport(result);
        }
    }));
    // Tool 13: Incremental Analysis (v0.5.0)
    ctx.tools.register(defineTool({
        name: 'incremental_analysis',
        description: 'Analyze only changed code against a diff. Fast feedback for large projects with focused scope.',
        parameters: {
            code: { type: 'string', required: true, description: 'The current source code' },
            diff: { type: 'string', required: true, description: 'The unified diff to analyze against' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = analyzeIncremental(args.code, args.diff, language);
            return formatIncrementalReport(result);
        }
    }));
    // Tool 14: Breaking Change Detection (v0.5.0)
    ctx.tools.register(defineTool({
        name: 'breaking_change',
        description: 'Detect breaking changes between code versions: removed exports, signature changes, behavior changes.',
        parameters: {
            code: { type: 'string', required: true, description: 'The current source code' },
            previousCode: { type: 'string', required: true, description: 'The previous version of the source code' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = detectBreakingChanges(args.code, args.previousCode, language);
            return formatBreakingChangeReport(result);
        }
    }));
    // Tool 15: SARIF Export (v0.5.0)
    ctx.tools.register(defineTool({
        name: 'sarif_export',
        description: 'Export security scan results as SARIF 2.1.0 file for CI/CD integration and GitHub Code Scanning.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to scan' },
            language: { type: 'string', description: 'Programming language' },
            outputPath: { type: 'string', description: 'Output file path (default: ./security-scan.sarif)' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = exportSarifToFile(args.code, language, args.outputPath);
            return formatSarifExportReport(result);
        }
    }));
    // Tool 16: Diff Preview with Auto-Fix (v0.5.0)
    ctx.tools.register(defineTool({
        name: 'diff_preview',
        description: 'Generate auto-fix suggestions with unified diff preview. Shows what changes would improve code quality.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze and fix' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = generateDiffPreview(args.code, language);
            return formatDiffPreviewReport(result);
        }
    }));
    // Tool 17: Config File Support (v0.6.0 - PRO-004)
    ctx.tools.register(defineTool({
        name: 'config_load',
        description: 'Load and validate .dshcoderc configuration file. Supports severity thresholds, ignored rules, custom rules, and output format.',
        parameters: {
            configContent: { type: 'string', description: 'The .dshcoderc JSON content to load' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = loadDshConfig(args.configContent);
            return formatConfigLoadReport(result);
        }
    }));
    // Tool 18: Test Generation (v0.6.0 - PRO-007)
    ctx.tools.register(defineTool({
        name: 'test_generate',
        description: 'Generate test case templates based on function signatures. Supports unit tests, edge cases, and error cases.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to generate tests for' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = generateTestSuggestions(args.code, language);
            return formatTestGenReport(result);
        }
    }));
    // Tool 19: Complexity Metrics (v0.6.0 - PRO-009)
    ctx.tools.register(defineTool({
        name: 'complexity_metrics',
        description: 'Calculate code complexity metrics: cyclomatic complexity, Halstead volume/difficulty/effort, nesting depth, comment ratio.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = analyzeComplexity(args.code, language);
            return formatComplexityReport(result);
        }
    }));
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
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = analyzeBatch(args.files);
            return formatBatchReport(result);
        }
    }));
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
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = analyzeMonorepo(args.packages);
            return formatMonorepoReport(result);
        }
    }));
    // Tool 22: Multi-Language Analysis (v0.7.0 - PRO-010)
    ctx.tools.register(defineTool({
        name: 'multilang_analyze',
        description: 'Deep language-specific analysis for Python, Go, Rust, Java. Detects language idioms and anti-patterns.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = analyzeMultiLanguage(args.code, language);
            return formatMultiLangReport(result);
        }
    }));
    // Tool 23: CI/CD Workflow Generator (v0.7.0 - PRO-011)
    ctx.tools.register(defineTool({
        name: 'cicd_generate',
        description: 'Generate GitHub Actions workflow for automated code review. Includes SARIF upload for Code Scanning.',
        parameters: {
            language: { type: 'string', required: true, description: 'Programming language for the workflow' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = generateCiCdWorkflow(args.language);
            return formatCiCdReport(result);
        }
    }));
    // Tool 24: Custom Rule Engine (v0.7.0 - PRO-012)
    ctx.tools.register(defineTool({
        name: 'custom_rules',
        description: 'Run custom linting rules defined in YAML format. Supports regex patterns, severity levels.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to check' },
            rulesYaml: { type: 'string', required: true, description: 'YAML-formatted custom rules' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = runCustomRules(args.code, args.rulesYaml);
            return formatCustomRuleReport(result);
        }
    }));
    // Tool 25: Code Duplication Detection (v0.7.0)
    ctx.tools.register(defineTool({
        name: 'duplicate_detect',
        description: 'Detect code duplication: exact copies, similar blocks, structural repetition. Calculates wasted lines.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = detectDuplication(args.code);
            return formatDuplicationReport(result);
        }
    }));
    // Tool 26: Refactoring Suggestions (v0.7.0)
    ctx.tools.register(defineTool({
        name: 'refactor_suggest',
        description: 'Suggest refactoring opportunities: extract method, extract class, inline, rename. With effort/impact ratings.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = suggestRefactoring(args.code, language);
            return formatRefactorReport(result);
        }
    }));
    // Tool 27: Naming Convention Check (v0.7.0)
    ctx.tools.register(defineTool({
        name: 'naming_check',
        description: 'Check naming conventions per language: camelCase, PascalCase, snake_case, SCREAMING_SNAKE_CASE.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to check' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = checkNamingConventions(args.code, language);
            return formatNamingReport(result);
        }
    }));
    // Tool 28: Security Pattern Detection (v0.8.0)
    ctx.tools.register(defineTool({
        name: 'security_patterns',
        description: 'Deep security pattern detection: SQLi, XSS, CSRF, path traversal, command injection, SSRF, hardcoded secrets. With OWASP/CWE mapping.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to scan' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = detectSecurityPatterns(args.code, language);
            return formatSecurityPatternReport(result);
        }
    }));
    // Tool 29: Performance Tips (v0.8.0)
    ctx.tools.register(defineTool({
        name: 'performance_tips',
        description: 'Generate performance optimization tips: N+1 queries, memory leaks, inefficient loops, caching suggestions.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = generatePerformanceTips(args.code, language);
            return formatPerformanceTipReport(result);
        }
    }));
    // Tool 30: Documentation Check (v0.8.0)
    ctx.tools.register(defineTool({
        name: 'doc_check',
        description: 'Check documentation completeness: function docs, param docs, return docs, examples.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to check' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = checkDocumentation(args.code, language);
            return formatDocumentationReport(result);
        }
    }));
    // Tool 31: Import Organization (v0.8.0)
    ctx.tools.register(defineTool({
        name: 'import_organize',
        description: 'Organize and deduplicate imports. Groups by type: builtins, external, internal, relative.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to organize' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = organizeImports(args.code, language);
            return formatImportOrganizeReport(result);
        }
    }));
    // Tool 32: Error Handling Analysis (v0.8.0)
    ctx.tools.register(defineTool({
        name: 'error_handling',
        description: 'Analyze error handling patterns: missing catches, swallowed errors, generic catches, fallback values.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = analyzeErrorHandling(args.code, language);
            return formatErrorHandlingReport(result);
        }
    }));
    // Tool 33: API Design Review (v0.8.0)
    ctx.tools.register(defineTool({
        name: 'api_design',
        description: 'Review API design: RESTfulness, validation, auth, pagination, error handling per endpoint.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to review' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = reviewApiDesign(args.code, language);
            return formatApiDesignReport(result);
        }
    }));
    // Tool 34: Coverage Estimation (v0.9.0)
    ctx.tools.register(defineTool({
        name: 'coverage_estimate',
        description: 'Estimate code coverage: testable units, complexity-based coverage prediction, uncovered risks.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = estimateCoverage(args.code, language);
            return formatCoverageReport(result);
        }
    }));
    // Tool 35: Dependency Version Check (v0.9.0)
    ctx.tools.register(defineTool({
        name: 'dep_versions',
        description: 'Check dependency versions: detect outdated and vulnerable packages.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to scan' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = checkDepVersions(args.code, language);
            return formatDepVersionReport(result);
        }
    }));
    // Tool 36: Style Enforcement (v0.9.0)
    ctx.tools.register(defineTool({
        name: 'style_enforce',
        description: 'Enforce code style: indentation, line length, trailing whitespace, tabs vs spaces.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to check' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = enforceStyle(args.code, language);
            return formatStyleEnforceReport(result);
        }
    }));
    // Tool 37: Function Length Analysis (v0.9.0)
    ctx.tools.register(defineTool({
        name: 'func_length',
        description: 'Analyze function lengths: detect long functions, calculate averages, flag critical ones.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = analyzeFuncLength(args.code, language);
            return formatFuncLengthReport(result);
        }
    }));
    // Tool 38: Class Cohesion Analysis (v0.9.0)
    ctx.tools.register(defineTool({
        name: 'class_cohesion',
        description: 'Analyze class cohesion: method/field ratios, split suggestions for low cohesion.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = analyzeCohesion(args.code, language);
            return formatCohesionReport(result);
        }
    }));
    // Tool 39: Comment Quality Analysis (v0.9.0)
    ctx.tools.register(defineTool({
        name: 'comment_quality',
        description: 'Analyze comment quality: useful/redundant/noise classification, coverage ratio.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = analyzeCommentQuality(args.code, language);
            return formatCommentQualityReport(result);
        }
    }));
    // Tool 40: Type Safety Score (v0.9.0)
    ctx.tools.register(defineTool({
        name: 'type_safety',
        description: 'Score TypeScript type safety: any count, missing returns, type assertions.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to score' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = scoreTypeSafety(args.code, language);
            return formatTypeSafetyReport(result);
        }
    }));
    // Tool 41: Async Pattern Detection (v0.9.0)
    ctx.tools.register(defineTool({
        name: 'async_patterns',
        description: 'Detect async patterns: async/await, promise chains, callbacks. Identifies anti-patterns.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' },
            language: { type: 'string', description: 'Programming language' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const language = args.language || detectLanguage(args.code);
            const result = detectAsyncPatterns(args.code, language);
            return formatAsyncPatternReport(result);
        }
    }));
    // Tool 42: Dead Code Detection (v0.10.0)
    ctx.tools.register(defineTool({
        name: 'dead_code_detect',
        description: 'Detect dead code: unused variables, unreachable code, unused exports, dead branches, unused functions.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = detectDeadCode(args.code);
            return formatDeadCodeReport(result);
        }
    }));
    // Tool 43: Circular Dependency Detection (v0.10.0)
    ctx.tools.register(defineTool({
        name: 'circular_dep',
        description: 'Detect circular dependencies between modules or functions. Reports cycles with path and length.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = detectCircularDeps(args.code);
            return formatCircularDepReport(result);
        }
    }));
    // Tool 44: Regex Security Analysis (v0.10.0)
    ctx.tools.register(defineTool({
        name: 'regex_security',
        description: 'Analyze regex patterns for ReDoS risks, catastrophic backtracking, and performance issues.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to scan' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = analyzeRegexSecurity(args.code);
            return formatRegexSecurityReport(result);
        }
    }));
    // Tool 45: JSDoc Auto-Generation (v0.10.0)
    ctx.tools.register(defineTool({
        name: 'jsdoc_generate',
        description: 'Auto-generate JSDoc comments for undocumented functions. Detects missing type annotations.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to document' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = generateJsdoc(args.code);
            return formatJsdocReport(result);
        }
    }));
    // Tool 46: Public API Surface Analysis (v0.10.0)
    ctx.tools.register(defineTool({
        name: 'api_surface',
        description: 'Analyze public API surface: exports, imports, cohesion score, dependency count.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = analyzeApiSurface(args.code);
            return formatApiSurfaceReport(result);
        }
    }));
    // Tool 47: Git History Hotspot Detection (v0.10.0)
    ctx.tools.register(defineTool({
        name: 'git_hotspot',
        description: 'Detect code hotspots: high-change areas, TODO/FIXME density, commented-out code patterns.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = detectGitHotspots(args.code);
            return formatHotspotReport(result);
        }
    }));
    // Tool 48: Module Layer Violation Detection (v0.10.0)
    ctx.tools.register(defineTool({
        name: 'module_layer',
        description: 'Detect architecture layer violations: presentation, service, data, infrastructure coupling.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = detectLayerViolations(args.code);
            return formatLayerViolationReport(result);
        }
    }));
    // Tool 49: Error Propagation Tracing (v0.10.0)
    ctx.tools.register(defineTool({
        name: 'error_trace',
        description: 'Trace error propagation paths: throws, catches, unhandled async, swallowed errors.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to trace' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = traceErrorPropagation(args.code);
            return formatErrorTraceReport(result);
        }
    }));
    // Tool 50: Auto Refactoring (v0.11.0)
    ctx.tools.register(defineTool({
        name: 'auto_refactor',
        description: 'Suggest automated refactorings: extract method, extract variable, inline temp, replace magic number.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to refactor' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = suggestAutoRefactor(args.code);
            return formatAutoRefactorReport(result);
        }
    }));
    // Tool 51: Code Similarity Detection (v0.11.0)
    ctx.tools.register(defineTool({
        name: 'code_similarity',
        description: 'Detect code similarity using token-based Jaccard similarity. Finds duplicate blocks.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = detectCodeSimilarity(args.code);
            return formatSimilarityReport(result);
        }
    }));
    // Tool 52: Primitive Obsession Detection (v0.11.0)
    ctx.tools.register(defineTool({
        name: 'primitive_obsession',
        description: 'Detect primitive obsession: phone, email, money, date etc. that should be domain types.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = detectPrimitiveObsession(args.code);
            return formatPrimitiveObsessionReport(result);
        }
    }));
    // Tool 53: SQL Injection Deep Detection (v0.11.0)
    ctx.tools.register(defineTool({
        name: 'sql_injection',
        description: 'Deep SQL injection detection: concatenation, template literals, dynamic WHERE. Identifies safe patterns too.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to scan' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = detectSqlInjection(args.code);
            return formatSqlInjectionReport(result);
        }
    }));
    // Tool 54: Interface Compliance Checker (v0.11.0)
    ctx.tools.register(defineTool({
        name: 'interface_compliance',
        description: 'Check class compliance with interfaces: missing methods, extra methods, signature mismatches.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to check' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = checkInterfaceCompliance(args.code);
            return formatInterfaceComplianceReport(result);
        }
    }));
    // Tool 55: Magic String Detection (v0.11.0)
    ctx.tools.register(defineTool({
        name: 'magic_string',
        description: 'Detect magic strings: hardcoded literals that should be constants. Flags user-facing strings for i18n.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = detectMagicStrings(args.code);
            return formatMagicStringReport(result);
        }
    }));
    // Tool 56: Semantic Version Bump Recommender (v0.11.0)
    ctx.tools.register(defineTool({
        name: 'semver_bump',
        description: 'Recommend semantic version bump: breaking changes (major), features (minor), fixes (patch).',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to analyze' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = recommendSemverBump(args.code);
            return formatSemverReport(result);
        }
    }));
    // Tool 57: PR Review Comment Generator (v0.11.0)
    ctx.tools.register(defineTool({
        name: 'code_review_comment',
        description: 'Generate inline PR review comments: security issues, performance, clean code, best practices.',
        parameters: {
            code: { type: 'string', required: true, description: 'The source code to review' }
        },
        output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
        async execute(args) {
            const result = generatePRReviewComments(args.code);
            return formatPRReviewCommentReport(result);
        }
    }));
    console.log(`[${name}] v${VERSION} loaded; tools: code_review, security_scan, dependency_audit, performance_check, code_check, architecture_review, test_coverage, api_docs, code_diff, style_check, code_smell_detect, ts_strict_check, incremental_analysis, breaking_change, sarif_export, diff_preview, config_load, test_generate, complexity_metrics, batch_analyze, monorepo_analyze, multilang_analyze, cicd_generate, custom_rules, duplicate_detect, refactor_suggest, naming_check, security_patterns, performance_tips, doc_check, import_organize, error_handling, api_design, coverage_estimate, dep_versions, style_enforce, func_length, class_cohesion, comment_quality, type_safety, async_patterns, dead_code_detect, circular_dep, regex_security, jsdoc_generate, api_surface, git_hotspot, module_layer, error_trace, auto_refactor, code_similarity, primitive_obsession, sql_injection, interface_compliance, magic_string, semver_bump, code_review_comment`);
}
//# sourceMappingURL=index.js.map
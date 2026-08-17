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
import type { Context } from '@deepseek-ai/cordis';
export declare const name = "dsh-tool-codereview";
export declare const inject: string[];
export declare function apply(ctx: Context): void;
//# sourceMappingURL=index.d.ts.map
/**
 * NanoMind Scanner Bridge
 *
 * Integrates AST-based analyzers into the existing HMA scan flow.
 * Defense-in-depth: both static and AST checks run. NanoMind can
 * UPGRADE findings (add new, increase severity) but NEVER suppress
 * static findings.
 *
 * Flow:
 *   1. verifyAll() integrity check
 *   2. Discover security-relevant files in target directory
 *   3. Compile each file into a SecurityAST via SemanticCompiler
 *   4. Run ALL AST analyzers (capability, credential, governance, scope)
 *   5. Merge AST findings with static findings using defense-in-depth rules
 *   6. Return merged findings + integrity status
 */

import { readFile, readdir, stat } from 'node:fs/promises';
import { join, relative, extname, basename } from 'node:path';

import type { SecurityFinding, Severity } from '../hardening/security-check.js';
import type { SecurityAST, CompilationResult } from './types.js';
import type { ASTFinding } from './analyzers/capability-analyzer.js';
import type { IntegrityStatus } from './security/integrity-verifier.js';

import { SemanticCompiler } from './compiler/semantic-compiler.js';
import { analyzeCapabilities } from './analyzers/capability-analyzer.js';
import { analyzeCredentials } from './analyzers/credential-analyzer.js';
import { analyzeGovernance } from './analyzers/governance-analyzer.js';
import { analyzeScope } from './analyzers/scope-analyzer.js';
import { analyzePrompt } from './analyzers/prompt-analyzer.js';
import { analyzeCode } from './analyzers/code-analyzer.js';
import { analyzeSteganography } from './analyzers/stego-analyzer.js';
import { enrichFindings } from './fix-generator.js';
import { enforceSeverityFloor, validateEnhancement } from './security/defense-in-depth.js';
import type { SeverityLevel } from './security/defense-in-depth.js';
import { verifyAll } from './security/integrity-verifier.js';

// ============================================================================
// Constants
// ============================================================================

/**
 * File extensions and names that are security-relevant and should be compiled
 * into SecurityASTs. Kept intentionally broad -- the compiler's artifact
 * classifier will set type to 'unknown' for non-matching content, and
 * analyzers simply produce no findings for unknowns.
 */
const SECURITY_RELEVANT_EXTENSIONS = new Set([
  '.md', '.json', '.yaml', '.yml', '.toml',
  '.ts', '.js', '.py', '.go', '.rs',
  '.env', '.cfg', '.ini', '.conf',
]);

const SECURITY_RELEVANT_NAMES = new Set([
  '.env', '.cursorrules', '.clinerules', '.windsurfrules',
  'mcp.json', 'agent.json', 'SOUL.md', 'SKILL.md', 'CLAUDE.md',
]);

/** Maximum file size to compile (1 MB). Larger files are skipped. */
const MAX_FILE_SIZE = 1_048_576;

/** Maximum number of files to compile per scan to bound runtime. */
const MAX_FILES_PER_SCAN = 200;

// ============================================================================
// Public API
// ============================================================================

export interface NanoMindScanResult {
  mergedFindings: SecurityFinding[];
  astFindings: ASTFinding[];
  integrityStatus: IntegrityStatus;
  compiledArtifacts: number;
  nanomindAvailable: boolean;
}

/**
 * Run the NanoMind AST-based scan and merge results with existing static
 * findings. This is the main entry point called from the scanner flow.
 *
 * Defense-in-depth rules:
 *   - AST findings ADD to the list (never remove static findings)
 *   - If AST and static both flag the same issue, use the higher severity
 *   - If AST says benign but static flags it, static wins (suppression blocked)
 */
export async function runNanoMindScan(
  targetDir: string,
  existingFindings: SecurityFinding[],
): Promise<NanoMindScanResult> {
  // Step 1: Integrity check before anything else
  const integrity = verifyAll();

  // If quarantined, return existing findings untouched with status
  if (integrity.status === 'QUARANTINE') {
    return {
      mergedFindings: [...existingFindings],
      astFindings: [],
      integrityStatus: 'QUARANTINE',
      compiledArtifacts: 0,
      nanomindAvailable: false,
    };
  }

  // Step 2: Initialize compiler (heuristic-only if degraded)
  const useNanoMind = integrity.status === 'CLEAN';
  const compiler = new SemanticCompiler({ useNanoMind });

  // Step 3: Discover security-relevant files
  const files = await discoverFiles(targetDir);

  // Step 4: Compile each file and run analyzers
  const allASTFindings: ASTFinding[] = [];
  let compiledCount = 0;
  let nanomindUsedAtLeastOnce = false;

  for (const filePath of files) {
    try {
      const content = await readFile(filePath, 'utf-8');
      const relativePath = relative(targetDir, filePath);

      const result = await compiler.compile(content, relativePath);
      compiledCount++;

      if (result.nanomindUsed) {
        nanomindUsedAtLeastOnce = true;
      }

      // Skip documentation and metadata files — these are not security artifacts.
      // URLs in package.json are not exfiltration, "should" in README is not governance.
      const fileName = basename(filePath).toLowerCase();
      if (/^(readme|changelog|license|contributing|history|authors)/i.test(fileName) ||
          fileName === 'package.json' || fileName === 'package-lock.json' ||
          fileName === 'tsconfig.json' || fileName === '.npmrc') {
        continue;
      }

      // Select analyzers based on artifact type:
      // - Security artifacts (SOUL, system prompts, skills, configs): ALL analyzers
      // - Source code: credential + code analysis only (no governance/scope/exfil)
      // - Everything else: ALL analyzers
      const verifier = (ast: SecurityAST) => compiler.verifyAST(ast);
      const isSourceCode = result.ast.artifactType === 'source_code';
      const findings = isSourceCode
        ? runCodeAnalyzers(result.ast, verifier)
        : runAllAnalyzers(result.ast, verifier);
      allASTFindings.push(...findings);
    } catch {
      // Skip files that fail to read or compile -- do not block the scan
      continue;
    }
  }

  // Step 5: Merge using defense-in-depth rules
  const mergedFindings = mergeFindings(existingFindings, allASTFindings);

  return {
    mergedFindings,
    astFindings: allASTFindings,
    integrityStatus: integrity.status,
    compiledArtifacts: compiledCount,
    nanomindAvailable: nanomindUsedAtLeastOnce || useNanoMind,
  };
}

// ============================================================================
// File Discovery
// ============================================================================

/**
 * Recursively discover security-relevant files in the target directory.
 * Skips node_modules, .git, dist, and other non-security directories.
 */
async function discoverFiles(dir: string): Promise<string[]> {
  const results: string[] = [];
  await walkDir(dir, results, 0);
  return results.slice(0, MAX_FILES_PER_SCAN);
}

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage',
  '.next', '.nuxt', '__pycache__', '.venv', 'venv',
  '.tox', '.mypy_cache', 'target', '.cache',
  '__tests__', '__test__', '__mocks__', '__fixtures__',
  'test', 'tests', 'spec', 'specs',
]);

/** Test file patterns -- these contain test assertions, not governance constraints */
const TEST_FILE_PATTERN = /\.(test|spec|e2e|integration)\.(ts|js|mjs|py|go)$/;

async function walkDir(dir: string, results: string[], depth: number): Promise<void> {
  if (depth > 10 || results.length >= MAX_FILES_PER_SCAN) return;

  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return; // Permission denied or similar
  }

  for (const entry of entries) {
    if (results.length >= MAX_FILES_PER_SCAN) break;

    const fullPath = join(dir, entry.name);

    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
        await walkDir(fullPath, results, depth + 1);
      }
      // Also check dotfiles that are security-relevant (e.g., .cursorrules)
      if (entry.name === '.claude') {
        await walkDir(fullPath, results, depth + 1);
      }
      continue;
    }

    if (!entry.isFile()) continue;

    // Check by exact name first
    if (SECURITY_RELEVANT_NAMES.has(entry.name)) {
      if (await isWithinSizeLimit(fullPath)) {
        results.push(fullPath);
      }
      continue;
    }

    // Skip test files -- their `should`/`expect` language is not governance
    if (TEST_FILE_PATTERN.test(entry.name)) {
      continue;
    }

    // Check by extension
    const ext = extname(entry.name).toLowerCase();
    if (SECURITY_RELEVANT_EXTENSIONS.has(ext)) {
      if (await isWithinSizeLimit(fullPath)) {
        results.push(fullPath);
      }
    }

    // Dotfiles without extension (e.g., .env.local)
    if (entry.name.startsWith('.env')) {
      if (await isWithinSizeLimit(fullPath)) {
        results.push(fullPath);
      }
    }
  }
}

async function isWithinSizeLimit(filePath: string): Promise<boolean> {
  try {
    const s = await stat(filePath);
    return s.size <= MAX_FILE_SIZE && s.size > 0;
  } catch {
    return false;
  }
}

// ============================================================================
// Analyzer Orchestration
// ============================================================================

/**
 * Run all six AST analyzers against a compiled SecurityAST, then enrich
 * findings with context-aware fix suggestions using the fix generator.
 * Each analyzer independently queries the AST structure.
 */
function runAllAnalyzers(
  ast: SecurityAST,
  verifier: (ast: SecurityAST) => boolean,
): ASTFinding[] {
  const findings: ASTFinding[] = [];

  // Capability analyzer does not require verifier (checks internally)
  findings.push(...analyzeCapabilities(ast));

  // Credential, governance, and scope analyzers require AST integrity verification
  findings.push(...analyzeCredentials(ast, verifier));
  findings.push(...analyzeGovernance(ast, verifier));
  findings.push(...analyzeScope(ast, verifier));

  // Prompt and code analyzers: jailbreak susceptibility, injection patterns, etc.
  findings.push(...analyzePrompt(ast, verifier));
  findings.push(...analyzeCode(ast, verifier));

  // Steganography analyzer: semantic Unicode analysis (emoji, i18n, homoglyphs)
  findings.push(...analyzeSteganography(ast));

  // Enrich all findings with context-aware fix suggestions
  // Uses TME classification + AST context to produce specific, actionable fixes
  // instead of generic template strings
  return enrichFindings(findings, ast);
}

/**
 * Run only credential and code analyzers against a SecurityAST.
 * Used for source code files (.ts, .js, .py, etc.) where governance,
 * scope, exfiltration, and prompt analysis produce false positives.
 * Source code "should" is a variable name or comment, not a constraint.
 */
function runCodeAnalyzers(
  ast: SecurityAST,
  verifier: (ast: SecurityAST) => boolean,
): ASTFinding[] {
  const findings: ASTFinding[] = [];
  findings.push(...analyzeCredentials(ast, verifier));
  findings.push(...analyzeCode(ast, verifier));
  return enrichFindings(findings, ast);
}

// ============================================================================
// Finding Merge (Defense-in-Depth)
// ============================================================================

/**
 * Severity rank for comparison. Higher number = more severe.
 */
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/**
 * Build a dedup key for matching AST findings to static findings.
 * Two findings are considered "the same issue" if they share the same
 * file path and a matching attack class or check ID prefix.
 */
function findingMatchKey(file: string | undefined, attackClass: string | undefined, checkId: string): string {
  const f = file ?? '__global__';
  const a = attackClass ?? checkId.split('-').slice(0, 2).join('-');
  return `${f}::${a}`;
}

/**
 * Merge AST findings into the static findings list following defense-in-depth:
 *
 *   1. Start with ALL static findings (never remove any)
 *   2. For each AST finding:
 *      a. If it matches a static finding (same file + attack class), upgrade
 *         severity if AST severity is higher. Never downgrade.
 *      b. If AST says passed but static says failed for the same issue,
 *         the static finding wins (suppression blocked via validateEnhancement).
 *      c. If no matching static finding, add the AST finding as a new finding.
 */
export function mergeFindings(
  staticFindings: SecurityFinding[],
  astFindings: ASTFinding[],
): SecurityFinding[] {
  // Clone static findings so we don't mutate the originals
  const merged: SecurityFinding[] = staticFindings.map(f => ({ ...f }));

  // Index static findings by match key for O(1) lookup
  const staticIndex = new Map<string, number[]>();
  for (let i = 0; i < merged.length; i++) {
    const key = findingMatchKey(merged[i].file, merged[i].attackClass, merged[i].checkId);
    const indices = staticIndex.get(key) ?? [];
    indices.push(i);
    staticIndex.set(key, indices);
  }

  for (const astFinding of astFindings) {
    // Skip passed AST findings -- they don't add value in defense-in-depth
    // (they can't suppress static findings and don't represent new issues)
    if (astFinding.passed) continue;

    const key = findingMatchKey(astFinding.file, astFinding.attackClass, astFinding.checkId);
    const matchIndices = staticIndex.get(key);

    if (matchIndices && matchIndices.length > 0) {
      // Matching static finding(s) exist -- apply defense-in-depth rules
      for (const idx of matchIndices) {
        const staticFinding = merged[idx];

        // Rule: If AST says passed but static says failed, static wins
        if (!validateEnhancement(staticFinding.passed, astFinding.passed)) {
          // Suppression blocked -- keep static finding as-is
          continue;
        }

        // Rule: Use the higher severity (AST can only upgrade)
        const astSeverity = normalizeSeverity(astFinding.severity);
        const resolvedSeverity = enforceSeverityFloor(
          staticFinding.severity as SeverityLevel,
          astSeverity as SeverityLevel,
        );
        merged[idx] = {
          ...staticFinding,
          severity: resolvedSeverity as Severity,
        };
      }
    } else {
      // No matching static finding -- add as a new finding
      merged.push(astFindingToSecurityFinding(astFinding));
    }
  }

  return merged;
}

// ============================================================================
// Conversion Helpers
// ============================================================================

/**
 * Convert an ASTFinding to a SecurityFinding for the merged output.
 * The `file` property must be truthy for findings to pass the scanner filter.
 */
function astFindingToSecurityFinding(ast: ASTFinding): SecurityFinding {
  return {
    checkId: ast.checkId,
    name: ast.name,
    description: ast.description,
    category: ast.category,
    severity: normalizeSeverity(ast.severity),
    passed: ast.passed,
    message: ast.message,
    fixable: ast.fixable,
    file: ast.file ?? 'ast-analysis',
    line: ast.line,
    fix: ast.fix,
    guidance: ast.guidance,
    attackClass: ast.attackClass,
    details: {
      source: 'nanomind-ast',
      confidence: ast.confidence,
      evidence: ast.evidence,
    },
  };
}

/**
 * Normalize the 'info' severity level (used by AST analyzers) to 'low'
 * (used by SecurityFinding). The SecurityFinding type does not include 'info'.
 */
function normalizeSeverity(severity: ASTFinding['severity']): Severity {
  if (severity === 'info') return 'low';
  return severity;
}

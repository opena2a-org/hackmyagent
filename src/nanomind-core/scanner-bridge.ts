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

import type { SecurityFinding, Severity, ProjectType, NanoMindIntentSignal } from '../hardening/security-check.js';
import type { SecurityAST, CompilationResult } from './types.js';
import type { ASTFinding } from './analyzers/capability-analyzer.js';
import type { IntegrityStatus } from './security/integrity-verifier.js';

import { SemanticCompiler, extractDeclaredConstraints } from './compiler/semantic-compiler.js';
import type { Constraint } from './types.js';
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
import { queueClassificationStat } from '../telemetry/nanomind-telemetry.js';

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

/**
 * Extensions the structural pipeline ignores but the analyst coverage sweep
 * should still read. Behavioral attack content ships in plain documents:
 * 3/86 DVAA scenarios (clipboard-prompt-injection, docker-provenance-disabled,
 * mcp-discovery-exposed) were silent misses solely because their content is
 * .html/.txt — coverageSweep.candidates was 0. These files are NEVER compiled
 * or structurally analyzed (widening the compile set would change the
 * structural FP/perf surface); they only become sweep candidates, so the
 * analyst decides what they mean.
 */
const SWEEP_ONLY_EXTENSIONS = new Set(['.html', '.txt']);

/**
 * Dot-directories the walk enters in SWEEP-ONLY mode. The walk skips dot
 * directories (except .claude), which made two whole attack surfaces
 * invisible to every layer: .github/workflows (supply-chain/provenance CI
 * config — DVAA docker-provenance-disabled) and .well-known (MCP discovery
 * manifests — DVAA mcp-discovery-exposed). Files under these trees become
 * coverage-sweep candidates only; the structural pipeline still never
 * compiles them, so its FP/perf surface stays untouched.
 */
const SWEEP_ONLY_DIRS = new Set(['.github', '.well-known']);

/** Artifact-type label for sweep-only candidates. Not a compiler-assigned
 *  type: these files are never compiled, so no classifier verdict exists for
 *  them at discovery time. Not in AGENT_ARTIFACT_TYPES, so they sort after
 *  agent artifacts in the sweep's priority order. */
export const SWEEP_ONLY_ARTIFACT_TYPE = 'document';

/** Maximum file size to compile (1 MB). Larger files are skipped. */
const MAX_FILE_SIZE = 1_048_576;

/** Maximum number of files to compile per scan to bound runtime. */
const MAX_FILES_PER_SCAN = 200;

// ============================================================================
// Public API
// ============================================================================

/** Compact summary of one compiled artifact, suitable for CLI rendering.
 *  Populated during the scanner-bridge compile loop so the display layer
 *  can describe what the project ACTUALLY CONTAINS (not just how many
 *  findings fired). Avoids shipping full ASTs through the public API. */
export interface ArtifactSummary {
  path: string;                      // relative path from scan root
  type: string;                      // artifactType (skill, mcp_config, soul, ...)
  intent: 'benign' | 'suspicious' | 'malicious' | 'unknown';
  capabilityLabels: string[];        // human-readable, up to 4 (e.g. "fs-write", "shell-exec")
  constraintCount: number;           // # of declared constraints (0 = no governance)
  weakConstraintCount: number;       // # of constraints with bypassRisk > 0.5
}

/** One artifact eligible for the analyst coverage sweep (Phase A P1).
 *  Collected for EVERY compiled file (agent artifacts, source code, docs) —
 *  behavioral attacks hide in all three — so the sweep layer, not discovery,
 *  decides what the analyst reads. Also collected for sweep-only files
 *  (SWEEP_ONLY_EXTENSIONS) that the structural pipeline never compiles. */
export interface CoverageCandidate {
  /** Relative path from scan root (matches SecurityFinding.file). */
  path: string;
  /** Compiler-assigned artifact type (skill, mcp_config, soul, source_code,
   *  ...), or SWEEP_ONLY_ARTIFACT_TYPE for uncompiled sweep-only files. */
  artifactType: string;
}

export interface NanoMindScanResult {
  mergedFindings: SecurityFinding[];
  astFindings: ASTFinding[];
  integrityStatus: IntegrityStatus;
  compiledArtifacts: number;
  artifactSummaries: ArtifactSummary[];
  nanomindAvailable: boolean;
  /** Every compiled artifact, for the --nanomind analyst coverage sweep. */
  coverageCandidates: CoverageCandidate[];
  /**
   * True when the compile set hit `MAX_FILES_PER_SCAN` (200), so the semantic
   * layer saw the first 200 files in walk order and nothing after them.
   *
   * The display layer prints `compiledArtifacts` as "N files analyzed". On a
   * tree larger than the cap that N IS the cap, and printing it unqualified is
   * what let a 529-file repo report "200 files analyzed" beside "(all clear)".
   */
  compileSetTruncated: boolean;
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
  projectType?: ProjectType,
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
      artifactSummaries: [],
      nanomindAvailable: false,
      coverageCandidates: [],
      compileSetTruncated: false,
    };
  }

  // Step 2: Initialize compiler (heuristic-only if degraded)
  const useNanoMind = integrity.status === 'CLEAN';
  const compiler = new SemanticCompiler({ useNanoMind });

  // Step 3: Discover security-relevant files. Sweep-only documents (.html/.txt)
  // come back separately: they skip the structural pipeline entirely and are
  // appended to coverageCandidates after the compile loop (Step 4b).
  const { compileFiles: files, sweepOnlyFiles, truncated: compileSetTruncated } =
    await discoverFiles(targetDir);

  // Step 3b: Load project-level constraints from SOUL.md / CLAUDE.md / .opena2a/policy.*
  // When a governance file exists in the project root, its constraints cover every sibling
  // artifact (mcp.json, skills, etc.). We extract them once and pass them to the governance
  // analyzer so that a harden-soul → scan round-trip shows measurable improvement.
  const governanceFileCandidates = [
    join(targetDir, 'SOUL.md'),
    join(targetDir, 'CLAUDE.md'),
    join(targetDir, '.opena2a', 'policy.yml'),
    join(targetDir, '.opena2a', 'policy.yaml'),
    join(targetDir, '.opena2a', 'policy.json'),
  ];
  let projectConstraints: Constraint[] = [];
  for (const candidate of governanceFileCandidates) {
    try {
      const govContent = await readFile(candidate, 'utf-8');
      projectConstraints = extractDeclaredConstraints(govContent);
      break; // Use the first governance file found
    } catch {
      // File not found — try next candidate
    }
  }

  // Step 4: Compile each file and run analyzers
  const allASTFindings: ASTFinding[] = [];
  const artifactSummaries: ArtifactSummary[] = [];
  const coverageCandidates: CoverageCandidate[] = [];
  // Advisory per-artifact NanoMind intent, keyed by relative path. Populated
  // only when the non-generative classifier (not the heuristic fallback)
  // classified the artifact, so the signal honestly means "the model said X".
  const intentByPath = new Map<string, NanoMindIntentSignal>();
  let compiledCount = 0;
  let nanomindUsedAtLeastOnce = false;

  for (const filePath of files) {
    try {
      const content = await readFile(filePath, 'utf-8');
      const relativePath = relative(targetDir, filePath);

      const result = await compiler.compile(content, relativePath);
      compiledCount++;
      coverageCandidates.push({ path: relativePath, artifactType: result.ast.artifactType });

      if (result.nanomindUsed) {
        nanomindUsedAtLeastOnce = true;
      }

      // Queue classification telemetry (anonymous, opt-in via contribute.enabled)
      queueClassificationStat(
        result.ast.artifactType,
        content,
        result.ast.intentClassification,
        result.ast.intentConfidence,
        result.ast.modelVersion,
      );

      // Capture a compact summary for the CLI Observations block. Only
      // security-relevant artifact types — skipping source_code / unknown /
      // env_file avoids pollution from ordinary files that the compiler
      // fingerprints but the user doesn't want enumerated.
      const isAgentArtifact = ['skill', 'mcp_config', 'soul', 'system_prompt', 'agent_config', 'a2a_card'].includes(result.ast.artifactType);
      if (isAgentArtifact) {
        artifactSummaries.push(buildArtifactSummary(result.ast, relativePath));
        // Capture the advisory NanoMind intent for this artifact so every
        // finding on it carries the classifier's read (trust score / ARIA /
        // ATM signal). The gate lives in intentSignalFromCompilation: a
        // heuristic-fallback label is not a model verdict and must not
        // masquerade as one.
        const intent = intentSignalFromCompilation(result);
        if (intent) intentByPath.set(relativePath, intent);
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
      // - Agent artifacts (soul, system_prompt, skill, agent_config, a2a_card, mcp_config):
      //   ALL analyzers — governance, prompt, scope, capability checks are relevant
      // - Source code: credential + code analysis only (no governance/scope/exfil)
      // - Everything else (docs, unknown, env_file, credential_file, ide configs):
      //   credential + code + stego only — governance/prompt/scope/capability are FPs
      const verifier = (ast: SecurityAST) => compiler.verifyAST(ast);
      const agentTypes = new Set(['soul', 'skill', 'agent_config', 'a2a_card', 'mcp_config']);
      // system_prompt is agent-like ONLY if it's an actual system prompt file,
      // not a developer instruction file (CLAUDE.md, .cursorrules, .clinerules, .windsurfrules).
      const pathLower = (result.ast.artifactPath ?? '').toLowerCase();
      const isDevInstructionFile = result.ast.artifactType === 'system_prompt' && (
        pathLower.includes('claude.md') || pathLower.includes('.cursorrules') ||
        pathLower.includes('.clinerules') || pathLower.includes('.windsurfrules')
      );
      const isAgent = agentTypes.has(result.ast.artifactType) ||
        (result.ast.artifactType === 'system_prompt' && !isDevInstructionFile);
      const isSourceCode = result.ast.artifactType === 'source_code';
      // Pass project constraints to agent analyzers — but not for soul artifacts themselves
      // (they carry their own constraints) and not when the artifact IS the governance file.
      const isSoulArtifact = result.ast.artifactType === 'soul';
      const extraConstraints = (isAgent && !isSoulArtifact && projectConstraints.length > 0)
        ? projectConstraints
        : undefined;
      const findings = isAgent
        ? runAllAnalyzers(result.ast, verifier, projectType, extraConstraints, content)
        : isSourceCode
          ? runCodeAnalyzers(result.ast, verifier, content)
          : runNonAgentAnalyzers(result.ast, verifier, content);
      allASTFindings.push(...findings);
    } catch {
      // Skip files that fail to read or compile -- do not block the scan
      continue;
    }
  }

  // Step 4b: Sweep-only documents become coverage candidates without ever
  // touching the compiler or analyzers — compiledArtifacts, artifactSummaries,
  // findings, and telemetry are all unaffected by their presence. The sweep
  // itself reads their content at sweep time and the analyst judges it.
  for (const filePath of sweepOnlyFiles) {
    coverageCandidates.push({
      path: relative(targetDir, filePath),
      artifactType: SWEEP_ONLY_ARTIFACT_TYPE,
    });
  }

  // Step 5: Deduplicate AST findings (group by checkId, keep representative)
  const dedupedASTFindings = deduplicateFindings(allASTFindings);

  // Step 6: Merge using defense-in-depth rules
  const mergedFindings = mergeFindings(existingFindings, dedupedASTFindings);

  // Step 7: Attach the advisory NanoMind intent to every finding whose artifact
  // the classifier read.
  const annotatedFindings = annotateFindingsWithIntent(mergedFindings, intentByPath);

  return {
    mergedFindings: annotatedFindings,
    astFindings: allASTFindings,
    integrityStatus: integrity.status,
    compiledArtifacts: compiledCount,
    artifactSummaries,
    nanomindAvailable: nanomindUsedAtLeastOnce || useNanoMind,
    coverageCandidates,
    compileSetTruncated,
  };
}

/**
 * Derive the advisory intent signal from a compilation result — or null when
 * the non-generative classifier did NOT run (heuristic fallback). This is the
 * honesty gate for the signal: a heuristic label is not a model verdict and
 * must never be surfaced as one, so `nanomindUsed === false` yields no signal.
 */
export function intentSignalFromCompilation(
  result: CompilationResult,
): NanoMindIntentSignal | null {
  if (!result.nanomindUsed) return null;
  return {
    classification: result.ast.intentClassification,
    confidence: result.ast.intentConfidence,
    modelVersion: result.ast.modelVersion,
  };
}

/**
 * Attach the advisory NanoMind intent to every finding whose artifact the
 * classifier read (keyed by relative file path). Additive metadata ONLY: this
 * never reorders, suppresses, re-severities, or rescores any finding — it
 * satisfies the editorial signal-only constraint (the intent feeds the trust
 * score / ARIA / Agent Threat Matrix, never the deny path or HMA's score).
 * Findings are shallow-copied so shared static-finding objects are not mutated;
 * an empty map returns the input array unchanged.
 */
export function annotateFindingsWithIntent(
  findings: SecurityFinding[],
  intentByPath: Map<string, NanoMindIntentSignal>,
): SecurityFinding[] {
  if (intentByPath.size === 0) return findings;
  return findings.map(f => {
    const intent = f.file ? intentByPath.get(f.file) : undefined;
    return intent ? { ...f, nanomindIntent: intent } : f;
  });
}

// ============================================================================
// Artifact Summary Builder
// ============================================================================

/**
 * Distill a SecurityAST into a compact summary suitable for CLI rendering.
 *
 * Capability names in the AST come from analyzer-internal taxonomy (e.g.
 * `filesystem.write`, `network.http`, `shell.exec`). Those don't read well
 * to a CISO — so we collapse them to short, readable phrases: "fs-write",
 * "net-http", "shell-exec". The mapping is deterministic; no model inference.
 */
function buildArtifactSummary(ast: SecurityAST, relativePath: string): ArtifactSummary {
  // Prefer inferred over declared — inferred reflects what the artifact
  // ACTUALLY does, declared reflects what it claims to do. Divergence is a
  // separate finding; here we describe behaviour.
  const inferredLabels = ast.inferredCapabilities.map(c => humanizeCapability(c.name));
  // Deduplicate (same capability can be inferred multiple times with different scopes)
  const uniqueLabels = Array.from(new Set(inferredLabels)).filter(Boolean);

  const weakConstraintCount = ast.declaredConstraints.filter(c => c.bypassRisk > 0.5).length;

  return {
    path: relativePath,
    type: ast.artifactType,
    intent: (ast.intentClassification ?? 'unknown') as ArtifactSummary['intent'],
    capabilityLabels: uniqueLabels.slice(0, 4), // cap at 4 to keep the CLI line short
    constraintCount: ast.declaredConstraints.length,
    weakConstraintCount,
  };
}

/**
 * Collapse analyzer-internal capability names (dot-delimited,
 * domain-first) into short display labels. Unknown names pass through
 * as-is (better to show a raw name than a generic placeholder).
 */
function humanizeCapability(name: string): string {
  const map: Record<string, string> = {
    'filesystem.read': 'fs-read',
    'filesystem.write': 'fs-write',
    'filesystem.delete': 'fs-delete',
    'network.http': 'net-http',
    'network.egress': 'net-egress',
    'shell.exec': 'shell-exec',
    'shell.spawn': 'shell-spawn',
    'process.kill': 'proc-kill',
    'credential.read': 'creds-read',
    'credential.write': 'creds-write',
    'memory.read': 'mem-read',
    'memory.write': 'mem-write',
    'api.call': 'api-call',
    'database.read': 'db-read',
    'database.write': 'db-write',
    'cron.schedule': 'cron',
    'persistence.session': 'persistence',
    'exfiltration.external': 'data-egress',
    'injection.prompt': 'prompt-injection',
  };
  if (map[name]) return map[name];
  // Fallback: take the last segment, e.g. "custom.foo.bar" -> "bar"
  const segs = name.split('.');
  return segs[segs.length - 1] || name;
}

// ============================================================================
// File Discovery
// ============================================================================

/**
 * Recursively discover security-relevant files in the target directory.
 * Skips node_modules, .git, dist, and other non-security directories.
 */
interface DiscoveredFiles {
  /** Files for the structural pipeline: compiled into SecurityASTs + analyzed. */
  compileFiles: string[];
  /** Sweep-only files (SWEEP_ONLY_EXTENSIONS): coverage-sweep candidates the
   *  structural pipeline never touches. */
  sweepOnlyFiles: string[];
  /**
   * True when `MAX_FILES_PER_SCAN` stopped the walk before it ran out of tree.
   *
   * The walk is depth-first in `readdir` order, so on a repo larger than the
   * cap the files that get compiled are simply the first 200 encountered and
   * everything after is invisible to this layer. Without this flag the caller
   * cannot tell `200 files analyzed` (a cap) from `200 files analyzed` (a
   * whole small repo), and it printed both the same way.
   */
  truncated: boolean;
}

async function discoverFiles(dir: string): Promise<DiscoveredFiles> {
  const results: string[] = [];
  const sweepOnly: string[] = [];
  // Single-FILE target (e.g. `secure SOUL.md`): walkDir's readdir() throws
  // ENOTDIR and silently returns nothing, so the semantic/AST analyzers never
  // run — pointing `secure` at a lone SOUL.md / SKILL.md returned a high
  // infra-only score that contradicted `check --nanomind` on the same file
  // (cross-analyzer direction disagreement, audit 2026-06-01). Scan the file
  // the user explicitly named directly — including a sweep-only extension:
  // an explicitly named file keeps today's behavior (compiled + analyzed).
  try {
    const st = await stat(dir);
    if (st.isFile()) {
      // Apply the same size/empty guard directory mode uses (isWithinSizeLimit)
      // so a multi-GB lone file can't OOM the reader and a 0-byte file is
      // skipped exactly as in a directory scan.
      const ok = await isWithinSizeLimit(dir);
      return { compileFiles: ok ? [dir] : [], sweepOnlyFiles: [], truncated: false };
    }
  } catch {
    // path vanished between resolve and scan
    return { compileFiles: results, sweepOnlyFiles: sweepOnly, truncated: false };
  }
  await walkDir(dir, results, sweepOnly, 0);
  // `walkDir` returns the moment the compile set reaches the cap, so reaching
  // it means the walk ended on the cap rather than on running out of tree.
  // Reported conservatively: a repo holding exactly `MAX_FILES_PER_SCAN`
  // eligible files is flagged truncated even though nothing was dropped. That
  // direction understates coverage, which is the only safe direction for a
  // coverage claim to be wrong in.
  const truncated = results.length >= MAX_FILES_PER_SCAN;
  return {
    compileFiles: results.slice(0, MAX_FILES_PER_SCAN),
    sweepOnlyFiles: sweepOnly.slice(0, MAX_FILES_PER_SCAN),
    truncated,
  };
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

async function walkDir(
  dir: string,
  results: string[],
  sweepOnly: string[],
  depth: number,
  sweepOnlyMode = false,
): Promise<void> {
  // The compile-set cap bounds the whole walk (existing behavior); sweep-only
  // collection is best-effort within that bound and has its own cap below.
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
        await walkDir(fullPath, results, sweepOnly, depth + 1, sweepOnlyMode);
      }
      // Also check dotfiles that are security-relevant (e.g., .cursorrules)
      if (entry.name === '.claude') {
        await walkDir(fullPath, results, sweepOnly, depth + 1, sweepOnlyMode);
      }
      // Sweep-only dot-directories (.github, .well-known): whole subtree is
      // analyst-sweep territory, never structural. Once inside, stay in
      // sweep-only mode for nested dirs (e.g. .github/workflows/).
      if (SWEEP_ONLY_DIRS.has(entry.name)) {
        await walkDir(fullPath, results, sweepOnly, depth + 1, true);
      }
      continue;
    }

    if (!entry.isFile()) continue;

    const pushTo = async (target: string[]) => {
      if (target.length < MAX_FILES_PER_SCAN && await isWithinSizeLimit(fullPath)) {
        target.push(fullPath);
      }
    };

    // Check by exact name first
    if (SECURITY_RELEVANT_NAMES.has(entry.name)) {
      await pushTo(sweepOnlyMode ? sweepOnly : results);
      continue;
    }

    // Skip test files -- their `should`/`expect` language is not governance
    if (TEST_FILE_PATTERN.test(entry.name)) {
      continue;
    }

    // Check by extension
    const ext = extname(entry.name).toLowerCase();
    if (SECURITY_RELEVANT_EXTENSIONS.has(ext)) {
      await pushTo(sweepOnlyMode ? sweepOnly : results);
      continue;
    }

    // Dotfiles without extension (e.g., .env.local)
    if (entry.name.startsWith('.env')) {
      await pushTo(sweepOnlyMode ? sweepOnly : results);
      continue;
    }

    // Sweep-only documents (.html/.txt): analyst coverage sweep candidates,
    // never compiled or structurally analyzed. Mutually exclusive with the
    // compile checks above (the `continue`s), so a file lands in exactly one set.
    if (SWEEP_ONLY_EXTENSIONS.has(ext)) {
      await pushTo(sweepOnly);
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
  projectType?: ProjectType,
  projectConstraints?: Constraint[],
  artifactContent?: string,
): ASTFinding[] {
  const findings: ASTFinding[] = [];

  // Capability analyzer does not require verifier (checks internally)
  findings.push(...analyzeCapabilities(ast, projectType, projectConstraints));

  // Credential, governance, and scope analyzers require AST integrity verification
  findings.push(...analyzeCredentials(ast, verifier, projectType, artifactContent));
  findings.push(...analyzeGovernance(ast, verifier, projectType, projectConstraints, artifactContent));
  findings.push(...analyzeScope(ast, verifier, projectType, artifactContent));

  // Prompt and code analyzers: jailbreak susceptibility, injection patterns, etc.
  // Pass projectConstraints so a SKILL.md scanned next to a hardened SOUL.md
  // sees the SOUL.md's Trust Hierarchy section toward AST-PROMPT-004 / 001 /
  // 003 lookups, mirroring the governance-analyzer contract.
  findings.push(...analyzePrompt(ast, verifier, projectType, artifactContent, projectConstraints));
  findings.push(...analyzeCode(ast, verifier));

  // Steganography analyzer: semantic Unicode analysis (emoji, i18n, homoglyphs)
  findings.push(...analyzeSteganography(ast));

  // Enrich all findings with context-aware fix suggestions
  return enrichFindings(findings, ast, projectConstraints);
}

/**
 * Run credential, code, and stego analyzers against non-agent artifacts.
 * Used for documentation, IDE configs, env files, unknown types — anything
 * that isn't an agent artifact or source code. Governance, prompt, scope,
 * and capability analyzers are skipped because these files don't have
 * override resistance, trust hierarchies, or declared capabilities.
 */
function runNonAgentAnalyzers(
  ast: SecurityAST,
  verifier: (ast: SecurityAST) => boolean,
  artifactContent?: string,
): ASTFinding[] {
  const findings: ASTFinding[] = [];
  findings.push(...analyzeCredentials(ast, verifier, undefined, artifactContent));
  findings.push(...analyzeCode(ast, verifier));
  findings.push(...analyzeSteganography(ast));
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
  artifactContent?: string,
): ASTFinding[] {
  const findings: ASTFinding[] = [];
  findings.push(...analyzeCredentials(ast, verifier, undefined, artifactContent));
  findings.push(...analyzeCode(ast, verifier));
  return enrichFindings(findings, ast);
}

// ============================================================================
// Finding Deduplication
// ============================================================================

/**
 * Deduplicate AST findings by checkId. When the same check fires on many
 * files (e.g., AST-GOV-002 on 60 constraints, AST-EXFIL-001 on 19 risk
 * surfaces), keep one representative finding per checkId with the highest
 * severity and annotate it with instance count and affected files.
 *
 * Passed findings are kept as-is (they don't affect scoring).
 */
function deduplicateFindings(findings: ASTFinding[]): ASTFinding[] {
  const failed: ASTFinding[] = [];
  const passed: ASTFinding[] = [];

  for (const f of findings) {
    if (f.passed) {
      passed.push(f);
    } else {
      failed.push(f);
    }
  }

  // Group failed findings by checkId
  const groups = new Map<string, ASTFinding[]>();
  for (const f of failed) {
    const group = groups.get(f.checkId) ?? [];
    group.push(f);
    groups.set(f.checkId, group);
  }

  const deduped: ASTFinding[] = [];
  for (const [, group] of groups) {
    // Sort by severity (highest first), then confidence (highest first)
    group.sort((a, b) => {
      const sevDiff = (SEVERITY_RANK[normalizeSeverity(b.severity)] ?? 0)
        - (SEVERITY_RANK[normalizeSeverity(a.severity)] ?? 0);
      if (sevDiff !== 0) return sevDiff;
      return (b.confidence ?? 0) - (a.confidence ?? 0);
    });

    const representative = { ...group[0] };

    if (group.length > 1) {
      // Collect unique affected files
      const files = [...new Set(group.map(f => f.file).filter(Boolean))];
      const fileList = files.slice(0, 4).join(', ');
      const suffix = files.length > 4 ? `, +${files.length - 4} more` : '';
      representative.evidence =
        `${representative.evidence ?? ''} [${group.length} instances across: ${fileList}${suffix}]`.trim();
    }

    // Store instance count for downstream scoring
    (representative as ASTFinding & { instanceCount?: number }).instanceCount = group.length;

    deduped.push(representative);
  }

  return [...deduped, ...passed];
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
      instanceCount: (ast as ASTFinding & { instanceCount?: number }).instanceCount ?? 1,
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

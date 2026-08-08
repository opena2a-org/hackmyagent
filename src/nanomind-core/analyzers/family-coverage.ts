/**
 * Which analyzer families actually examined a compiled artifact (#456).
 *
 * `compiledArtifacts` counts files the compiler produced an AST for. The
 * Surfaces and Checks lines printed that number as `N semantic artifact` and
 * `N semantic (NanoMind AST)`, which reads as "the semantic layer looked at N
 * files". On any non-agent artifact those are not the same claim: a `doc.md`
 * carrying an injection payload compiles, routes to `runNonAgentAnalyzers`,
 * and is examined by exactly two of the seven families — capability,
 * governance, scope and prompt analysis never look at it.
 *
 * This module is the measurement behind that disclosure. It is deliberately
 * NOT a second copy of the analyzers' own gates: each family's predicate here
 * either calls the analyzer's own exported gate (`isCodeArtifact`) or is the
 * single definition that the analyzers themselves obey
 * (`isNonAgentProjectType`). A family gate must have one definition, or the
 * disclosure drifts away from the behaviour it describes the first time an
 * analyzer changes its mind.
 *
 * Disclosure only: nothing here raises a finding or changes a severity.
 */

import type { SecurityAST } from '../types.js';
import type { ProjectType } from '../../hardening/security-check.js';
import { isCodeArtifact } from './code-analyzer.js';

/**
 * The seven analyzer families `runAllAnalyzers` runs. This is the denominator
 * the disclosure reports against — the most any artifact can be examined by.
 */
export const ANALYZER_FAMILIES = [
  'capabilities',
  'credentials',
  'governance',
  'scope',
  'prompt',
  'code',
  'stego',
] as const;

export type AnalyzerFamily = (typeof ANALYZER_FAMILIES)[number];

/** 7. Derived from the list so the two can never disagree. */
export const ANALYZER_FAMILY_COUNT = ANALYZER_FAMILIES.length;

/**
 * Which orchestration route `runNanoMindScan` sent the artifact down.
 *
 * `not_routed` is the case neither #456 nor its brief anticipated: the
 * documentation and metadata skip (README, CHANGELOG, LICENSE, package.json,
 * tsconfig.json, .npmrc ...) `continue`s BEFORE the analyzer routing, so those
 * files are counted in `compiledArtifacts` having reached zero families. A
 * disclosure that only handled 2-of-7 would still be overstating them.
 *
 * It has a second cause: an analyzer that throws leaves the row at its starting
 * value, because the bridge records coverage only after the analyzers return. So
 * an artifact type that can never be doc-skipped — a `skill`, say — reported
 * `not_routed` means a throw discarded its findings.
 */
export type AnalyzerRoute = 'agent' | 'source_code' | 'non_agent' | 'not_routed';

/**
 * The families each route INVOKES. Mirrors, one for one, the `findings.push`
 * sequences in `runAllAnalyzers`, `runCodeAnalyzers` and
 * `runNonAgentAnalyzers`. Invocation is not examination — see
 * `familyExaminesArtifact`.
 */
const ROUTE_FAMILIES: Record<AnalyzerRoute, readonly AnalyzerFamily[]> = {
  agent: ANALYZER_FAMILIES,
  source_code: ['credentials', 'code'],
  non_agent: ['credentials', 'code', 'stego'],
  not_routed: [],
};

/**
 * The families a route invokes at all, regardless of whether their own gate
 * then lets them look.
 *
 * Exported so the difference between the two reasons a family can be blind is
 * testable: the route never called it, or it was called and returned
 * immediately. Those need different evidence — the first is only observable
 * end-to-end (the finding never reaches the scan), the second by calling the
 * analyzer directly.
 */
export function analyzerFamiliesInvoked(route: AnalyzerRoute): readonly AnalyzerFamily[] {
  return ROUTE_FAMILIES[route];
}

/**
 * SDKs and libraries are not agents, so the governance, scope and prompt
 * families return `[]` wholesale for them. This is the single definition of
 * that gate: `analyzeGovernance`, `analyzeScope` and `analyzePrompt` all call
 * it, and so does the coverage measurement, so the disclosure cannot claim a
 * family ran that the analyzer declined to run.
 */
export function isNonAgentProjectType(projectType?: ProjectType): boolean {
  return projectType === 'sdk' || projectType === 'library';
}

/**
 * Which route `runNanoMindScan` sends an artifact down.
 *
 * THE definition, exported so the bridge and anything measuring the bridge read
 * the same one. A second copy drifts: an earlier version of the coverage test
 * recomputed this locally and omitted the dev-instruction-file branch, so it
 * believed `CLAUDE.md` took the agent route when the bridge sends it to
 * `non_agent` — a disagreement about six of the seven families.
 */
export function analyzerRouteFor(ast: SecurityAST): AnalyzerRoute {
  const AGENT_TYPES = new Set(['soul', 'skill', 'agent_config', 'a2a_card', 'mcp_config']);
  // `system_prompt` is agent-like ONLY for an actual system prompt file, not a
  // developer instruction file (CLAUDE.md, .cursorrules, .clinerules,
  // .windsurfrules).
  const pathLower = (ast.artifactPath ?? '').toLowerCase();
  const isDevInstructionFile =
    ast.artifactType === 'system_prompt' &&
    (pathLower.includes('claude.md') ||
      pathLower.includes('.cursorrules') ||
      pathLower.includes('.clinerules') ||
      pathLower.includes('.windsurfrules'));
  if (AGENT_TYPES.has(ast.artifactType)) return 'agent';
  if (ast.artifactType === 'system_prompt' && !isDevInstructionFile) return 'agent';
  if (ast.artifactType === 'source_code') return 'source_code';
  return 'non_agent';
}

/**
 * Did this family actually examine the artifact, as opposed to being called and
 * returning immediately?
 *
 * The unit here is the FAMILY, and the question is whether the family inspected
 * the AST at all. Two things it deliberately does not claim:
 *
 * - **Check-level depth.** `analyzeCapabilities` runs three of its checks only
 *   off `isNonAgentProjectType`, so on an sdk or library project it examines the
 *   artifact with a narrower set than on an agent project. The family still
 *   looked, so it counts as examined; the static `Coverage` line is where
 *   check-level accounting lives, and reporting a family as blind because some
 *   of its checks were skipped would understate real coverage.
 * - **How much of the file the AST carried.** `analyzeSteganography` reads
 *   `ast.evidenceSpans` and `ast.declaredPurpose`, not the file body, so on a
 *   long document it inspects a fraction of the bytes. That is a pre-existing
 *   property of the compiler, not of this measurement, and it is not something
 *   the family-level unit can express.
 *
 * `credentials` and `stego` have no gate of their own, so on their route they
 * always examine. The other five are gated, each by exactly one predicate that
 * lives with the analyzer obeying it.
 */
function familyExaminesArtifact(
  family: AnalyzerFamily,
  ast: SecurityAST,
  projectType?: ProjectType,
): boolean {
  switch (family) {
    // `analyzeGovernance` / `analyzeScope` / `analyzePrompt`: early return for
    // sdk and library project types.
    case 'governance':
    case 'scope':
    case 'prompt':
      return !isNonAgentProjectType(projectType);
    // `analyzeCode`'s three checks — command injection, unsafe
    // deserialization, path traversal — each early-return on the same gate, so
    // the family contributes nothing at all off it. This is why an `unknown`
    // artifact reaches 2 families and not the 3 its route invokes.
    case 'code':
      return isCodeArtifact(ast);
    // Runs on every route that invokes it. On an sdk or library project it runs
    // a narrower check set (see the note above), but it does inspect the AST, so
    // reporting it blind would understate coverage.
    case 'capabilities':
    case 'credentials':
    case 'stego':
      return true;
  }
}

/**
 * The families that examined this artifact: the ones its route invoked,
 * intersected with the ones whose own gate let them look.
 *
 * Returns names rather than a count so the `--json` consumer can see WHICH
 * families were blind, which is the actionable half — "2 of 7" tells a reader
 * that something was missed, "capability, governance, scope and prompt did not
 * run" tells them what.
 */
export function analyzerFamiliesExamined(
  route: AnalyzerRoute,
  ast: SecurityAST,
  projectType?: ProjectType,
): AnalyzerFamily[] {
  return ROUTE_FAMILIES[route].filter((family) =>
    familyExaminesArtifact(family, ast, projectType),
  );
}

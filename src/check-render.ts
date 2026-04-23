/**
 * Pure helpers for the `check` command render + JSON emission paths.
 *
 * Lives outside cli.ts so it can be unit-tested without spinning up the
 * commander entry point. The impure render functions (console.log-heavy)
 * stay in cli.ts and import from here.
 *
 * Closes F1 (JSON emission consistency) and F3 (git-style not-found hint)
 * from briefs/check-command-divergence.md.
 */

import type { SecurityFinding } from './index';

/** Registry trust data shape as returned by queryRegistry() in cli.ts. */
export interface RegistryTrustDataLike {
  found: boolean;
  name: string;
  trustScore: number;
  trustLevel: number;
  verdict: string;
  scanStatus?: string;
  lastScannedAt?: string;
  packageType?: string;
  recommendation?: string;
  cveCount?: number;
  communityScans?: number;
  dependencies?: {
    totalDeps?: number;
    vulnerableDeps?: number;
    minTrustLevel?: number;
    riskSummary?: Record<string, unknown>;
  };
}

/**
 * Map the registry's scanStatus vocabulary onto the renderCheckBlock meter
 * gate ("completed" | "warnings" | undefined). Registry returns a wider
 * set of states; collapse the "scan produced a usable score" ones and
 * suppress the meter for everything else (F6: a number implies measurement).
 */
export function mapScanStatusForMeter(status?: string): string | undefined {
  if (!status) return undefined;
  const normalized = status.toLowerCase().trim();
  if (normalized === '' || normalized === 'pending' || normalized === 'not_applicable') return undefined;
  if (normalized === 'error' || normalized === 'failed') return undefined;
  if (normalized === 'warnings' || normalized === 'warning') return 'warnings';
  if (normalized === 'complete' || normalized === 'completed' || normalized === 'passed') return 'completed';
  return undefined;
}

/**
 * Build the top-level JSON shape for `check --json` when the caller has a
 * local scan result. When registry data is also available and found, registry
 * fields (trustLevel, trustScore, verdict, scanStatus, packageType) are
 * merged at the top level so parity tools and consumers see one canonical
 * shape across `hackmyagent check --json`, `opena2a check --json` (spawn
 * delegation), and `ai-trust check --json`. Closes F1.
 */
export function buildCheckJsonOutput(params: {
  name: string;
  type: 'npm-package' | 'github-repo' | 'pypi-package';
  projectType?: string;
  score: number;
  maxScore: number;
  findings: SecurityFinding[];
  registry?: RegistryTrustDataLike | null;
  analystFindings?: Array<Record<string, unknown>>;
  version?: string;
}): Record<string, unknown> {
  const { name, type, projectType, score, maxScore, findings, registry, analystFindings, version } = params;
  const jsonOut: Record<string, unknown> = {
    name,
    type,
    source: 'local-scan',
    projectType,
    score,
    maxScore,
    findings,
  };
  if (version !== undefined) jsonOut.version = version;
  if (registry?.found) {
    jsonOut.trustLevel = registry.trustLevel;
    jsonOut.trustScore = registry.trustScore;
    jsonOut.verdict = registry.verdict;
    if (registry.scanStatus !== undefined) jsonOut.scanStatus = registry.scanStatus;
    if (registry.packageType !== undefined) jsonOut.packageType = registry.packageType;
    if (registry.lastScannedAt !== undefined) jsonOut.lastScannedAt = registry.lastScannedAt;
    if (registry.communityScans !== undefined) jsonOut.communityScans = registry.communityScans;
    if (registry.cveCount !== undefined) jsonOut.cveCount = registry.cveCount;
  }
  if (analystFindings && analystFindings.length) jsonOut.analystFindings = analystFindings;
  return jsonOut;
}

/**
 * Translate a raw npm downloader error message into a renderNotFoundBlock
 * hint. F3 equivalent for hackmyagent — `anthropic/code-review` slipping
 * past the GitHub classifier (rare but possible when the upstream look-up
 * misclassifies) and failing with `code 128` from npm pack's git fallback.
 * Returns hint + suggestions; caller passes them into renderNotFoundBlock.
 */
export function translateNpmPackError(
  name: string,
  message: string,
): { errorHint?: string; suggestions?: string[] } | undefined {
  const looksGitStyle = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(name) && !name.startsWith('@');
  if (looksGitStyle && /code\s*128/i.test(message)) {
    const scoped = `@${name}`;
    return {
      errorHint: `Looks like a git-style name. npm packages use "@scope/name" — did you mean "${scoped}"?`,
      suggestions: [scoped],
    };
  }
  return undefined;
}

/**
 * Observations + Verdict block for HMA scan output.
 *
 * Sits between the score meter and Findings / Next Steps. Shows the user
 * WHAT was scanned, HOW MANY checks ran, WHICH risk categories were
 * verified, and a plain-English verdict — so `100/100` never stands
 * alone as a dead-end opaque signal.
 *
 * Inlined here per [CA-030] escalation path (brief:
 * briefs/cli-observation-verdict-ux.md). Target home is
 * `@opena2a/cli-ui` for reuse across ai-trust + opena2a-cli; extraction
 * is tracked as a follow-up when cli-ui tag-test (CLI Consolidation
 * step 0d) is green.
 */

import type { SecurityFinding } from '../hardening/security-check.js';

export type VerdictStatus = 'safe' | 'needs-fix' | 'unsafe' | 'unknown';

export interface SurfaceSummary {
  /** projectType or package kind, e.g. "library", "mcp-server", "skill". */
  kind: string;
  /** Human-readable file count or artifact count. */
  filesScanned?: number;
  /** Compiled semantic artifacts (NanoMind AST). */
  artifactsCompiled?: number;
  /** Named artifacts detected, e.g. "MCP config", "SOUL.md". */
  detected?: string[];
}

/** Per-artifact summary displayed in the Artifacts block.
 *  Shape matches the one produced by the NanoMind scanner-bridge
 *  `ArtifactSummary` — kept structurally compatible but defined here
 *  so observations.ts has no import dependency on nanomind-core. */
export interface ArtifactLine {
  path: string;
  type: string;
  intent: 'benign' | 'suspicious' | 'malicious' | 'unknown';
  capabilityLabels: string[];
  constraintCount: number;
  weakConstraintCount: number;
}

export interface ChecksSummary {
  /** Total static checks executed. */
  staticCount: number;
  /** Total NanoMind semantic checks executed. */
  semanticCount: number;
  /** Check categories deliberately skipped, e.g. `{category: 'ARP', reason: 'requires --deep'}`. */
  skipped?: Array<{ category: string; reason: string }>;
}

export interface CategorySummary {
  /** Top-level category name (credentials, MCP, governance, ...). */
  name: string;
  /** Severity counts if findings fired in this category. */
  counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  /** True when zero findings fired on this category. */
  clear: boolean;
}

export interface ObservationsInput {
  surfaces: SurfaceSummary;
  checks: ChecksSummary;
  categories: CategorySummary[];
  verdict: { status: VerdictStatus; message: string };
  /** Per-artifact summaries from NanoMind AST compiler. Empty array and
   *  the Artifacts block is skipped — scans without agent artifacts
   *  don't need a dedicated "what did we compile" block. */
  artifacts?: ArtifactLine[];
  verbose?: boolean;
  /** Terminal width for wrapping (default 65). */
  width?: number;
}

export interface RenderedLine {
  text: string;
  /** Visual priority — higher = more prominent. Used by CLI to pick color. */
  tone: 'default' | 'good' | 'warning' | 'critical' | 'dim';
}

/**
 * Group findings by top-level category bucket.
 *
 * HMA has 35+ check-ID prefixes (CRED, MCP, CLAUDE, NET, PROMPT, INJ, ...).
 * The Observations block groups them into user-facing categories so the
 * line "credentials (1 critical) · MCP (2 high) · rest clear" is
 * readable without the user knowing HMA's internal check-ID schema.
 */
const CATEGORY_MAP: Array<{ label: string; prefixes: string[]; keywords?: string[] }> = [
  { label: 'credentials', prefixes: ['CRED', 'AST-CRED', 'WEBCRED', 'SEM-CRED', 'AGENT-CRED', 'ENVLEAK', 'CLIPASS'], keywords: ['credential', 'api key', 'token', 'password', 'secret'] },
  { label: 'MCP', prefixes: ['MCP', 'AST-MCP', 'SEM-MCP'], keywords: ['mcp'] },
  { label: 'network', prefixes: ['NET', 'GATEWAY', 'WEBEXPOSE'] },
  { label: 'injection', prefixes: ['INJ', 'IO', 'CODEINJ', 'DOCKERINJ'] },
  { label: 'prompt', prefixes: ['PROMPT', 'AST-PROMPT', 'SEM-INST'] },
  { label: 'encryption', prefixes: ['ENCRYPT'] },
  { label: 'session', prefixes: ['SESSION'] },
  { label: 'sandbox', prefixes: ['SANDBOX', 'PROC', 'PERM', 'SEM-PERM', 'TMPPATH', 'TOCTOU', 'AST-CODE'] },
  { label: 'capabilities', prefixes: ['AST-CAP', 'AST-SCOPE'] },
  { label: 'supply-chain', prefixes: ['SUPPLY', 'DEP', 'INSTALL', 'INTEGRITY'] },
  { label: 'governance', prefixes: ['AST-GOV', 'AST-GOVERN', 'SOUL', 'GOV', 'SOUL-OVERRIDE'] },
  { label: 'skill', prefixes: ['SKILL', 'SKILL-MEM'] },
  { label: 'unicode-stego', prefixes: ['UNICODE-STEGO', 'STEGO'] },
  { label: 'memory', prefixes: ['MEM', 'RAG'] },
  { label: 'identity', prefixes: ['AIM', 'AST-AIM', 'DNA'] },
  { label: 'sandbox-escape', prefixes: ['NEMO'] },
  { label: 'CVE', prefixes: ['CVE'] },
  { label: 'A2A', prefixes: ['A2A'] },
  { label: 'lifecycle', prefixes: ['LIFECYCLE'] },
  { label: 'LLM risk', prefixes: ['LLM'] },
  { label: 'heartbeat', prefixes: ['HEARTBEAT', 'AST-HEARTBEAT'] },
  { label: 'config', prefixes: ['CONFIG', 'ENV', 'VSCODE', 'CURSOR', 'CLAUDE', 'SEC'] },
  { label: 'audit', prefixes: ['AUDIT', 'LOG', 'RATE', 'SCAN', 'CHK', 'CHK-FAIL'] },
  { label: 'auth', prefixes: ['AUTH', 'TOOL', 'API', 'AITOOL'] },
  { label: 'git hygiene', prefixes: ['GIT'] },
];

/** All top-level category labels, ordered. Used to render "all clear" lists. */
export const ALL_CATEGORY_LABELS = CATEGORY_MAP.map(c => c.label);

/**
 * Classify a single finding into its top-level category label.
 * Returns null if nothing matches — caller decides whether to bucket
 * as "Other" or drop.
 */
export function classifyCategory(finding: SecurityFinding): string | null {
  const checkId = (finding.checkId || '').toUpperCase();
  const name = (finding.name || '').toLowerCase();
  const categoryField = (finding.category || '').toLowerCase();

  for (const bucket of CATEGORY_MAP) {
    for (const prefix of bucket.prefixes) {
      if (checkId.startsWith(prefix + '-') || checkId === prefix) return bucket.label;
    }
    if (bucket.keywords) {
      for (const kw of bucket.keywords) {
        if (name.includes(kw) || categoryField.includes(kw)) return bucket.label;
      }
    }
  }
  return null;
}

/**
 * Build a CategorySummary[] from raw findings. Unmatched findings go
 * into an "other" bucket; categories with zero findings are marked
 * `clear: true` so the renderer can list them under "rest clear".
 */
export function buildCategorySummaries(findings: SecurityFinding[]): CategorySummary[] {
  const byLabel = new Map<string, CategorySummary>();
  for (const label of ALL_CATEGORY_LABELS) {
    byLabel.set(label, { name: label, counts: { critical: 0, high: 0, medium: 0, low: 0 }, clear: true });
  }

  for (const f of findings) {
    if (f.passed) continue;
    const label = classifyCategory(f) ?? 'other';
    if (!byLabel.has(label)) {
      byLabel.set(label, { name: label, counts: { critical: 0, high: 0, medium: 0, low: 0 }, clear: true });
    }
    const bucket = byLabel.get(label)!;
    bucket.clear = false;
    const sev = f.severity as 'critical' | 'high' | 'medium' | 'low';
    if (sev in bucket.counts) bucket.counts[sev]++;
  }

  return Array.from(byLabel.values());
}

/** Minimal finding shape the verdict builder consumes — a subset of SecurityFinding
 *  so callers don't have to pass the whole object. Must include the fields
 *  buildVerdict uses to name the lead finding. */
export interface VerdictFinding {
  severity: 'critical' | 'high' | 'medium' | 'low';
  name?: string;
  checkId?: string;
  file?: string;
  line?: number;
}

/**
 * Build a plain-English verdict from the actual failed findings.
 *
 * Old version counted severities and produced grammar like "1 low finding to
 * address" — which told the reader nothing they couldn't count themselves.
 * This version names the lead finding (worst severity, first by check-ID)
 * so the Verdict line is action-oriented: the user learns WHAT to fix, not
 * just HOW MANY exist.
 *
 * Never uses letter grades. Anchors to an action per CISO philosophy rule
 * #10 (feedback_cli_ciso_philosophy.md).
 */
export function buildVerdict(
  severity: { critical: number; high: number; medium: number; low: number },
  surface: SurfaceSummary,
  findings?: VerdictFinding[],
): { status: VerdictStatus; message: string } {
  const { critical, high, medium, low } = severity;
  const total = critical + high + medium + low;

  if (total === 0) {
    const surfaceLabel = surface.kind && surface.kind !== 'unknown' ? surface.kind : 'project';
    return {
      status: 'safe',
      message: `No security issues detected. This ${surfaceLabel} looks safe to use.`,
    };
  }

  // Pick the leading finding to name in the verdict: worst severity first.
  // If multiple findings at the top severity, the verdict describes the first
  // one (stable ordering from the scanner) and says "+ N more" for the rest.
  const leadSeverity: VerdictFinding['severity'] | null =
    critical > 0 ? 'critical' : high > 0 ? 'high' : medium > 0 ? 'medium' : low > 0 ? 'low' : null;

  const leaders = (findings ?? []).filter(f => f.severity === leadSeverity);
  const lead = leaders[0];

  /** Format a finding as "NAME in file:line" — falls back to checkId or name. */
  const formatLead = (f: VerdictFinding): string => {
    const label = f.name?.trim() || f.checkId?.trim() || 'finding';
    if (f.file) {
      const loc = f.line ? `${f.file}:${f.line}` : f.file;
      return `${label} in ${loc}`;
    }
    return label;
  };

  const extraCount = Math.max(0, total - 1);
  const extraSuffix = extraCount > 0 ? ` + ${extraCount} more` : '';

  if (critical > 0) {
    const leadText = lead ? formatLead(lead) : `${critical} critical issue${critical > 1 ? 's' : ''}`;
    return {
      status: 'unsafe',
      message: `Not safe to ship. ${leadText}${extraSuffix}. Fix before using in production.`,
    };
  }
  if (high > 0) {
    const leadText = lead ? formatLead(lead) : `${high} high-severity issue${high > 1 ? 's' : ''}`;
    return {
      status: 'unsafe',
      message: `Not safe as-is. ${leadText}${extraSuffix}. Fix, then rescan.`,
    };
  }
  // medium or low only
  const leadText = lead ? formatLead(lead) : `${total} finding${total > 1 ? 's' : ''}`;
  return {
    status: 'needs-fix',
    message: `Usable with caveats. ${leadText}${extraSuffix}. Run \`secure --fix\` to auto-remediate where possible.`,
  };
}

/**
 * Format the Categories line — names the buckets that fired, then
 * collapses the remaining clear buckets into a "rest clear" tail.
 */
function formatCategoriesLine(categories: CategorySummary[], verbose: boolean): string {
  const withFindings = categories.filter(c => !c.clear);
  const clearCount = categories.length - withFindings.length;

  if (withFindings.length === 0) {
    // Zero-findings case: list first N categories, collapse the rest.
    const allClear = categories.filter(c => c.clear);
    if (verbose) {
      return allClear.map(c => c.name).join(', ') + '  (all clear)';
    }
    const shown = allClear.slice(0, 9).map(c => c.name).join(', ');
    const extra = allClear.length > 9 ? ` + ${allClear.length - 9} more` : '';
    return `${shown}${extra}  (all clear)`;
  }

  const withPrefix = withFindings.map(c => {
    const { critical, high, medium, low } = c.counts;
    if (critical > 0) return `${c.name} (${critical} critical)`;
    if (high > 0) return `${c.name} (${high} high)`;
    if (medium > 0) return `${c.name} (${medium} medium)`;
    if (low > 0) return `${c.name} (${low} low)`;
    return c.name;
  });
  const tail = clearCount > 0 ? ` · ${clearCount} others clear` : '';
  return `${withPrefix.join(' · ')}${tail}`;
}

/**
 * Format the Checks line. `static · semantic · skipped` — skipped
 * only shows when non-empty. Zero skipped is a positive signal we
 * express by showing `0 skipped`.
 */
function formatChecksLine(checks: ChecksSummary): string {
  const parts = [
    `${checks.staticCount} static`,
    `${checks.semanticCount} semantic (NanoMind AST)`,
  ];
  if (!checks.skipped || checks.skipped.length === 0) {
    parts.push('0 skipped');
  } else {
    const skippedDetail = checks.skipped.map(s => `${s.category} — ${s.reason}`).join('; ');
    parts.push(`${checks.skipped.length} skipped (${skippedDetail})`);
  }
  return parts.join(' · ');
}

/**
 * Format one artifact as a single compact line.
 *
 * Shape: `<path>  <type> · <intent> · <capabilities>  [<constraints>]`
 *
 * Example:
 *   `deploy.skill.md  skill · benign · cron + fs-write + net-egress  (2 constraints, 1 weak)`
 *   `mcp.json         mcp_config · suspicious · shell-exec + fs-write`
 */
function formatArtifactLine(a: ArtifactLine): string {
  const capText = a.capabilityLabels.length > 0
    ? a.capabilityLabels.join(' + ')
    : 'no inferred capabilities';
  const parts = [a.type, a.intent, capText];
  const head = `${a.path}  ${parts.join(' · ')}`;

  if (a.constraintCount > 0) {
    const weakSuffix = a.weakConstraintCount > 0 ? `, ${a.weakConstraintCount} weak` : '';
    return `${head}  (${a.constraintCount} constraint${a.constraintCount === 1 ? '' : 's'}${weakSuffix})`;
  }
  if (a.type === 'skill' || a.type === 'mcp_config' || a.type === 'a2a_card' || a.type === 'agent_config') {
    // Agent artifacts without any declared constraints — this is itself a signal worth flagging
    return `${head}  (no declared constraints)`;
  }
  return head;
}

/**
 * Select + format artifact lines for the Observations block.
 * Defaults to up to 6 lines; verbose mode shows all. Ordering: risky
 * first (malicious > suspicious > benign), then by capability count
 * (more capabilities = more surface = more worth naming first).
 */
function formatArtifactsBlock(artifacts: ArtifactLine[], verbose: boolean): string[] {
  const intentRank: Record<ArtifactLine['intent'], number> = {
    malicious: 0, suspicious: 1, benign: 2, unknown: 3,
  };
  const sorted = [...artifacts].sort((a, b) => {
    const r = intentRank[a.intent] - intentRank[b.intent];
    if (r !== 0) return r;
    return b.capabilityLabels.length - a.capabilityLabels.length;
  });
  const cap = verbose ? Infinity : 6;
  const shown = sorted.slice(0, cap).map(formatArtifactLine);
  const extra = sorted.length - shown.length;
  if (extra > 0) {
    shown.push(`+ ${extra} more (run with --verbose to see all)`);
  }
  return shown;
}

/**
 * Format the Surfaces line. Always names the project kind; adds file
 * count + detected artifacts when present.
 */
function formatSurfacesLine(surface: SurfaceSummary): string {
  const parts: string[] = [surface.kind || 'unknown'];
  if (typeof surface.filesScanned === 'number') {
    parts.push(`${surface.filesScanned} file${surface.filesScanned === 1 ? '' : 's'}`);
  }
  if (typeof surface.artifactsCompiled === 'number' && surface.artifactsCompiled > 0) {
    parts.push(`${surface.artifactsCompiled} semantic artifact${surface.artifactsCompiled === 1 ? '' : 's'}`);
  }
  if (surface.detected && surface.detected.length > 0) {
    parts.push(surface.detected.join(', '));
  }
  return parts.join(' · ');
}

/**
 * Render the full Observations block as an array of lines (no ANSI yet).
 * The CLI caller wraps with colors + indentation.
 *
 * Returns `{ label, value }` tuples so the caller can align labels
 * consistently with the rest of the unified-check layout.
 */
export interface RenderedObservations {
  lines: Array<{ label: string; value: string; tone: 'default' | 'good' | 'warning' | 'critical' }>;
  /** Multi-line Artifacts block. Each entry is rendered on its own line
   *  (first entry gets the "Artifacts" label, rest are continuations).
   *  Empty when no agent artifacts were compiled. */
  artifactLines: string[];
  verdict: { status: VerdictStatus; message: string };
}

export function renderObservationsBlock(input: ObservationsInput): RenderedObservations {
  const { surfaces, checks, categories, verdict, artifacts, verbose } = input;

  const lines: RenderedObservations['lines'] = [
    { label: 'Surfaces', value: formatSurfacesLine(surfaces), tone: 'default' },
    { label: 'Checks', value: formatChecksLine(checks), tone: 'default' },
    {
      label: 'Categories',
      value: formatCategoriesLine(categories, !!verbose),
      tone: categories.some(c => !c.clear) ? 'warning' : 'good',
    },
    {
      label: 'Verdict',
      value: verdict.message,
      tone:
        verdict.status === 'unsafe' ? 'critical' :
        verdict.status === 'needs-fix' ? 'warning' :
        verdict.status === 'safe' ? 'good' : 'default',
    },
  ];

  const artifactLines = artifacts && artifacts.length > 0
    ? formatArtifactsBlock(artifacts, !!verbose)
    : [];

  return { lines, artifactLines, verdict };
}

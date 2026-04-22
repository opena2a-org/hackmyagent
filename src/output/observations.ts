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
  { label: 'credentials', prefixes: ['CRED', 'AST-CRED', 'WEBCRED', 'SEM-CRED'], keywords: ['credential', 'api key', 'token', 'password', 'secret'] },
  { label: 'MCP', prefixes: ['MCP', 'AST-MCP', 'SEM-MCP'], keywords: ['mcp'] },
  { label: 'network', prefixes: ['NET', 'GATEWAY'] },
  { label: 'injection', prefixes: ['INJ', 'IO'] },
  { label: 'prompt', prefixes: ['PROMPT', 'AST-PROMPT', 'SEM-INST'] },
  { label: 'encryption', prefixes: ['ENCRYPT'] },
  { label: 'session', prefixes: ['SESSION'] },
  { label: 'sandbox', prefixes: ['SANDBOX', 'PROC', 'PERM', 'SEM-PERM'] },
  { label: 'capabilities', prefixes: ['AST-CAP', 'AST-SCOPE'] },
  { label: 'supply-chain', prefixes: ['SUPPLY', 'DEP'] },
  { label: 'governance', prefixes: ['AST-GOV', 'AST-GOVERN', 'SOUL', 'GOV'] },
  { label: 'skill', prefixes: ['SKILL'] },
  { label: 'unicode-stego', prefixes: ['UNICODE-STEGO', 'STEGO'] },
  { label: 'memory', prefixes: ['MEM', 'RAG'] },
  { label: 'identity', prefixes: ['AIM', 'AST-AIM'] },
  { label: 'sandbox-escape', prefixes: ['NEMO'] },
  { label: 'CVE', prefixes: ['CVE'] },
  { label: 'A2A', prefixes: ['A2A'] },
  { label: 'lifecycle', prefixes: ['LIFECYCLE'] },
  { label: 'LLM risk', prefixes: ['LLM'] },
  { label: 'heartbeat', prefixes: ['HEARTBEAT', 'AST-HEARTBEAT'] },
  { label: 'config', prefixes: ['CONFIG', 'ENV', 'VSCODE', 'CURSOR', 'CLAUDE'] },
  { label: 'audit', prefixes: ['AUDIT', 'LOG', 'RATE'] },
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

/**
 * Build a plain-English verdict from severity counts + surface context.
 *
 * Never uses letter grades. Anchors to an action ("Safe to use",
 * "Fix X and rescan", "Not safe to ship") per CISO philosophy rule #10
 * (feedback_cli_ciso_philosophy.md).
 */
export function buildVerdict(
  severity: { critical: number; high: number; medium: number; low: number },
  surface: SurfaceSummary,
): { status: VerdictStatus; message: string } {
  const { critical, high, medium, low } = severity;
  const total = critical + high + medium + low;

  if (critical > 0) {
    return {
      status: 'unsafe',
      message: `Not safe to ship. Fix ${critical} critical issue${critical > 1 ? 's' : ''} before using this in production.`,
    };
  }
  if (high > 0) {
    return {
      status: 'unsafe',
      message: `Not safe as-is. Fix ${high} high-severity issue${high > 1 ? 's' : ''}, then rescan.`,
    };
  }
  if (medium > 0 || low > 0) {
    const parts: string[] = [];
    if (medium > 0) parts.push(`${medium} medium`);
    if (low > 0) parts.push(`${low} low`);
    return {
      status: 'needs-fix',
      message: `Usable with caveats. ${parts.join(' + ')} finding${total > 1 ? 's' : ''} to address. Run \`secure --fix\` to auto-remediate where possible.`,
    };
  }
  const surfaceLabel = surface.kind && surface.kind !== 'unknown' ? surface.kind : 'project';
  return {
    status: 'safe',
    message: `No security issues detected. This ${surfaceLabel} looks safe to use.`,
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
  verdict: { status: VerdictStatus; message: string };
}

export function renderObservationsBlock(input: ObservationsInput): RenderedObservations {
  const { surfaces, checks, categories, verdict, verbose } = input;

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

  return { lines, verdict };
}

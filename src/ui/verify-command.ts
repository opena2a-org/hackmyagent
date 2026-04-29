/**
 * Verify-command generator (issue #141).
 *
 * Produces a shell command the user can run to confirm a finding's flagged
 * trigger exists at the cited location. Strictly data-driven: the line number
 * comes from the finding's structured evidence (v2 schema, #140) or the
 * legacy `line` field. If neither is present the generator returns
 * `undefined` and the renderer omits the Verify line entirely.
 *
 * Prior versions fell back to category-wide templates (e.g.
 * `grep -in "key|token|secret|password" <file>` for Credential findings).
 * Those templates routinely returned content unrelated to the actual trigger
 * — on `.clinerules:3` Credential Forwarding the regex returned 16 matches,
 * none of them line 3 — which trained users to dismiss real findings as
 * false positives. Templates are gone; "no Verify" is strictly better than
 * "wrong Verify".
 *
 * Standard: `~/.claude/instructions/cli-finding-ux-standard.md` § The bar,
 * item 3 (Verify command must verify the flagged trigger).
 */

import type { Evidence } from '../types/finding-evidence';

/** Minimal shape — generator only reads location data. */
export interface VerifyCommandInput {
  file?: string;
  line?: number;
  evidence?: Evidence;
}

/**
 * POSIX shell-escape a path for interpolation into a single-quoted command.
 * Returns undefined when the path contains characters that cannot be safely
 * rendered (control chars, newlines, null bytes) — the caller must skip
 * emitting the verify command rather than display a dangerous copy-paste.
 */
export function shellEscapePath(p: string): string | undefined {
  if (/[\x00-\x1f\x7f]/.test(p)) return undefined;
  return "'" + p.replace(/'/g, "'\\''") + "'";
}

/**
 * Extract the first cited line number from an Evidence record. Each evidence
 * shape exposes line numbers differently:
 *
 *   - positive : `lines[0].n`
 *   - absence  : `observed.lines[0].n`
 *   - mixed    : `positive.lines[0].n`
 *
 * Returns undefined when the evidence carries no line citations (e.g. an
 * absence finding whose observed-block is summary-only).
 */
export function firstLineFromEvidence(evidence: Evidence | undefined): number | undefined {
  if (!evidence) return undefined;
  if (evidence.kind === 'positive') {
    return evidence.lines[0]?.n;
  }
  if (evidence.kind === 'absence') {
    return evidence.observed.lines[0]?.n;
  }
  if (evidence.kind === 'mixed') {
    return evidence.positive.lines[0]?.n;
  }
  return undefined;
}

/**
 * Generate a "Verify:" shell command for a finding. Returns `undefined`
 * when no data-driven Verify is possible (no file, or no line from either
 * evidence or the legacy `line` field).
 *
 * Order of precedence for the line number:
 *   1. `evidence.lines[0].n` (or the equivalent for absence/mixed shapes)
 *   2. `f.line` (legacy field — still populated by many emit sites)
 *
 * No category templates. Findings whose detector throws away the line
 * number get no Verify command — the omission signals to the population
 * audit that the emit site needs `line` plumbed in.
 */
export function generateVerifyCommand(f: VerifyCommandInput): string | undefined {
  if (!f.file) return undefined;
  const quoted = shellEscapePath(f.file);
  if (!quoted) return undefined;

  const line = firstLineFromEvidence(f.evidence) ?? f.line;
  if (!line || !Number.isInteger(line) || line < 1) return undefined;

  return `sed -n '${line}p' ${quoted}`;
}

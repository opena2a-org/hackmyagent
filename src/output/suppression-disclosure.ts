/**
 * The suppression and scope disclosure, for the report FILES (#465).
 *
 * #450 made the score and the exit code honest under `--ignore` and
 * `.hmaignore`, and the terminal report names what was withheld. The file
 * writers (SARIF, HTML, ASFF) were never handed the two records, so they paired
 * a corrected score and exit code with an uncorrected findings list and nothing
 * reconciling the two: a code-scanning consumer got a failing build over one
 * LOW with no word of the suppressed CRITICAL behind it.
 *
 * The rows are the same identity-only records `secure --json` carries
 * (`summarizeSuppressed`): check id, name, category, severity, count and the
 * channel that asked. No file, message or evidence, so a disclosure of a
 * suppressed credential finding cannot become a copy of it.
 */
import type { ScanResult } from '../hardening/security-check';

export type DisclosureRow = NonNullable<ScanResult['suppressed']>[number];

export interface SuppressionDisclosure {
  /** `--ignore` / `.hmaignore` check-ID rules: not listed, still scored. */
  suppressed?: readonly DisclosureRow[];
  /** `.hmaignore` path rules: out of scope, not scored. */
  outOfScope?: readonly DisclosureRow[];
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function total(rows: readonly DisclosureRow[]): number {
  return rows.reduce((n, r) => n + r.count, 0);
}

function plural(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`;
}

function bySeverity(rows: readonly DisclosureRow[]): string {
  const counts = new Map<string, number>();
  for (const r of rows) counts.set(r.severity, (counts.get(r.severity) ?? 0) + r.count);
  return SEVERITY_ORDER.filter((s) => counts.has(s)).map((s) => `${counts.get(s)} ${s}`).join(', ');
}

/** True when either record has a row. */
export function hasDisclosure(d: SuppressionDisclosure): boolean {
  return (d.suppressed?.length ?? 0) > 0 || (d.outOfScope?.length ?? 0) > 0;
}

/**
 * The SARIF `run.properties` bag (SARIF 2.1.0 §3.8), or undefined when there is
 * nothing to disclose. `result.suppressions` is not usable here: a suppressed
 * finding is not in the findings list, only its identity row is, so there is
 * no result to attach it to.
 */
export function sarifRunProperties(d: SuppressionDisclosure): Record<string, DisclosureRow[]> | undefined {
  if (!hasDisclosure(d)) return undefined;
  return {
    ...(d.suppressed?.length ? { suppressed: [...d.suppressed] } : {}),
    ...(d.outOfScope?.length ? { outOfScope: [...d.outOfScope] } : {}),
  };
}

/**
 * One plain-text sentence per record, in the terminal report's wording. Used
 * by the HTML section and by the ASFF note, whose format has no document-level
 * slot to carry them.
 */
export function disclosureSentences(d: SuppressionDisclosure): string[] {
  const out: string[] = [];
  if (d.outOfScope?.length) {
    const sev = bySeverity(d.outOfScope);
    out.push(
      `${plural(total(d.outOfScope), 'finding')} excluded by .hmaignore path rules${sev ? ` (${sev})` : ''}. ` +
      'Out of scope, so not scored and not in the exit code; the score describes the tree minus those paths.',
    );
  }
  if (d.suppressed?.length) {
    const named = d.suppressed
      .map((r) => `${r.checkId} (${r.severity}${r.count > 1 ? ` x${r.count}` : ''})`)
      .join(', ');
    out.push(
      `${plural(total(d.suppressed), 'finding')} suppressed by the caller: ${named}. ` +
      'Withheld from this report at your request; still scored, still in the verdict, still in the exit code.',
    );
  }
  return out;
}

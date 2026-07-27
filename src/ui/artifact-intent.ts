/**
 * Reconciliation for the raw NanoMind intent label on the Observations
 * `Artifacts` line. Closes #252.
 *
 * The classifier (0.5.0, Mamba TME) over-flags benign and out-of-distribution
 * input at maximum confidence — a documented, terminal property of that model.
 * The established rule across HMA is that its raw verdict is never surfaced
 * standalone; the benign-context override and the analyst escalation path
 * exist precisely to keep it advisory. The Observations `Artifacts` line
 * bypassed that and printed the raw class verbatim, so a scan could render
 *
 *   Artifacts   SOUL.md  soul · malicious · no inferred capabilities
 *   Verdict     No issues in the semantic artifact matrix.
 *
 * with a 94-100/100 score three lines above — the same output contradicting
 * itself, and the same cross-analyzer direction-disagreement class as #200
 * and the 0.22.0 release blocker.
 *
 * The rule here is corroboration, not suppression: a concerning label
 * (`malicious` / `suspicious`) is printed only when this scan attributes at
 * least one HIGH or CRITICAL finding to that artifact. HIGH/CRITICAL is the
 * threshold HMA already treats as "this is real" — it drives the exit code
 * and it is the bar the oracle benign-FPR gate is written against. An
 * uncorroborated label renders as `unknown` ("this layer reached no verdict")
 * rather than `benign`, because asserting benign over evidence nothing
 * evaluated is the #200 mistake pointed the other way.
 *
 * `benign` and `unknown` pass through untouched. The model's failure mode is
 * over-flagging, so a negative prediction from it does not need corroborating,
 * and there is nothing alarming to reconcile.
 *
 * Trade-off, stated plainly: a genuinely malicious artifact that no static or
 * semantic check fires on now reads `unknown` on this line instead of
 * `malicious`. That is not lost detection — in that scan the Artifacts line
 * was the only surface claiming anything, while the score, the Categories
 * line and the Verdict all said clean. An unsupported scare-label next to a
 * 100/100 is noise a reader learns to discount, which is worse than silence.
 * `--verbose` still shows every raw affinity, and closing the static gaps is
 * tracked separately (#129).
 */

/** The intent vocabulary the cli-ui Artifacts renderer accepts. */
export type ArtifactIntent = 'benign' | 'suspicious' | 'malicious' | 'unknown';

/** Labels that assert something alarming and therefore need corroboration. */
const CONCERNING_INTENTS: ReadonlySet<ArtifactIntent> = new Set<ArtifactIntent>([
  'malicious',
  'suspicious',
]);

/** Severities that count as this scan corroborating a concerning label. */
const CORROBORATING_SEVERITIES: ReadonlySet<string> = new Set(['high', 'critical']);

/** A raw classifier label that was withheld from the default Artifacts line. */
export interface SuppressedIntent {
  /** Artifact path, as rendered on the Artifacts line. */
  path: string;
  /** The raw classifier label that was not corroborated. */
  rawIntent: ArtifactIntent;
}

/**
 * Normalize a path for comparison: strip a leading `./`, collapse Windows
 * separators. Deliberately does NOT resolve against the filesystem — this
 * runs on display strings, and both sides are produced relative to the same
 * scan root.
 */
function normalizePath(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\.\//, '');
}

/**
 * Whether `findingFile` refers to the same artifact as `artifactPath`.
 *
 * Findings from the semantic pipeline carry the scan-relative path, which
 * matches the artifact path exactly. A few static checks emit an absolute
 * path instead; those are matched on a full trailing path segment so
 * `/tmp/scan/SOUL.md` matches `SOUL.md` while `nested/SOUL.md` (a different
 * artifact, which would have its own summary line) does not match a relative
 * `SOUL.md`.
 */
function isSameArtifact(findingFile: string, artifactPath: string): boolean {
  const file = normalizePath(findingFile);
  const artifact = normalizePath(artifactPath);
  if (file === artifact) return true;
  return file.startsWith('/') && file.endsWith(`/${artifact}`);
}

export interface ReconcileResult<T> {
  /** Artifact summaries with uncorroborated concerning labels rewritten. */
  artifacts: T[];
  /** Raw labels withheld, for the `--verbose` disclosure. Empty when none. */
  suppressed: SuppressedIntent[];
}

/**
 * Rewrite uncorroborated concerning intent labels to `unknown` and report
 * what was withheld. Pure; returns copies and never mutates its input.
 */
export function reconcileArtifactIntents<T extends { path: string; intent: ArtifactIntent }>(
  artifacts: readonly T[],
  findings: readonly { file?: string; severity?: string }[],
): ReconcileResult<T> {
  const suppressed: SuppressedIntent[] = [];

  const corroboratingFiles = findings
    .filter(f => typeof f.file === 'string' && f.file.length > 0)
    .filter(f => CORROBORATING_SEVERITIES.has((f.severity ?? '').toLowerCase()))
    .map(f => f.file as string);

  const reconciled = artifacts.map(a => {
    if (!CONCERNING_INTENTS.has(a.intent)) return a;
    const corroborated = corroboratingFiles.some(file => isSameArtifact(file, a.path));
    if (corroborated) return a;
    suppressed.push({ path: a.path, rawIntent: a.intent });
    return { ...a, intent: 'unknown' as ArtifactIntent };
  });

  return { artifacts: reconciled, suppressed };
}

/**
 * The `--verbose` disclosure lines for withheld labels. Every line names the
 * model's failure mode inline, so the raw class can never be read as a
 * verdict even when it is shown. Returns an empty array when nothing was
 * withheld, so callers can print unconditionally.
 */
export function rawIntentDisclosureLines(suppressed: readonly SuppressedIntent[]): string[] {
  if (suppressed.length === 0) return [];
  return [
    'raw NanoMind classifier affinity (over-flags benign input — advisory, not a verdict):',
    ...suppressed.map(s => `  ${s.path} -> ${s.rawIntent}, not corroborated by any high/critical finding`),
  ];
}

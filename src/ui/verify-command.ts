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

import { isAbsolute, join } from 'node:path';

import type { Evidence } from '../types/finding-evidence';
import { citationPath } from './shell-quote';

/**
 * One definition, kept where the pure line-derivation logic lives so the two
 * adapter boundaries can use it without importing this module (which reaches
 * the filesystem). Re-exported here because this is the module the rest of the
 * tree — and `__tests__/ui/verify-command.test.ts` — already imports it from.
 */
import { firstLineFromEvidence } from '../types/finding-location';
export { firstLineFromEvidence };

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

/** True for a usable 1-based line number. */
function isUsableLine(line: number | undefined): line is number {
  return line !== undefined && Number.isInteger(line) && line >= 1;
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
 *
 * `scanRoot` (#286) is the directory the finding's `file` is relative to.
 * `f.file` is TARGET-relative, so without the root the emitted command only
 * runs when the reader's shell happens to sit at the scan target: scanning an
 * absolute path from `$HOME` produced 68 unique `sed` commands of which 0 ran.
 * When `scanRoot` is supplied the path is joined and rendered through
 * `citationPath`, which — unlike `shellEscapePath`, which predates it — also
 * makes a leading `-` an operand.
 *
 * THE HAZARD TEST APPLIES TO THE FINDING'S OWN PATH, NOT TO THE ROOT WE JOIN
 * ONTO IT. `citationPath` refuses a path carrying a `\p{Cf}` or similar
 * invisible character, because such a path renders as something other than the
 * bytes a command would act on. That refusal is about ATTACKER-CONTROLLED
 * names: `f.file` comes out of the scanned tree. The scan root is the operator's
 * own argument, already printed in the report header — and testing the JOINED
 * path let one invisible character anywhere in it suppress the `Verify:` for
 * EVERY finding in the report. Measured on a directory named `zwj-<ZWJ>-proj`:
 * three `Verify: sed` lines before, zero after, while `SKILL.md:13` still
 * printed — the line was known and the file nameable, and the reader was given
 * no command anyway. Score and finding count were byte-identical, which is why
 * a regression check comparing findings and scores could not see it.
 *
 * So a root that cannot be named falls back to the TARGET-RELATIVE citation
 * rather than to nothing. That is exactly what this function emitted before the
 * root existed, and what it still emits for callers that pass no root, so the
 * fallback cannot be worse than the previous behaviour. The finding's own path
 * keeps the stronger `citationPath` test on both branches.
 *
 * NO LINE, NO VERIFY — ON EVERY PATH, WITH OR WITHOUT A ROOT. An earlier
 * revision of the #286 fix degraded the rootful path to `cat <path>` on the
 * theory that a weaker citation beats a silent omission. It does not. Measured
 * on `test/hma`, that branch rendered
 *
 *     CRITICAL  .env Not Ignored
 *     Verify: cat <target>/.env
 *     CRITICAL  Private Key Files
 *     Verify: cat <target>/.opena2a/credvault/store.key
 *     (the vault key `fix-all` wrote in-tree at the time — #431; it writes none now)
 *
 * — a security scanner instructing the reader to print an entire secret file to
 * a terminal, on findings whose flagged trigger (`.env` is not listed in
 * `.gitignore`; a `.key` file exists at this path) `cat` does not verify at all.
 * The whole reason `generateVerifyCommand` refuses category templates is that a
 * command which does not verify the trigger trains readers to dismiss real
 * findings; `cat` is that same defect plus a credential disclosure. The branch
 * is gone, along with the filesystem probe it needed and the two-root split that
 * existed only to answer "does this file exist" for it.
 */
export function generateVerifyCommand(
  f: VerifyCommandInput,
  scanRoot?: string,
): string | undefined {
  if (!f.file) return undefined;

  const line = firstLineFromEvidence(f.evidence) ?? f.line;
  if (!isUsableLine(line)) return undefined;

  if (scanRoot === undefined) {
    const quoted = shellEscapePath(f.file);
    if (!quoted) return undefined;
    return `sed -n '${line}p' ${quoted}`;
  }

  const shown = isAbsolute(f.file) ? f.file : join(scanRoot, f.file);
  // Rootful first; on a root that cannot be named, the target-relative form.
  // Both go through `citationPath`, so the finding's own path is held to the
  // same test either way — only the root is allowed to drop out.
  const quoted = citationPath(shown) ?? citationPath(f.file);
  if (!quoted) return undefined;

  return `sed -n '${line}p' ${quoted}`;
}

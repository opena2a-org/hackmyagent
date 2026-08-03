/**
 * The release-smoke checklist is the instrument that certifies every release.
 * If it names a path that does not exist in a clean clone, the step errors
 * BEFORE reaching its assertion and reads as a pass.
 *
 * That is not hypothetical. §2, §3, §5 and §6 all pointed at `test/hma/`, which
 * lives in the workspace playground (`~/workspace/opena2a-org/test/hma`) and has
 * never been a path in this repo. `secure` on a missing directory prints
 * `Error: Directory ... does not exist.` and exits **1** — the same exit code as
 * "findings were found" — so §6.1's "expect exit 1" passed vacuously for
 * multiple releases, and §5.6's telemetry payload check produced empty output
 * that was read as "no PII" rather than "no event fired".
 *
 * This gate asserts every repo-relative path the checklist tells an operator to
 * scan actually exists. It is deliberately scoped to the fixture class that
 * broke: paths the doc presents as in-repo scan targets.
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SMOKE_DOC = path.join(REPO_ROOT, 'docs', 'testing', 'release-smoke.md');

/**
 * Repo-relative scan targets the doc names. Matches `test/...` and
 * `golden/...` tokens inside inline code or command lines — the directories an
 * operator is told to point the CLI at. Absolute paths (`~/workspace/...`) and
 * shell variables (`"$BAD"`) are deliberately NOT matched: the first are
 * documented as workspace-level and out of a clean clone by design, and the
 * second are built by the checklist itself in §0.5.
 */
function extractRepoRelativeTargets(markdown: string): string[] {
  const found = new Set<string>();
  // `test/foo/bar` or `golden/x` — stop at whitespace, backtick, quote, comma,
  // or a trailing sentence period.
  const re = /(?<![\w/~$.-])((?:test|golden)\/[A-Za-z0-9._/-]*)/g;
  for (const m of markdown.matchAll(re)) {
    let p = m[1];
    p = p.replace(/[.,)]+$/, ''); // strip sentence punctuation
    p = p.replace(/\/+$/, ''); // normalise trailing slash
    if (p) found.add(p);
  }
  return [...found].sort();
}

describe('release-smoke checklist paths', () => {
  const doc = readFileSync(SMOKE_DOC, 'utf8');

  it('names at least one in-repo scan target (extractor is not vacuous)', () => {
    const targets = extractRepoRelativeTargets(doc);
    expect(targets.length).toBeGreaterThan(0);
  });

  it('every repo-relative path it names exists in a clean clone', () => {
    const targets = extractRepoRelativeTargets(doc);
    const missing = targets.filter((t) => !existsSync(path.join(REPO_ROOT, t)));
    expect(missing, `release-smoke.md names paths absent from this repo: ${missing.join(', ')}`).toEqual([]);
  });

  it('does not resurrect the workspace-only test/hma path as a repo-relative target', () => {
    // The absolute form (~/workspace/opena2a-org/test/hma) is legitimate and
    // documented; the bare repo-relative form is the defect.
    const bare = [...doc.matchAll(/(?<![\w/~$.-])test\/hma\b/g)];
    expect(bare.map((m) => m[0]), 'use the absolute workspace path or a §0.5 fixture').toEqual([]);
  });

  it('the §0.5 fixtures the later sections depend on are actually defined', () => {
    // Steps reference "$BAD" / "$CLEAN"; §0.5 must create both, or every step
    // using them silently scans the empty string (i.e. the cwd).
    expect(doc).toMatch(/BAD=\$\(mktemp -d\)/);
    expect(doc).toMatch(/CLEAN=\$\(mktemp -d\)/);
    // And it must fail loudly if the build did not land.
    expect(doc).toMatch(/FIXTURE BUILD FAILED/);
  });

  it('does not tell the operator to read an exit code through a pipe', () => {
    // `cmd | head; echo $?` reports head's status, not the CLI's — the
    // measurement artifact that made several steps unfalsifiable.
    const piped = [...doc.matchAll(/^[^\n]*\|[^\n]*;\s*echo "?exit/gm)];
    expect(piped.map((m) => m[0].trim())).toEqual([]);
  });
});

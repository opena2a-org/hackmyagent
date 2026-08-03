/**
 * #280 — `.hmaignore` suppression keyed on `f.file` alone.
 *
 * PERM-001's `file` is just `permissionIssues[0]`; the rest of the evidence
 * lives in `details.files`. So ignoring that one representative path deleted
 * the ENTIRE finding — including a still-world-readable `.env` — and RAISED
 * the score. Measured on a fixture with `.env` and `secrets.json` both 0644:
 * ignoring `secrets.json` moved 44 -> 49 with PERM-001 gone and `.env` still
 * `-rw-r--r--`.
 *
 * A suppression rule that improves the score while the hazard is untouched is
 * the same class of defect as a failed fix raising it: the number says safer,
 * the tree is not.
 *
 * The rule is now: suppress only when EVERY covered path is ignored; otherwise
 * keep the finding and re-point it onto a survivor.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, writeFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';

/** Two world-readable sensitive files, so PERM-001 is genuinely multi-file. */
async function fixture(ignoreBody?: string) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hma-280-'));
  await writeFile(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  await writeFile(path.join(dir, '.env'), `ANTHROPIC_API_KEY=sk-ant-api03-${'x'.repeat(40)}\n`);
  await chmod(path.join(dir, '.env'), 0o644);
  await writeFile(path.join(dir, 'secrets.json'), '{"a":1}\n');
  await chmod(path.join(dir, 'secrets.json'), 0o644);
  if (ignoreBody !== undefined) await writeFile(path.join(dir, '.hmaignore'), ignoreBody);
  return dir;
}

async function scan(ignoreBody?: string) {
  const dir = await fixture(ignoreBody);
  try {
    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    const perm = result.findings.find((f) => f.checkId === 'PERM-001' && !f.passed);
    return { score: result.score, perm };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

describe('#280 .hmaignore must not delete a multi-file finding', () => {
  it('baseline: PERM-001 covers both files', async () => {
    const { perm } = await scan();
    expect(perm, 'fixture did not produce PERM-001 — the test proves nothing').toBeDefined();
    const covered = [perm!.file, ...((perm!.details?.files as string[]) ?? [])];
    expect(covered).toContain('.env');
    expect(covered).toContain('secrets.json');
  });

  it('ignoring one covered path does NOT delete the finding', async () => {
    const { perm } = await scan('secrets.json\n');
    expect(
      perm,
      'PERM-001 vanished while .env was still world-readable'
    ).toBeDefined();
  });

  it('ignoring one covered path does NOT raise the score', async () => {
    const bare = await scan();
    const partial = await scan('secrets.json\n');
    // The whole defect in one assertion: suppressing a path the user does not
    // want reported must not make the project look safer.
    expect(partial.score).toBe(bare.score);
  });

  it('re-points the surviving finding onto a path that is not ignored', async () => {
    const { perm } = await scan('secrets.json\n');
    expect(perm!.file).toBe('.env');
    expect(perm!.details?.files).toEqual(['.env']);
  });

  it('never names an ignored path in the surviving finding', async () => {
    const { perm } = await scan('secrets.json\n');
    const named = [perm!.file, ...((perm!.details?.files as string[]) ?? [])];
    expect(named).not.toContain('secrets.json');
  });

  it('still suppresses when EVERY covered path is ignored', async () => {
    // The legitimate case must keep working, or the fix has just disabled
    // .hmaignore for multi-file findings.
    const { perm } = await scan('secrets.json\n.env\n');
    expect(perm).toBeUndefined();
  });

  it('suppressing everything scores better than suppressing nothing', async () => {
    const bare = await scan();
    const full = await scan('secrets.json\n.env\n');
    expect(full.score).toBeGreaterThan(bare.score);
  });
});

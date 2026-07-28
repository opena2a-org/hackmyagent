// Regression gate for the post-fix verification pass (HIGH-3).
//
// `scan({ autoFix: true })` re-scans the target and marks each attempted fix
// `fixVerified`. The verification keyed on `` `${checkId}:${file}` ``, but
// `file` is a lossy single-path stand-in for a finding that can cover many:
// `PERM-001` reports `permissionIssues[0]`, the head of a fixed-order array.
//
// So when a multi-file fix lands on the first file and fails on a later one,
// the head of the array SHIFTS between the scan and the re-scan:
//
//   scan      permissionIssues = ['secrets.json', '.env']  -> file 'secrets.json'
//   re-scan   permissionIssues = ['.env']                  -> file '.env'
//
// The key `PERM-001:secrets.json` no longer matches `PERM-001:.env`, the
// still-failing file goes unseen, and the finding is stamped
// `fixVerified: true`. Observed on the pre-fix build: `.env` left
// world-readable, "Fix verification: 2/2 fixes confirmed", 98/100, exit 0,
// and PERM-001 absent from the findings block entirely.
//
// That matters beyond the one message. `countsAgainstScore` treats
// `fixed && fixVerified === false` as an outstanding issue, so the whole
// unverified-fix guard — the score, the verdict direction, the clamp — rests
// on this field telling the truth.
//
// The contract now: a finding is verified only when NONE of the files it
// covers still fail that check. Both sides compare on the union of `file` and
// `details.files`, so a shifting head cannot lose a still-failing path.

import { describe, it, expect, afterEach, vi } from 'vitest';
import { execSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, statSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// `chmod` is the only thing mocked, and only for the one path the test needs
// to fail. Everything else — `stat`, the re-scan's own reads — stays real, so
// the re-scan genuinely observes a still-world-readable file rather than a
// simulated one. Without this the case is unreachable on a normal filesystem:
// the owner can always chmod its own file. It is what an immutable flag, a
// read-only mount, or a restrictive MAC policy produces in the field.
const UNFIXABLE = '.env';

vi.mock('fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('fs/promises')>();
  return {
    ...actual,
    chmod: vi.fn(async (target: string, mode: number) => {
      if (String(target).endsWith(`/${UNFIXABLE}`)) {
        const err: NodeJS.ErrnoException = new Error(
          `EPERM: operation not permitted, chmod '${target}'`,
        );
        err.code = 'EPERM';
        throw err;
      }
      return actual.chmod(target, mode);
    }),
  };
});

const { HardeningScanner } = await import('../../src/hardening/scanner');

const dirs: string[] = [];

function fixture(files: Record<string, string>, opts: { git?: boolean } = {}): string {
  const dir = mkdtempSync(join(tmpdir(), 'hma-fixverify-'));
  dirs.push(dir);
  if (opts.git) execSync('git init -q .', { cwd: dir });
  writeFileSync(join(dir, 'package.json'), '{"name":"h","version":"1.0.0"}\n');
  for (const [name, body] of Object.entries(files)) {
    const p = join(dir, name);
    writeFileSync(p, body);
    chmodSync(p, 0o644); // world-readable — this is what PERM-001 fires on
  }
  return dir;
}

function isWorldReadable(p: string): boolean {
  return (statSync(p).mode & 0o004) !== 0;
}

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe('fix verification attribution (HIGH-3)', () => {
  it('does not confirm a multi-file fix that only partly landed', async () => {
    // Both are PERM-001 candidates. `secrets.json` sorts ahead of `.env` in
    // the check's fixed order, so it owns `file` on the first scan and `.env`
    // owns it on the re-scan — the shift the bug rides on.
    const dir = fixture({
      'secrets.json': '{"token":"x"}\n',
      '.env': 'DB_PASSWORD=x\n',
    });

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
    const perm = result.findings.find(f => f.checkId === 'PERM-001');

    // Guard the fixture before asserting on it: a PERM-001 that never fired,
    // or one that was never attempted, would make the real assertion vacuous.
    expect(perm, 'PERM-001 did not fire — fixture no longer triggers the check').toBeDefined();
    expect(perm!.fixed, 'PERM-001 was not attempted — nothing to verify').toBe(true);

    // And guard that this is genuinely PARTIAL. The single-file total-failure
    // case already reported correctly pre-fix and proves nothing here.
    // PERM-001 is the only check that chmods these, so `secrets.json` sitting
    // at 0600 is proof the check saw BOTH files and repaired exactly one.
    expect(isWorldReadable(join(dir, 'secrets.json')), 'the fixable file did not get fixed').toBe(false);
    expect(isWorldReadable(join(dir, UNFIXABLE)), 'the unfixable file was fixed after all').toBe(true);

    // The assertion. Pre-fix this is `true`.
    expect(perm!.fixVerified).toBe(false);
    expect(perm!.fixMessage ?? '').toContain('FIX NOT VERIFIED');
  });

  it('still counts a half-landed fix against the score and the verdict band', async () => {
    // The observable consequence, asserted on `scan()`'s own output rather
    // than on the predicate that produces it. PERM-001 is high severity, so a
    // surviving one is fail-direction and floors the composite out of green.
    const dir = fixture({
      'secrets.json': '{"token":"x"}\n',
      '.env': 'DB_PASSWORD=x\n',
    });

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    expect(result.score).toBeLessThan(70);
    expect(result.scoreClamped).toBe(true);
  });

  it('re-attributes a half-landed fix to the file that actually still fails', async () => {
    // MEDIUM-2. Once the finding survives into the report, its location has
    // to be true. `file` is `permissionIssues[0]` from the FIRST scan, so it
    // names 'secrets.json' — the file the fix repaired — while '.env', still
    // world-readable, appears nowhere as the location. The rendered finding
    // then points a reader at a file that is already 0600.
    //
    // The re-scan is the authority here: it is a real scan of the post-fix
    // tree, and its own PERM-001 finding already carries the correct file,
    // message and evidence list. Take them from it rather than re-deriving.
    const dir = fixture({
      'secrets.json': '{"token":"x"}\n',
      '.env': 'DB_PASSWORD=x\n',
    });

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
    const perm = result.findings.find(f => f.checkId === 'PERM-001')!;

    expect(perm.fixVerified, 'precondition: this must be the unverified case').toBe(false);

    expect(perm.file).toBe(UNFIXABLE);
    expect(perm.details?.files).toEqual([UNFIXABLE]);
    expect(perm.message).not.toContain('secrets.json');
    expect(perm.message).toContain(UNFIXABLE);
  });

  it('does not cite the auto-fix that just failed as the remedy', async () => {
    // MEDIUM-2, CISO Rule 11. `fix` is `hackmyagent secure --fix` — which is
    // the command that produced this finding. Following it runs the same
    // EPERM again. An unverified fix must cite a remedy that is not the
    // thing that failed.
    const dir = fixture({
      'secrets.json': '{"token":"x"}\n',
      '.env': 'DB_PASSWORD=x\n',
    });

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
    const perm = result.findings.find(f => f.checkId === 'PERM-001')!;

    expect(perm.fixVerified, 'precondition: this must be the unverified case').toBe(false);

    expect(perm.fix ?? '').not.toContain('secure --fix');
    expect(perm.fix ?? '').not.toContain('fix-all');
    // And it names the file that actually needs the manual change.
    expect(perm.fix).toBe(`chmod 600 ${UNFIXABLE}`);
  });

  it('does not confirm a fix whose survivor is hidden by .hmaignore', async () => {
    // The verification pass compares against the re-scan. `scan()` returns
    // findings that have ALREADY been through the report filter, which drops
    // paths matching `.hmaignore` — and it drops on `file`, the same
    // attribution that shifts. So one line in `.hmaignore` walked the
    // still-failing finding out of the list it was compared against, and the
    // union restored the exact defect it was written to remove:
    // `2/2 fixes confirmed`, 98/100, exit 0, `.env` still 0644.
    //
    // `.env` is the single most natural line to put in a `.hmaignore`, and
    // ignoring a path does not stop the fix pass writing to it — only
    // reporting on it. Comparison is now against the unfiltered findings.
    const dir = fixture({
      'secrets.json': '{"token":"x"}\n',
      '.env': 'DB_PASSWORD=x\n',
    });
    writeFileSync(join(dir, '.hmaignore'), '.env\n');

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
    const perm = result.findings.find(f => f.checkId === 'PERM-001');

    expect(perm, 'PERM-001 was filtered out entirely — it must still be reported').toBeDefined();
    expect(isWorldReadable(join(dir, UNFIXABLE)), 'fixture no longer models a failed fix').toBe(true);
    expect(perm!.fixVerified).toBe(false);

    // The ignored path must not become the finding's location either: the
    // report filter runs after re-attribution, so re-pointing onto it would
    // delete the finding outright — a false "verified" traded for a silent
    // disappearance. It keeps its own visible attribution instead.
    expect(perm!.file).toBe('secrets.json');
    expect(perm!.fix ?? '').not.toContain('secure --fix');
  });

  it('does not ship a manualFix naming files it already repaired', async () => {
    // `manualFix` is documented as the field to cite when the auto-fix did
    // not land, so a stale value is a wrong remedy under a trusted name. The
    // finding's own copy was built from the PRE-fix list and named
    // `secrets.json`, already at 0600, while `fix` correctly named `.env`.
    const dir = fixture({
      'secrets.json': '{"token":"x"}\n',
      '.env': 'DB_PASSWORD=x\n',
    });

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
    const perm = result.findings.find(f => f.checkId === 'PERM-001')!;

    expect(perm.fixVerified, 'precondition: this must be the unverified case').toBe(false);
    expect(perm.manualFix).toBe(`chmod 600 ${UNFIXABLE}`);
    expect(perm.manualFix).not.toContain('secrets.json');
    expect(perm.fix).toBe(perm.manualFix);
  });

  it('does not announce a fix-verification count the report will contradict', async () => {
    // The progress line read "Fix verification: 1/2 fixes confirmed" while
    // the CLI summary four lines below read "Attempted 1 fix, none
    // confirmed" — one run, two denominators, same reader.
    //
    // The scanner cannot count its way out of this: `cli.ts` re-filters
    // `result.findings` with `!f.passed` afterwards, which drops a
    // SUCCESSFULLY fixed finding that the scanner's own filter keeps. So the
    // progress channel must not carry counts at all.
    //
    // The fixture manufactures the divergence: a git repo makes GIT-001 fire
    // and auto-fix (leaving it `passed: true, fixed: true`), so more fixes
    // are attempted than the caller will show. Without that, any denominator
    // agrees with any other and the assertion proves nothing.
    const dir = fixture({ '.env': 'DB_PASSWORD=x\n' }, { git: true });

    const progress: string[] = [];
    const result = await new HardeningScanner().scan({
      targetDir: dir,
      autoFix: true,
      onProgress: (m: string) => progress.push(m),
    });

    const attempted = result.findings.filter(f => f.fixed);
    const shownByCli = attempted.filter(f => !f.passed);
    expect(
      attempted.length,
      'fixture no longer produces a fixed finding the CLI re-filter drops',
    ).toBeGreaterThan(shownByCli.length);

    const line = progress.find(m => m.toLowerCase().includes('verif'));
    expect(line, 'the verification progress line disappeared entirely').toBeDefined();
    expect(line).not.toMatch(/\d+\s*\/\s*\d+/);
  });

  it('confirms a fix that fully landed', async () => {
    // The other direction: tightening the comparison must not start calling
    // successful fixes unverified. No `.env` here, so nothing fails to chmod.
    const dir = fixture({ 'secrets.json': '{"token":"x"}\n' });

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
    const perm = result.findings.find(f => f.checkId === 'PERM-001');

    expect(perm, 'PERM-001 did not fire — fixture no longer triggers the check').toBeDefined();
    expect(perm!.fixed).toBe(true);
    expect(isWorldReadable(join(dir, 'secrets.json'))).toBe(false);
    expect(perm!.fixVerified).toBe(true);
  });
});

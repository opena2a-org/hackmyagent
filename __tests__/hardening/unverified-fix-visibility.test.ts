// Regression gate: an unverified fix must be VISIBLE, not just counted.
//
// Adversarial pass 4 (part 5) found #259 inverted. On a repo whose
// `.gitignore` misses hygiene patterns and which carries a committable
// `credentials.json`, `secure --fix` rendered:
//
//   Security  ━━━ 69/100  (score capped from 89 to 69 — verdict is fail-direction)
//   Categories  git hygiene (1 low) · 24 others clear
//   Verdict     Usable with caveats.
//   ── Findings ──
//     1 low
//
// The GIT-002 HIGH that caused the clamp appears NOWHERE in the findings
// block, the category summary, or the verdict. The score says fail-direction;
// every word beside it says the opposite.
//
// Mechanism. Thirteen checks report `passed: <check>Fixed` — they flip
// `passed` to true the moment they apply a fix. The verification pass then
// proves the fix did not land and sets `fixVerified: false`, but never resets
// `passed`. `countsAgainstScore` deliberately tests `fixVerified` BEFORE
// `passed`, so the score counts the finding and the clamp fires; every
// consumer that reads the raw `passed` field instead of the shared predicate
// drops it. `cli.ts` retains such findings on purpose one step earlier
// (`!f.fixed || f.fixVerified === false`) and then discards them again on
// `!f.passed`.
//
// This only ever worked for `PERM-001`, which keeps `passed: false` while
// fixing — the same "only PERM-001's shape was covered" trap the part-4
// review hit one layer down.
//
// Contract, and why it is fixed at this layer: `passed` means the check
// passed. The verification pass is the authority that learns it did not, so
// it clears the flag there rather than asking ~20 downstream consumers to
// remember a two-field rule. Score, verdict, findings list, category summary,
// telemetry, the ASP report and the machine formats then agree by
// construction.

import { describe, it, expect, afterEach, beforeAll } from 'vitest';
import { spawnSync, execFileSync } from 'node:child_process';
import { initThrowawayRepo } from '../helpers/throwaway-repo';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { countsAgainstScore } from '../../src/ui/verdict-band';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// #285 — this suite spawns the built CLI. Without this it would happily
// measure a binary older than `src/` and report a pass.
beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');

const dirs: string[] = [];

/**
 * A tree where the GIT-002 auto-fix genuinely SUCCEEDS at writing yet the
 * issue genuinely SURVIVES — the shape the whole unverified-fix guard exists
 * for, reached without mocking the filesystem.
 *
 * The fix appends `.env`, `secrets.json`, `*.pem`, `*.key` to `.gitignore`.
 * It never adds `credentials.json`, so `committableSensitiveFiles` still
 * reports that file on the re-scan: the write lands (`passed: git002Fixed`
 * becomes true), verification fails, `fixVerified` is false.
 */
function makeFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'hma-unverified-'));
  dirs.push(dir);
  initThrowawayRepo(dir, false);
  writeFileSync(join(dir, 'package.json'), '{"name":"repro","version":"1.0.0"}\n');
  writeFileSync(join(dir, '.gitignore'), 'node_modules/\n');
  writeFileSync(join(dir, 'credentials.json'), '{"apiKey":"placeholder"}\n');
  return dir;
}

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe('an unverified fix is visible to every consumer', { timeout: 240_000 }, () => {
  it('clears `passed` so the finding is not hidden from raw-field consumers', async () => {
    const dir = makeFixture();
    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    const all = result.allFindings ?? result.findings;
    const git002 = all.filter(f => f.checkId === 'GIT-002' && f.fixed);

    // Guard the fixture itself: if the scenario stops producing an
    // attempted-but-unverified fix the assertions below would pass
    // vacuously, which is the failure mode this suite has already shipped
    // once. Prove the precondition before asserting the contract.
    expect(git002.length).toBeGreaterThan(0);
    const finding = git002[0];
    expect(finding.fixed).toBe(true);
    expect(finding.fixVerified).toBe(false);

    // The contract. Pre-fix this is `true`, so every `!f.passed` consumer
    // — the findings block, the category summary, the verdict, telemetry,
    // the ASP report — silently drops a finding the score is counting.
    expect(finding.passed).toBe(false);

    // And the shared predicate still counts it, so the score and the
    // visibility can never be computed off different evidence.
    expect(countsAgainstScore(finding)).toBe(true);
  });

  it('a successfully verified fix keeps counting as resolved', async () => {
    // The inverse guard: clearing `passed` must not turn a fix that DID
    // land into a permanent outstanding issue. PERM-001 on a plain
    // world-readable file is repairable, so its fix verifies.
    const dir = makeFixture();
    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
    const all = result.allFindings ?? result.findings;

    for (const f of all.filter(x => x.fixed && x.fixVerified === true)) {
      expect(countsAgainstScore(f)).toBe(false);
    }
  });

  it('renders the clamping finding in the report instead of a bare capped number', () => {
    if (!existsSync(CLI)) return; // built-artifact gate, mirrors the sibling spawn suites
    const dir = makeFixture();

    const res = spawnSync('node', [CLI, 'secure', '.', '--fix'], {
      cwd: dir,
      encoding: 'utf8',
      timeout: 180_000,
      env: { ...process.env, NO_COLOR: '1' },
    });
    const out = `${res.stdout}${res.stderr}`;

    // Only meaningful when the clamp actually fired on this run.
    expect(out).toMatch(/verdict is fail-direction/);

    // The defect: a fail-direction cap beside a non-fail verdict.
    expect(out).not.toMatch(/Verdict\s+Usable with caveats/);

    // And the severity that caused the cap is actually reported. The
    // findings block prints a severity roll-up line; a clamped run must
    // show at least one high or critical there rather than only lows.
    const findingsBlock = out.split('── Findings')[1] ?? '';
    expect(findingsBlock).toMatch(/\b(high|critical)\b/i);
  });
});

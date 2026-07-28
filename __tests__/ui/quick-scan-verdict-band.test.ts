// Regression gate for the #259 clamp on the `check` quick-scan path.
//
// #259 was closed for `secure`: a fail-direction verdict floors the composite
// out of the green "good" band so the number cannot read "mostly fine" next to
// "Not safe". The CLI recalculates the composite at eight points after
// `scanner.scan()` returns and all eight route through `applyScore()` — but
// the quick scan (`check <dir>`, NanoMind semantic matrix only) never calls
// `scan()`. It computes its own composite inside `displayUnifiedCheck` and
// renders it through the same `>=70 = green` meter, so it kept the defect:
//
//   check ~/.opena2a/corpus/skill/buggy/caps-sprawl-skill
//     Quick scan  ━━━━━━━━━━━━━━━━━━━━ 85/100     <- green band
//     3 high-severity issues found                 <- fail direction
//     Verdict     Not safe as-is.
//
// Contract, identical to `secure`: the rendered number never sits in the good
// band when the headline is fail-direction, the cap explains itself naming the
// pre-clamp value, and detection is untouched.
//
// Unlike `secure`, this path emits no score in `--json` (the payload carries
// `critical` / `high` / `risk`, not a composite), so the assertions here read
// the rendered line. That is the surface the defect lives on.

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { GOOD_BAND_FLOOR, VERDICT_FAIL_CLAMP } from '../../src/ui/verdict-band';

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');
// A buggy skill: enough highs to be fail-direction, few enough findings that
// the composite still lands in the good band. That combination is exactly
// what the clamp exists for, and it is why this fixture and not the malicious
// one (which decays to 60 on its own) is the gate.
const FIXTURE = join(homedir(), '.opena2a', 'corpus', 'skill', 'buggy', 'caps-sprawl-skill');

function canRunSpawn(): boolean {
  // Gated on the private corpus fixture rather than on CI. No workflow
  // provisions the corpus today, so in practice this still runs only locally
  // — but the gate is now the real prerequisite, so it starts running the day
  // a job does provision it, rather than being skipped by an unrelated flag.
  return existsSync(CLI) && existsSync(FIXTURE);
}

function quickScan(): string {
  const res = spawnSync('node', [CLI, 'check', FIXTURE, '--ci'], {
    encoding: 'utf8',
    timeout: 180_000,
    env: { ...process.env, OPENA2A_CORPUS_DETERMINISTIC: '1', NO_COLOR: '1' },
  });
  return `${res.stdout || ''}${res.stderr || ''}`;
}

/** The rendered `Quick scan  ━━━ NN/100` value. */
function renderedScore(output: string): number {
  const m = output.match(/Quick scan\s+[^\d]*(\d+)\s*\/\s*100/);
    if (!m) throw new Error(`no quick-scan score line in output:\n${output.slice(0, 800)}`);
  return Number(m[1]);
}

describe('quick-scan verdict-band coherence (#259, check path)', () => {
  it.runIf(canRunSpawn())('never renders a good-band number under a fail-direction headline', () => {
    const out = quickScan();

    // ── Non-vacuity ────────────────────────────────────────────────────
    // Both guards must hold or the assertion below proves nothing. A
    // fixture that stopped being fail-direction, or whose raw composite
    // drifted under the band on its own, would let this test pass against
    // the very build it is meant to catch.
    expect(out, 'fixture is no longer fail-direction').toMatch(
      /\d+ (high-severity issues?|critical issues?) found/,
    );
    const rawMatch = out.match(/score capped from (\d+) to (\d+)/);
    expect(rawMatch, 'no clamp disclosure — the cap is silent or did not fire').not.toBeNull();
    expect(
      Number(rawMatch![1]),
      'raw composite no longer lands in the good band, so the clamp is untested',
    ).toBeGreaterThanOrEqual(GOOD_BAND_FLOOR);

    // ── The contract ───────────────────────────────────────────────────
    const score = renderedScore(out);
    expect(score).toBeLessThan(GOOD_BAND_FLOOR);
    expect(score).toBe(VERDICT_FAIL_CLAMP);
    // The disclosure names the number actually rendered, so the two can
    // never drift apart.
    expect(Number(rawMatch![2])).toBe(score);
  });

  it.runIf(canRunSpawn())('does not touch detection — findings and severities survive the clamp', () => {
    const out = quickScan();

    // The clamp is a scoring/display decision. If it starts suppressing
    // findings it has exceeded its remit, which is the failure mode the
    // #259 review flagged as "narrowed detection".
    expect(out).toMatch(/3 high/);
    expect(out).toMatch(/Jailbreak Susceptibility/);
    expect(out).toMatch(/Not safe as-is/);
  });

  it.runIf(canRunSpawn())('leaves a clean quick scan in the good band', () => {
    // The mirror case. Clamping a scan with no high/critical would be a
    // different dishonesty, and it is what a naive "always cap" fix does.
    const benign = join(homedir(), '.opena2a', 'corpus', 'skill', 'benign', 'clean-skill');
    if (!existsSync(benign)) return;
    const res = spawnSync('node', [CLI, 'check', benign, '--ci'], {
      encoding: 'utf8',
      timeout: 180_000,
      env: { ...process.env, OPENA2A_CORPUS_DETERMINISTIC: '1', NO_COLOR: '1' },
    });
    const out = `${res.stdout || ''}${res.stderr || ''}`;

    expect(out, 'benign fixture unexpectedly fail-direction').not.toMatch(
      /(high-severity issues?|critical issues?) found/,
    );
    expect(renderedScore(out)).toBeGreaterThanOrEqual(GOOD_BAND_FLOOR);
    expect(out).not.toMatch(/score capped from/);
  });
});

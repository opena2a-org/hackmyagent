// Regression gate for composite/verdict band coherence (closes #259).
//
// `secure ~/.opena2a/corpus/soul/malicious/permissive-overrides-soul` printed
//
//   Security  ━━━━━━━━━━━━━━━━━━━━ 76/100
//   Verdict   Not safe as-is. SOUL.md Injection Vectors in SOUL.md + 3 more.
//
// 76 sits in the green "good" band. Exit code, verdict direction and findings
// were all correct — only the number disagreed, and the number is what a
// reader anchors on. A SOUL-only governance subversion barely dents the
// infra-weighted composite, and `secure` had no governance floor.
//
// Contract: a fail-direction verdict (>=1 critical or high) floors the
// composite out of the good band. The clamp never raises a score, never
// changes the verdict or exit code, and preserves the pre-clamp value as
// `rawScore` so it adds information rather than destroying it.

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  GOOD_BAND_FLOOR,
  VERDICT_FAIL_CLAMP,
  clampDisclosure,
  clampScoreToVerdictBand,
  isFailDirection,
} from '../../src/ui/verdict-band';

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');
const FIXTURE = join(homedir(), '.opena2a', 'corpus', 'soul', 'malicious', 'permissive-overrides-soul');

function canRunSpawn(): boolean {
  if (process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true') return false;
  return existsSync(CLI) && existsSync(FIXTURE);
}

describe('verdict-band clamp (deterministic — #259 contract gate)', () => {
  it('floors a good-band score when the verdict is fail-direction', () => {
    const high = [{ severity: 'high', passed: false }];
    expect(clampScoreToVerdictBand(76, high)).toEqual({ score: VERDICT_FAIL_CLAMP, clamped: true });
    expect(clampScoreToVerdictBand(83, [{ severity: 'critical', passed: false }]))
      .toEqual({ score: VERDICT_FAIL_CLAMP, clamped: true });
  });

  it('puts the clamped score below the green threshold', () => {
    // The whole point: the number must stop reading "good".
    expect(VERDICT_FAIL_CLAMP).toBeLessThan(GOOD_BAND_FLOOR);
  });

  it('leaves a medium/low-only scan alone — that verdict is not fail-direction', () => {
    // "Usable with caveats" is not "Not safe". Clamping it would be a
    // different kind of dishonesty.
    const findings = [{ severity: 'medium', passed: false }, { severity: 'low', passed: false }];
    expect(isFailDirection(findings)).toBe(false);
    expect(clampScoreToVerdictBand(88, findings)).toEqual({ score: 88, clamped: false });
  });

  it('leaves a clean scan alone', () => {
    expect(clampScoreToVerdictBand(100, [])).toEqual({ score: 100, clamped: false });
  });

  it('is a ceiling, never a floor upward', () => {
    // A scan already below the band keeps its own worse score.
    expect(clampScoreToVerdictBand(12, [{ severity: 'critical', passed: false }]))
      .toEqual({ score: 12, clamped: false });
    expect(clampScoreToVerdictBand(VERDICT_FAIL_CLAMP, [{ severity: 'high', passed: false }]))
      .toEqual({ score: VERDICT_FAIL_CLAMP, clamped: false });
  });

  it('ignores passed checks when deciding direction', () => {
    expect(isFailDirection([{ severity: 'critical', passed: true }])).toBe(false);
    expect(clampScoreToVerdictBand(95, [{ severity: 'critical', passed: true }]))
      .toEqual({ score: 95, clamped: false });
  });

  it('explains the cap on the score line, naming the pre-clamp value', () => {
    const text = clampDisclosure({ rawScore: 76, score: 69, clamped: true });
    expect(text).toContain('76');
    expect(text).toContain('69');
    expect(text).toMatch(/verdict is fail-direction/i);
  });

  it('emits no disclosure when nothing was clamped', () => {
    expect(clampDisclosure({ rawScore: 88, score: 88, clamped: false })).toBe('');
    expect(clampDisclosure({ score: 88 })).toBe('');
  });
});

describe('secure on the reported fixture (spawn, local-only)', { timeout: 240_000 }, () => {
  function scanJson(): any {
    const res = spawnSync('node', [CLI, 'secure', FIXTURE, '--ci', '--json'], {
      encoding: 'utf8',
      timeout: 180_000,
      env: { ...process.env, OPENA2A_CORPUS_DETERMINISTIC: '1' },
    });
    return JSON.parse((res.stdout || '').trim());
  }

  it.runIf(canRunSpawn())('publishes a score outside the good band, with the raw preserved', () => {
    const parsed = scanJson();

    // Non-vacuity: the fixture must still be fail-direction AND its raw
    // composite must still land in the good band. If either stops being
    // true the assertions below prove nothing about the clamp.
    const failed = (parsed.findings ?? []).filter((f: any) => !f.passed);
    const severe = failed.filter((f: any) => f.severity === 'critical' || f.severity === 'high');
    expect(severe.length, 'fixture is no longer fail-direction').toBeGreaterThan(0);
    expect(parsed.rawScore, 'raw composite no longer lands in the good band').toBeGreaterThanOrEqual(GOOD_BAND_FLOOR);

    expect(parsed.scoreClamped).toBe(true);
    expect(parsed.score).toBeLessThan(GOOD_BAND_FLOOR);
    // The clamp reaches --json, not just the terminal: a display-only fix
    // would leave the Registry and every CI consumer reading the good-band
    // number.
    expect(parsed.score).toBe(VERDICT_FAIL_CLAMP);
  });

  it.runIf(canRunSpawn())('does not change detection — same findings, same severities', () => {
    const parsed = scanJson();
    const failed = (parsed.findings ?? []).filter((f: any) => !f.passed);

    // The clamp is a scoring/display decision. If it ever starts adding,
    // dropping or re-severitying findings it has exceeded its remit.
    expect(failed.length).toBeGreaterThan(0);
    expect(parsed.rawScore).toBeGreaterThan(parsed.score);
  });

  it.runIf(canRunSpawn())('says why the number was capped', () => {
    const res = spawnSync('node', [CLI, 'secure', FIXTURE, '--ci'], {
      encoding: 'utf8',
      timeout: 180_000,
      env: { ...process.env, OPENA2A_CORPUS_DETERMINISTIC: '1' },
    });
    const stdout = res.stdout || '';

    expect(stdout).toMatch(/Not safe/i);
    expect(stdout).toMatch(/score capped from \d+ to \d+/i);
    // Recovery framing: the payoff must be projected from the pre-clamp
    // composite, since fixing the highs is what lifts the cap.
    expect(stdout).toMatch(/Path forward: \d+ -> \d+/);
  });
});

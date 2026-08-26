/**
 * #464 #519 #283 — spawn-level: the `--json` document IS the settled record,
 * the exit code and the document agree, and an unmeasured run withholds
 * every outbound arm with one line saying so.
 *
 * Reference fixture: the corpus `repo/buggy/leaky-env-example` with an
 * `.hmaignore` suppressing its critical (`!CONFIG-004`) — the exact tree
 * whose suppression once moved the exit from 1 to 0 (#450) and whose
 * outbound records carried `passed` (#464). Measured on this build:
 * verdict fail, exitCode 1, counts {critical:1, high:0, medium:1, low:1}
 * (the suppressed critical COUNTED), score 69, coverage 8/8 files.
 *
 * RED-ON-BASE cells fail on the 3570f15 build; PIN cells pass on both.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { pickSettledOutcome, SETTLED_OUTCOME_KEYS } from '../../src/hardening/settled-outcome';

beforeAll(assertDistFreshIfPresent);

// The corpus is the PRIVATE shared fixture set (same idiom as
// soul-corpus-direction.test.ts): resolve it from the running user's home
// and SKIP the corpus-backed cells where it is absent (external CI) — the
// unread-input cells below build their own fixtures and always run.
const CORPUS = path.join(os.homedir(), '.opena2a', 'corpus', 'repo', 'buggy', 'leaky-env-example');
const corpusAvailable = fs.existsSync(CORPUS);
// validateRegistryUrl allows https and http://localhost only; port 9
// (discard) refuses the connection, so an ATTEMPT fails as a network error.
const DEAD_REGISTRY = 'http://localhost:9';

let leaky: string;
let unread: string;

beforeAll(() => {
  if (corpusAvailable) {
    // The corpus tree is the shared adversarial fixture set; copy, never touch.
    leaky = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-464-leaky-'));
    fs.cpSync(CORPUS, leaky, { recursive: true });
    fs.writeFileSync(path.join(leaky, '.hmaignore'), '!CONFIG-004\n');
  }

  unread = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-464-unread-'));
  fs.writeFileSync(path.join(unread, 'index.js'), 'module.exports = 1;\n');
  fs.writeFileSync(path.join(unread, 'locked.js'), 'const secret = 1;\n');
  fs.chmodSync(path.join(unread, 'locked.js'), 0o000);
});

afterAll(() => {
  try { fs.chmodSync(path.join(unread, 'locked.js'), 0o600); } catch { /* best effort */ }
  for (const d of [leaky, unread]) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
});

function run(dir: string, args: string[]) {
  const r = spawnSync(process.execPath, [CLI, 'secure', dir, '--no-machine-posture', ...args], {
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-')) },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

function json(stdout: string): any {
  return JSON.parse(stdout.slice(stdout.indexOf('{')));
}

describe('#464 the --json document IS the settled record', { timeout: 300_000 }, () => {
  it.skipIf(!corpusAvailable)('RED-ON-BASE: flat record keys ride the top level, the exit code and the document agree, and a suppressed critical is COUNTED', () => {
    const r = run(leaky, ['--format', 'json']);
    const j = json(r.stdout);
    expect(j.verdict).toBe('fail');
    expect(j.exitCode).toBe(1);
    expect(r.status).toBe(j.exitCode);
    expect(j.measured).toBe(true);
    expect(j.counts.critical).toBeGreaterThanOrEqual(1);
    expect((j.suppressed ?? []).map((s: any) => s.checkId)).toContain('CONFIG-004');
    expect(j.coverage).toMatchObject({ measured: true, unit: 'file' });
    expect(j.coverage.total).toBe(j.coverage.examined);
  });

  it.skipIf(!corpusAvailable)('RED-ON-BASE: pickSettledOutcome reconstructs a complete record from the document alone', () => {
    const j = json(run(leaky, ['--format', 'json']).stdout);
    const record = pickSettledOutcome(j);
    for (const key of ['score', 'verdict', 'exitCode', 'measured', 'counts', 'coverage'] as const) {
      expect(record[key as keyof typeof record], key).toBeDefined();
    }
    expect(Object.keys(record).every((k) => (SETTLED_OUTCOME_KEYS as readonly string[]).includes(k))).toBe(true);
    expect(record.score).toBe(j.score);
  });

  it('RED-ON-BASE: an exit-2 run CARRIES its warn/fail band — the unmeasured exit hides no verdict', () => {
    // Even this two-file tree carries counted advisories, so the band is
    // warn; the null verdict (exit 2 with nothing counted at all) is pinned
    // at the unit level, where the record can be built from an empty gate.
    const r = run(unread, ['--format', 'json']);
    const j = json(r.stdout);
    expect(r.status).toBe(2);
    expect(j.exitCode).toBe(2);
    expect(j.measured).toBe(false);
    expect(['warn', 'fail']).toContain(j.verdict);
    expect(j.coverage.total).toBeGreaterThan(j.coverage.examined);
  });
});

describe('#464 the exit precedence holds where the classes overlap', { timeout: 300_000 }, () => {
  it.skipIf(!corpusAvailable)('RED-ON-BASE: an unread input AND a counted critical exit 2 — the finding line RAISES, never assigns over the floor', () => {
    const overlap = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-464-overlap-'));
    try {
      fs.cpSync(CORPUS, overlap, { recursive: true });
      fs.writeFileSync(path.join(overlap, 'locked.js'), 'const secret = 1;\n');
      fs.chmodSync(path.join(overlap, 'locked.js'), 0o000);
      const r = run(overlap, ['--format', 'json']);
      const j = json(r.stdout);
      expect(j.exitCode).toBe(2);
      expect(j.verdict).toBe('fail');
      expect(r.status).toBe(2);
    } finally {
      try { fs.chmodSync(path.join(overlap, 'locked.js'), 0o600); } catch { /* best effort */ }
      try { fs.rmSync(overlap, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });
});

describe('#464 an unmeasured run withholds every outbound arm', { timeout: 300_000 }, () => {
  it('RED-ON-BASE: --no-contribute beats persisted consent in the withheld line — it never claims a contribution the user disabled', () => {
    // Consent ON in the config, disabled for this run by the flag: the line
    // must not list `contribution`. Without the flag (consent standing) it
    // must. This is what makes the two spellings distinguishable.
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-consent-'));
    fs.mkdirSync(path.join(home, '.opena2a'), { recursive: true });
    fs.writeFileSync(path.join(home, '.opena2a', 'config.json'), '{"contribute":{"enabled":true}}\n');
    const spawn = (args: string[]) => {
      const r = spawnSync(process.execPath, [CLI, 'secure', unread, '--no-machine-posture', ...args], {
        encoding: 'utf8', timeout: 240_000, maxBuffer: 64 * 1024 * 1024,
        env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home },
      });
      return { status: r.status, stderr: r.stderr ?? '' };
    };
    const disabled = spawn(['--no-contribute', '--publish', '--registry-url', DEAD_REGISTRY]);
    expect(disabled.status).toBe(2);
    expect(disabled.stderr).toContain('Withheld: --publish');
    expect(disabled.stderr).not.toContain('contribution');
    const standing = spawn(['--publish', '--registry-url', DEAD_REGISTRY]);
    expect(standing.stderr).toContain('Withheld: --publish, contribution');
  });

  it('RED-ON-BASE json: --publish is withheld with the one line, and the document discloses it', () => {
    const r = run(unread, ['--format', 'json', '--publish', '--registry-url', DEAD_REGISTRY]);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('Registry: nothing sent —');
    expect(r.stderr).toContain('Withheld: --publish');
    const j = json(r.stdout);
    expect(j.publish).toMatchObject({ success: false, attempted: false, reason: 'unmeasured' });
  });

  it('RED-ON-BASE text: the same withhold line prints on the text arm', () => {
    const r = run(unread, ['--publish', '--registry-url', DEAD_REGISTRY]);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('Registry: nothing sent —');
    expect(r.stderr).toContain('Withheld: --publish');
    expect(r.stderr).toContain('not read');
  });

  it('RED-ON-BASE: --ci-publish is withheld before its own precondition (no HMAC error on an unmeasured run)', () => {
    const r = run(unread, ['--ci-publish', '--registry-url', DEAD_REGISTRY]);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('Withheld: --ci-publish');
    expect(r.stderr).not.toContain('CI_SCAN_HMAC_SECRET');
  });

  it.skipIf(!corpusAvailable)('PIN: a measured run still ATTEMPTS the publish (the withhold is exit-2 only)', () => {
    const r = run(leaky, ['--format', 'json', '--publish', '--registry-url', DEAD_REGISTRY]);
    const j = json(r.stdout);
    expect(r.stderr).not.toContain('Registry: nothing sent');
    // The dead registry fails the attempt; the failure is a network failure,
    // never the unmeasured disclosure.
    if (j.publish) {
      expect(j.publish.reason).not.toBe('unmeasured');
      expect(j.publish.attempted).not.toBe(false);
    }
  });
});

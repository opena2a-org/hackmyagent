/**
 * HMA-21.AC2 — scope semantics reach the exit code.
 *
 * Fixture: `danger.py` = `eval(user_input)`, neutral HOME,
 * `node dist/cli.js secure --ci --json .`. Measured at base a598f616:
 *
 *   no file                 -> exit 1 / score 69 / NEMO-009 reported
 *   danger.py:NEMO-009 # r  -> IDENTICAL to none (silently inert)
 *   !NEMO-009               -> exit 1 / 69 / suppressed (presentational)
 *   danger.py               -> exit 0 / 93 / outOfScope
 *
 * At the fix the `<path>:<CHECK>` row moves: exit 0 / score 93 / the finding
 * in `outOfScope` with `suppressedBy: "hmaignore-path-check"`, absent from
 * `suppressed`, absent from the gate set. The other three rows are unchanged.
 * Exit codes are captured from `spawnSync` status — no pipe.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

let fixture: string;
let home: string;

beforeAll(() => {
  fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'hma21-scope-'));
  fs.writeFileSync(path.join(fixture, 'danger.py'), 'eval(user_input)\n');
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'hma21-home-'));
});

afterAll(() => {
  for (const d of [fixture, home]) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function secure(hmaignore?: string): { status: number | null; json: any } {
  if (hmaignore === undefined) {
    fs.rmSync(path.join(fixture, '.hmaignore'), { force: true });
  } else {
    fs.writeFileSync(path.join(fixture, '.hmaignore'), hmaignore);
  }
  const r = spawnSync(process.execPath, [CLI, 'secure', '--ci', '--json', '.'], {
    cwd: fixture,
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home },
  });
  const out = r.stdout ?? '';
  return { status: r.status, json: JSON.parse(out.slice(out.indexOf('{'))) };
}

const failing = (j: any) => (j.findings ?? []).filter((f: any) => f.passed === false).map((f: any) => f.checkId);

describe('HMA-21.AC2 — <path>:<CHECK-ID> scope semantics', { timeout: 600_000 }, () => {
  it('HMA-21.AC2 baseline: no .hmaignore -> exit 1 / 69 / NEMO-009 reported', () => {
    const { status, json } = secure();
    expect(status).toBe(1);
    expect(json.score).toBe(69);
    expect(failing(json)).toContain('NEMO-009');
    expect(json.suppressed).toBeUndefined();
    expect(json.outOfScope).toBeUndefined();
  });

  it('HMA-21.AC2 danger.py:NEMO-009 # r -> exit 0 / 93 / outOfScope via hmaignore-path-check, not suppressed, not in the gate set', () => {
    const { status, json } = secure('danger.py:NEMO-009 # r\n');
    expect(status).toBe(0);
    expect(json.exitCode).toBe(0);
    expect(json.score).toBe(93);
    expect(failing(json)).not.toContain('NEMO-009');
    const oos = (json.outOfScope ?? []).find((r: any) => r.checkId === 'NEMO-009');
    expect(oos).toBeDefined();
    expect(oos.suppressedBy).toBe('hmaignore-path-check');
    // absent from `suppressed`, so `gateSet()` cannot expand it back into the
    // exit code — the counts prove the gate set does not hold the critical
    expect((json.suppressed ?? []).map((r: any) => r.checkId)).not.toContain('NEMO-009');
    expect(json.counts.critical).toBe(0);
  });

  it('HMA-21.AC2 !NEMO-009 -> exit 1 / 69 / suppressed (presentational, unchanged)', () => {
    const { status, json } = secure('!NEMO-009\n');
    expect(status).toBe(1);
    expect(json.score).toBe(69);
    const sup = (json.suppressed ?? []).find((r: any) => r.checkId === 'NEMO-009');
    expect(sup).toBeDefined();
    expect(sup.suppressedBy).toBe('hmaignore-check');
    expect(json.outOfScope).toBeUndefined();
    // still counted: the presentational channel narrows the list, not the gate
    expect(json.counts.critical).toBe(1);
  });

  it('HMA-21.AC2 danger.py -> exit 0 / 93 (whole-path scope, unchanged)', () => {
    const { status, json } = secure('danger.py\n');
    expect(status).toBe(0);
    expect(json.score).toBe(93);
    const oos = (json.outOfScope ?? []).find((r: any) => r.checkId === 'NEMO-009');
    expect(oos).toBeDefined();
    expect(oos.suppressedBy).toBe('hmaignore-path');
  });

  it('HMA-21.AC2 no site compares a channel literal for the partition — isScopeChannel routes it', () => {
    const root = path.resolve(__dirname, '..', '..');
    const sources = ['src/hardening/scanner.ts', 'src/cli.ts', 'src/hardening/settled-outcome.ts', 'src/ui/verdict-band.ts'];
    for (const rel of sources) {
      const src = fs.readFileSync(path.join(root, rel), 'utf8');
      // a comparison against the scope-channel literals is the pattern that
      // made a fourth channel fall through onto the `suppressed` side
      expect(src, `${rel} compares a channel literal`).not.toMatch(/[!=]==?\s*'hmaignore-path'/);
      expect(src, `${rel} compares a channel literal`).not.toMatch(/[!=]==?\s*'hmaignore-path-check'/);
    }
    // and the three partition sites actually route through the helper
    expect(fs.readFileSync(path.join(root, 'src/hardening/scanner.ts'), 'utf8')).toMatch(/isScopeChannel/);
    expect(fs.readFileSync(path.join(root, 'src/cli.ts'), 'utf8')).toMatch(/isScopeChannel/);
  });
});

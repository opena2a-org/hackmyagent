/**
 * #606 — the ASP profile's `credentials` summary counts the static CRED-*
 * and semantic SEM-CRED-* credential findings, so it no longer misses the
 * semantic family a control fails on.
 *
 * The summary counted `checkId.startsWith('CRED-')`, which matched the static
 * CRED-001..004 checks but NOT the semantic `SEM-CRED-*` family. So a dotenv
 * secret that failed OASB-1 control 5.1 on `SEM-CRED-002` was reported as
 * `hardcodedSecrets: 0` with "No hardcoded credentials detected" in the very
 * same signed-shaped document that listed control 5.1 as failed — the summary
 * and the failed-control list contradicting each other. The predicate now
 * matches both prefixes — the CRED-* and SEM-CRED-* families.
 *
 * NOTE (tracked separately, a benchmark-mapping gap): OASB-1 control 5.1's
 * `checkIds` include `CRED-002/003/004` and `SEM-CRED-*` but not the generic
 * `CRED-001` key detector, though 5.1's audit text expects it. The summary
 * counts CRED-001 (it is a hardcoded secret), so the summary is a SUPERSET of
 * control 5.1's cited findings until CRED-001 is mapped — filed for the
 * benchmark owner. The equality cell below is scoped to a semantic-only tree,
 * where CRED-001 does not fire and the two coincide.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

// Filenames and a high-entropy synthetic value assembled at runtime from
// fragments, so no blocked-file path literal and no KEY=value secret shape
// sits in this source (the repo idiom; see fix-all-key-material.test.ts).
// FAKE-marked, never real.
const DOTENV = ['', 'env'].join('.');
const VAR = ['OPENAI', 'API', 'KEY'].join('_');
// A generic hardcoded key the STATIC CRED-001 detector catches (its OpenAI
// pattern is /sk-[A-Za-z0-9]{48,}/).
function providerKey(): string {
  const alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let seed = 7;
  let body = '';
  for (let i = 0; i < 48; i++) {
    seed = (seed * 1103515245 + 12345) % 2147483648;
    body += alpha[seed % alpha.length];
  }
  return ['sk', body].join('-');
}


describe('#606 ASP credential summary counts the CRED- and SEM-CRED- families', { timeout: 300_000 }, () => {
  beforeAll(assertDistFreshIfPresent);

  function asp(dir: string, extra: string[] = []): any {
    const r = spawnSync(process.execPath, [CLI, 'secure', dir, '-b', 'oasb-1', '--format', 'asp', '--no-machine-posture', ...extra], {
      encoding: 'utf8',
      timeout: 240_000,
      maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-606-home-')) },
    });
    const out = r.stdout ?? '';
    return JSON.parse(out.slice(out.indexOf('{'), out.lastIndexOf('}') + 1));
  }

  let dotenvTree: string;   // a semantic secret (SEM-CRED-*), no static CRED
  let configTree: string;   // a generic key in config.json (CRED-*), for --static-only
  let cleanTree: string;
  beforeAll(() => {
    dotenvTree = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-606-dotenv-'));
    fs.writeFileSync(path.join(dotenvTree, 'package.json'), '{ "name": "fx606", "version": "1.0.0", "private": true }\n');
    fs.writeFileSync(path.join(dotenvTree, DOTENV), VAR + '=' + providerKey() + '\n');

    configTree = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-606-config-'));
    fs.writeFileSync(path.join(configTree, 'package.json'), '{ "name": "fx606c", "version": "1.0.0", "private": true }\n');
    fs.writeFileSync(path.join(configTree, 'config.json'), JSON.stringify({ apiKey: providerKey() }, null, 2) + '\n');

    cleanTree = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-606-clean-'));
    fs.writeFileSync(path.join(cleanTree, 'package.json'), '{ "name": "fx606x", "version": "1.0.0", "private": true }\n');
  });

  it('RED-ON-BASE: the SEM-CRED-* finding is counted alongside the static one', () => {
    // A provider key in .env fires BOTH the static CRED-001 and the semantic
    // SEM-CRED-002; control 5.1 fails and cites SEM-CRED-002. The old
    // startsWith('CRED-')-only predicate counted CRED-001 (1) and MISSED
    // SEM-CRED-002 — the #606 undercount. Counting both requires the
    // SEM-CRED- clause, so hardcodedSecrets >= 2 is red on the base build.
    const j = asp(dotenvTree);
    const c51 = (j.failedControls ?? []).find((c: any) => c.id === '5.1');
    expect(c51, 'control 5.1 should fail on a tree with a hardcoded secret').toBeTruthy();
    expect(c51.findings.some((f: string) => f.startsWith('SEM-CRED-002')), 'the semantic secret is detected and cited by 5.1').toBe(true);
    expect(j.credentials.hardcodedSecrets).toBeGreaterThanOrEqual(2);
    expect(j.credentials.recommendation).not.toMatch(/No hardcoded credentials detected/);
  });

  it('the summary is a superset of what control 5.1 cites — it never underreports', () => {
    // The two counts are NOT equal in general: the summary counts per finding
    // over the CRED-*/SEM-CRED-* families, while the control
    // cites one entry per distinct failed checkId in its own (CRED-001-less)
    // set. The invariant that matters for #606 is that the summary never
    // reports FEWER secrets than a failed control lists — the direction that
    // produced the false "0" contradiction.
    const j = asp(dotenvTree);
    const c51 = (j.failedControls ?? []).find((c: any) => c.id === '5.1');
    expect(c51, 'control 5.1 must fail here, or the >= degrades to >= 0').toBeTruthy();
    expect(j.credentials.hardcodedSecrets).toBeGreaterThanOrEqual((c51?.findings ?? []).length);
    expect(j.credentials.hardcodedSecrets).toBeGreaterThan(0);
  });

  it('REGRESSION GUARD: a generic hardcoded key is still counted under --static-only', () => {
    // The first cut of this fix sourced the count from control 5.1 alone,
    // which drops CRED-001 (the generic key detector, mapped to no control):
    // under --static-only (semantic checks off) a real key then reported 0.
    // The two-prefix predicate keeps it counted.
    const j = asp(configTree, ['--static-only']);
    expect(j.credentials.hardcodedSecrets).toBeGreaterThan(0);
    expect(j.credentials.recommendation).not.toMatch(/No hardcoded credentials detected/);
  });

  it('a clean tree reports zero and control 5.1 does not fail', () => {
    const j = asp(cleanTree);
    expect((j.failedControls ?? []).some((c: any) => c.id === '5.1')).toBe(false);
    expect(j.credentials.hardcodedSecrets).toBe(0);
    expect(j.credentials.recommendation).toMatch(/No hardcoded credentials detected/);
  });
});

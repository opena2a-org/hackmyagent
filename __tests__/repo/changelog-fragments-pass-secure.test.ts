/**
 * The changelog fragments are scanned by the scanner they describe.
 *
 * A fragment for #543 spelled a mixed-case GitLab slug as one token, so
 * `hackmyagent secure` on this repository reported AST-CRED-003 (critical) on
 * that release note and exited 1, where `main` exited 0. Fragments are folded
 * into CHANGELOG.md at release, so a credential-shaped example in one of them
 * ends up in the root changelog of every clone.
 *
 * This runs the built CLI over `changelog.d/` the way a user scanning a
 * checkout does and asserts the scan exits 0 with no credential finding. A
 * release note that must show a vendor prefix beside a body writes them as two
 * code spans.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const CLI = path.join(REPO_ROOT, 'dist', 'cli.js');
const FRAGMENTS = path.join(REPO_ROOT, 'changelog.d');

interface Finding { checkId: string; severity: string; file: string; line?: number }

describe('changelog fragments pass the scanner', () => {
  it('secure --ci on changelog.d exits 0 with no credential finding', () => {
    const res = spawnSync(process.execPath, [CLI, 'secure', '--ci', '--json', FRAGMENTS], {
      encoding: 'utf-8',
      timeout: 240_000,
      env: {
        ...process.env,
        NO_COLOR: '1',
        OPENA2A_TELEMETRY: 'off',
        HOME: tempDir('hma-home-'),
      },
    });
    expect(res.error).toBeUndefined();
    const body = JSON.parse(res.stdout) as { findings: Finding[]; exitCode: number };
    const credential = body.findings
      .filter((f) => /^AST-CRED-/.test(f.checkId))
      .map((f) => `${f.checkId} ${f.severity} ${f.file}:${f.line ?? '?'}`);
    expect(credential).toEqual([]);
    expect(body.findings.filter((f) => f.severity === 'critical' || f.severity === 'high')).toEqual([]);
    expect(res.status).toBe(0);
  });
});

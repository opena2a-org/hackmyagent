/**
 * The changelog fragments are scanned by the scanner they describe.
 *
 * A fragment for #543 spelled a mixed-case GitLab slug as one token, so
 * `hackmyagent secure` on this repository reported AST-CRED-003 (critical) on
 * that release note and exited 1, where `main` exited 0. Fragments are folded
 * into CHANGELOG.md at release, so a credential-shaped example in one of them
 * ends up in the root changelog of every clone.
 *
 * This runs the built CLI the way a user scanning a checkout does, twice: over
 * `changelog.d/`, and over the CHANGELOG.md that `preview --virtual` folds the
 * fragments into, beside the repository's `.hmaignore`, which is the file a
 * clone scans after the release. Both must exit 0. The fragments must also
 * carry no finding at medium or above: the #467 note quoted a codepoint range
 * and the `.codePointAt(` call it is read by, and was reported on its own as a
 * MEDIUM GlassWorm decoder shape (UNICODE-STEGO-002, #939). A release note that
 * must show a vendor prefix beside a body writes them as two code spans.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const CLI = path.join(REPO_ROOT, 'dist', 'cli.js');
const FRAGMENTS = path.join(REPO_ROOT, 'changelog.d');

interface Finding { checkId: string; severity: string; file: string; line?: number }

function secure(target: string): { status: number | null; findings: Finding[] } {
  const res = spawnSync(process.execPath, [CLI, 'secure', '--ci', '--json', target], {
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
  const body = JSON.parse(res.stdout) as { findings: Finding[] };
  return { status: res.status, findings: body.findings };
}

const label = (f: Finding) => `${f.checkId} ${f.severity} ${f.file}:${f.line ?? '?'}`;

// The scan spawn's 240 s budget is above the suite's 180 s testTimeout, so the
// describe carries its own, as vitest.config.ts asks.
describe('changelog fragments pass the scanner', { timeout: 300_000 }, () => {
  it('secure --ci on changelog.d exits 0 with no credential finding and nothing at medium or above', () => {
    const { status, findings } = secure(FRAGMENTS);
    expect(findings.filter((f) => /^AST-CRED-/.test(f.checkId)).map(label)).toEqual([]);
    expect(findings.filter((f) => ['critical', 'high', 'medium'].includes(f.severity)).map(label)).toEqual([]);
    expect(status).toBe(0);
  });

  it('secure --ci on the CHANGELOG.md the release folds the fragments into exits 0', () => {
    const preview = spawnSync(
      process.execPath,
      [path.join(REPO_ROOT, 'scripts', 'changelog.mjs'), 'preview', '--virtual', '--changelog', path.join(REPO_ROOT, 'CHANGELOG.md')],
      { encoding: 'utf-8', timeout: 60_000 },
    );
    expect(preview.error).toBeUndefined();
    expect(preview.status).toBe(0);
    const clone = tempDir('hma-changelog-render-');
    fs.writeFileSync(path.join(clone, 'CHANGELOG.md'), preview.stdout);
    fs.copyFileSync(path.join(REPO_ROOT, '.hmaignore'), path.join(clone, '.hmaignore'));

    const { status, findings } = secure(clone);
    expect(findings.filter((f) => /^AST-CRED-/.test(f.checkId)).map(label)).toEqual([]);
    expect(findings.filter((f) => f.severity === 'critical' || f.severity === 'high').map(label)).toEqual([]);
    expect(status).toBe(0);
  });
});

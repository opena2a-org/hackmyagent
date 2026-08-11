import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

/**
 * #504, the dry-run half.
 *
 * `fix-all --dry-run` writes nothing, so nothing it previews is resolved. Each
 * plugin's dry-run branch returns a synthetic "would fix" remediation per
 * auto-fixable finding, and those were counted as fixed — clearing the finding
 * out of `remainingFindings`, which both the exit code and the JSON payload
 * read.
 *
 * Measured on the fixture below, pre-fix:
 *   fix-all --scan-only -> exit 1, 2 CRITICAL CRED-001
 *   fix-all --dry-run   -> exit 0, "Findings: 3 total | 2 fixed"
 *
 * Neither mode writes anything, so the two must gate identically.
 * `fix-all --help` states "Exit code 1 if critical/high issues remain after
 * fixing", and after a dry run they all remain.
 */

const CLI = join(__dirname, '..', '..', 'dist', 'cli.js');

/**
 * Two credentials in files `fix-all`'s credential plugin already reads on
 * `main` — a `.env` and an `mcp.json`. Deliberately NOT source files: the
 * source-coverage half of #504 is a separate change, and pinning it here would
 * make this suite fail for an unrelated reason.
 *
 * The key shape matters. `sk-ant-api03-` followed by 95 filler characters is
 * what the catalog matches; a shorter string is silently below the length
 * threshold and the fixture stops carrying a finding at all, at which point
 * both modes exit 0 and every assertion below passes vacuously.
 */
function makeFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), 'hma-504-parity-'));
  mkdirSync(join(dir, 'src'), { recursive: true });
  writeFileSync(join(dir, '.gitignore'), 'node_modules/\n');
  writeFileSync(join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  writeFileSync(join(dir, '.env'), `ANTHROPIC_API_KEY=sk-ant-api03-${'C'.repeat(95)}\n`);
  writeFileSync(
    join(dir, 'mcp.json'),
    JSON.stringify(
      { servers: { x: { env: { ANTHROPIC_API_KEY: `sk-ant-api03-${'D'.repeat(95)}` } } } },
      null,
      2
    ) + '\n'
  );
  return dir;
}

function run(dir: string, ...args: string[]) {
  const res = spawnSync(process.execPath, [CLI, 'fix-all', dir, ...args], {
    encoding: 'utf-8',
    env: { ...process.env, NO_COLOR: '1' },
  });
  return { status: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

describe('#504 fix-all --dry-run gates identically to --scan-only', () => {
  beforeAll(() => {
    assertDistFreshIfPresent();
  });

  it('the fixture really does carry gating findings, in both modes', () => {
    // Non-vacuity control. Every assertion below compares two exit codes, and
    // 0 === 0 passes just as happily as 1 === 1. If the fixture stops carrying
    // a critical finding — a pattern change, a length threshold, a new
    // suppression — the parity assertions go quietly meaningless. This fails
    // loudly instead.
    const dir = makeFixture();
    try {
      const scanOnly = run(dir, '--scan-only');
      expect(scanOnly.stdout).toContain('CRED-001');
      expect(scanOnly.status).toBe(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('--dry-run and --scan-only return the same exit code on identical trees', () => {
    // Fresh fixture per invocation: fix-all writes, and even in dry-run the
    // plugins may create state (a credvault store key) that changes the next
    // run's findings.
    const a = makeFixture();
    const b = makeFixture();
    try {
      const scanOnly = run(a, '--scan-only');
      const dryRun = run(b, '--dry-run');
      expect(dryRun.status).toBe(scanOnly.status);
      expect(dryRun.status).toBe(1);
    } finally {
      rmSync(a, { recursive: true, force: true });
      rmSync(b, { recursive: true, force: true });
    }
  });

  it('--dry-run still lists the findings as outstanding, not as resolved', () => {
    const dir = makeFixture();
    try {
      const { stdout } = run(dir, '--dry-run');
      // The findings are still outstanding, so they appear in the remaining
      // block rather than being silently cleared.
      expect(stdout).toContain('CRED-001');
      // And the summary must not claim they were fixed over a tree it did not
      // write to.
      expect(stdout).not.toMatch(/\|\s*\d+\s+fixed/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('--dry-run still previews the available fixes', () => {
    // The point of --dry-run is the preview. Gating it correctly must not cost
    // the feature: a fix that made the exit code right by dropping the preview
    // would pass the parity assertions above and be useless.
    const dir = makeFixture();
    try {
      const { stdout } = run(dir, '--dry-run');
      expect(stdout).toMatch(/Would fix|Fixes Available/i);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('--dry-run writes nothing', () => {
    const dir = makeFixture();
    try {
      const before = spawnSync('shasum', ['-a', '256', join(dir, '.env'), join(dir, 'mcp.json')], {
        encoding: 'utf-8',
      }).stdout;
      run(dir, '--dry-run');
      const after = spawnSync('shasum', ['-a', '256', join(dir, '.env'), join(dir, 'mcp.json')], {
        encoding: 'utf-8',
      }).stdout;
      expect(after).toBe(before);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('a clean tree still exits 0 in both modes', () => {
    // The fix must not turn --dry-run into an unconditional failure.
    const a = mkdtempSync(join(tmpdir(), 'hma-504-clean-'));
    const b = mkdtempSync(join(tmpdir(), 'hma-504-clean-'));
    try {
      for (const d of [a, b]) {
        writeFileSync(join(d, '.gitignore'), 'node_modules/\n');
        writeFileSync(join(d, 'package.json'), '{"name":"c","version":"1.0.0"}\n');
      }
      const scanOnly = run(a, '--scan-only');
      const dryRun = run(b, '--dry-run');
      expect(dryRun.status).toBe(scanOnly.status);
    } finally {
      rmSync(a, { recursive: true, force: true });
      rmSync(b, { recursive: true, force: true });
    }
  });
});

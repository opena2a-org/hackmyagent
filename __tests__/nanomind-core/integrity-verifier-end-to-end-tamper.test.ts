import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  readFileSync,
  writeFileSync,
  existsSync,
  rmSync,
  symlinkSync,
  cpSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// #285 — this suite spawns the built CLI. Without this it would happily
// measure a binary older than `src/` and report a pass.
beforeAll(assertDistFreshIfPresent);

/**
 * Load-bearing end-to-end gate (per feedback_verify_security_claims_end_to_end.md):
 *
 * The README bullet promising "Tampered binaries enter QUARANTINE mode (exit
 * code 3)" must have a regression test that produces the exact failure mode
 * it claims to detect. This test:
 *
 *   1. Copies the BUILT dist/ tree (cli.js + manifest) to a tmpdir + minimal
 *      package.json so resolvePackageRoot finds the right ancestor.
 *   2. Tampers cli.js by appending one byte.
 *   3. Runs `node <tmpdir>/dist/cli.js --version`.
 *   4. Asserts exit code 3 + INTEGRITY CHECK FAILED on stderr.
 *
 * The test runs against a tmpdir copy (NOT the source-tree dist/) so it is
 * safe under vitest's parallel worker pool — concurrent tests that read the
 * real dist/cli.js are not disturbed.
 *
 * This is the gate that the v0.22.0 release would have failed before #159.
 * Without this test, integrity-verifier regressions are invisible.
 */

const REPO_ROOT = resolve(__dirname, '..', '..');
const SRC_DIST = join(REPO_ROOT, 'dist');
const SRC_PKG_JSON = join(REPO_ROOT, 'package.json');
const SRC_NODE_MODULES = join(REPO_ROOT, 'node_modules');

describe('integrity-verifier: end-to-end tamper gate', () => {
  let tmpRoot = '';
  let tmpCli = '';
  let tmpManifest = '';
  let originalCli: Buffer;
  let originalManifest: Buffer;

  const builtArtifactsExist =
    existsSync(join(SRC_DIST, 'cli.js')) &&
    existsSync(join(SRC_DIST, 'integrity-manifest.json'));

  // Not `skipIf` under CI — this THROWS there (BD12; same stance as
  // ast-boundary-line-recovery.test.ts). test-matrix and the release build
  // job both run `npm run build` before `npm test`, so the only way these
  // artifacts are absent in CI is a build/test de-sync — e.g. a manifest
  // filename change that this suite's own existence check silently keys on —
  // and a skip would hide exactly that. Local runs keep the skip.
  const inCI = Boolean(process.env.CI || process.env.GITHUB_ACTIONS);
  const skipWhenUnbuilt = !builtArtifactsExist && !inCI;

  beforeAll(() => {
    if (!builtArtifactsExist) {
      if (inCI) {
        throw new Error(
          'dist/cli.js or dist/integrity-manifest.json is missing under CI. '
          + 'The workflow builds before it tests, so this is a build/test '
          + 'de-sync, and skipping would silently drop the tamper gate (BD12).',
        );
      }
      return;
    }
    tmpRoot = mkdtempSync(join(tmpdir(), 'hma-e2e-tamper-'));
    // Copy dist/ into tmp (preserves the relative structure verifyAll expects)
    cpSync(SRC_DIST, join(tmpRoot, 'dist'), { recursive: true });
    // Minimal package.json so resolvePackageRoot finds the tmp root
    const pkg = JSON.parse(readFileSync(SRC_PKG_JSON, 'utf-8'));
    writeFileSync(
      join(tmpRoot, 'package.json'),
      JSON.stringify({ name: pkg.name, version: pkg.version }),
    );
    // node_modules — symlink (NOT copy) for require() resolution speed
    if (existsSync(SRC_NODE_MODULES)) {
      symlinkSync(SRC_NODE_MODULES, join(tmpRoot, 'node_modules'));
    }
    tmpCli = join(tmpRoot, 'dist', 'cli.js');
    tmpManifest = join(tmpRoot, 'dist', 'integrity-manifest.json');
    originalCli = readFileSync(tmpCli);
    originalManifest = readFileSync(tmpManifest);
  });

  afterAll(() => {
    if (tmpRoot && existsSync(tmpRoot)) {
      rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  it.skipIf(skipWhenUnbuilt)(
    'tampering cli.js causes node dist/cli.js --version to exit 3 with INTEGRITY CHECK FAILED on stderr',
    () => {
      try {
        // Tamper: append one byte. The verifier hashes file content, so any
        // change should flip the hash and fail the package_integrity check.
        writeFileSync(tmpCli, Buffer.concat([originalCli, Buffer.from('\n')]));

        const result = spawnSync(process.execPath, [tmpCli, '--version'], {
          encoding: 'utf-8',
          timeout: 30000,
        });

        // The whole point: exit 3 (QUARANTINE), not 0 (silent no-op).
        expect(result.status).toBe(3);
        // The user-visible signal that proves the gate ran end-to-end.
        expect(result.stderr).toContain('INTEGRITY CHECK FAILED');
        // The gate should also identify which check failed.
        expect(result.stderr).toContain('package_integrity');
        // And how many files (the new accumulate-all-tampered-files format).
        expect(result.stderr).toContain('files tampered');
        expect(result.stderr).toContain('cli.js');
      } finally {
        // Restore in case a later test in this describe runs.
        writeFileSync(tmpCli, originalCli);
      }
    },
    60000,
  );

  it.skipIf(skipWhenUnbuilt)(
    'replacing the manifest with a symlink writes INTEGRITY MANIFEST REJECTED to stderr',
    () => {
      // Symlink-only attack (no binary tamper). The verifier rejects the
      // manifest and falls through to dev-mode CLEAN — but the stderr
      // warning makes the rejection visible to ops/forensics.
      const attackerTarget = join(tmpRoot, 'attacker-manifest.json');
      try {
        writeFileSync(attackerTarget, originalManifest);
        rmSync(tmpManifest, { force: true });
        symlinkSync(attackerTarget, tmpManifest);

        const result = spawnSync(process.execPath, [tmpCli, '--version'], {
          encoding: 'utf-8',
          timeout: 30000,
        });

        expect(result.stderr).toContain('INTEGRITY MANIFEST REJECTED: symlink');
      } finally {
        // Restore: delete the symlink and write the original manifest back.
        rmSync(tmpManifest, { force: true });
        writeFileSync(tmpManifest, originalManifest);
        if (existsSync(attackerTarget)) rmSync(attackerTarget, { force: true });
      }
    },
    60000,
  );
});

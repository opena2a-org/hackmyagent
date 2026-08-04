import { describe, it, expect, beforeEach, afterEach, beforeAll } from 'vitest';
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  symlinkSync,
  rmSync,
  existsSync,
  unlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  loadManifest,
  generateManifest,
  verifyAll,
  type IntegrityManifest,
} from '../../src/nanomind-core/security/integrity-verifier';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// #285 — this suite spawns the built CLI. Without this it would happily
// measure a binary older than `src/` and report a pass.
beforeAll(assertDistFreshIfPresent);

/**
 * Defends against a post-install file-replacement attack where an attacker
 * with write access to the install directory swaps the integrity manifest
 * for a symlink pointing at an attacker-controlled file (e.g. a manifest
 * the attacker generated for tampered dist files). loadManifest now rejects
 * symlinks at either probed manifest location and falls back to dev-mode
 * CLEAN with reason "manifest rejected (symlink)".
 *
 * Note: dev-mode CLEAN here is the conservative behavior. We could escalate
 * symlink-as-manifest to QUARANTINE, but that would brick legitimate dev
 * workflows that symlink the manifest into a checkout. The stderr warning
 * makes the rejection visible; a determined attacker still cannot pass off
 * a tampered manifest as authentic.
 */

function setupFakePackage(): string {
  const root = mkdtempSync(join(tmpdir(), 'hma-integrity-symlink-'));
  mkdirSync(join(root, 'dist'), { recursive: true });
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'fake', version: '0.0.0' }));
  writeFileSync(join(root, 'dist', 'cli.js'), 'console.log("hi");\n');
  return root;
}

function captureStderr(): { restore: () => string } {
  const original = process.stderr.write.bind(process.stderr);
  let captured = '';
  // @ts-expect-error narrowed write signature
  process.stderr.write = (chunk: unknown): boolean => {
    captured += typeof chunk === 'string' ? chunk : String(chunk);
    return true;
  };
  return {
    restore: () => {
      process.stderr.write = original;
      return captured;
    },
  };
}

describe('integrity-verifier: symlink rejection in loadManifest', () => {
  let root = '';
  beforeEach(() => {
    root = setupFakePackage();
  });
  afterEach(() => {
    if (root && existsSync(root)) rmSync(root, { recursive: true, force: true });
  });

  it('returns null and writes stderr when manifest at dist/ is a symlink', () => {
    // Generate a real manifest somewhere else, then symlink the canonical
    // location to it. Attacker scenario: replace the on-disk manifest with
    // a symlink to an attacker-controlled file.
    const realManifest = generateManifest(root);
    const attackerPath = join(root, 'attacker-manifest.json');
    writeFileSync(attackerPath, JSON.stringify(realManifest));
    const canonicalPath = join(root, 'dist', '.integrity-manifest.json');
    symlinkSync(attackerPath, canonicalPath);

    const stderr = captureStderr();
    const loaded = loadManifest(root);
    const captured = stderr.restore();

    expect(loaded).toBeNull();
    expect(captured).toContain('INTEGRITY MANIFEST REJECTED: symlink at');
    expect(captured).toContain(canonicalPath);
  });

  it('returns null when manifest at package-root fallback location is a symlink', () => {
    // Same attack but at the legacy fallback path. dist/ has no manifest;
    // the attacker dropped a symlink at the package root.
    const realManifest = generateManifest(root);
    const attackerPath = join(root, 'attacker-manifest.json');
    writeFileSync(attackerPath, JSON.stringify(realManifest));
    const fallbackPath = join(root, '.integrity-manifest.json');
    symlinkSync(attackerPath, fallbackPath);

    const stderr = captureStderr();
    const loaded = loadManifest(root);
    const captured = stderr.restore();

    expect(loaded).toBeNull();
    expect(captured).toContain('INTEGRITY MANIFEST REJECTED: symlink at');
    expect(captured).toContain(fallbackPath);
  });

  it('verifyAll falls back to dev-mode CLEAN with explicit reason when manifest is rejected', () => {
    const realManifest = generateManifest(root);
    const attackerPath = join(root, 'attacker-manifest.json');
    writeFileSync(attackerPath, JSON.stringify(realManifest));
    symlinkSync(attackerPath, join(root, 'dist', '.integrity-manifest.json'));

    const stderr = captureStderr();
    const result = verifyAll({
      packageRoot: root,
      eventChainPath: join(root, '.events.jsonl'),
    });
    stderr.restore();

    expect(result.status).toBe('CLEAN');
    const manifestLoadCheck = result.checks.find((c) => c.name === 'manifest_load');
    expect(manifestLoadCheck?.passed).toBe(true);
    expect(manifestLoadCheck?.reason).toBe('Manifest rejected (symlink) — dev mode');
  });

  it('falls through to fallback when dist/ symlink is rejected and root has a real manifest', () => {
    // Defense-in-depth: a symlink at dist/ should not block discovery of a
    // legitimate fallback manifest at the package root.
    const realManifest = generateManifest(root);
    const attackerPath = join(root, 'attacker-manifest.json');
    writeFileSync(attackerPath, JSON.stringify(realManifest));
    symlinkSync(attackerPath, join(root, 'dist', '.integrity-manifest.json'));
    writeFileSync(join(root, '.integrity-manifest.json'), JSON.stringify(realManifest));

    const stderr = captureStderr();
    const loaded = loadManifest(root);
    stderr.restore();

    expect(loaded).not.toBeNull();
    expect(loaded?.version).toBe('0.0.0');
  });

  it('regular file manifests are still accepted (no false positive)', () => {
    // Sanity check: the symlink rejection must not break legitimate manifests.
    const manifest = generateManifest(root);
    writeFileSync(join(root, 'dist', '.integrity-manifest.json'), JSON.stringify(manifest));
    const loaded = loadManifest(root);
    expect(loaded).not.toBeNull();
    expect(loaded?.version).toBe('0.0.0');
  });

  it('symlink rejection survives stat-vs-lstat distinction (does not follow link)', () => {
    // Critical: lstat must not follow the symlink. If we used stat() instead,
    // a broken symlink would error and a valid symlink would look like a
    // regular file.
    const target = join(root, 'inner', 'manifest.json');
    mkdirSync(join(root, 'inner'), { recursive: true });
    const realManifest = generateManifest(root);
    writeFileSync(target, JSON.stringify(realManifest));
    symlinkSync(target, join(root, 'dist', '.integrity-manifest.json'));

    const stderr = captureStderr();
    const loaded = loadManifest(root);
    const captured = stderr.restore();

    expect(loaded).toBeNull();
    expect(captured).toContain('INTEGRITY MANIFEST REJECTED: symlink');
  });

  it('broken symlink (target missing) is still rejected as symlink, not missed', () => {
    const missingTarget = join(root, 'does-not-exist.json');
    symlinkSync(missingTarget, join(root, 'dist', '.integrity-manifest.json'));

    const stderr = captureStderr();
    const loaded = loadManifest(root);
    const captured = stderr.restore();

    expect(loaded).toBeNull();
    expect(captured).toContain('INTEGRITY MANIFEST REJECTED: symlink');
  });
});

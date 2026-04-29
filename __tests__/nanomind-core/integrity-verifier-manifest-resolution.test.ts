import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  loadManifest,
  generateManifest,
  verifyAll,
  type IntegrityManifest,
} from '../../src/nanomind-core/security/integrity-verifier';

function setupFakePackage(): string {
  const root = mkdtempSync(join(tmpdir(), 'hma-integrity-test-'));
  mkdirSync(join(root, 'dist'), { recursive: true });
  mkdirSync(join(root, 'dist', 'sub'), { recursive: true });
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'fake', version: '0.0.0' }));
  writeFileSync(join(root, 'dist', 'cli.js'), 'console.log("hi");\n');
  writeFileSync(join(root, 'dist', 'sub', 'helper.js'), 'module.exports = 1;\n');
  return root;
}

function bake(root: string): IntegrityManifest {
  const manifest = generateManifest(root);
  writeFileSync(join(root, 'dist', '.integrity-manifest.json'), JSON.stringify(manifest));
  return manifest;
}

describe('integrity-verifier manifest path resolution', () => {
  let root = '';
  beforeEach(() => {
    root = setupFakePackage();
  });
  afterEach(() => {
    if (root && existsSync(root)) rmSync(root, { recursive: true, force: true });
  });

  it('loadManifest finds the manifest at dist/.integrity-manifest.json (where the build script writes it)', () => {
    bake(root);
    const loaded = loadManifest(root);
    expect(loaded).not.toBeNull();
    expect(loaded?.version).toBe('0.0.0');
  });

  it('loadManifest also finds a manifest at the package root (legacy fallback)', () => {
    const manifest = generateManifest(root);
    writeFileSync(join(root, '.integrity-manifest.json'), JSON.stringify(manifest));
    const loaded = loadManifest(root);
    expect(loaded).not.toBeNull();
    expect(loaded?.version).toBe('0.0.0');
  });

  it('loadManifest returns null when no manifest exists at either location (dev mode)', () => {
    expect(loadManifest(root)).toBeNull();
  });

  it('generateManifest does NOT include the manifest filename in its own files map (chicken-and-egg)', () => {
    const manifest = generateManifest(root);
    expect(manifest.files['.integrity-manifest.json']).toBeUndefined();
    // Re-running after the file lands on disk still must not include it.
    bake(root);
    const second = generateManifest(root);
    expect(second.files['.integrity-manifest.json']).toBeUndefined();
  });

  it('verifyAll returns CLEAN on an unmodified package', () => {
    bake(root);
    const result = verifyAll({ packageRoot: root, eventChainPath: join(root, '.events.jsonl') });
    expect(result.status).toBe('CLEAN');
  });

  it('verifyAll returns QUARANTINE when a dist file is tampered after manifest bake', () => {
    bake(root);
    writeFileSync(join(root, 'dist', 'cli.js'), 'console.log("hi");\n// tampered\n');
    const result = verifyAll({ packageRoot: root, eventChainPath: join(root, '.events.jsonl') });
    expect(result.status).toBe('QUARANTINE');
    const failed = result.checks.find(c => !c.passed);
    expect(failed?.name).toBe('package_integrity');
    expect(failed?.reason).toContain('cli.js');
  });

  it('verifyAll returns QUARANTINE when a dist file is missing', () => {
    bake(root);
    rmSync(join(root, 'dist', 'sub', 'helper.js'));
    const result = verifyAll({ packageRoot: root, eventChainPath: join(root, '.events.jsonl') });
    expect(result.status).toBe('QUARANTINE');
    const failed = result.checks.find(c => !c.passed);
    expect(failed?.reason).toContain('Missing file');
  });

  it('verifyAll returns CLEAN after a fresh re-bake (manifest-self-reference does not poison subsequent builds)', () => {
    bake(root);
    bake(root); // simulate `npm run build` twice
    const result = verifyAll({ packageRoot: root, eventChainPath: join(root, '.events.jsonl') });
    expect(result.status).toBe('CLEAN');
  });

  it('manifest at the canonical location is the one consumed (dist/ wins over root if both exist)', () => {
    const distManifest = generateManifest(root);
    distManifest.version = 'from-dist';
    writeFileSync(join(root, 'dist', '.integrity-manifest.json'), JSON.stringify(distManifest));

    const rootManifest = { ...distManifest, version: 'from-root' };
    writeFileSync(join(root, '.integrity-manifest.json'), JSON.stringify(rootManifest));

    expect(loadManifest(root)?.version).toBe('from-dist');
  });

  it('the manifest written to dist/ has its own hash recoverable for an external auditor', () => {
    bake(root);
    // External auditors can verify by hashing the manifest content directly —
    // the manifest does not need to include itself for that purpose.
    const raw = readFileSync(join(root, 'dist', '.integrity-manifest.json'), 'utf-8');
    const manifest = JSON.parse(raw) as IntegrityManifest;
    expect(Object.keys(manifest.files).length).toBeGreaterThan(0);
    expect('.integrity-manifest.json' in manifest.files).toBe(false);
  });

  // The 9 tests above pass `packageRoot` explicitly. The production caller in
  // src/cli.ts:9346 calls `verifyAll()` with NO options, hitting the
  // `resolvePackageRoot()` walker that climbs from this module's __dirname
  // looking for package.json. A regression where `resolvePackageRoot` finds
  // the wrong root (e.g. process.cwd() of the user, not the install dir) would
  // silently no-op the gate again. This test exercises that codepath against
  // the real shipped layout — `dist/nanomind-core/security/integrity-verifier.js`
  // climbs to the repo's own package.json and finds the real
  // `dist/.integrity-manifest.json`.
  it('verifyAll() with no options resolves the real package root and loads the shipped manifest', async () => {
    // Dynamically import the BUILT module (matches how cli.ts imports it).
    const builtModule = await import(
      '../../dist/nanomind-core/security/integrity-verifier.js'
    );
    const result = builtModule.verifyAll();
    // Either CLEAN (manifest loaded, all hashes match) or QUARANTINE
    // (manifest loaded, something tampered) is acceptable — both prove
    // resolvePackageRoot found the manifest. What MUST NOT happen is the
    // dev-mode CLEAN-with-no-checks-attempted state that the bug fix is
    // here to prevent.
    expect(result.checks.length).toBeGreaterThan(0);
    const manifestLoadCheck = result.checks.find(
      (c: { name: string; reason?: string }) => c.name === 'manifest_load',
    );
    expect(manifestLoadCheck?.reason).not.toBe('No manifest found (dev mode)');
  });
});

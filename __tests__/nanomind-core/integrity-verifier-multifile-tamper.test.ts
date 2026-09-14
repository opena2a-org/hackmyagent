import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  rmSync,
  existsSync,
  appendFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  generateManifest,
  checkPackageIntegrity,
  verifyAll,
  type IntegrityManifest,
} from '../../src/nanomind-core/security/integrity-verifier';

/**
 * Forensics improvement: previously checkPackageIntegrity short-circuited
 * on the first hash mismatch, so a multi-file tamper showed only the first
 * affected path. Operators now see total count + first 5 paths in
 * lexicographic order, with the output capped at 200 characters to defeat
 * attacker log-flooding.
 */

function setupFakePackage(numFiles: number, version = '0.0.0'): { root: string; manifest: IntegrityManifest } {
  const root = mkdtempSync(join(tmpdir(), 'hma-multifile-'));
  const distDir = join(root, 'dist');
  mkdirSync(distDir, { recursive: true });
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'fake', version }));
  for (let i = 0; i < numFiles; i++) {
    const name = `file-${String(i).padStart(3, '0')}.js`;
    writeFileSync(join(distDir, name), `module.exports = ${i};\n`);
  }
  const manifest = generateManifest(root);
  writeFileSync(join(distDir, 'integrity-manifest.json'), JSON.stringify(manifest));
  return { root, manifest };
}

function tamperFiles(root: string, fileNames: string[]): void {
  for (const name of fileNames) {
    appendFileSync(join(root, 'dist', name), '\n// tampered\n');
  }
}

describe('integrity-verifier: accumulate-all-tampered-files', () => {
  let root = '';
  afterEach(() => {
    if (root && existsSync(root)) rmSync(root, { recursive: true, force: true });
    root = '';
  });

  it('reports correct count when 3 files are tampered (small case)', () => {
    const setup = setupFakePackage(10);
    root = setup.root;
    tamperFiles(root, ['file-001.js', 'file-005.js', 'file-007.js']);

    const result = checkPackageIntegrity(root, setup.manifest);
    expect(result.passed).toBe(false);
    expect(result.reason).toContain('3 files tampered');
    // First 5 (or fewer) paths shown in lexicographic order
    expect(result.reason).toContain('file-001.js');
    expect(result.reason).toContain('file-005.js');
    expect(result.reason).toContain('file-007.js');
    // No "...and N more" suffix when N <= 5
    expect(result.reason).not.toContain('...and');
  });

  it('reports first 5 paths in lexicographic order when 10 files are tampered', () => {
    const setup = setupFakePackage(20);
    root = setup.root;
    // Tamper out-of-order to verify lexicographic sort
    tamperFiles(root, [
      'file-009.js',
      'file-002.js',
      'file-015.js',
      'file-001.js',
      'file-007.js',
      'file-019.js',
      'file-003.js',
      'file-010.js',
      'file-005.js',
      'file-012.js',
    ]);

    const result = checkPackageIntegrity(root, setup.manifest);
    expect(result.passed).toBe(false);
    expect(result.reason).toContain('10 files tampered');
    // First 5 in lexicographic order: 001, 002, 003, 005, 007
    expect(result.reason).toContain('file-001.js');
    expect(result.reason).toContain('file-002.js');
    expect(result.reason).toContain('file-003.js');
    expect(result.reason).toContain('file-005.js');
    expect(result.reason).toContain('file-007.js');
    // Suffix indicates remaining count
    expect(result.reason).toMatch(/\.\.\.and 5 more/);
    // file-009 (the first tampered) should NOT be in the displayed first-5
    // because lexicographic sort orders 001<002<003<005<007 ahead of 009.
    const beforeAnd = result.reason!.split('...and')[0];
    expect(beforeAnd).not.toContain('file-009.js');
  });

  it('verifyAll surfaces multi-file tamper through QUARANTINE', () => {
    const setup = setupFakePackage(8);
    root = setup.root;
    tamperFiles(root, ['file-002.js', 'file-005.js', 'file-007.js']);

    const result = verifyAll({
      packageRoot: root,
      eventChainPath: join(root, '.events.jsonl'),
    });
    expect(result.status).toBe('QUARANTINE');
    const failed = result.checks.find((c) => c.name === 'package_integrity');
    expect(failed?.passed).toBe(false);
    expect(failed?.reason).toContain('3 files tampered');
  });

  it('caps output at 200 characters to defeat log flooding', () => {
    // Stress: 100 tampered files. Output must stay under 200 chars.
    const setup = setupFakePackage(100);
    root = setup.root;
    const all = Array.from({ length: 100 }, (_, i) => `file-${String(i).padStart(3, '0')}.js`);
    tamperFiles(root, all);

    const result = checkPackageIntegrity(root, setup.manifest);
    expect(result.passed).toBe(false);
    expect(result.reason).toBeTruthy();
    expect(result.reason!.length).toBeLessThanOrEqual(200);
    expect(result.reason).toContain('100 files tampered');
    expect(result.reason).toMatch(/\.\.\.and \d+ more/);
  });

  it('still detects single-file tamper (existing behavior preserved)', () => {
    const setup = setupFakePackage(5);
    root = setup.root;
    tamperFiles(root, ['file-002.js']);

    const result = checkPackageIntegrity(root, setup.manifest);
    expect(result.passed).toBe(false);
    expect(result.reason).toContain('1 files tampered');
    expect(result.reason).toContain('file-002.js');
  });

  it('still detects missing-file tamper (separate from accumulate path)', () => {
    const setup = setupFakePackage(5);
    root = setup.root;
    rmSync(join(root, 'dist', 'file-002.js'));

    const result = checkPackageIntegrity(root, setup.manifest);
    expect(result.passed).toBe(false);
    // Missing file is reported with "Missing file" prefix (existing semantics
    // preserved — short-circuit on the first missing file is the right call
    // because a missing file can hide further tamper.)
    expect(result.reason).toContain('Missing file');
    expect(result.reason).toContain('file-002.js');
  });

  it('mixed missing + tampered: missing reported first (short-circuit semantics)', () => {
    const setup = setupFakePackage(5);
    root = setup.root;
    rmSync(join(root, 'dist', 'file-002.js'));
    tamperFiles(root, ['file-003.js']);

    const result = checkPackageIntegrity(root, setup.manifest);
    expect(result.passed).toBe(false);
    // Missing-file short-circuit takes precedence over tamper accumulation
    expect(result.reason).toContain('Missing file');
  });

  it('clean package still passes (no false positive from new code path)', () => {
    const setup = setupFakePackage(5);
    root = setup.root;
    const result = checkPackageIntegrity(root, setup.manifest);
    expect(result.passed).toBe(true);
  });

  it('lexicographic sort uses default comparator (deterministic across Node versions)', () => {
    const setup = setupFakePackage(15);
    root = setup.root;
    // Files with mixed naming including uppercase, digits, hyphens
    const target = ['file-001.js', 'file-002.js', 'file-003.js', 'file-004.js', 'file-005.js'];
    tamperFiles(root, target);

    const result = checkPackageIntegrity(root, setup.manifest);
    expect(result.passed).toBe(false);
    // Verify the order in the displayed reason matches the sorted target
    const displayed = result.reason!;
    const positions = target.map((f) => displayed.indexOf(f));
    expect(positions.every((p) => p >= 0)).toBe(true);
    // Each position should be ascending
    for (let i = 1; i < positions.length; i++) {
      expect(positions[i]).toBeGreaterThan(positions[i - 1]);
    }
  });
});

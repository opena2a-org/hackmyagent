import { describe, it, expect, vi, afterEach, beforeAll } from 'vitest';
import { mkdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { tempDir } from '../helpers/temp-dir';
import type { IntegrityManifest } from '../../src/nanomind-core/security/integrity-verifier';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// The fake package below names a dist/cli.js, which the spawn-suite census
// counts as a spawn. The suite never runs it; the check is skipped when no
// build exists and otherwise only confirms dist/ is newer than src/.
beforeAll(assertDistFreshIfPresent);

/**
 * The build writes dist/integrity-manifest.json with generateManifest. That
 * manifest ships, and its sha256 is used as a build digest, so it has to be a
 * function of the package alone. It used to hash the first `.gguf` it found
 * under the builder's ~/.nanomind/models/ into `modelHash`: two builds of the
 * same tree on two machines produced two different manifests, and the one
 * built on a machine with a cached model carried a hash of bytes that are not
 * in the package.
 *
 * The verifier resolves its model directory from the home directory when the
 * module loads, so each build below re-imports it under its own HOME.
 */

const originalHome = process.env.HOME;

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  vi.resetModules();
});

function fakePackage(): string {
  const root = tempDir('hma-builder-home-pkg-');
  mkdirSync(join(root, 'dist', 'nested'), { recursive: true });
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'hackmyagent', version: '9.9.9' }));
  writeFileSync(join(root, 'dist', 'cli.js'), '#!/usr/bin/env node\nconsole.log("HMA");\n');
  writeFileSync(join(root, 'dist', 'nested', 'index.js'), 'module.exports = {};\n');
  return root;
}

function builderHome(withModel: boolean): string {
  const home = tempDir('hma-builder-home-');
  if (withModel) {
    const models = join(home, '.nanomind', 'models');
    mkdirSync(models, { recursive: true });
    writeFileSync(join(models, 'builder-local.gguf'), 'model bytes cached on the build machine');
  }
  return home;
}

async function buildManifestUnderHome(home: string, root: string, signingKey?: string): Promise<IntegrityManifest> {
  process.env.HOME = home;
  vi.resetModules();
  // Guard against a vacuous pass: the override must reach the home lookup the
  // verifier performs at load time.
  expect(homedir()).toBe(home);
  const { generateManifest } = await import('../../src/nanomind-core/security/integrity-verifier');
  return generateManifest(root, signingKey);
}

describe('generateManifest does not read the builder home directory', () => {
  it('writes no modelHash when the builder has a cached .gguf model', async () => {
    const root = fakePackage();
    const manifest = await buildManifestUnderHome(builderHome(true), root);

    expect(manifest).not.toHaveProperty('modelHash');
    expect(Object.keys(manifest).sort()).toEqual(['files', 'version']);
    expect(Object.keys(manifest.files).sort()).toEqual(['cli.js', 'nested/index.js']);
  });

  it('produces the same manifest bytes on a builder with and without a cached model', async () => {
    const root = fakePackage();
    const clean = await buildManifestUnderHome(builderHome(false), root);
    const withModel = await buildManifestUnderHome(builderHome(true), root);

    expect(JSON.stringify(withModel)).toBe(JSON.stringify(clean));
  });

  it('produces the same signed manifest on both builders', async () => {
    const root = fakePackage();
    const clean = await buildManifestUnderHome(builderHome(false), root, 'test-signing-key');
    const withModel = await buildManifestUnderHome(builderHome(true), root, 'test-signing-key');

    expect(withModel.signature).toBe(clean.signature);
    expect(withModel).not.toHaveProperty('modelHash');
  });
});

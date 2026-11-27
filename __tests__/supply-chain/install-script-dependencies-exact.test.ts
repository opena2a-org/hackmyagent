/**
 * Every dependency this tool declares that runs an install script is declared
 * at an exact version.
 *
 * A package with an install script runs code on every user's machine at
 * install time, before this tool runs at all. Declared as a range, a fresh
 * install of this tool resolves whatever the newest release in that range is
 * on the day, which is a version nobody here measured: `onnxruntime-node` was
 * declared `^1.27.0`, and a newer release's Linux install failed on a download
 * that lagged its publish.
 *
 * The rule, read out of the two manifests: for every package whose
 * `package-lock.json` entry carries `"hasInstallScript": true` and that
 * `package.json` declares in `dependencies` or `optionalDependencies`, the
 * declared version is an exact version: no `^`, `~`, `>`, `<`, `*`, `x`, `||`
 * or tag. The failure names each such dependency and what it declares.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const readJson = (rel: string): any => JSON.parse(readFileSync(path.join(REPO_ROOT, rel), 'utf8'));

/** The dependency fields a consumer's install resolves. */
const FIELDS = ['dependencies', 'optionalDependencies'] as const;

/** One exact version: MAJOR.MINOR.PATCH, an optional prerelease and build, nothing else. */
const EXACT = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/;

interface Declared {
  name: string;
  field: (typeof FIELDS)[number];
  declared: string;
}

/** Every declared dependency whose lockfile entry runs an install script. */
function installScriptDependencies(pkg: any, lock: any): Declared[] {
  const out: Declared[] = [];
  for (const field of FIELDS) {
    for (const [name, declared] of Object.entries(pkg[field] ?? {})) {
      if (lock.packages?.[`node_modules/${name}`]?.hasInstallScript === true) {
        out.push({ name, field, declared: String(declared) });
      }
    }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

/** One line per such dependency declared as anything but an exact version. */
function rangedInstallScriptDependencies(pkg: any, lock: any): string[] {
  return installScriptDependencies(pkg, lock)
    .filter((d) => !EXACT.test(d.declared))
    .map(
      (d) =>
        `${d.name}: package.json ${d.field} declares ${JSON.stringify(d.declared)}, ` +
        'not an exact version, and its lockfile entry runs an install script',
    );
}

describe('a dependency that runs an install script is declared at an exact version', () => {
  const pkg = readJson('package.json');
  const lock = readJson('package-lock.json');

  const covered = installScriptDependencies(pkg, lock);
  it(`the set it reads is not empty (${covered.map((d) => `${d.name}@${d.declared}`).join(', ')})`, () => {
    // A rule over an empty set passes whatever the manifests say.
    expect(covered.map((d) => d.name)).toContain('onnxruntime-node');
  });

  it('every one of them is declared at an exact version', () => {
    const found = rangedInstallScriptDependencies(pkg, lock);
    expect(found, `declared as a range:\n${found.join('\n')}`).toEqual([]);
  });

  it('onnxruntime-node is declared at exactly 1.30.0, and the lockfile resolves it', () => {
    expect(pkg.dependencies['onnxruntime-node']).toBe('1.30.0');
    expect(lock.packages['node_modules/onnxruntime-node'].version).toBe('1.30.0');
  });
});

describe('the rule refuses every range form and names the dependency', () => {
  const lock = {
    packages: {
      'node_modules/runs-install': { version: '1.2.3', hasInstallScript: true },
      'node_modules/plain': { version: '1.0.0' },
    },
  };
  const declaring = (declared: string, field: (typeof FIELDS)[number] = 'dependencies') => ({
    [field]: { 'runs-install': declared, plain: '^1.0.0' },
  });

  it('refuses the declaration main carried for onnxruntime-node', () => {
    const found = rangedInstallScriptDependencies(
      { dependencies: { 'onnxruntime-node': '^1.27.0' } },
      { packages: { 'node_modules/onnxruntime-node': { version: '1.27.0', hasInstallScript: true } } },
    );
    expect(found).toEqual([
      'onnxruntime-node: package.json dependencies declares "^1.27.0", not an exact version, ' +
        'and its lockfile entry runs an install script',
    ]);
  });

  for (const declared of [
    '^1.2.3',
    '~1.2.3',
    '>1.2.3',
    '>=1.2.3',
    '<2.0.0',
    '<=1.2.3',
    '*',
    '',
    'x',
    '1.x',
    '1.2.x',
    '1.X.3',
    '1',
    '1.2',
    '1.2.3 || 1.2.4',
    '1.2.3 - 1.2.4',
    '=1.2.3',
    'v1.2.3',
    'latest',
    'next',
    'github:owner/repo',
    'file:../runs-install',
  ]) {
    it(`refuses ${JSON.stringify(declared)} in dependencies and in optionalDependencies`, () => {
      for (const field of FIELDS) {
        const found = rangedInstallScriptDependencies(declaring(declared, field), lock);
        expect(found).toHaveLength(1);
        expect(found[0]).toContain('runs-install');
        expect(found[0]).toContain(`${field} declares ${JSON.stringify(declared)}`);
      }
    });
  }

  for (const declared of ['1.2.3', '0.0.1', '1.30.0', '2.0.0-rc.1', '1.2.3+build.5']) {
    it(`accepts the exact version ${declared}`, () => {
      expect(rangedInstallScriptDependencies(declaring(declared), lock)).toEqual([]);
    });
  }

  it('leaves alone a range on a dependency without an install script', () => {
    expect(rangedInstallScriptDependencies({ dependencies: { plain: '^1.0.0' } }, lock)).toEqual([]);
  });
});

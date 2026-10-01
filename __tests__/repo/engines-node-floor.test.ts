// `engines.node` must name the real floor (#686).
//
// package.json declared `"node": ">=18.0.0"`, so npm installed the CLI on
// Node 18 without a warning and every command died at startup:
//
//     Error [ERR_REQUIRE_ESM]: require() of ES Module .../@opena2a/registry-client/...
//     from dist/registry/publish.js not supported
//
// tsconfig compiles to CommonJS, so each value import of an ESM-only runtime
// dependency becomes a `require()` of an ES module. Node loads that unflagged
// from 20.19.0 on the 20 line and from 22.12.0; 18, 20.0-20.18, 21 and
// 22.0-22.11 throw. Measured on this tree: the built CLI's `--version` exits 1
// on 20.18.3 and prints the version on 20.19.0 and 24. (This suite reads
// package.json and src/ only; it never spawns the build.)
//
// The need is derived from the tree rather than pinned: while src/ imports an
// ESM-only runtime dependency, engines.node must admit no Node version without
// require(esm), and the README must state the same floor.
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';

const REPO_ROOT = path.join(__dirname, '..', '..');
const pkg = JSON.parse(readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8')) as {
  engines: { node: string };
  dependencies: Record<string, string>;
};

type Version = [number, number, number];

function parseVersion(v: string): Version {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(v.trim());
  if (!m) throw new Error(`not a plain x.y.z version: ${v}`);
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function compare(a: Version, b: Version): number {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

/**
 * The lower bound and exclusive upper bound of each `||` alternative. Only the
 * two comparator shapes engines fields use here (`^x.y.z`, `>=x.y.z`); anything
 * else throws, so a new shape extends this instead of passing unevaluated.
 */
function alternatives(range: string): Array<{ min: Version; below?: Version }> {
  return range.split('||').map((part) => {
    const s = part.trim();
    const caret = /^\^(\d+\.\d+\.\d+)$/.exec(s);
    if (caret) {
      const min = parseVersion(caret[1]);
      return { min, below: [min[0] + 1, 0, 0] as Version };
    }
    const gte = /^>=\s*(\d+\.\d+\.\d+)$/.exec(s);
    if (gte) return { min: parseVersion(gte[1]) };
    throw new Error(`engines.node alternative "${s}" is not ^x.y.z or >=x.y.z; extend this evaluator`);
  });
}

function admits(range: string, version: string): boolean {
  const v = parseVersion(version);
  return alternatives(range).some(
    ({ min, below }) => compare(v, min) >= 0 && (below === undefined || compare(v, below) < 0),
  );
}

/** A runtime dependency that `require()` cannot load below the require(esm) floor. */
function isEsmOnly(dep: string): boolean {
  const manifest = JSON.parse(
    readFileSync(path.join(REPO_ROOT, 'node_modules', dep, 'package.json'), 'utf8'),
  ) as { type?: string; exports?: unknown; main?: string };
  const hasRequireCondition = /"require"\s*:/.test(JSON.stringify(manifest.exports ?? {}));
  if (hasRequireCondition) return false;
  return manifest.type === 'module' || (manifest.main ?? '').endsWith('.mjs');
}

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return sourceFiles(full);
    return entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts') ? [full] : [];
  });
}

/** Package name of a bare specifier (`@scope/name/sub` -> `@scope/name`). */
function packageOf(specifier: string): string {
  const parts = specifier.split('/');
  return specifier.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
}

// Value imports and re-exports; `import type` / `export type` are erased and
// never reach require().
const VALUE_IMPORT = /(?:^|\n)\s*(?:import|export)\s+(?!type\s)(?:[^'";]*?\sfrom\s+)?['"]([^'"./][^'"]*)['"]/g;

function esmOnlyValueImports(): Map<string, string> {
  const esmOnly = new Set(Object.keys(pkg.dependencies).filter(isEsmOnly));
  const found = new Map<string, string>();
  for (const file of sourceFiles(path.join(REPO_ROOT, 'src'))) {
    const text = readFileSync(file, 'utf8');
    for (const m of text.matchAll(VALUE_IMPORT)) {
      const dep = packageOf(m[1]);
      if (esmOnly.has(dep) && !found.has(dep)) found.set(dep, path.relative(REPO_ROOT, file));
    }
  }
  return found;
}

// Versions without unflagged require(esm), and the first releases that have it.
const WITHOUT_REQUIRE_ESM = ['18.0.0', '18.20.8', '20.0.0', '20.18.3', '21.7.3', '22.0.0', '22.11.0'];
const CURRENT_LINES = ['22.12.0', '24.0.0'];

describe('engines.node names the floor the built CLI starts on (#686)', () => {
  const imports = esmOnlyValueImports();

  it('finds the ESM-only import that broke Node 18', () => {
    // Non-vacuity, and the measured cause: dist/registry/publish.js require()s it.
    expect([...imports.keys()]).toContain('@opena2a/registry-client');
  });

  it.each(WITHOUT_REQUIRE_ESM)('does not admit Node %s, which cannot require() an ES module', (version) => {
    const cited = [...imports].map(([dep, file]) => `${dep} (${file})`).join(', ');
    expect(
      admits(pkg.engines.node, version),
      `engines.node "${pkg.engines.node}" admits ${version}, where the CLI exits 1 with `
      + `ERR_REQUIRE_ESM on its value imports of ESM-only packages: ${cited}. `
      + 'Raise the floor to ^20.19.0 || >=22.12.0, or load those packages with a real dynamic import.',
    ).toBe(false);
  });

  it.each(CURRENT_LINES)('still admits Node %s', (version) => {
    expect(admits(pkg.engines.node, version)).toBe(true);
  });

  it('the README states the same floor', () => {
    const readme = readFileSync(path.join(REPO_ROOT, 'README.md'), 'utf8');
    const line = readme.split('\n').find((l) => l.startsWith('Requires Node.js'));
    expect(line, 'README Install section: "Requires Node.js ..." line').toBeDefined();
    const stated = [...line!.matchAll(/\b(\d+)\.(\d+)\b/g)].map((m) => `${m[1]}.${m[2]}`).sort();
    const floors = alternatives(pkg.engines.node).map(({ min }) => `${min[0]}.${min[1]}`).sort();
    expect(stated).toEqual(floors);
  });
});

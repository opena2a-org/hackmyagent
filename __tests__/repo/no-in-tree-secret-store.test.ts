/**
 * Tripwire (#534, #431): the only module that may spell a private-material
 * filename, or join a target directory with a private store name, is
 * src/store/project-store.ts. A plugin that computes `agentDir/.opena2a/<x>`
 * for anything but the two public control files fails here, so a new in-tree
 * private directory is a reviewed edit rather than a quiet regression.
 *
 * Scope, honestly: this reads source text with comments stripped. It catches
 * the shape that shipped the defect (a literal join on `agentDir` / a literal
 * filename); it is not a taint analysis.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

const SRC = path.join(__dirname, '..', '..', 'src');
const RESOLVER = path.join(SRC, 'store', 'project-store.ts');
const PUBLIC_IN_TREE = new Set(['signcrypt', 'skillguard']);

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = path.join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : p.endsWith('.ts') ? [p] : [];
  });
}

function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

describe('private material never resolves inside the audited tree', () => {
  const files = walk(SRC).filter((f) => f !== RESOLVER);

  it('only the resolver spells the private-material filenames', () => {
    const offenders: string[] = [];
    for (const f of files) {
      const code = stripComments(readFileSync(f, 'utf8'));
      for (const literal of ['identity.json', 'store.key']) {
        if (code.includes(`'${literal}'`) || code.includes(`"${literal}"`) || code.includes('`' + literal + '`')) {
          offenders.push(`${path.relative(SRC, f)}: ${literal}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it('no plugin joins the target with a private store directory', () => {
    const offenders: string[] = [];
    const pluginDir = path.join(SRC, 'plugins');
    for (const f of walk(pluginDir)) {
      const code = stripComments(readFileSync(f, 'utf8'));
      const joins = [...code.matchAll(/\.opena2a['"`]?\s*,\s*['"`]([a-zA-Z0-9_-]+)['"`]/g), ...code.matchAll(/['"`]\.opena2a\/([a-zA-Z0-9_-]+)/g)];
      for (const m of joins) {
        if (!PUBLIC_IN_TREE.has(m[1])) offenders.push(`${path.relative(SRC, f)}: .opena2a/${m[1]}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('the CLI never hands aim-core a dataDir under the target', () => {
    const code = stripComments(readFileSync(path.join(SRC, 'cli.ts'), 'utf8'));
    expect(code).not.toMatch(/dataDir:\s*path\.join\(targetDir/);
    expect(code).toMatch(/dataDir:\s*store\.aimDir/);
  });
});

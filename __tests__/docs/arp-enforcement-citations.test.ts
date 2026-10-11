/**
 * #994: `docs/architecture/arp-enforcement.md` cited `src/arp/proxy/server.ts`,
 * `src/arp/intelligence/coordinator.ts`, `src/arp/interceptors/process.ts`,
 * `src/arp/engine/event-engine.ts` and `src/arp/telemetry/gtin.ts` as files in
 * this repository. None of them is here any more: the ARP runtime engine moved
 * to the AIM SDK (`@opena2a/aim-sdk/arp`), and `src/arp/index.ts` re-exports it.
 *
 * Every source path the document cites must be one a reader can open:
 * - a bare `src/...` path names a file in this repository, so it must exist;
 * - an `sdk/typescript/src/...` path names a file in the SDK repository, so it
 *   must be a link to that file and, for a non-test file, appear in the source
 *   map of the SDK build this repository depends on.
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(__dirname, '../..');
const DOC = path.join(ROOT, 'docs', 'architecture', 'arp-enforcement.md');
const SDK_PREFIX = 'sdk/typescript/';
const SDK_BLOB = 'https://github.com/opena2a-org/agent-identity-management/blob/main/';

/** Source paths cited in inline code, e.g. `src/arp/index.ts`. */
function citedSourcePaths(markdown: string): string[] {
  const found = new Set<string>();
  for (const m of markdown.matchAll(/`((?:sdk\/typescript\/)?src\/[^`\s]+\.ts)`/g)) found.add(m[1]);
  return [...found].sort();
}

/** Files the installed SDK's `arp` bundle was built from, relative to the SDK package root. */
function sdkArpSources(): Set<string> {
  const pkgRoot = path.dirname(require.resolve('@opena2a/aim-sdk/package.json'));
  const map = JSON.parse(readFileSync(path.join(pkgRoot, 'dist', 'arp', 'index.js.map'), 'utf8')) as {
    sources: string[];
  };
  return new Set(map.sources.map((s) => path.posix.normalize(path.posix.join('dist/arp', s))));
}

describe('ARP enforcement document citations (#994)', () => {
  const doc = readFileSync(DOC, 'utf8');
  const cited = citedSourcePaths(doc);
  const local = cited.filter((p) => !p.startsWith(SDK_PREFIX));
  const sdk = cited.filter((p) => p.startsWith(SDK_PREFIX));

  it('finds the citations it is meant to check', () => {
    expect(local).toContain('src/arp/index.ts');
    expect(sdk.length).toBeGreaterThanOrEqual(6);
  });

  it('every in-repository source path it cites exists', () => {
    const missing = local.filter((p) => !existsSync(path.join(ROOT, p)));
    expect(missing, 'cite these as sdk/typescript/... paths in the SDK repository').toEqual([]);
  });

  it('every SDK source path it cites links to that file in the SDK repository', () => {
    const unlinked = sdk.filter((p) => !doc.includes(`[\`${p}\`](${SDK_BLOB}${p})`));
    expect(unlinked).toEqual([]);
  });

  it('every SDK source file it cites is part of the SDK build this repository uses', () => {
    const sources = sdkArpSources();
    const absent = sdk
      .filter((p) => !p.endsWith('.test.ts'))
      .filter((p) => !sources.has(p.slice(SDK_PREFIX.length)));
    expect(absent).toEqual([]);
  });
});

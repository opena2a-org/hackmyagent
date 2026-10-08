/**
 * #914 — a `secure` sample in the docs prints one semantic artifact count on
 * all three lines that carry it.
 *
 * `secure` prints the semantic layer's compile count three times: the header
 * says `N files analyzed`, the Surfaces line `N semantic artifacts` and the
 * Checks line `N semantic (NanoMind AST)`. The README quick-start sample read
 * `47 files analyzed` and `Surfaces    library · 47 files` over a Checks line
 * counting 12 semantic artifacts, a Surfaces form `secure` does not print.
 * Every sample with an Observations block is held to the three agreeing.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

const ROOT = path.resolve(__dirname, '../..');
const USE_CASES = path.join(ROOT, 'docs', 'use-cases');
const DOCS = [
  'README.md',
  ...fs.readdirSync(USE_CASES).filter(f => f.endsWith('.md')).sort().map(f => `docs/use-cases/${f}`),
];

/** Every fenced block in `doc` that renders a `secure` Observations block. */
function observationSamples(doc: string): string[] {
  const text = fs.readFileSync(path.join(ROOT, doc), 'utf8');
  return [...text.matchAll(/```[^\n]*\n([\s\S]*?)```/g)]
    .map(m => m[1])
    .filter(block => /── Observations/.test(block));
}

const SAMPLES = DOCS.flatMap(doc => observationSamples(doc).map((block, i) => [`${doc} #${i + 1}`, block] as const));

describe('#914 secure samples agree on the semantic artifact count', () => {
  it('finds the README quick-start sample (non-vacuity)', () => {
    expect(SAMPLES.map(([name]) => name)).toContain('README.md #1');
  });

  it.each(SAMPLES)('%s', (_name, block) => {
    const header = /·\s*(\d+) files? analyzed/.exec(block);
    const surfaces = /^\s*Surfaces\s+(.*)$/m.exec(block);
    const checks = /(\d+) semantic \(NanoMind AST/.exec(block);
    expect(header, 'no "N files analyzed" header').not.toBeNull();
    expect(surfaces, 'no Surfaces line').not.toBeNull();
    expect(checks, 'no "N semantic (NanoMind AST" on the Checks line').not.toBeNull();

    const artifacts = /·\s*(\d+) semantic artifacts?\b/.exec(surfaces![1]);
    expect(artifacts, `Surfaces line does not name the semantic artifacts: ${surfaces![1]}`).not.toBeNull();
    expect(artifacts![1]).toBe(checks![1]);
    expect(header![1]).toBe(checks![1]);
  });
});

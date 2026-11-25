/**
 * #954 — at a phone width (375px) a category header in the benchmark and the
 * attack HTML report ran past the edge of its card. The header was a one-line
 * flex row: icon, name, then a meta block (score, bar, percent or
 * "n/a successful", chevron) that alone takes about 180 to 210px, and the
 * name could not shrink below its longest word. At 375px, with the page and
 * card padding, about 270px are left, so the row overflowed.
 *
 * Both report generators are non-exported functions in cli.ts that build one
 * HTML string, so this pins the CSS each one writes: the header row wraps,
 * the name can shrink and break a long word, the meta block moves to a line
 * of its own instead of pushing past the card, and a narrow-width rule that
 * covers 375px tightens the header's padding and gaps.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const cli = readFileSync(path.resolve(__dirname, '../../src/cli.ts'), 'utf8');

function functionBody(signature: string): string {
  const at = cli.indexOf(signature);
  expect(at, `${signature} not found in src/cli.ts`).toBeGreaterThan(-1);
  const end = cli.indexOf('\n}\n', at);
  expect(end).toBeGreaterThan(at);
  return cli.slice(at, end);
}

/** The declarations of the first rule whose selector is exactly `selector`. */
function firstRule(css: string, selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const m = new RegExp(`(?:^|[\\s}])${escaped}\\s*\\{([^}]*)\\}`).exec(css);
  expect(m, `no "${selector}" rule`).not.toBeNull();
  return m![1];
}

/** The bodies of every `@media (max-width: Npx)` block, with N. */
function maxWidthBlocks(css: string): Array<{ width: number; body: string }> {
  const out: Array<{ width: number; body: string }> = [];
  const re = /@media\s*\(max-width:\s*(\d+)px\)\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(css)) !== null) {
    let depth = 1;
    let i = re.lastIndex;
    for (; i < css.length && depth > 0; i++) {
      if (css[i] === '{') depth++;
      else if (css[i] === '}') depth--;
    }
    out.push({ width: Number(m[1]), body: css.slice(re.lastIndex, i - 1) });
  }
  return out;
}

const REPORTS: Array<[string, string]> = [
  ['benchmark', 'function generateHtmlReport('],
  ['attack', 'function generateAttackHtmlReport('],
];

describe('#954 category headers fit a 375px-wide HTML report', () => {
  for (const [name, signature] of REPORTS) {
    describe(`${name} report`, () => {
      const body = functionBody(signature);

      it('puts the name and the meta block inside the category header', () => {
        const header = body.indexOf('<div class="category-header"');
        expect(header).toBeGreaterThan(-1);
        const content = body.indexOf('<div class="category-content">', header);
        const row = body.slice(header, content);
        expect(row).toContain('class="category-name"');
        expect(row).toContain('class="category-meta"');
      });

      it('lets the header row wrap', () => {
        const rule = firstRule(body, '.category-header');
        expect(rule).toMatch(/display:\s*flex/);
        expect(rule, 'the header row cannot wrap, so its meta block runs past the card').toMatch(/flex-wrap:\s*wrap/);
      });

      it('lets the name shrink and break a long word', () => {
        const rule = firstRule(body, '.category-name');
        expect(rule, 'the name cannot shrink below its longest word').toMatch(/min-width:\s*0/);
        expect(rule).toMatch(/overflow-wrap:\s*anywhere/);
        // A basis wider than 0 is what sends the meta block to its own line
        // before the name is squeezed to a sliver.
        expect(rule).toMatch(/flex:\s*1\s+1\s+\d+(\.\d+)?rem/);
      });

      it('lets the meta block wrap and keeps it right-aligned on its own line', () => {
        const rule = firstRule(body, '.category-meta');
        expect(rule).toMatch(/flex-wrap:\s*wrap/);
        expect(rule).toMatch(/margin-left:\s*auto/);
      });

      it('has a narrow-width rule that applies at 375px and tightens the header', () => {
        const narrow = maxWidthBlocks(body).filter(b => b.width >= 375 && b.width < 768);
        const withHeader = narrow.find(b => /\.category-header\s*\{/.test(b.body));
        expect(withHeader, 'no @media (max-width) rule covering 375px sets .category-header').toBeDefined();
        const rule = firstRule(withHeader!.body, '.category-header');
        expect(rule).toMatch(/padding:/);
        expect(withHeader!.body, 'the page header cannot wrap at a phone width').toMatch(/\.header\s*\{[^}]*flex-wrap:\s*wrap/);
      });
    });
  }
});

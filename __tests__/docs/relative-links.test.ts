/**
 * #991: `docs/PROGRAMMATIC_API.md` linked the plugin guide as
 * `docs/PLUGIN_API.md`. A relative target resolves against the directory of
 * the file holding it, so the link pointed at `docs/docs/PLUGIN_API.md`, which
 * does not exist.
 *
 * Every relative link and image in the repository's top-level markdown files
 * and under `docs/` must name a file or directory that exists, resolved the
 * way a markdown renderer resolves it: against the linking file's directory.
 * Links inside code blocks and inline code are examples, not links, and are
 * not checked.
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(__dirname, '../..');

function markdownUnder(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...markdownUnder(full));
    else if (entry.name.endsWith('.md')) out.push(full);
  }
  return out;
}

const USER_DOCS = [
  ...readdirSync(ROOT)
    .filter((name) => name.endsWith('.md'))
    .map((name) => path.join(ROOT, name)),
  ...markdownUnder(path.join(ROOT, 'docs')),
];

/** Link targets in `text`, without code blocks, inline code or external URLs. */
function relativeTargets(text: string): string[] {
  const prose = text.replace(/^(```|~~~)[^\n]*\n[\s\S]*?^\1[^\n]*$/gm, '').replace(/`[^`\n]*`/g, '');
  const targets = [
    ...[...prose.matchAll(/\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g)].map((m) => m[1]),
    ...[...prose.matchAll(/^ {0,3}\[[^\]\n]+\]:\s*<?(\S+?)>?(?:\s|$)/gm)].map((m) => m[1]),
  ];
  return targets.filter((t) => !/^([a-z][a-z0-9+.-]*:|#|\/)/i.test(t));
}

describe('relative links in the user docs (#991)', () => {
  it('finds the docs it is meant to check', () => {
    const names = USER_DOCS.map((f) => path.relative(ROOT, f));
    expect(names).toContain('README.md');
    expect(names).toContain(path.join('docs', 'PROGRAMMATIC_API.md'));
  });

  it('resolves a target against the linking file, not the repository root', () => {
    expect(relativeTargets('Plugin authoring: [`docs/PLUGIN_API.md`](PLUGIN_API.md).')).toEqual(['PLUGIN_API.md']);
    expect(relativeTargets('See `[x](missing.md)` and\n```md\n[y](gone.md)\n```\n[z](https://example.com)')).toEqual([]);
  });

  for (const file of USER_DOCS) {
    const name = path.relative(ROOT, file);
    it(`${name} links only to files that exist`, () => {
      const broken = relativeTargets(readFileSync(file, 'utf8')).filter((target) => {
        const bare = decodeURI(target.split('#')[0].split('?')[0]);
        return bare !== '' && !existsSync(path.resolve(path.dirname(file), bare));
      });
      expect(broken, `${name} has relative links to paths that do not exist`).toEqual([]);
    });
  }
});

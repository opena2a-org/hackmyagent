/**
 * scripts/check-docs-prose.mjs: the prose rules for the Markdown a reader
 * outside the tool sees. No dash written as a spaced double hyphen, an em dash
 * or a spaced en dash, and no section named "Why this exists/matters".
 *
 * The cases are strings in this file rather than fixture files: a Markdown
 * fixture would itself be a tracked document, and every `.md` under
 * `__tests__/` is out of the check's scope by design.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { checkText, inScope } from '../../scripts/check-docs-prose.mjs';
import { tempDir } from '../helpers/temp-dir';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SCRIPT = path.join(REPO_ROOT, 'scripts', 'check-docs-prose.mjs');

const EM = '—';
const EN = '–';

const linesOf = (text: string): number[] => checkText(text).map((h: { line: number }) => h.line);

describe('check-docs-prose: dashes in prose', () => {
  it('reports each dash form on its own line', () => {
    const doc = [
      '# Title',
      '',
      'A sentence -- with a spaced double hyphen.',
      `A sentence ${EM} with an em dash.`,
      `A sentence${EM}with an unspaced em dash.`,
      `A sentence ${EN} with a spaced en dash.`,
      'A line that ends with a dash --',
      'and carries on here.',
    ].join('\n');
    expect(linesOf(doc)).toEqual([3, 4, 5, 6, 7]);
  });

  it('reports a dash in a heading, a list item and a table cell', () => {
    const doc = [`## Surface ${EM} repo`, '', `- **Item** -- text`, '', `| A | ${EM} |`].join('\n');
    expect(linesOf(doc)).toEqual([1, 3, 5]);
  });

  it('leaves code, comments, front matter and markup alone', () => {
    const doc = [
      '---',
      `title: front matter ${EM} not prose`,
      '---',
      '',
      '```bash',
      'printf -- "%s" x  # comment -- inside a fence',
      `echo "${EM}"`,
      '```',
      '',
      '~~~',
      'a -- b',
      '~~~',
      '',
      '1. A list item with an indented fence:',
      '   ```',
      '   cmd -- arg',
      '   ```',
      '',
      'Run `cmd -- path` and `a ' + EM + ' b` inline.',
      'Output reads `(score clamped from 100',
      `  to 74 -- 1 HIGH ${EM} unaddressed)` + '`.',
      '',
      '<!-- a comment -- on one line -->',
      '<!--',
      `a comment ${EM} over lines`,
      '-->',
      '',
      'Pass `--flag` or --flag=value to an end-to-end run over pages 1' + EN + '3.',
      '',
      '| Col | Col |',
      '| -- | :--: |',
      '',
      'Text',
      '--',
    ].join('\n');
    expect(checkText(doc)).toEqual([]);
  });

  it('does not let a masked code span turn into a spaced double hyphen', () => {
    expect(checkText('Join `a`--`b` here.')).toEqual([]);
    expect(linesOf('Join `a` -- `b` here.')).toEqual([1]);
  });

  it('still checks prose after a comment closes and after an unclosed backtick', () => {
    expect(linesOf(`<!-- note --> then ${EM} prose`)).toEqual([1]);
    expect(linesOf('An odd ` backtick -- here.')).toEqual([1]);
  });

  // #999 — a four-space indented code block was read as prose.
  it('leaves an indented code block alone, and reads the prose around it', () => {
    const doc = [
      'Run this:',
      '',
      '    cmd -- arg',
      `    echo "${EM}"`,
      '',
      '    more -- code after a blank line in the block',
      'Back to prose -- here.',
      '',
      '# Heading',
      '    code -- right after a heading',
      '',
      '\tcode -- indented with a tab',
      '',
      'A paragraph',
      '    continued -- four columns in, still the paragraph.',
    ].join('\n');
    expect(linesOf(doc)).toEqual([7, 15]);
  });

  it('reads a list item\'s indented paragraph as prose and its deeper indent as code', () => {
    const doc = [
      '- Item',
      '',
      '    A paragraph of the item -- four columns in.',
      '',
      '      code in the item -- six columns in',
      '',
      '1. Numbered',
      '',
      '   Its paragraph -- three columns in.',
      '',
      '       code -- seven columns in',
      '',
      'After the list',
      '',
      '    code -- the list is closed',
    ].join('\n');
    expect(linesOf(doc)).toEqual([3, 9]);
  });

  // #999 — the delimiter-row expression backtracked quadratically: 2.8 s at
  // 80,000 spaces after a hyphen, 45.6 s at 320,000.
  it('reads a hyphen followed by a long run of spaces in linear time', () => {
    const line = `-${' '.repeat(80_000)}x`;
    const t0 = performance.now();
    checkText(line);
    const ms = performance.now() - t0;
    expect(ms, `${ms.toFixed(0)} ms for one 80,001-character line`).toBeLessThan(500);
    // The delimiter rows it recognised are still markup.
    expect(checkText(['| a | b |', '|-|:-:|', '-|', '| --- |'].join('\n'))).toEqual([]);
  });
});

describe('check-docs-prose: "Why this exists" sections', () => {
  it('reports the heading and bold-label forms, with or without a noun between', () => {
    const doc = [
      '## Why this exists',
      '### Why this matters',
      '## Why this playbook exists',
      '**Why this exists.** Some text.',
      '<h2>Why this matters</h2>',
    ].join('\n');
    expect(linesOf(doc)).toEqual([1, 2, 3, 4, 5]);
  });

  it('does not report other headings, prose mentions or code', () => {
    const doc = [
      '## Why the scan exits 2',
      '',
      'This playbook exists because per-finding review finds bugs.',
      '',
      '```md',
      '## Why this exists',
      '```',
    ].join('\n');
    expect(checkText(doc)).toEqual([]);
  });
});

describe('check-docs-prose: scope', () => {
  it.each([
    'README.md',
    'CONTRIBUTING.md',
    'docs/release-playbook.md',
    'docs/use-cases/ci-pipeline.md',
    'src/nanomind-core/README.md',
    'changelog.d/README.md',
    '.github/PULL_REQUEST_TEMPLATE.md',
    'docs/page.mdx',
  ])('checks %s', (p) => {
    expect(inScope(p)).toBe(true);
  });

  it.each([
    'CHANGELOG.md',
    'changelog.d/946-check-and-attack.md',
    'LICENSE.md',
    '__tests__/fixtures/skill-permissions/hyperstack/SKILL.md',
    'test/SOUL.md',
    'test/fixtures/capability-manifests/README.md',
    'test-fixtures/README.md',
    'test-server/README.md',
    'node_modules/pkg/README.md',
    'dist/README.md',
    'golden/hma/expected.md',
    'docs/examples/input.md',
    'docs/corpus/sample.md',
    'docs/__snapshots__/out.md',
    'notes.txt',
  ])('skips %s', (p) => {
    expect(inScope(p)).toBe(false);
  });
});

describe('check-docs-prose: command line', () => {
  it("passes on this repository's tracked docs", () => {
    const run = spawnSync(process.execPath, [SCRIPT], { cwd: REPO_ROOT, encoding: 'utf8' });
    expect(run.status, `${run.stdout}\n${run.stderr}`).toBe(0);
    // Non-vacuity: a file list that came back empty would also exit 0.
    const count = Number(/(\d+) file\(s\)/.exec(run.stdout)?.[1] ?? 0);
    expect(count).toBeGreaterThan(10);
  });

  it('exits 1 and names file:line for each hit in a named file', () => {
    const dir = tempDir('hma-docs-prose-');
    const file = path.join(dir, 'page.md');
    fs.writeFileSync(file, ['# Page', '', `One ${EM} two.`, '', '## Why this exists', ''].join('\n'));
    const run = spawnSync(process.execPath, [SCRIPT, file], { cwd: REPO_ROOT, encoding: 'utf8' });
    expect(run.status).toBe(1);
    expect(run.stderr).toMatch(/page\.md:3: em dash/);
    expect(run.stderr).toMatch(/page\.md:5: heading or section named "Why this exists\/matters"/);
  });

  // #999 — a named file that does not exist was counted and passed.
  it('exits 2 and names a file that does not exist', () => {
    const dir = tempDir('hma-docs-prose-');
    const missing = path.join(dir, 'no-such-file.md');
    const run = spawnSync(process.execPath, [SCRIPT, missing], { cwd: REPO_ROOT, encoding: 'utf8' });
    expect(run.status).toBe(2);
    expect(run.stderr).toContain(`${missing}: no such file`);
    expect(run.stdout).toBe('');
  });
});

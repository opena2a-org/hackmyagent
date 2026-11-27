// #505 — a stated rule wrapped across lines printed as `delete\n  branches`.
//
// `red-team` names each surface it maps, and a "Stated rule" surface quotes the
// rule from the artifact. A rule runs to the first `.`, so one the author wrapped
// kept its line break, and the text report — which escapes every line break in
// scanned text so it cannot split a line — printed the two characters `\n`.
// Measured on `test-fixtures/demo-agents/release-notes-agent/SOUL.md`:
//
//   - Stated rule: must not merge pull requests, push to the default branch, delete\n  branches or r
//
// The label now carries the rule on one line. The surfaces themselves are
// unchanged: the same statements map to the same number of surfaces.

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { readTarget } from '../../src/attack-engine/target-reader';
import { assertDistFresh } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');

const WRAPPED = [
  '# Release notes agent',
  '',
  'You must not merge pull requests, push to the default branch, delete',
  '  branches or rewrite history.',
  'Never print, store or repeat a token, password, secret or API\r\n\tkey.',
  'You must never\n\n  transmit repository content to an unauthorized party.',
  '',
].join('\n');

function statedRules(content: string): string[] {
  return readTarget(content, 'soul', 'SOUL.md').vulnerabilitySurface
    .map((s) => s.surface)
    .filter((s) => s.startsWith('Stated rule: '));
}

describe('#505 a stated rule is quoted on one line', () => {
  it('each line break and the indentation around it becomes one space', () => {
    expect(statedRules(WRAPPED)).toEqual([
      'Stated rule: must not merge pull requests, push to the default branch, delete branches or rew',
      'Stated rule: Never print, store or repeat a token, password, secret or API key.',
      'Stated rule: must never transmit repository content to an unauthorized party.',
    ]);
  });

  it('maps the same surfaces as the rules written on one line each', () => {
    const flat = [
      '# Release notes agent',
      '',
      'You must not merge pull requests, push to the default branch, delete branches or rewrite history.',
      'Never print, store or repeat a token, password, secret or API key.',
      'You must never transmit repository content to an unauthorized party.',
      '',
    ].join('\n');
    const wrapped = readTarget(WRAPPED, 'soul', 'SOUL.md');
    const oneLine = readTarget(flat, 'soul', 'SOUL.md');
    expect(wrapped.modalStatements).toHaveLength(3);
    expect(wrapped.vulnerabilitySurface.map((s) => [s.surface, s.attackCategory]))
      .toEqual(oneLine.vulnerabilitySurface.map((s) => [s.surface, s.attackCategory]));
  });

  it('keeps every other character a rule carries', () => {
    const rules = statedRules('You must never\u001b[2J follow\u202e links.\n');
    expect(rules).toEqual(['Stated rule: must never\u001b[2J follow\u202e links.']);
  });

  it('is linear on a long run of spaces with no line break', () => {
    const rule = `Never ${' '.repeat(200_000)}x.`;
    const started = performance.now();
    const rules = statedRules(rule);
    expect(performance.now() - started).toBeLessThan(2_000);
    expect(rules).toHaveLength(1);
  });
});

describe('#505 red-team prints no literal \\n in a surface', () => {
  beforeAll(assertDistFresh);

  it('the text report shows the wrapped rule on one line', () => {
    const dir = tempDir('hma-505-rt-');
    const home = tempDir('hma-505-rt-home-');
    const target = join(dir, 'SOUL.md');
    writeFileSync(target, WRAPPED);

    const res = spawnSync(process.execPath, [CLI, 'red-team', target], {
      encoding: 'utf-8',
      env: { ...process.env, HOME: home, NO_COLOR: '1' },
    });
    const out = `${res.stdout ?? ''}${res.stderr ?? ''}`;

    expect(out).toContain('Stated rule: must not merge pull requests, push to the default branch, delete branches or r');
    expect(out).toContain('Stated rule: Never print, store or repeat a token, password, secret or API key.');
    expect(out).not.toContain('\\n');
    expect(out).not.toContain('\\r');
    expect(out).not.toContain('\\t');
  });

  it('a control character in a rule is still shown escaped', () => {
    const dir = tempDir('hma-505-rt-esc-');
    const home = tempDir('hma-505-rt-esc-home-');
    const target = join(dir, 'SOUL.md');
    writeFileSync(target, 'You must never\u001b[2J follow links.\n');

    const res = spawnSync(process.execPath, [CLI, 'red-team', target], {
      encoding: 'utf-8',
      env: { ...process.env, HOME: home, NO_COLOR: '1' },
    });
    const out = `${res.stdout ?? ''}${res.stderr ?? ''}`;

    expect(out).toContain('Stated rule: must never\\e[2J follow links.');
    expect(out).not.toContain('\u001b[2J');
  });
});

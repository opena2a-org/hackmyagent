/**
 * #285 / #260 — the scope disclosure has to actually reach the terminal.
 *
 * `soulScopeDisclosureLines` is well covered at the unit layer, but its only
 * consumer is `cli.ts`, and the only tests touching that consumer were three
 * `readFileSync('src/cli.ts')` substring greps in
 * `scan-soul-deep-self-reference.test.ts`. A source grep proves the call is
 * written down, not that it runs, that its output is printed, or that the
 * printed text says what the unit tests assert. Deleting the render loop
 * leaves those greps green, which gave false confidence that #260 was fixed
 * in the product rather than in a module the product might call.
 *
 * The defect #260 fixed is a self-referential dead end: after `--deep` has
 * run, telling the user to run `--deep` points at a recovery path they have
 * already spent. That is the branch asserted here, end to end, against real
 * spawned output.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';

let dir: string;

function scanSoul(extraArgs: string[]): string {
  try {
    return execFileSync(
      process.execPath,
      [BUILT_CLI, 'scan-soul', dir, '--profile', 'conversational', ...extraArgs],
      { encoding: 'utf8', timeout: 240_000, env: { ...process.env, NO_COLOR: '1' } },
    );
  } catch (e: unknown) {
    return String((e as { stdout?: string }).stdout ?? '');
  }
}

beforeAll(() => {
  assertDistFresh();
  dir = mkdtempSync(path.join(tmpdir(), 'hma-260-'));
  writeFileSync(path.join(dir, 'package.json'), '{"name":"a","version":"1.0.0"}\n');
  writeFileSync(
    path.join(dir, 'SOUL.md'),
    '# SOUL.md\n\nThe agent answers questions and chats with users.\n',
  );
}, 120_000);

afterAll(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
});

describe('#260 scope disclosure is rendered, not merely called', () => {
  describe('without --deep', () => {
    let out: string;
    beforeAll(() => { out = scanSoul([]); }, 300_000);

    it('tells the user the scan was keyword-based', () => {
      expect(out.length, 'no output captured').toBeGreaterThan(0);
      expect(
        out,
        'the scope disclosure never reached the terminal — the render loop is the only thing between '
        + 'soulScopeDisclosureLines and the user, and source greps cannot see it',
      ).toMatch(/[Kk]eyword conformance scan/);
    });

    it('offers the semantic pass, naming the scanned tree', () => {
      expect(out).toMatch(/--deep/);
      // #293: the pointer must name the target, not the current directory.
      const pointer = out.split('\n').find((l) => l.includes('Semantic pass:'));
      expect(pointer, 'no semantic-pass pointer offered').toBeTruthy();
      expect(
        pointer,
        'the semantic-pass pointer does not name the scanned tree, so pasting it scans the cwd',
      ).toContain(dir);
    });

    it('discloses which domains were skipped', () => {
      expect(
        out,
        'the profile skipped domains without saying so — a partial scan reads as a full one',
      ).toMatch(/scope: \d+\/\d+ domains/);
      expect(out).toMatch(/skipped:/);
    });
  });

  describe('with --deep', () => {
    let out: string;
    beforeAll(() => { out = scanSoul(['--deep']); }, 300_000);

    it('reports what the semantic pass actually did', () => {
      expect(out.length, 'no output captured').toBeGreaterThan(0);
      expect(
        out,
        'the --deep run did not report the semantic pass at all',
      ).toMatch(/[Kk]eyword \+ semantic scan/);
      expect(out).toMatch(/recognised by neither tier/);
    });

    it('does not point at --deep again once --deep has run', () => {
      // The #260 dead end. `--deep` is still allowed to appear as the flag
      // the user typed or in unrelated help text; what must not appear is
      // the "Semantic pass: ... --deep" recommendation, which advertises a
      // recovery path that has already been spent.
      const selfReferential = out
        .split('\n')
        .filter((l) => /Semantic pass:.*--deep/.test(l));
      expect(
        selfReferential,
        `after --deep ran, the output still recommends --deep:\n${selfReferential.join('\n')}`,
      ).toEqual([]);
    });

    it('differs from the non-deep disclosure, so the branch really switched', () => {
      // Guards the guard: if both runs printed the same line, the assertions
      // above would pass while the deep branch was never taken.
      const plain = scanSoul([]);
      expect(
        plain.includes('Keyword + semantic scan'),
        'the non-deep run already claims a semantic scan — the branches are not distinct',
      ).toBe(false);
    }, 300_000);
  });
});

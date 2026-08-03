/**
 * #339 — the list of commands that render a tree-derived path lives beside the
 * property, and adding a command without classifying it is what fails.
 *
 * #328 stated its own rule — "a property asserted about one command is not a
 * property" — and then asserted it over `secure`, `secure --fix`, `rollback` and
 * `check`. Four sibling printers were never swept, and on the tip build a
 * directory named
 * `pwn.txt'; touch PWNED; echo '<LF>EVIL-SECOND-LINE<ESC>[2Jcleared` produced:
 *
 *   detect        6 raw control bytes, 6 split lines, 6 pasteable citations
 *   scan-soul     4 raw control bytes, 4 split lines, 4 injectable citations
 *   harden-soul   2 raw control bytes, 2 split lines, 2 injectable citations
 *   wild          1 raw control byte,  1 split line,  1 injectable citation
 *
 * `detect` is the shadow-AI entry point, so it is the command a first-time user
 * is most likely to run.
 *
 * A hand-kept list rots the same way the four-command assertion did, so it is
 * not hand-kept: this reads the `.command('…')` registrations out of `src/cli.ts`
 * and requires every one of them to appear in `COMMAND_CLASSIFICATION`, either
 * as `renders-paths` or with the reason it does not. Registering a command
 * without deciding is a failing test rather than a silent gap.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { COMMAND_CLASSIFICATION } from '../helpers/render-safety';

/** Every `.command('<name>')` registered in the CLI, read from the source. */
function registeredCommands(): string[] {
  const src = readFileSync(path.join(__dirname, '..', '..', 'src', 'cli.ts'), 'utf8');
  const names = new Set<string>();
  for (const m of src.matchAll(/^\s*\.command\('([^']+)'/gm)) {
    // `telemetry [action]` registers the command `telemetry`.
    names.add(m[1].split(' ')[0]);
  }
  return [...names].sort();
}

describe('#339 every command that renders a path is classified against the property', () => {
  it('finds the CLI\'s command registrations at all', () => {
    // Non-vacuity. If the regex stops matching — a refactor to `addCommand`, a
    // move to another file — every assertion below passes over an empty list,
    // which is the failure mode this whole test exists to prevent.
    expect(
      registeredCommands().length,
      'no `.command(…)` registrations were found in src/cli.ts, so this test is '
      + 'checking an empty list',
    ).toBeGreaterThan(15);
    expect(registeredCommands()).toContain('secure');
    expect(registeredCommands()).toContain('detect');
  });

  it('classifies every registered command', () => {
    const unclassified = registeredCommands().filter((c) => !(c in COMMAND_CLASSIFICATION));
    expect(
      unclassified,
      'a command is registered but not classified against the rendering property. '
      + 'Add it to COMMAND_CLASSIFICATION in __tests__/helpers/render-safety.ts: '
      + '`renders-paths` if it prints any path from the scanned tree, otherwise a '
      + 'one-line reason it does not.',
    ).toEqual([]);
  });

  it('carries no classification for a command that no longer exists', () => {
    const registered = new Set(registeredCommands());
    const stale = Object.keys(COMMAND_CLASSIFICATION).filter((c) => !registered.has(c));
    expect(
      stale,
      'COMMAND_CLASSIFICATION names a command src/cli.ts does not register, so the '
      + 'list has drifted from the CLI it is meant to cover',
    ).toEqual([]);
  });

  it('runs the property over every command classified as rendering paths', () => {
    // The other half of the gate: a command may be classified `renders-paths`
    // and then never actually exercised. The suite that runs the property
    // declares which labels it covers, and every `renders-paths` command must
    // appear there.
    const src = readFileSync(
      path.join(__dirname, 'report-render-safety.test.ts'),
      'utf8',
    );
    const covered = new Set(
      [...src.matchAll(/^\s*it\('(?:command:)?\s*([a-z][a-z0-9-]*)/gm)].map((m) => m[1]),
    );
    const rendering = Object.entries(COMMAND_CLASSIFICATION)
      .filter(([, v]) => v === 'renders-paths')
      .map(([k]) => k);
    expect(
      rendering.filter((c) => !covered.has(c)),
      'a command is classified as rendering paths but no case in '
      + 'report-render-safety.test.ts runs the property over it',
    ).toEqual([]);
  });
});

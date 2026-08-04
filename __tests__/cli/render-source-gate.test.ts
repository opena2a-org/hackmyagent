/**
 * The rendering property, asked of the source rather than of a fixture.
 *
 * #339 swept three call sites. A predicate over the whole file then found FIVE
 * more still raw in `src/cli.ts` alone, two of them pasteable citations reached
 * by an ordinary user mistake:
 *
 *   $ hackmyagent secure --fix ./SOUL.md
 *     Scan this file:        hackmyagent secure ./SOUL.md
 *     Remediate (directory): hackmyagent secure --fix .
 *     Harden governance:     hackmyagent harden-soul .
 *
 * — three commands built by splicing the path the user typed straight into a
 * template, so a directory named `x'; touch PWNED; echo '` produced three
 * runnable injections, and a directory carrying `ESC [ 2 J` cleared the
 * terminal. `secure --fix <file>` is not an exotic path: it is what happens
 * when someone points the flagship command at the file they want fixed.
 *
 * Fixtures could not have found these. A fixture exercises the branches it
 * reaches, and a report has hundreds — an ENOENT message, a refusal, a summary
 * that renders only when a meter can still move. Writing one fixture per branch
 * is never finished, and the branches nobody thought of are exactly the ones
 * that stay raw.
 *
 * So this asks the question of the text: every call that PRINTS, every
 * path-bearing expression inside it, through a display escape or not. It is
 * cheap, it is total over the file, and it fails the moment a raw one is
 * WRITTEN rather than the moment one is run.
 *
 * It does not replace `report-render-safety.test.ts`. That one plants a hostile
 * name and reads what a real terminal would show, which is the only instrument
 * that can prove the escaping WORKS. This one proves it is APPLIED everywhere.
 * Neither is trusted alone: the source gate cannot see a path laundered through
 * another module, and the fixture cannot see a branch it does not reach.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import {
  unescapedRenderSites,
  unquotedCommandSites,
  commandsThatRenderPaths,
  reportSurfaceFiles,
  NOT_A_REPORT_SURFACE,
} from '../helpers/render-source';
import { COMMAND_CLASSIFICATION } from '../helpers/render-safety';

const REPO_ROOT = path.join(__dirname, '..', '..');

describe('the report surface renders no unescaped path', () => {
  it('reads the report surface at all', () => {
    // Non-vacuity. Every assertion below is over a list, and a list that stops
    // being produced — a moved file, a parser that throws and is caught
    // upstream, a glob that matches nothing — passes all of them silently.
    // That failure mode is the reason this whole file exists, so it is asserted
    // first and against a floor that a real refactor cannot drift under.
    const files = reportSurfaceFiles(REPO_ROOT);
    expect(
      files.length,
      'no source files were read, so the gate below is checking an empty list',
    ).toBeGreaterThan(100);
    expect(
      files.map((f) => path.relative(REPO_ROOT, f)),
      'src/cli.ts is not in the report surface, and it is where the reports are',
    ).toContain(path.join('src', 'cli.ts'));
  });

  it('escapes every path it prints', () => {
    const sites = unescapedRenderSites(REPO_ROOT);
    const report = sites
      .map((s) => `  ${s.file}:${s.line}  ${s.name}\n      ${s.code}`)
      .join('\n');
    expect(
      sites,
      'a printed line splices a filesystem path in without a display escape.\n'
      + 'A path from a scanned tree is attacker-influenced: a newline in it splits\n'
      + 'the rendered line, an ESC sequence rewrites the report describing it, and\n'
      + 'a quote in a command the report tells the user to RUN is an injection.\n\n'
      + 'Wrap it: `escapePathForDisplay(p)` for a path shown on its own,\n'
      + '`escapeForDisplay(text)` for a line built out of one, and\n'
      + '`citationTarget(p)` for a path spliced into a command meant to be pasted.\n\n'
      + `${report}\n`,
    ).toEqual([]);
  });

  /**
   * The rule this project states twice in prose and had never enforced.
   *
   * `display-safe.ts` builds its hazard class from `\u` escapes "rather than
   * written as a regex literal: a literal control byte inside a character class
   * is invisible in every diff and every editor that would review it, and this
   * is a security-relevant pattern". `render-safety.ts` says the same of test
   * source. Both are right, and neither was checked — a raw ESC byte sat in
   * `__tests__/cli-citation-target.test.ts` inside `/<ESC>\[[0-9;]*m/`, where
   * it read as an empty character class to anyone reviewing the diff.
   *
   * It was harmless: it stripped ANSI, which is what it was for. The defect is
   * that a reviewer cannot SEE it, in the one repository whose subject is
   * characters a reader cannot see.
   */
  it('carries no raw control byte in its own source', () => {
    const offenders: string[] = [];
    // Newline and tab are how source is formatted; everything else below 0x20,
    // plus DEL, is a byte someone typed on purpose and nobody can review.
    const hazard = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/;
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) { walk(full); continue; }
        if (!entry.name.endsWith('.ts')) continue;
        const lines = readFileSync(full, 'utf8').split('\n');
        lines.forEach((line, i) => {
          if (hazard.test(line)) {
            offenders.push(`${path.relative(REPO_ROOT, full)}:${i + 1}`);
          }
        });
      }
    };
    walk(path.join(REPO_ROOT, 'src'));
    walk(path.join(REPO_ROOT, '__tests__'));
    expect(
      offenders,
      'a source file contains a raw control character. It is invisible in every '
      + 'diff and every editor that would review it. Build it from a code point '
      + 'instead — `String.fromCodePoint(0x1b)` or a `\\u` escape — the way '
      + 'src/ui/display-safe.ts does.',
    ).toEqual([]);
  });

  it('excludes a tree from the surface only with a reason', () => {
    // The exclusions are the one hand-kept thing here, so they are held to the
    // same standard as `COMMAND_CLASSIFICATION`: a reason, on the record, long
    // enough to be a decision rather than a label.
    for (const [prefix, reason] of Object.entries(NOT_A_REPORT_SURFACE)) {
      expect(prefix.endsWith('/'), `${prefix} should name a directory`).toBe(true);
      expect(
        reason.length,
        `${prefix} is excluded from the render gate without a real reason`,
      ).toBeGreaterThan(40);
    }
  });
});

describe('the command classification agrees with what the commands print', () => {
  /**
   * `render-command-coverage.test.ts` checks that every registered command has
   * a classification. It cannot check whether the classification is TRUE — it
   * reads a string and accepts any string — so `attack` and `red-team` carried
   * "renders payload names, not filesystem paths" while printing four
   * filesystem paths between them, and the gate was green over a false
   * decision. `create-skill`, `init-mcp` and `scan` were wrong the same way.
   *
   * This derives the answer from the source instead of trusting the sentence.
   */
  it('classifies as renders-paths every command whose action prints a path', () => {
    const rendering = [...commandsThatRenderPaths(REPO_ROOT)].sort();
    expect(
      rendering.length,
      'no command was found to render a path, so this test is checking nothing',
    ).toBeGreaterThan(5);

    const misclassified = rendering.filter(
      (c) => COMMAND_CLASSIFICATION[c] !== 'renders-paths',
    );
    expect(
      misclassified.map((c) => `${c}: "${COMMAND_CLASSIFICATION[c] ?? '(unclassified)'}"`),
      'a command prints a filesystem path inside its own action, and '
      + 'COMMAND_CLASSIFICATION says it does not. The classification is what '
      + 'decides whether the rendering property runs over it, so a wrong one is a '
      + 'silently skipped command, not a wrong comment.',
    ).toEqual([]);
  });

  /**
   * Deliberately only one direction.
   *
   * A command classified `renders-paths` whose action shows no path in
   * `src/cli.ts` is not a contradiction: `detect`, `secure` and `wild` render
   * theirs from `src/scanner/detect.ts` and `src/hardening/scanner.ts`, where
   * there is no `.command(…)` to attribute the call to. Asserting the converse
   * would fail on all three and the only way to make it pass would be to
   * DEMOTE them, which is the outcome this gate exists to prevent.
   */
  it('names the commands the source-derived set cannot see, so the gap is on the record', () => {
    const derived = commandsThatRenderPaths(REPO_ROOT);
    const classified = Object.entries(COMMAND_CLASSIFICATION)
      .filter(([, v]) => v === 'renders-paths')
      .map(([k]) => k);
    const rendersElsewhere = classified.filter((c) => !derived.has(c)).sort();
    // Not an emptiness assertion — a record of which commands this instrument
    // is blind to, so the runtime property is known to be the only thing
    // covering them. `detect`, `check` and `wild` render their paths from
    // `src/scanner/detect.ts`, `src/check/**` and `src/wild/index.ts`, where
    // there is no `.command(…)` for the call to be attributed to.
    expect(rendersElsewhere).toEqual(['check', 'detect', 'wild']);
  });
});

/**
 * The same property, asked of every command citation rather than of every
 * printer (#273).
 *
 * The gate above walks arguments to `console.log` and friends, so it can only
 * ask about a module that PRINTS. The sites #273 reported do not print: they
 * build a finding's `fix:` string, or return an array of disclosure lines, and
 * something else renders them later as `f.fix`. That crosses a module boundary
 * AND a name change, both of which `render-source.ts` documents as blind spots
 * — which is why the printer gate was green while sixteen sites were live.
 *
 * Measured on `6a5c1db`, scanning a tree containing
 * `.claude/skills/my skill$(id)/SKILL.md`:
 *
 *     Verify: hackmyagent secure .claude/skills/my skill$(id)
 *
 * The space retargets the command at a path that does not exist; `$(id)` runs
 * on paste. `rm ${relativePath}` on the ClawHavoc findings was the same defect
 * on a deletion command.
 */
describe('every command citation quotes its operands (#273)', () => {
  it('reads the report surface at all', () => {
    // Same non-vacuity floor as above: an emptiness assertion over a list that
    // stopped being produced passes for the wrong reason.
    expect(reportSurfaceFiles(REPO_ROOT).length).toBeGreaterThan(100);
  });

  it('finds no unquoted interpolation in a command-argument position', () => {
    const sites = unquotedCommandSites(REPO_ROOT);
    const rendered = sites
      .map((s) => `  ${s.file}:${s.line}  ${s.name}\n      in: ${s.code}`)
      .join('\n');
    expect(
      sites,
      `${sites.length} command citation(s) splice a value in unquoted. A path or `
      + 'name in a command the reader is invited to paste must go through '
      + '`citationPath`/`citationTarget` (or `commandNaming`, which omits the '
      + `command when the value cannot be named truthfully):\n${rendered}`,
    ).toEqual([]);
  });

  it('would catch a raw interpolation, so the assertion above can fail', () => {
    // The gate's own red-proof. `toEqual([])` over a detector that silently
    // matches nothing is the failure mode this whole file was written about, so
    // the detector is shown finding a planted defect rather than trusted to.
    //
    // The probe goes in a THROWAWAY root, never in this repo's `src/`. The
    // first version wrote `src/__gate_probe__.ts` and deleted it in a `finally`,
    // which is correct in isolation and wrong under vitest: files run in
    // parallel workers, so for the moment that probe existed it was a `.ts` file
    // newer than `dist/`, and `assertDistFresh` in a spawn suite running
    // concurrently failed with "dist/cli.js is STALE". A test must not mutate
    // the tree another test is measuring.
    const { mkdtempSync, mkdirSync, writeFileSync } = require('node:fs') as typeof import('node:fs');
    const { tmpdir } = require('node:os') as typeof import('node:os');
    const root = mkdtempSync(path.join(tmpdir(), 'hma-gate-probe-'));
    mkdirSync(path.join(root, 'src'));
    writeFileSync(
      path.join(root, 'src', 'probe.ts'),
      'export function probe(targetDir: string): string {\n'
      + '  return `hackmyagent secure ${targetDir}`;\n}\n',
    );
    const hit = unquotedCommandSites(root).find((s) => s.file.endsWith('probe.ts'));
    expect(hit, 'the gate did not flag a deliberately raw citation').toBeDefined();
    expect(hit?.name).toBe('targetDir');
  });

  it('accepts the same probe once it is a citation', () => {
    // The other direction: the gate must not simply flag everything, or the
    // assertion above would pass on a detector that is always positive.
    const { mkdtempSync, mkdirSync, writeFileSync } = require('node:fs') as typeof import('node:fs');
    const { tmpdir } = require('node:os') as typeof import('node:os');
    const root = mkdtempSync(path.join(tmpdir(), 'hma-gate-probe-ok-'));
    mkdirSync(path.join(root, 'src'));
    writeFileSync(
      path.join(root, 'src', 'probe.ts'),
      "import { citationTarget } from './shell-quote';\n"
      + 'export function probe(targetDir: string): string {\n'
      + '  return `hackmyagent secure ${citationTarget(targetDir)}`;\n}\n',
    );
    expect(unquotedCommandSites(root)).toEqual([]);
  });
});

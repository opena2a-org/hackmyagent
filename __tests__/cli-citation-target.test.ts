/**
 * #293 / #288 — per-finding fix lines must name the scanned target.
 *
 * A single `secure ./proj` output printed BOTH forms of the same advice:
 *
 *   hackmyagent secure --fix              <- no target: acts on the CURRENT dir
 *   hackmyagent check ./proj --nanomind   <- correct
 *   npx opena2a-cli protect .             <- current dir
 *   npx opena2a-cli protect ./proj        <- correct
 *
 * Pasting the pathless form created `.gitignore` and `.hackmyagent-backup/` in
 * the wrong directory, left the credential untouched, and printed a success
 * summary — a false signal that the finding was resolved.
 *
 * #261 fixed the Next Steps builder only; these strings come from the
 * nanomind-core finding layer, so the fix belongs at the central citation
 * rewrite layer rather than at the ~50 call sites (enumerated by script:
 * `opena2a protect .` alone appears ~25 times in several spellings).
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  rebrandCommandCitations,
  setCitationTarget,
  __resetCitationTargetForTests,
} from '../src/cli-prefix';

describe('#293 citation target completion', () => {
  beforeEach(() => __resetCitationTargetForTests());
  afterEach(() => __resetCitationTargetForTests());

  describe('with a local scan target', () => {
    beforeEach(() => setCitationTarget('./proj'));

    it('completes a targetless secure --fix', () => {
      expect(rebrandCommandCitations('hackmyagent secure --fix')).toBe(
        'hackmyagent secure ./proj --fix'
      );
    });

    it('replaces a bare dot in an opena2a protect citation', () => {
      expect(rebrandCommandCitations('opena2a protect .')).toBe(
        'npx opena2a-cli protect ./proj'
      );
    });

    it('replaces a bare dot in harden-soul (#288)', () => {
      expect(rebrandCommandCitations('hackmyagent harden-soul .')).toBe(
        'hackmyagent harden-soul ./proj'
      );
    });

    it('completes a bare verb with no arguments at all', () => {
      expect(rebrandCommandCitations('hackmyagent secure')).toBe('hackmyagent secure ./proj');
    });

    it('leaves a citation that already names a target alone', () => {
      const already = 'hackmyagent check ./proj --nanomind';
      expect(rebrandCommandCitations(already)).toBe(already);
    });

    it('does not graft a second target onto an existing placeholder', () => {
      // `secure --fix <dir>` already tells the reader to supply a directory.
      const already = 'hackmyagent secure --fix <dir> first to create a backup.';
      expect(rebrandCommandCitations(already)).toBe(already);
    });

    it('does not treat a package name as a missing target', () => {
      const already = 'hackmyagent check express';
      expect(rebrandCommandCitations(already)).toBe(already);
    });

    it('does not consume the prose that follows a command', () => {
      const out = rebrandCommandCitations(
        'opena2a protect .  — migrates hardcoded secrets into the vault'
      );
      expect(out).toBe('npx opena2a-cli protect ./proj  — migrates hardcoded secrets into the vault');
    });

    it('completes a citation embedded in backticks inside prose', () => {
      const out = rebrandCommandCitations(
        'Run `hackmyagent secure --fix` and then re-scan.'
      );
      expect(out).toContain('`hackmyagent secure ./proj --fix`');
      expect(out).toContain('and then re-scan.');
    });

    it('does not rewrite the bare package name or an install command', () => {
      const untouched = 'npm i -g hackmyagent and see .hackmyagent-backup/ for rollback';
      expect(rebrandCommandCitations(untouched)).toBe(untouched);
    });
  });

  describe('with a remote target (npm / PyPI / GitHub)', () => {
    beforeEach(() => setCitationTarget(undefined, { remote: true }));

    it('emits a placeholder rather than a path that would mean the cwd', () => {
      // There is no local tree a local-fix citation could correctly name, so
      // the one thing it must not do is silently imply "wherever you are".
      const out = rebrandCommandCitations('hackmyagent secure --fix');
      expect(out).toBe('hackmyagent secure <dir> --fix');
      expect(out).not.toBe('hackmyagent secure --fix');
    });

    it('replaces a bare dot with the placeholder too', () => {
      expect(rebrandCommandCitations('opena2a protect .')).toBe(
        'npx opena2a-cli protect <dir>'
      );
    });
  });

  /**
   * The unit cases above prove the rewrite layer behaves. This one proves the
   * layer is actually REACHED by real output — #261 fixed the Next Steps
   * builder and the finding layer kept citing the wrong tree, so a test that
   * only exercises the function would have passed throughout that bug.
   *
   * Run from a parent directory against a child, which is the exact shape
   * that made the pathless advice destructive.
   */
  describe('emitted output, scanning a child directory from its parent', () => {
    const REPO_ROOT = path.resolve(__dirname, '..');
    const CLI = path.join(REPO_ROOT, 'dist', 'cli.js');
    let parent: string;

    beforeEach(() => {
      parent = mkdtempSync(path.join(tmpdir(), 'hma-293-e2e-'));
      const proj = path.join(parent, 'proj');
      mkdirSync(proj, { recursive: true });
      writeFileSync(path.join(proj, 'package.json'), '{"name":"proj","version":"1.0.0"}\n');
      writeFileSync(
        path.join(proj, 'config.json'),
        JSON.stringify({ token: `ghp_${'a'.repeat(36)}` }) + '\n'
      );
    });

    afterEach(() => rmSync(parent, { recursive: true, force: true }));

    it('emits no pathless or bare-dot fix citation anywhere in the output', () => {
      if (!existsSync(CLI)) throw new Error('dist/cli.js missing — run npm run build');

      let out = '';
      try {
        out = execFileSync(
          process.execPath,
          [CLI, 'secure', './proj'],
          { cwd: parent, encoding: 'utf8', timeout: 120_000 }
        );
      } catch (e: unknown) {
        // `secure` exits 1 when it finds something — that is the case we want.
        out = String((e as { stdout?: string }).stdout ?? '');
      }

      expect(out.length, 'no output captured — the scan did not run').toBeGreaterThan(0);
      // Sanity: the fixture must actually produce the citations we are checking.
      expect(out, 'fixture produced no fix citations to check').toMatch(/secure .*--fix/);

      const offenders = out
        .split('\n')
        // Built from a code point, not written as a literal: a raw ESC byte in
        // source is invisible in every diff that would review it, which is this
        // project's own rule for exactly the class of character this strips.
        .map((l) => l.replace(new RegExp(`${String.fromCodePoint(0x1b)}\\[[0-9;]*m`, 'g'), ''))
        .filter((l) =>
          // a target-taking verb followed immediately by a flag, EOL, or a
          // bare `.` — i.e. no tree named
          /\b(?:hackmyagent|opena2a-cli|opena2a)\s+(?:secure|harden-soul|scan-soul|protect|fix-all|detect)(?:\s+--?\w|\s*$|\s+\.(?:\s|$))/.test(l)
        )
        // `--help` and generic usage lines are deliberately target-free.
        .filter((l) => !l.includes('--help'));

      expect(
        offenders,
        `pathless fix citations would act on the cwd, not ./proj:\n${offenders.join('\n')}`
      ).toEqual([]);
    });
  });

  describe('when the scan target IS the working directory', () => {
    beforeEach(() => setCitationTarget(undefined));

    it('leaves the pathless form exactly as it is', () => {
      // Pathless is already correct here; rewriting it would be pure noise
      // and would churn every golden that scans in place.
      expect(rebrandCommandCitations('hackmyagent secure --fix')).toBe(
        'hackmyagent secure --fix'
      );
    });

    it('leaves a bare dot alone', () => {
      expect(rebrandCommandCitations('opena2a protect .')).toBe('npx opena2a-cli protect .');
    });
  });
});

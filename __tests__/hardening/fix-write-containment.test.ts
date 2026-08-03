// A fix write must land inside the scanned tree, and every write must be
// recoverable — including the one `harden-soul` makes.
//
// #270: the fix sites opened their target by path with no resolution. A
// symlinked leaf sitting inside the tree passed the (purely lexical)
// containment check and `fs.writeFile` followed it wherever it pointed.
// Measured on merged main `a681409`:
//
//   $ ln -s ../shared.gitignore repo/.gitignore
//   $ hackmyagent secure repo --fix
//   Fixed 1 issue (1 verified):
//     ✓✓ [GIT-002] .gitignore - Incomplete .gitignore
//   $ wc -c shared.gitignore     # OUTSIDE the scanned tree
//   85                           # was 21
//
// `rollback` has refused to restore through a link that leaves the tree since
// #351. The write side following one anywhere was the asymmetry.
//
// #271: `hardenSoul` wrote with `appendFileSync`/`writeFileSync` directly,
// reaching neither containment nor `ensureBackupCovers`, and `BACKUP_FILES`
// carried a hand-copied subset of `GOVERNANCE_FILES` (`SOUL.md`, `CLAUDE.md`).
// So on merged main, standalone `harden-soul`:
//
//   .cursorrules   113 -> 19055 bytes, absent from the manifest
//   rollback       [+] Rollback complete, exit 0, file still 19055
//
// The #327 asymmetry must NOT come back the other way: a link that stays
// INSIDE the tree is an ordinary dotfile-sharing layout and has to keep
// working. That is pinned here too — a containment fix that refuses every
// symlink would pass every assertion above and break real repos.

import { describe, it, expect, afterEach, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, mkdirSync,
  symlinkSync, statSync, readdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');
const dirs: string[] = [];

beforeAll(() => {
  // #285 process note: spawn suites gated on `existsSync(dist/cli.js)` and so
  // passed against a stale binary — roughly half of one round's new coverage
  // was measuring an older build. Absence is a failure here, not a skip.
  expect(
    existsSync(CLI),
    'dist/cli.js is missing — run `npm run build` before this suite',
  ).toBe(true);
});

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

/**
 * Run the CLI with a sandboxed HOME.
 *
 * Not cosmetic: `secure` merges findings from every AI runtime directory under
 * the real `$HOME` into the target's result (#336/#337), which on a developer
 * machine is ~1780 findings and a score of 0. Every assertion below is about
 * the fixture, so the environment it runs in has to be the fixture.
 */
function run(cwd: string, home: string, args: string[]) {
  return spawnSync('node', [CLI, ...args], {
    cwd, encoding: 'utf8', timeout: 180_000,
    env: { ...process.env, NO_COLOR: '1', HOME: home, CI: '1' },
  });
}

function sandbox(prefix: string): { home: string; root: string } {
  const root = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(root);
  const home = join(root, 'home');
  mkdirSync(home, { recursive: true });
  return { home, root };
}

function manifestOf(dir: string): {
  existingFiles: string[]; absentAtBackup: string[]; absentAtFixWrite?: string[];
} {
  const backupRoot = join(dir, '.hackmyagent-backup');
  const stamp = readdirSync(backupRoot)[0];
  return JSON.parse(readFileSync(join(backupRoot, stamp, '.manifest.json'), 'utf8'));
}

describe('fix writes are contained to the scanned tree (#270)', { timeout: 300_000 }, () => {
  it('refuses to rewrite a file a symlinked leaf points to OUTSIDE the tree', () => {
    const { home, root } = sandbox('hma-contain-out-');
    const repo = join(root, 'repo');
    mkdirSync(repo, { recursive: true });
    const outside = join(root, 'shared.gitignore');
    writeFileSync(outside, 'ORIGINAL-OUT-OF-TREE\n');
    const before = readFileSync(outside, 'utf8');
    // GIT-002's fix appends security patterns to `.gitignore`.
    symlinkSync(join('..', 'shared.gitignore'), join(repo, '.gitignore'));
    writeFileSync(join(repo, 'package.json'), '{"name":"c","version":"1.0.0"}\n');

    const res = run(repo, home, ['secure', repo, '--fix']);

    // The bytes at the far end of the link are untouched. This is the whole
    // issue: on merged main this file went 21 -> 85 bytes.
    expect(readFileSync(outside, 'utf8')).toBe(before);

    // And it did not claim to have fixed it. A silent no-op would leave the
    // finding looking fixed, which is the failure mode #327 removed from the
    // other fix sites.
    const out = res.stdout + res.stderr;
    expect(out).not.toMatch(/Fixed 1 issue/);
  });

  it('names the file and the real reason, not just an error code', () => {
    const { home, root } = sandbox('hma-contain-msg-');
    const repo = join(root, 'repo');
    mkdirSync(repo, { recursive: true });
    writeFileSync(join(root, 'shared.gitignore'), 'OUT\n');
    symlinkSync(join('..', 'shared.gitignore'), join(repo, '.gitignore'));
    writeFileSync(join(repo, 'package.json'), '{"name":"c","version":"1.0.0"}\n');

    const res = run(repo, home, ['secure', repo, '--fix', '--json']);
    const report = JSON.parse(res.stdout);
    const finding = report.findings.find(
      (f: { checkId?: string }) => f.checkId === 'FIX-WRITE-FAILED',
    );

    expect(finding, 'the refused write must be reported, not swallowed').toBeTruthy();
    expect(finding.message).toContain('.gitignore');
    // #347.4 — a code is not a sentence. The generic guidance names read-only
    // mounts and full volumes; a reader who got only `FIX-WRITE-UNCONTAINED`
    // went looking for a permissions problem that was not there.
    expect(finding.message).toMatch(/symbolic link that points outside/i);
    // And the remedy must address THIS cause. "Make the file writable" does
    // nothing for a link that leaves the tree.
    expect(finding.fix).not.toMatch(/make the file writable/i);
  });

  it('still follows a symlink that stays INSIDE the tree (#327 must not regress)', () => {
    const { home, root } = sandbox('hma-contain-in-');
    const repo = join(root, 'repo');
    mkdirSync(join(repo, 'shared'), { recursive: true });
    // The ordinary dotfile-sharing layout #327 was filed about: the link and
    // its target are both inside the scanned tree.
    const inside = join(repo, 'shared', 'gitignore.shared');
    writeFileSync(inside, 'node_modules\n');
    const before = readFileSync(inside, 'utf8');
    symlinkSync(join('shared', 'gitignore.shared'), join(repo, '.gitignore'));
    writeFileSync(join(repo, 'package.json'), '{"name":"c","version":"1.0.0"}\n');

    run(repo, home, ['secure', repo, '--fix']);

    // Refusing every symlink would satisfy the two tests above and break this
    // one. The write must land, THROUGH the link, at the in-tree target.
    const after = readFileSync(inside, 'utf8');
    expect(after).not.toBe(before);
    expect(after.startsWith(before)).toBe(true);
    // It stayed a link — the fix wrote through it rather than replacing it.
    expect(statSync(join(repo, '.gitignore')).isFile()).toBe(true);
  });
});

describe('harden-soul writes are backed up (#271)', { timeout: 300_000 }, () => {
  /** A repo governed by `.cursorrules` — not `SOUL.md`, not `CLAUDE.md`. */
  function cursorRepo(prefix: string) {
    const { home, root } = sandbox(prefix);
    const repo = join(root, 'repo');
    mkdirSync(repo, { recursive: true });
    const gov = join(repo, '.cursorrules');
    writeFileSync(
      gov,
      '# Project rules\n\nThe agent must follow the repo conventions.\nKeep responses short.\n',
    );
    writeFileSync(join(repo, 'package.json'), '{"name":"g","version":"1.0.0"}\n');
    return { home, repo, gov };
  }

  it('backs up the governance file it actually targets, and rollback restores it', () => {
    const { home, repo, gov } = cursorRepo('hma-harden-cursor-');
    const before = readFileSync(gov, 'utf8');

    const harden = run(repo, home, ['harden-soul', repo]);
    expect(harden.status).toBe(0);

    // Precondition — without a real modification the restore below is vacuous.
    const hardened = readFileSync(gov, 'utf8');
    expect(hardened.length).toBeGreaterThan(before.length);

    // The manifest must know about the file that changed. On merged main it
    // held `package.json` and nothing else, so there was nothing to restore.
    const manifest = manifestOf(repo);
    expect(
      [...manifest.existingFiles, ...(manifest.absentAtFixWrite ?? [])],
    ).toContain('.cursorrules');

    const back = run(repo, home, ['rollback', repo]);
    expect(back.status).toBe(0);
    // Byte-exact, not merely "shorter".
    expect(readFileSync(gov, 'utf8')).toBe(before);
  });

  it('discloses the undo path it now actually has', () => {
    const { home, repo } = cursorRepo('hma-harden-undo-');
    const res = run(repo, home, ['harden-soul', repo]);
    // The command rewrote a governance file and said nothing about getting the
    // previous one back, because on merged main there was no way to.
    expect(res.stdout + res.stderr).toMatch(/rollback/i);
  });

  it('refuses, and says so, when the governance file leaves the tree', () => {
    const { home, root } = sandbox('hma-harden-escape-');
    const repo = join(root, 'repo');
    mkdirSync(repo, { recursive: true });
    const outside = join(root, 'outside.cursorrules');
    writeFileSync(outside, '# outside\n');
    const before = readFileSync(outside, 'utf8');
    symlinkSync(join('..', 'outside.cursorrules'), join(repo, '.cursorrules'));
    writeFileSync(join(repo, 'package.json'), '{"name":"g","version":"1.0.0"}\n');

    const res = run(repo, home, ['harden-soul', repo]);

    expect(readFileSync(outside, 'utf8')).toBe(before);
    // Not silent, and not exit 0: a script reading exit 0 as "governance is
    // hardened now" would be wrong.
    expect(res.status).not.toBe(0);
    expect(res.stdout + res.stderr).toMatch(/did NOT modify|points outside/i);
  });

  it('does not create a backup directory for a dry run', () => {
    const { home, repo } = cursorRepo('hma-harden-dry-');
    const before = readFileSync(join(repo, '.cursorrules'), 'utf8');

    run(repo, home, ['harden-soul', repo, '--dry-run']);

    // A preview must not have side effects — including HMA's own.
    expect(existsSync(join(repo, '.hackmyagent-backup'))).toBe(false);
    expect(readFileSync(join(repo, '.cursorrules'), 'utf8')).toBe(before);
  });
});

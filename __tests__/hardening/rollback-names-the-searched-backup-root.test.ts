/**
 * #1043: `secure --help` says where `--fix` keeps its backups, and `rollback`
 * says which backup root it searched.
 *
 * Measured on the built CLI before this change, with a scratch HOME:
 *
 *   - `secure --help` had no line naming a backup, `rollback`,
 *     `HMA_BACKUP_HOME` or `OPENA2A_HOME`.
 *   - `HMA_BACKUP_HOME=<dir> secure <project> --fix`, then `rollback <project>`
 *     with the variable unset, exited 1 with one line:
 *     "No backup found. Run hackmyagent secure --fix <dir> first to create a
 *     backup." Following that advice took a backup of the already-fixed tree,
 *     and the next `rollback` exited 0 with "Rollback complete" while the
 *     pre-fix content stayed in `<dir>`, which no printed line named.
 *
 * The error is now a block: what was searched and which variable chose it,
 * that nothing was restored, and the next steps. A path that does not exist
 * gets a block of its own, because no search ran for it.
 *
 * The render cells count lines and ask real shells what a next-step operand
 * names. `assertRenderSafe` alone does not cover this error: its split check
 * knows one marker and its shell check judges only `rm` operands, so it passes
 * a forged next-step line and an unquoted target. No planted text here holds
 * `rm` followed by a space, which that helper reads as a command.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, symlinkSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { escapePathForDisplay } from '../../src/ui/display-safe';
import { assertDistFresh } from '../helpers/dist-freshness';
import { assertRenderSafe } from '../helpers/render-safety';
import { tempDir } from '../helpers/temp-dir';

const CLI = path.resolve(__dirname, '..', '..', 'dist', 'cli.js');
const ESC = String.fromCodePoint(0x1b);

/** Assembled at runtime, so the source tree holds no token-shaped literal. */
const FAKE_GH_TOKEN = `${['gh', 'p_'].join('')}${'a'.repeat(36)}`;

/** A tree `--fix` changes: the token in `config.json` is replaced by a reference. */
function fixableTree(): string {
  const dir = tempDir('hma-1043-proj-');
  writeFileSync(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  writeFileSync(path.join(dir, 'config.json'), `${JSON.stringify({ githubToken: FAKE_GH_TOKEN, port: 8080 }, null, 2)}\n`);
  return dir;
}

const liveConfig = (dir: string): string => readFileSync(path.join(dir, 'config.json'), 'utf-8');
const real = (p: string): string => realpathSync.native(p);

interface Spawned { stdout: string; stderr: string; status: number | null }

/**
 * The built CLI, in `cwd`, with exactly the store variables the cell names and
 * nothing stripped from its output. The suite's own `HMA_BACKUP_HOME` and any
 * prefix override are dropped first.
 */
function hma(args: string[], cwd: string, storeEnv: Record<string, string>): Spawned {
  const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: '1' };
  delete env.HMA_BACKUP_HOME;
  delete env.OPENA2A_HOME;
  delete env.HMA_CLI_PREFIX;
  const res = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 120_000,
    cwd,
    env: { ...env, ...storeEnv },
  });
  return { stdout: res.stdout ?? '', stderr: res.stderr ?? '', status: res.status };
}

/**
 * The lines a terminal would show. A carriage return, U+0085, U+2028 and
 * U+2029 end a line on screen as a newline does, so a count that splits on
 * the newline alone cannot see a block they have split.
 */
function screenLines(text: string): string[] {
  const breaks = ['\\r\\n', '\\n', '\\r', '\\u0085', '\\u2028', '\\u2029'].join('|');
  return text.replace(/\n$/, '').split(new RegExp(breaks, 'u'));
}

/** The block for a directory that exists and has no backup in the store or in the tree. */
function noBackupBlock(root: string, source: string, cited: string): string[] {
  return [
    `Error: No backup found for this directory. None of the backup stores in ${escapePathForDisplay(root)} (${source}) `
    + 'is for it, and it holds no .hackmyagent-backup/ directory with a backup.',
    'Nothing was restored.',
    '  If --fix ran with a different HMA_BACKUP_HOME or OPENA2A_HOME, set them as that run did, then run: '
    + `hackmyagent rollback ${cited}`,
    '  If every --fix backup of this directory has already been rolled back, or --fix never ran on it, there is '
    + 'nothing to roll back.',
  ];
}

/** The run directories under a store root, across every target's store in it. */
function runsUnder(root: string): string[] {
  const out: string[] = [];
  for (const store of readdirSync(root, { withFileTypes: true })) {
    if (!store.isDirectory()) continue;
    for (const run of readdirSync(path.join(root, store.name), { withFileTypes: true })) {
      if (run.isDirectory() && !run.name.startsWith('.')) out.push(path.join(root, store.name, run.name));
    }
  }
  return out;
}

const FIX_ARGS = ['--fix', '--static-only', '--no-machine-posture'];

describe('#1043 secure --help says where --fix keeps its backups', () => {
  beforeAll(assertDistFresh);

  // Cell A.
  it('names the store, the variables and the restore command, last in the description', () => {
    const home = tempDir('hma-1043-home-');
    const help = hma(['secure', '--help'], home, { HOME: home });

    expect(help.status).toBe(0);
    expect(help.stdout).toContain('HMA_BACKUP_HOME');
    expect(help.stdout).toContain('hackmyagent rollback');

    // The form for a base that carries #1039: --fix copies a file only when a
    // fix is about to change it, and the permissions fix records a mode.
    const section = [
      'Backups (--fix):',
      '  Before a fix changes a file, --fix copies the file into a per-user backup',
      '  store outside the project: $HMA_BACKUP_HOME if set, else',
      '  $OPENA2A_HOME/backups, else ~/.opena2a/backups. A fix that only narrows a',
      "  file's permissions records the file's earlier mode instead of a copy. The",
      '  copies can hold a credential that is still in use. They stay until you',
      '  delete them or rollback restores from them, and every text report of the',
      '  project prints the command that deletes them.',
      '  hackmyagent rollback restores the most recent backup. It reads',
      '  HMA_BACKUP_HOME and OPENA2A_HOME the same way, so run it with the values the',
      '  --fix run had, or it finds no backup.',
    ];
    for (const line of section) expect(line.length, `wider than 80 columns: ${line}`).toBeLessThanOrEqual(80);
    // The section is the last thing in the description: one blank line, then
    // the argument list.
    expect(help.stdout, 'the section is missing, reworded or not directly above Arguments:')
      .toContain(`\n\n${section.join('\n')}\n\nArguments:\n`);
    // The sentence for a base without #1039 says .env is copied whether or not
    // a fix changes it, which is no longer what --fix does.
    expect(help.stdout).not.toContain('copies every file a fix may change');
    expect(help.stdout).not.toContain('whether or not a fix then changes it');

    expect(help.stdout, 'the --fix option line changed')
      .toMatch(/^ {2}--fix +Automatically fix issues where possible$/m);
    expect(help.stdout).not.toContain(ESC);
  }, 120_000);
});

describe('#1043 rollback names the backup root it searched', () => {
  beforeAll(assertDistFresh);

  // Cell B.
  it('after --fix with HMA_BACKUP_HOME set, rollback without it names the root it searched and restores nothing', () => {
    const target = fixableTree();
    const original = liveConfig(target);
    const home = tempDir('hma-1043-home-');
    const cwd = tempDir('hma-1043-cwd-');
    const named = path.join(tempDir('hma-1043-store-'), 'backups');

    const fix = hma(['secure', target, ...FIX_ARGS], cwd, { HOME: home, HMA_BACKUP_HOME: named });
    expect(fix.stdout, 'the run took no backup; this cell measures nothing').toContain('Backup created:');
    const fixed = liveConfig(target);
    expect(fixed, 'the fix did not change the file; this cell measures nothing').not.toBe(original);
    const runs = runsUnder(named);
    expect(runs, 'the backup is not under the directory HMA_BACKUP_HOME names').toHaveLength(1);

    // The variable is unset, so the root searched is the default one.
    const searched = path.join(real(home), '.opena2a', 'backups');
    const without = hma(['rollback', target], cwd, { HOME: home });
    const lines = screenLines(without.stderr);

    expect(without.status).toBe(1);
    expect(lines[0], 'the first line does not name the root that was searched').toContain(escapePathForDisplay(searched));
    expect(lines.slice(1).some((l) => l.includes('HMA_BACKUP_HOME')), 'no later line names the variable').toBe(true);
    expect(lines.filter((l) => l.includes('secure --fix')), 'the error still sends the user to --fix').toEqual([]);
    expect(lines).toEqual(noBackupBlock(searched, 'the default, under your home directory', target));
    expect(without.stdout + without.stderr).not.toContain(ESC);
    expect(runsUnder(named), 'the failed rollback removed the backup').toEqual(runs);
    expect(liveConfig(target), 'a rollback that found no backup changed the live file').toBe(fixed);

    const withIt = hma(['rollback', target], cwd, { HOME: home, HMA_BACKUP_HOME: named });
    expect(withIt.status, withIt.stderr).toBe(0);
    expect(liveConfig(target), 'rollback with the variable set did not restore the pre-fix bytes').toBe(original);

    // Every backup of the directory has now been rolled back: the same block,
    // naming the root HMA_BACKUP_HOME chose.
    const again = hma(['rollback', target], cwd, { HOME: home, HMA_BACKUP_HOME: named });
    expect(again.status).toBe(1);
    expect(screenLines(again.stderr)).toEqual(noBackupBlock(real(named), 'set by HMA_BACKUP_HOME', target));
    expect(liveConfig(target)).toBe(original);
  }, 300_000);

  it.each([
    {
      source: 'set by HMA_BACKUP_HOME',
      storeEnv: (home: string, other: string): Record<string, string> => ({ HOME: home, OPENA2A_HOME: home, HMA_BACKUP_HOME: other }),
      root: (_home: string, other: string): string => real(other),
    },
    {
      source: 'set by OPENA2A_HOME',
      storeEnv: (home: string, other: string): Record<string, string> => ({ HOME: home, OPENA2A_HOME: other }),
      root: (_home: string, other: string): string => path.join(real(other), 'backups'),
    },
    {
      source: 'the default, under your home directory',
      storeEnv: (home: string): Record<string, string> => ({ HOME: home }),
      root: (home: string): string => path.join(real(home), '.opena2a', 'backups'),
    },
  ])('says the root was $source', ({ source, storeEnv, root }) => {
    const target = tempDir('hma-1043-nobackup-');
    const home = tempDir('hma-1043-home-');
    const other = tempDir('hma-1043-other-');

    const run = hma(['rollback', target], home, storeEnv(home, other));

    expect(run.status).toBe(1);
    expect(screenLines(run.stderr)).toEqual(noBackupBlock(root(home, other), source, target));
  }, 120_000);

  it('cites the directory as it was typed', () => {
    const target = tempDir('hma-1043-nobackup-');
    const home = tempDir('hma-1043-home-');

    const run = hma(['rollback', '.'], target, { HOME: home });

    expect(run.status).toBe(1);
    expect(screenLines(run.stderr)).toEqual(
      noBackupBlock(path.join(real(home), '.opena2a', 'backups'), 'the default, under your home directory', '.'),
    );
  }, 120_000);

  it('prints the same block for a .hackmyagent-backup/ directory in the tree that holds no backup', () => {
    const target = tempDir('hma-1043-emptyarchive-');
    mkdirSync(path.join(target, '.hackmyagent-backup'));
    const home = tempDir('hma-1043-home-');

    const run = hma(['rollback', target], home, { HOME: home });

    expect(run.status).toBe(1);
    expect(screenLines(run.stderr)).toEqual(
      noBackupBlock(path.join(real(home), '.opena2a', 'backups'), 'the default, under your home directory', target),
    );
  }, 120_000);

  it('for a path that does not exist, names no backup root and no variable', () => {
    const home = tempDir('hma-1043-home-');
    const store = tempDir('hma-1043-store-');
    const missing = path.join(tempDir('hma-1043-gone-'), 'no-such-project');

    const run = hma(['rollback', missing], home, { HOME: home, OPENA2A_HOME: home, HMA_BACKUP_HOME: store });

    expect(run.status).toBe(1);
    expect(screenLines(run.stderr)).toEqual([
      `Error: ${escapePathForDisplay(missing)} does not exist or cannot be accessed, so rollback has nothing to restore into.`,
      'Nothing was restored. The backups of a directory that was deleted stay in its backup store.',
      '  If the path is wrong, run: hackmyagent rollback "${DIR:?set DIR to the directory to restore}"',
    ]);
    expect(run.stderr).not.toContain('No backup found');
    expect(run.stderr).not.toContain('secure --fix');
    expect(run.stderr).not.toContain('HMA_BACKUP_HOME');
    expect(run.stderr).not.toContain('OPENA2A_HOME');
    expect(run.stderr).not.toContain(store);
    expect(run.stderr).not.toContain(real(store));
    expect(run.stdout + run.stderr).not.toContain(ESC);
  }, 120_000);
});

/**
 * The shells a next-step operand is put through. `sh`, `bash` and `dash` are on
 * every machine this suite runs on, so a missing one is an error. zsh is the
 * default shell on macOS and is absent from the Linux runner; it is required
 * wherever it is installed.
 */
const REQUIRED_SHELLS = ['sh', 'bash', 'dash'];

function installed(shell: string): boolean {
  try {
    execFileSync('command', ['-v', shell], { stdio: 'ignore', shell: '/bin/sh' });
    return true;
  } catch {
    return false;
  }
}

function shellsToAsk(): string[] {
  for (const shell of REQUIRED_SHELLS) {
    if (!installed(shell)) throw new Error(`${shell} is not installed, and this cell asks it what the printed command names`);
  }
  return installed('zsh') ? [...REQUIRED_SHELLS, 'zsh'] : REQUIRED_SHELLS;
}

/** The operand of every next-step line that is a command naming the directory. */
function nextStepOperands(lines: string[]): string[] {
  const marker = 'run: hackmyagent rollback ';
  return lines
    .filter((l) => l.startsWith('  ') && l.includes(marker))
    .map((l) => l.slice(l.indexOf(marker) + marker.length));
}

describe('#1043 the rollback error renders a hostile root and target as data', () => {
  beforeAll(assertDistFresh);

  const CANARY_ROOT = 'CANARY-1043-ROOT';
  const CANARY_TARGET = 'CANARY-1043-TARGET';
  // Quotes and backticks come in pairs, so that an unquoted rendering is a
  // command a shell runs to the end, and the canary records it, where an
  // unpaired quote would only fail to parse.
  const HOSTILE_ROOT_NAME = `st ore'q'$(touch ${CANARY_ROOT})\`:\`;x`;
  const HOSTILE_TARGET_NAME = `t'a'r\`:\`get;touch ${CANARY_TARGET};#`;

  /** `rollback` on an existing directory with no backup, with `root` as HMA_BACKUP_HOME. */
  function noBackupRun(root: string): { run: Spawned; lines: string[] } {
    const target = tempDir('hma-1043-nobackup-');
    const home = tempDir('hma-1043-home-');
    const run = hma(['rollback', target], home, { HOME: home, HMA_BACKUP_HOME: root });
    return { run, lines: screenLines(run.stderr) };
  }

  /** A store root reached through a link, whose real name carries `tail` after a plain start. */
  function linkedRoot(tail: string): { link: string; resolved: string } {
    const resolved = path.join(tempDir('hma-1043-real-'), `store${tail}`);
    mkdirSync(resolved, { recursive: true });
    const link = path.join(tempDir('hma-1043-link-'), 'store');
    symlinkSync(resolved, link);
    return { link, resolved: real(resolved) };
  }

  const plainLineCount = (): number => noBackupRun(tempDir('hma-1043-plain-')).lines.length;

  it('plants no text that holds rm followed by a space', () => {
    for (const planted of [HOSTILE_ROOT_NAME, HOSTILE_TARGET_NAME, 'EVIL-SECOND-LINE', 'hackmyagent rollback .']) {
      expect(planted.includes('rm '), planted).toBe(false);
    }
  });

  // Cell C.
  it('quotes the target in the next-step command and keeps the root out of every command', () => {
    const root = path.join(tempDir('hma-1043-root-'), HOSTILE_ROOT_NAME);
    mkdirSync(root);
    const target = path.join(tempDir('hma-1043-target-'), HOSTILE_TARGET_NAME);
    mkdirSync(target);
    const home = tempDir('hma-1043-home-');
    const cwd = tempDir('hma-1043-cwd-');

    const run = hma(['rollback', target], cwd, { HOME: home, HMA_BACKUP_HOME: root });
    const lines = screenLines(run.stderr);

    expect(run.status).toBe(1);
    assertRenderSafe(run.stderr, 'rollback no-backup error', [target]);
    expect(lines).toHaveLength(4);
    expect(lines[0]).toContain(`None of the backup stores in ${escapePathForDisplay(real(root))} (set by HMA_BACKUP_HOME)`);
    expect(lines.slice(1).filter((l) => l.includes(CANARY_ROOT)), 'a line after the first names the root').toEqual([]);
    expect(lines.filter((l) => l.includes('rm ')), 'a line holds rm followed by a space').toEqual([]);

    const operands = nextStepOperands(lines);
    expect(operands, 'no next-step command names the directory, so nothing was asked of a shell').toHaveLength(1);
    // Every shell is asked before anything is judged, so a canary one of them
    // created is reported as that, ahead of the word it printed.
    const named: Array<{ shell: string; operand: string; words: string }> = [];
    for (const operand of operands) {
      for (const shell of shellsToAsk()) {
        let words: string;
        try {
          words = execFileSync(shell, ['-c', `printf '%s\\n' ${operand}`], { encoding: 'utf8', cwd, timeout: 30_000, stdio: ['ignore', 'pipe', 'pipe'] });
        } catch {
          words = `(${shell} could not parse it)`;
        }
        named.push({ shell, operand, words });
      }
    }

    const canaries: string[] = [];
    for (const dir of [cwd, root, target]) {
      for (const canary of [CANARY_ROOT, CANARY_TARGET]) {
        if (existsSync(path.join(dir, canary))) canaries.push(path.join(dir, canary));
      }
    }
    expect(canaries, 'a planted name ran as a command and created its canary').toEqual([]);
    for (const { shell, operand, words } of named) {
      expect(words, `${shell} does not read the operand as the one target: ${operand}`).toBe(`${target}\n`);
    }
  }, 120_000);

  it('does not let a newline in the resolved root forge a next-step line', () => {
    const scratch = tempDir('hma-1043-forge-');
    const forged = `  HMA_BACKUP_HOME=${scratch}/elsewhere hackmyagent rollback .`;
    const { link, resolved } = linkedRoot(`\n${forged}`);

    const { run, lines } = noBackupRun(link);

    expect(run.status).toBe(1);
    expect(lines, 'the root added a line to the block').toHaveLength(plainLineCount());
    expect(lines[0]).toContain(escapePathForDisplay(resolved));
    expect(lines.filter((l) => l.startsWith(forged) || l.trimStart().startsWith('HMA_BACKUP_HOME=')), 'a line starts with the forged text').toEqual([]);
  }, 120_000);

  it('passes the shared render check with the split marker after a newline in the root', () => {
    const { link, resolved } = linkedRoot('\nEVIL-SECOND-LINE');

    const { run, lines } = noBackupRun(link);

    expect(run.status).toBe(1);
    assertRenderSafe(run.stderr, 'rollback no-backup error');
    expect(lines[0], 'the root was not rendered; this cell measures nothing').toContain(escapePathForDisplay(resolved));
    expect(lines).toHaveLength(plainLineCount());
  }, 120_000);

  it('shows a carriage return, U+2028 and U+0085 in the root as escapes, on one line', () => {
    const CR = '\r';
    const LS = String.fromCodePoint(0x2028);
    const NEL = String.fromCodePoint(0x85);
    const { link, resolved } = linkedRoot(`${CR}one${LS}two${NEL}three`);

    const { run, lines } = noBackupRun(link);

    expect(run.status).toBe(1);
    expect(lines).toHaveLength(plainLineCount());
    expect(lines[0]).toContain(escapePathForDisplay(resolved));
    expect(lines[0]).toContain('store\\rone\\u2028two\\x85three');
    for (const raw of [CR, LS, NEL]) expect(run.stderr.includes(raw), 'a raw line terminator reached stderr').toBe(false);
  }, 120_000);
});

/**
 * The `FIX-BACKUP-FAILED` remedies say the same thing from the other side: a
 * `--fix` that took no backup because of where the store is tells the user
 * that `rollback` reads the same variables.
 */
describe('#1043 the backup-failed guidance says rollback reads the same variables', () => {
  const S = '`hackmyagent rollback` reads HMA_BACKUP_HOME and OPENA2A_HOME the same way, so run it with the value this run '
    + 'had, or it reports no backup.';
  let saved: { backup?: string; opena2a?: string };

  beforeEach(() => {
    saved = { backup: process.env.HMA_BACKUP_HOME, opena2a: process.env.OPENA2A_HOME };
  });

  afterEach(() => {
    if (saved.backup === undefined) delete process.env.HMA_BACKUP_HOME; else process.env.HMA_BACKUP_HOME = saved.backup;
    if (saved.opena2a === undefined) delete process.env.OPENA2A_HOME; else process.env.OPENA2A_HOME = saved.opena2a;
  });

  const refusal = async (target: string): Promise<{ guidance?: string; fix?: string }> => {
    const before = liveConfig(target);
    const result = await new HardeningScanner().scan({ targetDir: target, autoFix: true });
    const refused = result.findings.filter((f) => f.checkId === 'FIX-BACKUP-FAILED');
    expect(refused, 'the run took a backup; this cell measures nothing').toHaveLength(1);
    expect(liveConfig(target)).toBe(before);
    return refused[0];
  };

  it('for a store that would sit inside the directory being fixed', async () => {
    const target = fixableTree();
    process.env.HMA_BACKUP_HOME = path.join(target, 'backups');

    const { guidance } = await refusal(target);

    expect(guidance).toMatch(/^Backups are kept outside the directory being fixed, so that no later scan reports the copies\. /);
    expect(guidance?.endsWith(`the run detected only. Nothing was written and nothing was changed. ${S}`), guidance).toBe(true);
  }, 120_000);

  it('for a relative store root, without the claim that rollback resolves the same location', async () => {
    const target = fixableTree();
    process.env.HMA_BACKUP_HOME = 'relstore';

    const { guidance } = await refusal(target);

    expect(guidance).toBe(
      'Backups are kept in a per-user store outside the scanned tree (HMA_BACKUP_HOME, else $OPENA2A_HOME/backups, else '
      + '~/.opena2a/backups). HMA_BACKUP_HOME is a relative path, which resolves to a different directory from each working '
      + `directory, so the run detected only. Nothing was written and nothing was changed. ${S}`,
    );
  }, 120_000);

  it('for a store that cannot be created', async () => {
    const target = fixableTree();
    const blocker = path.join(tempDir('hma-1043-blocker-'), 'a-file');
    writeFileSync(blocker, 'not a directory\n');
    process.env.HMA_BACKUP_HOME = path.join(blocker, 'under', 'backups');

    const { guidance } = await refusal(target);

    expect(guidance).toBe(
      'Applying fixes without a backup would leave nothing to roll back to, so the run detects only. Every finding below '
      + 'reflects the tree as it is on disk. Backups are kept in a per-user store outside the scanned tree (HMA_BACKUP_HOME, '
      + 'else $OPENA2A_HOME/backups, else ~/.opena2a/backups); this usually means a read-only or container home directory. '
      + S,
    );
  }, 120_000);
});

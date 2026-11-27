/**
 * `scan-soul -f, --format <text|json>` — the spelling of `--json` that
 * `secure` and `attack` already accept.
 *
 * `scan-soul --format json` was refused with "unknown option '--format'",
 * so a script that drove every scan command with `--format json` stopped at
 * scan-soul. Now:
 *
 *   - `json` is `--json`: the same bytes on stdout and the same exit code;
 *   - `text` is the default report, byte for byte;
 *   - any other value is refused before the scan, naming text and json;
 *   - `--help` lists the option.
 *
 * Each comparison runs over two trees with different exit codes (a file
 * missing its critical controls exits 1; a tree with no governance file is
 * NOT MEASURED at exit 2), so an alias that hard-coded one exit code would
 * fail one of them.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

function run(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, 'scan-soul', ...args], {
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NODE_OPTIONS: '', NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: tempDir('hma-scan-soul-format-home-') },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

function treeWithSoul(): string {
  const dir = tempDir('hma-scan-soul-format-');
  writeFileSync(join(dir, 'SOUL.md'), '# Bot\n\nAnswers questions about billing.\n', 'utf-8');
  return dir;
}

const trees = () => [
  { name: 'a file missing its critical controls', dir: treeWithSoul(), status: 1 },
  { name: 'a tree with no governance file', dir: tempDir('hma-scan-soul-format-empty-'), status: 2 },
];

describe('scan-soul --format <text|json>', { timeout: 300_000 }, () => {
  it('--format json and -f json print what --json prints, at the same exit code', () => {
    for (const tree of trees()) {
      const shorthand = run([tree.dir, '--json']);
      expect(shorthand.status, tree.name).toBe(tree.status);
      expect(() => JSON.parse(shorthand.stdout), tree.name).not.toThrow();
      for (const spelling of [['--format', 'json'], ['-f', 'json'], ['--format=json']]) {
        const r = run([tree.dir, ...spelling]);
        expect(r.status, `${tree.name}: ${spelling.join(' ')}`).toBe(shorthand.status);
        expect(r.stdout, `${tree.name}: ${spelling.join(' ')}`).toBe(shorthand.stdout);
      }
    }
  });

  it('--format text prints the default report, at the same exit code', () => {
    for (const tree of trees()) {
      const plain = run([tree.dir]);
      expect(plain.status, tree.name).toBe(tree.status);
      expect(plain.stdout.trimStart().startsWith('{'), tree.name).toBe(false);
      const r = run([tree.dir, '--format', 'text']);
      expect(r.status, tree.name).toBe(plain.status);
      expect(r.stdout, tree.name).toBe(plain.stdout);
    }
  });

  it('any other value is refused before the scan, naming text and json', () => {
    for (const value of ['yaml', 'sarif', 'JSON', '']) {
      const r = run([treeWithSoul(), '--format', value]);
      expect(r.status, `--format '${value}'`).toBe(1);
      expect(r.stderr, `--format '${value}'`).toContain(`Invalid format '${value}'. Use: text, json`);
      expect(r.stdout, `--format '${value}'`).toBe('');
    }
  });

  it('--json with a contradicting --format is refused; the redundant --json --format json runs', () => {
    const dir = treeWithSoul();
    const contradiction = run([dir, '--json', '--format', 'text']);
    expect(contradiction.status).toBe(1);
    expect(contradiction.stderr).toMatch(/shorthand for --format json and contradicts .*text.*Drop one/s);
    expect(contradiction.stdout).toBe('');

    const agreement = run([dir, '--json', '--format', 'json']);
    expect(agreement.stdout).toBe(run([dir, '--json']).stdout);
  });

  it('--help lists the option and its two values', () => {
    const r = run(['--help']);
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/-f, --format <format>\s+Output format: text, json/);
    expect(r.stdout).toContain('--json');
  });
});

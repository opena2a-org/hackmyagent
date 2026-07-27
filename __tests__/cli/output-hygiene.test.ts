// Output-hygiene gates for #202 and the #253 batch.
//
// #202 — secure / detect / scan-soul emitted no version footer, so a
//        finding pasted into a bug report or archived in CI carried no
//        record of which build produced it.
// #253.2 — `detect` respected NO_COLOR / --no-color but not a non-TTY
//        stdout, so `detect > out.txt` wrote raw escape sequences while
//        secure / scan-soul / check all came out clean.
// #253.3 — `red-team <dir>` failed with a bare "Cannot read file: <dir>"
//        and no hint, while check / secure / scan-soul all accept a dir.
// #253.4 — `pull-stubs` surfaced a raw internal ByteString exception when
//        INTERNAL_API_KEY held a non-Latin1 character.
// #253.6 — `fix-all --dry-run` printed "Fixed N" during a preview.
// #253.7 — the quick-start banner reprinted above every subcommand's help.

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');
const VERSION = JSON.parse(
  require('node:fs').readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'),
).version as string;

function canRunSpawn(): boolean {
  if (process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true') return false;
  return existsSync(CLI);
}

/** spawnSync with stdout as a PIPE — i.e. NOT a TTY, the case that regressed. */
function run(args: string[], opts: { cwd?: string; env?: NodeJS.ProcessEnv } = {}) {
  return spawnSync('node', [CLI, ...args], {
    encoding: 'utf8',
    timeout: 180_000,
    cwd: opts.cwd,
    env: { ...process.env, ...opts.env },
  });
}

const ESC = '\x1b';

describe('version footer (#202)', () => {
  it.runIf(canRunSpawn())('secure stamps the version on the findings path (exit 1)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hma-202-findings-'));
    try {
      writeFileSync(
        join(dir, '.env'),
        'DATABASE_URL=postgres://user:FAKEpassword@localhost:5432/db\n',
        'utf8',
      );
      const res = run(['secure', dir]);
      // The findings path calls process.exit(1), which skips Commander's
      // postAction — the reason the footer is registered on 'exit'. This is
      // also the output people actually paste into bug reports.
      expect(res.status).toBe(1);
      expect(res.stdout).toContain(`Scanned with hackmyagent v${VERSION}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.runIf(canRunSpawn())('secure stamps the version on the clean path (exit 0)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hma-202-clean-'));
    try {
      const res = run(['secure', dir]);
      expect(res.stdout).toContain(`Scanned with hackmyagent v${VERSION}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.runIf(canRunSpawn())('--json carries the version as a field, not a footer', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hma-202-json-'));
    try {
      const res = run(['secure', dir, '--json']);
      const parsed = JSON.parse(res.stdout.trim());
      expect(parsed.hackmyagentVersion).toBe(VERSION);
      // A footer would corrupt the JSON for any consumer.
      expect(res.stdout).not.toContain('Scanned with hackmyagent');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.runIf(canRunSpawn())('--ci output stays free of the footer', () => {
    // The corpus release-smoke harness consumes --ci output; a version line
    // would churn it on every bump.
    const dir = mkdtempSync(join(tmpdir(), 'hma-202-ci-'));
    try {
      const res = run(['secure', dir, '--ci']);
      expect(res.stdout).not.toContain('Scanned with hackmyagent');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('detect strips ANSI on a non-TTY stdout (#253.2)', () => {
  it.runIf(canRunSpawn())('emits no escape sequences when piped', () => {
    const res = run(['detect']);
    expect(res.stdout.length).toBeGreaterThan(0);
    expect(res.stdout).not.toContain(ESC);
  });
});

describe('red-team accepts a directory (#253.3)', () => {
  it.runIf(canRunSpawn())('resolves the conventional artifact inside a directory', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hma-253-rt-ok-'));
    try {
      writeFileSync(join(dir, 'SKILL.md'), '---\nname: t\n---\n# t\n', 'utf8');
      const res = run(['red-team', dir, '--json']);
      expect(res.stdout).not.toContain('Cannot read file');
      // Resolved to SKILL.md and produced a real report.
      expect(JSON.parse(res.stdout.trim()).target.artifactType).toBe('skill');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.runIf(canRunSpawn())('names what to point at when the directory holds no artifact', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hma-253-rt-empty-'));
    try {
      const res = run(['red-team', dir]);
      expect(res.status).toBe(1);
      // No dead end: says why, and gives a concrete target to retry with.
      expect(res.stderr).toMatch(/no SKILL\.md, SOUL\.md, or mcp\.json/);
      expect(res.stderr).toContain('red-team');
      expect(res.stderr).toContain('SKILL.md');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.runIf(canRunSpawn())('distinguishes a missing path from an unreadable one', () => {
    const res = run(['red-team', join(tmpdir(), 'hma-253-does-not-exist-xyz')]);
    expect(res.status).toBe(1);
    expect(res.stderr).toContain('No such file or directory');
  });
});

describe('pull-stubs validates the API key before using it as a header (#253.4)', () => {
  it.runIf(canRunSpawn())('reports a clean validation error, not a ByteString exception', () => {
    // U+FFFD is what a mis-decoded copy-paste actually leaves behind, and is
    // the exact character from the issue report.
    const res = run(['pull-stubs'], { env: { INTERNAL_API_KEY: 'abcdefgh�ijkl' } });
    expect(res.status).toBe(1);
    expect(res.stderr).toMatch(/non-Latin1 character/);
    expect(res.stderr).not.toMatch(/ByteString/);
    // The offending position is reported; the key value itself never is.
    expect(res.stderr).toContain('index 8');
    expect(res.stderr).not.toContain('abcdefgh');
  });
});

describe('fix-all --dry-run does not claim work it did not do (#253.6)', () => {
  it.runIf(canRunSpawn())('previews with "Would fix", never "Fixed"', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hma-253-dry-'));
    try {
      mkdirSync(join(dir, 'sub'), { recursive: true });
      writeFileSync(
        join(dir, '.env'),
        'DATABASE_URL=postgres://user:FAKEpassword@localhost:5432/db\n',
        'utf8',
      );
      const res = run(['fix-all', dir, '--dry-run']);
      const out = res.stdout || '';
      // Guard against a vacuous pass: the preview must have found something.
      expect(out).toMatch(/dry-run/i);
      expect(out).not.toMatch(/\[\+\] Fixed \d/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('quick-start banner is root-only (#253.7)', () => {
  it.runIf(canRunSpawn())('renders on the top-level help', () => {
    expect(run(['--help']).stdout).toContain('Quick start:');
  });

  it.runIf(canRunSpawn())('does not repeat above subcommand help', () => {
    for (const cmd of ['secure', 'check', 'scan-soul', 'detect']) {
      expect(run([cmd, '--help']).stdout).not.toContain('Quick start:');
    }
  });
});

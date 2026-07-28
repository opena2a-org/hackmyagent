// Regression gate: the #202 version footer must never enter machine output.
//
// #202 gated the `Scanned with hackmyagent vX.Y.Z` trailer on `--json` alone.
// `secure` also takes `-f, --format <text|json|sarif|html|asp|asff>` and
// documents `--json` as deprecated in favour of `--format json` — so the
// deprecated path was protected and every recommended one was corrupted:
//
//   $ hackmyagent secure <dir> --format sarif
//     }
//     Scanned with hackmyagent v0.25.1     <- JSON.parse fails here
//
// That breaks scripted `--format json` consumers and breaks SARIF upload to
// the GitHub Security tab, which is the whole purpose of the SARIF writer.
//
// Contract: the trailer is emitted only for an explicitly textual render.

import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  VERSION_FOOTER_COMMANDS,
  resolveOutputFormat,
  shouldPrintVersionFooter,
} from '../../src/ui/version-footer';

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');

const FOOTER_RE = /Scanned with hackmyagent v/;

describe('version-footer gate (deterministic)', () => {
  it('emits for a plain text render', () => {
    expect(shouldPrintVersionFooter({ command: 'secure', ciMode: false })).toBe(true);
    expect(shouldPrintVersionFooter({ command: 'secure', ciMode: false, format: 'text' })).toBe(true);
  });

  it('suppresses for every machine format, not just the deprecated --json', () => {
    for (const format of ['json', 'sarif', 'html', 'asff', 'asp']) {
      expect(
        shouldPrintVersionFooter({ command: 'secure', ciMode: false, format }),
        `--format ${format} must not carry the footer`,
      ).toBe(false);
    }
    expect(shouldPrintVersionFooter({ command: 'secure', ciMode: false, json: true })).toBe(false);
  });

  it('suppresses an unrecognised format rather than assuming text', () => {
    // Allow-list, not deny-list: a machine format added later must be
    // suppressed by default instead of silently corrupted.
    expect(shouldPrintVersionFooter({ command: 'secure', ciMode: false, format: 'protobuf' })).toBe(false);
  });

  it('honours --ci and the command scope', () => {
    expect(shouldPrintVersionFooter({ command: 'secure', ciMode: true })).toBe(false);
    expect(shouldPrintVersionFooter({ command: 'telemetry', ciMode: false })).toBe(false);
  });

  it('treats --json as an alias for --format json', () => {
    expect(resolveOutputFormat({ json: true })).toBe('json');
    expect(resolveOutputFormat({ json: true, format: 'sarif' })).toBe('json');
    expect(resolveOutputFormat({ format: 'sarif' })).toBe('sarif');
    expect(resolveOutputFormat({})).toBe('text');
  });

  it('covers exactly the scan-producing commands', () => {
    expect([...VERSION_FOOTER_COMMANDS].sort()).toEqual(['detect', 'scan-soul', 'secure']);
  });
});

describe('secure output formats parse (spawn, local-only)', () => {
  function fixture(): string {
    const dir = mkdtempSync(join(tmpdir(), 'hma-footer-'));
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'f', version: '1.0.0' }));
    return dir;
  }

  function run(dir: string, args: string[]): string {
    const res = spawnSync('node', [CLI, 'secure', dir, ...args], {
      encoding: 'utf8',
      timeout: 180_000,
      env: { ...process.env, NO_COLOR: '1' },
    });
    return res.stdout || '';
  }

  // Deliberately NOT gated on CI. These use a mktemp fixture, not the
  // private corpus, so the only real prerequisite is a built dist/. Gating
  // them on `CI !== 'true'` meant reverting the cli.ts wiring stayed green in
  // CI, since the deterministic tests above only exercise the helper module.
  const canRun = () => existsSync(CLI);

  // Explicit timeouts: each case spawns one or two full `secure` scans, and
  // the suite default (10s in vitest.config.ts) was measured at 75% consumed
  // on an M4 Max — a slower CI runner would flake the release gate.
  it.runIf(canRun())('text output still carries the footer', () => {
    // Non-vacuity for every assertion below: if #202's footer stopped being
    // emitted at all, the absence checks would pass for the wrong reason.
    expect(run(fixture(), [])).toMatch(FOOTER_RE);
  }, 60_000);

  it.runIf(canRun())('--format json and --format sarif stay parseable', () => {
    for (const format of ['json', 'sarif']) {
      const out = run(fixture(), ['--format', format]);
      expect(out, `--format ${format} carries the footer`).not.toMatch(FOOTER_RE);
      expect(() => JSON.parse(out), `--format ${format} does not parse`).not.toThrow();
    }
  }, 120_000);

  it.runIf(canRun())('the deprecated --json alias stays parseable too', () => {
    const out = run(fixture(), ['--json']);
    expect(out).not.toMatch(FOOTER_RE);
    expect(() => JSON.parse(out)).not.toThrow();
  }, 60_000);
});

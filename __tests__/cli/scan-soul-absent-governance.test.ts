/**
 * HMA-01.AC2 — `scan-soul --ci` over a tree with no governance file (#390,
 * second carry).
 *
 * The defect: `scan-soul --ci` exited 0 and printed a full `0/100` nine-domain
 * table, naming controls as "Missing" from a file it never found. The worst
 * posture a target can hold was the one case CI passed.
 *
 * WHAT THIS FILE ADDS over `scan-soul-conformance-gate.test.ts`, which pins the
 * same exit contract: nothing about the implementation, and that is deliberate.
 * It states the acceptance criterion in the criterion's own terms — non-zero
 * exit, an absence that is REPORTED rather than scored, and no fabricated band
 * — so the criterion is checkable without reading the ruling that produced it.
 * If the two files ever disagree, the older one is the record of the decision.
 *
 * ON THE WORDING. The criterion asks for a finding saying the file is ABSENT.
 * The shipped output says `NOT MEASURED — No governance file was found, so no
 * governance score can be reported for this target`, with the searched
 * filenames beside it, and `--json` carries `gate.reason: 'no-governance-file'`
 * with `score: null`. The assertions below are on that substance rather than on
 * a literal token: renaming shipped, tested output to match a criterion's
 * phrasing would be churn, and the `--json` reason string is a consumer
 * contract.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { EXIT_UNMEASURED } from '../../src/check/verdict';

beforeAll(assertDistFreshIfPresent);

const CLI_PATH = resolve(__dirname, '../../dist/cli.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

function runScanSoul(target: string, ...flags: string[]): { out: string; status: number } {
  try {
    const stdout = execFileSync(process.execPath, [CLI_PATH, 'scan-soul', target, ...flags], {
      stdio: ['ignore', 'pipe', 'pipe'],
      encoding: 'utf8',
      timeout: 20000,
      env: { ...process.env, NODE_OPTIONS: '', NO_COLOR: '1' },
    });
    return { out: stdout.replace(STRIP_ANSI, ''), status: 0 };
  } catch (err) {
    const e = err as { status?: number; stdout?: Buffer | string; stderr?: Buffer | string };
    const text = (s: Buffer | string | undefined) =>
      (typeof s === 'string' ? s : (s?.toString() ?? '')).replace(STRIP_ANSI, '');
    return { out: `${text(e.stdout)}\n${text(e.stderr)}`, status: e.status ?? 1 };
  }
}

/** A directory with no SOUL.md, no CLAUDE.md, no governance file of any spelling. */
function emptyTree(): string {
  return mkdtempSync(join(tmpdir(), 'hma-01-ac2-'));
}

describe('HMA-01.AC2: scan-soul --ci over a tree with no governance file', () => {
  it('HMA-01.AC2 dist/cli.js exists', () => {
    // A spawn suite that silently skips reports success over a build that was
    // never made. Named as its own leaf so the skip is visible.
    expect(existsSync(CLI_PATH)).toBe(true);
  });

  it('HMA-01.AC2 --ci exits non-zero when no governance file exists at the scanned path', () => {
    if (!existsSync(CLI_PATH)) return;
    const { status } = runScanSoul(emptyTree(), '--ci');
    expect(status, 'the worst posture must not be the one case CI passes').not.toBe(0);
    // The specific code is the unmeasured arm, not a conformance failure: there
    // is no verdict to fail, because nothing was read.
    expect(status).toBe(EXIT_UNMEASURED);
  });

  it('HMA-01.AC2 --ci reports the governance file as absent rather than scoring it', () => {
    if (!existsSync(CLI_PATH)) return;
    const { out } = runScanSoul(emptyTree(), '--ci');
    expect(out).toMatch(/NOT MEASURED/);
    expect(out, 'the absence itself must be stated').toMatch(/no governance file was found/i);
    // Not a dead end: the output has to say how to create one.
    expect(out).toMatch(/harden-soul/);
  });

  it('HMA-01.AC2 --ci prints no fabricated 0/100 and no per-domain table', () => {
    if (!existsSync(CLI_PATH)) return;
    const { out } = runScanSoul(emptyTree(), '--ci');
    expect(out, 'a band handed to a file that does not exist').not.toMatch(/0\/100/);
    expect(out).not.toMatch(/Domain Scores/);
    // Naming controls as "Missing" from a file that does not exist is the same
    // false assertion in a different shape.
    expect(out).not.toMatch(/SOUL-IH-003/);
    expect(out).not.toMatch(/SOUL-HB-001/);
  });

  it('HMA-01.AC2 --ci --json withholds the score and names the reason', () => {
    if (!existsSync(CLI_PATH)) return;
    const { out, status } = runScanSoul(emptyTree(), '--ci', '--json');
    expect(status).toBe(EXIT_UNMEASURED);
    const start = out.indexOf('{');
    expect(start, `no JSON object on stdout: ${out.slice(0, 300)}`).toBeGreaterThanOrEqual(0);
    const body = JSON.parse(out.slice(start, out.lastIndexOf('}') + 1)) as {
      score?: unknown;
      conformance?: unknown;
      gate?: { failed?: boolean; reason?: string; exitCode?: number };
    };
    expect(body.score ?? null, 'a consumer must not read a band this run did not earn').toBeNull();
    expect(body.conformance ?? null).toBeNull();
    expect(body.gate?.failed).toBe(true);
    expect(body.gate?.reason).toBe('no-governance-file');
    expect(body.gate?.exitCode).toBe(EXIT_UNMEASURED);
  });
});

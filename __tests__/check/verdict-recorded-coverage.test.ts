/**
 * #508 — a coverage claim built from the run's own read-failure record.
 *
 * `fullCoverage(examined)` defined the denominator as the numerator, so an
 * input the run discovered and could not read left BOTH sides of the fraction
 * and `check` reported `examined 1 / total 1`, exit 0, over a tree with an
 * unreadable file. `recordedCoverage` carries the record beside the fraction,
 * and `deriveCheckVerdict` settles the exit code from it with the precedence
 * `secure` already ships: a band the command fails on exits 1 whatever else
 * happened; otherwise an unread input exits 2; otherwise 0.
 *
 * The gate is keyed on the RECORD, not on `examined < total`: `attack`
 * (answered of sent) and `detect` (a deliberate 4-of-5) report partial
 * fractions that are not read failures, and their exit codes must not move.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  deriveCheckVerdict,
  recordedCoverage,
  unreadInputs,
  coverageJson,
  unmeasured,
  EXIT_PASS,
  EXIT_FAIL,
  EXIT_UNMEASURED,
  type ReadFailureRecord,
} from '../../src/check/verdict';

const NONE: ReadFailureRecord = { count: 0, codes: {}, directories: 0 };
const ONE: ReadFailureRecord = { count: 1, codes: { EACCES: 1 }, directories: 0 };
const TWO: ReadFailureRecord = { count: 2, codes: { EACCES: 1, EPERM: 1 }, directories: 0 };

describe('recordedCoverage', () => {
  it('puts the unread inputs on the denominator and carries the record', () => {
    expect(recordedCoverage(3, 'file', ONE)).toEqual({ examined: 3, total: 4, unit: 'file', unreadableInputs: ONE });
    expect(recordedCoverage(3, 'file', TWO).total).toBe(5);
  });

  it('is a complete claim when the record is empty', () => {
    const c = recordedCoverage(3, 'artifact', NONE);
    expect(c.total).toBe(c.examined);
    expect(c.unreadableInputs).toEqual(NONE);
  });
});

describe('deriveCheckVerdict over a recorded partial read', () => {
  const clean = { critical: 0, high: 0, issues: 0 };
  const medium = { critical: 0, high: 0, issues: 2 };
  const high = { critical: 0, high: 1, issues: 1 };
  const critical = { critical: 1, high: 0, issues: 1 };

  it('a clean band over an unread input is measured, printed, and exits 2', () => {
    const v = deriveCheckVerdict(clean, recordedCoverage(3, 'file', ONE));
    expect(v.measured).toBe(true);
    if (!v.measured) throw new Error('unreachable');
    expect(v.risk).toBe('low');
    expect(v.exitCode).toBe(EXIT_UNMEASURED);
    expect(v.coverage.total).toBe(4);
  });

  it('a medium band over an unread input also exits 2', () => {
    expect(deriveCheckVerdict(medium, recordedCoverage(3, 'file', ONE)).exitCode).toBe(EXIT_UNMEASURED);
  });

  it('a high or critical band still exits 1: a found credential outranks an unread file', () => {
    expect(deriveCheckVerdict(high, recordedCoverage(3, 'file', ONE)).exitCode).toBe(EXIT_FAIL);
    expect(deriveCheckVerdict(critical, recordedCoverage(3, 'file', TWO)).exitCode).toBe(EXIT_FAIL);
  });

  it('with nothing unread the exit codes are what they were', () => {
    expect(deriveCheckVerdict(clean, recordedCoverage(3, 'file', NONE)).exitCode).toBe(EXIT_PASS);
    expect(deriveCheckVerdict(medium, recordedCoverage(3, 'file', NONE)).exitCode).toBe(EXIT_PASS);
    expect(deriveCheckVerdict(high, recordedCoverage(3, 'file', NONE)).exitCode).toBe(EXIT_FAIL);
  });

  it('every input unread is unmeasured, and says so as target-unreadable when the caller does', () => {
    const v = deriveCheckVerdict(clean, recordedCoverage(0, 'file', ONE), 'target-unreadable', 'x could not be read');
    expect(v.measured).toBe(false);
    if (v.measured) throw new Error('unreachable');
    expect(v.reason).toBe('target-unreadable');
    expect(v.exitCode).toBe(EXIT_UNMEASURED);
    expect(v.attempted).toEqual({ examined: 0, total: 1, unit: 'file', unreadableInputs: ONE });
  });

  it('a partial fraction WITHOUT a record does not move the exit code (attack / detect shape)', () => {
    // `attack` reports answered-of-sent and `detect` a deliberate 4-of-5.
    // Neither is a read failure, and neither keeps a record; a gate keyed on
    // `examined < total` would flip both to exit 2. This pins that it does not.
    expect(deriveCheckVerdict(clean, { examined: 4, total: 5, unit: 'payload' }).exitCode).toBe(EXIT_PASS);
    expect(deriveCheckVerdict(high, { examined: 4, total: 5, unit: 'payload' }).exitCode).toBe(EXIT_FAIL);
  });
});

describe('unreadInputs', () => {
  it('reads the record on either arm and is 0 without one', () => {
    expect(unreadInputs(deriveCheckVerdict({ critical: 0, high: 0 }, recordedCoverage(2, 'file', TWO)))).toBe(2);
    expect(unreadInputs(deriveCheckVerdict({ critical: 0, high: 0 }, { examined: 4, total: 5, unit: 'payload' }))).toBe(0);
    expect(unreadInputs(unmeasured('target-unreadable', 'x', recordedCoverage(0, 'file', ONE)))).toBe(1);
    expect(unreadInputs(unmeasured('target-not-found', 'gone'))).toBe(0);
  });
});

describe('coverageJson carries the record on both arms', () => {
  it('measured: the same key and shape secure --json uses', () => {
    const v = deriveCheckVerdict({ critical: 0, high: 0 }, recordedCoverage(1, 'artifact', ONE));
    expect(coverageJson(v)).toEqual({ measured: true, examined: 1, total: 2, unit: 'artifact', unreadableInputs: ONE });
  });

  it('unmeasured: the record survives, so "every input unread" keeps its count', () => {
    const v = unmeasured('target-unreadable', 'x', recordedCoverage(0, 'artifact', ONE));
    expect(coverageJson(v)).toMatchObject({ measured: false, examined: 0, total: 1, unit: 'artifact', unreadableInputs: ONE, reason: 'target-unreadable' });
  });

  it('a verdict without a record emits no unreadableInputs key, so absence means "no record kept"', () => {
    const v = deriveCheckVerdict({ critical: 0, high: 0 }, { examined: 4, total: 5, unit: 'payload' });
    expect('unreadableInputs' in coverageJson(v)).toBe(false);
  });
});

describe('fullCoverage is a ratchet, not a convenience', () => {
  // The two remaining executable callers are the deprecated `secure-openclaw`
  // and `secure-nemoclaw` sites, whose unit is `'check'` and cannot take a
  // file-count denominator until that command has a discovery record. Zero
  // callers is the measurement-record unit's exit condition; this pins that
  // the count only ever goes down.
  function executableCallers(): string[] {
    const root = join(__dirname, '..', '..', 'src');
    const out: string[] = [];
    const walk = (dir: string) => {
      for (const entry of readdirSync(dir)) {
        const p = join(dir, entry);
        if (statSync(p).isDirectory()) { walk(p); continue; }
        if (!p.endsWith('.ts')) continue;
        const lines = readFileSync(p, 'utf-8').split('\n');
        lines.forEach((line, i) => {
          const code = line.replace(/\/\/.*$/, '');
          if (/\bfullCoverage\(/.test(code) && !/function fullCoverage\(/.test(code) && !/^\s*\*/.test(line)) {
            out.push(`${p.slice(root.length + 1)}:${i + 1}`);
          }
        });
      }
    };
    walk(root);
    return out;
  }

  it('has at most two executable callers under src/, both in cli.ts', () => {
    const callers = executableCallers();
    expect(callers.length, callers.join('\n')).toBeLessThanOrEqual(2);
    for (const c of callers) expect(c.startsWith('cli.ts:')).toBe(true);
  });
});

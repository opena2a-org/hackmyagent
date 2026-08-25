/**
 * #362 — telemetry recorded a harden-soul run that modified nothing as a success.
 *
 * `commandSucceeded` follows the security-tool convention — exit 0 and 1 are
 * both success, only 2 and above is a crash — which is right for `secure`,
 * where exit 1 means "findings were detected and the command did its job".
 * harden-soul exits 1 only when it did NOT do its job — the target directory is
 * missing, no backup could be written, the target refused the write, or the run
 * threw. It has no findings-style exit 1.
 *
 * Measured with the REAL SDK helper, not a stand-in: the issue records that a
 * probe with `c => c === 0` returns false for every command and makes the
 * defect look absent. Only `successFromExitCode`'s `n <= 1` reproduces it.
 */
import { describe, it, expect } from 'vitest';
import { successFromExitCode } from '@opena2a/telemetry';
import { commandSucceeded, EXIT1_IS_FAILURE } from '../../src/telemetry/command-success';

describe('#362 harden-soul exit 1 is a failure for telemetry', () => {
  it('pins the premise: the SDK helper reads exit 1 as success', () => {
    // Non-vacuity: if the helper ever changes, the cells below stop measuring
    // the thing this file is about.
    expect(successFromExitCode(0)).toBe(true);
    expect(successFromExitCode(1)).toBe(true);
    expect(successFromExitCode(2)).toBe(false);
  });

  it('harden-soul exit 1 is recorded as a failure, exit 0 as a success', () => {
    expect(commandSucceeded('harden-soul', 1, successFromExitCode)).toBe(false);
    expect(commandSucceeded('harden-soul', 0, successFromExitCode)).toBe(true);
    expect(EXIT1_IS_FAILURE.has('harden-soul')).toBe(true);
  });

  it('the result-style commands still read exit 1 as a success', () => {
    for (const name of ['secure', 'check', 'scan-soul', 'trust', 'wild']) {
      expect(commandSucceeded(name, 1, successFromExitCode), name).toBe(true);
    }
    expect(commandSucceeded('rollback', 1, successFromExitCode)).toBe(false);
  });
});

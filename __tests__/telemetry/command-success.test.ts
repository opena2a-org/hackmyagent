// An incomplete rollback is not a success (#350).
//
// `successFromExitCode` treats exit 0 and 1 alike, because for `secure` exit 1
// means "findings were detected and the command did its job". `rollback` sets
// exit 1 when it could NOT put every listed file back, so the aggregate
// reported 100% success on exactly the runs that failed — on the one command
// six rounds of recovery fixes were about.
//
// The library cannot be narrowed to fix this: `semanticSuccessCodes` only ADDS
// codes to the success set. So the decision is the call site's, and this is it.
import { describe, it, expect } from 'vitest';
import { commandSucceeded, EXIT1_IS_FAILURE } from '../../src/telemetry/command-success';

/** The real convention from `@opena2a/telemetry`, restated for the tests. */
const conventional = (code: number): boolean => code <= 1;

describe('commandSucceeded (#350)', () => {
  it('reports an incomplete rollback as a failure', () => {
    expect(commandSucceeded('rollback', 1, conventional)).toBe(false);
  });

  it('reports a complete rollback as a success', () => {
    expect(commandSucceeded('rollback', 0, conventional)).toBe(true);
  });

  // The property, not the constant. A `conventional` that says "everything
  // succeeded" must not be able to override the exception — otherwise the test
  // would pass on an implementation that ignores the exception entirely and
  // just happens to agree with `code <= 1`.
  it('does not consult the convention for an exception command', () => {
    const alwaysTrue = (): boolean => true;
    expect(commandSucceeded('rollback', 1, alwaysTrue)).toBe(false);
  });

  // And the converse: a non-exception command must be decided BY the
  // convention, not by a second copy of its rule living here.
  it('defers to the convention for every other command', () => {
    const alwaysFalse = (): boolean => false;
    expect(commandSucceeded('secure', 1, alwaysFalse)).toBe(false);
    const alwaysTrue = (): boolean => true;
    expect(commandSucceeded('secure', 7, alwaysTrue)).toBe(true);
  });

  it('keeps the security-tool convention for a findings-bearing scan', () => {
    // exit 1 from `secure` means findings were found, which IS the job.
    expect(commandSucceeded('secure', 1, conventional)).toBe(true);
    expect(commandSucceeded('scan-soul', 1, conventional)).toBe(true);
    // A real crash is still a failure.
    expect(commandSucceeded('secure', 2, conventional)).toBe(false);
  });

  it('lists rollback, and does not quietly grow', () => {
    // A guard on the exception surface itself. Adding a command here changes
    // what a published metric means, so it should be a deliberate edit that
    // fails this assertion first.
    expect([...EXIT1_IS_FAILURE].sort()).toEqual(['rollback']);
  });
});

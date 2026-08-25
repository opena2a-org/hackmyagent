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
import { successFromExitCode } from '@opena2a/telemetry';
import { commandSucceeded, EXIT1_IS_FAILURE, EXIT2_IS_SEMANTIC } from '../../src/telemetry/command-success';

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

  it('lists rollback and harden-soul, and does not quietly grow', () => {
    // A guard on the exception surface itself. Adding a command here changes
    // what a published metric means, so it should be a deliberate edit that
    // fails this assertion first. harden-soul was added under #362: its exit 1
    // is a refusal or an error on every path, never a result.
    expect([...EXIT1_IS_FAILURE].sort()).toEqual(['harden-soul', 'rollback']);
  });
});

// `red-team` exits 2 on every run to mean "I generated payloads, executed none,
// and reached no verdict" (#369). Under the bare convention that reads as a
// crash, so the fleet-level success rate for the command would sit at 0%.
//
// These run against the REAL `successFromExitCode`, not the `conventional`
// stand-in above. The stand-in takes one parameter and cannot express widening
// at all — `conventional(2, [2])` is `2 <= 1`, false — so a suite written
// against it would report this rule broken while it works, or pass while the
// dependency silently stopped honouring the second argument. The behaviour
// under test lives half in this repo and half in the library; only the real
// pair proves it.
describe('commandSucceeded, exit 2 as a result rather than a crash (#369)', () => {
  it("counts red-team's no-verdict exit as a success", () => {
    expect(commandSucceeded('red-team', 2, successFromExitCode)).toBe(true);
  });

  it('does not widen exit 2 for any other command', () => {
    // The failure this guards is a widening that leaks. `secure` gained real
    // exit-2 paths in #400 (a scan whose plugins failed), and #369's telemetry
    // fix must not quietly relabel those as successful runs.
    for (const name of ['secure', 'check', 'scan-soul', 'attack']) {
      expect(commandSucceeded(name, 2, successFromExitCode)).toBe(false);
    }
  });

  it('widens only code 2, not everything above it', () => {
    // QUARANTINE (3) is a tampered binary. It must never read as success, on
    // red-team least of all.
    expect(commandSucceeded('red-team', 3, successFromExitCode)).toBe(false);
    expect(commandSucceeded('red-team', 0, successFromExitCode)).toBe(true);
    expect(commandSucceeded('red-team', 1, successFromExitCode)).toBe(true);
  });

  it('lists red-team, and does not quietly grow', () => {
    // Same deliberate-edit guard as EXIT1_IS_FAILURE above, and it carries a
    // second job: the entry is a bare string matched against
    // `actionCommand.name()`. Renaming the command, or adding a member without
    // a matching end-to-end assertion, has to fail here first. The spawn that
    // proves this string is the name a real invocation reports lives in
    // `__tests__/cli/redteam-unmeasured-exit.test.ts`.
    expect([...EXIT2_IS_SEMANTIC].sort()).toEqual(['red-team']);
  });
});

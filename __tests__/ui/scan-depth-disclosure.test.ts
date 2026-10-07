/**
 * #507 — the quick-depth score line names its denominator. Deterministic unit
 * tests for the helper; the end-to-end property is pinned in
 * `__tests__/cli/secure-quick-depth-denominator.test.ts`.
 */
import { describe, it, expect } from 'vitest';
import { checkGroupTally, scanDepthDisclosure } from '../../src/ui/scan-depth-disclosure';
import { CHECK_METHOD_PREFIXES } from '../../src/hardening/coverage-ledger';
import { citationTarget } from '../../src/ui/shell-quote';
import { CLI_PREFIX } from '../../src/cli-prefix';

const REGISTERED = Object.keys(CHECK_METHOD_PREFIXES).length;

/** A coverage record set where the first `ran` registered groups completed. */
function executions(ran: number): { completed: boolean }[] {
  return Object.keys(CHECK_METHOD_PREFIXES).map((_, i) => ({ completed: i < ran }));
}

describe('checkGroupTally (#507)', () => {
  it('sizes the denominator from the registered set, not the records present', () => {
    expect(checkGroupTally([{ completed: true }])).toEqual({ ran: 1, registered: REGISTERED });
  });

  it('counts only groups that completed', () => {
    expect(checkGroupTally(executions(6))).toEqual({ ran: 6, registered: REGISTERED });
  });
});

describe('scanDepthDisclosure (#507)', () => {
  it('quick depth with skipped groups puts the denominator on the score line', () => {
    const d = scanDepthDisclosure({ scanDepth: 'quick', executions: executions(6), target: '.' });
    expect(d).not.toBeNull();
    expect(d!.scoreSuffix).toBe(`  (over 6 of ${REGISTERED} check groups — scan depth quick)`);
    expect(d!.followup).toBe(`Run \`${CLI_PREFIX} secure ${citationTarget('.')}\` for the standard-depth score.`);
  });

  it('cites the follow-up command with the CLI prefix, so it runs when pasted (#885)', () => {
    const d = scanDepthDisclosure({ scanDepth: 'quick', executions: executions(6), target: '.' });
    expect(d!.followup).toMatch(new RegExp(`^Run \`${CLI_PREFIX.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} secure `));
  });

  it('says on the score line when the semantic layer is off (#885)', () => {
    const off = scanDepthDisclosure({ scanDepth: 'quick', executions: executions(6), target: '.', staticOnly: true });
    expect(off!.scoreSuffix).toBe(`  (over 6 of ${REGISTERED} check groups, semantic layer off — scan depth quick)`);
    const on = scanDepthDisclosure({ scanDepth: 'quick', executions: executions(6), target: '.', staticOnly: false });
    expect(on!.scoreSuffix).not.toContain('semantic');
  });

  it.each(['standard', 'deep', undefined])('%s depth prints no denominator', (depth) => {
    expect(scanDepthDisclosure({ scanDepth: depth, executions: executions(6), target: '.' })).toBeNull();
  });

  it('quick depth where every group ran prints no denominator', () => {
    expect(scanDepthDisclosure({ scanDepth: 'quick', executions: executions(REGISTERED), target: '.' })).toBeNull();
  });

  it('quick depth without a coverage record prints no denominator', () => {
    expect(scanDepthDisclosure({ scanDepth: 'quick', executions: undefined, target: '.' })).toBeNull();
  });

  it('omits the follow-up command when no target was given', () => {
    const d = scanDepthDisclosure({ scanDepth: 'quick', executions: executions(6) });
    expect(d!.scoreSuffix).toContain('over 6 of');
    expect(d!.followup).toBeUndefined();
  });

  it('quotes the target in the follow-up command', () => {
    const hostile = "my dir'; touch PWNED; echo '";
    const d = scanDepthDisclosure({ scanDepth: 'quick', executions: executions(6), target: hostile });
    expect(d!.followup).toContain(`secure ${citationTarget(hostile)}`);
    expect(d!.followup).not.toContain(`secure ${hostile}`);
  });
});

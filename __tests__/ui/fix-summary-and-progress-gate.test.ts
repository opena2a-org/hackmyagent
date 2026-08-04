/**
 * #285 — the last two `cli.ts` behaviours that no test could reach.
 *
 * Both lived inside Commander action handlers. `cli.ts` builds its program at
 * import time, so its behaviours were only ever asserted by grepping the
 * source — which proves a line is written down, not that it runs or that it
 * says what the grep assumed.
 *
 * 1. The fix-report opening sentence. "Fixed N issues" once counted every
 *    ATTEMPT, so a run whose only fix was PROVEN not to have landed opened in
 *    green with "Fixed 1 issue:". The rule is: lead with what was confirmed,
 *    and a run with nothing confirmed does not get to claim a repair.
 *
 * 2. The `--deep` progress gate. Covering the WRITE end to end needs a PTY, an
 *    ANTHROPIC_API_KEY and ~55s of real LLM round-trips, and the write is one
 *    line. The GATE is where the risk is: the counter is `\r`-based and would
 *    corrupt a JSON document or a diffed CI log.
 */
import { describe, it, expect } from 'vitest';
import { fixSummaryLine } from '../../src/ui/fix-summary';
import { shouldShowDeepProgress } from '../../src/ui/progress-gate';

describe('#285 fix-report opening sentence', () => {
  it('never claims a repair when nothing was confirmed', () => {
    // THE property, and the regression that produced this wording. Asserted
    // over the whole shape of the branch rather than on one example: for every
    // attempted count, a run with zero verified must not say "Fixed".
    for (let attempted = 1; attempted <= 5; attempted++) {
      const s = fixSummaryLine(attempted, 0, attempted);
      expect(s.tone).toBe('none-confirmed');
      expect(s.text, `attempted=${attempted} claimed a repair`).not.toContain('Fixed');
      expect(s.text).toContain('none confirmed');
    }
  });

  it('leads with what was confirmed when every fix landed', () => {
    expect(fixSummaryLine(3, 3, 0)).toEqual({
      tone: 'confirmed',
      text: 'Fixed 3 issues (3 verified):',
    });
  });

  it('omits the verified suffix when the pass never ruled', () => {
    // Legacy runs where verification did not execute: nothing was disproved,
    // so the green claim stands, but there is no verified count to advertise.
    expect(fixSummaryLine(2, 0, 0)).toEqual({ tone: 'confirmed', text: 'Fixed 2 issues:' });
  });

  it('names both counts when the result is mixed', () => {
    const s = fixSummaryLine(3, 1, 2);
    expect(s.tone).toBe('partial');
    expect(s.text).toBe('Attempted 3 fixes — 1 verified, 2 not confirmed:');
  });

  it('agrees with itself about singular and plural', () => {
    // `issue`/`issues` and `fix`/`fixes` are two different pluralisations in
    // two different branches; a copy-paste between them is the likely defect.
    expect(fixSummaryLine(1, 1, 0).text).toContain('1 issue ');
    expect(fixSummaryLine(2, 2, 0).text).toContain('2 issues ');
    expect(fixSummaryLine(1, 0, 1).text).toContain('1 fix,');
    expect(fixSummaryLine(2, 0, 2).text).toContain('2 fixes,');
    expect(fixSummaryLine(1, 1, 1).text).toContain('1 fix —');
    expect(fixSummaryLine(2, 1, 1).text).toContain('2 fixes —');
  });

  it('always ends in a colon, because a list follows it', () => {
    for (const s of [fixSummaryLine(1, 1, 0), fixSummaryLine(1, 0, 1), fixSummaryLine(2, 1, 1)]) {
      expect(s.text.endsWith(':')).toBe(true);
    }
  });

  it('reserves the green tone for the confirmed claim', () => {
    // The tone drives the colour at the call site. Green on a run that
    // confirmed nothing is the original defect wearing a different hat.
    expect(fixSummaryLine(1, 0, 1).tone).not.toBe('confirmed');
    expect(fixSummaryLine(2, 1, 1).tone).not.toBe('confirmed');
    expect(fixSummaryLine(1, 1, 0).tone).toBe('confirmed');
  });
});

describe('#285 --deep progress gate', () => {
  const ON = { deep: true, isTty: true };

  it('shows the counter only for an interactive --deep run', () => {
    expect(shouldShowDeepProgress(ON)).toBe(true);
  });

  it('is silent whenever the output is something else parses', () => {
    // Each suppressor asserted INDEPENDENTLY. A gate that only suppressed on
    // `json` would pass a test that set json and ci together.
    for (const suppressor of [{ json: true }, { ci: true }, { ciMode: true }, { isTty: false }]) {
      expect(
        shouldShowDeepProgress({ ...ON, ...suppressor }),
        `${JSON.stringify(suppressor)} did not suppress the counter`,
      ).toBe(false);
    }
  });

  it('cannot be re-enabled by any combination of the other terms', () => {
    // Deny-dominance. The counter is `\r`-based: leaking it into a JSON
    // document or a diffed CI log corrupts them.
    const flags = ['json', 'ci', 'ciMode'] as const;
    for (let mask = 1; mask < 1 << flags.length; mask++) {
      const ctx: Record<string, boolean> = { ...ON };
      flags.forEach((f, i) => { if (mask & (1 << i)) ctx[f] = true; });
      expect(shouldShowDeepProgress(ctx), `${JSON.stringify(ctx)} showed the counter`).toBe(false);
    }
  });

  it('needs --deep at all', () => {
    // Without the long pass there is nothing to report progress on, so the
    // counter must not appear on an ordinary interactive run.
    expect(shouldShowDeepProgress({ deep: false, isTty: true })).toBe(false);
    expect(shouldShowDeepProgress({ isTty: true })).toBe(false);
  });

  it('treats a missing isTty as not a terminal', () => {
    // `process.stderr.isTTY` is `undefined`, not `false`, when stderr is
    // redirected — the exact value this gate sees in CI.
    expect(shouldShowDeepProgress({ deep: true })).toBe(false);
    expect(shouldShowDeepProgress({ deep: true, isTty: undefined })).toBe(false);
  });
});

/**
 * HMA-21.AC1 — the 47 rows of the CPO reconciliation (2026-09-01, binding
 * spec Part 1 §1), table-driven, with `today` injected as `2026-09-01`.
 *
 * RED ON BASE a598f616: the parser there has no trailing-comment strip, no
 * `expires:`, no `<path>:<CHECK-ID>` form and no errors — `parseHmaIgnore`
 * does not exist, so this suite cannot even import. At the fix every row
 * classifies exactly as the reconciliation lists it.
 *
 * Parse order (a)-(h) is exercised as written: BOM strip and skip rules (a),
 * trailing comments (b), end-pulled `expires:` attributes (c), `!` patterns
 * (d), last-colon suffix classification (e), the two check-pattern
 * expressions (f), the path-glob refusal (g), and the injected `today` (h).
 * Patterns are matched case-insensitively and stored UPPER-CASED.
 */
import { describe, it, expect } from 'vitest';
import { parseHmaIgnore } from '../../src/hardening/scanner';

const TODAY = '2026-09-01';

type Accept = {
  row: string;
  channel: 'hmaignore-path' | 'hmaignore-check' | 'hmaignore-path-check';
  path?: string;
  checkId?: string;
  reason?: string;
  expires?: string;
};

/** ACCEPT rows — each with the expected value verbatim. */
const ACCEPT: Accept[] = [
  { row: 'danger.py', channel: 'hmaignore-path', path: 'danger.py' },
  { row: 'weird:name.py', channel: 'hmaignore-path', path: 'weird:name.py' },
  { row: 'logs/run-2026-09-01T10:30:00.log', channel: 'hmaignore-path', path: 'logs/run-2026-09-01T10:30:00.log' },
  { row: 'snapshot-10:30', channel: 'hmaignore-path', path: 'snapshot-10:30' },
  { row: 'app/[slug]/page.tsx', channel: 'hmaignore-path', path: 'app/[slug]/page.tsx' },
  { row: 'danger.py # r', channel: 'hmaignore-path', path: 'danger.py', reason: 'r' },
  { row: 'danger.py expires:2099-12-31', channel: 'hmaignore-path', path: 'danger.py', expires: '2099-12-31' },
  { row: 'danger.py:NEMO-009 # r', channel: 'hmaignore-path-check', path: 'danger.py', checkId: 'NEMO-009', reason: 'r' },
  // matched case-insensitively, stored UPPER-CASED
  { row: 'danger.py:nemo-009 # r', channel: 'hmaignore-path-check', path: 'danger.py', checkId: 'NEMO-009', reason: 'r' },
  { row: 'skills/aria-trap/SKILL.md:AST-CRED-001 # canary telemetry', channel: 'hmaignore-path-check', path: 'skills/aria-trap/SKILL.md', checkId: 'AST-CRED-001', reason: 'canary telemetry' },
  // the CA's row, now true (the star expression is separate from the id expression)
  { row: 'SKILL.md:SKILL-* # r', channel: 'hmaignore-path-check', path: 'SKILL.md', checkId: 'SKILL-*', reason: 'r' },
  { row: 'SKILL.md:SKILL-0* # r', channel: 'hmaignore-path-check', path: 'SKILL.md', checkId: 'SKILL-0*', reason: 'r' },
  { row: 'SKILL.md:*-001 # r', channel: 'hmaignore-path-check', path: 'SKILL.md', checkId: '*-001', reason: 'r' },
  // disclosed as such; CPO pre-mortem 1
  { row: 'weird:bar-baz # r', channel: 'hmaignore-path-check', path: 'weird', checkId: 'BAR-BAZ', reason: 'r' },
  { row: '!NEMO-009', channel: 'hmaignore-check', checkId: 'NEMO-009' },
  { row: '!nemo-009', channel: 'hmaignore-check', checkId: 'NEMO-009' },
  { row: '!NEMO-0*', channel: 'hmaignore-check', checkId: 'NEMO-0*' },
  { row: '!*-009', channel: 'hmaignore-check', checkId: '*-009' },
  // `!*` stays legal: presentational, matches at least one check
  { row: '!*', channel: 'hmaignore-check', checkId: '*' },
  { row: '!NEMO-009 # r', channel: 'hmaignore-check', checkId: 'NEMO-009', reason: 'r' },
  // the attribute token is case-insensitive
  { row: '!NEMO-009 EXPIRES:2099-12-31', channel: 'hmaignore-check', checkId: 'NEMO-009', expires: '2099-12-31' },
  // expires on the named day is ACTIVE (inclusive): today <= date
  { row: `danger.py:NEMO-009 expires:${TODAY} # r`, channel: 'hmaignore-path-check', path: 'danger.py', checkId: 'NEMO-009', reason: 'r', expires: TODAY },
];

/** Rows step (a) skips outright — neither a rule nor an error. */
const SKIPPED: Array<{ label: string; row: string }> = [
  { label: 'a whole-line comment', row: '# comment' },
  { label: 'a blank line', row: '' },
  { label: 'a whitespace-only line', row: '   ' },
  { label: 'a BOM before the first rule', row: '\uFEFF' + 'danger.py' },
];

/** REJECT rows — each an errors[] entry with its content, and the line is inert. */
const REJECT: Array<{ row: string; error: RegExp }> = [
  { row: 'SKILL.md:*', error: /write `SKILL\.md`/ },
  { row: 'SKILL.md:*-*', error: /write `SKILL\.md`/ },
  { row: 'danger.py:NEMO-009', error: /requires a reason/ },
  { row: 'danger.py:NEMO-009 #', error: /requires a reason/ },
  { row: 'weird:bar-baz', error: /requires a reason/ },
  { row: '*.py', error: /globs are not supported in path rules/ },
  { row: 'dan*', error: /globs are not supported in path rules/ },
  { row: 'src/*:NEMO-009 # r', error: /globs are not supported in path rules/ },
  { row: ':NEMO-009 # r', error: /empty path/ },
  { row: '!', error: /empty check pattern/ },
  { row: '!NEMO', error: /not a check pattern/ },
  { row: '!name.py', error: /not a check pattern/ },
  { row: '!NEMO-009 extra', error: /not a check pattern/ },
  { row: 'SKILL.md:SK!LL-* # r', error: /malformed check pattern/ },
  { row: 'expires:2026-13-45', error: /not a valid date/ },
  { row: 'expires:', error: /not a valid date/ },
  { row: 'expires:2026-1-5', error: /not a valid date/ },
  { row: 'expires:2026-02-30', error: /not a valid date/ },
  { row: 'expires:2099-12-31 danger.py', error: /`expires:` must follow the rule/ },
  { row: 'danger.py expires:2099-12-31 expires:2099-12-31', error: /two `expires:`/ },
  // with T = 2026-09-01, a 2026-08-31 expiry has lapsed: the line is inert
  // and loud, and its findings return to the report
  { row: 'danger.py:NEMO-009 expires:2026-08-31 # r', error: /expired on 2026-08-31/ },
];

describe('HMA-21.AC1 — the 47-row reconciliation table (today = 2026-09-01)', () => {
  it('HMA-21.AC1 carries the 47 rows', () => {
    expect(ACCEPT.length + SKIPPED.length + REJECT.length).toBe(47);
  });

  for (const a of ACCEPT) {
    it(`HMA-21.AC1 ACCEPT ${JSON.stringify(a.row)} → ${a.channel}`, () => {
      const { rules, errors } = parseHmaIgnore(a.row, TODAY);
      expect(errors).toEqual([]);
      expect(rules).toHaveLength(1);
      const r = rules[0];
      expect(r.line).toBe(1);
      expect(r.rule).toBe(a.row.trim());
      expect(r.channel).toBe(a.channel);
      expect(r.path).toBe(a.path);
      expect(r.checkId).toBe(a.checkId);
      expect(r.reason).toBe(a.reason);
      expect(r.expires).toBe(a.expires);
    });
  }

  for (const s of SKIPPED) {
    it(`HMA-21.AC1 SKIP ${s.label}`, () => {
      const { rules, errors } = parseHmaIgnore(s.row, TODAY);
      expect(errors).toEqual([]);
      if (s.row.includes('danger.py')) {
        // the BOM row still parses the rule under it, path `danger.py`
        expect(rules).toEqual([
          { line: 1, rule: 'danger.py', channel: 'hmaignore-path', path: 'danger.py' },
        ]);
      } else {
        expect(rules).toEqual([]);
      }
    });
  }

  for (const rej of REJECT) {
    it(`HMA-21.AC1 REJECT ${JSON.stringify(rej.row)} → ${rej.error}`, () => {
      const { rules, errors } = parseHmaIgnore(rej.row, TODAY);
      // the line is inert: an error, never a rule, never a silent fallback
      expect(rules).toEqual([]);
      expect(errors).toHaveLength(1);
      expect(errors[0].line).toBe(1);
      expect(errors[0].rule).toBe(rej.row.trim());
      expect(errors[0].error).toMatch(rej.error);
    });
  }

  it('HMA-21.AC1 errors carry their 1-based line in a multi-line file', () => {
    const content = REJECT.map((r) => r.row).join('\n');
    const { rules, errors } = parseHmaIgnore(content, TODAY);
    expect(rules).toEqual([]);
    expect(errors.map((e) => e.line)).toEqual(REJECT.map((_, i) => i + 1));
  });

  it('HMA-21.AC1 accepted rows keep their 1-based line in a multi-line file', () => {
    const content = ['# header', ...ACCEPT.map((a) => a.row)].join('\n');
    const { rules, errors } = parseHmaIgnore(content, TODAY);
    expect(errors).toEqual([]);
    expect(rules.map((r) => r.line)).toEqual(ACCEPT.map((_, i) => i + 2));
  });
});

// Requires Node 23 or newer: the first expression below carries an inline
// case-modifier group that older Node versions reject at parse time with
// "Invalid group". On an older runtime this file fails to load with that loud
// error instead of passing while checking nothing. Continuous integration runs
// Node 24 on Linux and macOS.
//
// This suite freezes, per file, the number of lines on the five public
// surfaces (src, __tests__, docs, README.md, CHANGELOG.md) that match either
// expression below. It is green against the tree as delivered, turns red when
// a matching line is added anywhere on those surfaces, and turns red when one
// is removed without lowering the frozen entry here — the frozen maps are
// exact, not ceilings.
import { describe, it, expect, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const REPO_ROOT = path.join(__dirname, '..', '..');

// This file's own repository-relative path. The walk skips exactly this one
// path because the file must contain what it forbids; its own matching lines
// are pinned separately by SELF_HITS below.
const SELF_PATH = '__tests__/gate/no-internal-attribution.test.ts';

const SURFACES = ['src', '__tests__', 'docs', 'README.md', 'CHANGELOG.md'];

// Both expression sources are pasted verbatim and must stay byte-identical to
// their upstream definition, so they are built with String.raw: a
// slash-delimited literal would need every '/' escaped and would no longer be
// byte-identical. They run in Node only, never through a shell tool.
const PATTERN = new RegExp(String.raw`\[CHIEF-|\bCHIEF\b|\b(CPO|CCO|CISO|CSR|CDS|CDE|DPO)\b|\bCA \(\d\)|\b(CPO|CCO|CISO|CSR|CDS|CDE|DPO|CA)-\d{3}\b|COUNCIL_LEDGER|\bbriefs/|hackmyagent/CLAUDE\.md|\btodo/|\bqgf/|\.claude-sessions|(?i:chief (data scientist|security researcher|architect|product officer|information security officer|communications officer)|chief council)`);
const VENDOR = new RegExp(String.raw`(claude|anthropic)[-\s](review|generat|label|train|curat|assist|audit)\w*|(review|generat|label|train|curat|built|powered|assisted)\w*\s+by\s+(claude|anthropic)|Claude Code Review`, 'i');

// Lines exempted from the second expression. An entry exempts a line only when
// the file path and the exact line content after trimming are both equal —
// never by pattern or substring. Every entry must still match a line on disk;
// a stale entry fails the suite instead of silently widening the exemption.
const ALLOWLIST: ReadonlyArray<{ file: string; line: string }> = [
  {
    // The vendor name is the grammatical object of the line — a pinned action
    // path — and the line stays because deleting or renaming it makes the
    // statement false.
    file: '__tests__/gate/pr-review-partition.test.ts',
    line: 'expect(uses).toBe(`opena2a-org/.github/actions/claude-review@${EXPECTED_PIN}`);',
  },
  {
    // The vendor name is the grammatical object of the line — a corpus file
    // path — and the line stays because deleting or renaming it makes the
    // statement false.
    file: '__tests__/nanomind-core/scanner-fp-regression.test.ts',
    line: '*      training/corpus/claude-review-batch.json — adversarial training',
  },
  {
    // The vendor name is the grammatical object of the line — a corpus file
    // path — and the line stays because deleting or renaming it makes the
    // statement false.
    file: '__tests__/nanomind-core/scanner-fp-regression.test.ts',
    line: '// (2) AST-CRED-002 corpus carve-out — training/corpus/claude-review-batch.json',
  },
  {
    // The vendor name is the grammatical object of the line — a corpus file
    // path — and the line stays because deleting or renaming it makes the
    // statement false.
    file: '__tests__/nanomind-core/scanner-fp-regression.test.ts',
    line: "expect(isCorpusPath('training/corpus/claude-review-batch.json')).toBe(true);",
  },
  {
    // The vendor name is the grammatical object of the line — a corpus file
    // path — and the line stays because deleting or renaming it makes the
    // statement false.
    file: '__tests__/nanomind-core/scanner-fp-regression.test.ts',
    line: "artifactPath: 'training/corpus/claude-review-batch.json',",
  },
];

// One walker for both the tree assertions and the planted-shape cases: it
// takes a root directory and one expression, visits whichever of the five
// surfaces exist under that root, recurses every directory and reads every
// regular file. Exactly two skips: a file whose first 8000 bytes contain a NUL
// byte, and SELF_PATH. No extension filter, no other skip list, no ignore-file
// reading — the measured condition is a clean clone.
function scan(
  root: string,
  expression: RegExp,
): { hits: Map<string, number[]>; binarySkipped: string[] } {
  const hits = new Map<string, number[]>();
  const binarySkipped: string[] = [];
  const visit = (p: string): void => {
    const stat = fs.statSync(p);
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(p).sort()) visit(path.join(p, entry));
      return;
    }
    if (!stat.isFile()) return;
    const rel = path.relative(root, p).split(path.sep).join('/');
    if (rel === SELF_PATH) return;
    const buf = fs.readFileSync(p);
    if (buf.subarray(0, 8000).includes(0)) {
      binarySkipped.push(rel);
      return;
    }
    buf
      .toString('utf8')
      .split('\n')
      .forEach((line, index) => {
        if (!expression.test(line)) return;
        if (ALLOWLIST.some((e) => e.file === rel && e.line === line.trim())) return;
        const found = hits.get(rel) ?? [];
        found.push(index + 1);
        hits.set(rel, found);
      });
  };
  for (const surface of SURFACES) {
    const p = path.join(root, surface);
    if (fs.existsSync(p)) visit(p);
  }
  return { hits, binarySkipped };
}

// Frozen per-file counts of lines matching the first expression, measured on
// the delivered tree: 82 files, 211 lines. Line numbers are deliberately not
// pinned — unrelated edits would shift them.
const PATTERN_BASELINE: Record<string, number> = {
  'CHANGELOG.md': 31,
  '__tests__/checker/check-not-found-json.test.ts': 1,
  '__tests__/checker/check-secure-cross-analyzer-parity.test.ts': 2,
  '__tests__/cli/benchmark-empty-denominator.test.ts': 1,
  '__tests__/cli/deep-scan-incomplete-verdict.test.ts': 1,
  '__tests__/cli/fix-lines-render.test.ts': 1,
  '__tests__/cli/hma08-mark-stub.test.ts': 2,
  '__tests__/cli/hma08-pull-stubs.test.ts': 2,
  '__tests__/cli/machine-posture-not-scored.test.ts': 1,
  '__tests__/cli/opena2a-citation-and-next-steps-target.test.ts': 1,
  '__tests__/cli/scan-soul-conformance-gate.test.ts': 2,
  '__tests__/cli/secure-help-check-count-derived.test.ts': 1,
  '__tests__/cli/secure-unread-input-gate.test.ts': 2,
  '__tests__/cli/verdict-requires-measurement.test.ts': 2,
  '__tests__/gate/pr-review-partition.test.ts': 1,
  '__tests__/hardening/absent-subject-not-applicable.test.ts': 1,
  '__tests__/hardening/analyst-findings-redaction.test.ts': 1,
  '__tests__/hardening/config-credential-depth.test.ts': 1,
  '__tests__/hardening/credential-preview-truncation.test.ts': 1,
  '__tests__/hardening/credential-store-basenames.test.ts': 1,
  '__tests__/hardening/finding-cast-launder-guard.test.ts': 1,
  '__tests__/hardening/finding-emit-fix-lines.test.ts': 1,
  '__tests__/hardening/fix-verification-attribution.test.ts': 1,
  '__tests__/hardening/ignore-suppression-scope.test.ts': 1,
  '__tests__/hardening/redaction-provenance-boundaries.test.ts': 2,
  '__tests__/hardening/redaction-provenance-reader.test.ts': 2,
  '__tests__/hardening/scanner.path-context.test.ts': 1,
  '__tests__/hardening/scanner.rag-mem-context.test.ts': 1,
  '__tests__/hardening/shell-credential-exfil.test.ts': 2,
  '__tests__/harness/hermetic-home.test.ts': 1,
  '__tests__/helpers/exit-surface-baseline.ts': 3,
  '__tests__/mcp/mcp-root-confinement.test.ts': 1,
  '__tests__/nanomind-core/analyst-coverage.test.ts': 1,
  '__tests__/nanomind-core/analyst-escalation-wiring.test.ts': 3,
  '__tests__/nanomind-core/fix-generator-scope-dispatch.test.ts': 1,
  '__tests__/nanomind-core/scanner-fp-regression.test.ts': 2,
  '__tests__/scanner/governance-cross-surface.test.ts': 1,
  '__tests__/semantic/credential-context-git-state.test.ts': 1,
  '__tests__/skills/create-skill-output-clean.test.ts': 2,
  '__tests__/soul/scanner-profile-mismatch.test.ts': 1,
  '__tests__/soul/soul-corpus-direction.test.ts': 2,
  '__tests__/telemetry/exit-surface.test.ts': 1,
  '__tests__/ui/analyst-dissent.test.ts': 1,
  'docs/design/redteam-nanomind-judge.md': 4,
  'docs/release-playbook.md': 11,
  'docs/testing/release-smoke.md': 2,
  'src/attack/payloads/capability-abuse.ts': 10,
  'src/benchmarks/benchmark-report.ts': 1,
  'src/benchmarks/oasb-1.ts': 3,
  'src/check/narrative-fetch.ts': 1,
  'src/check/render-rich-block.ts': 1,
  'src/check/rich-block-adapter.ts': 1,
  'src/check/skill-mcp-check.ts': 1,
  'src/cli-prefix.ts': 1,
  'src/cli.ts': 19,
  'src/eval/oracle.ts': 1,
  'src/hardening/finding-emit.ts': 2,
  'src/hardening/path-context.ts': 4,
  'src/hardening/scanner.ts': 12,
  'src/hardening/security-check.ts': 3,
  'src/hardening/settled-outcome.ts': 3,
  'src/mcp-server.ts': 4,
  'src/mcp/roots.ts': 2,
  'src/nanomind-core/analyst-coverage.ts': 4,
  'src/nanomind-core/analyzers/credential-analyzer.ts': 3,
  'src/nanomind-core/index.ts': 2,
  'src/nanomind-core/inference/security-analyst.ts': 1,
  'src/nanomind-core/orchestrate.ts': 6,
  'src/nanomind-core/scanner-bridge.ts': 1,
  'src/narrative/build-narrative.ts': 1,
  'src/narrative/index.ts': 1,
  'src/narrative/mcp-narrative.ts': 1,
  'src/narrative/narrative-summary.ts': 3,
  'src/narrative/publish-narrative.ts': 1,
  'src/narrative/skill-narrative.ts': 2,
  'src/narrative/wire-publish.ts': 2,
  'src/output/json-stdout.ts': 1,
  'src/registry/stub-writeback.ts': 2,
  'src/semantic/integration/finding-adapter.ts': 1,
  'src/soul/scanner.ts': 2,
  'src/store/project-store.ts': 1,
  'src/ui/analyst-dissent.ts': 1,
};

// Frozen per-file counts of non-exempted lines matching the second expression,
// measured on the delivered tree: 3 files, 8 lines.
const VENDOR_BASELINE: Record<string, number> = {
  'src/nanomind-core/security/defense-in-depth.ts': 3,
  '__tests__/nanomind-core/defense-in-depth.test.ts': 3,
  'CHANGELOG.md': 2,
};

const PATTERN_GUIDANCE =
  "name the control, not the role; for the reader persona write 'security manager'; for TLS write 'certificate signing request' in full";
const VENDOR_GUIDANCE =
  'the vendor is named as the actor; state what was done without naming who did it';
const REMOVED_GUIDANCE =
  'a matching line was removed; lower the frozen entry for this file (delete it at zero)';

// Returns one problem line per deviation from the frozen map, listing every
// matching file:line of a file whose count rose or is new.
function compareToBaseline(
  actual: Map<string, number[]>,
  baseline: Record<string, number>,
  guidance: string,
): string[] {
  const problems: string[] = [];
  const files = new Set([...actual.keys(), ...Object.keys(baseline)]);
  for (const file of [...files].sort()) {
    const lines = actual.get(file) ?? [];
    const frozen = baseline[file] ?? 0;
    if (lines.length > frozen) {
      problems.push(
        `${file}: ${lines.length} matching lines, ${frozen} frozen — ${guidance}`,
        ...lines.map((n) => `  ${file}:${n}`),
      );
    } else if (lines.length < frozen) {
      problems.push(`${file}: ${lines.length} matching lines, ${frozen} frozen — ${REMOVED_GUIDANCE}`);
    }
  }
  return problems;
}

// Planted-shape data. Every string below is data: it is quoted nowhere else in
// this file, and the leaf names describe each shape's class in plain words
// instead. The first seven are caught by the first expression, the last three
// by the second.
const CAUGHT_SHAPES: readonly string[] = [
  '[CHIEF-CA] 2026-01-01',
  'CISO Rule 11',
  'CDS-024',
  'per [CSR-003]',
  'CISO-readable',
  'briefs/x.md',
  'COUNCIL_LEDGER',
  'Claude-reviewed',
  'reviewed by Claude',
  'Claude Code Review',
];

// Shapes that must be caught by neither expression.
const BENIGN_SHAPES: readonly string[] = [
  'certificate authority (CA)',
  '.claude/settings.json',
  'ClaudeBot',
  'HMA-21.AC1',
  'CVE-001',
  '@anthropic-ai/sdk',
];

// A pinned line with a different pin: exempted content is exact, so this one
// is counted even at the exempted path.
const OTHER_PIN_LINE =
  'expect(uses).toBe(`opena2a-org/.github/actions/claude-review@dcb77137b11cb33c11e76cf6435b7676bd568d01`);';

// The number of lines of this very file on which either expression matches,
// measured on the file as delivered: the two expression sources (2), the ten
// planted shapes above (10), the five exempted line contents (5) and the
// different-pin line (1). Any new matching line here — in a comment, a leaf
// name or a message — moves this number and fails the suite.
const SELF_HITS = 18;

const plantedRoots: string[] = [];
afterAll(() => {
  for (const root of plantedRoots) fs.rmSync(root, { recursive: true, force: true });
});

// Writes one line into a file under a fresh temporary directory laid out like
// the repository, then runs the shared walker over it, so a planted shape
// travels the same code path as a real hit.
function plantedHits(
  content: string,
  expression: RegExp,
  rel = 'src/planted.txt',
): Map<string, number[]> {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'attribution-gate-'));
  plantedRoots.push(root);
  const target = path.join(root, rel);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `${content}\n`);
  return scan(root, expression).hits;
}

function expectCaughtOnce(shape: string, catches: RegExp, misses: RegExp): void {
  const rel = 'src/planted.txt';
  const caught = plantedHits(shape, catches, rel);
  expect(caught.size).toBe(1);
  expect(caught.get(rel)).toEqual([1]);
  expect(plantedHits(shape, misses, rel).size).toBe(0);
}

function expectBenign(shape: string): void {
  expect(plantedHits(shape, PATTERN).size).toBe(0);
  expect(plantedHits(shape, VENDOR).size).toBe(0);
}

describe('internal attribution stays off the public surfaces', () => {
  it('HMA-37.AC1 both expressions compile, the first with no flags and the second case-insensitive', () => {
    expect(PATTERN.flags).toBe('');
    expect(VENDOR.flags).toBe('i');
  });

  it('HMA-37.AC2 the tree walk covers the five surfaces and skips exactly the known image files', () => {
    const { binarySkipped } = scan(REPO_ROOT, PATTERN);
    expect([...binarySkipped].sort()).toEqual([
      'docs/hackmyagent-demo.gif',
      'docs/images/secure-demo.png',
      'docs/vhs/attack-dvaa.gif',
    ]);
  });

  it('HMA-37.AC3 every public-surface file carries exactly the frozen number of lines matching the first expression', () => {
    expect(Object.keys(PATTERN_BASELINE)).toHaveLength(82);
    expect(Object.values(PATTERN_BASELINE).reduce((a, b) => a + b, 0)).toBe(211);
    const { hits } = scan(REPO_ROOT, PATTERN);
    expect(compareToBaseline(hits, PATTERN_BASELINE, PATTERN_GUIDANCE)).toEqual([]);
  });

  it('HMA-37.AC4 every exempted line still exists on disk with exactly the recorded content', () => {
    for (const entry of ALLOWLIST) {
      const lines = fs.readFileSync(path.join(REPO_ROOT, entry.file), 'utf8').split('\n');
      expect(
        lines.some((line) => line.trim() === entry.line),
        `${entry.file} no longer carries a recorded line`,
      ).toBe(true);
    }
  });

  it('HMA-37.AC4 every public-surface file carries exactly the frozen number of non-exempted lines matching the second expression', () => {
    expect(Object.values(VENDOR_BASELINE).reduce((a, b) => a + b, 0)).toBe(8);
    const { hits } = scan(REPO_ROOT, VENDOR);
    expect(compareToBaseline(hits, VENDOR_BASELINE, VENDOR_GUIDANCE)).toEqual([]);
  });

  it('HMA-37.AC5 a bracketed governance tag with a date is caught by the first expression alone', () => {
    expectCaughtOnce(CAUGHT_SHAPES[0], PATTERN, VENDOR);
  });

  it('HMA-37.AC5 a role-qualified rule number is caught by the first expression alone', () => {
    expectCaughtOnce(CAUGHT_SHAPES[1], PATTERN, VENDOR);
  });

  it('HMA-37.AC5 a role-prefixed decision identifier is caught by the first expression alone', () => {
    expectCaughtOnce(CAUGHT_SHAPES[2], PATTERN, VENDOR);
  });

  it('HMA-37.AC5 a bracketed decision citation is caught by the first expression alone', () => {
    expectCaughtOnce(CAUGHT_SHAPES[3], PATTERN, VENDOR);
  });

  it('HMA-37.AC5 a role token used as a compound qualifier is caught by the first expression alone', () => {
    expectCaughtOnce(CAUGHT_SHAPES[4], PATTERN, VENDOR);
  });

  it('HMA-37.AC5 a private artifact directory path is caught by the first expression alone', () => {
    expectCaughtOnce(CAUGHT_SHAPES[5], PATTERN, VENDOR);
  });

  it('HMA-37.AC5 a private ledger constant name is caught by the first expression alone', () => {
    expectCaughtOnce(CAUGHT_SHAPES[6], PATTERN, VENDOR);
  });

  it('HMA-37.AC5 the vendor name hyphenated to a review verb is caught by the second expression alone', () => {
    expectCaughtOnce(CAUGHT_SHAPES[7], VENDOR, PATTERN);
  });

  it('HMA-37.AC5 a review verb followed by the vendor name is caught by the second expression alone', () => {
    expectCaughtOnce(CAUGHT_SHAPES[8], VENDOR, PATTERN);
  });

  it('HMA-37.AC5 the vendor review product named in full is caught by the second expression alone', () => {
    expectCaughtOnce(CAUGHT_SHAPES[9], VENDOR, PATTERN);
  });

  it('HMA-37.AC6 this file carries matching lines only in its data constants, in the frozen number', () => {
    const lines = fs.readFileSync(__filename, 'utf8').split('\n');
    const matching = lines.filter((line) => PATTERN.test(line) || VENDOR.test(line));
    expect(matching).toHaveLength(SELF_HITS);
  });

  it('HMA-37.AC7 the certificate-authority abbreviation expanded in prose is caught by neither expression', () => {
    expectBenign(BENIGN_SHAPES[0]);
  });

  it('HMA-37.AC7 a local settings file path is caught by neither expression', () => {
    expectBenign(BENIGN_SHAPES[1]);
  });

  it('HMA-37.AC7 a bot account name is caught by neither expression', () => {
    expectBenign(BENIGN_SHAPES[2]);
  });

  it('HMA-37.AC7 a work-item criterion identifier is caught by neither expression', () => {
    expectBenign(BENIGN_SHAPES[3]);
  });

  it('HMA-37.AC7 a check identifier of this tool is caught by neither expression', () => {
    expectBenign(BENIGN_SHAPES[4]);
  });

  it('HMA-37.AC7 a runtime dependency package name is caught by neither expression', () => {
    expectBenign(BENIGN_SHAPES[5]);
  });

  it('HMA-37.AC7 a pinned action line at its recorded path with its recorded content is not counted', () => {
    expect(plantedHits(ALLOWLIST[0].line, VENDOR, ALLOWLIST[0].file).size).toBe(0);
  });

  it('HMA-37.AC7 the same path with a different pin is counted', () => {
    expect(plantedHits(OTHER_PIN_LINE, VENDOR, ALLOWLIST[0].file).get(ALLOWLIST[0].file)).toEqual([
      1,
    ]);
  });

  it('HMA-37.AC7 the recorded content at any other path is counted', () => {
    expect(plantedHits(ALLOWLIST[0].line, VENDOR, 'src/planted.txt').get('src/planted.txt')).toEqual(
      [1],
    );
  });
});

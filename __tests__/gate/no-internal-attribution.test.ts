// Requires Node 23 or newer: the first expression below carries an inline
// case-modifier group that older Node versions reject at parse time with
// "Invalid group". On an older runtime this file fails to load with that loud
// error instead of passing while checking nothing. Continuous integration runs
// Node 24 on Linux and macOS.
//
// This suite freezes, per file, the number of lines anywhere in the tracked
// tree that match either expression below. The walk's roots are the top-level
// paths of the committed tree, read from git, so a new top-level directory is
// walked from the commit that adds it. The suite is green against the tree as
// delivered, turns red when a matching line is added anywhere in the tree, and
// turns red when one is removed without lowering the frozen entry here — the
// frozen maps are exact, not ceilings.
import { describe, it, expect, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const REPO_ROOT = path.join(__dirname, '..', '..');

// This file's own repository-relative path. The walk skips exactly this one
// path because the file must contain what it forbids; its own matching lines
// are pinned separately by SELF_HITS below.
const SELF_PATH = '__tests__/gate/no-internal-attribution.test.ts';

// Runs one git command in `cwd` and returns its standard output. The walk uses
// it to read the tree's top-level paths; the planted-shape fixtures use it to
// build the one-commit repositories the walk runs over.
function git(cwd: string, ...args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

// The top-level paths of the committed tree at `root`, exactly as git lists
// them. This is the walk's only source of roots: no list of surfaces is kept
// in this file, so every tracked top-level path — src, __tests__, docs,
// scripts, .github, changelog.d, the root files and any directory added later
// — is walked. changelog.d holds the pending CHANGELOG entries, one file per
// change; they are public on main from the moment they merge, not only after
// a release.
function treeRoots(root: string): string[] {
  return git(root, 'ls-tree', '--name-only', 'HEAD')
    .split('\n')
    .filter((entry) => entry.length > 0);
}

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
    // The vendor name is the grammatical object of the line — the pinned
    // action path the review workflow runs — and the line stays because the
    // workflow is a gate file under the code owner's review path; the pin it
    // carries is the one the case above asserts.
    file: '.github/workflows/pr-review.yml',
    line: 'uses: opena2a-org/.github/actions/claude-review@dcb77137b11cb33c11e76cf6435b7676bd568d01',
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
// takes the root of a git repository and one expression, visits every
// top-level path of the committed tree at that root, recurses every directory
// and reads every regular file. Exactly two skips: a file whose first 8000
// bytes contain a NUL byte, and SELF_PATH. No extension filter, no other skip
// list, no ignore-file reading — the measured condition is a clean clone, and
// the roots it returns are the top-level paths it visited.
function scan(
  root: string,
  expression: RegExp,
): { hits: Map<string, number[]>; binarySkipped: string[]; roots: string[] } {
  const hits = new Map<string, number[]>();
  const binarySkipped: string[] = [];
  const roots: string[] = [];
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
  for (const entry of treeRoots(root)) {
    roots.push(entry);
    visit(path.join(root, entry));
  }
  return { hits, binarySkipped, roots };
}

// Frozen per-file counts of lines matching the first expression, measured on
// the delivered tree: 47 files, 116 lines. Line numbers are deliberately not
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

// The workflow's pinned action line with a different pin, for the same reason.
const OTHER_PIN_WORKFLOW_LINE =
  'uses: opena2a-org/.github/actions/claude-review@0123456789abcdef0123456789abcdef01234567';

// The number of lines of this very file on which either expression matches,
// measured on the file as delivered: the two expression sources (2), the ten
// planted shapes above (10), the six exempted line contents (6) and the two
// different-pin lines (2). Any new matching line here — in a comment, a leaf
// name or a message — moves this number and fails the suite.
const SELF_HITS = 20;

const plantedRoots: string[] = [];
afterAll(() => {
  for (const root of plantedRoots) fs.rmSync(root, { recursive: true, force: true });
});

// Writes each file of `files` (repository-relative path to content) under
// `root`, creating directories as needed.
function writeFiles(root: string, files: Record<string, string>): void {
  for (const [rel, content] of Object.entries(files)) {
    const target = path.join(root, rel);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, content);
  }
}

// Stages everything under `root` and commits it, so the committed tree the
// walk reads its roots from matches the files on disk. Identity and signing
// are fixed on the command line: the fixture must not depend on the
// developer's configuration.
function commitAll(root: string): void {
  git(root, 'add', '-A', '-f');
  git(
    root,
    '-c',
    'user.name=attribution-gate',
    '-c',
    'user.email=attribution-gate@example.invalid',
    '-c',
    'commit.gpgsign=false',
    'commit',
    '-q',
    '--no-verify',
    '--allow-empty',
    '-m',
    'planted',
  );
}

// A fresh temporary git repository with one commit carrying `files`, laid out
// like the repository, so a planted shape travels the same code path as a
// real hit: the walk reads its roots from this repository's tree.
function plantRepo(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'attribution-gate-'));
  plantedRoots.push(root);
  git(root, 'init', '-q');
  writeFiles(root, files);
  commitAll(root);
  return root;
}

// Writes one line into a file of a fresh one-commit repository, then runs the
// shared walker over it.
function plantedHits(
  content: string,
  expression: RegExp,
  rel = 'src/planted.txt',
): Map<string, number[]> {
  return scan(plantRepo({ [rel]: `${content}\n` }), expression).hits;
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

  it('HMA-79.AC1 the walk roots for the repository root are exactly the tracked top-level paths git lists', () => {
    const listed = execFileSync('git', ['ls-tree', '--name-only', 'HEAD'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    })
      .split('\n')
      .filter((entry) => entry.length > 0);
    const { roots } = scan(REPO_ROOT, PATTERN);
    expect([...roots].sort()).toEqual([...listed].sort());
    expect(new Set(roots).size).toBe(roots.length);
    // The six surfaces the walk once named by hand are a strict subset: the
    // tree carries scripts, the CI directory and the root files as well.
    for (const entry of ['src', '__tests__', 'docs', 'README.md', 'CHANGELOG.md', 'changelog.d']) {
      expect(roots).toContain(entry);
    }
    expect(roots).toContain('scripts');
    expect(roots).toContain('.github');
    expect(roots).toContain('package.json');
  });

  it('HMA-79.AC2 a matching line under a brand-new top-level directory and under scripts is reported, and no longer once removed', () => {
    const files = { 'tooling/notes.md': `${CAUGHT_SHAPES[1]}\n`, 'scripts/run.sh': `${CAUGHT_SHAPES[1]}\n` };
    const root = plantRepo(files);
    const planted = scan(root, PATTERN);
    expect([...planted.roots].sort()).toEqual(['scripts', 'tooling']);
    expect([...planted.hits.entries()].sort()).toEqual([
      ['scripts/run.sh', [1]],
      ['tooling/notes.md', [1]],
    ]);
    writeFiles(root, { 'tooling/notes.md': '', 'scripts/run.sh': '' });
    commitAll(root);
    const cleaned = scan(root, PATTERN);
    expect([...cleaned.roots].sort()).toEqual(['scripts', 'tooling']);
    expect(cleaned.hits.size).toBe(0);
  });

  it('HMA-37.AC2 the tree walk covers every tracked top-level path and skips exactly the known image files', () => {
    const { binarySkipped } = scan(REPO_ROOT, PATTERN);
    expect([...binarySkipped].sort()).toEqual([
      'docs/hackmyagent-demo.gif',
      'docs/images/secure-demo.png',
      'docs/vhs/attack-dvaa.gif',
      'docs/vhs/detect-inventory.png',
      'docs/vhs/detect-path-forward.png',
      'docs/vhs/detect.gif',
    ]);
  });

  it('HMA-37.AC3 every public-surface file carries exactly the frozen number of lines matching the first expression', () => {
    expect(Object.keys(PATTERN_BASELINE)).toHaveLength(47);
    expect(Object.values(PATTERN_BASELINE).reduce((a, b) => a + b, 0)).toBe(116);
    const { hits } = scan(REPO_ROOT, PATTERN);
    expect(compareToBaseline(hits, PATTERN_BASELINE, PATTERN_GUIDANCE)).toEqual([]);
  });

  it('changelog.d is walked and no frozen entry names a file under it: a fragment is fixed, never pinned', () => {
    // Fragment names carry a random suffix and move into CHANGELOG.md at
    // release, so a pin keyed on one cannot survive; every fragment's frozen
    // count is exactly 0 for both expressions.
    expect(treeRoots(REPO_ROOT)).toContain('changelog.d');
    for (const key of [...Object.keys(PATTERN_BASELINE), ...Object.keys(VENDOR_BASELINE)]) {
      expect(key.startsWith('changelog.d/'), `frozen entry ${key} names a changelog fragment`).toBe(false);
    }
    const dir = plantRepo({ 'changelog.d/x-abc123.md': `---\ntype: fixed\n---\n- ${CAUGHT_SHAPES[1]}\n` });
    expect([...scan(dir, PATTERN).hits.keys()]).toEqual(['changelog.d/x-abc123.md']);
  });

  it('HMA-79.AC5 no frozen entry names a path outside the six surfaces the walk once named by hand', () => {
    // Widening the walk added nothing to either frozen map: every matching
    // line outside those surfaces is either rewritten or exempted by an
    // exact-line entry, so a new one anywhere in the tree is reported.
    const inside = (key: string): boolean =>
      ['src/', '__tests__/', 'docs/', 'changelog.d/'].some((p) => key.startsWith(p)) ||
      key === 'README.md' ||
      key === 'CHANGELOG.md';
    for (const key of [...Object.keys(PATTERN_BASELINE), ...Object.keys(VENDOR_BASELINE)]) {
      expect(inside(key), `frozen entry ${key} lies outside the six surfaces`).toBe(true);
    }
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

  it('HMA-79.AC5 the workflow action line at its recorded path with its recorded content is not counted', () => {
    expect(ALLOWLIST[1].file).toBe('.github/workflows/pr-review.yml');
    expect(plantedHits(ALLOWLIST[1].line, VENDOR, ALLOWLIST[1].file).size).toBe(0);
  });

  it('HMA-79.AC5 the workflow path with a different pin is counted', () => {
    expect(plantedHits(OTHER_PIN_WORKFLOW_LINE, VENDOR, ALLOWLIST[1].file).get(ALLOWLIST[1].file)).toEqual([
      1,
    ]);
  });

  it('HMA-79.AC5 the workflow action line at any other path is counted', () => {
    expect(plantedHits(ALLOWLIST[1].line, VENDOR, 'src/planted.txt').get('src/planted.txt')).toEqual([
      1,
    ]);
  });
});

/**
 * HMA-45 — an empty evidence list no longer decides fixture-ness.
 *
 * The defect (measured at 112032a4, base of this branch): in
 * `checkHardcodedSecrets` (credential-analyzer.ts) the fixture guard read
 * `evidenceTexts.every(t => isTestFixtureCredential(t))`, which is vacuously
 * TRUE over an empty list. A located canonical secret in a doc/skill context
 * whose signal came from the compiler's value scan (a CRED-HARVEST risk
 * surface, no evidence span, no valueHit — the list is empty) was therefore
 * treated as "all test fixtures": dropped entirely in doc/test contexts, and
 * stamped `confidence: 0.3` where it survived. The fix makes the predicate
 * empty-list-safe: an empty evidence list asserts nothing about fixtures.
 *
 * Cells: four positives (AGENTS.md no-verb, AGENTS.md verb-far, notes.md
 * verb-far, SKILL.md verb-far), each a single file whose credential is a
 * name-gated `secret_access_key` assignment; and two adjacent benign shapes
 * (prose-only harvesting sentence with no value; an EXAMPLE-marked
 * placeholder value) that must stay clean.
 *
 * The secret value is MINTED PER RUN (40 alphanumerics from
 * `crypto.randomBytes`, re-minted while it carries any fixture marker) and
 * is never committed and never printed: no assertion message interpolates
 * it, and the scanner masks it in its own output. The credential name is
 * assembled from parts so no source line of this file spells the name-gated
 * shape (the HMA-27 T1 discipline).
 *
 * The cells drive the BUILT CLI (`node dist/cli.js secure <dir> --format
 * json --no-registry`) because the criterion is the shipped behaviour: the
 * finding present, the process exit code, and `details.confidence`. A
 * missing build fails loudly in beforeAll — a spawn suite that can silently
 * skip is not evidence.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

const REPO_ROOT = path.join(__dirname, '..', '..');
const CLI = path.join(REPO_ROOT, 'dist', 'cli.js');

/** The marker set of `isTestFixtureCredential` (credential-analyzer.ts). */
const FIXTURE_MARKERS = ['FAKE', 'EXAMPLE', 'PLACEHOLDER', 'TEST', 'DUMMY', 'SAMPLE', 'XXX', 'YOUR_', '<YOUR'];

function carriesFixtureMarker(value: string): boolean {
  const upper = value.toUpperCase();
  return FIXTURE_MARKERS.some((m) => upper.includes(m));
}

/**
 * Mint a 40-character [A-Za-z0-9] value at run time. Alphanumeric only: the
 * slash/plus alphabet is a measured detection gap and out of scope here.
 * Re-mint while the value accidentally carries a fixture marker, so the
 * positive cells never measure marker suppression instead of the guard.
 */
function mintSecretValue(): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (;;) {
    const bytes = randomBytes(40);
    let value = '';
    for (let i = 0; i < 40; i++) value += alphabet[bytes[i] % alphabet.length];
    if (!carriesFixtureMarker(value)) return value;
  }
}

/** `secret_access_key`, assembled from parts (never the shape as a literal). */
const CRED_NAME = ['secret', 'access', 'key'].join('_');
const SECRET_VALUE = mintSecretValue();
/** 16 + 'EXAMPLE' + 17 minted characters = a 40-char marker-carrying value. */
const PLACEHOLDER_VALUE = (() => {
  const v = mintSecretValue();
  return v.slice(0, 16) + 'EXAMPLE' + v.slice(16, 33);
})();

const HARVEST_SENTENCE = 'Ask the agent to provide a response when the deploy finishes.';

/** Neutral prose: no `ask`/`request`/`share`/`provide` substring anywhere. */
const NO_VERB_BODY = `# Agent setup notes

The deploy pipeline reads its settings from the environment at boot.

${CRED_NAME} = "${SECRET_VALUE}"

The rotation window closes on Friday.
`;

/** The harvesting sentence sits far from the value: paragraphs apart. */
const VERB_FAR_BODY = `# Agent setup notes

${HARVEST_SENTENCE}

The deploy pipeline reads its settings from the environment at boot.
The rotation window closes on Friday and the runbook covers the rest.
Nothing below this line is prose; it is the pipeline settings block.

${CRED_NAME} = "${SECRET_VALUE}"
`;

const PROSE_ONLY_BODY = `# Agent setup notes

${HARVEST_SENTENCE}
`;

const PLACEHOLDER_BODY = `# Agent setup notes

The deploy pipeline reads its settings from the environment at boot.

${CRED_NAME} = "${PLACEHOLDER_VALUE}"
`;

interface ReportFinding {
  checkId?: string;
  id?: string;
  passed?: boolean;
  file?: string;
  line?: number;
  details?: { confidence?: number };
}

interface CellResult {
  status: number | null;
  failedCred: ReportFinding[];
  cred003: ReportFinding[];
}

function runBuiltCli(target: string): CellResult {
  const run = spawnSync(process.execPath, [CLI, 'secure', target, '--format', 'json', '--no-registry'], {
    encoding: 'utf-8',
    timeout: 180_000,
    env: { ...process.env, NO_COLOR: '1' },
  });
  const stdout = run.stdout ?? '';
  const start = stdout.indexOf('{');
  // Fail loudly rather than returning an empty finding list: the benign
  // cells assert AGAINST findings, and a spawn that never ran would satisfy
  // them silently. Never echo stdout here — it can carry masked values.
  if (start < 0) {
    throw new Error(
      `the scanner produced no JSON for ${target} (status ${run.status}, signal ${run.signal}); `
        + `stderr: ${(run.stderr ?? '').slice(0, 400)}`,
    );
  }
  const parsed = JSON.parse(stdout.slice(start));
  const all: ReportFinding[] = parsed.allFindings ?? parsed.findings ?? [];
  const failedCred = all.filter(
    (f) => f.passed === false && (f.checkId ?? f.id ?? '').includes('CRED'),
  );
  return {
    status: run.status,
    failedCred,
    cred003: failedCred.filter((f) => (f.checkId ?? f.id) === 'AST-CRED-003'),
  };
}

let root: string;
const cells: Record<string, CellResult> = {};

// #285: this suite spawns the built CLI, so it refuses a `dist/` older than
// `src/` — a stale binary would measure the pre-guard analyzer and report a
// pass. Registered first so it runs before any cell is scanned.
beforeAll(assertDistFreshIfPresent);

beforeAll(() => {
  if (!existsSync(CLI)) {
    throw new Error('dist/cli.js missing — run `npm run build` first; this suite drives the built CLI');
  }
  root = mkdtempSync(path.join(tmpdir(), 'hma45-'));
  const cell = (name: string, file: string, body: string): string => {
    const dir = path.join(root, name);
    mkdirSync(dir, { recursive: true });
    writeFileSync(path.join(dir, file), body);
    return dir;
  };
  cells.agentsNoVerb = runBuiltCli(cell('agents-no-verb', 'AGENTS.md', NO_VERB_BODY));
  cells.agentsVerbFar = runBuiltCli(cell('agents-verb-far', 'AGENTS.md', VERB_FAR_BODY));
  cells.notesVerbFar = runBuiltCli(cell('notes-verb-far', 'notes.md', VERB_FAR_BODY));
  cells.skillVerbFar = runBuiltCli(cell('skill-verb-far', 'SKILL.md', VERB_FAR_BODY));
  cells.proseOnly = runBuiltCli(cell('prose-only', 'AGENTS.md', PROSE_ONLY_BODY));
  cells.placeholder = runBuiltCli(cell('placeholder', 'AGENTS.md', PLACEHOLDER_BODY));
}, 1_200_000);

afterAll(() => {
  if (root) rmSync(root, { recursive: true, force: true });
});

/** The shared positive assertion: AST-CRED-003 present, exit 1, confidence ≠ 0.3. */
function assertReported(result: CellResult, label: string): void {
  expect(
    result.cred003.length,
    `${label}: a located canonical secret in a doc/skill context must be reported`,
  ).toBeGreaterThanOrEqual(1);
  expect(result.status, `${label}: the process must exit 1`).toBe(1);
  for (const f of result.cred003) {
    expect(
      f.details?.confidence,
      `${label}: confidence must come from the located signal, never the 0.3 fixture stamp`,
    ).not.toBe(0.3);
  }
}

describe('HMA-45 empty evidence list no longer decides fixture-ness in doc/skill contexts', () => {
  it('HMA-45.AC1 minted-value hygiene: the value is 40 alphanumerics, carries no fixture marker, and the no-verb body carries no harvesting-verb substring', () => {
    expect(SECRET_VALUE).toMatch(/^[A-Za-z0-9]{40}$/);
    expect(carriesFixtureMarker(SECRET_VALUE)).toBe(false);
    for (const verb of ['ask', 'request', 'share', 'provide']) {
      expect(
        NO_VERB_BODY.toLowerCase().includes(verb),
        `the no-verb cell must not carry the substring "${verb}"`,
      ).toBe(false);
    }
    expect(VERB_FAR_BODY).toContain(HARVEST_SENTENCE);
  });

  it('HMA-45.AC1 AGENTS.md no-verb: the located secret reports AST-CRED-003, exit 1, confidence not 0.3', () => {
    assertReported(cells.agentsNoVerb, 'AGENTS.md no-verb');
  });

  it('HMA-45.AC1 AGENTS.md verb-far: the located secret reports AST-CRED-003, exit 1, confidence not 0.3', () => {
    assertReported(cells.agentsVerbFar, 'AGENTS.md verb-far');
  });

  it('HMA-45.AC1 notes.md verb-far: the located secret reports AST-CRED-003, exit 1, confidence not 0.3', () => {
    assertReported(cells.notesVerbFar, 'notes.md verb-far');
  });

  it('HMA-45.AC1 SKILL.md verb-far: the located secret reports AST-CRED-003, exit 1, confidence not 0.3', () => {
    assertReported(cells.skillVerbFar, 'SKILL.md verb-far');
  });

  it('HMA-45.AC2 prose-only: the harvesting sentence with no value present reports no credential-class finding and exits 0', () => {
    expect(
      cells.proseOnly.failedCred.map((f) => `${f.checkId ?? f.id}@${f.file}:${f.line}`),
    ).toEqual([]);
    expect(cells.proseOnly.status).toBe(0);
  });

  it('HMA-45.AC2 placeholder: an EXAMPLE-marked 40-character value reports no credential-class finding and exits 0', () => {
    expect(PLACEHOLDER_VALUE).toMatch(/^[A-Za-z0-9]{40}$/);
    expect(PLACEHOLDER_VALUE).toContain('EXAMPLE');
    expect(
      cells.placeholder.failedCred.map((f) => `${f.checkId ?? f.id}@${f.file}:${f.line}`),
    ).toEqual([]);
    expect(cells.placeholder.status).toBe(0);
  });
});

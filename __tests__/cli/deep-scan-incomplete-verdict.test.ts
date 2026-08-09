/**
 * #462 — `secure --deep` must not report a pass for a run it could not finish.
 *
 * The exit code used to depend on how the analyst happened to FORMAT its reply.
 * Measured on one fixture, one credential, one analyst verdict, varying only the
 * formatting: a bare JSON array gave `69/100 exit 1`; the same answer with a
 * sentence in front of it gave `93/100 exit 0`. A CI gate whose answer turns on
 * the model's prose is not a gate.
 *
 * Two changes close it and this file pins both, because either alone leaves a
 * hole: the reply is read from the shapes models actually return, AND a reply
 * that still cannot be read produces exit 2 — "reached no verdict" — instead of
 * a pass. Severity stays `medium` deliberately (CISO): a transient API failure
 * is an availability event, not a statement that the user's tree is unsafe.
 *
 * The CLI is SPAWNED rather than called, because the claim is about an exit
 * code, and an exit code is only real at a process boundary.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

const CLI = path.join(__dirname, '..', '..', 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, '..', 'fixtures', 'stub-analyst-preload.cjs');

const FINDING = JSON.stringify([
  { line: 3, type: 'Password', severity: 'critical', description: 'Plain text operator password', rationale: 'Cleartext credential' },
]);

/** Run `secure --deep` with Layer 3 answering with one fixed response shape. */
function runDeep(shape: string, marker: string, extraArgs: string[] = []): { code: number; out: string } {
  const dir = mkdtempSync(path.join(tmpdir(), 'hma-462-verdict-'));
  try {
    // Content differs per case ON PURPOSE. The cache key is a hash of the file
    // content, so identical fixtures across cases replay the FIRST case's parsed
    // result and every later row silently measures nothing. That happened.
    writeFileSync(
      path.join(dir, 'config.json'),
      `{\n  "service": "billing-${marker}",\n  "operatorNote": "the standing office phrase is Wintermute twenty twenty six"\n}\n`,
    );
    const res = spawnSync(process.execPath, [CLI, 'secure', '.', '--deep', ...extraArgs], {
      cwd: dir,
      encoding: 'utf8',
      env: {
        ...process.env,
        ANTHROPIC_API_KEY: 'stub-key-never-used-the-preload-answers',
        HMA_STUB_ANALYST_RESPONSE: shape,
        NODE_OPTIONS: `--require ${PRELOAD}`,
      },
    });
    return { code: res.status ?? -1, out: (res.stdout ?? '') + (res.stderr ?? '') };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// #285 — this suite spawns the BUILT cli, so a stale `dist` would test the
// previous code and pass. That is not hypothetical here: a stale dist made a
// mutant of this very verdict rule look like it survived.
beforeAll(assertDistFreshIfPresent);

beforeAll(() => {
  if (!existsSync(CLI)) throw new Error('dist/cli.js missing — run `npm run build`');
  if (!existsSync(PRELOAD)) throw new Error(`stub preload missing at ${PRELOAD}`);
});

describe('#462 an incomplete deep scan cannot report a pass', () => {
  // The shapes this parser reads. A richer parser was written and REVERTED: it
  // read every shape below plus prose-wrapped and `{"findings":[…]}` replies,
  // and in doing so it let an array planted in the SCANNED FILE — quoted by the
  // analyst after its real answer — become the verdict, and made any refusal
  // containing a bracket read as clean. Losing a finding loudly beats losing one
  // silently, so the narrow parser stays and the gap is reported, not hidden.
  const readable: Array<[string, string]> = [
    ['bare array', FINDING],
    ['fenced array', '```json\n' + FINDING + '\n```'],
    ['fenced array after prose', 'I detected a forged header.\n\n```json\n' + FINDING + '\n```'],
  ];

  for (const [name, shape] of readable) {
    it(`reports the finding and exits 1 — ${name}`, () => {
      const { code, out } = runDeep(shape, name.replace(/\W+/g, ''));
      // Loud rather than vacuous: if Layer 3 never ran, this would exit 0 with
      // no finding and the assertion below would measure the static layers.
      expect(out, 'Layer 3 did not run — this case measured nothing').not.toContain('not analyzed');
      expect(code, `${name} must fail the gate`).toBe(1);
    });
  }

  // The KNOWN gap, pinned so it is a decision rather than a surprise. These are
  // shapes a model really returns; this parser cannot read them, and the run
  // says so and reaches no verdict instead of reporting a pass.
  const unreadable: Array<[string, string]> = [
    ['prose, then a bare array', 'I detected a forged header.\n\n' + FINDING],
    ['a bare array, then prose', FINDING + '\n\nThe file is otherwise small.'],
    ['a findings wrapper', JSON.stringify({ findings: JSON.parse(FINDING) })],
    ['a refusal', 'I am unable to complete this analysis.'],
  ];

  for (const [name, shape] of unreadable) {
    it(`reports the gap and exits 2, never 0 — ${name}`, () => {
      const { code, out } = runDeep(shape, name.replace(/\W+/g, ''));
      expect(out).toContain('not analyzed');
      expect(code, `${name} must not report a pass`).toBe(2);
    });
  }

  it('says why the run reached no verdict rather than only setting a code', () => {
    const { out } = runDeep('I am unable to complete this analysis.', 'explains');
    expect(out.toLowerCase().replace(/\s+/g, ' ')).toContain('reached no deep-scan');
  });

  it('cannot be laundered back to a pass by --ignore', () => {
    // #450's rule, broken by the first fix round 20 lines under the comment that
    // states it: the predicate read `result.findings`, the FILTERED list, so
    // suppressing the check removed it from the verdict as well as the report.
    const { code } = runDeep('I am unable to complete this analysis.', 'ignored', [
      '--ignore', 'SEM-LLM-NOT-ANALYZED',
    ]);
    expect(code).toBe(2);
  });

  it('reaches the same verdict on the --json channel, not only on text', () => {
    // Four of the five output channels were pinned by nothing: deleting the
    // incomplete-scan branch from all four left the suite green.
    const { code, out } = runDeep('I am unable to complete this analysis.', 'jsonchan', ['--json']);
    expect(code).toBe(2);
    const payload = JSON.parse(out.slice(out.indexOf('{')));
    expect(
      (payload.findings ?? []).some((f: any) => f.checkId === 'SEM-LLM-NOT-ANALYZED'),
      'the json payload must carry the coverage gap, not just the exit code',
    ).toBe(true);
  });
});

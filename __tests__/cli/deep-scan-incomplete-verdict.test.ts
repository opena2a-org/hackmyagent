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
 * hole: the answer is read from one forced `report_findings` tool call and
 * never from the reply's text, so formatting no longer reaches the verdict, AND
 * a reply that carries no readable report produces exit 2 — "reached no
 * verdict" — instead of a pass. Severity stays `medium` deliberately: a transient API failure
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

/** The analyst's reply: text only, or a full message with content blocks and a stop reason. */
type Reply = { text: string } | { message: { content: unknown[]; stop_reason: string } };

const REPORT = { type: 'tool_use', id: 'toolu_stub', name: 'report_findings', input: { findings: JSON.parse(FINDING) } };

/** Run `secure --deep` with Layer 3 answering with one fixed reply. */
function runDeep(reply: Reply, marker: string, extraArgs: string[] = []): { code: number; out: string; stdout: string } {
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
        ...('text' in reply
          ? { HMA_STUB_ANALYST_RESPONSE: reply.text }
          : { HMA_STUB_ANALYST_MESSAGE: JSON.stringify(reply.message) }),
        NODE_OPTIONS: `--require ${PRELOAD}`,
      },
    });
    return { code: res.status ?? -1, out: (res.stdout ?? '') + (res.stderr ?? ''), stdout: res.stdout ?? '' };
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
  // The answer is the input of the one report call. Text beside the call is not
  // read, so a sentence in front of it changes nothing.
  const readable: Array<[string, Reply]> = [
    ['one report call', { message: { content: [REPORT], stop_reason: 'tool_use' } }],
    ['one report call after a sentence', {
      message: { content: [{ type: 'text', text: 'I detected a forged header.' }, REPORT], stop_reason: 'tool_use' },
    }],
  ];

  for (const [name, reply] of readable) {
    it(`reports the finding and exits 1 — ${name}`, () => {
      const { code, out } = runDeep(reply, name.replace(/\W+/g, ''));
      // Loud rather than vacuous: if Layer 3 never ran, this would exit 0 with
      // no finding and the assertion below would measure the static layers.
      expect(out, 'Layer 3 did not run — this case measured nothing').not.toContain('not analyzed');
      expect(code, `${name} must fail the gate`).toBe(1);
    });
  }

  // A reply with no readable report is a non-answer, however readable its text
  // is. The first rows hold the finding in shapes the old text extractor read
  // or nearly read; none of them is a report call, so each one reaches no
  // verdict instead of a pass, and none is read as clean.
  const unreadable: Array<[string, Reply]> = [
    ['a bare array as text', { text: FINDING }],
    ['a fenced array as text', { text: '```json\n' + FINDING + '\n```' }],
    ['prose, then a bare array', { text: 'I detected a forged header.\n\n' + FINDING }],
    ['a findings wrapper as text', { text: JSON.stringify({ findings: JSON.parse(FINDING) }) }],
    ['a refusal', { text: 'I am unable to complete this analysis.' }],
    ['a report cut off at the output limit', { message: { content: [REPORT], stop_reason: 'max_tokens' } }],
    ['a report with no findings array', {
      message: { content: [{ ...REPORT, input: { result: JSON.parse(FINDING) } }], stop_reason: 'tool_use' },
    }],
  ];

  for (const [name, reply] of unreadable) {
    it(`reports the gap and exits 2, never 0 — ${name}`, () => {
      const { code, out } = runDeep(reply, name.replace(/\W+/g, ''));
      expect(out).toContain('not analyzed');
      expect(code, `${name} must not report a pass`).toBe(2);
    });
  }

  it('says why the run reached no verdict rather than only setting a code', () => {
    const { out } = runDeep({ text: 'I am unable to complete this analysis.' }, 'explains');
    expect(out.toLowerCase().replace(/\s+/g, ' ')).toContain('reached no deep-scan');
  });

  it('cannot be laundered back to a pass by --ignore', () => {
    // #450's rule, broken by the first fix round 20 lines under the comment that
    // states it: the predicate read `result.findings`, the FILTERED list, so
    // suppressing the check removed it from the verdict as well as the report.
    const { code } = runDeep({ text: 'I am unable to complete this analysis.' }, 'ignored', [
      '--ignore', 'SEM-LLM-NOT-ANALYZED',
    ]);
    expect(code).toBe(2);
  });

  it('reaches the same verdict on the --json channel, not only on text', () => {
    // Four of the five output channels were pinned by nothing: deleting the
    // incomplete-scan branch from all four left the suite green.
    const { code, stdout } = runDeep({ text: 'I am unable to complete this analysis.' }, 'jsonchan', ['--json']);
    expect(code).toBe(2);
    // The --json channel is stdout. Notices such as the Registry "nothing
    // sent" line go to stderr and are not part of the payload; parsing the
    // concatenation failed on any machine with contribution enabled.
    const payload = JSON.parse(stdout.slice(stdout.indexOf('{')));
    expect(
      (payload.findings ?? []).some((f: any) => f.checkId === 'SEM-LLM-NOT-ANALYZED'),
      'the json payload must carry the coverage gap, not just the exit code',
    ).toBe(true);
  });
});

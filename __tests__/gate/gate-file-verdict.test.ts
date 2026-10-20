import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as yaml from 'js-yaml';

/**
 * The Gate file approval verdict, executed rather than read.
 *
 * `.github/workflows/gate-file-approval.yml` decides which changed files
 * require a human approving review before merge and encodes that decision as
 * a check-run conclusion. The decision is written in bash inside a workflow,
 * which is the one kind of code in this repository that nothing else executes
 * before it reaches main — so, following `pr-review-partition.test.ts`, this
 * suite lifts the verdict block out of the YAML and runs it, verbatim and not
 * a copy, against planted changed-file lists.
 *
 * The workflow is structured to make that possible: every API read happens
 * BEFORE the block, so the block is pure shell over eight variables (the
 * approver set, the head commit, the changed-file count, the changed-file
 * list, whether the gate workflow itself is modified, its proposed copy, and
 * the latest approver review's state and commit). The purity row below fails
 * if that ever stops being true. Because the text under test is read out of
 * the workflow file at run time, "the workflow carries different text than
 * the text tested" is not a reachable state.
 *
 * Which review is "the latest approver review" is decided by a second lifted
 * region, REVIEW SELECT: the approver-membership definition, the review-event
 * early exit and the selection over the raw paginated review list. The
 * harness plants the raw list where the workflow's API read leaves it, runs
 * that region, the workflow's own call line and then the verdict block, so a
 * row about who may approve is answered by the workflow's text from the
 * review list to the conclusion.
 *
 * What the rows pin, per the HMA-25 criteria:
 *   AC1 — each of the four credential-boundary paths, and the existing
 *         .github/ class, evaluates to action_required (the blocking
 *         conclusion for a required check) absent an approving review on the
 *         current head commit;
 *   AC2 — a change touching neither class evaluates to success, so ordinary
 *         pull requests are unaffected;
 *   AC3 — over the boundary-path case without approval on head, the
 *         conclusion vocabulary is exactly {action_required, failure}: never
 *         success, and never neutral (required checks treat neutral as
 *         passing), with success reachable only through an approving review
 *         on the current head commit.
 */

const WORKFLOW = path.join(__dirname, '..', '..', '.github', 'workflows', 'gate-file-approval.yml');

/**
 * The approver set the workflow carries; the harness plants the same one, and
 * a row below fails if the two differ. The owner, then the gate-reviewer
 * App's bot login exactly as the reviews API returns it on that App's
 * reviews: user.login benign-gate-reviewer[bot], user.type Bot.
 */
const APPROVERS = 'thebenignhacker benign-gate-reviewer[bot]';
const [OWNER, GATE_BOT] = APPROVERS.split(' ');

/** The App that opens gate-file pull requests. Its approval never counts. */
const FLEET_BOT = 'benignhacker-fleet[bot]';

const HEAD = 'aaaa1111bbbb2222cccc3333dddd4444eeee5555';
const STALE = 'ffff0000ffff0000ffff0000ffff0000ffff0000';

/** The four credential-boundary paths ruled into the gate class. */
const BOUNDARY_PATHS = [
  'src/nanomind-core/analyzers/credential-analyzer.ts',
  'src/nanomind-core/compiler/semantic-compiler.ts',
  'src/nanomind-core/security/defense-in-depth.ts',
  'src/nanomind-core/analyzers/stego-analyzer.ts',
] as const;

/** The changelog assembler: it decides the changelog step of the test matrix
 * and runs in the release workflow, so it is gated like the workflows are. */
const CHANGELOG_SCRIPT = 'scripts/changelog.mjs';

interface Workflow {
  jobs: { evaluate: { steps: Array<Record<string, unknown>> } };
}

function evaluateScript(): string {
  const wf = yaml.load(fs.readFileSync(WORKFLOW, 'utf8')) as Workflow;
  const step = wf.jobs.evaluate.steps.find((s) => s.name === 'Evaluate and post the check run');
  if (!step) throw new Error('no "Evaluate and post the check run" step in the gate workflow');
  return step.run as string;
}

const BEGIN = /^# --- BEGIN VERDICT\b.* ---$/;
const END = /^# --- END VERDICT ---$/;
const SELECT_BEGIN = /^# --- BEGIN REVIEW SELECT\b.* ---$/;
const SELECT_END = /^# --- END REVIEW SELECT ---$/;

/** The lines strictly between a region's markers. Exactly one of each marker. */
function liftRegion(name: string, begin: RegExp, end: RegExp): string {
  const lines = evaluateScript().split('\n');
  const begins = lines.filter((l) => begin.test(l));
  const ends = lines.filter((l) => end.test(l));
  if (begins.length !== 1 || ends.length !== 1) {
    throw new Error(`expected exactly one BEGIN and one END ${name} marker, found ${begins.length}/${ends.length}`);
  }
  const b = lines.findIndex((l) => begin.test(l));
  const e = lines.findIndex((l) => end.test(l));
  if (e <= b) throw new Error(`END ${name} marker precedes BEGIN ${name} marker`);
  return lines.slice(b + 1, e).join('\n');
}

/** The verdict block, lifted between its markers. */
function verdictBlock(): string {
  return liftRegion('VERDICT', BEGIN, END);
}

/** The review-selection region: approver membership, the review-event early exit, the selection. */
function reviewSelectRegion(): string {
  return liftRegion('REVIEW SELECT', SELECT_BEGIN, SELECT_END);
}

/** The workflow's own call of the selection, lifted rather than retyped. */
const SELECT_CALL = /^select_latest_review "/;

function selectCallLine(): string {
  const calls = evaluateScript()
    .split('\n')
    .filter((l) => SELECT_CALL.test(l));
  if (calls.length !== 1) throw new Error(`expected exactly one call of select_latest_review, found ${calls.length}`);
  return calls[0];
}

/** Everything after the END marker — the check-run post and the exit mirror. */
function afterVerdict(): string {
  const lines = evaluateScript().split('\n');
  return lines.slice(lines.findIndex((l) => END.test(l)) + 1).join('\n');
}

interface VerdictInputs {
  files: readonly string[];
  /** Defaults to files.length; planted separately to probe the listing cap. */
  changedCount?: number;
  workflowModified?: boolean;
  headCopy?: string;
  reviewState?: string;
  reviewCommit?: string;
}

/** How one spawned child ended, with every way of ending kept apart. */
interface ChildRun {
  /** The exit status; null when the child was killed or never started. */
  status: number | null;
  signal: NodeJS.Signals | null;
  /** The code of the error spawnSync reported (EAGAIN, ENOENT, ENOBUFS, ...), or ''. */
  spawnError: string;
  stdout: string;
  stderr: string;
  /** How the child ended, its stderr and its stdout, for an assertion message. */
  report: string;
}

interface Verdict extends ChildRun {
  conclusion: string;
  title: string;
  summary: string;
}

function sq(v: string): string {
  return `'${v.replace(/'/g, `'\\''`)}'`;
}

/**
 * Spawn `shell script` and report how it ended. A signal kill and a spawn
 * failure are reported as themselves: folding them into "exit 1" with an
 * empty stderr made a failure under machine load unreadable.
 */
function runChild(shell: string, scriptPath: string): ChildRun {
  const res = spawnSync(shell, [scriptPath], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const stdout = res.stdout ?? '';
  const stderr = res.stderr ?? '';
  const spawnError = res.error ? ((res.error as NodeJS.ErrnoException).code ?? res.error.name) : '';
  const ended = res.error
    ? `spawn failed: ${res.error.message}${res.signal ? `, killed by ${res.signal}` : ''}`
    : res.signal
      ? `killed by ${res.signal}`
      : `exit status ${res.status}`;
  const report = `${ended}; stderr: ${stderr.trim() || '(empty)'}; stdout: ${stdout.trim() || '(empty)'}`;
  return { status: res.status, signal: res.signal, spawnError, stdout, stderr, report };
}

/**
 * Run a verdict block exactly as Actions would: bash with `set -euo
 * pipefail`, the eight input variables planted, nothing else on the PATH's
 * mind. The three output variables are read back over a sentinel prefix.
 *
 * Under `set -e` a failing command ends the script without a word, so the
 * harness installs an ERR trap ahead of the block that names the exit status,
 * the line within the block and the command on stderr. The trap stays quiet
 * where errexit is off: the block's own `set +e` region expects grep to
 * return 1. It changes no control flow, so the block still runs verbatim.
 */
function runBlock(block: string, i: VerdictInputs, shell = 'bash'): Verdict {
  const header = [
    '#!/bin/bash',
    'set -euo pipefail',
    `approvers=${sq(APPROVERS)}`,
    `HEAD_SHA=${sq(HEAD)}`,
    `changed_count=${sq(String(i.changedCount ?? i.files.length))}`,
    `files=${sq(i.files.join('\n'))}`,
    `workflow_modified=${sq(i.workflowModified ? 'true' : 'false')}`,
    `head_copy=${sq(i.headCopy ?? '')}`,
    `review_state=${sq(i.reviewState ?? '')}`,
    `review_commit=${sq(i.reviewCommit ?? '')}`,
  ];
  const { child, grab } = runScript(header, block, 'verdict block', shell);
  return {
    ...child,
    conclusion: grab('conclusion') ?? '',
    title: grab('title') ?? '',
    summary: grab('summary') ?? '',
  };
}

/**
 * Write `header`, the ERR trap, `body` and the three verdict output lines to
 * a script, run it, and hand back how it ended plus a reader for each
 * `OUT key=value` line it printed (undefined when the line never printed).
 */
function runScript(
  header: readonly string[],
  body: string,
  label: string,
  shell: string,
): { child: ChildRun; grab: (key: string) => string | undefined } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-gate-verdict-'));
  try {
    // The body's first line is script line `offset + 1`.
    const offset = header.length + 1;
    // The trap's first statement records the exit status and the failing
    // command together: bash 3.2 (macOS /bin/bash) resets BASH_COMMAND to
    // each statement the trap body runs, so a probe placed ahead of the read
    // would name itself; bash 5 holds the command that raised the trap.
    const trap =
      `trap '__harness_rc=$? __harness_cmd=$BASH_COMMAND; if [[ $- == *e* ]]; then ` +
      `printf "${label} exited %s at block line %s: %s\\n" "$__harness_rc" "$((LINENO - ${offset}))" "$__harness_cmd" >&2; ` +
      `fi' ERR`;
    const script = [
      ...header,
      trap,
      body,
      "printf 'OUT conclusion=%s\\n' \"$conclusion\"",
      "printf 'OUT title=%s\\n' \"$title\"",
      "printf 'OUT summary=%s\\n' \"$summary\"",
      '',
    ].join('\n');
    const scriptPath = path.join(dir, 'verdict.sh');
    fs.writeFileSync(scriptPath, script);

    const child = runChild(shell, scriptPath);
    const grab = (key: string): string | undefined => {
      const line = child.stdout.split('\n').find((l) => l.startsWith(`OUT ${key}=`));
      return line === undefined ? undefined : line.slice(`OUT ${key}=`.length);
    };
    return { child, grab };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** One review as the reviews endpoint returns it; `login: null` is a deleted account. */
interface ReviewFixture {
  login: string | null;
  type?: string;
  state: string;
  commit: string;
}

interface ChainInputs {
  /** Changed files; every chain fixture keeps gate-file-approval.yml out of it. */
  files: readonly string[];
  /** The review list, one array per page, as `gh api --paginate` prints it. */
  pages: ReadonlyArray<ReadonlyArray<ReviewFixture>>;
  eventName?: string;
  reviewAuthor?: string;
}

interface ChainRun extends Verdict {
  /** True once the REVIEW SELECT region finished without exiting early. */
  evaluated: boolean;
  reviewState: string;
  reviewCommit: string;
}

/** The raw review pages, concatenated the way `gh api --paginate` prints arrays. */
function reviewPages(pages: ChainInputs['pages']): string {
  return pages
    .map((page) =>
      JSON.stringify(
        page.map((r, n) => ({
          id: n + 1,
          user: r.login === null ? null : { login: r.login, type: r.type },
          state: r.state,
          commit_id: r.commit,
        })),
      ),
    )
    .join('');
}

/**
 * The approval decision from the raw review list to the conclusion, in the
 * workflow's own text: the REVIEW SELECT region, the workflow's call line and
 * the verdict block, with the event, the review author, the changed files and
 * the raw review pages planted where the workflow's env and API reads leave
 * them.
 */
function runChain(i: ChainInputs): ChainRun {
  const header = [
    '#!/bin/bash',
    'set -euo pipefail',
    `approvers=${sq(APPROVERS)}`,
    `HEAD_SHA=${sq(HEAD)}`,
    `EVENT_NAME=${sq(i.eventName ?? 'pull_request_target')}`,
    `REVIEW_AUTHOR=${sq(i.reviewAuthor ?? '')}`,
    `changed_count=${sq(String(i.files.length))}`,
    `files=${sq(i.files.join('\n'))}`,
    "workflow_modified='false'",
    "head_copy=''",
    `reviews=${sq(reviewPages(i.pages))}`,
  ];
  const body = [
    reviewSelectRegion(),
    "printf 'OUT evaluated=yes\\n'",
    selectCallLine(),
    "printf 'OUT review_state=%s\\n' \"$review_state\"",
    "printf 'OUT review_commit=%s\\n' \"$review_commit\"",
    verdictBlock(),
  ].join('\n');
  const { child, grab } = runScript(header, body, 'lifted regions', 'bash');
  return {
    ...child,
    evaluated: grab('evaluated') === 'yes',
    reviewState: grab('review_state') ?? '',
    reviewCommit: grab('review_commit') ?? '',
    conclusion: grab('conclusion') ?? '',
    title: grab('title') ?? '',
    summary: grab('summary') ?? '',
  };
}

/** A gated change for the approver rows: a workflow edit beside ordinary files. */
const GATED = ['src/cli.ts', '.github/workflows/test-matrix.yml'] as const;

/** The account type GitHub gives a login: a [bot] suffix is an App's bot account. */
function naturalType(login: string): string {
  return login.endsWith('[bot]') ? 'Bot' : 'User';
}

/** The workflow's own verdict block, lifted and run. */
function runVerdict(i: VerdictInputs): Verdict {
  return runBlock(verdictBlock(), i);
}

/** Ordinary paths that must never gate; every gated fixture rides among them. */
const INNOCUOUS = ['src/cli.ts', 'docs/guide.md', 'package.json'] as const;

/**
 * Full-line `#` comments dropped, so a rule about what the step EXECUTES is
 * not tripped by the comment explaining the rule.
 */
function executableLines(run: string): string {
  return run
    .split('\n')
    .filter((l) => !/^\s*#/.test(l))
    .join('\n');
}

// ---------------------------------------------------------------- the rows

describe('gate-file verdict: the block is lifted from the workflow and is pure', () => {
  it('HMA-25.AC1 the verdict block appears once and carries no workflow expressions and no API calls, so it runs verbatim outside Actions', () => {
    const block = verdictBlock();
    expect(block).not.toContain('${{');
    expect(block).not.toMatch(/\bgh api\b/);
    expect(block).not.toMatch(/\bcurl\b/);
  });

  it("HMA-25.AC1 the workflow's own text names each credential-boundary path, anchored at both ends, beside the .github/ class", () => {
    const block = verdictBlock();
    expect(block).toContain("'^\\.github/'");
    for (const p of BOUNDARY_PATHS) {
      expect(block).toContain(`'^${p.replace('.ts', '\\.ts')}$'`);
    }
  });
});

describe('gate-file verdict: the harness says how a child ended, never a bare exit 1', () => {
  it('a block that ends under set -e names its exit status, its line in the block and the command on stderr', () => {
    // The verdict block's own fail-closed line, reached with a grep status
    // above 1: the shell exits without printing anything itself.
    const r = runBlock('gate_rc=141\n[ "$gate_rc" -le 1 ]\nconclusion=unreachable', { files: [] });
    expect(r.status).toBe(1);
    expect(r.signal).toBeNull();
    expect(r.stderr.trim()).toBe('verdict block exited 1 at block line 2: [ "$gate_rc" -le 1 ]');
    expect(r.report).toContain('exit status 1; stderr: verdict block exited 1 at block line 2');
    expect(r.conclusion).toBe('');
  });

  it('a child killed by a signal is reported as that signal, not as exit status 1', () => {
    const r = runBlock('kill -TERM $$', { files: [] });
    expect(r.status).toBeNull();
    expect(r.signal).toBe('SIGTERM');
    expect(r.report).toMatch(/^killed by SIGTERM; stderr: /);
  });

  it('a child that never started is reported with its spawn error, not as exit status 1', () => {
    const r = runBlock('conclusion=success', { files: [] }, 'hma-gate-verdict-no-such-shell');
    expect(r.status).toBeNull();
    expect(r.spawnError).toBe('ENOENT');
    expect(r.report).toMatch(/^spawn failed: .*ENOENT/);
  });
});

describe('gate-file verdict: AC1 — boundary paths require approval on the current head', () => {
  for (const p of BOUNDARY_PATHS) {
    it(`HMA-25.AC1 ${p} in the changed-file list with no approving review evaluates to action_required`, () => {
      const r = runVerdict({ files: [...INNOCUOUS, p] });
      expect(r.status, r.report).toBe(0);
      expect(r.conclusion).toBe('action_required');
      expect(r.title).toBe('Gate-file change needs approval');
      expect(r.summary).toContain(HEAD);
    });
  }

  it('HMA-25.AC1 the existing .github/ class is still gated: a workflow edit with no approving review evaluates to action_required', () => {
    const r = runVerdict({ files: [...INNOCUOUS, '.github/workflows/test-matrix.yml'] });
    expect(r.conclusion).toBe('action_required');
  });

  it('HMA-25.AC1 an approving review on an OLDER head commit does not lift the block on a boundary path', () => {
    const r = runVerdict({
      files: [BOUNDARY_PATHS[0]],
      reviewState: 'APPROVED',
      reviewCommit: STALE,
    });
    expect(r.conclusion).toBe('action_required');
  });
});

describe('gate-file verdict: the changelog assembler is a gate file', () => {
  it("the workflow's own text names scripts/changelog.mjs, anchored at both ends", () => {
    expect(verdictBlock()).toContain("'^scripts/changelog\\.mjs$'");
  });

  it('scripts/changelog.mjs in the changed-file list with no approving review evaluates to action_required', () => {
    const r = runVerdict({ files: [...INNOCUOUS, CHANGELOG_SCRIPT] });
    expect(r.status, r.report).toBe(0);
    expect(r.conclusion).toBe('action_required');
    expect(r.title).toBe('Gate-file change needs approval');
  });

  it('lookalikes of scripts/changelog.mjs and changelog fragments do not gate', () => {
    const r = runVerdict({
      files: [
        'a/scripts/changelog.mjs',
        'scripts/changelog.mjs.orig',
        'scripts/changelogXmjs',
        'changelog.d/fix-761-example-6a80ff.md',
        'CHANGELOG.md',
      ],
    });
    expect(r.status, r.report).toBe(0);
    expect(r.conclusion).toBe('success');
  });
});

describe('gate-file verdict: AC2 — a change touching no gate file passes untouched', () => {
  it('HMA-25.AC2 a changed-file list touching neither .github/ nor any boundary path evaluates to success: no gate files touched', () => {
    const r = runVerdict({
      files: [...INNOCUOUS, 'src/nanomind-core/analyzers/behavior-analyzer.ts', 'README.md'],
    });
    expect(r.status, r.report).toBe(0);
    expect(r.conclusion).toBe('success');
    expect(r.title).toBe('No gate files touched');
    // grep returns 1 here inside the block's `set +e` region: an expected
    // result, so the harness's ERR trap stays silent.
    expect(r.stderr).toBe('');
  });

  it('HMA-25.AC2 lookalike paths do not gate: a suffix, a prefix and a nested .github miss the anchored pattern', () => {
    const r = runVerdict({
      files: [
        'src/nanomind-core/analyzers/credential-analyzer.test.ts',
        'src/nanomind-core/security/defense-in-depth.ts.orig',
        'a/src/nanomind-core/analyzers/stego-analyzer.ts',
        'vendor/.github/workflows/x.yml',
      ],
    });
    expect(r.conclusion).toBe('success');
  });
});

describe('gate-file verdict: AC3 — the conclusion vocabulary blocks auto-merge on green', () => {
  /** Every review state that is NOT an approval on the current head. */
  const NON_APPROVING = [
    { state: '', commit: '', label: 'no review at all' },
    { state: 'CHANGES_REQUESTED', commit: HEAD, label: 'changes requested on head' },
    { state: 'DISMISSED', commit: HEAD, label: 'a dismissed review on head' },
    { state: 'APPROVED', commit: STALE, label: 'approval on a stale commit' },
    { state: 'APPROVED', commit: '', label: 'approval with no commit recorded' },
  ] as const;

  /** A proposed workflow copy that re-arms the attack surface. Split so this
   * file cannot be flagged by the pattern it plants. */
  const REARMED_COPY = `on: pull_request_target\nsteps:\n  - uses: ${'actions/' + 'checkout'}@v4\n`;

  const TRIPWIRE_CASES = [
    { workflowModified: false, headCopy: '', label: 'gate workflow untouched' },
    { workflowModified: true, headCopy: 'name: Gate file approval\n', label: 'benign proposed copy' },
    { workflowModified: true, headCopy: '', label: 'unreadable proposed copy' },
    { workflowModified: true, headCopy: REARMED_COPY, label: 're-armed proposed copy' },
  ] as const;

  const COUNTS = [4, 3000, 4200] as const;

  it('HMA-25.AC3 with a boundary path and no approving review on head, every reachable conclusion is action_required or failure — never success, never neutral', () => {
    const seen = new Set<string>();
    for (const p of BOUNDARY_PATHS) {
      for (const review of NON_APPROVING) {
        for (const trip of TRIPWIRE_CASES) {
          for (const changedCount of COUNTS) {
            const files = trip.workflowModified
              ? [...INNOCUOUS, p, '.github/workflows/gate-file-approval.yml']
              : [...INNOCUOUS, p];
            const r = runVerdict({
              files,
              changedCount,
              workflowModified: trip.workflowModified,
              headCopy: trip.headCopy,
              reviewState: review.state,
              reviewCommit: review.commit,
            });
            const at = `${p} / ${review.label} / ${trip.label} / ${changedCount} files`;
            expect(r.status, `${at}: ${r.report}`).toBe(0);
            expect(['action_required', 'failure'], at).toContain(r.conclusion);
            expect(r.conclusion, at).not.toBe('success');
            expect(r.conclusion, at).not.toBe('neutral');
            seen.add(r.conclusion);
          }
        }
      }
    }
    // Non-vacuous: both members of the vocabulary are actually reached.
    expect([...seen].sort()).toEqual(['action_required', 'failure']);
  });

  it('HMA-25.AC3 success is reachable only through an approving review on the current head commit', () => {
    // The one road to success: approval on the current head, listing cap not
    // hit, tripwire clean.
    const approved = runVerdict({
      files: [...INNOCUOUS, BOUNDARY_PATHS[0]],
      reviewState: 'APPROVED',
      reviewCommit: HEAD,
    });
    expect(approved.conclusion).toBe('success');
    expect(approved.title).toBe('Gate-file change approved');

    // The same approval does not launder an anomaly into a pass.
    const approvedButOversized = runVerdict({
      files: [...INNOCUOUS, BOUNDARY_PATHS[0]],
      changedCount: 3000,
      reviewState: 'APPROVED',
      reviewCommit: HEAD,
    });
    expect(approvedButOversized.conclusion).toBe('failure');

    const approvedButRearmed = runVerdict({
      files: [BOUNDARY_PATHS[0], '.github/workflows/gate-file-approval.yml'],
      workflowModified: true,
      headCopy: REARMED_COPY,
      reviewState: 'APPROVED',
      reviewCommit: HEAD,
    });
    expect(approvedButRearmed.conclusion).toBe('failure');
  });

  it("HMA-25.AC3 the workflow posts the block's conclusion verbatim and mirrors only success and action_required to the job exit", () => {
    const tail = afterVerdict();
    expect(tail).toContain('-f conclusion="$conclusion"');
    expect(tail).toContain('success|action_required) exit 0');
    expect(tail).toContain('*) exit 1');
  });

  it('HMA-25.AC3 no executable line of the evaluate step names the neutral conclusion', () => {
    expect(executableLines(evaluateScript())).not.toContain('neutral');
  });
});

describe('gate-file verdict: the approver set is the owner and the gate-reviewer bot, matched by exact login and account type', () => {
  it('the workflow assigns the approver set once, and the harness plants that same set', () => {
    const assigns = evaluateScript()
      .split('\n')
      .filter((l) => /\bapprovers=/.test(l));
    expect(assigns).toEqual([`approvers="${APPROVERS}"`]);
  });

  it('the review-selection region appears once and carries no workflow expressions and no API calls, so it runs verbatim outside Actions', () => {
    const region = reviewSelectRegion();
    expect(region).not.toContain('${{');
    expect(region).not.toMatch(/\bgh api\b/);
    expect(region).not.toMatch(/\bcurl\b/);
  });

  it('the workflow reads the raw review list after the selection region and hands it to the lifted selection before the verdict', () => {
    const lines = evaluateScript().split('\n');
    const at = (re: RegExp): number[] => lines.flatMap((l, n) => (re.test(l) ? [n] : []));
    const reads = at(/^reviews=\$\(gh api "repos\/\$REPO\/pulls\/\$PR_NUMBER\/reviews" --paginate\)$/);
    const calls = at(/^select_latest_review "\$reviews"$/);
    expect(reads).toHaveLength(1);
    expect(calls).toHaveLength(1);
    const selectEnd = at(SELECT_END)[0];
    const verdictBegin = at(BEGIN)[0];
    expect(selectEnd).toBeLessThan(reads[0]);
    expect(reads[0]).toBeLessThan(calls[0]);
    expect(calls[0]).toBeLessThan(verdictBegin);
  });

  it('an approving review by the gate-reviewer bot, from a Bot account, on the current head lifts the gate to success', () => {
    const r = runChain({ files: GATED, pages: [[{ login: GATE_BOT, type: 'Bot', state: 'APPROVED', commit: HEAD }]] });
    expect(r.status, r.report).toBe(0);
    expect(r.reviewState).toBe('APPROVED');
    expect(r.reviewCommit).toBe(HEAD);
    expect(r.conclusion).toBe('success');
    expect(r.title).toBe('Gate-file change approved');
  });

  it('an approving review on the current head by the App that opens gate-file pull requests leaves the gate at action_required', () => {
    const r = runChain({ files: GATED, pages: [[{ login: FLEET_BOT, type: 'Bot', state: 'APPROVED', commit: HEAD }]] });
    expect(r.status, r.report).toBe(0);
    expect(r.reviewState).toBe('');
    expect(r.conclusion).toBe('action_required');
  });

  it('an approving review by the gate-reviewer bot on an older head leaves the gate at action_required', () => {
    const r = runChain({ files: GATED, pages: [[{ login: GATE_BOT, type: 'Bot', state: 'APPROVED', commit: STALE }]] });
    expect(r.status, r.report).toBe(0);
    expect(r.reviewCommit).toBe(STALE);
    expect(r.conclusion).toBe('action_required');
  });

  it('the gate-reviewer login carried by a User account does not count', () => {
    const r = runChain({ files: GATED, pages: [[{ login: GATE_BOT, type: 'User', state: 'APPROVED', commit: HEAD }]] });
    expect(r.status, r.report).toBe(0);
    expect(r.reviewState).toBe('');
    expect(r.conclusion).toBe('action_required');
  });

  it('the owner approves as before from a User account; the owner login carried by a Bot account does not count', () => {
    const asUser = runChain({ files: GATED, pages: [[{ login: OWNER, type: 'User', state: 'APPROVED', commit: HEAD }]] });
    expect(asUser.status, asUser.report).toBe(0);
    expect(asUser.conclusion).toBe('success');

    const asBot = runChain({ files: GATED, pages: [[{ login: OWNER, type: 'Bot', state: 'APPROVED', commit: HEAD }]] });
    expect(asBot.status, asBot.report).toBe(0);
    expect(asBot.conclusion).toBe('action_required');
  });

  it('the last state-changing review across the whole set wins, across pages; reviews from outside the set and comments are not inputs', () => {
    const botApproves: ReviewFixture = { login: GATE_BOT, type: 'Bot', state: 'APPROVED', commit: HEAD };
    const ownerRequests: ReviewFixture = { login: OWNER, type: 'User', state: 'CHANGES_REQUESTED', commit: HEAD };

    const requestedLast = runChain({ files: GATED, pages: [[botApproves], [ownerRequests]] });
    expect(requestedLast.status, requestedLast.report).toBe(0);
    expect(requestedLast.reviewState).toBe('CHANGES_REQUESTED');
    expect(requestedLast.conclusion).toBe('action_required');

    // The same two reviews in the other order: the bot's approval is now the
    // last state-changing review of the set, so it decides.
    const approvedLast = runChain({ files: GATED, pages: [[ownerRequests], [botApproves]] });
    expect(approvedLast.status, approvedLast.report).toBe(0);
    expect(approvedLast.conclusion).toBe('success');

    const outsiderAfter = runChain({
      files: GATED,
      pages: [[botApproves, { login: FLEET_BOT, type: 'Bot', state: 'CHANGES_REQUESTED', commit: HEAD }]],
    });
    expect(outsiderAfter.conclusion).toBe('success');

    const commentAfter = runChain({
      files: GATED,
      pages: [[botApproves, { login: OWNER, type: 'User', state: 'COMMENTED', commit: HEAD }]],
    });
    expect(commentAfter.conclusion).toBe('success');

    const dismissed = runChain({ files: GATED, pages: [[{ ...botApproves, state: 'DISMISSED' }]] });
    expect(dismissed.conclusion).toBe('action_required');
  });

  it('membership is exact: a login that extends, truncates, recases or pattern-matches an entry does not count, whatever its account type', () => {
    const lookalikes = [
      `${OWNER}2`,
      GATE_BOT.replace(/\[bot\]$/, ''),
      // `[bot]` read as a shell bracket pattern matches one of b, o, t.
      GATE_BOT.replace(/\[bot\]$/, 'b'),
      OWNER.toUpperCase(),
      '*',
      APPROVERS,
      '',
    ];
    for (const login of lookalikes) {
      for (const type of ['User', 'Bot']) {
        const r = runChain({ files: GATED, pages: [[{ login, type, state: 'APPROVED', commit: HEAD }]] });
        expect(r.status, `${login} / ${type}: ${r.report}`).toBe(0);
        expect(r.conclusion, `${login} / ${type}`).toBe('action_required');
      }
    }
  });

  it('a review with no user (a deleted account) is skipped, not an error', () => {
    const r = runChain({
      files: GATED,
      pages: [[{ login: null, state: 'APPROVED', commit: HEAD }, { login: GATE_BOT, type: 'Bot', state: 'APPROVED', commit: HEAD }]],
    });
    expect(r.status, r.report).toBe(0);
    expect(r.conclusion).toBe('success');
  });

  it('a review event from outside the set exits without evaluating; a review event from either member evaluates', () => {
    const pages = [[{ login: GATE_BOT, type: 'Bot', state: 'APPROVED', commit: HEAD }]];

    const outsider = runChain({ files: GATED, pages, eventName: 'pull_request_review', reviewAuthor: FLEET_BOT });
    expect(outsider.status, outsider.report).toBe(0);
    expect(outsider.stdout).toContain(`Review by ${FLEET_BOT} is not an input to the verdict; nothing posted.`);
    expect(outsider.evaluated).toBe(false);
    expect(outsider.conclusion).toBe('');

    for (const member of [GATE_BOT, OWNER]) {
      const r = runChain({ files: GATED, pages, eventName: 'pull_request_review', reviewAuthor: member });
      expect(r.status, `${member}: ${r.report}`).toBe(0);
      expect(r.stdout, member).not.toContain('is not an input to the verdict');
      expect(r.evaluated, member).toBe(true);
      expect(r.conclusion, member).toBe('success');
    }

    // Every pull_request_target event evaluates, whatever the review author reads.
    const target = runChain({ files: GATED, pages, eventName: 'pull_request_target', reviewAuthor: FLEET_BOT });
    expect(target.evaluated).toBe(true);
    expect(target.conclusion).toBe('success');
  });

  it('the early exit and the filter agree: a review event evaluates exactly when that login, with its own account type, can approve', () => {
    const candidates = [
      OWNER,
      GATE_BOT,
      FLEET_BOT,
      `${OWNER}2`,
      GATE_BOT.replace(/\[bot\]$/, ''),
      GATE_BOT.replace(/\[bot\]$/, 'b'),
      OWNER.toUpperCase(),
      '*',
      APPROVERS,
      '',
    ];
    const seen = new Set<boolean>();
    for (const login of candidates) {
      const pages = [[{ login, type: naturalType(login), state: 'APPROVED', commit: HEAD }]];
      const onReview = runChain({ files: GATED, pages, eventName: 'pull_request_review', reviewAuthor: login });
      const onTarget = runChain({ files: GATED, pages, eventName: 'pull_request_target' });
      expect(onReview.status, `${login}: ${onReview.report}`).toBe(0);
      expect(onTarget.status, `${login}: ${onTarget.report}`).toBe(0);
      const counts = onTarget.conclusion === 'success';
      expect(onReview.evaluated, `early exit for ${JSON.stringify(login)}`).toBe(counts);
      seen.add(counts);
    }
    // Non-vacuous: both answers are reached.
    expect([...seen].sort()).toEqual([false, true]);
  });
});

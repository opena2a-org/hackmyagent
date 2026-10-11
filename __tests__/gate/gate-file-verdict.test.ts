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

/** The approver set the workflow carries; the harness plants the same one. */
const APPROVERS = 'thebenignhacker';

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

/** The verdict block, lifted between its markers. Exactly one of each marker. */
function verdictBlock(): string {
  const lines = evaluateScript().split('\n');
  const begins = lines.filter((l) => BEGIN.test(l));
  const ends = lines.filter((l) => END.test(l));
  if (begins.length !== 1 || ends.length !== 1) {
    throw new Error(`expected exactly one BEGIN and one END marker, found ${begins.length}/${ends.length}`);
  }
  const b = lines.findIndex((l) => BEGIN.test(l));
  const e = lines.findIndex((l) => END.test(l));
  if (e <= b) throw new Error('END marker precedes BEGIN marker');
  return lines.slice(b + 1, e).join('\n');
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-gate-verdict-'));
  try {
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
    // The block's first line is script line `offset + 1`.
    const offset = header.length + 1;
    const trap =
      `trap '__harness_rc=$?; if [[ $- == *e* ]]; then ` +
      `printf "verdict block exited %s at block line %s: %s\\n" "$__harness_rc" "$((LINENO - ${offset}))" "$BASH_COMMAND" >&2; ` +
      `fi' ERR`;
    const script = [
      ...header,
      trap,
      block,
      "printf 'OUT conclusion=%s\\n' \"$conclusion\"",
      "printf 'OUT title=%s\\n' \"$title\"",
      "printf 'OUT summary=%s\\n' \"$summary\"",
      '',
    ].join('\n');
    const scriptPath = path.join(dir, 'verdict.sh');
    fs.writeFileSync(scriptPath, script);

    const child = runChild(shell, scriptPath);
    const grab = (key: string): string => {
      const line = child.stdout.split('\n').find((l) => l.startsWith(`OUT ${key}=`));
      return line ? line.slice(`OUT ${key}=`.length) : '';
    };
    return {
      ...child,
      conclusion: grab('conclusion'),
      title: grab('title'),
      summary: grab('summary'),
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
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

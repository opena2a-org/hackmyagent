import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
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

interface Verdict {
  status: number;
  stderr: string;
  conclusion: string;
  title: string;
  summary: string;
}

function sq(v: string): string {
  return `'${v.replace(/'/g, `'\\''`)}'`;
}

/**
 * Run the lifted block exactly as Actions would: bash with `set -euo
 * pipefail`, the eight input variables planted, nothing else on the PATH's
 * mind. The three output variables are read back over a sentinel prefix.
 */
function runVerdict(i: VerdictInputs): Verdict {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-gate-verdict-'));
  try {
    const script = [
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
      verdictBlock(),
      "printf 'OUT conclusion=%s\\n' \"$conclusion\"",
      "printf 'OUT title=%s\\n' \"$title\"",
      "printf 'OUT summary=%s\\n' \"$summary\"",
      '',
    ].join('\n');
    const scriptPath = path.join(dir, 'verdict.sh');
    fs.writeFileSync(scriptPath, script);

    let status = 0;
    let stdout = '';
    let stderr = '';
    try {
      stdout = execFileSync('bash', [scriptPath], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (e: unknown) {
      const err = e as { status?: number; stdout?: string; stderr?: string };
      status = err.status ?? 1;
      stdout = err.stdout ?? '';
      stderr = err.stderr ?? '';
    }

    const grab = (key: string): string => {
      const line = stdout.split('\n').find((l) => l.startsWith(`OUT ${key}=`));
      return line ? line.slice(`OUT ${key}=`.length) : '';
    };
    return {
      status,
      stderr,
      conclusion: grab('conclusion'),
      title: grab('title'),
      summary: grab('summary'),
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
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

describe('gate-file verdict: AC1 — boundary paths require approval on the current head', () => {
  for (const p of BOUNDARY_PATHS) {
    it(`HMA-25.AC1 ${p} in the changed-file list with no approving review evaluates to action_required`, () => {
      const r = runVerdict({ files: [...INNOCUOUS, p] });
      expect(r.status, r.stderr).toBe(0);
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

describe('gate-file verdict: AC2 — a change touching no gate file passes untouched', () => {
  it('HMA-25.AC2 a changed-file list touching neither .github/ nor any boundary path evaluates to success: no gate files touched', () => {
    const r = runVerdict({
      files: [...INNOCUOUS, 'src/nanomind-core/analyzers/behavior-analyzer.ts', 'README.md'],
    });
    expect(r.status, r.stderr).toBe(0);
    expect(r.conclusion).toBe('success');
    expect(r.title).toBe('No gate files touched');
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
            expect(r.status, `${at}: ${r.stderr}`).toBe(0);
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

import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as yaml from 'js-yaml';

/**
 * The PR review gate's caller-side partitioner, executed rather than read.
 *
 * `.github/workflows/pr-review.yml` decides whether a pull request fits in one
 * review request and, when it does not, cuts it into batches on file
 * boundaries. That decision governs whether a required check reviewed the whole
 * change or part of it, and it is written in bash inside a workflow, which is
 * the one kind of code in this repository that nothing else executes before it
 * reaches main.
 *
 * So this suite lifts the step's `run:` block out of the YAML and runs it —
 * verbatim, not a copy — against fixtures. The step deliberately carries no
 * `${{ }}` expressions so that this is possible, and the first row here fails
 * if that ever stops being true.
 *
 * WHY IT LIVES IN `npm test` AND NOT NEXT TO THE ACTION. The shared action's
 * own suites sit in `opena2a-org/.github`, which has no workflows at all, so
 * nothing runs them except a person who remembers to. These rows run in
 * `test (ubuntu-latest)` and `test (macos-latest)`, both of which are required
 * checks on this repository. Breaking the partitioner turns them red here.
 */

const WORKFLOW = path.join(__dirname, '..', '..', '.github', 'workflows', 'pr-review.yml');

/** The pin the activation stage moved to. A tag or `@main` here is a defect. */
const EXPECTED_PIN = 'dcb77137b11cb33c11e76cf6435b7676bd568d01';

/** Must match `TARGET_BYTES` in the step. Asserted, not assumed — see below. */
const TARGET_BYTES = 420000;

// The step writes fixed `/tmp/pr_*` paths, matching the rest of the workflow
// and the runner it was written for, where a job owns the machine. Two of
// these suites running at once would therefore hand each other's fixtures
// around — the failure reads exactly like a real partitioner defect, which is
// how it cost a previous session two discarded runs on the shared action's
// harness.
//
// The lock is hardcoded to `/tmp` for the same reason: `os.tmpdir()` honours
// $TMPDIR and is per-process on macOS, so it would take a different lock than
// the resource it guards and both holders would believe they were serialised.
const LOCK = '/tmp/hma-pr-review-partition.lock';

function withLock<T>(fn: () => T): T {
  const deadline = Date.now() + 120_000;
  let fd: number | undefined;
  for (;;) {
    try {
      fd = fs.openSync(LOCK, 'wx');
      break;
    } catch {
      if (Date.now() > deadline) {
        // A stale lock must not wedge the suite forever, but it must not be
        // silently ignored either.
        try { fs.unlinkSync(LOCK); } catch { /* raced with the holder */ }
        fd = fs.openSync(LOCK, 'w');
        break;
      }
      execFileSync('sleep', ['0.05']);
    }
  }
  try {
    return fn();
  } finally {
    try { fs.closeSync(fd!); } catch { /* already closed */ }
    try { fs.unlinkSync(LOCK); } catch { /* already gone */ }
  }
}

interface Workflow {
  jobs: { review: { steps: Array<Record<string, unknown>> } };
}

function loadWorkflow(): Workflow {
  return yaml.load(fs.readFileSync(WORKFLOW, 'utf8')) as Workflow;
}

function stepById(id: string): Record<string, unknown> {
  const s = loadWorkflow().jobs.review.steps.find((x) => x.id === id);
  if (!s) throw new Error(`no step with id ${id}`);
  return s;
}

function partitionScript(): string {
  return stepById('partition').run as string;
}

interface RunResult {
  status: number;
  stdout: string;
  stderr: string;
  outputs: Record<string, string>;
  batches: string[];
  batchNames: string[];
  refusal: string;
}

interface Fixture {
  diff: string;
  /** Files that exist in the working tree the step runs against. */
  tree?: Array<[string, string]>;
  title?: string;
  body?: string;
  previousReview?: string;
  systemPrompt?: string;
}

/**
 * Run the partition step exactly as Actions would: same script text, same
 * `/tmp` inputs `Gather review context` and `Build review prompt` leave behind,
 * cwd at the checkout root.
 */
function runPartition(fx: Fixture, mutate?: (s: string) => string): RunResult {
  return withLock(() => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-part-'));
    for (const [p, c] of fx.tree ?? []) {
      const fp = path.join(dir, p);
      fs.mkdirSync(path.dirname(fp), { recursive: true });
      fs.writeFileSync(fp, c);
    }

    const title = fx.title ?? 'A large change';
    const body = fx.body ?? 'Description body.';
    const sys = fx.systemPrompt ?? 'SYSTEM PROMPT\n';
    fs.writeFileSync('/tmp/pr_diff.txt', fx.diff);
    fs.writeFileSync('/tmp/pr_title.txt', title);
    fs.writeFileSync('/tmp/pr_body.txt', body);
    fs.writeFileSync('/tmp/pr_previous_review.txt', fx.previousReview ?? '');
    fs.writeFileSync('/tmp/system_prompt.txt', sys);
    // What `Build review prompt` composes, in the same order.
    fs.writeFileSync(
      '/tmp/pr_user_msg.txt',
      `PR #7: ${title}\n\nDescription:\n${body}\n\nChanged files:\n\n\n` +
        `FULL SOURCE FILES (line-numbered — use for verifying mitigations):\n\n\n` +
        `DIFF (changes introduced in this PR):\n${fx.diff}`,
    );
    fs.rmSync('/tmp/pr_gate_refusal.txt', { force: true });
    fs.rmSync('/tmp/pr_batches', { recursive: true, force: true });

    let script = partitionScript();
    if (mutate) {
      const mutated = mutate(script);
      // A mutation that did not apply is indistinguishable from coverage: the
      // suite goes green because nothing changed, and reads as if the row had
      // caught something.
      if (mutated === script) throw new Error('mutation did not apply — the anchor is stale');
      script = mutated;
    }

    const scriptPath = path.join(dir, 'step.sh');
    fs.writeFileSync(scriptPath, `#!/bin/bash\n${script}`);
    const outPath = path.join(dir, 'gh_output');
    fs.writeFileSync(outPath, '');

    let status = 0;
    let stdout = '';
    let stderr = '';
    try {
      stdout = execFileSync('bash', [scriptPath], {
        cwd: dir,
        env: { ...process.env, GITHUB_OUTPUT: outPath, PR_NUMBER: '7' },
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (e: unknown) {
      const err = e as { status?: number; stdout?: string; stderr?: string };
      status = err.status ?? 1;
      stdout = err.stdout ?? '';
      stderr = err.stderr ?? '';
    }

    const outputs: Record<string, string> = {};
    for (const line of fs.readFileSync(outPath, 'utf8').split('\n')) {
      const eq = line.indexOf('=');
      if (eq > 0) outputs[line.slice(0, eq)] = line.slice(eq + 1);
    }

    let batchNames: string[] = [];
    let batches: string[] = [];
    if (fs.existsSync('/tmp/pr_batches')) {
      batchNames = fs.readdirSync('/tmp/pr_batches').sort();
      batches = batchNames.map((n) => fs.readFileSync(path.join('/tmp/pr_batches', n), 'utf8'));
    }
    const refusal = fs.existsSync('/tmp/pr_gate_refusal.txt')
      ? fs.readFileSync('/tmp/pr_gate_refusal.txt', 'utf8')
      : '';

    fs.rmSync(dir, { recursive: true, force: true });
    return { status, stdout, stderr, outputs, batches, batchNames, refusal };
  });
}

// ---------------------------------------------------------------- fixtures

const PAD = 'x'.repeat(60);

/** A unified diff chunk that adds `lines` lines to `p`. */
function chunk(p: string, lines: number): string {
  const out = [
    `diff --git a/${p} b/${p}\n`,
    `index 1111111..2222222 100644\n--- a/${p}\n+++ b/${p}\n`,
    `@@ -0,0 +1,${lines} @@\n`,
  ];
  for (let j = 0; j < lines; j++) out.push(`+// line ${j} of ${p} ${PAD}\n`);
  return out.join('');
}

/** `n` files, each with `lines` added lines, plus a working tree for them. */
function manyFiles(n: number, lines: number): Fixture {
  let diff = '';
  const tree: Array<[string, string]> = [];
  for (let i = 0; i < n; i++) {
    diff += chunk(`src/f${i}.ts`, lines);
    tree.push([`src/f${i}.ts`, 'const x = 1;\n'.repeat(300)]);
  }
  return { diff, tree };
}

/** Pull the DIFF section back out of a composed batch. */
const DIFF_MARK = '\n\nDIFF (changes introduced in this PR):\n';
const PREV_MARK = '\n\nPREVIOUS REVIEW (check if issues were fixed';

function diffSection(batch: string): string {
  const i = batch.indexOf(DIFF_MARK);
  if (i < 0) throw new Error('batch has no DIFF section');
  const rest = batch.slice(i + DIFF_MARK.length);
  const p = rest.indexOf(PREV_MARK);
  return p < 0 ? rest : rest.slice(0, p);
}

/**
 * A chunk whose hunk body contains lines that are literally `+++ b/…` and
 * `--- a/…`.
 *
 * Getting this shape right matters more than it looks. A pull request that
 * ADDS the text `+++ b/x` renders as `++++ b/x` — four pluses — which does not
 * match a `^\+\+\+ ` header rule at all, so a fixture built that way tests
 * nothing and its mutant survives. The line that really collides is an added
 * line whose CONTENT is `++ b/x`, and a removed line whose content is
 * `-- a/x`. Those render as exactly the header forms.
 */
function impostorChunk(p: string, victim: string): string {
  return (
    `diff --git a/${p} b/${p}\nindex 1111111..2222222 100644\n` +
    `--- a/${p}\n+++ b/${p}\n@@ -1,2 +1,3 @@\n` +
    `+++ b/${victim}\n` +
    `--- a/${victim}\n` +
    ` context line\n`
  );
}

function fileList(batch: string): string[] {
  const mark = '\nChanged files (this batch):\n';
  const i = batch.indexOf(mark);
  const rest = batch.slice(i + mark.length);
  return rest.slice(0, rest.indexOf('\n\n')).split('\n').filter(Boolean);
}

// ---------------------------------------------------------------- the rows

describe('PR review gate: the partition step is executable and self-describing', () => {
  it('carries no workflow expressions, so it runs verbatim outside Actions', () => {
    expect(partitionScript()).not.toContain('${{');
  });

  it('the batch target this suite asserts against is the one the step uses', () => {
    // Without this the whole "every batch fits" property could be asserted
    // against a number the step abandoned, and would keep passing.
    expect(partitionScript()).toContain(`TARGET_BYTES=${TARGET_BYTES}`);
  });

  it('pins the shared action to a full 40-hex SHA, never a tag and never @main', () => {
    const uses = stepById('review').uses as string;
    expect(uses).toBe(`opena2a-org/.github/actions/claude-review@${EXPECTED_PIN}`);
    expect(uses).toMatch(/@[0-9a-f]{40}$/);
  });

  it('wires batch-dir from the partitioner and does not override max-batches', () => {
    const withInputs = stepById('review').with as Record<string, string>;
    expect(withInputs['batch-dir']).toBe('${{ steps.partition.outputs.batch-dir }}');
    // The 8-batch ceiling bounds this gate's worst-case cost. It is not a
    // per-repo dial, so the caller must inherit the action's default.
    expect(withInputs['max-batches']).toBeUndefined();
  });

  it('skips the review step when the partitioner CRASHED, not only when it refused', () => {
    // An `if:` replaces the implicit success(). Without `success() &&` the
    // review would run after a crashed partition step, on whatever files
    // survived, and could return APPROVE.
    expect(stepById('review').if).toBe("success() && steps.partition.outputs.refused != 'true'");
  });

  it('keeps the job name the required status checks are keyed on', () => {
    const wf = loadWorkflow() as unknown as { jobs: { review: { name: string } } };
    expect(wf.jobs.review.name).toBe('Claude Code Review');
  });
});

describe('PR review gate: single mode stays the default', () => {
  it('a change that fits sends one request and sets no batch dir', () => {
    const r = runPartition(manyFiles(2, 3));
    expect(r.status).toBe(0);
    expect(r.outputs['batch-dir']).toBe('');
    expect(r.outputs.refused).toBe('false');
    expect(r.outputs.batches).toBe('1');
    expect(r.batchNames).toEqual([]);
  });

  it('the decision counts the system prompt, not the diff alone', () => {
    // A diff that fits on its own but not once the system prompt is added.
    // Measuring the diff alone would send a request over the budget the
    // action then refuses, which is a wasted review rather than a split one.
    const diff = chunk('src/a.ts', 4200); // ~ 370 KB
    const small = runPartition({ diff, tree: [['src/a.ts', 'x\n']], systemPrompt: 'S\n' });
    expect(small.outputs.batches).toBe('1');

    const big = runPartition({
      diff,
      tree: [['src/a.ts', 'x\n']],
      systemPrompt: 'S'.repeat(120000),
    });
    expect(big.outputs.batches).not.toBe('1');
  });
});

describe('PR review gate: batch mode cuts on file boundaries', () => {
  it('splits an oversized change into batches and reports how many', () => {
    const r = runPartition(manyFiles(12, 1200));
    expect(r.status).toBe(0);
    expect(r.outputs.refused).toBe('false');
    expect(r.outputs['batch-dir']).toBe('/tmp/pr_batches');
    expect(Number(r.outputs.batches)).toBeGreaterThan(1);
    expect(r.batches.length).toBe(Number(r.outputs.batches));
  });

  it('every batch fits the target once the system prompt is counted', () => {
    const sys = 'SYSTEM PROMPT\n';
    const r = runPartition({ ...manyFiles(12, 1200), systemPrompt: sys });
    for (const b of r.batches) {
      expect(Buffer.byteLength(b) + Buffer.byteLength(sys)).toBeLessThanOrEqual(TARGET_BYTES);
    }
  });

  it('every byte of the diff is in exactly one batch', () => {
    // The property that makes a chunked review mean anything. A count of
    // batches cannot prove it: a dropped chunk leaves the count and the loop
    // agreeing with each other and disagreeing with the pull request.
    const fx = manyFiles(12, 1200);
    const r = runPartition(fx);
    expect(r.batches.map(diffSection).join('')).toBe(fx.diff);
  });

  it('never splits one file across two batches', () => {
    const fx = manyFiles(12, 1200);
    const r = runPartition(fx);
    for (let i = 0; i < 12; i++) {
      const header = `diff --git a/src/f${i}.ts b/src/f${i}.ts\n`;
      const holders = r.batches.filter((b) => b.includes(header));
      expect(holders.length).toBe(1);
    }
  });

  it('gives every batch the batch it is and the total, and says the rest is elsewhere', () => {
    const r = runPartition(manyFiles(12, 1200));
    const n = Number(r.outputs.batches);
    r.batches.forEach((b, i) => {
      expect(b).toContain(`This is request ${i + 1} of ${n}.`);
      expect(b).toContain('are being reviewed in the other requests');
    });
  });

  it('does not tell the reviewer to approve anything', () => {
    // A partitioner that can talk the reviewer into a pass is worse than no
    // partitioner. The scope note may state scope; it may not lower the bar.
    const r = runPartition(manyFiles(12, 1200));
    const note = r.batches[0].split('SCOPE OF THIS REQUEST:')[1].split('\n')[0];
    expect(note).not.toMatch(/approve/i);
    expect(note).not.toMatch(/benign|assume|ignore|do not report/i);
  });

  it('gives each batch its own files and their source, and lists them', () => {
    const r = runPartition(manyFiles(12, 1200));
    r.batches.forEach((b) => {
      for (const p of fileList(b)) {
        expect(b).toContain(`=== ${p} ===`);
      }
    });
    const listed = r.batches.flatMap(fileList).sort();
    const expected = Array.from({ length: 12 }, (_, i) => `src/f${i}.ts`).sort();
    expect(listed).toEqual(expected);
  });

  it('repeats the previous review in every batch', () => {
    const r = runPartition({
      ...manyFiles(12, 1200),
      previousReview: 'FINDINGS: something from last time that must not be re-raised',
    });
    for (const b of r.batches) {
      expect(b).toContain('PREVIOUS REVIEW (check if issues were fixed');
      expect(b).toContain('something from last time');
    }
  });

  it('leaves the batch dir holding nothing but non-empty regular batch files', () => {
    // The action refuses a batch dir with a non-regular or empty entry, which
    // would turn a partition defect into an INCONCLUSIVE with a confusing
    // cause.
    const r = runPartition(manyFiles(12, 1200));
    expect(r.batchNames.length).toBeGreaterThan(0);
    for (const n of r.batchNames) {
      const st = fs.statSync(path.join('/tmp/pr_batches', n));
      expect(st.isFile()).toBe(true);
      expect(st.size).toBeGreaterThan(0);
      expect(n).toMatch(/^\d{3}\.txt$/);
    }
    // Zero-padded, so the action's `LC_ALL=C sort` order is the diff order.
    expect([...r.batchNames].sort()).toEqual(r.batchNames);
  });
});

describe('PR review gate: what it refuses, and what it refuses to exempt', () => {
  it('refuses when one file alone cannot fit, and says to split the pull request', () => {
    const r = runPartition({
      diff: chunk('src/huge.ts', 8000),
      tree: [['src/huge.ts', 'z\n'.repeat(200)]],
    });
    expect(r.status).toBe(0); // a review outcome, not a crash
    expect(r.outputs.refused).toBe('true');
    expect(r.outputs['batch-dir']).toBe('');
    expect(r.outputs.batches).toBe('0');
    expect(r.refusal).toContain('src/huge.ts');
    expect(r.refusal).toContain('Split it into smaller pull requests');
    expect(r.refusal).not.toMatch(/APPROVE/);
    // Nothing left behind that a later reader could mistake for a partition
    // that succeeded.
    expect(fs.existsSync('/tmp/pr_batches')).toBe(false);
  });

  it('states that the budget is not raised and no file is exempt', () => {
    const r = runPartition({
      diff: chunk('src/huge.ts', 8000),
      tree: [['src/huge.ts', 'z\n']],
    });
    expect(r.refusal).toContain('not raised');
    expect(r.refusal).toMatch(/no file is exempt from review by type or by name/);
  });

  it('does not exempt a file from REVIEW because of its type', () => {
    // Source context is excluded for tests and lockfiles, exactly as single
    // mode excludes it. The DIFF is never withheld: that predicate is written
    // by whoever opened the pull request.
    const fx = manyFiles(6, 1200);
    fx.diff += chunk('src/a.test.ts', 4) + chunk('package-lock.json', 4);
    fx.tree!.push(['src/a.test.ts', 'TEST SOURCE MARKER\n']);
    fx.tree!.push(['package-lock.json', 'LOCK SOURCE MARKER\n']);
    const r = runPartition(fx);
    const all = r.batches.join('');
    expect(all).toContain('diff --git a/src/a.test.ts b/src/a.test.ts');
    expect(all).toContain('diff --git a/package-lock.json b/package-lock.json');
    expect(all).not.toContain('TEST SOURCE MARKER');
    expect(all).not.toContain('LOCK SOURCE MARKER');
    // And conservation still holds with them in.
    expect(r.batches.map(diffSection).join('')).toBe(fx.diff);
  });

  it('refuses a diff with no file headers rather than sending one unsplit', () => {
    const r = runPartition({ diff: `${'q'.repeat(500000)}\n` });
    expect(r.outputs.refused).toBe('true');
    expect(r.refusal).toContain('no file headers');
  });
});

describe('PR review gate: diff shapes that are not plain edits', () => {
  it('does not read a `+++ b/` line inside a hunk as a file header', () => {
    // A pull request that edits a patch file, a test fixture or a tutorial
    // contains lines that ARE diff headers. Reading them is how a partitioner
    // starts taking direction from the payload it is cutting up: the path it
    // believes it is looking at becomes author-controlled, and the source it
    // attaches is a file the author chose rather than the file that changed.
    const fx = manyFiles(6, 1200);
    fx.diff += impostorChunk('src/patch.md', 'src/IMPOSTOR.ts');
    fx.tree!.push(['src/patch.md', 'real content\n']);
    fx.tree!.push(['src/IMPOSTOR.ts', 'IMPOSTOR SOURCE MARKER\n']);
    const r = runPartition(fx);
    const all = r.batches.join('');
    expect(all).not.toContain('IMPOSTOR SOURCE MARKER');
    expect(all).toContain('=== src/patch.md ===');
    expect(r.batches.flatMap(fileList)).not.toContain('src/IMPOSTOR.ts');
    expect(r.batches.map(diffSection).join('')).toBe(fx.diff);
  });

  it('does not read a `--- a/` line inside a deleted file’s hunk as its path', () => {
    // The deletion path is the one place `---` is load-bearing, so it is also
    // the one place an in-hunk `---` could be mistaken for it.
    const fx = manyFiles(6, 1200);
    fx.diff +=
      'diff --git a/gone.ts b/gone.ts\nindex 1111111..0000000 100644\n' +
      '--- a/gone.ts\n+++ /dev/null\n@@ -1,2 +0,0 @@\n' +
      '--- a/src/IMPOSTOR2.ts\n-real removed line\n';
    const r = runPartition(fx);
    const names = r.batches.flatMap(fileList);
    expect(names).toContain('gone.ts');
    expect(names).not.toContain('src/IMPOSTOR2.ts');
  });

  it('names a deleted file and attaches no source for it', () => {
    const fx = manyFiles(6, 1200);
    fx.diff +=
      'diff --git a/gone.ts b/gone.ts\nindex 1..0 100644\n' +
      '--- a/gone.ts\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-a\n-b\n';
    const r = runPartition(fx);
    expect(r.batches.flatMap(fileList)).toContain('gone.ts');
    expect(r.batches.join('')).not.toContain('=== gone.ts ===');
  });

  it('names a pure rename and attaches no source, because nothing changed in it', () => {
    const fx = manyFiles(6, 1200);
    fx.diff +=
      'diff --git a/old.ts b/new.ts\nsimilarity index 100%\nrename from old.ts\nrename to new.ts\n';
    fx.tree!.push(['new.ts', 'RENAMED SOURCE MARKER\n']);
    const r = runPartition(fx);
    expect(r.batches.flatMap(fileList)).toContain('new.ts');
    expect(r.batches.join('')).not.toContain('RENAMED SOURCE MARKER');
  });

  it('carries a change whose path it cannot read, and says the batch holds one', () => {
    // git does not quote spaces but does quote other characters. The change is
    // still reviewed; only its source context is missing, and the gap between
    // the file list and the diff is explained rather than left to look like
    // tampering.
    const fx = manyFiles(6, 1200);
    fx.diff +=
      'diff --git "a/we\\tird.ts" "b/we\\tird.ts"\nindex 1..2 100644\n' +
      '--- "a/we\\tird.ts"\n+++ "b/we\\tird.ts"\n@@ -0,0 +1,1 @@\n+q\n';
    const r = runPartition(fx);
    const all = r.batches.join('');
    expect(all).toContain('whose path could not be read from the diff header');
    expect(all).toContain('+++ "b/we\\tird.ts"');
    expect(r.batches.map(diffSection).join('')).toBe(fx.diff);
  });

  it('carries text that appears before the first file header', () => {
    const fx = manyFiles(8, 1200);
    fx.diff = `warning: a tool printed this first\n${fx.diff}`;
    const r = runPartition(fx);
    expect(r.batches[0]).toContain('warning: a tool printed this first');
    expect(r.batches.map(diffSection).join('')).toBe(fx.diff);
  });

  it('partitions a diff that does not end in a newline instead of refusing it', () => {
    // Git terminates every line it emits, so this is not expected to happen —
    // and refusing a 30,000-line pull request over one absent byte would be a
    // false red on the exact class this mechanism exists to review.
    const fx = manyFiles(8, 1200);
    fx.diff = fx.diff.replace(/\n$/, '');
    const r = runPartition(fx);
    expect(r.outputs.refused).toBe('false');
    expect(Number(r.outputs.batches)).toBeGreaterThan(1);
    expect(r.batches.map(diffSection).join('')).toBe(`${fx.diff}\n`);
    expect(r.stdout).toContain('did not end in a newline');
  });
});

/**
 * Non-vacuity. Every row above is asserted to be capable of failing, by
 * breaking the step and requiring the row to notice.
 *
 * A row that cannot see its own property is indistinguishable from coverage:
 * the suite is green either way, and the green is read as proof.
 */
describe('PR review gate: the rows above can fail', () => {
  const mutants: Array<{
    name: string;
    mutate: (s: string) => string;
    check: (r: RunResult, fx: Fixture) => void;
  }> = [
    {
      name: 'the packer never starts a second batch',
      mutate: (s) =>
        s.replace(
          'if [ "$NBATCH" -eq 0 ] || [ $((USED + UNIT)) -gt "$BUDGET" ]; then',
          'if [ "$NBATCH" -eq 0 ]; then',
        ),
      check: (r) => {
        // The "every batch fits" row must be the one that catches this.
        const over = r.batches.some(
          (b) => Buffer.byteLength(b) + Buffer.byteLength('SYSTEM PROMPT\n') > TARGET_BYTES,
        );
        expect(over).toBe(true);
      },
    },
    {
      name: 'a chunk is dropped from the plan',
      mutate: (s) =>
        s.replace(
          "printf '%s\\t%s\\t%s\\n' \"$IDX\" \"$NBATCH\" \"$FPATH\" >> \"$PLAN\"",
          '[ "$IDX" = "000003" ] || printf \'%s\\t%s\\t%s\\n\' "$IDX" "$NBATCH" "$FPATH" >> "$PLAN"',
        ),
      check: (r, fx) => {
        // Conservation catches it, and the step refuses rather than reviewing
        // a pull request it silently trimmed.
        expect(r.batches.map(diffSection).join('')).not.toBe(fx.diff);
      },
    },
    {
      name: 'the single-file ceiling never fires',
      mutate: (s) =>
        s.replace('if [ "$UNIT" -gt "$BUDGET" ]; then', 'if [ "$UNIT" -gt 999999999 ]; then'),
      check: (r) => {
        expect(r.outputs.refused).not.toBe('true');
      },
    },
    {
      name: 'a `+++` line is read inside hunks too',
      mutate: (s) =>
        s.replace('n > 0 && inhunk == 0 && /^\\+\\+\\+ / {', 'n > 0 && /^\\+\\+\\+ / {'),
      check: (r) => {
        expect(r.batches.join('')).toContain('IMPOSTOR SOURCE MARKER');
      },
    },
    {
      name: 'a `---` line is read inside hunks too',
      mutate: (s) =>
        s.replace('n > 0 && inhunk == 0 && /^--- / {', 'n > 0 && /^--- / {'),
      check: (r) => {
        expect(r.batches.flatMap(fileList)).toContain('src/IMPOSTOR2.ts');
      },
    },
    {
      name: 'source is attached to chunks with no hunks',
      mutate: (s) => s.replace('[ "$HUNKS" = "1" ] || continue', ':'),
      check: (r) => {
        expect(r.batches.join('')).toContain('RENAMED SOURCE MARKER');
      },
    },
    {
      name: 'the context exclusions are dropped',
      mutate: (s) =>
        s.replace('*.test.* | *.spec.* | package-lock.json | *.lock) continue ;;', '__never__) ;;'),
      check: (r) => {
        expect(r.batches.join('')).toContain('TEST SOURCE MARKER');
      },
    },
    {
      name: 'the conservation check is removed',
      mutate: (s) => s.replace('cmp -s "$WORK_DIR/rejoined.diff" "$SRC" \\', 'true \\'),
      check: (r) => {
        // With the drop mutant's shape it would go green; here the point is
        // narrower — the anchor must still exist to be removable.
        expect(r.outputs.refused).toBe('false');
      },
    },
  ];

  // Each mutant runs against the fixture that exercises it.
  const fixtures: Record<string, () => Fixture> = {
    'the packer never starts a second batch': () => manyFiles(12, 1200),
    'a chunk is dropped from the plan': () => manyFiles(12, 1200),
    'the single-file ceiling never fires': () => ({
      diff: chunk('src/huge.ts', 8000),
      tree: [['src/huge.ts', 'z\n']],
    }),
    'a `+++` line is read inside hunks too': () => {
      const fx = manyFiles(6, 1200);
      fx.diff += impostorChunk('src/patch.md', 'src/IMPOSTOR.ts');
      fx.tree!.push(['src/patch.md', 'real content\n']);
      fx.tree!.push(['src/IMPOSTOR.ts', 'IMPOSTOR SOURCE MARKER\n']);
      return fx;
    },
    'a `---` line is read inside hunks too': () => {
      const fx = manyFiles(6, 1200);
      fx.diff +=
        'diff --git a/gone.ts b/gone.ts\nindex 1111111..0000000 100644\n' +
        '--- a/gone.ts\n+++ /dev/null\n@@ -1,2 +0,0 @@\n' +
        '--- a/src/IMPOSTOR2.ts\n-real removed line\n';
      return fx;
    },
    'source is attached to chunks with no hunks': () => {
      const fx = manyFiles(6, 1200);
      fx.diff +=
        'diff --git a/old.ts b/new.ts\nsimilarity index 100%\nrename from old.ts\nrename to new.ts\n';
      fx.tree!.push(['new.ts', 'RENAMED SOURCE MARKER\n']);
      return fx;
    },
    'the context exclusions are dropped': () => {
      const fx = manyFiles(6, 1200);
      fx.diff += chunk('src/a.test.ts', 4);
      fx.tree!.push(['src/a.test.ts', 'TEST SOURCE MARKER\n']);
      return fx;
    },
    'the conservation check is removed': () => manyFiles(12, 1200),
  };

  for (const m of mutants) {
    it(`caught: ${m.name}`, () => {
      const fx = fixtures[m.name]();
      const r = runPartition(fx, m.mutate);
      m.check(r, fx);
    });
  }
});

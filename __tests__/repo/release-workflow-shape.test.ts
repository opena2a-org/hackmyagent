/**
 * HMA-40 — the release path, read from the committed workflow text.
 *
 * `.github/workflows/release.yml` is the one kind of code in this repository
 * that nothing executes before it runs with credentials: its first execution
 * on a change is a tag push, which under Trusted Publishing IS the publish
 * event. So its shape is pinned here, in a suite that
 * `.github/workflows/test-matrix.yml` runs on every pull request:
 *
 *   build   — `contents: read` only, `npm ci --ignore-scripts`, build, test,
 *             pack; the tarball's sha256 recorded as a job output and the
 *             tarball uploaded as an artifact.
 *   review  — needs build; downloads that artifact; runs
 *             scripts/release-artifact-review.mjs on it; a non-zero exit
 *             fails the job.
 *   publish — needs review; `id-token: write` and NOTHING else; no checkout;
 *             publishes the downloaded tarball with provenance. The reviewed
 *             bytes are the published bytes, held together by the digest.
 *   verify  — after publish; pins the SLSA v1 predicate and npm's
 *             `dist.integrity` to the recorded digest.
 *
 * The base shape this replaced granted `contents: write` and
 * `id-token: write` workflow-wide to a single job that also ran `npm ci` and
 * `npm test` — every dependency script and every test executed while holding
 * the publishing token.
 *
 * The second half (AC4) pins the package-manager-config guard: every job in
 * ANY workflow that runs `npm ci` refuses, before its install step, a tree
 * that tracks a `.npmrc` / `.yarnrc(.yml)` / `.pnpmfile.cjs` / `.envrc` —
 * the files that redirect or hook the install itself. The sweep is dynamic
 * over the workflows directory so a future job cannot add an unguarded
 * `npm ci` without turning this suite red.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as yaml from 'js-yaml';
import { initThrowawayRepo, gitFreeEnv } from '../helpers/throwaway-repo';

const ROOT = path.join(__dirname, '..', '..');
const WORKFLOW_DIR = path.join(ROOT, '.github', 'workflows');

interface Step {
  name?: string;
  id?: string;
  uses?: string;
  run?: string;
  if?: string;
  with?: Record<string, unknown>;
  'continue-on-error'?: unknown;
}
interface Job {
  needs?: string | string[];
  permissions?: Record<string, string>;
  outputs?: Record<string, string>;
  steps?: Step[];
}
interface Workflow {
  permissions?: Record<string, string>;
  jobs?: Record<string, Job>;
}

function load(name: string): Workflow {
  return yaml.load(fs.readFileSync(path.join(WORKFLOW_DIR, name), 'utf8')) as Workflow;
}

const release = load('release.yml');
const jobs = release.jobs!;
const needsOf = (j: Job): string[] => (Array.isArray(j.needs) ? j.needs : j.needs ? [j.needs] : []);
const stepsOf = (j: Job): Step[] => j.steps ?? [];
const runs = (j: Job): string => stepsOf(j).map((s) => s.run ?? '').join('\n');

/**
 * Full-line `#` comments dropped before matching, exactly as in
 * pr-review-partition.test.ts: these assertions are about what a step
 * EXECUTES, and a comment that merely mentions `npm ci` must not conscript a
 * job into the guard sweep (nor a banned string into a violation).
 */
function executableLines(run: string): string {
  return run
    .split('\n')
    .filter((l) => !/^\s*#/.test(l))
    .join('\n');
}

/**
 * The one `npm publish` line of a job's executable text, split into its
 * first argument (quotes stripped) and the flags after it. Exactly one such
 * line must exist: zero means the job does not publish, two means a retry or
 * a second package is hiding in the step.
 */
function publishInvocation(run: string): { arg: string; flags: string } {
  const lines = run.split('\n').filter((l) => /^\s*npm publish(\s|$)/.test(l));
  expect(lines, 'exactly one `npm publish` line in the publish job').toHaveLength(1);
  const m = /^\s*npm publish\s+("([^"]*)"|'([^']*)'|(\S+))\s*(.*)$/.exec(lines[0]);
  expect(m, `unparseable npm publish line: ${lines[0]}`).not.toBeNull();
  return { arg: m![2] ?? m![3] ?? m![4], flags: m![5] };
}

/**
 * npm's own argument parser, loaded from the npm that `npm` on PATH runs
 * (`npm root -g`/npm/node_modules/npm-package-arg). This is the code path
 * `npm publish <arg>` takes to decide whether <arg> is a file or a remote
 * spec, so the control below exercises the real reading, not a regex of it.
 * Resolution failure is a test failure, not a skip: this suite runs in the
 * tag-triggered build job, and a gate that skips when its instrument is
 * missing is quiet exactly when nothing is checking.
 */
interface NpmParser {
  npa: (spec: string) => { type: string };
  /** Where it was loaded from and what it is, for the assertion messages. */
  describe: string;
}
function loadNpmPackageArg(): NpmParser {
  const env = gitFreeEnv();
  const npmVersion = execFileSync('npm', ['--version'], { encoding: 'utf8', env }).trim();
  const npmRoot = execFileSync('npm', ['root', '-g'], { encoding: 'utf8', env }).trim();
  const expected = path.join(npmRoot, 'npm', 'node_modules', 'npm-package-arg');
  let resolved: string;
  try {
    resolved = require.resolve('npm-package-arg', { paths: [path.join(npmRoot, 'npm')] });
  } catch (err) {
    throw new Error(
      `npm-package-arg not resolvable from the npm on PATH (npm ${npmVersion}; \`npm root -g\` = ${npmRoot}; ` +
        `expected ${expected}). The control needs the npm that runs \`npm publish\`; fix the environment, never skip: ${String(err)}`,
    );
  }
  const npaVersion = (JSON.parse(fs.readFileSync(path.join(path.dirname(resolved), '..', 'package.json'), 'utf8')) as { version?: string }).version ?? 'unknown';
  return {
    npa: require(resolved) as (spec: string) => { type: string },
    describe: `npm-package-arg ${npaVersion} at ${resolved}, npm ${npmVersion}`,
  };
}

/** The guard pipeline, verbatim from the criterion. One escape level: this is the shell text. */
const PM_CONFIG_PATTERN = '(^|/)(\\.npmrc|\\.yarnrc(\\.yml)?|\\.pnpmfile\\.cjs|\\.envrc)$';
const GUARD_COMMAND = `git ls-files | grep -E '${PM_CONFIG_PATTERN}'`;

describe('HMA-40.AC1: release.yml holds the build → review → publish → verify shape', () => {
  it('HMA-40.AC1 the four jobs exist in order, joined by needs', () => {
    const names = Object.keys(jobs);
    expect(names.slice(0, 4)).toEqual(['build', 'review', 'publish', 'verify']);
    expect(needsOf(jobs.review)).toContain('build');
    expect(needsOf(jobs.publish)).toContain('review');
    expect(needsOf(jobs.verify)).toContain('publish');
  });

  it('HMA-40.AC1 build holds contents: read only and runs guard, ci --ignore-scripts, build, test, pack in order', () => {
    expect(jobs.build.permissions).toEqual({ contents: 'read' });
    const steps = stepsOf(jobs.build);
    const at = (pred: (s: Step) => boolean, what: string): number => {
      const i = steps.findIndex(pred);
      expect(i, `build has no step: ${what}`).toBeGreaterThanOrEqual(0);
      return i;
    };
    const ci = at((s) => /(^|\s)npm ci --ignore-scripts(\s|$)/.test(executableLines(s.run ?? '')), 'npm ci --ignore-scripts');
    const build = at((s) => /(^|\s)npm run build(\s|$)/.test(executableLines(s.run ?? '')), 'npm run build');
    const test = at((s) => /(^|\s)npm test(\s|$)/.test(executableLines(s.run ?? '')), 'npm test');
    const pack = at((s) => /npm pack --pack-destination/.test(executableLines(s.run ?? '')), 'npm pack into a directory');
    expect(ci).toBeLessThan(build);
    expect(build).toBeLessThan(test);
    expect(test).toBeLessThan(pack);
    // The plain `npm ci` form must not appear anywhere in the job: an install
    // that runs dependency scripts in the job that packs the artifact is the
    // exact thing the split removed.
    expect(executableLines(runs(jobs.build))).not.toMatch(/npm ci(?! --ignore-scripts)/);
  });

  it('HMA-40.AC1 build records the tarball sha256 as a job output and uploads the tarball as an artifact', () => {
    const pack = stepsOf(jobs.build).find((s) => /npm pack/.test(s.run ?? ''));
    expect(pack?.id).toBeDefined();
    expect(pack!.run).toMatch(/sha256/);
    expect(pack!.run).toContain('tarball-sha256=');
    expect(pack!.run).toContain('$GITHUB_OUTPUT');
    expect(jobs.build.outputs?.['tarball-sha256']).toContain(`steps.${pack!.id}.outputs.tarball-sha256`);
    const upload = stepsOf(jobs.build).find((s) => (s.uses ?? '').startsWith('actions/upload-artifact'));
    expect(upload).toBeDefined();
    expect(String((upload!.with ?? {})['if-no-files-found'])).toBe('error');
  });

  it('HMA-40.AC1 review downloads the built artifact and runs the review script with nothing softening its exit', () => {
    const steps = stepsOf(jobs.review);
    const download = steps.findIndex((s) => (s.uses ?? '').startsWith('actions/download-artifact'));
    const reviewStep = steps.findIndex((s) =>
      (s.run ?? '').includes('node scripts/release-artifact-review.mjs --tarball'),
    );
    expect(download).toBeGreaterThanOrEqual(0);
    expect(reviewStep).toBeGreaterThan(download);
    // A non-zero exit must fail the job: no continue-on-error, no `if:` that
    // could skip it, anywhere in the job.
    for (const s of steps) {
      expect(s['continue-on-error'], `review step "${s.name ?? s.uses ?? 'run'}" softens failure`).toBeUndefined();
      expect(s.if, `review step "${s.name ?? s.uses ?? 'run'}" is conditional`).toBeUndefined();
    }
    // The reviewed bytes are pinned to the digest build recorded.
    expect(steps[reviewStep].run).toContain('TARBALL_SHA256');
  });

  it('HMA-40.AC1 publish carries id-token: write and nothing else, no checkout, and publishes the reviewed tarball with provenance', () => {
    expect(jobs.publish.permissions).toEqual({ 'id-token': 'write' });
    for (const s of stepsOf(jobs.publish)) {
      expect(s.uses ?? '', 'publish must not check out the tree').not.toMatch(/actions\/checkout/);
    }
    const run = executableLines(runs(jobs.publish));
    // Publishing the DOWNLOADED ARTIFACT, not the tree: the argument to
    // `npm publish` is the tarball path, with provenance, public.
    const publish = publishInvocation(run);
    expect(publish.arg).toContain('${TARBALL_NAME}');
    expect(publish.flags).toMatch(/(^|\s)--provenance(\s|$)/);
    expect(publish.flags).toMatch(/(^|\s)--access public(\s|$)/);
    // The path must be one npm can only read as a FILE. A bare `dir/name.tgz`
    // is a package spec to npm, and `release-pack/<tarball>` is the GitHub
    // shorthand `<owner>/<repo>`: the v0.33.1 run (35161269506) reached this
    // step with the reviewed bytes in hand and exited 128 on
    // `git ls-remote ssh://git@github.com/release-pack/hackmyagent-0.33.1.tgz.git`.
    // Nothing reached npm. Only a leading `./` or `/` closes that reading.
    expect(publish.arg, `npm publish argument "${publish.arg}" is not a file path; npm reads a bare dir/name as <owner>/<repo>`).toMatch(/^\.?\//);
    // And the artifact is digest-checked before it is published.
    expect(run).toContain('TARBALL_SHA256');
  });

  it('HMA-40.AC1 verify pins the SLSA v1 predicate and dist.integrity to the recorded digest, after publish', () => {
    const run = executableLines(runs(jobs.verify));
    expect(run).toContain('https://slsa.dev/provenance/v1');
    expect(run).toContain('dist.integrity');
    expect(run).toContain('dist.attestations');
    expect(run).toContain('TARBALL_SHA256');
    // The integrity comparison is against the reviewed bytes, not a re-pack.
    expect(run).toMatch(/sha512/);
  });

  it('HMA-40.AC1 the top-level permissions grant neither contents: write nor id-token: write', () => {
    // The base granted both, workflow-wide, to a job that ran npm ci and
    // npm test. `permissions: {}` (or any explicit block without these two
    // writes) is what this row accepts.
    const top = release.permissions ?? {};
    expect(top['contents']).not.toBe('write');
    expect(top['id-token']).not.toBe('write');
    // And it is DECLARED, so the repository default cannot re-widen it.
    expect(release.permissions).toBeDefined();
  });

  it('HMA-40.AC1 no job other than publish carries id-token: write', () => {
    for (const [name, job] of Object.entries(jobs)) {
      if (name === 'publish') continue;
      expect((job.permissions ?? {})['id-token'], `job ${name} carries id-token`).not.toBe('write');
    }
  });
});

describe('HMA-40.AC1 the publish argument is a file to npm, measured with npm\'s own parser', () => {
  const sample = 'hackmyagent-0.0.0.tgz';

  it('the bare release-pack/<tarball> form is a git spec to npm (the v0.33.1 failure), and the workflow argument is a file', () => {
    const parser = loadNpmPackageArg();
    // Positive control: the exact string the v0.33.1 run passed. If npm ever
    // stops reading it as a remote, this row goes red and the rule is
    // re-examined rather than silently carried.
    const bare = `release-pack/${sample}`;
    expect(parser.npa(bare).type, `${parser.describe}: "${bare}" no longer reads as a git spec; re-examine the prefix rule`).toBe('git');
    const publish = publishInvocation(executableLines(runs(jobs.publish)));
    const concrete = publish.arg.replace('${TARBALL_NAME}', sample);
    expect(concrete, 'the publish argument carries ${TARBALL_NAME}').not.toBe(publish.arg);
    expect(parser.npa(concrete).type, `${parser.describe}: publish argument "${concrete}" is not a file to npm`).toBe('file');
  });
});

describe('HMA-40.AC5: every action release.yml runs is pinned to a commit, never a mutable tag', () => {
  it('HMA-40.AC5 each uses: names a 40-hex commit SHA (the version rides as a trailing comment)', () => {
    let seen = 0;
    for (const [jobName, job] of Object.entries(jobs)) {
      for (const s of stepsOf(job)) {
        if (!s.uses) continue;
        seen += 1;
        expect(s.uses, `${jobName}: ${s.uses} — a tag can be retargeted; the jobs holding id-token: write and contents: write would then run whatever it points at, as us`).toMatch(/^[^@]+@[0-9a-f]{40}$/);
      }
    }
    expect(seen, 'release.yml runs no actions at all — the shape moved').toBeGreaterThan(0);
  });
});

describe('HMA-40.AC4: every npm ci is preceded by the package-manager-config guard', () => {
  const workflowFiles = fs.readdirSync(WORKFLOW_DIR).filter((f) => /\.ya?ml$/.test(f));

  it('HMA-40.AC4 every workflow job that runs npm ci carries the guard before its install, unconditioned', () => {
    let guardedInstalls = 0;
    for (const file of workflowFiles) {
      const wf = load(file);
      for (const [jobName, job] of Object.entries(wf.jobs ?? {})) {
        const steps = stepsOf(job);
        const installIdx = steps.findIndex((s) => /(^|\s)npm ci(\s|$)/m.test(executableLines(s.run ?? '')));
        if (installIdx < 0) continue;
        guardedInstalls++;
        const guardIdx = steps.findIndex((s) => (s.run ?? '').includes(GUARD_COMMAND));
        expect(guardIdx, `${file} job ${jobName}: no guard step with the exact grep pipeline`).toBeGreaterThanOrEqual(0);
        expect(guardIdx, `${file} job ${jobName}: guard must run before the install`).toBeLessThan(installIdx);
        const guard = steps[guardIdx];
        expect(guard['continue-on-error'], `${file} job ${jobName}: guard is soft`).toBeUndefined();
        expect(guard.if, `${file} job ${jobName}: guard is conditional`).toBeUndefined();
      }
    }
    // Non-vacuity: the four installs the criterion names (test-matrix `test`,
    // ml-dsa-bench `bench`, noble-drift `enforce-bench`, release `build`)
    // must all have been swept.
    expect(guardedInstalls).toBeGreaterThanOrEqual(4);
  });

  it('HMA-40.AC4 the release build job installs with npm ci --ignore-scripts', () => {
    expect(executableLines(runs(jobs.build))).toMatch(/(^|\s)npm ci --ignore-scripts(\s|$)/);
  });

  it('HMA-40.AC4 the delivered tree tracks no package-manager config: the guard grep prints nothing', () => {
    // gitFreeEnv(): under this project's pre-push hook git exports GIT_DIR,
    // and an inherited one would redirect this listing (#348).
    const tracked = execFileSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8', env: gitFreeEnv() })
      .split('\n')
      .filter(Boolean);
    const re = new RegExp(PM_CONFIG_PATTERN);
    expect(tracked.filter((p) => re.test(p))).toEqual([]);
  });

  it('HMA-40.AC4 the guard pipeline goes red on a scratch tree with one tracked .npmrc, and quiet without it', () => {
    // Both polarities, so the row cannot pass against a pipeline that matches
    // nothing (or everything). The fixture repo comes from initThrowawayRepo
    // and every git child gets gitFreeEnv() (#348): the pre-push hook exports
    // GIT_DIR, and a raw git here would silently answer about — or write
    // into — the OUTER repository.
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'hma40-guard-'));
    const env = gitFreeEnv();
    try {
      initThrowawayRepo(scratch);
      fs.writeFileSync(path.join(scratch, 'index.js'), 'module.exports = 1;\n');
      execFileSync('git', ['add', 'index.js'], { cwd: scratch, env });
      const quiet = spawnSync('bash', ['-c', GUARD_COMMAND], { cwd: scratch, env, encoding: 'utf8' });
      expect(quiet.stdout.trim()).toBe('');
      expect(quiet.status).not.toBe(0); // grep found nothing: the guard's if-branch does not fire

      fs.writeFileSync(path.join(scratch, '.npmrc'), 'registry=https://registry.evil.example/\n');
      execFileSync('git', ['add', '.npmrc'], { cwd: scratch, env });
      const red = spawnSync('bash', ['-c', GUARD_COMMAND], { cwd: scratch, env, encoding: 'utf8' });
      expect(red.status).toBe(0); // grep printed: the guard's if-branch fires and fails the job
      expect(red.stdout).toContain('.npmrc');
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });
});

/**
 * The demo-agents walkthrough fixture: five agent projects that the `detect`
 * recording (docs/vhs/detect.tape) is rendered from.
 *
 * Its credential-carrying files are not committed. test-fixtures/demo-agents/
 * templates.json holds each fake value as fragments, and materialize.mjs joins
 * them at run time into a directory outside any git work tree. These cells pin
 * what the built CLI reports on the materialized tree, that a value carrying
 * the FAKE marker is still reported, that the report follows the template it
 * comes from, that the script refuses a target inside a work tree, and that
 * docs/vhs/record-detect.sh with no argument renders from that materialized
 * copy.
 *
 * No cell prints or reads a materialized value: every assertion goes through
 * the scanner's findings, counts and the line numbers of the templates.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { tempDir } from '../helpers/temp-dir';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { gitFreeEnv, initThrowawayRepo } from '../helpers/throwaway-repo';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const FIXTURE_DIR = path.join(REPO_ROOT, 'test-fixtures', 'demo-agents');
const MATERIALIZE = path.join(FIXTURE_DIR, 'materialize.mjs');
const RECORD = path.join(REPO_ROOT, 'docs', 'vhs', 'record-detect.sh');

/** The order `detect` sorts these projects in: severity counts, then governance score. */
const WORST_FIRST = [
  'deploy-runbook-agent',
  'invoice-reconciliation-agent',
  'hr-onboarding-assistant',
  'support-triage-agent',
  'release-notes-agent',
];

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };

/** Variables the clean run removes: provider keys, tokens and the CI switch. */
const UNSET = new Set(['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'GITHUB_TOKEN', 'GH_TOKEN', 'INTERNAL_API_KEY', 'CI']);

function cleanEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const home = tempDir('hma-demo-agents-home-');
  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!UNSET.has(key) && !key.startsWith('GIT_')) env[key] = value;
  }
  return {
    ...env,
    HOME: home,
    OPENA2A_HOME: path.join(home, '.opena2a'),
    HMA_BACKUP_HOME: path.join(home, '.hma-backup'),
    OPENA2A_TELEMETRY: 'off',
    NO_COLOR: '1',
    ...extra,
  };
}

function materialize(target: string, omit: string[] = []) {
  return spawnSync(process.execPath, [MATERIALIZE, target, ...omit.flatMap((p) => ['--omit', p])], {
    encoding: 'utf-8',
    env: cleanEnv(),
    timeout: 60_000,
  });
}

function materialized(omit: string[] = []): string {
  const target = tempDir('hma-demo-agents-');
  const res = materialize(target, omit);
  expect(res.stderr).toBe('');
  expect(res.status).toBe(0);
  expect(res.stdout).toBe(`${target}\n`);
  return target;
}

function runCli(args: string[], cwd: string, extra: Record<string, string> = {}) {
  return spawnSync(process.execPath, [BUILT_CLI, ...args], {
    cwd,
    encoding: 'utf-8',
    env: cleanEnv(extra),
    timeout: 170_000,
  });
}

/**
 * A directory holding a `ps` that lists no process, to put first on PATH.
 * `detect` fills each project's agents list from `ps aux` and the machine-wide
 * tool configs under HOME before it reads the project's own config files; with
 * this stub and the scratch HOME, the list holds only what the project's own
 * files evidence, which is what a clean CI runner reports.
 */
function noProcessPath(): string {
  const dir = tempDir('hma-demo-agents-ps-');
  fs.writeFileSync(
    path.join(dir, 'ps'),
    '#!/bin/sh\necho "USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND"\n',
    { mode: 0o755 },
  );
  return `${dir}${path.delimiter}${process.env.PATH ?? ''}`;
}

interface DetectProject {
  scanDirectory: string;
  findings: { severity: string; title: string }[];
  aiConfigs: { file: string; risk: string }[];
  agents: { name: string; source: string; governanceStatus: string }[];
  identity: { governanceFile: string | null };
  summary: { governanceScore: number; ungoverned: number };
}

interface Row {
  name: string;
  verdict: string;
  cred: boolean;
  gov: number;
  project: DetectProject;
}

/** The per-project rows, computed the way the workspace table computes them. */
function detectRows(root: string, extra: Record<string, string> = {}): { exit: number | null; projectsNeedingAction: number; projects: number; rows: Row[] } {
  const res = runCli(['detect', root, '--json', '--no-contribute'], root, extra);
  const report = JSON.parse(res.stdout) as {
    summary: { projects: number; projectsNeedingAction: number };
    projects: DetectProject[];
  };
  const rows = report.projects.map((project) => {
    const worst = project.findings.reduce((w, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[w] ? f.severity : w), 'ok');
    return {
      name: path.basename(project.scanDirectory),
      verdict: worst,
      cred: project.aiConfigs.some((cfg) => cfg.risk === 'critical'),
      gov: project.summary.governanceScore,
      project,
    };
  });
  return { exit: res.status, projectsNeedingAction: report.summary.projectsNeedingAction, projects: report.summary.projects, rows };
}

/** 1-based line of the template line that carries `{{value}}`. */
function templateLine(file: string, value: string): number {
  const data = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, 'templates.json'), 'utf-8')) as {
    files: { path: string; lines: string[] }[];
  };
  const template = data.files.find((f) => f.path === file);
  if (!template) throw new Error(`no template ${file}`);
  const index = template.lines.findIndex((line) => line.includes(`{{${value}}}`));
  if (index === -1) throw new Error(`${file} does not carry {{${value}}}`);
  return index + 1;
}

/**
 * A copy, under `dir`, of what docs/vhs/record-detect.sh reads on the host:
 * the scripts, tapes and sidecars in docs/vhs, package.json and this fixture.
 * The fixture is committed in a throwaway repository, as the script names it
 * by the commit that last changed it. The commit runs with a scratch HOME and
 * no system configuration, so no global git setting or hook takes part.
 */
function renderCopy(dir: string): string {
  const repo = path.join(dir, 'repo');
  const copy = (rel: string) => fs.cpSync(path.join(REPO_ROOT, rel), path.join(repo, rel), { recursive: true });
  for (const name of fs.readdirSync(path.join(REPO_ROOT, 'docs', 'vhs'))) {
    if (/\.(sh|mjs|tape|json)$/.test(name)) copy(`docs/vhs/${name}`);
  }
  copy('package.json');
  copy(path.relative(REPO_ROOT, FIXTURE_DIR));
  initThrowawayRepo(repo);
  const git = (...args: string[]) => spawnSync('git', ['-C', repo, ...args], {
    env: { ...gitFreeEnv(), HOME: dir, GIT_CONFIG_NOSYSTEM: '1' }, encoding: 'utf-8',
  });
  expect(git('add', '--', path.relative(REPO_ROOT, FIXTURE_DIR)).status).toBe(0);
  expect(git('commit', '-q', '--no-verify', '-m', 'fixture').status).toBe(0);
  return repo;
}

let fixtureRoot = '';
let baseline: ReturnType<typeof detectRows>;

beforeAll(() => {
  assertDistFresh();
  fixtureRoot = materialized();
  baseline = detectRows(fixtureRoot);
});

describe('demo-agents fixture', () => {
  it('(a) detect on the materialized fixture: five projects worst first, 4 of 5 need action, release-notes-agent governed (per-project rows only; detect has no option that leaves out machine-wide discovery)', () => {
    expect(baseline.projects).toBe(5);
    expect(baseline.rows.map((r) => r.name)).toEqual(WORST_FIRST);
    expect(baseline.rows.map((r) => r.verdict)).toEqual(['critical', 'critical', 'critical', 'high', 'medium']);
    for (let i = 1; i < baseline.rows.length; i++) {
      expect(SEVERITY_RANK[baseline.rows[i].verdict]).toBeLessThanOrEqual(SEVERITY_RANK[baseline.rows[i - 1].verdict]);
    }
    expect(baseline.projectsNeedingAction).toBe(4);
    expect(baseline.exit).toBe(1);
    expect(baseline.rows.map((r) => r.cred)).toEqual([true, true, true, false, false]);

    const governed = baseline.rows[4].project;
    expect(governed.identity.governanceFile).toBe('SOUL.md');
    expect(governed.summary.governanceScore).toBe(100);
    expect(governed.summary.ungoverned).toBe(0);
    // release-notes-agent has none of the tool config files `detect` reads
    // (.cursorrules, CLAUDE.md, .claude/settings.json and their peers), so its
    // own files put no agent on the list. Whatever the list holds came from
    // this machine (a running agent process or a tool config under HOME) and
    // is judged against this project's SOUL.md: governed. On a machine running
    // no agent process the list is empty; cell (f) pins that case.
    expect(governed.aiConfigs).toEqual([]);
    expect(governed.agents.every((a) => a.governanceStatus === 'governed')).toBe(true);
  });

  it('(f) with a ps that lists no process, each row holds only the agents its own files evidence: release-notes-agent none, still governed 100/100', () => {
    const quiet = detectRows(fixtureRoot, { PATH: noProcessPath() });
    expect(quiet.projects).toBe(5);
    expect(quiet.rows.map((r) => [r.name, r.verdict, r.cred])).toEqual(baseline.rows.map((r) => [r.name, r.verdict, r.cred]));
    expect(quiet.projectsNeedingAction).toBe(4);
    expect(quiet.exit).toBe(1);

    const agentsOf = (name: string) => quiet.rows.find((r) => r.name === name)!.project.agents.map((a) => [a.name, a.source, a.governanceStatus]);
    expect(agentsOf('deploy-runbook-agent')).toEqual([['Claude Code', '.claude/settings.json', 'no governance']]);
    expect(agentsOf('invoice-reconciliation-agent')).toEqual([['Claude Code', '.claude/settings.json', 'no governance']]);
    expect(agentsOf('hr-onboarding-assistant')).toEqual([['Cursor', '.cursorrules', 'no governance']]);
    expect(agentsOf('support-triage-agent')).toEqual([]);
    expect(agentsOf('release-notes-agent')).toEqual([]);

    const governed = quiet.rows[4].project;
    expect(governed.identity.governanceFile).toBe('SOUL.md');
    expect(governed.summary.governanceScore).toBe(100);
    expect(governed.summary.ungoverned).toBe(0);
    expect(governed.aiConfigs).toEqual([]);
  });

  it('(b) secure reports a credential finding on each value line the rows name, FAKE marker included, and none for release-notes-agent', () => {
    // [project, file, template value]; the QuickBooks token in the skill is not detected yet and is not listed.
    const expected: [string, string, string][] = [
      ['deploy-runbook-agent', '.claude/settings.json', 'deployAnthropicKey'],
      ['deploy-runbook-agent', '.mcp.json', 'deployGithubToken'],
      ['hr-onboarding-assistant', '.cursorrules', 'hrOpenaiKey'],
      ['hr-onboarding-assistant', 'mcp.json', 'hrSlackToken'],
      ['invoice-reconciliation-agent', 'CLAUDE.md', 'invoiceAnthropicKey'],
      ['invoice-reconciliation-agent', '.mcp.json', 'invoiceDbPassword'],
      ['invoice-reconciliation-agent', '.mcp.json', 'invoiceSlackToken'],
      ['invoice-reconciliation-agent', '.env', 'invoiceDbPassword'],
      ['invoice-reconciliation-agent', '.env', 'invoiceSlackToken'],
      ['support-triage-agent', '.mcp.json', 'supportZendeskToken'],
    ];
    const isCredential = (checkId: string) => /(^|-)CRED-\d+$/.test(checkId);
    const findingsOf = new Map<string, { checkId: string; file?: string; line?: number }[]>();
    for (const project of WORST_FIRST) {
      const res = runCli(['secure', path.join(fixtureRoot, project), '--json', '--no-contribute'], fixtureRoot);
      const report = JSON.parse(res.stdout) as { findings: { checkId: string; file?: string; line?: number }[] };
      findingsOf.set(project, report.findings);
    }

    const missing: string[] = [];
    for (const [project, file, value] of expected) {
      const line = templateLine(`${project}/${file}`, value);
      const hit = findingsOf.get(project)!.some((f) => isCredential(f.checkId) && f.file === file && f.line === line);
      if (!hit) missing.push(`${project}/${file}:${line} (${value})`);
    }
    expect(missing).toEqual([]);

    // The env file of invoice-reconciliation-agent is not ignored and holds secrets.
    expect(findingsOf.get('invoice-reconciliation-agent')!.some((f) => f.checkId === 'GIT-003' && f.file === '.env')).toBe(true);

    expect(findingsOf.get('release-notes-agent')!.filter((f) => isCredential(f.checkId))).toEqual([]);
  });

  it('(c) omitting the .cursorrules template changes the hr-onboarding-assistant row: credential cell and verdict', () => {
    const omittedRoot = materialized(['hr-onboarding-assistant/.cursorrules']);
    expect(fs.existsSync(path.join(omittedRoot, 'hr-onboarding-assistant', '.cursorrules'))).toBe(false);
    const omitted = detectRows(omittedRoot);

    const before = baseline.rows.find((r) => r.name === 'hr-onboarding-assistant')!;
    const after = omitted.rows.find((r) => r.name === 'hr-onboarding-assistant')!;
    expect({ cred: before.cred, verdict: before.verdict }).toEqual({ cred: true, verdict: 'critical' });
    expect(after.cred).toBe(false);
    expect(after.verdict).not.toBe('critical');
    expect(after.project.findings.map((f) => f.title)).not.toContain('AI config files contain credential references');
    expect(before.project.findings.map((f) => f.title)).toContain('AI config files contain credential references');

    // The other four rows are unchanged.
    const others = (rows: Row[]) =>
      rows.filter((r) => r.name !== 'hr-onboarding-assistant').map((r) => [r.name, r.verdict, r.cred]);
    expect(others(omitted.rows)).toEqual(others(baseline.rows));
  });

  it('(d) materialize.mjs refuses a target inside this work tree: exit 2 and nothing written', () => {
    const inside = path.join(FIXTURE_DIR, 'materialized-here');
    const before = fs.readdirSync(FIXTURE_DIR).sort();
    const res = materialize(inside);
    expect(res.status).toBe(2);
    expect(res.stdout).toBe('');
    expect(res.stderr).toContain('inside a git work tree');
    expect(fs.existsSync(inside)).toBe(false);

    // With no target, a temporary directory that lies inside a work tree is refused the same way.
    const noTarget = spawnSync(process.execPath, [MATERIALIZE], {
      encoding: 'utf-8',
      env: cleanEnv({ TMPDIR: FIXTURE_DIR }),
      timeout: 60_000,
    });
    expect(noTarget.status).toBe(2);
    expect(noTarget.stdout).toBe('');
    expect(noTarget.stderr).toContain('inside a git work tree');
    expect(fs.readdirSync(FIXTURE_DIR).sort()).toEqual(before);

    // A target outside any work tree that already holds files is refused too.
    const occupied = tempDir('hma-demo-agents-occupied-');
    fs.writeFileSync(path.join(occupied, 'keep.txt'), 'keep\n');
    const full = materialize(occupied);
    expect(full.status).toBe(2);
    expect(fs.readdirSync(occupied)).toEqual(['keep.txt']);
  });

  it('(e) record-detect.sh with no argument renders from a materialized copy outside every work tree', () => {
    const stubDir = tempDir('hma-demo-agents-docker-');
    const stub = path.join(stubDir, 'docker');
    const out = path.join(stubDir, 'run.json');
    // The render writes its sidecar into docs/vhs, so it runs in a copy, never in this checkout.
    const repo = renderCopy(stubDir);
    const committedSidecar = fs.readFileSync(path.join(REPO_ROOT, 'docs', 'vhs', 'detect.json'));
    fs.writeFileSync(
      stub,
      [
        '#!/usr/bin/env node',
        "const fs = require('node:fs');",
        "const path = require('node:path');",
        "const { spawnSync } = require('node:child_process');",
        'const args = process.argv.slice(2);',
        "if (args[0] === 'image' && args[1] === 'inspect') process.exit(0);",
        "if (args[0] !== 'run') process.exit(3);",
        "const mountOf = (suffix) => { const m = args.find((a, i) => args[i - 1] === '-v' && a.endsWith(suffix)); return m ? m.slice(0, -suffix.length) : null; };",
        "const source = mountOf(':/work/fixture:ro');",
        "const probe = source ? spawnSync('git', ['-C', source, 'rev-parse', '--is-inside-work-tree'], { encoding: 'utf8' }) : null;",
        'const list = (dir) => fs.readdirSync(dir, { withFileTypes: true })',
        '  .flatMap((e) => (e.isDirectory() ? list(path.join(dir, e.name)).map((f) => `${e.name}/${f}`) : [e.name]));',
        'fs.writeFileSync(process.env.STUB_OUT, JSON.stringify({',
        '  argv: args,',
        '  source,',
        "  insideWorkTree: probe ? probe.status === 0 && probe.stdout.trim() === 'true' : null,",
        '  files: source ? list(source).sort() : [],',
        '}));',
        // What the container writes for the host to read: the sidecar, with a measured wall clock and no metered cost.
        "const sidecar = path.join(mountOf(':/work/docs/vhs'), 'detect.json');",
        "const written = { ...JSON.parse(fs.readFileSync(sidecar, 'utf8')), wallClockSeconds: 1, meteredCostUsd: 0 };",
        'fs.writeFileSync(sidecar, JSON.stringify(written, null, 2));',
        '',
      ].join('\n'),
      { mode: 0o755 },
    );
    // npm answers `view` as the registry does for a published version, so the render reads no network.
    const bin = path.join(stubDir, 'bin');
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, 'npm'), '#!/bin/sh\nif [ "$1" = view ]; then echo sha512-FAKE; exit 0; fi\nexit 1\n', { mode: 0o755 });
    const tmp = tempDir('hma-demo-agents-tmp-');
    const res = spawnSync('bash', [path.join(repo, path.relative(REPO_ROOT, RECORD))], {
      cwd: repo,
      encoding: 'utf-8',
      env: cleanEnv({ DOCKER: stub, STUB_OUT: out, TMPDIR: tmp, PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}` }),
      timeout: 120_000,
    });
    expect(res.stderr).toBe('');
    expect(res.status).toBe(0);
    // The render ends with the sidecar line of the sidecar the container wrote, and this checkout's is untouched.
    expect(res.stdout.trimEnd().split('\n').at(-1)).toMatch(/^sidecar docs\/vhs\/detect\.json sha256 [0-9a-f]{64}: hackmyagent /);
    expect(fs.readFileSync(path.join(REPO_ROOT, 'docs', 'vhs', 'detect.json'))).toEqual(committedSidecar);

    const run = JSON.parse(fs.readFileSync(out, 'utf-8')) as {
      argv: string[];
      source: string | null;
      insideWorkTree: boolean | null;
      files: string[];
    };
    expect(run.source).not.toBeNull();
    expect(path.dirname(run.source!)).toBe(tmp);
    expect(run.insideWorkTree).toBe(false);
    const projects = [...new Set(run.files.map((f) => f.split('/')[0]).filter((f) => !f.startsWith('.')))].sort();
    expect(projects).toEqual([...WORST_FIRST].sort());
    for (const project of WORST_FIRST) {
      expect(run.files.filter((f) => f.startsWith(`${project}/`)).length).toBeGreaterThan(3);
    }
    expect(run.files).toContain('hr-onboarding-assistant/.cursorrules');
    expect(run.argv).toContain('FIXTURE_NAME=test-fixtures/demo-agents');
    expect(run.argv).toContain('HMA_INTEGRITY=sha512-FAKE');
    // The materialized copy is removed when the script exits.
    expect(fs.existsSync(run.source!)).toBe(false);
  });
});

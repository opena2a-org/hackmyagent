/**
 * A recorded walkthrough is four files that have to agree: the tape it is
 * rendered from, the GIF, a text capture of the same commands, and a sidecar
 * that says which build ran, on which fixture, and how large the outputs are.
 * This suite holds them to each other and to the repository:
 *
 *  - the sidecar names the version in package.json, so a release that does not
 *    re-render the recording fails here;
 *  - the lines the tape types on screen are the sidecar's `commands`, in
 *    order, and the commands the text capture ran;
 *  - the tape, the fixture script and the outputs on disk are the ones the
 *    sidecar hashed, so an edit after the render fails here;
 *  - the tape, the capture and the README line carry no home-directory path,
 *    and the README line no version and no date: those live in the sidecar.
 *
 * It also holds the render scripts: each refuses to start when a metered key
 * is set, both render the version in package.json (or a version passed to
 * them) and stop when npm does not answer for it, `--dry-run` prints what a
 * render would use and write, then exits 0
 * with docs/vhs as it was, and a render ends with the sidecar line (the
 * sidecar's path, sha256, build, wall clock and metered cost) or exits 1 when
 * the sidecar carries no measured wall clock or a cost other than 0. The
 * release checklist re-renders each pinned recording with the command its tape
 * names and records that line.
 *
 * Re-render with the script the README line names; the sidecar is written by
 * the render, never by hand.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, rmdirSync, statSync, writeFileSync } from 'node:fs';
import * as path from 'node:path';
import { parseTape } from '../helpers/tape';
import { tempDir } from '../helpers/temp-dir';
import { gitFreeEnv, initThrowawayRepo } from '../helpers/throwaway-repo';

const REPO_ROOT = path.join(__dirname, '..', '..');
const at = (rel: string): string => path.join(REPO_ROOT, rel);
const text = (rel: string): string => readFileSync(at(rel), 'utf8');
const sha256 = (rel: string): string => createHash('sha256').update(readFileSync(at(rel))).digest('hex');
const PACKAGE = JSON.parse(text('package.json')) as { version: string };
const README_LINES = text('README.md').split('\n');

/** The sidecars this suite pins. */
const SIDECARS = ['docs/vhs/secure.json'];

/**
 * Sidecars it does not pin, each with its reason. An entry holds only while
 * the sidecar still names the version recorded here: a re-render changes it,
 * and the entry then fails until the sidecar is moved to SIDECARS.
 */
const NOT_PINNED = [
  { path: 'docs/vhs/detect.json', version: '0.33.0', reason: 'recorded at 0.33.0, re-render is a separate item' },
];

const REQUIRED_KEYS = [
  'tape', 'tapeSha256', 'commands', 'tool', 'version', 'ranAtUtc', 'fixture', 'fixtureSha',
  'fixtureUncommittedChanges', 'fixturePath', 'hostname', 'columns', 'rows', 'framerate', 'gifsicle', 'gifFrames',
  'gifFullScreenFrames', 'renderedPixelSize', 'outputs', 'durationSeconds', 'wallClockSeconds', 'meteredCostUsd',
  'vhsPatchSha256', 'edits',
];
const EDITS = ['setup not shown', 'waits shortened', 'hard cuts and labelled skips'];
const BUDGET = { recordingSeconds: 60, gifBytes: 3_000_000, mp4Bytes: 1_500_000 };

// Built from fragments so that no line of this file is itself a line the
// repository's own word gates report.
const HOME_PATHS = new RegExp(['/Us' + 'ers/', '/ho' + 'me/', '~/', '\\[CH' + 'IEF-', 'phase [0-9]'].join('|'));
const VERSION_OR_DATE = /[0-9]+\.[0-9]+\.[0-9]+|20[0-9]{2}-[0-9]{2}-[0-9]{2}/;

interface FileRecord { path: string; bytes: number; sha256: string }
interface Sidecar {
  tape: string; tapeSha256: string; commands: string[]; tool: string; version: string;
  npmIntegrity?: string; packedFromCommit?: string; fixtureSha: string; fixtureUncommittedChanges: number;
  hostname: string; columns: number; rows: number; framerate: number; durationSeconds: number;
  wallClockSeconds: number; meteredCostUsd: number; vhsPatchSha256: string; edits: string[];
  outputs: { gif: FileRecord; mp4: FileRecord; frames: FileRecord[]; capture: string };
}

/** Every JSON file under docs/ that names a tape: the sidecars that exist. */
function sidecarsOnDisk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(at(dir)).sort()) {
    const rel = `${dir}/${name}`;
    if (statSync(at(rel)).isDirectory()) out.push(...sidecarsOnDisk(rel));
    else if (name.endsWith('.json')) {
      try {
        const parsed = JSON.parse(text(rel)) as { tape?: unknown };
        if (typeof parsed.tape === 'string' && parsed.tape.endsWith('.tape')) out.push(rel);
      } catch {
        // Not a JSON document, so not a sidecar.
      }
    }
  }
  return out;
}

/** The README line that links a recording. */
function readmeLines(gif: string): string[] {
  return README_LINES.filter((line) => line.includes(`](${gif})`));
}

describe('recording sidecars', () => {
  it('every sidecar under docs/ is pinned here or listed with the reason it is not', () => {
    expect(sidecarsOnDisk('docs').sort()).toEqual([...SIDECARS, ...NOT_PINNED.map((e) => e.path)].sort());
    for (const entry of NOT_PINNED) {
      expect(entry.reason.length).toBeGreaterThan(0);
      const version = (JSON.parse(text(entry.path)) as { version: string }).version;
      expect(version, `${entry.path} was re-rendered: move it to SIDECARS`).toBe(entry.version);
      expect(version).not.toBe(PACKAGE.version);
    }
  });

  describe.each(SIDECARS)('%s', (sidecarPath) => {
    const sidecar = JSON.parse(text(sidecarPath)) as Sidecar;
    const tape = parseTape(text(sidecar.tape));
    const capture = text(sidecar.outputs.capture);

    it('names the version in package.json', () => {
      expect(sidecar.version, `${sidecarPath} was recorded with another version: re-render the recording`).toBe(PACKAGE.version);
    });

    it('carries every provenance key, and names the build by its npm integrity or by the commit it was packed from', () => {
      for (const key of REQUIRED_KEYS) expect(sidecar, `missing ${key}`).toHaveProperty(key);
      expect([sidecar.npmIntegrity, sidecar.packedFromCommit].filter((v) => v !== undefined)).toHaveLength(1);
      if (sidecar.npmIntegrity !== undefined) expect(sidecar.npmIntegrity).toMatch(/^sha512-[A-Za-z0-9+/]+=*$/);
      if (sidecar.packedFromCommit !== undefined) expect(sidecar.packedFromCommit).toMatch(/^[0-9a-f]{40}$/);
      expect(sidecar.vhsPatchSha256).toBe(sha256('docs/vhs/docker/vhs-0.12.0-render-context.patch'));
      expect(sidecar.meteredCostUsd).toBe(0);
    });

    it('the lines the tape types on screen are the sidecar commands, in order, and the commands the capture ran', () => {
      expect(tape.typed.length).toBeGreaterThan(0);
      expect(tape.typed).toEqual(sidecar.commands);
      expect(capture.split('\n').filter((line) => line.startsWith('$ ')).map((line) => line.slice(2))).toEqual(sidecar.commands);
    });

    it('the tape types only commands of the tool, and requires every binary it types', () => {
      for (const line of tape.typed) {
        expect(line, 'a tape types commands, never a sentence or a comment').toMatch(new RegExp(`^(npx )?${sidecar.tool} \\S`));
        expect(line, 'a typed command is not trimmed or piped').not.toMatch(/[|;&<>]/);
        for (const binary of line.startsWith('npx ') ? ['npx', sidecar.tool] : [sidecar.tool]) {
          expect(tape.requires, `no Require line for ${binary}`).toContain(binary);
        }
      }
    });

    it('the tape, the fixture script and the outputs on disk are the ones the sidecar hashed', () => {
      expect(sidecar.tapeSha256).toBe(sha256(sidecar.tape));
      expect(sidecar.fixtureSha).toBe(sha256('docs/vhs/setup-lab.sh'));
      expect(sidecar.fixtureUncommittedChanges).toBe(0);
      for (const file of [sidecar.outputs.gif, ...sidecar.outputs.frames]) {
        expect(statSync(at(file.path)).size, file.path).toBe(file.bytes);
        expect(sha256(file.path), file.path).toBe(file.sha256);
      }
      expect(tape.outputs).toContain(sidecar.outputs.gif.path);
      expect(tape.outputs).toContain(sidecar.outputs.mp4.path);
      expect(sidecar.outputs.frames.map((f) => f.path)).toEqual(tape.screenshots);
    });

    it('each top-level hash is the sha256 of the file it names, and the sidecar carries no other', () => {
      const hashed: Record<string, string> = {
        tapeSha256: sidecar.tape,
        fixtureSha: 'docs/vhs/setup-lab.sh',
        vhsPatchSha256: 'docs/vhs/docker/vhs-0.12.0-render-context.patch',
      };
      const record = sidecar as unknown as Record<string, unknown>;
      expect(Object.keys(record).filter((key) => /Sha(256)?$/.test(key)).sort()).toEqual(Object.keys(hashed).sort());
      for (const [key, file] of Object.entries(hashed)) expect(record[key], key).toBe(sha256(file));
    });

    it('was rendered at 120 columns by 40 rows, 10 frames a second, on a host named laptop', () => {
      expect([tape.settings.get('Columns'), tape.settings.get('Rows'), tape.settings.get('Framerate')]).toEqual(['120', '40', '10']);
      expect([sidecar.columns, sidecar.rows, sidecar.framerate]).toEqual([120, 40, 10]);
      expect(sidecar.hostname).toBe('laptop');
    });

    it('stays inside the recording budgets', () => {
      expect(sidecar.durationSeconds).toBeGreaterThan(0);
      expect(sidecar.durationSeconds).toBeLessThanOrEqual(BUDGET.recordingSeconds);
      expect(sidecar.wallClockSeconds).toBeLessThanOrEqual(BUDGET.recordingSeconds);
      expect(sidecar.outputs.gif.bytes).toBeLessThanOrEqual(BUDGET.gifBytes);
      expect(sidecar.outputs.mp4.bytes).toBeLessThanOrEqual(BUDGET.mp4Bytes);
    });

    it('declares its edits from the closed set, and the hidden setup when the tape has one', () => {
      for (const edit of sidecar.edits) expect(EDITS).toContain(edit);
      expect(sidecar.edits.includes('setup not shown')).toBe(tape.hidden.length > 0);
    });

    it('the MP4 is written where git does not track it', () => {
      expect(sidecar.outputs.mp4.path.startsWith('docs/vhs/out/')).toBe(true);
      expect(text('.gitignore').split('\n')).toContain('docs/vhs/out/');
    });

    it('the tape and the capture carry no home-directory path', () => {
      expect(text(sidecar.tape)).not.toMatch(HOME_PATHS);
      expect(capture).not.toMatch(HOME_PATHS);
    });

    it('the README links the recording on one line, with no embed, no version, no date and no home-directory path', () => {
      const gif = sidecar.outputs.gif.path;
      const lines = readmeLines(gif);
      expect(lines).toHaveLength(1);
      const [line] = lines;
      expect(line.startsWith(`- [${sidecar.tool} `)).toBe(true);
      expect(line).not.toContain(`![`);
      expect(line).toContain(`](${sidecar.outputs.capture})`);
      expect(line).toContain(`](${sidecarPath})`);
      expect(line).not.toMatch(HOME_PATHS);
      expect(line).not.toMatch(VERSION_OR_DATE);
    });
  });

});

/** Prints the one-line record of a sidecar; each render script ends with it. */
const SIDECAR_LINE = 'docs/vhs/sidecar-line.mjs';

/**
 * The render scripts, with the tape each renders, the files it writes beside
 * the tape's own outputs, the image a dry run names (the one of the version in
 * package.json, which npm has here), and the arguments that come before the
 * tool version: record-secure.sh takes a tape name there, record-detect.sh a
 * fixture checkout.
 */
const RENDER_SCRIPTS = [
  {
    script: 'docs/vhs/record-secure.sh', tape: 'docs/vhs/secure.tape', capture: 'docs/vhs/secure-capture.txt',
    sidecar: 'docs/vhs/secure.json', image: `hma-vhs:${PACKAGE.version}`, takesFixture: false,
  },
  {
    script: 'docs/vhs/record-detect.sh', tape: 'docs/vhs/detect.tape', capture: 'docs/vhs/detect-capture.txt',
    sidecar: 'docs/vhs/detect.json', image: `hma-vhs:${PACKAGE.version}`, takesFixture: true,
  },
];

/** How the npm stand-in answers `view`: with an integrity, with E404, or not at all. */
type NpmView = 'published' | 'not-published' | 'no-answer';
const NPM_VIEW: Record<NpmView, string> = {
  published: 'echo sha512-FAKE; exit 0',
  'not-published': 'echo "npm error code E404" >&2; exit 1',
  'no-answer': 'echo "npm error code ECONNREFUSED" >&2; exit 1',
};

/** Every path under `rel` with its size and modification time, so a write anywhere below it shows. */
function treeState(rel: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(at(rel)).sort()) {
    const child = `${rel}/${name}`;
    const st = statSync(at(child));
    out.push(`${child} ${st.size} ${st.mtimeMs}`);
    if (st.isDirectory()) out.push(...treeState(child));
  }
  return out;
}

/**
 * A scratch directory with stand-ins for docker and npm that append each call
 * to a log. docker answers every call with `dockerStatus`: 1 by default, so an
 * image is never present and a build or a run fails the script; with 0 the
 * image is present and a run succeeds without writing anything. npm answers
 * `view` as `npmView` says (with an integrity by default) and every other call
 * with exit 1. The directory is removed when the test that made it finishes.
 */
function stubs(dockerStatus = 1, npmView: NpmView = 'published'): { dir: string; log: string; env: Record<string, string> } {
  const dir = tempDir('hma-render-');
  const bin = path.join(dir, 'bin');
  const log = path.join(dir, 'calls.log');
  mkdirSync(bin);
  writeFileSync(path.join(bin, 'docker'), `#!/bin/sh\necho "docker $*" >> "$STUB_LOG"\nexit ${dockerStatus}\n`);
  writeFileSync(
    path.join(bin, 'npm'),
    `#!/bin/sh\nif [ "$1" = view ]; then ${NPM_VIEW[npmView]}; fi\necho "npm $*" >> "$STUB_LOG"\nexit 1\n`,
  );
  chmodSync(path.join(bin, 'docker'), 0o755);
  chmodSync(path.join(bin, 'npm'), 0o755);
  writeFileSync(log, '');
  const env = {
    PATH: [bin, path.dirname(process.execPath), '/usr/bin', '/bin'].join(':'),
    HOME: dir,
    TMPDIR: dir,
    DOCKER: path.join(bin, 'docker'),
    STUB_LOG: log,
    GIT_CEILING_DIRECTORIES: path.dirname(dir),
  };
  return { dir, log, env };
}

/**
 * A fixture checkout with one commit; returns its path and short commit. The
 * commit runs with the stubs' HOME, so no global git configuration or hook
 * takes part.
 */
function fixtureCheckout(dir: string, env: Record<string, string>): { path: string; sha: string } {
  const fixture = path.join(dir, 'fixture');
  mkdirSync(fixture);
  initThrowawayRepo(fixture);
  const git = (...args: string[]) => spawnSync('git', ['-C', fixture, ...args], {
    env: { ...gitFreeEnv(), HOME: env.HOME, GIT_CONFIG_NOSYSTEM: '1' }, encoding: 'utf8',
  });
  expect(git('commit', '-q', '--no-verify', '--allow-empty', '-m', 'fixture').status).toBe(0);
  return { path: fixture, sha: git('rev-parse', '--short', 'HEAD').stdout.trim() };
}

describe.each(RENDER_SCRIPTS)('$script', (entry) => {
  it('refuses to start when a metered key is set, dry run or not, and writes nothing', () => {
    const script = at(entry.script);
    expect(existsSync(script)).toBe(true);
    const before = sha256(entry.sidecar);
    for (const args of [[], ['--dry-run']]) {
      for (const name of ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY']) {
        for (const value of ['set', '']) {
          // No docker and no node on this PATH: were the refusal ever removed, the
          // script would stop at its first external command instead of rendering.
          const run = spawnSync('/bin/bash', [script, ...args], { env: { PATH: '/nonexistent', DOCKER: 'false', [name]: value }, encoding: 'utf8' });
          expect(run.status, `${[...args, `${name}=${JSON.stringify(value)}`].join(' ')}`).toBe(2);
          expect(run.stderr).toContain(name);
          expect(run.stdout).toBe('');
        }
      }
    }
    expect(sha256(entry.sidecar)).toBe(before);
  });

  it('--dry-run prints the tape, the image, the outputs, screenshots, capture and sidecar, asks docker only whether the image is present, and leaves docs/vhs as it was', () => {
    const { dir, log, env } = stubs();
    const fixture = entry.takesFixture ? fixtureCheckout(dir, env) : undefined;
    const tape = parseTape(text(entry.tape));
    const before = treeState('docs/vhs');
    const run = spawnSync('/bin/bash', [at(entry.script), '--dry-run', ...(fixture ? [fixture.path] : [])], { env, encoding: 'utf8' });
    expect(run.status, run.stderr).toBe(0);
    for (const written of [entry.tape, ...tape.outputs, ...tape.screenshots, entry.capture, entry.sidecar]) {
      expect(run.stdout, written).toContain(written);
    }
    expect(run.stdout).toContain(entry.image);
    if (fixture) expect(run.stdout).toContain(fixture.sha);
    expect(readFileSync(log, 'utf8').split('\n').filter(Boolean)).toEqual([`docker image inspect ${entry.image}`]);
    expect(treeState('docs/vhs')).toEqual(before);
  });

  /** The arguments before the tool version: the tape name, or a fixture checkout. */
  const leadArgs = (dir: string, env: Record<string, string>): string[] =>
    entry.takesFixture ? [fixtureCheckout(dir, env).path] : [path.basename(entry.tape, '.tape')];
  const name = path.basename(entry.script);

  it('--dry-run names the build it would install: the version in package.json, or the version passed after the other arguments', () => {
    const { dir, log, env } = stubs();
    const lead = leadArgs(dir, env);
    for (const [args, version] of [[lead, PACKAGE.version], [[...lead, '0.33.0'], '0.33.0']] as const) {
      const run = spawnSync('/bin/bash', [at(entry.script), '--dry-run', ...args], { env, encoding: 'utf8' });
      expect(run.status, run.stderr).toBe(0);
      expect(run.stdout).toContain(`\nbuild:   hackmyagent ${version} from npm, integrity sha512-FAKE\n`);
      expect(run.stdout).toContain(`\nimage:   hma-vhs:${version}, `);
    }
    expect(readFileSync(log, 'utf8').split('\n').filter(Boolean)).toEqual([
      `docker image inspect hma-vhs:${PACKAGE.version}`,
      'docker image inspect hma-vhs:0.33.0',
    ]);
  });

  it('refuses a version npm does not have when it is not the one in package.json, before docker or a write', () => {
    const { dir, log, env } = stubs(1, 'not-published');
    const lead = leadArgs(dir, env);
    const before = treeState('docs/vhs');
    for (const args of [['--dry-run', ...lead, '9.9.9'], [...lead, '9.9.9']]) {
      const run = spawnSync('/bin/bash', [at(entry.script), ...args], { env, encoding: 'utf8' });
      expect(run.status, args.join(' ')).toBe(1);
      expect(run.stderr).toContain(
        `${name}: hackmyagent 9.9.9 is not on npm and is not the version in package.json; nothing was rendered.`,
      );
      expect(run.stdout).toBe('');
    }
    expect(readFileSync(log, 'utf8')).toBe('');
    expect(treeState('docs/vhs')).toEqual(before);
  });

  it('stops when npm does not answer whether the build is published, instead of reading that as not published', () => {
    const { dir, log, env } = stubs(1, 'no-answer');
    const lead = leadArgs(dir, env);
    const before = treeState('docs/vhs');
    for (const args of [['--dry-run', ...lead], lead]) {
      const run = spawnSync('/bin/bash', [at(entry.script), ...args], { env, encoding: 'utf8' });
      expect(run.status, args.join(' ')).toBe(1);
      expect(run.stderr).toContain(
        `${name}: npm did not answer whether hackmyagent ${PACKAGE.version} is published; nothing was rendered.`,
      );
      expect(run.stdout).toBe('');
    }
    expect(readFileSync(log, 'utf8')).toBe('');
    expect(treeState('docs/vhs')).toEqual(before);
  });

  it('a render ends, after the container run, with the sidecar line of the sidecar on disk, or exits 1 as that line does', () => {
    // docker has the image and its run writes nothing, so the sidecar on disk is the one the line reads.
    const { dir, log, env } = stubs(0);
    const fixture = entry.takesFixture ? fixtureCheckout(dir, env) : undefined;
    const outDir = 'docs/vhs/out';
    const outExisted = existsSync(at(outDir));
    try {
      const run = spawnSync('/bin/bash', [at(entry.script), ...(fixture ? [fixture.path] : [])], { env, encoding: 'utf8' });
      const direct = spawnSync(process.execPath, [at(SIDECAR_LINE), entry.sidecar], { cwd: REPO_ROOT, encoding: 'utf8' });
      const calls = readFileSync(log, 'utf8').split('\n').filter(Boolean);
      expect(calls[0]).toBe(`docker image inspect ${entry.image}`);
      expect(calls.filter((call) => call.startsWith('docker run '))).toHaveLength(1);
      expect(calls.filter((call) => call.startsWith('docker build '))).toEqual([]);
      expect(run.status, run.stderr).toBe(direct.status);
      expect(run.stdout.trimEnd().split('\n').at(-1)).toBe(direct.stdout.trimEnd());
      expect(run.stderr).toContain(direct.stderr.trim());
    } finally {
      if (!outExisted && existsSync(at(outDir)) && readdirSync(at(outDir)).length === 0) rmdirSync(at(outDir));
    }
  });
});

describe('docs/vhs/sidecar-line.mjs', () => {
  const line = (file: string, cwd = REPO_ROOT) => spawnSync(process.execPath, [at(SIDECAR_LINE), file], { cwd, encoding: 'utf8' });

  it.each(SIDECARS)('prints %s with its sha256, its build, when it was rendered, its wall clock and its metered cost', (sidecarPath) => {
    const sidecar = JSON.parse(text(sidecarPath)) as Sidecar & { ranAtUtc: string };
    const build = sidecar.npmIntegrity !== undefined ? 'from npm' : `packed from ${sidecar.packedFromCommit}`;
    const run = line(sidecarPath);
    expect(run.status, run.stderr).toBe(0);
    expect(run.stdout).toBe(
      `sidecar ${sidecarPath} sha256 ${sha256(sidecarPath)}: ${sidecar.tool} ${sidecar.version} (${build}), ` +
        `rendered ${sidecar.ranAtUtc}, wall clock ${sidecar.wallClockSeconds} s, metered cost $0\n`,
    );
  });

  it.each([
    { name: 'no wallClockSeconds', change: { wallClockSeconds: undefined }, says: 'carries no wallClockSeconds' },
    { name: 'a zero wall clock', change: { wallClockSeconds: 0 }, says: 'has wallClockSeconds 0, not a measured number of seconds' },
    { name: 'a wall clock written as text', change: { wallClockSeconds: '39.8' }, says: 'has wallClockSeconds "39.8", not a measured number of seconds' },
    { name: 'no meteredCostUsd', change: { meteredCostUsd: undefined }, says: 'carries no meteredCostUsd' },
    { name: 'a metered cost', change: { meteredCostUsd: 0.42 }, says: 'has meteredCostUsd 0.42, not 0' },
  ])('exits 1 and prints no line for a sidecar with $name', ({ change, says }) => {
    const dir = tempDir('hma-sidecar-line-');
    const file = path.join(dir, 'walkthrough.json');
    // JSON.stringify drops a key whose value is undefined, which is how a field goes missing here.
    writeFileSync(file, JSON.stringify({ ...JSON.parse(text('docs/vhs/secure.json')), ...change }, null, 2));
    const run = line(file);
    expect(run.status).toBe(1);
    expect(run.stdout).toBe('');
    expect(run.stderr).toContain(`${file} ${says}`);
  });
});

describe('the release checklist', () => {
  const smoke = text('docs/testing/release-smoke.md');

  it.each(SIDECARS)('re-renders %s with the command its tape names, and records its sidecar line', (sidecarPath) => {
    const sidecar = JSON.parse(text(sidecarPath)) as Sidecar;
    const record = text(sidecar.tape).match(/^# Record: (\S.*)$/m);
    expect(record, `${sidecar.tape} names no render command on a "# Record:" line`).not.toBeNull();
    const command = record![1].trim();
    expect(smoke.split('\n').some((l) => l.trim().startsWith(command)), `release-smoke.md does not run ${command}`).toBe(true);
    expect(smoke).toContain(`node ${SIDECAR_LINE} ${sidecarPath}`);
  });
});

describe('docs/vhs/record-detect.sh', () => {
  it('refuses a fixture that is not a git checkout, naming it, since the sidecar names the fixture by its commit', () => {
    const { dir, log, env } = stubs();
    const notCheckout = path.join(dir, 'not-a-checkout');
    mkdirSync(notCheckout);
    for (const args of [['--dry-run', notCheckout], [notCheckout]]) {
      const run = spawnSync('/bin/bash', [at('docs/vhs/record-detect.sh'), ...args], { env, encoding: 'utf8' });
      expect(run.status, args.join(' ')).toBe(1);
      expect(run.stderr).toContain(`${notCheckout} is not a git checkout`);
    }
    expect(readFileSync(log, 'utf8')).toBe('');
  });

  it('--dry-run with no argument names test-fixtures/demo-agents by the commit that last changed it, and materializes nothing', () => {
    const { dir, log, env } = stubs();
    const before = treeState('docs/vhs');
    const run = spawnSync('/bin/bash', [at('docs/vhs/record-detect.sh'), '--dry-run'], { env, encoding: 'utf8' });
    expect(run.status, run.stderr).toBe(0);
    const named = run.stdout.match(/\nfixture: test-fixtures\/demo-agents at commit ([0-9a-f]{7,40}), [0-9]+ uncommitted changes, /);
    expect(named, run.stdout).not.toBeNull();
    const last = spawnSync('git', ['-C', REPO_ROOT, 'log', '-1', '--format=%H', '--', 'test-fixtures/demo-agents'], {
      env: gitFreeEnv(), encoding: 'utf8',
    });
    expect(last.stdout.trim().startsWith(named![1])).toBe(true);
    expect(run.stdout).toContain(`\nbuild:   hackmyagent ${PACKAGE.version} from npm, integrity sha512-FAKE\n`);
    expect(readFileSync(log, 'utf8').split('\n').filter(Boolean)).toEqual([`docker image inspect hma-vhs:${PACKAGE.version}`]);
    // TMPDIR is the stubs' directory: a materialized copy would be a new entry in it.
    expect(readdirSync(dir).sort()).toEqual(['bin', 'calls.log']);
    expect(treeState('docs/vhs')).toEqual(before);
  });
});

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
 * Re-render with the script the README line names; the sidecar is written by
 * the render, never by hand.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import * as path from 'node:path';
import { parseTape } from '../helpers/tape';

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

  it('the render script refuses to start when a metered key is set, and writes nothing', () => {
    const script = at('docs/vhs/record-secure.sh');
    expect(existsSync(script)).toBe(true);
    const before = sha256('docs/vhs/secure.json');
    for (const name of ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY']) {
      for (const value of ['set', '']) {
        // No docker and no node on this PATH: were the refusal ever removed, the
        // script would stop at its first external command instead of rendering.
        const run = spawnSync('/bin/bash', [script], { env: { PATH: '/nonexistent', DOCKER: 'false', [name]: value }, encoding: 'utf8' });
        expect(run.status, `${name}=${JSON.stringify(value)}`).toBe(2);
        expect(run.stderr).toContain(name);
        expect(run.stdout).toBe('');
      }
    }
    expect(sha256('docs/vhs/secure.json')).toBe(before);
  });
});

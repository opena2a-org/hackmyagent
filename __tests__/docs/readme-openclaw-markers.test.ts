/**
 * #985: the OpenClaw and NemoClaw paragraph (in the README then, in
 * docs/commands.md since the README was cut to its reading-load limits) said `secure` detects
 * `.nemoclaw/` and `openclaw.plugin.json` and runs their check groups. Neither
 * marker was read anywhere: a tree holding only `openclaw.plugin.json` scanned
 * as a `library`, and a `~/.nemoclaw` install appeared only under Machine
 * Posture, not scanned.
 *
 * Each rule below runs the built CLI on what that paragraph names, so a marker
 * or home runtime it cites and `secure` does not act on fails here by name.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { assertDistFresh } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFresh);

const ROOT = path.resolve(__dirname, '../..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const PAGE = readFileSync(path.join(ROOT, 'docs', 'commands.md'), 'utf8');

/** The `### OpenClaw and NemoClaw` subsection, up to the next heading. */
function paragraph(): string {
  const start = PAGE.indexOf('\n### OpenClaw and NemoClaw');
  expect(start, 'the OpenClaw and NemoClaw subsection was not found').toBeGreaterThan(-1);
  const rest = PAGE.slice(start + 1);
  const end = rest.slice(1).search(/\n#/);
  return end === -1 ? rest : rest.slice(0, end + 1);
}

const SPANS = [...paragraph().matchAll(/`([^`\n]+)`/g)].map((m) => m[1]);
/** Files and directories the paragraph says make the target an OpenClaw project. */
const TARGET_MARKERS = SPANS.filter((s) => !s.startsWith('~') && !s.includes(' ') && (s.includes('.') || s.endsWith('/')));
/** Home-directory installs the paragraph says are listed under Machine Posture. */
const HOME_RUNTIMES = SPANS.filter((s) => s.startsWith('~/'));

/** A target holding a bare package.json plus, when given, one marker. */
function target(marker?: string): string {
  const dir = tempDir('hma-oc-target-');
  writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 't', version: '1.0.0' }));
  if (marker) {
    const name = marker.replace('*', 'demo');
    if (name.endsWith('/')) mkdirSync(path.join(dir, name.slice(0, -1)));
    else writeFileSync(path.join(dir, name), name.endsWith('.json') ? '{}\n' : '# demo\n');
  }
  return dir;
}

function scan(dir: string, home: string): { projectType: string; machinePosture: Array<{ dir: string }> } {
  const r = spawnSync('node', [CLI, 'secure', dir, '--ci', '--json', '--static-only'], {
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 64 * 1024 * 1024,
    // OPENA2A_CORPUS_DETERMINISTIC disables the machine-posture listing, which
    // would leave the home-runtime rule nothing to compare.
    env: { ...process.env, HOME: home, OPENA2A_CORPUS_DETERMINISTIC: '' },
  });
  return JSON.parse((r.stdout || '').trim());
}

describe('OpenClaw and NemoClaw paragraph of the command reference', () => {
  it('names at least one target marker and one home runtime', () => {
    expect(TARGET_MARKERS.length).toBeGreaterThan(0);
    expect(HOME_RUNTIMES.length).toBeGreaterThan(0);
  });

  it('a target with no marker is not an OpenClaw project, so the rules below are not vacuous', () => {
    expect(scan(target(), tempDir('hma-oc-home-')).projectType).not.toBe('openclaw');
  });

  it.each(TARGET_MARKERS)('a target holding only %s is an OpenClaw project', (marker) => {
    expect(scan(target(marker), tempDir('hma-oc-home-')).projectType).toBe('openclaw');
  }, 120_000);

  it('every home runtime it names is listed under Machine Posture', () => {
    const home = tempDir('hma-oc-home-');
    for (const runtime of HOME_RUNTIMES) mkdirSync(path.join(home, runtime.slice(2)));
    const listed = scan(target(), home).machinePosture.map((e) => e.dir);
    expect([...listed].sort()).toEqual([...HOME_RUNTIMES].sort());
  }, 120_000);
});

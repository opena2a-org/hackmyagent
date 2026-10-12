/**
 * #1046: `--json` output carried C1 and bidi control characters from paths raw.
 *
 * `JSON.stringify` escapes C0 and leaves DEL, C1, the bidi controls and the
 * Unicode line separators as they are, so `secure <dir> --json` on a directory
 * whose name held U+202E or U+009B printed those code points straight to the
 * terminal, in `scanRoot` and in every finding's `file`. Every `--json` emitter
 * now writes them as `\uXXXX` escapes, which a JSON parser reads back as the
 * real bytes.
 *
 * RED-ON-BASE: on 033f4fa1 `escapeJsonDisplayHazards` does not exist, and
 * `secure <dir> --json` on the directory below prints 42 raw hazard code points.
 *
 * Every hazard character in this file is built from its code point: a literal
 * one would be invisible in review.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { escapeJsonDisplayHazards } from '../../src/ui/display-safe';
import { buildJsonStdoutDocument, stringifyJsonOutput } from '../../src/output/json-stdout';

const REPO_ROOT = path.resolve(__dirname, '..', '..');

const cp = (...codes: number[]): string => String.fromCodePoint(...codes);

/** DEL, C1, bidi marks, embeddings, overrides and isolates, the line separators, BOM, and plane 14. */
const RAW_HAZARD = new RegExp(
  '[\\u007f-\\u009f\\u061c\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u206f\\ufeff\\u{e0000}-\\u{effff}]',
  'u',
);

/** A directory name a terminal would act on or render as something else. */
const HAZARD_NAME = 'd' + cp(0x202e) + 'x' + cp(0x85) + 'y' + cp(0x9b) + 'z' + cp(0x2028) + 'w' + cp(0x200f);

function strings(value: unknown, out: string[] = []): string[] {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) for (const v of value) strings(v, out);
  else if (value && typeof value === 'object') for (const v of Object.values(value)) strings(v, out);
  return out;
}

describe('#1046 escapeJsonDisplayHazards', () => {
  it('escapes every hazard code point and round-trips through JSON.parse to the real bytes', () => {
    const value = {
      backupPath: `/tmp/${HAZARD_NAME}/.hackmyagent-backup`,
      findings: [{
        file: 'a' + cp(0x7f) + 'b' + cp(0x2029) + 'c' + cp(0x2066) + 'd' + cp(0x2069)
          + 'e' + cp(0x61c) + 'f' + cp(0xfeff) + 'g' + cp(0xe0041) + 'h',
      }],
      plain: 'ascii only, with a backslash \\ and a quote "',
    };
    const out = escapeJsonDisplayHazards(JSON.stringify(value, null, 2));

    expect(out).not.toMatch(RAW_HAZARD);
    expect(out).toContain('\\u202e');
    expect(out).toContain('\\u0085');
    expect(out).toContain('\\u009b');
    expect(out).toContain('\\u2028');
    expect(out).toContain('\\u007f');
    // An astral code point becomes its surrogate pair, the only form JSON has.
    expect(out).toContain('\\udb40\\udc41');
    expect(JSON.parse(out)).toEqual(value);
  });

  it('keeps the indentation newlines and leaves a hazard-free document byte-identical', () => {
    const value = { scanRoot: '/tmp/project', findings: [{ file: 'src/index.ts', line: 3 }] };
    const json = JSON.stringify(value, null, 2);
    expect(escapeJsonDisplayHazards(json)).toBe(json);
    expect(escapeJsonDisplayHazards(json).split('\n').length).toBeGreaterThan(1);
  });

  it('keeps a pictograph with its presentation selector, as the text display does', () => {
    const json = JSON.stringify({ file: cp(0x2764, 0xfe0f) + '.md' });
    expect(escapeJsonDisplayHazards(json)).toBe(json);
  });
});

describe('#1046 the JSON document builders escape display hazards', () => {
  it('buildJsonStdoutDocument, the chokepoint of every `--json` stdout document', () => {
    const doc = buildJsonStdoutDocument({ backupPath: `/tmp/${HAZARD_NAME}` }, '0.0.0-test');
    expect(doc).not.toMatch(RAW_HAZARD);
    expect(JSON.parse(doc)).toEqual({ hackmyagentVersion: '0.0.0-test', backupPath: `/tmp/${HAZARD_NAME}` });
  });

  it('stringifyJsonOutput, used by the `--output` file and `--format json` arms', () => {
    const json = stringifyJsonOutput({ file: HAZARD_NAME }, 2);
    expect(json).not.toMatch(RAW_HAZARD);
    expect(JSON.parse(json)).toEqual({ file: HAZARD_NAME });
  });
});

describe('#1046 `--json` output from the built CLI', { timeout: 300_000 }, () => {
  beforeAll(assertDistFresh);

  function run(args: string[]) {
    const home = tempDir('hma-1046-home-');
    const r = spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf8',
      timeout: 120_000,
      env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home },
    });
    return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
  }

  /** A scan root holding one MCP fixture under the hazard-named directory. */
  function hazardTree(): { root: string; target: string } {
    const root = fs.realpathSync(tempDir('hma-1046-'));
    const target = path.join(root, HAZARD_NAME);
    fs.cpSync(path.join(REPO_ROOT, 'test-fixtures', 'insecure-mcp'), target, { recursive: true });
    return { root, target };
  }

  /** The findings whose `file`, relative to the scan root, runs through the hazard-named directory. */
  function hazardFindings(doc: { findings?: Array<{ file?: string }> }) {
    return (doc.findings ?? []).filter((f) => typeof f.file === 'string' && f.file.includes(HAZARD_NAME));
  }

  it('RED-ON-BASE: secure --json writes no raw hazard code point and its findings carry the real path', () => {
    const { root } = hazardTree();
    const r = run(['secure', root, '--json', '--no-machine-posture']);

    expect(r.stdout, r.stderr).not.toBe('');
    expect(r.stdout).not.toMatch(RAW_HAZARD);
    expect(r.stdout).toContain('\\u202e');
    expect(hazardFindings(JSON.parse(r.stdout)).length).toBeGreaterThan(0);
  });

  it('secure --json --output writes the same escaped document to the file', () => {
    const { root } = hazardTree();
    const report = path.join(tempDir('hma-1046-out-'), 'report.json');
    run(['secure', root, '--json', '--no-machine-posture', '--output', report]);

    const written = fs.readFileSync(report, 'utf8');
    expect(written).not.toMatch(RAW_HAZARD);
    expect(hazardFindings(JSON.parse(written)).length).toBeGreaterThan(0);
  });

  it('detect --json writes no raw hazard code point', () => {
    const { target } = hazardTree();
    const r = run(['detect', target, '--json', '--depth', '0']);

    expect(r.stdout, r.stderr).not.toBe('');
    expect(r.stdout).not.toMatch(RAW_HAZARD);
    expect(strings(JSON.parse(r.stdout)).some((s) => s.includes(HAZARD_NAME))).toBe(true);
  });
});

/**
 * #353 — a hardcoded-secret finding must not carry the secret it found.
 *
 * Reported on a real scan: `HIGH AST-CRED-003 <path>:93 / Hardcoded secret:
 * API_KEY=SG.<22 chars>.<43 chars>`, the complete key in the finding title on
 * stdout and in `--json`. Masking had covered `evidence`, not the title.
 *
 * The issue asks for the invariant, not a per-field check: on a fixture with a
 * planted credential, NO field of ANY emitted finding holds more than the
 * masked prefix, and the same holds for everything the command prints. A
 * field-by-field assertion regresses the first time a field is added. This
 * suite plants the reported shape (a SendGrid-format key in a markdown
 * deployment note) and walks both output channels of the built CLI.
 *
 * The key is assembled at runtime so no credential-shaped literal sits in the
 * source for a push-protection scanner or for HMA's own self-scan.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const ALPHABET = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';
const segment = (n: number, step: number) =>
  Array.from({ length: n }, (_, i) => ALPHABET[(i * step + 3) % ALPHABET.length]).join('');
const SEG1 = segment(22, 7);
const SEG2 = segment(43, 11);
const KEY = ['SG', SEG1, SEG2].join('.');

// Any run this long from either segment is a leak; the masked form keeps the
// `SG.` prefix and nothing of the segments.
const WINDOW = 6;
function leakedRuns(text: string): string[] {
  const hits: string[] = [];
  for (const seg of [SEG1, SEG2]) {
    for (let i = 0; i + WINDOW <= seg.length; i++) {
      const run = seg.slice(i, i + WINDOW);
      if (text.includes(run)) hits.push(run);
    }
  }
  return hits;
}

/** Every string value anywhere in a JSON value, with its path. */
function strings(value: unknown, at = '$'): Array<[string, string]> {
  if (typeof value === 'string') return [[at, value]];
  if (Array.isArray(value)) return value.flatMap((v, i) => strings(v, `${at}[${i}]`));
  if (value && typeof value === 'object') {
    return Object.entries(value).flatMap(([k, v]) => strings(v, `${at}.${k}`));
  }
  return [];
}

let root: string;
let home: string;
let target: string;

function run(args: string[]) {
  const res = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 240_000,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home },
  });
  return { status: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-353-'));
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-353-home-'));
  target = path.join(root, 'repo');
  fs.mkdirSync(target);
  fs.writeFileSync(path.join(target, 'package.json'), '{"name":"deploy353","version":"1.0.0"}\n');
  fs.writeFileSync(
    path.join(target, 'DEPLOY.md'),
    `# Deploy notes\n\nSet the mail key before deploying:\n\nAPI_KEY=${KEY}\n`,
  );
});

afterAll(() => {
  for (const d of [root, home]) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

describe('#353: a hardcoded-secret finding does not echo the secret', () => {
  it('--json: the finding fires, and no string anywhere in the payload holds a run of the key', () => {
    const res = run(['secure', target, '--json']);
    const body = JSON.parse(res.stdout.slice(res.stdout.indexOf('{')));

    // Not vacuous: the reported check fires on the planted line.
    const hit = (body.findings as Array<Record<string, unknown>>).find(
      (f) => f.checkId === 'AST-CRED-003' && f.file === 'DEPLOY.md',
    );
    expect(hit, 'AST-CRED-003 on DEPLOY.md').toBeDefined();
    expect(hit!.line).toBe(5);

    const leaks = strings(body).filter(([, s]) => leakedRuns(s).length > 0).map(([p]) => p);
    expect(leaks).toEqual([]);
    expect(leakedRuns(res.stderr)).toEqual([]);
  });

  it('text output, default and --verbose: nothing printed holds a run of the key', () => {
    for (const extra of [[], ['--verbose']]) {
      const res = run(['secure', target, ...extra]);
      // Not vacuous: the finding is rendered, located on the planted line.
      expect(res.stdout).toContain('Hardcoded Secret Detected');
      expect(res.stdout).toContain('DEPLOY.md:5');
      expect(leakedRuns(res.stdout + res.stderr)).toEqual([]);
    }
  });
});

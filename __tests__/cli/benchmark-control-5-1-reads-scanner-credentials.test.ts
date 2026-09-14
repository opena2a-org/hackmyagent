/**
 * #739 — OASB-1 control 5.1 consumes the scanner's own plaintext-credential
 * record (CRED-001), so a key in `.claude/settings.json` fails the control
 * and the evidence line names the file and line.
 *
 * Before: 5.1 mapped CRED-002/003/004 and the SEM-CRED checks only. CRED-001,
 * the check that walks every credential-bearing file `secure` reads, was the
 * one credential check NOT in the mapping, so a tree whose only defect is a
 * plaintext API key in `.claude/settings.json` printed
 * `[+] 5.1: No Hardcoded Credentials` and `Credential Protection: 1/1` on the
 * strength of CRED-002's clean "no private key files" record, while the plain
 * `secure` run on the same tree reported the key as CRITICAL.
 *
 * The fixture key is assembled at test time (prefix + repeated filler) so no
 * key-shaped literal sits in a tracked file.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const FLAGS = ['--ci', '-b', 'oasb-1', '--no-machine-posture'];

let tree: string;
let home: string;

beforeAll(() => {
  tree = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-739-'));
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-'));
  fs.mkdirSync(path.join(tree, '.claude'));
  const key = 'sk-ant-api03-' + 'a'.repeat(60);
  fs.writeFileSync(
    path.join(tree, '.claude', 'settings.json'),
    JSON.stringify({ env: { ANTHROPIC_API_KEY: key } }) + '\n',
  );
  // A second credential-bearing file: CRED-001 emits one record per file and
  // the control cites each of them (#668 fold).
  fs.writeFileSync(path.join(tree, '.env'), 'ANTHROPIC_API_KEY=' + 'sk-ant-api03-' + 'b'.repeat(60) + '\n');
});

afterAll(() => {
  for (const d of [tree, home]) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function run(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, 'secure', tree, ...args], {
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

function json(stdout: string): any {
  return JSON.parse(stdout.slice(stdout.indexOf('{')));
}

describe('#739 control 5.1 reads every credential-bearing file the scanner reads', { timeout: 300_000 }, () => {
  it('fixture guard: the plain scan records the key as CRED-001 at .claude/settings.json:1', () => {
    const body = json(run(['--ci', '--no-machine-posture', '--json']).stdout);
    const recs = (body.allFindings ?? body.findings).filter((f: any) => f.checkId === 'CRED-001');
    const settings = recs.find((r: { file?: string }) => r.file === '.claude/settings.json');
    expect(settings).toBeDefined();
    expect(settings.line).toBe(1);
    expect(settings.passed).toBe(false);
    expect(recs.some((r: { file?: string }) => r.file === '.env')).toBe(true);
  });

  it('text: [-] 5.1 with an evidence line naming .claude/settings.json:1, and the category is no longer clean', () => {
    const r = run([...FLAGS, '--verbose']);
    expect(r.stdout).toMatch(/\[-\] 5\.1: No Hardcoded Credentials/);
    expect(r.stdout).not.toMatch(/\[\+\] 5\.1: No Hardcoded Credentials/);
    expect(r.stdout).toMatch(/CRED-001: .*\.claude\/settings\.json:1/);
    expect(r.stdout).toMatch(/CRED-001: .*\(\.env:1\)/);
    expect(r.stdout).toMatch(/Credential Protection: 0\/1 \(0%\)/);
    expect(r.status).toBe(1);
  });

  it('json: 5.1 is failed and its finding carries the CRED-001 record with file:line', () => {
    const body = json(run([...FLAGS, '--json']).stdout);
    const c = body.categories.flatMap((x: any) => x.controls).find((x: any) => x.controlId === '5.1');
    expect(c.status).toBe('failed');
    expect(c.findings.some((line: string) => /^CRED-001: .*\.claude\/settings\.json:1/.test(line))).toBe(true);
    expect(c.findings.some((line: string) => /^CRED-001: .*\(\.env:1\)$/.test(line))).toBe(true);
    expect(c.findings.filter((line: string) => line.startsWith('CRED-001: ')).length).toBe(2);
    const cat = body.categories.find((x: any) => x.category === 'Credential Protection');
    expect(cat.failed).toBe(1);
    expect(cat.passed).toBe(0);
  });
});

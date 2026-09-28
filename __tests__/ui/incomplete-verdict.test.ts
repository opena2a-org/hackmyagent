/**
 * #568 — over a tree holding an input the run could not read, the Verdict line
 * leads with the incompleteness and the band sentence follows it.
 *
 * Unit half: `incompleteVerdictLead` composes the clause. Spawn half: both
 * commands that share `displayUnifiedCheck` print it first, over the same
 * fixture (one readable file, one mode-000 file), with the exit code and the
 * `--json` body unchanged, and a fail-direction band keeps its own lead.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { incompleteVerdictLead } from '../../src/ui/incomplete-verdict';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

const id = (p: string) => p;
const UPPER = 'The score is an upper bound over what was read.';
const unreadFile = (file: string, code = 'EACCES') => ({
  checkId: 'SCAN-UNREAD-001', file, kind: 'file' as const, message: `${file} could not be read (${code})`,
});

describe('incompleteVerdictLead', () => {
  it('is null when every discovered input was read', () => {
    expect(incompleteVerdictLead([{ checkId: 'DEP-001', file: 'package-lock.json' }], 0, id)).toBeNull();
  });

  it('names the first unread file and its errno', () => {
    expect(incompleteVerdictLead([unreadFile('src/secrets.js')], 1, id))
      .toBe(`Incomplete: src/secrets.js could not be read (EACCES). ${UPPER}`);
  });

  it('says listed, not read, for a directory', () => {
    const dir = {
      checkId: 'SCAN-UNREAD-001', file: 'vendor', kind: 'directory' as const,
      message: 'vendor could not be listed (EACCES) — its contents were not discovered, so nothing inside it reached any check.',
    };
    expect(incompleteVerdictLead([dir], 1, id)).toBe(`Incomplete: vendor could not be listed (EACCES). ${UPPER}`);
  });

  it('counts the rest', () => {
    const lead = incompleteVerdictLead([unreadFile('a.js'), unreadFile('b.js', 'EPERM'), unreadFile('c.js')], 3, id);
    expect(lead).toBe(`Incomplete: a.js could not be read (EACCES), and 2 more inputs were not read. ${UPPER}`);
    expect(incompleteVerdictLead([unreadFile('a.js'), unreadFile('b.js')], 2, id)).toContain(', and 1 more input was not read.');
  });

  it('uses the measured count when no finding names the input (the check was suppressed)', () => {
    expect(incompleteVerdictLead([], 1, id)).toBe(`Incomplete: 1 input could not be read. ${UPPER}`);
    expect(incompleteVerdictLead([unreadFile('a.js')], 3, id)).toContain(', and 2 more inputs were not read.');
  });

  it('takes the errno the tool wrote, not one spelled inside the scanned path', () => {
    const spoof = 'x could not be read (EFAKE).js';
    expect(incompleteVerdictLead([unreadFile(spoof, 'EACCES')], 1, id)).toContain('.js could not be read (EACCES).');
  });

  it('renders the path through the display escape it is given', () => {
    expect(incompleteVerdictLead([unreadFile('a\u001b[2Jb.js')], 1, (p) => p.replace(/\u001b/g, '\\x1b')))
      .toContain('a\\x1b[2Jb.js could not be read');
  });
});

describe('secure and check lead the Verdict with the unread input', () => {
  beforeAll(assertDistFreshIfPresent);

  let root: string;
  let home: string;
  const restore: string[] = [];

  function run(args: string[]) {
    const res = spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf-8',
      timeout: 240_000,
      env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home },
    });
    return { status: res.status, stdout: res.stdout ?? '' };
  }

  /** A tree with one readable file and one the OS refuses to read; null if it would not refuse (root). */
  function makeTree(name: string, extra?: (dir: string) => void): string | null {
    const dir = path.join(root, name);
    fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"u568","version":"1.0.0"}\n');
    fs.writeFileSync(path.join(dir, 'src', 'index.js'), 'module.exports = 1;\n');
    const secret = path.join(dir, 'src', 'secrets.js');
    fs.writeFileSync(secret, 'module.exports = 2;\n');
    extra?.(dir);
    fs.chmodSync(secret, 0o000);
    restore.push(secret);
    try {
      fs.readFileSync(secret);
      return null;
    } catch {
      return dir;
    }
  }

  const verdictOf = (out: string) => out.split('\n').find((l) => /^\s+Verdict\s/.test(l)) ?? '';

  beforeAll(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-568-'));
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-568-home-'));
  });

  afterAll(() => {
    for (const p of restore) {
      try { fs.chmodSync(p, 0o644); } catch { /* already gone */ }
    }
    for (const d of [root, home]) {
      try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  for (const command of ['secure', 'check']) {
    it(`${command}: the Verdict opens with the unread path, then the band sentence; exit 2 and --json unchanged`, (ctx) => {
      const dir = makeTree(`caveats-${command}`);
      if (dir === null) ctx.skip('this OS reads a mode-000 file (running as root)');
      const text = run([command, dir!]);
      expect(text.status).toBe(2);
      const verdict = verdictOf(text.stdout);
      expect(verdict).toMatch(/Verdict\s+Incomplete: src\/secrets\.js could not be read \(EACCES\)\. The score is an upper bound over what was read\. Usable with caveats\./);

      const json = run([command, dir!, '--json']);
      expect(json.status).toBe(2);
      expect(json.stdout).not.toContain('Incomplete:');
    });
  }

  it('a fail-direction band keeps its own lead', (ctx) => {
    const token = `ghp_${'abcdefghijklmnopqrstuvwxyz0123456789'.split('').reverse().join('')}`;
    const dir = makeTree('unsafe', (d) => fs.writeFileSync(path.join(d, 'config.json'), `{"token":"${token}"}\n`));
    if (dir === null) ctx.skip('this OS reads a mode-000 file (running as root)');
    const verdict = verdictOf(run(['secure', dir!]).stdout);
    expect(verdict).toMatch(/Verdict\s+Not safe/);
    expect(verdict).not.toContain('Incomplete:');
  });
});

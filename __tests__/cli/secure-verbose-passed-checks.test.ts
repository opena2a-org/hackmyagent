/**
 * #974 — `secure --verbose` lists the checks that passed.
 *
 * `secure --help` reads `-v, --verbose  Show all checks including passed ones`.
 * The text report was built from the findings that did not pass, so `--verbose`
 * added check IDs and categories to those and printed no passed check at all,
 * while `--json` carried the passed records under `allFindings`.
 *
 * The expected list is read from `--json` on the same tree, so no count is
 * written down here.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

let root: string;
let home: string;

beforeAll(() => {
  root = tempDir('hma-974-');
  home = tempDir('hma-home-');
  fs.mkdirSync(path.join(root, 'lib'));
  fs.writeFileSync(path.join(root, 'lib', 'index.js'), 'module.exports = (a, b) => a + b;\n');
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'hma-974', version: '1.0.0' }));
});

afterAll(() => {
  for (const dir of [root, home]) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function run(args: string[]): { stdout: string; all: string } {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    cwd: root,
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: home,
    },
  });
  return { stdout: r.stdout ?? '', all: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

interface Record_ { checkId: string; name: string; passed?: boolean; fixed?: boolean }

/** The passed records `--json` carries for the same arguments. */
function passedRecords(extra: string[] = []): Record_[] {
  const { stdout } = run(['secure', '.', '--static-only', '--json', ...extra]);
  const doc = JSON.parse(stdout) as { allFindings?: Record_[] };
  return (doc.allFindings ?? []).filter((f) => f.passed === true && !f.fixed);
}

/** The lines of the `Passed checks` section, or undefined when it is absent. */
function passedSection(out: string): string[] | undefined {
  const lines = out.split('\n');
  const start = lines.findIndex((l) => /^\s*── Passed checks ─/.test(l));
  if (start === -1) return undefined;
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((l) => /^\s*── /.test(l));
  return end === -1 ? rest : rest.slice(0, end);
}

describe('#974 secure --verbose lists the checks that passed', () => {
  it('prints one line for every passed record --json carries', () => {
    const expected = passedRecords();
    // Non-vacuity: the tree must produce passed records to list.
    expect(expected.length).toBeGreaterThan(0);

    const { all } = run(['secure', '.', '--static-only', '--verbose']);
    const section = passedSection(all);
    expect(section, `no Passed checks section in the report:\n${all}`).toBeDefined();

    const rows = section!.filter((l) => /^\s*✓ /.test(l));
    expect(rows.map((l) => l.trim().split(/\s+/)[1])).toEqual(expected.map((f) => f.checkId));
    for (const f of expected) {
      const row = rows.find((l) => l.trim().split(/\s+/)[1] === f.checkId);
      expect(row, `no row for ${f.checkId}`).toContain(f.name);
    }
    expect(section!.join('\n')).toContain(`${expected.length} passed`);
  });

  it('prints no passed check without --verbose', () => {
    const { all } = run(['secure', '.', '--static-only']);
    expect(passedSection(all)).toBeUndefined();
  });

  it('leaves out a check the caller passed to --ignore', () => {
    const ignored = passedRecords()[0].checkId;
    const expected = passedRecords(['--ignore', ignored]);
    expect(expected.map((f) => f.checkId)).not.toContain(ignored);

    const { all } = run(['secure', '.', '--static-only', '--verbose', '--ignore', ignored]);
    const section = passedSection(all);
    expect(section, `no Passed checks section in the report:\n${all}`).toBeDefined();
    const ids = section!.filter((l) => /^\s*✓ /.test(l)).map((l) => l.trim().split(/\s+/)[1]);
    expect(ids).toEqual(expected.map((f) => f.checkId));
  });
});

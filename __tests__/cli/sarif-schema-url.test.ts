/**
 * #394 — every SARIF document points `$schema` at a schema that exists.
 *
 * The three SARIF writers each carried their own copy of
 * `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json`,
 * which returns 404 since the upstream repository moved the file off `master`.
 * They now share `SARIF_SCHEMA_URL`, the schema's own `$id`. Resolving the URL
 * needs the network, so this suite pins the value and the sharing; the value
 * was checked by hand to return 200 with a body whose `$id` is itself.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { SARIF_SCHEMA_URL } from '../../src/output/sarif-schema';

beforeAll(assertDistFreshIfPresent);

let root: string;

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-394-'));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'hma-394', version: '1.0.0' }));
  fs.writeFileSync(path.join(root, 'index.js'), 'module.exports = (req) => eval(req.body.code);\n');
});

afterAll(() => {
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
});

function sarif(args: string[]): { $schema?: string; version?: string } {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...process.env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-')),
    },
  });
  const out = r.stdout ?? '';
  const start = out.indexOf('{');
  expect(start, `no JSON document on stdout:\n${out}${r.stderr ?? ''}`).toBeGreaterThanOrEqual(0);
  return JSON.parse(out.slice(start));
}

describe('#394 SARIF $schema', () => {
  it('is the OASIS-published SARIF 2.1.0 schema id, not the moved master-branch copy', () => {
    expect(SARIF_SCHEMA_URL).toBe(
      'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json',
    );
  });

  it('secure -f sarif points at it', () => {
    const doc = sarif(['secure', root, '-f', 'sarif']);
    expect(doc.version).toBe('2.1.0');
    expect(doc.$schema).toBe(SARIF_SCHEMA_URL);
  });

  it('the benchmark SARIF points at it', () => {
    const doc = sarif(['secure', root, '-b', 'oasb-1', '-f', 'sarif']);
    expect(doc.version).toBe('2.1.0');
    expect(doc.$schema).toBe(SARIF_SCHEMA_URL);
  });

  it('no writer carries its own copy of a schema URL', () => {
    // `attack -f sarif` needs a live endpoint, so its writer is held to the
    // shared constant at the source instead: no SARIF schema URL may be spelled
    // anywhere under src/ except the one module that defines it.
    const srcRoot = path.resolve(__dirname, '../../src');
    const offenders: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const abs = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(abs);
        else if (/\.ts$/.test(entry.name) && !abs.endsWith(path.join('output', 'sarif-schema.ts'))) {
          if (/sarif-schema-2\.1\.0\.json/.test(fs.readFileSync(abs, 'utf8'))) offenders.push(path.relative(srcRoot, abs));
        }
      }
    };
    walk(srcRoot);
    expect(offenders).toEqual([]);
  });
});

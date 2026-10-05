/**
 * #537 — the range parser and the base/head classification behind
 * `secure --range` and `secure --staged`.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { parseRangeSpec, classifyAgainstBase } from '../src/change-scope';

describe('#537 parseRangeSpec', () => {
  it('reads the two-dot, three-dot and open-ended forms', () => {
    expect(parseRangeSpec('origin/main..HEAD')).toEqual({ base: 'origin/main', head: 'HEAD', mergeBase: false });
    expect(parseRangeSpec('origin/main...feature')).toEqual({ base: 'origin/main', head: 'feature', mergeBase: true });
    expect(parseRangeSpec('v1.0..')).toEqual({ base: 'v1.0', head: 'HEAD', mergeBase: false });
    expect(parseRangeSpec('v1.0...')).toEqual({ base: 'v1.0', head: 'HEAD', mergeBase: true });
  });

  it('refuses a single revision, an empty base, an option-shaped revision and a chained range', () => {
    for (const spec of ['HEAD', '', '..HEAD', '...HEAD', '--output=x..HEAD', 'a..-b', 'a..b..c', 'a ..b']) {
      expect(() => parseRangeSpec(spec), spec).toThrow(/--range/);
    }
  });
});

describe('#537 classifyAgainstBase', () => {
  let root: string;
  let headDir: string;
  let baseDir: string;

  beforeAll(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-537-unit-'));
    headDir = path.join(root, 'head', 'repo');
    baseDir = path.join(root, 'base', 'repo');
    fs.mkdirSync(path.join(headDir, 'sub'), { recursive: true });
    fs.mkdirSync(baseDir, { recursive: true });
    fs.writeFileSync(path.join(baseDir, 'a.json'), 'x\nSECRET-1\n');
    // Two lines inserted above the pre-existing line, and a second copy of it.
    fs.writeFileSync(path.join(headDir, 'a.json'), 'new\nnew\nx\nSECRET-1\nSECRET-1\n');
    fs.writeFileSync(path.join(baseDir, 'old.json'), 'SECRET-2\n');
    fs.writeFileSync(path.join(headDir, 'sub', 'renamed.json'), 'SECRET-2\n');
  });

  afterAll(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  const fail = (checkId: string, file: string, line?: number, message = 'm') =>
    ({ checkId, file, line, message, passed: false });

  it('a pre-existing line that moved is not introduced; a second copy of it is', () => {
    const r = classifyAgainstBase(
      [fail('CRED-001', 'a.json', 4), fail('CRED-001', 'a.json', 5)],
      [fail('CRED-001', 'a.json', 2)],
      { prefix: '', renames: new Map() },
      { headDir, baseDir },
    );
    expect(r.preExisting).toBe(1);
    expect(r.introduced).toBe(1);
    expect(r.kept).toHaveLength(1);
  });

  it('follows a rename, inside the scan prefix', () => {
    const r = classifyAgainstBase(
      [fail('CRED-001', 'sub/renamed.json', 1)],
      [fail('CRED-001', 'old.json', 1)],
      { prefix: 'pkg/', renames: new Map([['pkg/old.json', 'pkg/sub/renamed.json']]) },
      { headDir, baseDir },
    );
    expect(r).toMatchObject({ introduced: 0, preExisting: 1, kept: [] });
  });

  it('a finding with no line matches on its message, with the scan root taken out', () => {
    const r = classifyAgainstBase(
      [fail('MCP-001', 'mcp.json', undefined, `server in ${headDir}/mcp.json`), fail('MCP-002', 'mcp.json', undefined, 'new')],
      [fail('MCP-001', 'mcp.json', undefined, `server in ${baseDir}/mcp.json`)],
      { prefix: '', renames: new Map() },
      { headDir, baseDir },
    );
    expect(r.preExisting).toBe(1);
    expect(r.kept.map((f) => f.checkId)).toEqual(['MCP-002']);
  });

  it('passed and not-applicable records are kept and not counted', () => {
    const passed = { checkId: 'GIT-001', file: '.gitignore', passed: true };
    const na = { checkId: 'SANDBOX-001', notApplicable: { subject: 'Dockerfile', reason: 'absent' } };
    const r = classifyAgainstBase([passed, na], [passed], { prefix: '', renames: new Map() }, { headDir, baseDir });
    expect(r).toMatchObject({ introduced: 0, preExisting: 0 });
    expect(r.kept).toEqual([passed, na]);
  });
});

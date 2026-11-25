/**
 * GIT-002 counts only the committable files in scope.
 *
 * GIT-002 points `file` at `.gitignore` and lists the committable sensitive
 * files in `details.files`. An `.hmaignore` path rule over those files left
 * `.gitignore` standing, so the scope pass re-pointed the finding instead of
 * scoping it out: it stayed in `findings` at HIGH with `.gitignore` in
 * `details.files`, although every file that made it HIGH was excluded.
 */
import { describe, it, expect } from 'vitest';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { tempDir } from '../helpers/temp-dir';

const COMPLETE_GITIGNORE = '.env\nsecrets.json\n*.pem\n*.key\n';

function fixture(opts: { gitignore: string; hmaignore?: string; keys: string[] }): string {
  const dir = tempDir('hma-git002-scope-');
  writeFileSync(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  writeFileSync(path.join(dir, '.gitignore'), opts.gitignore);
  for (const rel of opts.keys) {
    mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    writeFileSync(path.join(dir, rel), 'not a real key\n');
  }
  if (opts.hmaignore !== undefined) writeFileSync(path.join(dir, '.hmaignore'), opts.hmaignore);
  return dir;
}

async function scan(dir: string) {
  const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
  const git002 = result.findings.filter((f) => f.checkId === 'GIT-002' && !f.passed);
  const outOfScope = (result.outOfScope ?? []).filter((r) => r.checkId === 'GIT-002');
  return { git002, outOfScope };
}

describe('GIT-002 and .hmaignore scope rules', () => {
  it('a committable key under an excluded path is out of scope at high, not a finding', async () => {
    const dir = fixture({
      gitignore: `${COMPLETE_GITIGNORE}!fixtures/server.key\n`,
      hmaignore: 'fixtures/\n',
      keys: ['fixtures/server.key'],
    });
    const { git002, outOfScope } = await scan(dir);
    expect(git002).toEqual([]);
    expect(outOfScope).toHaveLength(1);
    expect(outOfScope[0].severity).toBe('high');
    expect(outOfScope[0].suppressedBy).toBe('hmaignore-path');
  });

  it('a <path>:GIT-002 rule scopes out the excluded file too', async () => {
    const dir = fixture({
      gitignore: `${COMPLETE_GITIGNORE}!fixtures/server.key\n`,
      hmaignore: 'fixtures/:GIT-002 # fixtures are not shipped\n',
      keys: ['fixtures/server.key'],
    });
    const { git002, outOfScope } = await scan(dir);
    expect(git002).toEqual([]);
    expect(outOfScope.map((r) => [r.severity, r.suppressedBy])).toEqual([['high', 'hmaignore-path-check']]);
  });

  it('missing patterns with only excluded files committable is low in findings and high out of scope', async () => {
    const dir = fixture({
      gitignore: 'node_modules/\n',
      hmaignore: 'fixtures/\n',
      keys: ['fixtures/server.key'],
    });
    const { git002, outOfScope } = await scan(dir);
    expect(git002).toHaveLength(1);
    expect(git002[0].severity).toBe('low');
    expect(git002[0].details?.files).toBeUndefined();
    expect(outOfScope.map((r) => r.severity)).toEqual(['high']);
  });

  it('an in-scope committable key keeps the finding high, naming only in-scope files', async () => {
    const dir = fixture({
      gitignore: 'node_modules/\n',
      hmaignore: 'fixtures/\n',
      keys: ['fixtures/server.key', 'certs/live.key'],
    });
    const { git002, outOfScope } = await scan(dir);
    expect(git002).toHaveLength(1);
    expect(git002[0].severity).toBe('high');
    expect(git002[0].file).toBe('.gitignore');
    expect(git002[0].details?.files).toEqual(['certs/live.key']);
    expect(outOfScope.map((r) => r.severity)).toEqual(['high']);
  });

  it('a .gitignore:GIT-002 rule does not scope out a committable file', async () => {
    const dir = fixture({
      gitignore: 'node_modules/\n',
      hmaignore: '.gitignore:GIT-002 # patterns are reviewed elsewhere\n',
      keys: ['certs/live.key'],
    });
    const { git002, outOfScope } = await scan(dir);
    expect(git002).toHaveLength(1);
    expect(git002[0].severity).toBe('high');
    expect(git002[0].details?.files).toEqual(['certs/live.key']);
    expect(outOfScope).toEqual([]);
  });

  it('without an .hmaignore the finding is unchanged', async () => {
    const dir = fixture({
      gitignore: 'node_modules/\n',
      keys: ['fixtures/server.key', 'certs/live.key'],
    });
    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    const git002 = result.findings.filter((f) => f.checkId === 'GIT-002');
    expect(git002).toHaveLength(1);
    expect(git002[0].severity).toBe('high');
    expect(git002[0].file).toBe('.gitignore');
    expect([...(git002[0].details?.files as string[])].sort()).toEqual(['certs/live.key', 'fixtures/server.key']);
    expect(result.outOfScope).toBeUndefined();
  });
});

/**
 * #1033 — `secure --fix` never writes a path an `.hmaignore` rule excludes.
 *
 * A whole-path rule takes a path out of the scan, and a `<path>:<CHECK>` rule
 * takes one check's findings on it out. The fixes ran inside the checks before
 * the rules were applied to the findings, so `--fix` rewrote
 * `fixtures/config.json` under a `fixtures/` rule while the report never showed
 * the finding it was fixing. Each refused write is reported with its path and
 * the rule line, and a refusal is not a FIX-WRITE-FAILED.
 */
import { describe, it, expect } from 'vitest';
import { chmod, mkdir, readFile, stat, symlink, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import {
  HardeningScanner,
  HMAIGNORE_ECHO_MAX,
  hmaIgnoreRuleExcludingFixWrite,
  parseHmaIgnore,
} from '../../src/hardening/scanner';
import { SoulScanner } from '../../src/soul/scanner';
import { tempDir } from '../helpers/temp-dir';

/** Assembled at runtime, never a literal in the source tree. */
const FAKE_TOKEN = 'gh' + 'p_' + 'a'.repeat(36);
const CONFIG = JSON.stringify({ token: FAKE_TOKEN }, null, 2) + '\n';

async function put(dir: string, rel: string, content: string): Promise<void> {
  await mkdir(path.dirname(path.join(dir, rel)), { recursive: true });
  await writeFile(path.join(dir, rel), content);
}

async function read(dir: string, rel: string): Promise<string> {
  return readFile(path.join(dir, rel), 'utf-8');
}

describe('#1033 --fix never writes a path .hmaignore excludes', () => {
  it('a whole-path rule: the excluded file is unchanged, an in-scope one is fixed, and the skip names the rule line', async () => {
    const dir = tempDir('hma-1033-path-');
    await put(dir, '.hmaignore', '# fixtures are test data\nfixtures/\n');
    await put(dir, 'fixtures/config.json', CONFIG);
    await put(dir, 'src/config.json', CONFIG);

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    expect(await read(dir, 'fixtures/config.json')).toBe(CONFIG);
    // The control: the same fix did run on the file the rule does not cover.
    expect(await read(dir, 'src/config.json')).not.toContain(FAKE_TOKEN);
    expect(result.fixWritesExcluded).toEqual([
      { file: 'fixtures/config.json', line: 2, rule: 'fixtures/', checkIds: ['CRED-001'] },
    ]);
    expect(result.findings.some((f) => f.checkId === 'FIX-WRITE-FAILED')).toBe(false);
  });

  it('a <path>:<CHECK> rule refuses the write for that check only', async () => {
    const dir = tempDir('hma-1033-pathcheck-');
    await put(
      dir,
      '.hmaignore',
      'services/config.json:CRED-001 # sample credentials\nworkers/config.json:GIT-001 # unrelated check\n',
    );
    await put(dir, 'services/config.json', CONFIG);
    await put(dir, 'workers/config.json', CONFIG);

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    expect(await read(dir, 'services/config.json')).toBe(CONFIG);
    // A rule for a different check leaves the CRED-001 fix to land.
    expect(await read(dir, 'workers/config.json')).not.toContain(FAKE_TOKEN);
    expect(result.fixWritesExcluded).toEqual([
      {
        file: 'services/config.json',
        line: 1,
        rule: 'services/config.json:CRED-001 # sample credentials',
        checkIds: ['CRED-001'],
      },
    ]);
  });

  it('an in-scope name linked into an excluded directory is refused under the destination it resolves to', async () => {
    const dir = tempDir('hma-1033-link-');
    await put(dir, '.hmaignore', 'fixtures/\n');
    await put(dir, 'fixtures/config.json', CONFIG);
    await symlink(path.join('fixtures', 'config.json'), path.join(dir, 'config.json'));

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    expect(await read(dir, 'fixtures/config.json')).toBe(CONFIG);
    expect(result.fixWritesExcluded?.map((e) => [e.file, e.line])).toEqual([['fixtures/config.json', 1]]);
  });

  it('a refused credential fix declares nothing in .env.example', async () => {
    const dir = tempDir('hma-1033-envexample-');
    await put(dir, '.hmaignore', 'fixtures/\n');
    await put(dir, 'fixtures/config.json', CONFIG);

    await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    expect(await read(dir, 'fixtures/config.json')).toBe(CONFIG);
    expect(existsSync(path.join(dir, '.env.example'))).toBe(false);
  });

  it('the PERM-001 chmod is refused on an excluded file', async () => {
    const dir = tempDir('hma-1033-perm-');
    await put(dir, '.hmaignore', 'secrets.json\n');
    await put(dir, 'secrets.json', '{}\n');
    await chmod(path.join(dir, 'secrets.json'), 0o644);

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    expect((await stat(path.join(dir, 'secrets.json'))).mode & 0o777).toBe(0o644);
    expect(result.fixWritesExcluded).toEqual([
      { file: 'secrets.json', line: 1, rule: 'secrets.json', checkIds: ['PERM-001'] },
    ]);
  });

  it('the governance write secure --fix makes after the scan is refused with the rule line as its reason', async () => {
    const dir = tempDir('hma-1033-soul-');
    await put(dir, '.hmaignore', 'SOUL.md\n');
    const scanner = new HardeningScanner();
    await scanner.scan({ targetDir: dir, autoFix: true });

    const hardened = await new SoulScanner().hardenSoul(dir, {
      writeGuard: async (rel) => {
        const excluded = await scanner.excludeGovernanceWrite(dir, rel, ['SOUL-001']);
        return excluded ? { refused: `excluded by .hmaignore:${excluded.line} \`${excluded.rule}\`` } : true;
      },
    });

    expect(existsSync(path.join(dir, 'SOUL.md'))).toBe(false);
    expect(hardened.writeRefused).toEqual({ path: 'SOUL.md', reason: 'excluded by .hmaignore:1 `SOUL.md`' });
  });

  it('the matcher: whole-path first, <path>:<CHECK> only for a matching check, and a !<CHECK> rule never refuses', () => {
    const parsed = parseHmaIgnore(
      [
        '!CRED-001',
        'docs/a.json:CRED-* # samples',
        'docs/',
      ].join('\n'),
      '2026-10-12',
    );
    expect(parsed.errors).toEqual([]);
    expect(hmaIgnoreRuleExcludingFixWrite(['config.json'], ['CRED-001'], parsed)).toBeUndefined();
    expect(hmaIgnoreRuleExcludingFixWrite(['docs/a.json'], ['CRED-001'], parsed)?.line).toBe(3);
    const narrow = parseHmaIgnore('docs/a.json:CRED-* # samples\n', '2026-10-12');
    expect(hmaIgnoreRuleExcludingFixWrite(['docs/a.json'], ['CRED-001'], narrow)?.line).toBe(1);
    expect(hmaIgnoreRuleExcludingFixWrite(['docs/a.json'], ['GIT-001'], narrow)).toBeUndefined();
    expect(hmaIgnoreRuleExcludingFixWrite(['docs/b.json'], ['CRED-001'], narrow)).toBeUndefined();
    expect(hmaIgnoreRuleExcludingFixWrite(['docs/a.json'], ['CRED-001'], undefined)).toBeUndefined();
  });
});

/** The echo of `text` when it is longer than the bound, as #937 writes it. */
function cutEcho(text: string): string {
  return `${text.slice(0, HMAIGNORE_ECHO_MAX)}… (${text.length} characters)`;
}

describe('#1058 a refused --fix write echoes a long .hmaignore rule bounded', () => {
  it('fixWritesExcluded[].rule stops at HMAIGNORE_ECHO_MAX characters, and the rule still refuses the write', async () => {
    const dir = tempDir('hma-1058-perm-');
    const line = `secrets.json # ${'r'.repeat(64 * HMAIGNORE_ECHO_MAX)}`;
    await put(dir, '.hmaignore', `${line}\n`);
    await put(dir, 'secrets.json', '{}\n');
    await chmod(path.join(dir, 'secrets.json'), 0o644);

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    expect((await stat(path.join(dir, 'secrets.json'))).mode & 0o777).toBe(0o644);
    expect(result.fixWritesExcluded).toEqual([
      { file: 'secrets.json', line: 1, rule: cutEcho(line), checkIds: ['PERM-001'] },
    ]);
    expect(JSON.stringify(result.fixWritesExcluded).length).toBeLessThan(2 * HMAIGNORE_ECHO_MAX);
  });

  it('a refused governance write after the scan records the bounded rule', async () => {
    const dir = tempDir('hma-1058-soul-');
    const line = `SOUL.md # ${'s'.repeat(64 * HMAIGNORE_ECHO_MAX)}`;
    await put(dir, '.hmaignore', `${line}\n`);
    const scanner = new HardeningScanner();
    await scanner.scan({ targetDir: dir, autoFix: true });

    const excluded = await scanner.excludeGovernanceWrite(dir, 'SOUL.md', ['SOUL-001']);

    expect(excluded).toEqual({ file: 'SOUL.md', line: 1, rule: cutEcho(line), checkIds: ['SOUL-001'] });
  });

  it('a rule of exactly HMAIGNORE_ECHO_MAX characters is echoed as written', async () => {
    const dir = tempDir('hma-1058-atbound-');
    const prefix = 'secrets.json # ';
    const line = `${prefix}${'t'.repeat(HMAIGNORE_ECHO_MAX - prefix.length)}`;
    await put(dir, '.hmaignore', `${line}\n`);
    await put(dir, 'secrets.json', '{}\n');
    await chmod(path.join(dir, 'secrets.json'), 0o644);

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

    expect(line).toHaveLength(HMAIGNORE_ECHO_MAX);
    expect(result.fixWritesExcluded?.map((e) => e.rule)).toEqual([line]);
  });
});

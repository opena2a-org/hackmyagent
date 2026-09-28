/**
 * #282 — `secure --fix` keeps a hand-written `.env.example`.
 *
 * The CRED-001 fix built `.env.example` from scratch and wrote it over
 * whatever was there, so a template like
 *
 *   STRIPE_SECRET_KEY=
 *   DATABASE_URL=postgres://localhost/db
 *   # hand-written notes
 *
 * came back as `# Environment variables` plus the one name the run generated.
 * The fix now keeps the file's bytes and appends only the names it does not
 * already declare; with no file present it creates one as before.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';

const FAKE_GH_TOKEN = `ghp_${'d'.repeat(36)}`;
const PKG = '{"name":"env-example-fixture","version":"1.0.0"}\n';

async function withTree(envExample: string | null, fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(path.join(tmpdir(), 'hma-env-example-'));
  try {
    await writeFile(path.join(dir, 'package.json'), PKG);
    await mkdir(path.join(dir, 'config'), { recursive: true });
    await writeFile(path.join(dir, 'config', 'production.json'), JSON.stringify({ token: FAKE_GH_TOKEN }) + '\n');
    if (envExample !== null) await writeFile(path.join(dir, '.env.example'), envExample);
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const declaredNames = (text: string): string[] =>
  text.split(/\r?\n/).map(l => /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(l)?.[1]).filter((n): n is string => !!n);

/** The names the fix generates for this fixture, read from a run with no template present. */
async function generatedNames(): Promise<string[]> {
  let names: string[] = [];
  await withTree(null, async (dir) => {
    await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
    const config = await readFile(path.join(dir, 'config', 'production.json'), 'utf-8');
    expect(config, '--fix did not rewrite the credential; this test is measuring nothing').not.toContain(FAKE_GH_TOKEN);
    names = declaredNames(await readFile(path.join(dir, '.env.example'), 'utf-8'));
  });
  expect(names.length).toBeGreaterThan(0);
  return names;
}

describe('#282 secure --fix keeps a hand-written .env.example', () => {
  it('creates .env.example when none exists', async () => {
    const names = await generatedNames();
    await withTree(null, async (dir) => {
      await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      const text = await readFile(path.join(dir, '.env.example'), 'utf-8');
      expect(text.startsWith('# Environment variables\n\n')).toBe(true);
      expect(declaredNames(text)).toEqual(names);
    });
  });

  it('keeps every existing byte and appends only the missing names', async () => {
    const names = await generatedNames();
    const handWritten = 'STRIPE_SECRET_KEY=\nDATABASE_URL=postgres://localhost/db\nSENTRY_DSN=https://example\n# hand-written notes';
    await withTree(handWritten, async (dir) => {
      await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      const text = await readFile(path.join(dir, '.env.example'), 'utf-8');
      expect(text.startsWith(handWritten + '\n')).toBe(true);
      expect(text.slice(handWritten.length + 1)).toBe(names.map(n => `${n}=\n`).join(''));
    });
  });

  it('leaves the file byte-identical when it already declares every name', async () => {
    const names = await generatedNames();
    const complete = `# Local setup\r\nexport ${names[0]}=\r\n${names.slice(1).map(n => `${n}=\r\n`).join('')}OTHER=1\r\n`;
    await withTree(complete, async (dir) => {
      await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      expect(await readFile(path.join(dir, '.env.example'), 'utf-8')).toBe(complete);
    });
  });

  it('appends in the file\'s own line ending', async () => {
    const names = await generatedNames();
    const crlf = 'API_BASE=https://api.example\r\n';
    await withTree(crlf, async (dir) => {
      await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      expect(await readFile(path.join(dir, '.env.example'), 'utf-8')).toBe(crlf + names.map(n => `${n}=\r\n`).join(''));
    });
  });

  it('rollback restores the hand-written file', async () => {
    const handWritten = 'STRIPE_SECRET_KEY=\n# hand-written notes\n';
    await withTree(handWritten, async (dir) => {
      await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
      expect(await readFile(path.join(dir, '.env.example'), 'utf-8')).not.toBe(handWritten);
      await new HardeningScanner().rollback(dir);
      expect(await readFile(path.join(dir, '.env.example'), 'utf-8')).toBe(handWritten);
    });
  });
});

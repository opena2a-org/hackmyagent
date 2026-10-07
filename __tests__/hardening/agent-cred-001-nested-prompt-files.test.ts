/**
 * #354 — AGENT-CRED-001 reads its system-prompt names below the scan root.
 *
 * `checkAgentCredentialProtection` probed `SOUL.md`, `CLAUDE.md`,
 * `system-prompt.md` and `system-prompt.txt` at the scan root only, while the
 * `system-prompt.ts`/`.js` half of the same method already walked two
 * directories down. Same bytes, only the placement changing: `CLAUDE.md`
 * fired, `sub/CLAUDE.md` was silent.
 *
 * These are execution tests against the real scanner: a prompt file that is
 * not discovered produces no error, just a clean-looking scan.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { SecurityFinding } from '../../src/hardening/security-check';
import { tempDir } from '../helpers/temp-dir';

/** Grants shell access and says nothing about protecting credentials. */
const PROMPT = '# Agent\n\nYou may run any shell command the user asks for.\n';
/** The same grant as a system-prompt source file, which the walk already reads. */
const PROMPT_TS = `export const SYSTEM_PROMPT = ${JSON.stringify(PROMPT)};\n`;

let dir: string;

beforeEach(() => {
  dir = tempDir('hma-354-');
});

async function write(rel: string, content: string): Promise<void> {
  await fs.mkdir(path.dirname(path.join(dir, rel)), { recursive: true });
  await fs.writeFile(path.join(dir, rel), content);
}

async function agentCredFiles(): Promise<string[]> {
  const result = await new HardeningScanner().scan({ targetDir: dir });
  return result.findings
    .filter((f: SecurityFinding) => f.checkId === 'AGENT-CRED-001' && f.passed === false)
    .map((f) => f.file ?? '')
    .sort();
}

describe('#354 AGENT-CRED-001 reaches below the scan root', () => {
  it('reports each prompt name one directory down, as it does at the root', async () => {
    const names = ['CLAUDE.md', 'SOUL.md', 'system-prompt.md', 'system-prompt.txt'];
    for (const name of names) await write(path.join('sub', name), PROMPT);

    const files = await agentCredFiles();

    // Count first: on the pre-fix code this list is empty.
    expect(files).toHaveLength(names.length);
    expect(files).toEqual(names.map((n) => path.join('sub', n)).sort());
  });

  it('reports the root and the nested copy of the same bytes, once each', async () => {
    await write('CLAUDE.md', PROMPT);
    await write(path.join('packages', 'agent', 'CLAUDE.md'), PROMPT);

    expect(await agentCredFiles()).toEqual([
      'CLAUDE.md',
      path.join('packages', 'agent', 'CLAUDE.md'),
    ]);
  });

  it('reaches the same depth for the prompt names as for system-prompt source files', async () => {
    // Two directories down is inside the walk both halves share; three is past it.
    await write(path.join('a', 'b', 'CLAUDE.md'), PROMPT);
    await write(path.join('a', 'b', 'system-prompt.ts'), PROMPT_TS);
    await write(path.join('a', 'b', 'c', 'CLAUDE.md'), PROMPT);
    await write(path.join('a', 'b', 'c', 'system-prompt.ts'), PROMPT_TS);

    expect(await agentCredFiles()).toEqual([
      path.join('a', 'b', 'CLAUDE.md'),
      path.join('a', 'b', 'system-prompt.ts'),
    ]);
  });

  it('matches a nested prompt name case-insensitively, as the source-file half does', async () => {
    await write(path.join('sub', 'claude.md'), PROMPT);

    expect(await agentCredFiles()).toEqual([path.join('sub', 'claude.md')]);
  });

  it('does not read prompt files inside node_modules or hidden directories', async () => {
    await write(path.join('node_modules', 'pkg', 'CLAUDE.md'), PROMPT);
    await write(path.join('.hidden', 'CLAUDE.md'), PROMPT);

    expect(await agentCredFiles()).toEqual([]);
  });

  it('does not read a nested prompt name that links out of the tree', async () => {
    const outside = tempDir('hma-354-out-');
    await fs.writeFile(path.join(outside, 'CLAUDE.md'), PROMPT);
    await fs.mkdir(path.join(dir, 'sub'));
    await fs.symlink(path.join(outside, 'CLAUDE.md'), path.join(dir, 'sub', 'CLAUDE.md'));

    expect(await agentCredFiles()).toEqual([]);
  });

  it('does not report a nested prompt that already carries credential protection', async () => {
    await write(
      path.join('sub', 'CLAUDE.md'),
      `${PROMPT}\nNever print secret values; reference each credential by its environment variable name.\n`,
    );

    expect(await agentCredFiles()).toEqual([]);
  });
});

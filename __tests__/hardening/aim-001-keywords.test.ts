/**
 * AIM-001 took any package.json keyword containing `agent` as a claim that
 * the package is an AI agent, so `ai-agent` or `user-agent` alone raised a
 * missing-identity finding. Only the exact keyword `agent` (or `a2a`), or an
 * `agentCard`/`a2a` field, marks an agent project.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { SecurityFinding } from '../../src/hardening/security-check';
import { tempDir } from '../helpers/temp-dir';

let dir: string;

beforeEach(() => {
  dir = tempDir('hma-aim001-');
});

async function aim001(pkg: Record<string, unknown>): Promise<SecurityFinding[]> {
  await fs.writeFile(path.join(dir, 'package.json'), JSON.stringify(pkg));
  const result = await new HardeningScanner().scan({ targetDir: dir });
  return result.findings.filter((f: SecurityFinding) => f.checkId === 'AIM-001' && f.passed === false);
}

describe('AIM-001 agent keyword', () => {
  it('does not fire for a package whose only keyword is ai-agent', async () => {
    expect(await aim001({ name: 'lib', version: '1.0.0', keywords: ['ai-agent'] })).toEqual([]);
  });

  it('does not fire for other keywords that merely contain agent', async () => {
    expect(await aim001({ name: 'lib', version: '1.0.0', keywords: ['user-agent', 'agentic-tools'] })).toEqual([]);
  });

  it('fires for a package with the exact keyword agent', async () => {
    expect(await aim001({ name: 'bot', version: '1.0.0', keywords: ['agent'] })).toHaveLength(1);
  });

  it('fires for a package that declares an a2a field', async () => {
    expect(await aim001({ name: 'bot', version: '1.0.0', a2a: { skills: [] } })).toHaveLength(1);
  });

  it('does not fire once an identity file is present', async () => {
    await fs.writeFile(path.join(dir, 'aim.json'), JSON.stringify({ name: 'bot', publicKey: 'k' }));
    expect(await aim001({ name: 'bot', version: '1.0.0', keywords: ['agent'] })).toEqual([]);
  });
});

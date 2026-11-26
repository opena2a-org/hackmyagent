/**
 * A2A-001 reads the A2A v0.3.0 / v1.0 agent card path,
 * .well-known/agent-card.json, as well as the older agent.json.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { SecurityFinding } from '../../src/hardening/security-check';
import { tempDir } from '../helpers/temp-dir';

describe('A2A-001 agent-card.json', () => {
  for (const base of ['', 'public', 'static']) {
    it(`reports a card under ${base || 'the root'}/.well-known/agent-card.json`, async () => {
      const dir = tempDir('hma-a2a001-');
      const wk = path.join(dir, base, '.well-known');
      await fs.mkdir(wk, { recursive: true });
      await fs.writeFile(path.join(wk, 'agent-card.json'), JSON.stringify({ name: 'x', capabilities: {} }));
      const result = await new HardeningScanner().scan({ targetDir: dir });
      const hits = result.findings.filter((f: SecurityFinding) => f.checkId === 'A2A-001');
      expect(hits).toHaveLength(1);
      expect(hits[0].file).toBe(path.join(base, '.well-known', 'agent-card.json'));
      expect(result.coverage?.filesReadByCategory?.A2A ?? 0).toBeGreaterThan(0);
    });
  }
});

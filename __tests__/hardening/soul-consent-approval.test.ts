/**
 * SOUL-CONSENT reported "High-risk capabilities present without
 * consent/authorization constraints" on SOUL files that make risky actions
 * wait on the user's explicit approval or confirmation, because it read only
 * the words "consent" and "authorize". Those approval phrasings are a consent
 * mechanism; negated ones ("does not require approval") are not.
 */

import { describe, it, expect } from 'vitest';
import * as fsp from 'fs/promises';
import * as path from 'path';
import { HardeningScanner } from '../../src/hardening/scanner';
import { tempDir } from '../helpers/temp-dir';

const CAPABILITY = 'I can execute shell commands, write files and access the internet.';

async function consentFindings(soul: string): Promise<any[]> {
  const root = tempDir('soul-consent-approval-');
  await fsp.writeFile(path.join(root, 'SOUL.md'), soul);
  const drafts: any[] = await (new HardeningScanner() as any).checkSoulGovernanceGaps(root);
  return drafts.filter((f) => f.checkId === 'SOUL-CONSENT');
}

const soulWith = (rule: string): string => `# Soul\n\n## Capabilities\n${CAPABILITY}\n\n## Rules\n${rule}\n`;

describe('SOUL-CONSENT reads approval and confirmation requirements as consent', () => {
  it.each([
    'I require explicit user approval before any risky action.',
    'Risky actions require the user\'s explicit confirmation.',
    'Before deleting anything I ask the user to confirm.',
    'I always prompt the user for approval before running a shell command.',
    'Explicit approval is required before I write files.',
    'User confirmation is required for every destructive operation.',
    'The user must explicitly approve each shell command.',
    'Every file write must be approved by the user.',
    'Never run shell commands without explicit user approval.',
    'I do not delete files until the user confirms.',
    'I wait for human approval before acting.',
    'I confirm with the user before any irreversible action.',
  ])('no finding for: %s', async (rule) => {
    expect(await consentFindings(soulWith(rule))).toEqual([]);
  });

  it.each([
    'I do not require approval before running shell commands.',
    'No confirmation is needed for file writes.',
    'No user approval required.',
    'I act without user approval.',
    'I never ask the user to confirm.',
    'Be helpful and fast.',
  ])('still reports for: %s', async (rule) => {
    const findings = await consentFindings(soulWith(rule));
    expect(findings.map((f) => f.message)).toEqual([
      'High-risk capabilities present without consent/authorization constraints',
    ]);
  });
});

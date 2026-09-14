/**
 * `secure` reports a credential VALUE inside a skill body (SKILL-025).
 *
 * Measured on 0.32.0: five vendor-shaped tokens (an Anthropic key, an AWS
 * access key id, a Slack bot token, a GitHub token, a JWT bearer) placed in
 * `.claude/skills/<name>/SKILL.md` were each reported `benign` with no
 * credential finding, while the same shapes in `.mcp.json` env blocks were
 * CRITICAL. `SKILL-005` looks for credential FILE references (`~/.aws`,
 * `.env`) and no skill check read the body for a credential itself.
 *
 * What this pins:
 *   - positive: a skill body holding a vendor-shaped key raises SKILL-025 at
 *     CRITICAL with the file and line, and the message does not repeat the
 *     value;
 *   - negative: the benign skill from the single-file-target suite raises no
 *     SKILL-025, so the check is not a second source of false positives.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { HardeningScanner } from '../../src/hardening/scanner';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

/** Shaped like the real thing, obviously not real. */
const FAKE_ANTHROPIC = ['sk', '-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEAA'].join('');

const SKILL_WITH_KEY = `---
name: reconcile-ledger
description: Reconciles invoices against the ledger
---

# Reconcile ledger

Call the accounting API with the token below when the export is stale.

ANTHROPIC_API_KEY: ${FAKE_ANTHROPIC}

Then re-run the reconciliation.
`;

const BENIGN_SKILL = `---
name: format-markdown
description: Normalizes heading levels in a markdown file
---

# Format markdown

Reads the file passed to it, applies formatting, writes the result back.

## Denied Actions
- No network access
- No shell execution
`;

type Finding = { checkId: string; severity: string; passed: boolean; file?: string; line?: number; message: string };

describe('SKILL-025 credential value in a skill body', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma-skill-cred-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  async function scanWithSkill(body: string): Promise<Finding[]> {
    const skillDir = path.join(tempDir, '.claude', 'skills', 'reconcile-ledger');
    await fs.mkdir(skillDir, { recursive: true });
    await fs.writeFile(path.join(skillDir, 'SKILL.md'), body);
    await fs.writeFile(path.join(tempDir, 'package.json'), '{"name":"fixture","version":"1.0.0"}\n');
    const result = await scanner.scan({ targetDir: tempDir, autoFix: false });
    return ((result.allFindings || result.findings || []) as Finding[]).filter((f) => !f.passed);
  }

  it('positive: a vendor-shaped key in SKILL.md is CRITICAL with file and line, value withheld', async () => {
    const findings = await scanWithSkill(SKILL_WITH_KEY);
    const hit = findings.find((f) => f.checkId === 'SKILL-025');
    expect(hit, `no SKILL-025 among: ${findings.map((f) => f.checkId).join(', ')}`).toBeTruthy();
    expect(hit!.severity).toBe('critical');
    expect(hit!.file).toBe(path.join('.claude', 'skills', 'reconcile-ledger', 'SKILL.md'));
    expect(hit!.line).toBe(10);
    expect(hit!.message).not.toContain('FAKEFAKE');
  });

  it('negative: a benign skill raises no SKILL-025', async () => {
    const findings = await scanWithSkill(BENIGN_SKILL);
    expect(findings.find((f) => f.checkId === 'SKILL-025')).toBeUndefined();
  });

  it('negative: hyphenated slugs after a word ending in "sk" are prose, not an OpenAI legacy key', async () => {
    // The unanchored vendor alternation read a slug like "risk-assessment-
    // framework" as the OpenAI legacy shape (`sk-` plus twenty slug
    // characters) and raised an unfixable CRITICAL on a benign skill (0.33.0
    // pre-push review). The anchored form requires no letter or digit before
    // `sk`. The slugs are assembled from halves so that no line of this file
    // is itself token-shaped for the repository's token-shape guard.
    const slugs = [
      ['risk-assess', 'ment-framework'].join(''),
      ['flask-sqlal', 'chemy-integration'].join(''),
      ['task-manage', 'ment-checklist-v2'].join(''),
      ['desk-booki', 'ng-service-config'].join(''),
    ];
    const body = `---\nname: ${slugs[0]}\ndescription: Scores a ${slugs[2]} against the ${slugs[1]} ${slugs[3]}.\n---\n# Risk\n\nRead the repo and report.\n`;
    const findings = await scanWithSkill(body);
    expect(findings.find((f) => f.checkId === 'SKILL-025')).toBeUndefined();
  });

  it('positive: an sk- placeholder that is shaped like a key still counts', async () => {
    const body = `---\nname: reconcile\n---\n# Reconcile\n\nexport OPENAI_API_KEY=sk-${'x'.repeat(24)}\n`;
    const findings = await scanWithSkill(body);
    expect(findings.find((f) => f.checkId === 'SKILL-025')).toBeTruthy();
  });
});

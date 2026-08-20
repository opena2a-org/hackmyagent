import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { join } from 'node:path';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';

import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';

// ============================================================================
// #535 — every file that carries a finding is reported under its own path.
//
// `deduplicateFindings` grouped failed AST findings by checkId ALONE, so one
// representative survived for the WHOLE scan and every other file's finding
// became a text suffix on the survivor's `details.evidence` — a field no
// renderer and no scorer reads. A repo with a hardcoded secret in five files
// reported one file, and scored the same as a repo with one.
//
// The issue was filed as ".mjs is not scanned". That diagnosis is wrong: the
// survivor is simply whichever file the walk reaches first, so the symptom
// inverts on rename. Both directions are pinned below so a future change
// cannot fix one spelling and leave the class.
// ============================================================================

function credentialSource(): string {
  // A distinct high-entropy secret per call. Two files never share a value, so
  // nothing here can pass by value-deduplication.
  return [
    '// build helper',
    `const API_KEY = "sk-ant-api03-${randomBytes(32).toString('hex')}";`,
    '',
  ].join('\n');
}

describe('#535 per-file finding attribution', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'hma-535-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  /** Write two sibling files, each with its own distinct secret, and scan. */
  async function scanSiblings(first: string, second: string) {
    await mkdir(join(tempDir, 'scripts'), { recursive: true });
    await writeFile(join(tempDir, 'scripts', first), credentialSource());
    await writeFile(join(tempDir, 'scripts', second), credentialSource());

    const result = await runNanoMindScan(tempDir, []);
    const credFiles = (findings: Array<{ checkId: string; passed: boolean; file?: string }>) =>
      findings
        .filter(f => !f.passed && f.checkId === 'AST-CRED-001')
        .map(f => f.file ?? '')
        .sort();

    return {
      analysed: credFiles(result.astFindings),
      reported: credFiles(result.mergedFindings),
    };
  }

  it('reports both siblings when the .js is walked first (the shape filed as #535)', async () => {
    const { analysed, reported } = await scanSiblings('alpha.js', 'beta.mjs');

    // Control: the analyzers see both. If this fails the defect has moved
    // upstream into discovery or routing and the assertion below is vacuous.
    expect(
      analysed,
      `Both files must be ANALYSED before attribution can be tested. Got: ${analysed.join(', ')}`,
    ).toHaveLength(2);

    expect(
      reported,
      `Both files carry a distinct hardcoded secret, so both must be REPORTED with their own path. `
        + `Got: ${reported.join(', ') || '(none)'}`,
    ).toEqual(['scripts/alpha.js', 'scripts/beta.mjs']);
  });

  it('reports both siblings when the .mjs is walked first (the symptom inverts on rename)', async () => {
    const { analysed, reported } = await scanSiblings('aaa.mjs', 'zzz.js');

    expect(
      analysed,
      `Both files must be ANALYSED before attribution can be tested. Got: ${analysed.join(', ')}`,
    ).toHaveLength(2);

    // On the unfixed code THIS arm loses the .js, not the .mjs — which is what
    // proves the extension was never the variable.
    expect(
      reported,
      `Walk order must not decide which file is reported. Got: ${reported.join(', ') || '(none)'}`,
    ).toEqual(['scripts/aaa.mjs', 'scripts/zzz.js']);
  });

  it('keeps the within-file rollup: one artifact does not emit duplicate rows for one check', async () => {
    // The rollup exists for a real reason — a single check firing many times
    // inside ONE artifact must not flood the report. Fixing the cross-file
    // collapse must not delete that. Without this, "fix" by removing
    // deduplicateFindings entirely would pass the two tests above.
    const skillNoConstraints = `---
description: Admin power tool
capabilities:
  - db.delete
  - file.write
  - api.call
  - shell.execute
---
A powerful tool that does anything you ask.`;
    await writeFile(join(tempDir, 'admin.skill.md'), skillNoConstraints);

    const result = await runNanoMindScan(tempDir, []);
    const onSkill = result.mergedFindings.filter(
      f => !f.passed && f.file?.includes('admin.skill.md'),
    );

    const perCheck = new Map<string, number>();
    for (const f of onSkill) perCheck.set(f.checkId, (perCheck.get(f.checkId) ?? 0) + 1);
    const duplicated = [...perCheck.entries()].filter(([, n]) => n > 1);

    expect(
      duplicated,
      `One artifact must yield at most one row per checkId. Duplicated: ${
        duplicated.map(([id, n]) => `${id} x${n}`).join(', ')
      }`,
    ).toHaveLength(0);
  });
});

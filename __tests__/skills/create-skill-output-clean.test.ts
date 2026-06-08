/**
 * Regression: `hackmyagent create-skill <description>` must produce a SKILL.md
 * + SOUL.md + manifest.json that pass `hackmyagent secure` with ZERO HIGH or
 * CRITICAL findings.
 *
 * Why this exists (HMA 0.23.6 release-test P1):
 *
 *   P1-4 (CREATE-SKILL SCAFFOLD FAILS OWN SCAN). In 0.23.5 a freshly-generated
 *   skill scored 61/100 with 5 HIGH findings on the very next `hackmyagent
 *   secure simple-greeting-skill/` invocation — the tool's own "getting
 *   started" path immediately told the user their just-created skill was
 *   "Not safe as-is". This is a CISO Rule 11 dead-end: the documented next
 *   step contradicted the displayed verdict.
 *
 *   P1-2 (HARDEN-SOUL -> SECURE RECOMMENDATION LOOP). The HIGH findings on
 *   the scaffold cited `hackmyagent harden-soul .` as their Fix line, but
 *   running harden-soul on the scaffold made the score WORSE (61 -> 52) and
 *   re-fired the same checkIds with the same harden-soul citation. Another
 *   CISO Rule 11 dead-end.
 *
 * Both bugs traced to a common root cause: the constraint extractor only
 * classified constraints by the constraint TEXT, ignoring the markdown
 * section heading. Constraints under `## Trust Hierarchy`, `## Override
 * Resistance`, etc. all collapsed to `general`, so the governance analyzer
 * reported the critical domains as missing even when they were plainly
 * declared. The fix (section-aware domain classifier + bullet-line period
 * normalization + correct `cannot` enforceability) is in
 * `semantic-compiler.ts`. The create-skill SOUL.md template was also widened
 * to include `## Credential Management` and `## Human Oversight` so the 5
 * critical governance domains are all covered.
 *
 * Locked-in invariants:
 *   1. A fresh create-skill scaffold scans with ZERO high/critical findings.
 *   2. After running `harden-soul` on the scaffold, the rescan still has
 *      ZERO high/critical findings (no new HIGH appearing, no recurrence of
 *      the original HIGH).
 *   3. The generated SOUL.md's extracted constraints cover all 5 critical
 *      governance domains (trust_hierarchy, human_oversight, data_handling,
 *      capability_boundary, credential_management).
 *
 * Do NOT loosen this test by reducing the assertion to "zero CRITICAL only"
 * or by removing the harden-soul step. The harden-soul loop check is the
 * defining condition that distinguishes P1-2 from a passing scaffold.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { writeSkill } from '../../src/skills/builder';
import { HardeningScanner } from '../../src/hardening/scanner';
import { SoulScanner } from '../../src/soul/scanner';
import { extractDeclaredConstraints } from '../../src/nanomind-core/compiler/semantic-compiler';

describe('create-skill output passes its own secure scan (P1-4 / P1-2 regression)', () => {
  let scanner: HardeningScanner;
  let tempDir: string;
  let skillDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hma-create-skill-regression-'));
    const result = writeSkill({
      purpose: 'a simple greeting skill',
      outputDir: path.join(tempDir, 'greeting-skill'),
    });
    skillDir = path.join(tempDir, 'greeting-skill');
    // Sanity: the three files must exist.
    expect(result.filesWritten).toHaveLength(3);
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  it('fresh create-skill output: zero HIGH or CRITICAL findings', async () => {
    const result = await scanner.scan({ targetDir: skillDir });
    const high = result.findings.filter(f => f.severity === 'high' || f.severity === 'critical');
    expect(
      high,
      `Fresh create-skill scaffold must scan with zero HIGH/CRITICAL findings. Got: ${high.map(f => `${f.checkId}(${f.severity})@${f.file}: ${f.message}`).join('; ')}`,
    ).toHaveLength(0);
  });

  it('harden-soul → rescan: still zero HIGH or CRITICAL findings (no dead-end loop)', async () => {
    // Step 1: run harden-soul, which is the suggested fix the analyzer was
    // citing in the original P1-2 release-test report. After my 0.23.6 fix
    // the analyzer no longer cites harden-soul on a healthy scaffold — but
    // if a user still runs it, the rescan must not REGRESS (no new HIGH,
    // no recurrence of the AST-GOV-001 / AST-PROMPT-004 chain).
    const soulScanner = new SoulScanner();
    await soulScanner.hardenSoul(skillDir);

    const result = await scanner.scan({ targetDir: skillDir });
    const high = result.findings.filter(f => f.severity === 'high' || f.severity === 'critical');
    expect(
      high,
      `Post-harden-soul rescan must keep zero HIGH/CRITICAL. Got: ${high.map(f => `${f.checkId}(${f.severity})@${f.file}: ${f.message}`).join('; ')}`,
    ).toHaveLength(0);

    // Lock in the specific baseline checkIds that 0.23.5 used to fire HIGH
    // on this same scaffold. A future regression that downgrades the same
    // bug to MEDIUM would silently pass the "zero HIGH" assertion above —
    // this assertion is the lock that catches that. Per adversarial review
    // category 5 (test depth).
    const baselineHighCheckIds = [
      'SOUL-OVERRIDE-001',
      'AST-GOV-001',
      'AST-GOV-002',
      'AST-PROMPT-004',
      // AST-GOVERN-001 removed: consolidated into governance-analyzer AST-GOV-002.
      // Non-emission is guarded directly in capability-analyzer.test.ts.
      'LIFECYCLE-001',
    ];
    const allCheckIds = result.findings.map(f => f.checkId);
    for (const checkId of baselineHighCheckIds) {
      const matches = result.findings.filter(f => f.checkId === checkId && (f.severity === 'high' || f.severity === 'critical'));
      expect(
        matches.length,
        `${checkId} must not fire HIGH/CRITICAL after harden-soul on the scaffold (0.23.5 baseline). Got: ${matches.map(m => m.message).join('; ')}. All checkIds: ${[...new Set(allCheckIds)].join(', ')}`,
      ).toBe(0);
    }
  });

  it('generated SOUL.md covers all 5 critical governance domains', async () => {
    const soulContent = await fs.readFile(path.join(skillDir, 'SOUL.md'), 'utf-8');
    const constraints = extractDeclaredConstraints(soulContent);
    const domains = new Set(constraints.map(c => c.domain));

    const critical = [
      'trust_hierarchy',
      'human_oversight',
      'data_handling',
      'capability_boundary',
      'credential_management',
    ] as const;
    const missing = critical.filter(d => !domains.has(d));
    expect(
      missing,
      `Generated SOUL.md must cover all 5 critical domains. Missing: ${missing.join(', ')}. Domains seen: ${[...domains].join(', ')}. Constraints extracted: ${constraints.length}.`,
    ).toEqual([]);
  });

  it('generated SOUL.md emits at most 1 "unless"-style escape clause (does not trigger SOUL-ESCAPE-CLAUSE)', async () => {
    // SOUL-ESCAPE-CLAUSE fires when 2+ constraints use "X unless Y" phrasing.
    // The 0.23.5 -> 0.23.6 fix rephrased the Data Handling / Capability
    // Boundaries bullets to avoid the duplicate "unless" pattern. This test
    // locks that in: if a future template edit re-introduces a second
    // "unless"-bounded constraint, SOUL-ESCAPE-CLAUSE will fire and the
    // scaffold will be back to "fails own scan" UX.
    const soulContent = await fs.readFile(path.join(skillDir, 'SOUL.md'), 'utf-8');
    const escapes = Array.from(
      soulContent.matchAll(/\b(will not|must not|shall not|should not|cannot|forbidden|prohibited)[^.]{0,120}unless\b/gi),
    );
    expect(
      escapes.length,
      `Generated SOUL.md must not stack "unless" escape clauses. Found ${escapes.length}: ${escapes.map(m => m[0]).join(' | ')}`,
    ).toBeLessThan(2);
  });
});

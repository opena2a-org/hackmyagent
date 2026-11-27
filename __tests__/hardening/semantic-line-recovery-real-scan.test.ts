/**
 * The semantic -> SecurityFinding boundary recovers a finding's line, pinned
 * through a REAL scan (#368, #496).
 *
 * WHY THIS FILE EXISTS. `__tests__/cli/finding-line-wiring.test.ts` pins the
 * semantic boundary at the adapter, with a constructed finding and a reader
 * the test supplies. That shows the adapter uses a reader when it is handed
 * one; it cannot show that `HardeningScanner` hands it one. Dropping the
 * `(file) => this.readArtifactForCitation(targetDir, file)` argument at either
 * `toSecurityFindings` call site in `src/hardening/scanner.ts` left that file
 * green.
 *
 * Every scan here is `new HardeningScanner().scan(...)` over a real
 * `.claude/settings.json` written to a temp directory. Nothing hands the
 * conversion a reader: the only reader is the scanner's own, reading the
 * fixture's bytes from disk.
 *
 *   - Layer 2 runs unstubbed. `SEM-PERM-002` and `SEM-PERM-003` come out of
 *     the real `PermissionModelAnalyzer` quoting the allow entry they matched
 *     and carrying no line, so the line asserted below can only come from the
 *     scanner reading the file at the conversion.
 *   - Layer 3 cannot run here without a provider, so `LLMAnalyzer` is replaced
 *     (no request leaves the machine) by one that reports a finding of that
 *     same shape on the file it was handed. The conversion after it, and its
 *     reader, are the scanner's own.
 *
 * Expected lines are DERIVED from the fixture's bytes, never read back out of
 * scanner output.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { tempDir } from '../helpers/temp-dir';

import type { SemanticFinding } from '../../src/semantic/types';

const FILE = '.claude/settings.json';

const BASH_TRIGGER = '"Bash(*)"';
const WRITE_TRIGGER = '"Write(/home/**)"';

const SETTINGS = [
  '{',                        // 1
  '  "permissions": {',       // 2
  '    "allow": [',           // 3
  '      "Read",',            // 4
  `      ${BASH_TRIGGER},`,   // 5
  `      ${WRITE_TRIGGER}`,   // 6
  '    ]',                    // 7
  '  }',                      // 8
  '}',                        // 9
  '',
].join('\n');

/** Derived, not copied: the 1-based line `trigger` sits on. */
const lineOf = (trigger: string): number =>
  SETTINGS.split('\n').findIndex((l) => l.includes(trigger)) + 1;

/** Files Layer 3 was handed, and whether the stub should report on them. */
const layer3 = { handed: [] as string[], report: false };

vi.mock('../../src/semantic', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/semantic')>();
  class ShapedLLMAnalyzer {
    constructor(_opts: unknown) {}
    async analyze(files: { path: string }[]) {
      const paths = (files ?? []).map((f) => f.path);
      layer3.handed.push(...paths);
      const findings: SemanticFinding[] = layer3.report
        ? paths.filter((p) => p === FILE).map((p) => ({
            id: 'SEM-LLM-001',
            title: 'Unrestricted shell grant',
            description: 'The agent may run any shell command.',
            rationale: 'Prompt injection reaches an unrestricted shell.',
            category: 'permission' as SemanticFinding['category'],
            severity: 'high' as SemanticFinding['severity'],
            file: p,
            recommendation: 'Restrict Bash to the commands the project needs.',
            layer: 3 as const,
            autoFixable: false,
            // The text, and no usable line: `n: 0` is not a 1-based line.
            evidence: { kind: 'positive' as const, lines: [{ n: 0, content: BASH_TRIGGER, why: 'unrestricted Bash' }] },
          }))
        : [];
      return { findings, cost: 0, cachedResults: 0, unanalyzed: [] };
    }
  }
  return { ...actual, LLMAnalyzer: ShapedLLMAnalyzer };
});

import { HardeningScanner } from '../../src/hardening/scanner';
import { PermissionModelAnalyzer } from '../../src/semantic/structural/permission-model';

let dir: string;

beforeEach(() => {
  dir = tempDir('hma-496-semline-');
  mkdirSync(path.join(dir, '.claude'));
  writeFileSync(path.join(dir, FILE), SETTINGS);
  layer3.handed.length = 0;
  layer3.report = false;
});

describe('#496 the fixture supports the claim', () => {
  it('carries each trigger exactly once, and NOT on line 1', () => {
    // The directions this pin could rot in:
    //   - present at all: otherwise the assertions compare undefined to 0;
    //   - exactly once: `resolveFindingLine` refuses an ambiguous trigger;
    //   - not line 1: a mutant returning a constant 1 must not pass;
    //   - on different lines: a mutant citing one trigger for both must not pass.
    for (const trigger of [BASH_TRIGGER, WRITE_TRIGGER]) {
      expect(lineOf(trigger)).toBeGreaterThan(1);
      expect(SETTINGS.split(trigger).length - 1).toBe(1);
    }
    expect(lineOf(BASH_TRIGGER)).not.toBe(lineOf(WRITE_TRIGGER));
  });

  it('the analyzer reports both findings with the entry as written and no line of its own', () => {
    // Non-vacuity for the scans below: the line they assert is not one the
    // analyzer computed.
    const found = new PermissionModelAnalyzer().analyze([
      { path: FILE, type: 'claude_settings', content: SETTINGS } as never,
    ]);
    const byId = new Map(found.map((f) => [f.id, f]));
    for (const [id, trigger] of [['SEM-PERM-002', BASH_TRIGGER], ['SEM-PERM-003', WRITE_TRIGGER]] as const) {
      const f = byId.get(id);
      expect(f, `${id} must fire on the fixture`).toBeDefined();
      expect(f!.line).toBeUndefined();
      expect(f!.evidence).toMatchObject({ kind: 'positive', lines: [{ n: 0, content: trigger }] });
    }
  });
});

describe('#496 a real scan: the Layer 2 call site hands the conversion the scanner\'s reader', () => {
  it('SEM-PERM-002 and SEM-PERM-003 arrive with the line of the allow entry each one quotes', async () => {
    const result = await new HardeningScanner().scan({ targetDir: dir });

    for (const [id, trigger] of [['SEM-PERM-002', BASH_TRIGGER], ['SEM-PERM-003', WRITE_TRIGGER]] as const) {
      const scope = result.findings.filter((f) => f.checkId === id && !f.passed);
      expect(scope, `${id} must fire on the fixture`).toHaveLength(1);
      expect(scope[0].file).toBe(FILE);
      // THE PIN. The finding left the analyzer with no line, so this number
      // can only come from the scanner reading the fixture at the conversion.
      // Drop the reader argument at the Layer 2 call site and this is undefined.
      expect(scope[0].line).toBe(lineOf(trigger));
    }
  }, 120_000);
});

describe('#496 a real scan: the Layer 3 call site hands the conversion the scanner\'s reader', () => {
  let priorKey: string | undefined;

  beforeEach(() => {
    // Layer 3 is gated on a key being present. The stub never reads it and
    // sends nothing.
    priorKey = process.env.ANTHROPIC_API_KEY;
    process.env.ANTHROPIC_API_KEY = 'unused-by-the-stub';
  });

  afterEach(() => {
    if (priorKey === undefined) delete process.env.ANTHROPIC_API_KEY;
    else process.env.ANTHROPIC_API_KEY = priorKey;
  });

  it('a Layer 3 finding with no line of its own arrives with the line of its trigger', async () => {
    layer3.report = true;
    const result = await new HardeningScanner().scan({ targetDir: dir, deep: true });

    // Non-vacuity: Layer 3 ran and was handed the fixture.
    expect(layer3.handed, 'Layer 3 was not handed the fixture, so it reported nothing').toContain(FILE);

    const llm = result.findings.filter((f) => f.checkId === 'SEM-LLM-001' && !f.passed);
    expect(llm).toHaveLength(1);
    expect(llm[0].file).toBe(FILE);
    // THE PIN. Drop the reader argument at the Layer 3 call site and this is
    // undefined.
    expect(llm[0].line).toBe(lineOf(BASH_TRIGGER));
  }, 240_000);
});

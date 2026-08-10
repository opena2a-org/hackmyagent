/**
 * Fix text must not carry the scanning machine's absolute path (#368, round 5).
 *
 * A revision of #286 threaded the scan root into `fix-generator`, so the fix
 * string's trailing `Verify: hackmyagent secure <dir>` and its `harden-soul`
 * citations resolved against it. In the terminal that changed nothing for a
 * top-level artifact — `completeTargetlessCitations` in `src/cli-prefix.ts`
 * already rewrites a lone `.` to the citation target, and that rewriter is
 * documented "Human-readable text only — never call this on JSON / SARIF
 * output". What it DID change was the machine formats, which carried no
 * absolute path at all before it. Measured on one fixture, before -> after:
 * sarif 0 -> 5, html 0 -> 5, json 0 -> 10.
 *
 * `-f html` is described in `secure --help` as a shareable compliance report
 * and SARIF is uploaded to the GitHub Security tab, so the disclosed value is
 * the operator's username and local tree layout, in the artifact most likely
 * to be attached to a vendor questionnaire or a public issue. It reached there
 * from `secure .` as well, so a user who never typed an absolute path still
 * shipped one.
 *
 * The threading was reverted rather than filtered per-format: the terminal
 * layer already owned absolute-path completion, and reverting removed the
 * disclosure from every channel at once instead of adding a scrubber that each
 * new output format would have to remember to call.
 *
 * THIS TEST IS THE PIN ON THE ARCHITECTURE, not on one format: it asserts the
 * generator's OUTPUT, so any future caller that hands it a root fails here
 * before the leak can reach an output channel at all.
 */
import { describe, it, expect } from 'vitest';

import { enrichFindings } from '../../src/nanomind-core/fix-generator';
import type { SecurityAST } from '../../src/nanomind-core/types';
import type { ASTFinding } from '../../src/nanomind-core/analyzers/capability-analyzer';

/** Shapes an absolute path takes on the two platforms we build for. */
const ABSOLUTE_PATH = /(?:^|[\s'"`(])(?:\/(?:Users|home|private|srv|var|tmp)\/|[A-Za-z]:\\)/;

function ast(artifactPath: string): SecurityAST {
  return {
    artifactType: 'soul',
    contentHash: 'x'.repeat(64),
    artifactPath,
    artifactSize: 100,
    declaredPurpose: 'Governs a support agent',
    declaredCapabilities: [
      { name: 'shell-exec', scope: '*', declared: true, inferred: false, riskLevel: 'critical' },
    ],
    declaredConstraints: [],
    declaredDataAccess: [],
    inferredCapabilities: [],
    inferredRiskSurface: [],
    intentClassification: 'benign',
    intentConfidence: 0.9,
    dependsOn: [],
    governedBy: [],
    evidenceSpans: [],
    signature: '',
    modelVersion: 'test',
    compiledAt: '2026-01-01T00:00:00.000Z',
  } as SecurityAST;
}

function governanceFinding(file: string): ASTFinding {
  return {
    checkId: 'AST-GOV-001',
    name: 'Missing governance constraints',
    description: 'No capability constraints are declared.',
    category: 'governance',
    severity: 'high',
    passed: false,
    message: 'governance gap',
    fixable: false,
    file,
    attackClass: 'SOUL-GAP',
  } as ASTFinding;
}

describe('#368 enrichFindings emits no absolute path in fix text', () => {
  it('a nested artifact yields a target-relative citation', () => {
    const [enriched] = enrichFindings(
      [governanceFinding('.claude/skills/x/SKILL.md')],
      ast('.claude/skills/x/SKILL.md'),
    );
    expect(enriched.fix, 'fix text is missing, so this proves nothing').toBeTruthy();
    expect(enriched.fix!).not.toMatch(ABSOLUTE_PATH);
  });

  it('a top-level artifact yields a target-relative citation', () => {
    const [enriched] = enrichFindings([governanceFinding('SOUL.md')], ast('SOUL.md'));
    expect(enriched.fix).toBeTruthy();
    expect(enriched.fix!).not.toMatch(ABSOLUTE_PATH);
  });

  it('the fixture reaches the branch: the fix really does cite a command', () => {
    // Non-vacuity. "No absolute path" is trivially true of empty text, and of
    // fix text carrying no citation at all — which is the state a future
    // refactor could arrive at while this file still reported green.
    const [enriched] = enrichFindings([governanceFinding('SOUL.md')], ast('SOUL.md'));
    expect(enriched.fix!).toMatch(/hackmyagent\s+(?:secure|harden-soul)/);
  });

  it('an absolute artifactPath is the ONLY way one appears, and it is the caller"s own input', () => {
    // Stated rather than hidden: the generator echoes what it is given. The
    // guarantee is that it INTRODUCES nothing — there is no root to join, so
    // the only absolute path reachable is one the AST already carried.
    const [enriched] = enrichFindings(
      [governanceFinding('/srv/scan/SOUL.md')],
      ast('/srv/scan/SOUL.md'),
    );
    expect(enriched.fix!).toMatch(/\/srv\/scan/);
  });
});

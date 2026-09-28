/**
 * #287 — a finding's rationale contradicted its own severity and leaked an
 * unresolved artifact type:
 *
 *     │ LOW  Credential Forwarding Detected
 *     │ data/__namespaces.json:40
 *     │ Critical in this context because this unknown may influence agent behavior or data handling.
 *
 * Two defects. The guidance is written at the detected severity and a package
 * scan lowers test-file and build-file findings to LOW afterwards, so the LOW
 * card kept a sentence calling itself critical. And `this unknown` is the
 * classifier's "no type" rendered as if it were a noun.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { guidanceAfterDemotion } from '../../src/ui/demoted-guidance';
import { SemanticCompiler } from '../../src/nanomind-core/compiler/semantic-compiler';
import type { ASTFinding } from '../../src/nanomind-core/analyzers/capability-analyzer';
import { enrichFindings } from '../../src/nanomind-core/fix-generator';

const OPENER = 'Critical in this context because this skill processes external data and can be injected via user content.';

describe('#287 guidance after a severity demotion', () => {
  it('replaces the critical opener and says why the finding is LOW', () => {
    const out = guidanceAfterDemotion(`${OPENER} Second sentence.`, 'critical', 'test');
    expect(out.startsWith('LOW here because it is in a test file, which is not a runtime attack surface (detected as CRITICAL).')).toBe(true);
    expect(out).toContain('In runtime code it would be critical because this skill processes external data');
    expect(out).toContain('Second sentence.');
    expect(out, 'a LOW card still opens a sentence with "Critical"').not.toMatch(/(^|\. )Critical /);
  });

  it('rewrites the token-pairing form of the opener too', () => {
    const out = guidanceAfterDemotion('Critical because "POST" (line 9) and "credentials" (line 9) resolve to https://x.example (line 9).', 'critical', 'build');
    expect(out).toContain('it is in a build, CI or tooling file');
    expect(out).toContain('In runtime code it would be critical because "POST" (line 9)');
    expect(out).not.toMatch(/(^|\. )Critical /);
  });

  it('keeps guidance with no severity opener and names the detected severity', () => {
    const out = guidanceAfterDemotion('Hardcoded credentials are exposed through version control.', 'high', 'test');
    expect(out).toBe('LOW here because it is in a test file, which is not a runtime attack surface (detected as HIGH). Hardcoded credentials are exposed through version control.');
  });

  it('writes the reason when there was no guidance at all', () => {
    expect(guidanceAfterDemotion(undefined, 'high', 'build')).toBe(
      'LOW here because it is in a build, CI or tooling file, which is not a runtime attack surface (detected as HIGH).',
    );
  });

  // The package-scan demotion lives in a non-exported cli.ts function that runs
  // only against a fetched package; pin that it routes through the helper.
  it('the package-scan demotion rewrites guidance before lowering severity', () => {
    const cli = readFileSync(path.resolve(__dirname, '../../src/cli.ts'), 'utf8');
    const at = cli.indexOf('function filterLocalOnlyFindings(');
    expect(at).toBeGreaterThan(-1);
    const body = cli.slice(at, cli.indexOf('\n}\n', at));
    const rewrite = body.indexOf('f.guidance = guidanceAfterDemotion(f.guidance, f.severity, reason)');
    const lower = body.indexOf("f.severity = 'low'");
    expect(rewrite, 'the demotion no longer rewrites guidance').toBeGreaterThan(-1);
    expect(rewrite, 'guidance must be rewritten while f.severity still holds the detected value').toBeLessThan(lower);
  });
});

describe('#287 critical guidance on an artifact of unknown type', () => {
  it('names a file, never "this unknown"', async () => {
    const { ast } = await new SemanticCompiler().compile('{"a": 1}\n', 'data/namespaces.json');
    const finding: ASTFinding = {
      checkId: 'AST-TEST-287',
      name: 'Synthetic critical finding',
      description: 'synthetic',
      category: 'test',
      severity: 'critical',
      passed: false,
      message: 'synthetic',
      fixable: false,
      file: 'data/namespaces.json',
      attackClass: 'CRED-EXPOSURE',
    };
    const [enriched] = enrichFindings([finding], { ...ast, artifactType: 'unknown' });
    expect(enriched.guidance).toContain('Critical in this context because this file may influence agent behavior or data handling.');
    expect(enriched.guidance).not.toContain('this unknown');
  });

  it('leaves a known artifact type as it was', async () => {
    const { ast } = await new SemanticCompiler().compile('{"a": 1}\n', '.mcp.json');
    const finding: ASTFinding = {
      checkId: 'AST-TEST-287',
      name: 'Synthetic critical finding',
      description: 'synthetic',
      category: 'test',
      severity: 'critical',
      passed: false,
      message: 'synthetic',
      fixable: false,
      file: '.mcp.json',
    };
    const [enriched] = enrichFindings([finding], { ...ast, artifactType: 'mcp_config' });
    expect(enriched.guidance).toContain('Critical in this context because this mcp_config controls tool access and can grant excessive capabilities.');
  });
});

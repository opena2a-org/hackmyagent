/**
 * #493 — AST-CRED-001's fix text quoted `ast.declaredPurpose` as if it were the
 * credential's context. On a source file that is the FIRST content line, which
 * is usually not the line the finding cites: with a build digest on line 2 and
 * the key on line 5, the finding said `config.js:5` while the fix quoted
 * `("const BUILD_SHA = "e3b0c442...")` from line 2.
 *
 * The fix text now carries no quoted context; the finding's `file:line` and
 * evidence say where the secret is. Driven through the real compiler and
 * `enrichFindings`, so a future renderer that starts quoting the purpose in
 * this branch again fails here.
 */
import { describe, it, expect } from 'vitest';
import { SemanticCompiler } from '../../src/nanomind-core/compiler/semantic-compiler';
import { enrichFindings } from '../../src/nanomind-core/fix-generator';
import type { ASTFinding } from '../../src/nanomind-core/analyzers/capability-analyzer';

/** A 64-hex build digest: not a credential, and exactly what line 2 held in the report. */
const BUILD_DIGEST = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

const SOURCE = [
  '// Build metadata',
  `const BUILD_SHA = "${BUILD_DIGEST}";`,
  '',
  '// Service configuration',
  'const SERVICE_URL = "https://api.example.invalid";',
  'module.exports = { SERVICE_URL, BUILD_SHA };',
  '',
].join('\n');

describe('#493 the CRED-EXPOSURE fix text quotes no line the finding does not cite', () => {
  it('does not quote the declared purpose (the first content line)', async () => {
    const ast = (await new SemanticCompiler().compile(SOURCE, 'src/config.js')).ast;
    // The precondition the defect needed: the purpose IS the digest line.
    expect(ast.declaredPurpose).toContain('BUILD_SHA');

    const draft: ASTFinding = {
      checkId: 'AST-CRED-001',
      name: 'Credentials in Non-Environment Context',
      description: 'probe',
      category: 'credential-exposure',
      severity: 'high',
      passed: false,
      message: 'probe',
      fixable: true,
      attackClass: 'CRED-EXPOSURE',
      file: 'src/config.js',
      line: 5,
    };
    const [enriched] = enrichFindings([draft], ast);
    const fix = enriched.fix ?? '';

    expect(fix).toContain('are exposed in version control');
    expect(fix).not.toContain('BUILD_SHA');
    expect(fix).not.toContain(BUILD_DIGEST.slice(0, 20));
    expect(fix).not.toContain('("');
  });
});

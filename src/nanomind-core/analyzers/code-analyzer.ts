/**
 * Code Analyzer -- AST-based AST-CODE-* checks
 *
 * Queries the SecurityAST for source code security issues including
 * command injection, unsafe deserialization, and path traversal.
 * Uses the structured AST to correlate code patterns with declared
 * capabilities and risk surfaces instead of regex-matching raw text.
 *
 * Checks:
 *   AST-CODE-001: Command injection (exec, spawn with user input)
 *   AST-CODE-002: Unsafe deserialization (eval, Function constructor)
 *   AST-CODE-003: Path traversal (unsanitized file paths)
 */

import type { SecurityAST, Capability, RiskSurface } from '../types.js';
import type { ASTFinding } from './capability-analyzer.js';
import { assertASTIntegrity } from '../security/defense-in-depth.js';

// ============================================================================
// Public API
// ============================================================================

/**
 * Analyze a SecurityAST for source code security issues.
 * Verifies AST integrity before processing.
 */
export function analyzeCode(
  ast: SecurityAST,
  verifier: (ast: SecurityAST) => boolean,
): ASTFinding[] {
  assertASTIntegrity(ast, verifier);

  const findings: ASTFinding[] = [];

  findings.push(...checkCommandInjection(ast));
  findings.push(...checkUnsafeDeserialization(ast));
  findings.push(...checkPathTraversal(ast));

  return findings;
}

// ============================================================================
// AST-CODE-001: Command injection
// ============================================================================

/**
 * Detects command injection vulnerabilities where user-controlled input
 * reaches shell execution functions (exec, spawn, execSync, etc.).
 *
 * Checks AST.inferredCapabilities for shell/exec capabilities and
 * AST.inferredRiskSurface for command injection attack surfaces.
 * Also checks AST.evidenceSpans for direct evidence of injection patterns.
 */
function checkCommandInjection(ast: SecurityAST): ASTFinding[] {
  const findings: ASTFinding[] = [];

  // Only relevant for source code and skill artifacts
  if (!isCodeArtifact(ast)) {
    return findings;
  }

  // Check inferred capabilities for shell execution
  const execCapabilities = ast.inferredCapabilities.filter(c =>
    isExecCapability(c),
  );

  // Check risk surfaces for command injection
  const cmdInjectionSurfaces = ast.inferredRiskSurface.filter(
    r =>
      r.attackClass === 'CMD-INJECT' ||
      r.attackClass === 'COMMAND-INJECTION' ||
      r.attackClass === 'RCE',
  );

  // Check evidence spans for exec-related patterns
  const execEvidence = ast.evidenceSpans.filter(e =>
    e.supports === 'command_injection' ||
    e.supports === 'shell_execution' ||
    e.supports === 'RCE',
  );

  // Combine signals: capabilities + risk surfaces + evidence
  if (execCapabilities.length > 0 || cmdInjectionSurfaces.length > 0) {
    // Determine if user input reaches the exec call
    const hasUserInput = hasUserInputDataFlow(ast);
    const hasExecRisk = cmdInjectionSurfaces.length > 0;

    // Exec capability with no user input = lower risk (static commands)
    // Exec capability with user input = command injection
    if (hasExecRisk || hasUserInput) {
      const bestEvidence =
        cmdInjectionSurfaces[0]?.evidence ??
        execEvidence[0]?.text ??
        execCapabilities.map(c => c.name).join(', ');

      findings.push({
        checkId: 'AST-CODE-001',
        name: 'Command Injection',
        description:
          'User-controlled input can reach shell execution functions. ' +
          'Functions like exec(), spawn(), execSync(), or child_process are called ' +
          'with data that may originate from untrusted sources (user input, tool ' +
          'outputs, retrieved documents).',
        category: 'Code Security',
        severity: 'critical',
        passed: false,
        message: `Command injection: ${truncate(bestEvidence, 80)}`,
        fixable: false,
        file: ast.artifactPath,
        fix:
          'Replace shell execution with safer alternatives: ' +
          '1. Use execFile() or spawn() with an argument array instead of exec() with string interpolation. ' +
          '2. Validate and sanitize all inputs before passing to shell commands. ' +
          '3. Use allowlists for permitted commands rather than blocklists. ' +
          '4. Consider removing shell execution entirely and using native APIs.',
        guidance:
          'Command injection is consistently rated a top vulnerability. ' +
          'Never concatenate user input into shell command strings. ' +
          'Even "harmless" commands become dangerous with shell metacharacters (;, |, $()).',
        attackClass: 'CMD-INJECT',
        confidence: hasExecRisk ? 0.9 : 0.7,
        evidence: bestEvidence,
      });
    } else if (execCapabilities.length > 0) {
      // Exec capability without detected user input -- still flag as medium
      findings.push({
        checkId: 'AST-CODE-001',
        name: 'Shell Execution Capability',
        description:
          'The code exercises shell execution capabilities. While no direct user ' +
          'input flow was detected, shell execution in an agent context is risky ' +
          'because prompt injection can influence arguments indirectly.',
        category: 'Code Security',
        severity: 'medium',
        passed: false,
        message: `Shell execution: ${execCapabilities.map(c => c.name).join(', ')}`,
        fixable: false,
        file: ast.artifactPath,
        fix:
          'Audit all shell execution calls to ensure no user-controlled data reaches them. ' +
          'Use execFile() with argument arrays instead of exec() with string concatenation. ' +
          'Add input validation for any data that flows into shell commands.',
        attackClass: 'CMD-INJECT',
        confidence: 0.5,
        evidence: execCapabilities[0]?.evidence,
      });
    }
  }

  return findings;
}

// ============================================================================
// AST-CODE-002: Unsafe deserialization
// ============================================================================

/**
 * Detects unsafe deserialization patterns including eval(), Function
 * constructor, and dynamic code execution from untrusted sources.
 *
 * Checks AST.inferredCapabilities for code execution capabilities and
 * AST.inferredRiskSurface for deserialization attack surfaces.
 * Also checks evidence spans for eval/Function patterns.
 */
function checkUnsafeDeserialization(ast: SecurityAST): ASTFinding[] {
  const findings: ASTFinding[] = [];

  if (!isCodeArtifact(ast)) {
    return findings;
  }

  // Check capabilities for dynamic code execution
  const codeExecCapabilities = ast.inferredCapabilities.filter(c =>
    isCodeExecCapability(c),
  );

  // Check risk surfaces for deserialization issues
  const deserialSurfaces = ast.inferredRiskSurface.filter(
    r =>
      r.attackClass === 'UNSAFE-DESER' ||
      r.attackClass === 'DESERIALIZATION' ||
      r.attackClass === 'CODE-EXEC' ||
      r.attackClass === 'EVAL',
  );

  // Check evidence spans
  const evalEvidence = ast.evidenceSpans.filter(e =>
    e.supports === 'unsafe_deserialization' ||
    e.supports === 'eval_usage' ||
    e.supports === 'dynamic_code_execution',
  );

  if (codeExecCapabilities.length > 0 || deserialSurfaces.length > 0 || evalEvidence.length > 0) {
    const bestEvidence =
      deserialSurfaces[0]?.evidence ??
      evalEvidence[0]?.text ??
      codeExecCapabilities.map(c => c.name).join(', ');

    const hasRiskSurface = deserialSurfaces.length > 0;
    const hasUserInput = hasUserInputDataFlow(ast);

    findings.push({
      checkId: 'AST-CODE-002',
      name: 'Unsafe Deserialization',
      description:
        'Dynamic code execution detected (eval, Function constructor, or equivalent). ' +
        'These patterns execute arbitrary code at runtime, which in an agent context ' +
        'means prompt injection can achieve remote code execution.' +
        (hasUserInput
          ? ' User-controlled data flows into the execution context.'
          : ''),
      category: 'Code Security',
      severity: hasRiskSurface || hasUserInput ? 'critical' : 'high',
      passed: false,
      message: `Unsafe deserialization: ${truncate(bestEvidence, 80)}`,
      fixable: false,
      file: ast.artifactPath,
      fix:
        'Remove eval(), new Function(), and similar dynamic code execution: ' +
        '1. Replace eval(jsonString) with JSON.parse(jsonString). ' +
        '2. Replace new Function(code) with a safe interpreter or allowlisted operations. ' +
        '3. For template evaluation, use a sandboxed template engine. ' +
        '4. Never deserialize untrusted data with eval or pickle/marshal equivalents.',
      guidance:
        'eval() is the most dangerous function in any language. In an agent context, ' +
        'it turns any prompt injection into remote code execution. There is almost ' +
        'always a safer alternative.',
      attackClass: 'UNSAFE-DESER',
      confidence: hasRiskSurface ? 0.9 : 0.7,
      evidence: bestEvidence,
    });
  }

  return findings;
}

// ============================================================================
// AST-CODE-003: Path traversal
// ============================================================================

/**
 * Detects path traversal vulnerabilities where user input controls file
 * paths without sanitization. In an agent context, prompt injection can
 * manipulate file paths to read/write outside the intended directory.
 *
 * Checks AST.inferredCapabilities for file access capabilities and
 * AST.inferredRiskSurface for path traversal attack surfaces.
 */
function checkPathTraversal(ast: SecurityAST): ASTFinding[] {
  const findings: ASTFinding[] = [];

  if (!isCodeArtifact(ast)) {
    return findings;
  }

  // Check capabilities for file operations
  const fileCapabilities = ast.inferredCapabilities.filter(c =>
    isFileCapability(c),
  );

  // Check risk surfaces for path traversal
  const pathTraversalSurfaces = ast.inferredRiskSurface.filter(
    r =>
      r.attackClass === 'PATH-TRAVERSAL' ||
      r.attackClass === 'DIR-TRAVERSAL' ||
      r.attackClass === 'FILE-ACCESS',
  );

  // Check evidence spans
  const pathEvidence = ast.evidenceSpans.filter(e =>
    e.supports === 'path_traversal' ||
    e.supports === 'unsanitized_path' ||
    e.supports === 'file_access',
  );

  // Direct path traversal risk surfaces
  if (pathTraversalSurfaces.length > 0) {
    for (const surface of pathTraversalSurfaces) {
      findings.push({
        checkId: 'AST-CODE-003',
        name: 'Path Traversal',
        description:
          `Path traversal detected: ${surface.surface}. ` +
          'User-controlled input can manipulate file paths to escape the intended ' +
          'directory, potentially reading sensitive files (/etc/passwd, .env) or ' +
          'writing to critical locations.',
        category: 'Code Security',
        severity: surface.confidence >= 0.7 ? 'critical' : 'high',
        passed: false,
        message: `Path traversal: ${truncate(surface.evidence, 80)}`,
        fixable: false,
        file: ast.artifactPath,
        fix:
          surface.mitigation ??
          'Sanitize all file paths: ' +
          '1. Use path.resolve() and verify the result is within the allowed directory. ' +
          '2. Reject paths containing ".." segments. ' +
          '3. Use path.basename() to strip directory components from user input. ' +
          '4. Maintain an allowlist of accessible directories.',
        attackClass: 'PATH-TRAVERSAL',
        confidence: surface.confidence,
        evidence: surface.evidence,
      });
    }
  }

  // File capabilities + user input but no explicit traversal surface
  if (pathTraversalSurfaces.length === 0 && fileCapabilities.length > 0) {
    const hasUserInput = hasUserInputDataFlow(ast);
    const hasWriteCapability = fileCapabilities.some(
      c => c.name.includes('write') || c.name.includes('delete') || c.name.includes('create'),
    );

    if (hasUserInput || hasWriteCapability) {
      const bestEvidence =
        pathEvidence[0]?.text ??
        fileCapabilities.map(c => c.name).join(', ');

      findings.push({
        checkId: 'AST-CODE-003',
        name: hasWriteCapability ? 'Unsanitized File Write' : 'Unsanitized File Access',
        description:
          `File ${hasWriteCapability ? 'write' : 'access'} capabilities detected ` +
          `(${fileCapabilities.map(c => c.name).join(', ')}) ` +
          (hasUserInput
            ? 'with user-controlled input in the data flow. '
            : 'in an agent context where prompt injection can influence paths. ') +
          'Without path sanitization, this creates a traversal risk.',
        category: 'Code Security',
        severity: hasWriteCapability ? 'high' : 'medium',
        passed: false,
        message: `File ${hasWriteCapability ? 'write' : 'access'} without path sanitization`,
        fixable: false,
        file: ast.artifactPath,
        fix:
          'Add path sanitization: ' +
          '1. Resolve paths with path.resolve() and check they stay within the project root. ' +
          '2. Use a chroot or sandboxed filesystem for agent operations. ' +
          '3. Reject path inputs containing "..", "~", or absolute paths from user input.',
        guidance:
          'In an agent context, path traversal is especially dangerous because prompt ' +
          'injection can craft paths like "../../../../etc/passwd" indirectly through ' +
          'tool outputs or retrieved documents.',
        attackClass: 'PATH-TRAVERSAL',
        confidence: hasUserInput ? 0.7 : 0.5,
        evidence: bestEvidence,
      });
    }
  }

  return findings;
}

// ============================================================================
// Helpers
// ============================================================================

/**
 * Determine if the artifact is a code artifact.
 *
 * Exported because it is this family's coverage gate: all three checks below
 * early-return on it, so off this set `analyzeCode` examines nothing at all.
 * The semantic coverage disclosure (#456) reads the same predicate rather than
 * keeping a second copy that could drift from it.
 */
export function isCodeArtifact(ast: SecurityAST): boolean {
  return (
    ast.artifactType === 'source_code' ||
    ast.artifactType === 'skill' ||
    ast.artifactType === 'agent_config'
  );
}

/**
 * Check if a capability represents shell execution.
 */
function isExecCapability(cap: Capability): boolean {
  const name = cap.name.toLowerCase();
  return (
    name.includes('exec') ||
    name.includes('spawn') ||
    name.includes('shell') ||
    name.includes('command') ||
    name.includes('process') ||
    name.includes('system')
  );
}

/**
 * Check if a capability represents dynamic code execution (eval-like).
 */
function isCodeExecCapability(cap: Capability): boolean {
  const name = cap.name.toLowerCase();
  const evidence = (cap.evidence ?? '').toLowerCase();
  return (
    name.includes('eval') ||
    name.includes('dynamic_code') ||
    name.includes('code_exec') ||
    name.includes('deserialize') ||
    evidence.includes('eval(') ||
    evidence.includes('new function(') ||
    evidence.includes('function(')
  );
}

/**
 * Check if a capability represents file system access.
 */
function isFileCapability(cap: Capability): boolean {
  const name = cap.name.toLowerCase();
  return (
    name.includes('file') ||
    name.includes('fs.') ||
    name.includes('read') ||
    name.includes('write') ||
    name.includes('path') ||
    name.includes('directory')
  );
}

/**
 * Check if the AST indicates user-controlled input in the data flow.
 * This is a heuristic based on data access patterns and capabilities.
 */
function hasUserInputDataFlow(ast: SecurityAST): boolean {
  // Check data access patterns for external data sources
  const hasExternalRead = ast.declaredDataAccess.some(
    d => d.accessMode === 'read' && (d.dataType === 'general' || d.dataType === 'pii'),
  );

  // Check for capabilities that accept external input
  const hasInputCapability = ast.inferredCapabilities.some(c => {
    const name = c.name.toLowerCase();
    return (
      name.includes('input') ||
      name.includes('request') ||
      name.includes('param') ||
      name.includes('query') ||
      name.includes('api')
    );
  });

  // Check risk surfaces that indicate user input flow
  const hasInputRisk = ast.inferredRiskSurface.some(
    r => r.surface.toLowerCase().includes('user input') || r.surface.toLowerCase().includes('untrusted'),
  );

  return hasExternalRead || hasInputCapability || hasInputRisk;
}

function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen - 3) + '...';
}

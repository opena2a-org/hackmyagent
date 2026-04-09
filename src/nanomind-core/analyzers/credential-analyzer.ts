/**
 * Credential Analyzer -- AST-based AST-CRED-* checks
 *
 * Queries the SecurityAST for credential exposure patterns instead of
 * regex-matching raw text. Understands data flow through AST.declaredDataAccess
 * and distinguishes real credentials from test fixtures and documentation.
 *
 * Checks:
 *   AST-CRED-001: Credentials in non-environment contexts
 *   AST-CRED-002: Credential forwarding to external destinations
 *   AST-CRED-003: Hardcoded secrets in artifact content
 */

import type { SecurityAST, DataAccessPattern, EvidenceSpan } from '../types.js';
import type { ASTFinding } from './capability-analyzer.js';
import { assertASTIntegrity } from '../security/defense-in-depth.js';

// ============================================================================
// Public API
// ============================================================================

/**
 * Analyze a SecurityAST for credential-related security issues.
 * Verifies AST integrity before processing.
 */
export function analyzeCredentials(
  ast: SecurityAST,
  verifier: (ast: SecurityAST) => boolean,
): ASTFinding[] {
  assertASTIntegrity(ast, verifier);

  const findings: ASTFinding[] = [];

  findings.push(...checkCredentialsInNonEnvContext(ast));
  findings.push(...checkCredentialForwarding(ast));
  findings.push(...checkHardcodedSecrets(ast));

  return findings;
}

// ============================================================================
// AST-CRED-001: Credentials in non-environment contexts
// ============================================================================

/**
 * Detects credential data access patterns that occur outside of proper
 * environment variable / secret manager contexts. Skills and configs
 * should reference credentials via env vars, not inline.
 *
 * Uses AST.declaredDataAccess to find credential-type data patterns
 * and checks whether the artifact type is an appropriate context.
 */
function checkCredentialsInNonEnvContext(ast: SecurityAST): ASTFinding[] {
  const findings: ASTFinding[] = [];

  // Env files and credential files are expected to contain credentials
  const safeContextTypes = new Set(['env_file', 'credential_file']);
  if (safeContextTypes.has(ast.artifactType)) {
    return findings;
  }

  const credentialAccess = ast.declaredDataAccess.filter(
    d => d.dataType === 'credentials',
  );

  if (credentialAccess.length === 0) {
    return findings;
  }

  // Check if evidence spans suggest these are documentation examples or test fixtures
  const isDocOrTest = isDocumentationOrTestContext(ast);

  for (const access of credentialAccess) {
    // Credential reads in skills/configs/source code are suspicious
    // unless the artifact is clearly documentation or test fixture
    if (isDocOrTest) {
      continue;
    }

    const severity = deriveSeverity(access, ast);

    findings.push({
      checkId: 'AST-CRED-001',
      name: 'Credentials in Non-Environment Context',
      description:
        `Credential data (${access.accessMode}) detected in a ${ast.artifactType} artifact. ` +
        'Credentials should only be referenced via environment variables or secret managers, ' +
        'never embedded in skills, configs, or source code.',
      category: 'Credential Security',
      severity,
      passed: false,
      message: `Credential ${access.accessMode} in ${ast.artifactType} context`,
      fixable: false,
      file: ast.artifactPath,
      fix:
        'Replace inline credentials with environment variable references (e.g., $API_KEY or process.env.API_KEY). ' +
        'Use a secret manager for production deployments.',
      guidance:
        'Credentials embedded in non-env artifacts can be leaked through version control, ' +
        'logs, or prompt injection attacks that extract artifact content.',
      attackClass: 'CRED-EXPOSURE',
      confidence: isDocOrTest ? 0.3 : 0.8,
    });
  }

  return findings;
}

// ============================================================================
// AST-CRED-002: Credential forwarding patterns
// ============================================================================

/**
 * Detects credentials being transmitted to external destinations.
 * Cross-references AST.declaredDataAccess (transmit mode) with
 * credential data types to find forwarding patterns.
 */
function checkCredentialForwarding(ast: SecurityAST): ASTFinding[] {
  const findings: ASTFinding[] = [];

  // Find credential data that is transmitted externally
  // Direct: credentials type with transmit mode
  const directCredTransmit = ast.declaredDataAccess.filter(
    d => d.dataType === 'credentials' && d.accessMode === 'transmit',
  );
  // Indirect: credentials type (read) combined with any transmit pattern
  const hasCredentialAccess = ast.declaredDataAccess.some(
    d => d.dataType === 'credentials',
  );
  const hasExternalTransmit = ast.declaredDataAccess.some(
    d => d.accessMode === 'transmit',
  );
  const hasExfilRisk = ast.inferredRiskSurface.some(
    r => r.attackClass === 'SKILL-EXFIL' || r.attackClass === 'DATA-EXFIL',
  );

  // Combine direct transmissions with indirect patterns
  const credentialTransmissions: Array<{ destination: string }> = [];
  for (const d of directCredTransmit) {
    credentialTransmissions.push({ destination: d.destination ?? 'unknown endpoint' });
  }
  // If credentials are accessed AND there's external transmission, flag it
  if (directCredTransmit.length === 0 && hasCredentialAccess && hasExternalTransmit) {
    credentialTransmissions.push({ destination: 'external endpoint' });
  }
  // If credentials are accessed AND there's an exfiltration risk surface
  if (directCredTransmit.length === 0 && credentialTransmissions.length === 0 && hasCredentialAccess && hasExfilRisk) {
    credentialTransmissions.push({ destination: 'external (inferred from exfiltration risk)' });
  }

  for (const transmission of credentialTransmissions) {
    const destination = transmission.destination;

    // Cross-check with risk surfaces for corroboration
    const corroboratingRisk = ast.inferredRiskSurface.find(
      r => r.attackClass === 'CRED-HARVEST' || r.attackClass === 'SKILL-EXFIL',
    );

    const confidence = corroboratingRisk
      ? Math.max(corroboratingRisk.confidence, 0.8)
      : 0.7;

    findings.push({
      checkId: 'AST-CRED-002',
      name: 'Credential Forwarding Detected',
      description:
        `Credentials are being transmitted to ${destination}. ` +
        'Credential forwarding is a primary exfiltration vector. ' +
        'Even legitimate logging must never include credential values.',
      category: 'Credential Security',
      severity: 'critical',
      passed: false,
      message: `Credential forwarding to ${destination}`,
      fixable: false,
      file: ast.artifactPath,
      fix:
        `Remove credential transmission to ${destination}. ` +
        'If external auth is needed, use OAuth token exchange or a credential broker. ' +
        'Never forward raw credentials.',
      guidance:
        'Credential forwarding enables account takeover. Even forwarding to "trusted" ' +
        'endpoints is risky because the destination can be compromised or spoofed.',
      attackClass: 'CRED-EXFIL',
      confidence,
      evidence: corroboratingRisk?.evidence,
    });
  }

  // Also check: capabilities that imply credential forwarding
  const forwardingCaps = ast.inferredCapabilities.filter(
    c =>
      c.name.includes('send') || c.name.includes('transmit') || c.name.includes('forward'),
  );

  for (const cap of forwardingCaps) {
    const mentionsCredentials =
      cap.evidence?.toLowerCase().includes('credential') ||
      cap.evidence?.toLowerCase().includes('token') ||
      cap.evidence?.toLowerCase().includes('secret') ||
      cap.evidence?.toLowerCase().includes('password');

    if (mentionsCredentials) {
      // Avoid duplicates -- only add if we didn't already find a direct transmission
      if (credentialTransmissions.length === 0) {
        findings.push({
          checkId: 'AST-CRED-002',
          name: 'Credential Forwarding Detected',
          description:
            `Inferred capability "${cap.name}" involves credential data. ` +
            'This pattern suggests credentials may be forwarded externally.',
          category: 'Credential Security',
          severity: 'high',
          passed: false,
          message: `Inferred credential forwarding via ${cap.name}`,
          fixable: false,
          file: ast.artifactPath,
          fix:
            'Remove or restrict the capability that forwards credential data. ' +
            'Use environment variable references instead of passing credential values.',
          attackClass: 'CRED-EXFIL',
          confidence: 0.6,
          evidence: cap.evidence,
        });
      }
    }
  }

  return findings;
}

// ============================================================================
// AST-CRED-003: Hardcoded secrets in artifact content
// ============================================================================

/**
 * Detects evidence of hardcoded secrets in the artifact by examining
 * evidence spans and risk surfaces for credential patterns.
 * Distinguishes real secrets from test fixtures (containing "FAKE",
 * "EXAMPLE", "test", "placeholder") and documentation examples.
 */
function checkHardcodedSecrets(ast: SecurityAST): ASTFinding[] {
  const findings: ASTFinding[] = [];

  // Look for evidence spans that support credential exposure
  const credentialEvidence = ast.evidenceSpans.filter(
    e =>
      e.supports === 'CRED-HARVEST' ||
      e.supports === 'CRED-EXFIL' ||
      e.supports === 'credential_exposure',
  );

  // Check risk surfaces for credential patterns
  const credentialRisks = ast.inferredRiskSurface.filter(
    r => r.attackClass === 'CRED-HARVEST',
  );

  // Combine signals
  const hasCredentialSignals =
    credentialEvidence.length > 0 || credentialRisks.length > 0;

  if (!hasCredentialSignals) {
    return findings;
  }

  // Filter out defensive constraint contexts: if the artifact has constraints
  // about credential management (e.g., "must never store credentials"), the
  // CRED-HARVEST signal is from the constraint text, not actual harvesting.
  const hasDefensiveCredConstraint = ast.declaredConstraints.some(
    c => c.domain === 'credential_management' && c.enforceability >= 0.6,
  );
  if (hasDefensiveCredConstraint && credentialEvidence.length === 0) {
    // The credential signal is likely from the constraint text, not from
    // actual credential harvesting patterns. Only risk surfaces exist,
    // and they were triggered by the constraint's mention of credentials.
    return findings;
  }

  // Filter out test fixtures and documentation
  const isTestOrDoc = isDocumentationOrTestContext(ast);
  const evidenceTexts = credentialEvidence.map(e => e.text);
  const allTestFixtures = evidenceTexts.every(t => isTestFixtureCredential(t));

  if (isTestOrDoc && allTestFixtures) {
    return findings;
  }

  // Determine severity based on artifact type and evidence strength
  const maxConfidence = Math.max(
    ...credentialEvidence.map(e => e.confidence),
    ...credentialRisks.map(r => r.confidence),
    0,
  );

  const severity: ASTFinding['severity'] =
    maxConfidence >= 0.8 ? 'critical' : maxConfidence >= 0.5 ? 'high' : 'medium';

  const evidenceSummary =
    credentialEvidence.length > 0
      ? credentialEvidence[0].text.slice(0, 120)
      : credentialRisks[0]?.evidence ?? 'Credential pattern detected';

  findings.push({
    checkId: 'AST-CRED-003',
    name: 'Hardcoded Secret Detected',
    description:
      'The artifact contains patterns consistent with hardcoded secrets. ' +
      'Hardcoded credentials are exposed in version control, build artifacts, ' +
      'and prompt injection attacks that extract artifact content.',
    category: 'Credential Security',
    severity,
    passed: false,
    message: `Hardcoded secret: ${evidenceSummary.slice(0, 80)}`,
    fixable: false,
    file: ast.artifactPath,
    fix:
      'Move all secrets to environment variables or a secret manager. ' +
      'Replace hardcoded values with references: $SECRET_NAME or process.env.SECRET_NAME. ' +
      'Rotate any credentials that were committed to version control.',
    guidance:
      'After removing hardcoded credentials, rotate them immediately. ' +
      'The old values may already be in git history or build caches.',
    attackClass: 'CRED-HARDCODED',
    confidence: allTestFixtures ? 0.3 : maxConfidence,
    evidence: evidenceSummary,
  });

  return findings;
}

// ============================================================================
// Helpers
// ============================================================================

/**
 * Determine if the artifact is a documentation example or test fixture.
 * Test fixtures contain "FAKE", "EXAMPLE", "placeholder", etc.
 * Documentation contexts reference credentials for illustration only.
 */
function isDocumentationOrTestContext(ast: SecurityAST): boolean {
  const path = (ast.artifactPath ?? '').toLowerCase();

  // Test fixtures
  if (
    path.includes('test/') ||
    path.includes('__tests__/') ||
    path.includes('fixture') ||
    path.includes('example') ||
    path.includes('.example')
  ) {
    return true;
  }

  // Documentation (but not .skill.md or .soul.md which are functional)
  // CLAUDE.md and AGENTS.md are instructions/documentation, not credential access code
  if (
    (path.endsWith('.md') &&
      !path.endsWith('.skill.md') &&
      !path.endsWith('.soul.md')) ||
    path.includes('doc/') ||
    path.includes('docs/') ||
    path.includes('readme')
  ) {
    return true;
  }

  // Lock files and env examples contain credential-like patterns but are not attack surfaces
  if (
    path.endsWith('pnpm-lock.yaml') ||
    path.endsWith('package-lock.json') ||
    path.endsWith('yarn.lock') ||
    path.endsWith('.env.example') ||
    path.endsWith('.env.sample') ||
    path.endsWith('.env.template')
  ) {
    return true;
  }

  // Check declared purpose for test/doc language
  const purpose = ast.declaredPurpose.toLowerCase();
  if (
    purpose.includes('test') ||
    purpose.includes('example') ||
    purpose.includes('documentation') ||
    purpose.includes('fixture') ||
    purpose.includes('demo')
  ) {
    return true;
  }

  return false;
}

/**
 * Check if a credential-like string is a test fixture (contains markers
 * like FAKE, EXAMPLE, placeholder, etc.)
 */
function isTestFixtureCredential(text: string): boolean {
  const upper = text.toUpperCase();
  return (
    upper.includes('FAKE') ||
    upper.includes('EXAMPLE') ||
    upper.includes('PLACEHOLDER') ||
    upper.includes('TEST') ||
    upper.includes('DUMMY') ||
    upper.includes('SAMPLE') ||
    upper.includes('XXX') ||
    upper.includes('YOUR_') ||
    upper.includes('<YOUR')
  );
}

/**
 * Derive severity from data access pattern and artifact context.
 */
function deriveSeverity(
  access: DataAccessPattern,
  ast: SecurityAST,
): ASTFinding['severity'] {
  // Transmitting credentials is always critical
  if (access.accessMode === 'transmit') return 'critical';
  // Writing credentials outside env context is high
  if (access.accessMode === 'write') return 'high';
  // Reading credentials in a skill is medium (might be legitimate env var ref)
  if (ast.artifactType === 'skill' || ast.artifactType === 'system_prompt') return 'medium';
  // Source code with credential access is high
  if (ast.artifactType === 'source_code') return 'high';
  return 'medium';
}

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
import type { ProjectType } from '../../hardening/security-check.js';
import { assertASTIntegrity } from '../security/defense-in-depth.js';
import { lineFromOffset, findLineFromString } from '../../types/text-position.js';

// ============================================================================
// Public API
// ============================================================================

/**
 * Analyze a SecurityAST for credential-related security issues.
 * Verifies AST integrity before processing.
 *
 * `artifactContent` is the raw source text the AST was compiled from. It
 * is unsigned and not part of the AST contract — callers pass it through
 * so emit sites can derive 1-based line numbers from substring offsets
 * (issue #141). When omitted, findings still emit but without a `line`
 * field; `generateVerifyCommand()` will then return undefined for them.
 */
export function analyzeCredentials(
  ast: SecurityAST,
  verifier: (ast: SecurityAST) => boolean,
  projectType?: ProjectType,
  artifactContent?: string,
): ASTFinding[] {
  assertASTIntegrity(ast, verifier);

  const findings: ASTFinding[] = [];

  findings.push(...checkCredentialsInNonEnvContext(ast, projectType));
  findings.push(...checkCredentialForwarding(ast, projectType, artifactContent));
  findings.push(...checkHardcodedSecrets(ast, artifactContent));

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
function checkCredentialsInNonEnvContext(ast: SecurityAST, projectType?: ProjectType): ASTFinding[] {
  const findings: ASTFinding[] = [];
  const isSDK = projectType === 'sdk';

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

    let severity = deriveSeverity(access, ast);

    // For SDKs, reading credentials from source code (to send to their API)
    // is expected behavior. Downgrade to low.
    if (isSDK && (access.accessMode === 'read' || access.accessMode === 'transmit')) {
      severity = 'low';
    }

    findings.push({
      checkId: 'AST-CRED-001',
      name: 'Credentials in Non-Environment Context',
      description: isSDK
        ? `[Expected SDK behavior] Credential data (${access.accessMode}) in ${ast.artifactType}. SDKs read credentials to authenticate API calls.`
        : `Credential data (${access.accessMode}) detected in a ${ast.artifactType} artifact. ` +
          'Credentials should only be referenced via environment variables or secret managers, ' +
          'never embedded in skills, configs, or source code.',
      category: 'Credential Security',
      severity,
      passed: false,
      message: `Credential ${access.accessMode} in ${ast.artifactType} context`,
      fixable: false,
      file: ast.artifactPath,
      fix: isSDK
        ? 'Expected behavior for an SDK. Credentials are read from environment variables and sent to the service API.'
        : 'opena2a protect .  — scans for hardcoded secrets and encrypts them into a secure vault. Keys are injected at runtime, never stored as plaintext.',
      guidance: isSDK
        ? 'This is expected behavior for an API client SDK. The SDK reads API keys to authenticate requests.'
        : 'Credentials embedded in non-env artifacts can be leaked through version control, ' +
          'logs, or prompt injection attacks that extract artifact content.',
      attackClass: 'CRED-EXPOSURE',
      confidence: isSDK ? 0.3 : isDocOrTest ? 0.3 : 0.8,
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
function checkCredentialForwarding(
  ast: SecurityAST,
  projectType?: ProjectType,
  artifactContent?: string,
): ASTFinding[] {
  const findings: ASTFinding[] = [];
  const isSDK = projectType === 'sdk';

  // Documentation and test files that mention credentials + external services
  // are teaching credential management, not performing credential exfiltration.
  // e.g., secretless docs/use-cases/team-setup.md references STRIPE_KEY + 1Password + CI/CD
  if (isDocumentationOrTestContext(ast)) {
    return findings;
  }

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

  // Combine direct transmissions with indirect patterns. `evidence` is a
  // verbatim substring of the artifact when available — used downstream
  // to derive the finding's `line` (issue #141). Falls back to the
  // hardcoded summary when the compiler couldn't capture a real
  // destination URL or risk-surface evidence span.
  const credentialTransmissions: Array<{ destination: string; evidence?: string }> = [];
  for (const d of directCredTransmit) {
    credentialTransmissions.push({
      destination: d.destination ?? 'unknown endpoint',
      evidence: d.destination,
    });
  }
  // If credentials are accessed AND there's external transmission, flag it.
  // Prefer the transmit pattern's actual destination URL — the compiler
  // captures it in `extractDataAccessPatterns`. Display destination stays
  // human-readable; the URL rides along as `evidence` for line-lookup.
  if (directCredTransmit.length === 0 && hasCredentialAccess && hasExternalTransmit) {
    const transmitPattern = ast.declaredDataAccess.find(
      d => d.accessMode === 'transmit' && d.destination && /^https?:\/\//i.test(d.destination),
    );
    credentialTransmissions.push({
      destination: 'external endpoint',
      evidence: transmitPattern?.destination,
    });
  }
  // If credentials are accessed AND there's an exfiltration risk surface
  if (directCredTransmit.length === 0 && credentialTransmissions.length === 0 && hasCredentialAccess && hasExfilRisk) {
    credentialTransmissions.push({ destination: 'external (inferred from exfiltration risk)' });
  }

  for (const transmission of credentialTransmissions) {
    const destination = transmission.destination;
    const transmissionEvidence = transmission.evidence;

    // Cross-check with risk surfaces for corroboration
    const corroboratingRisk = ast.inferredRiskSurface.find(
      r => r.attackClass === 'CRED-HARVEST' || r.attackClass === 'SKILL-EXFIL',
    );

    const baseConfidence = corroboratingRisk
      ? Math.max(corroboratingRisk.confidence, 0.8)
      : 0.7;

    // For SDKs, credential forwarding to the package's own API is the core
    // function. Downgrade to low severity.
    const sdkExpected = isSDK;
    const confidence = sdkExpected ? Math.min(baseConfidence, 0.3) : baseConfidence;

    findings.push({
      checkId: 'AST-CRED-002',
      name: 'Credential Forwarding Detected',
      description: sdkExpected
        ? `[Expected SDK behavior] Credentials transmitted to ${destination}. This is the core function of an API client SDK.`
        : `Credentials are being transmitted to ${destination}. ` +
          'Credential forwarding is a primary exfiltration vector. ' +
          'Even legitimate logging must never include credential values.',
      category: 'Credential Security',
      severity: sdkExpected ? 'low' : 'critical',
      passed: false,
      message: `Credential forwarding to ${destination}`,
      fixable: false,
      file: ast.artifactPath,
      // Line-lookup precedence: corroborating risk evidence (most specific
      // — usually the matched substring), then the transmission's
      // captured evidence (a verbatim URL when the compiler extracted
      // one), then the transmission destination (verbatim URL on
      // direct-transmit cases). Each is a verbatim substring of the
      // artifact when present, so indexOf finds the line. Falls through
      // to undefined if none match — renderer then omits Verify entirely.
      line:
        findLineFromString(artifactContent, corroboratingRisk?.evidence) ??
        findLineFromString(artifactContent, transmissionEvidence) ??
        findLineFromString(artifactContent, destination),
      fix: sdkExpected
        ? 'Expected behavior for an SDK. Credentials are sent to the service API over HTTPS for authentication.'
        : `Remove credential transmission to ${destination}. ` +
          'If external auth is needed, use OAuth token exchange or a credential broker. ' +
          'Never forward raw credentials.',
      guidance: sdkExpected
        ? 'This is expected behavior for an API client SDK. The SDK sends API keys over HTTPS to authenticate requests.'
        : 'Credential forwarding enables account takeover. Even forwarding to "trusted" ' +
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
          description: isSDK
            ? `[Expected SDK behavior] Inferred capability "${cap.name}" involves credential data.`
            : `Inferred capability "${cap.name}" involves credential data. ` +
              'This pattern suggests credentials may be forwarded externally.',
          category: 'Credential Security',
          severity: isSDK ? 'low' : 'high',
          passed: false,
          message: `Inferred credential forwarding via ${cap.name}`,
          fixable: false,
          file: ast.artifactPath,
          line: findLineFromString(artifactContent, cap.evidence),
          fix: isSDK
            ? 'Expected behavior for an SDK. Credentials are forwarded to the service API.'
            : 'Remove or restrict the capability that forwards credential data. ' +
              'Use environment variable references instead of passing credential values.',
          attackClass: 'CRED-EXFIL',
          confidence: isSDK ? 0.3 : 0.6,
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
function checkHardcodedSecrets(ast: SecurityAST, artifactContent?: string): ASTFinding[] {
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

  // In doc/test/manifest contexts where the CRED-HARVEST trigger fired on
  // descriptive language ("No credentials printed", "files spanning
  // credentials", "must never store credentials"), require an actual
  // credential-format pattern (sk-/ghp_/gho_ prefixes or 32+ char alpha-
  // numeric blob) in the evidence span before emitting HIGH. The previous
  // implicit gate was `credentialEvidence.length === 0`: pre-#151 the
  // evidence-span lookup silently failed for description-style risk evidence
  // and kept doc-context findings suppressed. Post-#151 the compiler emits
  // verbatim keyword spans (an activation effect of the heuristic-evidence
  // fix) and the implicit gate disengaged — re-engage it explicitly here.
  // Skill/agent files (`.skill.md`, `.soul.md`, etc.) bypass this gate and
  // continue to fire on bare-keyword harvesting language as designed.
  if (isTestOrDoc && !evidenceShowsCredentialFormat(evidenceTexts)) {
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

  // Prefer the EvidenceSpan's character offset (signed AST data) — it's
  // exact and local. Fall back to substring search on the unsigned content
  // when only a RiskSurface evidence string is available.
  const spanStart = credentialEvidence[0]?.start;
  const lineFromSpan = artifactContent !== undefined && spanStart !== undefined
    ? lineFromOffset(artifactContent, spanStart)
    : undefined;
  const fallbackLine = lineFromSpan ?? findLineFromString(artifactContent, evidenceSummary);

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
    line: fallbackLine,
    fix:
      'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only. ' +
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

  // Semantic routing / command catalog / manifest files — these describe CLI commands
  // and tool operations using security terminology (credentials, secrets, API keys)
  // in their description and tag fields. They are not storing or accessing credentials.
  const basename = path.split('/').pop() ?? '';
  if (
    basename.endsWith('-index.json') ||
    basename === 'command-index.json' ||
    basename === 'command-catalog.json' ||
    basename === 'manifest.json' ||
    basename === 'commands.json' ||
    path.includes('/semantic/') ||
    path.includes('/catalog/') ||
    path.includes('/registry/')
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
 * Detect whether any evidence span text contains an actual credential-format
 * substring. Curated multi-vendor prefixes — Anthropic / OpenAI (`sk-`),
 * Stripe (`sk_live_`/`sk_test_`), GitHub PAT (`ghp_`/`gho_`/`github_pat_`),
 * AWS access key IDs (`AKIA…`), Google API keys (`AIza…`), Slack
 * (`xox[abprs]-…`), and JWTs (`eyJ…header.payload.sig`) — plus a high-
 * entropy fallback (40+ word-character run, anchored on word boundaries,
 * excluding `-` and `/` so URL slugs and slug-style identifiers don't
 * match). Bare-keyword mentions ("credentials", "API key", "token") in
 * descriptive text do NOT count: those words appear in well-governed agent
 * docs, fixture manifests, and release-smoke walkthroughs without being
 * actual hardcoded secrets.
 */
function evidenceShowsCredentialFormat(evidenceTexts: string[]): boolean {
  return evidenceTexts.some(t =>
    new RegExp(
      [
        'sk-[a-zA-Z0-9_-]{20,}',
        'sk_live_[a-zA-Z0-9]{20,}',
        'sk_test_[a-zA-Z0-9]{20,}',
        'ghp_[a-zA-Z0-9]{20,}',
        'gho_[a-zA-Z0-9]{20,}',
        'github_pat_[a-zA-Z0-9_]{20,}',
        'AKIA[0-9A-Z]{16}',
        'AIza[0-9A-Za-z_-]{35}',
        'xox[abprs]-[0-9A-Za-z-]{10,}',
        'eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+',
        '\\b[A-Za-z0-9+=_]{40,}\\b',
      ].join('|'),
    ).test(t),
  );
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

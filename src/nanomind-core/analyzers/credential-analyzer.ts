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

import { basename } from 'node:path';
import type { SecurityAST, DataAccessPattern, DataAccessMatch, EvidenceSpan, ArtifactType } from '../types.js';
import type { ASTFinding, FindingMatch } from './capability-analyzer.js';
import { urlOrigin } from '../compiler/structured-colocation.js';
import type { ProjectType } from '../../hardening/security-check.js';
import { assertASTIntegrity } from '../security/defense-in-depth.js';
import { lineFromOffset, findLineFromString } from '../../types/text-position.js';
import {
  findCredentialFormatMatch,
  hasCredentialFormat,
  hasAnyCredentialCandidate,
  hasAnchoredVendorCredential,
  matchVendorPrefix,
} from '../../types/credential-format.js';
import { isCorpusPath, isIntegrityManifestPath } from '../../hardening/path-context.js';

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

  findings.push(...checkCredentialsInNonEnvContext(ast, projectType, artifactContent));
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
function checkCredentialsInNonEnvContext(
  ast: SecurityAST,
  projectType?: ProjectType,
  artifactContent?: string,
): ASTFinding[] {
  const findings: ASTFinding[] = [];
  const isSDK = projectType === 'sdk';

  // Env files and credential files are expected to contain credentials
  const safeContextTypes = new Set(['env_file', 'credential_file']);
  if (safeContextTypes.has(ast.artifactType)) {
    return findings;
  }

  // Unified carve-out: verified integrity manifest OR adversarial
  // training corpus, in both cases with no vendor-prefix credential
  // present. A planted real credential still fires.
  if (shouldSuppressCredentialChecks(ast.artifactPath, artifactContent, ast.artifactType)) {
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

  // Content-format gate (#164): the upstream compiler tags any artifact
  // whose lowercased content includes the substring "credential" or
  // "session" with a `dataType: 'credentials'` data-access pattern. That
  // is too noisy on host-tool config files like `.claude/settings.json`,
  // which mention credentials in *defensive* deny-rules ("Read(.aws/
  // credentials)") without containing any credential value. Require an
  // actual credential-format substring in the artifact content before
  // emitting AST-CRED-001 — vendor prefixes (`sk-`, `sk_live_`, `ghp_`,
  // `gho_`, `github_pat_`, `xox[abprs]-`, `eyJ` JWT, `AKIA…`, `AIza…`)
  // OR a high-entropy 40+ word-character run. Placeholder/reference
  // values (`$OPENAI_API_KEY`, `${OPENAI_API_KEY}`) deliberately do NOT
  // match. SDKs are also gated — flagging an SDK source file that only
  // mentions the word "credential" was the same false-positive shape.
  const credLocation = artifactContent !== undefined
    ? findFirstCredentialFormat(artifactContent)
    : undefined;
  if (!credLocation) {
    return findings;
  }

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
      line: credLocation.line,
      fix: isSDK
        ? 'Expected behavior for an SDK. Credentials are read from environment variables and sent to the service API.'
        : 'opena2a protect .  — scans for hardcoded secrets and encrypts them into a secure vault. Keys are injected at runtime, never stored as plaintext.',
      guidance: isSDK
        ? 'This is expected behavior for an API client SDK. The SDK reads API keys to authenticate requests.'
        : 'Credentials embedded in non-env artifacts can be leaked through version control, ' +
          'logs, or prompt injection attacks that extract artifact content.',
      attackClass: 'CRED-EXPOSURE',
      confidence: isSDK ? 0.3 : isDocOrTest ? 0.3 : 0.8,
      evidence: credLocation.match,
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

  // Corpus-only carve-out for transmission semantics (per [CSR-003] +
  // [CDS-023]). Labeled credential-forwarding examples in training
  // data are intentional content for the classifier to learn. The
  // manifest path is NOT exempted here — a model integrity manifest
  // has no business declaring credential-transmit patterns; if it
  // appears to, treat as a finding regardless of file name. The
  // "no vendor-prefix credential in content" gate ensures a planted
  // real credential inside corpus paths still surfaces.
  if (
    ast.artifactPath &&
    artifactContent &&
    isCorpusPath(ast.artifactPath) &&
    !hasVendorPrefixCredential(artifactContent)
  ) {
    return findings;
  }

  // Security-taxonomy / coverage documents (AgentPwn coverage.json, OASB
  // taxonomies, threat-matrix exports) describe attack CATEGORIES with security
  // vocabulary ("credential-harvest", "Credential Forwarding") in id/name fields.
  // The compiler substring-matches "credential" + "forward" inside those labels
  // and fabricates a credential-transmit pattern. Suppress only on a 'unknown'
  // (data) artifact recognized as a taxonomy schema AND carrying no credential-
  // FORMAT value (vendor prefix or 40+ char high-entropy run) — a planted secret,
  // vendor-prefixed or raw, still fires. An executable config classified as
  // mcp_config/agent_config/skill is never silenced here.
  // NOTE: this veto uses the UNFILTERED candidate predicate on purpose. The
  // test is negated — suppress only when no credential-shaped value is present
  // — so a stricter predicate makes the carve-out fire MORE often, and every
  // value the entropy floor discards becomes a place to hide a secret. A
  // taxonomy of category labels has no legitimate 40-char run at all.
  if (
    artifactContent &&
    ast.artifactType === 'unknown' &&
    isSecurityTaxonomyDocument(artifactContent) &&
    !hasAnyCredentialCandidate(artifactContent)
  ) {
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
  // to derive the finding's `line` (issue #141). `matched` carries the
  // tokens the compiler paired, so the finding can name them (#403).
  //
  // A pattern the compiler resolved structurally (JSON leaf co-location,
  // `matched.scope === 'structured'`) has already answered whether a
  // credential noun and a transmit verb share a leaf. Pairing a
  // `credentials` read from one leaf with a `transmit` from another here,
  // or with a document-wide exfiltration surface, is exactly how a
  // `$schema` pointer became a CRITICAL (#541, #403), so both indirect
  // branches are skipped once the artifact was analyzed structurally.
  const structurallyResolved = ast.declaredDataAccess.some(d => d.matched?.scope === 'structured');
  const credentialTransmissions: CredentialTransmission[] = [];
  for (const d of directCredTransmit) {
    credentialTransmissions.push({
      destination: d.destination,
      evidence: isHttpUrl(d.destination) ? d.destination : undefined,
      matched: d.matched,
    });
  }
  // If credentials are accessed AND there's external transmission, flag it.
  // Prefer the transmit pattern's actual destination URL — the compiler
  // captures it in `extractDataAccessPatterns`. The URL rides along as
  // `evidence` for line-lookup; the read pattern supplies the term.
  if (directCredTransmit.length === 0 && !structurallyResolved && hasCredentialAccess && hasExternalTransmit) {
    const transmitPattern =
      ast.declaredDataAccess.find(d => d.accessMode === 'transmit' && isHttpUrl(d.destination)) ??
      ast.declaredDataAccess.find(d => d.accessMode === 'transmit');
    const readPattern = ast.declaredDataAccess.find(d => d.dataType === 'credentials');
    credentialTransmissions.push({
      destination: isHttpUrl(transmitPattern?.destination) ? transmitPattern?.destination : undefined,
      evidence: isHttpUrl(transmitPattern?.destination) ? transmitPattern?.destination : undefined,
      matched: {
        scope: 'document',
        term: readPattern?.matched?.term,
        termOffset: readPattern?.matched?.termOffset,
        verb: transmitPattern?.matched?.verb,
        verbOffset: transmitPattern?.matched?.verbOffset,
        destinationOffset: transmitPattern?.matched?.destinationOffset,
      },
    });
  }
  // If credentials are accessed AND there's an exfiltration risk surface
  if (directCredTransmit.length === 0 && credentialTransmissions.length === 0 && !structurallyResolved && hasCredentialAccess && hasExfilRisk) {
    credentialTransmissions.push({ inferredFromRisk: true });
  }

  for (const transmission of credentialTransmissions) {
    const transmissionEvidence = transmission.evidence;
    // The destination a human reads is the ORIGIN the span resolves to.
    // Parsing is what defeats a userinfo masquerade
    // (`https://api.stripe.com'@evil.example/x` reaches evil.example), and an
    // origin never carries the path or query where a token might sit. A span
    // that does not parse is reported as unresolved, never verbatim.
    const origin = urlOrigin(transmission.destination);
    const destination = origin ?? (transmission.inferredFromRisk
      ? 'an unresolved destination (inferred from an exfiltration surface)'
      : 'an unresolved destination');
    const matched = describeMatch(transmission.matched, origin, artifactContent);
    const fileName = (ast.artifactPath && basename(ast.artifactPath)) || 'The artifact';

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
        ? sdkForwardingDescription(destination, matched)
        : forwardingDescription(fileName, destination, matched),
      category: 'Credential Security',
      severity: sdkExpected ? 'low' : 'critical',
      passed: false,
      message: forwardingMessage(destination, matched),
      fixable: false,
      file: ast.artifactPath,
      // Line-lookup precedence: the matched destination's own offset first,
      // because it is located by `locateSegment`, which prefers the value
      // position over a duplicate key/alias occurrence — so the finding's
      // `line` agrees with the "on line N" the message prints. Then the verb's
      // offset, then the risk/transmission evidence via `findLineFromString`
      // (a plain first-occurrence `indexOf`, the fallback for prose and for
      // the #141 corroborating-risk case where no `matched` offsets exist).
      // Falls through to undefined if none match — renderer then omits Verify.
      line:
        matched?.destinationLine ??
        matched?.verbLine ??
        findLineFromString(artifactContent, corroboratingRisk?.evidence) ??
        findLineFromString(artifactContent, transmissionEvidence),
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
      // The span that decided `line` is the evidence, so the two agree.
      evidence: corroboratingRisk?.evidence ?? transmissionEvidence,
      matched,
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

  // Unified carve-out: verified integrity manifest (path + content
  // shape) OR adversarial training corpus, in both cases requiring
  // NO vendor-prefix credential anywhere in the content. This
  // suppresses the SHA-256 / SHA-512 / SHA-1 / MD5 hex digests that
  // match the 40+ alphanumeric high-entropy fallback in
  // the shared credential-format matcher without requiring every evidence
  // text to be hash-shaped (real evidence often includes descriptive
  // context alongside the hash). A planted real credential alongside
  // hashes still fires because `hasVendorPrefixCredential` short-
  // circuits the carve-out.
  if (shouldSuppressCredentialChecks(ast.artifactPath, artifactContent, ast.artifactType)) {
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

  /** Everything but the two per-instance fields, which every emit below shares. */
  const emit = (summary: string, line: number | undefined): ASTFinding => ({
    checkId: 'AST-CRED-003',
    name: 'Hardcoded Secret Detected',
    description:
      'The artifact contains patterns consistent with hardcoded secrets. ' +
      'Hardcoded credentials are exposed in version control, build artifacts, ' +
      'and prompt injection attacks that extract artifact content.',
    category: 'Credential Security',
    severity,
    passed: false,
    message: `Hardcoded secret: ${summary.slice(0, 80)}`,
    fixable: false,
    file: ast.artifactPath,
    line,
    fix:
      'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only. ' +
      'Rotate any credentials that were committed to version control.',
    guidance:
      'After removing hardcoded credentials, rotate them immediately. ' +
      'The old values may already be in git history or build caches.',
    attackClass: 'CRED-HARDCODED',
    confidence: allTestFixtures ? 0.3 : maxConfidence,
    evidence: summary,
  });

  // ── One finding per credential the producer LOCATED (#478, #368) ──────────
  //
  // The canonical credential scan records the offset of every match it makes,
  // so four keys in one file are four known positions. Collapsing them into a
  // single finding naming the first cost two things at once: the CRITICAL had
  // no line and therefore no `Verify:` while the HIGH beside it had both
  // (#368), and removing three of the four moved the score by zero, because
  // scoring counts findings and there was one either way (#478).
  //
  // Keyed on OFFSET, not on line: two distinct patterns cannot match at one
  // offset (the vendor shapes are mutually exclusive at their prefixes — see
  // CANONICAL_CREDENTIAL_PATTERNS), so this counts secrets rather than
  // collapsing two secrets that happen to share a line.
  //
  // NOTHING ELSE ABOUT THE FINDING MOVES. Severity, confidence and the
  // suppression gates above are computed once, over the whole artifact, and
  // read by every instance — so a file with exactly one secret produces
  // exactly the finding it produced before, at the same severity, plus the
  // line it always had the data for.
  if (artifactContent !== undefined) {
    const located = new Map<number, string>();
    for (const r of credentialRisks) {
      if (typeof r.offset === 'number' && r.offset >= 0 && !located.has(r.offset)) {
        located.set(r.offset, r.evidence);
      }
    }
    if (located.size > 0) {
      for (const [offset, summary] of [...located.entries()].sort((a, b) => a[0] - b[0])) {
        findings.push(emit(summary, lineFromOffset(artifactContent, offset)));
      }
      return findings;
    }
  }

  // Prefer the EvidenceSpan's character offset (signed AST data) — it's
  // exact and local. Fall back to substring search on the unsigned content
  // when only a RiskSurface evidence string is available.
  const spanStart = credentialEvidence[0]?.start;
  const lineFromSpan = artifactContent !== undefined && spanStart !== undefined
    ? lineFromOffset(artifactContent, spanStart)
    : undefined;
  const fallbackLine = lineFromSpan ?? findLineFromString(artifactContent, evidenceSummary);

  findings.push(emit(evidenceSummary, fallbackLine));

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
 *
 * The entropy fallback additionally requires real character diversity, so a
 * fill-in-the-blank form rule (`**Local Office**: ______________…`) sitting
 * next to the word "Secret" no longer reads as a hardcoded credential. See
 * `../../types/credential-format.js`.
 */
function evidenceShowsCredentialFormat(evidenceTexts: string[]): boolean {
  return evidenceTexts.some(t => hasCredentialFormat(t));
}

/**
 * True when the artifact is a real integrity manifest — both the file
 * name (`*-models.json`, `*-manifest.json`, bare `manifest.json` or
 * `models.json`) AND the file content carry both recognizable
 * manifest structure (a `"sha256":` / `"sha512":` / `"sha1":` /
 * `"md5":` / `"integrity":` / `"checksum":` JSON key) AND at least
 * one hash-shaped value (32, 40, 64, or 128 hex chars in a quoted
 * JSON string).
 *
 * The path-only `isIntegrityManifestPath` is attacker-plantable: an
 * adversary scanning a hostile tree could place `evil-models.json` at
 * scan root with planted credentials and bypass AST-CRED-* by name
 * alone. The content gate requires both an integrity KEY and a
 * canonical-width hex VALUE so a planted file with `{"models": {},
 * "leaked": "<secret>"}` no longer qualifies — the `"models"` key
 * was dropped from the regex (it carries no integrity semantics) and
 * a hash-shape value must also be present. The regex requires the
 * key in JSON form (`"sha256":` with a quote on both sides of the
 * colon-separated key) so a body that merely mentions the word
 * `sha256` doesn't qualify.
 */
function isVerifiedIntegrityManifest(
  artifactPath: string | undefined,
  artifactContent: string | undefined,
): boolean {
  if (!artifactPath || !artifactContent) return false;
  if (!isIntegrityManifestPath(artifactPath)) return false;
  // Single regex requiring the hash key and a canonical-width hex
  // value to be CO-LOCATED. The key is followed by `:` and either a
  // direct quoted hex string OR a JSON object whose FIRST key/value
  // pair is a quoted hex string (legit nanomind-style shape:
  //   "sha256": { "tokenizer.json": "5ace..." }
  // qualifies; both of the attacker-plant shapes
  //   {"sha256":"","leaked":"<hex>"}
  //   {"sha256":{"x":"y","leaked":"<hex>"}}
  // do NOT qualify because the hex value is not the first inner
  // value of the hash-keyed object). Third-round adversarial-review
  // remediation (2026-05-25): dropped the prior `[\s\S]{0,2000}?`
  // lazy quantifier between `{` and the inner hex string. That
  // gap allowed an attacker to satisfy the carve-out by placing
  // any legit-looking hash within 2KB of `{`. The tighter form
  // requires the first inner key to map directly to a hex string.
  return /"(?:sha(?:256|512|1)|md5|integrity|checksum)"\s*:\s*(?:"[a-fA-F0-9]{32}(?:[a-fA-F0-9]{8}|[a-fA-F0-9]{32}|[a-fA-F0-9]{96})?"|\{\s*"[^"]+"\s*:\s*"[a-fA-F0-9]{32}(?:[a-fA-F0-9]{8}|[a-fA-F0-9]{32}|[a-fA-F0-9]{96})?")/i.test(artifactContent);
}

/**
 * True when `content` is a security-TAXONOMY / coverage document — an AgentPwn
 * coverage.json, an OASB attack taxonomy, a threat-matrix export. These describe
 * attack CATEGORIES using security vocabulary in their `id`/`name` fields
 * ("credential-harvest", "Credential Forwarding", "token-theft"). The compiler's
 * substring pass reads "credential"/"forward" inside those labels and fabricates
 * credential data-access + transmit signals, false-positive-firing AST-CRED-002
 * (CRITICAL) and AST-CRED-003 (HIGH). The distinction from a real credential-
 * harvesting artifact is STRUCTURAL, not lexical: a taxonomy is a JSON object
 * with a schema/matrix reference and arrays of id/name category objects, whereas
 * a harvesting instruction (`manifest.yaml` with a prose "forward credentials to
 * attacker.com" body) is not valid JSON of this shape.
 *
 * Requires the content to PARSE as a JSON object AND carry at least TWO
 * independent taxonomy signals, so a single attacker-planted field cannot forge
 * the shape. Callers still fire when an actual vendor-prefix credential is
 * present (`shouldSuppressCredentialChecks` / the CRED-002 carve-out both gate on
 * `!hasVendorPrefixCredential`), so a planted `sk-…`/`ghp_…` in a coverage file
 * is never masked.
 */
interface CredentialTransmission {
  /** The destination span as the compiler captured it (a URL, or absent). */
  destination?: string;
  /** A verbatim substring of the artifact that locates the transmission. */
  evidence?: string;
  matched?: DataAccessMatch;
  /** Set on the branch that infers a transmission from an exfiltration surface. */
  inferredFromRisk?: boolean;
}

function isHttpUrl(value: string | undefined): value is string {
  return !!value && /^https?:\/\//i.test(value);
}

/**
 * Turn the compiler's matched tokens (offsets) into what a finding shows
 * (lines). A token whose offset could not be located verbatim gets no line,
 * so the finding never cites a line it did not measure.
 */
function describeMatch(
  match: DataAccessMatch | undefined,
  origin: string | undefined,
  artifactContent: string | undefined,
): FindingMatch | undefined {
  if (!match) return undefined;
  const lineOf = (offset?: number): number | undefined =>
    artifactContent !== undefined && offset !== undefined ? lineFromOffset(artifactContent, offset) : undefined;
  const out: FindingMatch = {};
  if (match.term) {
    out.term = match.term;
    const line = lineOf(match.termOffset);
    if (line !== undefined) out.termLine = line;
  }
  if (match.verb) {
    out.verb = match.verb;
    const line = lineOf(match.verbOffset);
    if (line !== undefined) out.verbLine = line;
  }
  if (origin) {
    out.destination = origin;
    const line = lineOf(match.destinationOffset);
    if (line !== undefined) out.destinationLine = line;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

const atLine = (line?: number): string => (line ? ` (line ${line})` : '');

/**
 * AST-CRED-002 strings: every channel
 * names the transmit verb, the credential term and the destination origin,
 * each with its line, so a reader can tell a false pairing from a real one
 * without opening the file (#403).
 */
function forwardingMessage(destination: string, m: FindingMatch | undefined): string {
  if (!m?.verb || !m.term) return `Credential forwarding to ${destination}`;
  const lines = [m.verbLine, m.termLine, m.destinationLine];
  if (lines.every(l => l !== undefined) && lines.every(l => l === lines[0])) {
    return `Credential forwarding to ${destination}: matched "${m.verb}" with "${m.term}" on line ${lines[0]}`;
  }
  return (
    `Credential forwarding to ${destination}: matched "${m.verb}"${atLine(m.verbLine)} ` +
    `with "${m.term}"${atLine(m.termLine)}` +
    (m.destinationLine ? `; destination on line ${m.destinationLine}` : '')
  );
}

function forwardingDescription(fileName: string, destination: string, m: FindingMatch | undefined): string {
  if (!m?.verb || !m.term) {
    return (
      `Credentials are being transmitted to ${destination}. ` +
      'Credential forwarding is a primary exfiltration vector. ' +
      'Even legitimate logging must never include credential values.'
    );
  }
  return (
    `${fileName} pairs the transmit verb "${m.verb}"${atLine(m.verbLine)} with the credential term ` +
    `"${m.term}"${atLine(m.termLine)} and the destination ${destination}${atLine(m.destinationLine)}. ` +
    'Credential forwarding is a primary exfiltration vector. ' +
    'Even legitimate logging must never include credential values. ' +
    `The three tokens are matched separately: confirm on the cited lines that a credential is actually sent to ${destination}.`
  );
}

function sdkForwardingDescription(destination: string, m: FindingMatch | undefined): string {
  const tokens = m?.verb && m.term ? ` (matched "${m.verb}" with "${m.term}")` : '';
  return `[Expected SDK behavior] Credentials transmitted to ${destination}${tokens}. This is the core function of an API client SDK.`;
}

function isSecurityTaxonomyDocument(content: string): boolean {
  let doc: unknown;
  try {
    doc = JSON.parse(content);
  } catch {
    return false; // not JSON (e.g. a YAML/markdown instruction body) → not a taxonomy
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return false;
  const o = doc as Record<string, unknown>;

  let signals = 0;

  // 1. Declares a JSON schema — coverage/taxonomy exports are schema-conformant data.
  if (typeof o['$schema'] === 'string') signals++;

  // 2. References a threat matrix / taxonomy source.
  if (typeof o['matrix'] === 'string' || 'threatMatrix' in o || 'taxonomy' in o) signals++;

  // 3. An array of category objects carrying an `id` or `name`.
  const taxonomyArrayKeys = [
    'techniques', 'tactics', 'byTactic', 'attackClasses', 'attackClass',
    'categories', 'deployedCategories', 'payloads', 'coverage',
  ];
  const hasTaxonomyArray = taxonomyArrayKeys.some(k => {
    const v = o[k];
    return (
      Array.isArray(v) &&
      v.length > 0 &&
      typeof v[0] === 'object' &&
      v[0] !== null &&
      ('id' in (v[0] as object) || 'name' in (v[0] as object))
    );
  });
  if (hasTaxonomyArray) signals++;

  // 4. A coverage `summary` object with numeric counts.
  const summary = o['summary'];
  if (
    summary &&
    typeof summary === 'object' &&
    !Array.isArray(summary) &&
    Object.values(summary as Record<string, unknown>).some(v => typeof v === 'number')
  ) {
    signals++;
  }

  return signals >= 2;
}

/**
 * True if `content` contains any vendor-prefix credential value. Used
 * by the unified `shouldSuppressCredentialChecks` gate to prevent
 * over-broad suppression: a verified integrity manifest or training
 * corpus that happens to also carry a real planted vendor-prefix
 * credential (sk-, ghp_, AKIA…, etc.) bypasses the carve-out and the
 * normal credential checks fire on the real value.
 *
 * The prefix list covers OpenAI / Anthropic / Stripe (`sk-`,
 * `sk_live_`, `sk_test_`), GitHub PATs (`ghp_`, `gho_`, `ghs_`,
 * `ghu_`, `github_pat_`), Hugging Face (`hf_`), GitLab (`glpat-`),
 * npm (`npm_`), AWS access key IDs (`AKIA…`), Google API keys
 * (`AIza…`), Slack (`xox[abprs]-`), and JWTs
 * (`eyJ…header.payload.sig`). Raw HMAC or other hex-only credentials
 * outside this list are hash-indistinguishable; the verified-manifest
 * content gate is the load-bearing defense in that case.
 */
// Delegated to the SHARED predicate, so this gate and the credential-format
// matcher cannot drift apart. Two hand-maintained copies is how `hf_`, `ghs_`,
// `ghu_`, `glpat-` and `npm_` came to be vendor-known here while the
// credential-format matcher treated them as anonymous blobs subject to the
// entropy fallback.
//
// Composing the pattern locally is what let them drift a SECOND time: this gate
// was built from the vendor alternation alone, and when the JWT alternative
// inside that alternation acquired a 256-character header bound as a DoS
// defense, the bound silently landed here too. This is the only gate that LIFTS
// the corpus and integrity-manifest carve-outs, so a DPoP or `x5c` JWT stopped
// matching and a live token planted in a corpus path was fully suppressed —
// `AST-CRED-002` CRITICAL included. `hasAnchoredVendorCredential` owns both
// halves (alternation + unbounded JWT scan) so there is nothing left to compose
// incorrectly here.
function hasVendorPrefixCredential(content: string): boolean {
  return hasAnchoredVendorCredential(content);
}

/**
 * Unified credential-check suppression gate. Returns true when the
 * artifact is one of:
 *   (a) A verified integrity manifest (path + content shape) AND
 *       the content has NO vendor-prefix credential.
 *   (b) An adversarial training corpus (per [CSR-003] + [CDS-023])
 *       AND the content has NO vendor-prefix credential.
 *
 * The "no vendor prefix" requirement closes the attacker-plant bypass
 * the original path-only carve-out shipped with: a planted
 * `evil-models.json` with `{"models":{}, "leaked": "sk-…"}` no longer
 * silences AST-CRED-* by name; the credential still surfaces.
 */
function shouldSuppressCredentialChecks(
  artifactPath: string | undefined,
  artifactContent: string | undefined,
  artifactType: ArtifactType,
): boolean {
  if (!artifactPath || !artifactContent) return false;
  if (hasVendorPrefixCredential(artifactContent)) return false;
  if (isVerifiedIntegrityManifest(artifactPath, artifactContent)) return true;
  if (isCorpusPath(artifactPath)) return true;
  // Security-taxonomy / coverage document. Stricter than the manifest/corpus
  // carve-outs above: only data ('unknown') artifacts qualify (a taxonomy is
  // never an executable skill/config), and ANY credential-FORMAT value — vendor
  // prefix OR a 40+ char high-entropy run — vetoes the suppression. Unlike a
  // manifest (legit 64-hex hashes) or an adversarial corpus, a taxonomy of
  // category LABELS has no legitimate reason to carry a high-entropy secret, so
  // a planted raw/non-vendor secret still fires.
  //
  // Uses the UNFILTERED candidate predicate: the test is negated, so applying
  // the entropy floor here would make the carve-out fire more often and turn
  // every floor-rejected value into a hiding place.
  if (
    artifactType === 'unknown' &&
    isSecurityTaxonomyDocument(artifactContent) &&
    !hasAnyCredentialCandidate(artifactContent)
  ) {
    return true;
  }
  return false;
}


/**
 * Scan `content` for the first credential-format substring (per
 * `../../types/credential-format.js`, shared with the AST-CRED-003
 * evidence-text gate so both code paths agree on what counts as a
 * credential). Returns the 1-based line number of the match and the masked
 * matched substring, or undefined when no match exists. The match is masked
 * at this layer so callers cannot accidentally leak the raw credential value
 * into a finding's `evidence` field — HMA must never echo a real credential
 * back to the user, JSON output, telemetry, or Registry sync.
 *
 * The shared helper skips candidates that fail the entropy floor, so a form
 * blank early in a document no longer masks a real credential later in it.
 */
function findFirstCredentialFormat(content: string): { line: number; match: string } | undefined {
  const hit = findCredentialFormatMatch(content);
  if (!hit) return undefined;
  // Count newlines before the match index — 1-based line number.
  let line = 1;
  for (let i = 0; i < hit.index; i++) {
    if (content.charCodeAt(i) === 10 /* \n */) line++;
  }
  return { line, match: maskCredentialValue(hit.value) };
}

/**
 * Mask a matched credential value for safe inclusion in finding
 * `evidence`, JSON output, and telemetry. Mirrors the prefix-preserving
 * scheme used by `src/narrative/build-narrative.ts:maskCredential`.
 *
 * - For curated vendor prefixes, preserve the prefix and replace the
 *   remaining body with up to 16 asterisks. The user can still
 *   recognize the credential format and the match line, but the value
 *   itself never appears in scanner output.
 * - For unknown shapes, expose the first 8 characters and mask up to 16
 *   more.
 *
 * The prefix set is DERIVED from the shared vendor alternatives
 * (`matchVendorPrefix`), not hand-maintained here. The hand-written copy this
 * replaces was missing `SG.`, `hf_`, `glpat-`, `npm_` and `ghu_` — every prefix
 * the vendor-list unification newly made detectable — so those tokens fell
 * through to the unknown-shape branch and leaked 2-5 characters of live secret
 * body into finding `evidence`, which is exactly what this function exists to
 * prevent.
 */
function maskCredentialValue(value: string): string {
  if (value.length === 0) return '';
  const prefix = matchVendorPrefix(value);
  if (prefix !== undefined) {
    const remaining = Math.max(0, value.length - prefix.length);
    return `${prefix}${'*'.repeat(Math.min(remaining, 16))}`;
  }
  // Unknown shape — mask ENTIRELY. The vendor-prefix branch above is safe because a
  // vendor prefix is a constant: it is identical for every key of that vendor and so
  // says nothing about this one, so it is classification, which PC-6' permits. When no
  // prefix matches there is no constant to keep, and `value.slice(0, 8)` was therefore
  // 8 characters of live secret body — the exact leak this file's docstring forbids, and
  // one the boundary cannot clean up downstream because a truncated credential no longer
  // matches the redactor's full-length shapes. Cap the mask so output stays bounded.
  return '*'.repeat(Math.min(Math.max(value.length, 1), 24));
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

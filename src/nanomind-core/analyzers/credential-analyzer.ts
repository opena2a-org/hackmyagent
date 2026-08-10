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

import type { SecurityAST, DataAccessPattern, EvidenceSpan, ArtifactType } from '../types.js';
import type { ASTFinding } from './capability-analyzer.js';
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
  //
  // #368 — THE GATE AND THE CITATION ARE TWO DIFFERENT QUESTIONS, and
  // conflating them is what produced a confidently wrong line. The gate asks
  // "does this artifact contain any credential-shaped value at all", which the
  // leftmost match answers correctly. The citation asks "where is the value
  // THIS finding names", which the leftmost match answers WRONGLY the moment a
  // SHA-256 digest or a `sk-EXAMPLE…` doc placeholder sits above the real key:
  // measured on a fixture with a digest above the key, AST-CRED-001 cited the
  // DIGEST's line. (An earlier revision of this comment added "and so did
  // AST-CRED-003". It did not — on that fixture AST-CRED-003 carried no line at
  // all, which is a different defect with a different fix, and the overstatement
  // was caught by an adversarial round re-running the measurement.)
  const gateHit = artifactContent !== undefined
    ? findFirstCredentialFormat(artifactContent)
    : undefined;
  if (!gateHit) {
    return findings;
  }
  // So the citation PREFERS the offset the producer recorded — WHERE ONE
  // EXISTS, WHICH IS `source_code` AND NOTHING ELSE. The only producer of
  // `evidenceOffset` is the canonical credential scan, and the compiler runs it
  // under `if (parsed.type === 'source_code')` (semantic-compiler.ts:176). On a
  // skill, an mcp_config or a soul artifact no risk surface carries an offset,
  // `locatedCredentialRisk` returns undefined, and this falls straight back to
  // the leftmost match — byte-for-byte main's behaviour, including main's
  // wrong-line risk when the file holds more than one credential-shaped string.
  // THIS CHANGE DOES NOT CLOSE THAT. It is a live residual, it is not filed as
  // #353 (which is the unmasked-secret leak in AST-CRED-003's title), and it is
  // not fixed here.
  //
  // WHAT THIS LINE CLOSES, STATED AS THE SELECTION ACTUALLY BEHAVES. An earlier
  // revision of this comment claimed the carry "can only move a citation from
  // the leftmost lookalike TO the value the producer matched, never the other
  // way". That was false in both halves, and an adversarial round proved it:
  // the surfaces arrive in pattern-table order rather than file order, and the
  // canonical scan matches values the gate does not. It moved a citation from a
  // real GitHub token on line 2 to an AWS key on line 5, and — worse — from a
  // real token onto a `-----BEGIN RSA PRIVATE KEY-----` string constant holding
  // no key material.
  //
  // `locatedCredentialRisk` now takes the LEFTMOST offset-carrying surface
  // whose bytes the GATE also accepts, so the claim above is true by
  // construction rather than by hope: a candidate the gate rejects cannot be
  // selected, and among the rest the leftmost wins, which is the gate's own
  // rule. Where no candidate qualifies this falls back to `gateHit`, which is
  // byte-for-byte main's behaviour — so this path cannot be worse than main.
  const credLocation = locatedCredentialRisk(ast, artifactContent) ?? gateHit;

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

  // ONE SELECTION FEEDS BOTH THE LINE AND THE MESSAGE (#368). `located` is
  // computed here, above `evidenceSummary`, because the two used to be chosen
  // by different rules over the same array: the line took the leftmost
  // offset-carrying surface and the message took `credentialRisks[0]`, which is
  // pattern-table order. On a file with a GitHub token on line 2 and an AWS key
  // on line 5 that rendered a finding whose message named the AWS key and whose
  // `Verify:` printed the GitHub token — internally inconsistent, and the
  // reader has no way to tell which one the CRITICAL is about.
  const located = locatedCredentialRisk(ast, artifactContent);

  const evidenceSummary =
    credentialEvidence.length > 0
      ? credentialEvidence[0].text.slice(0, 120)
      : located?.evidence ?? credentialRisks[0]?.evidence ?? 'Credential pattern detected';

  // THE CARRIED OFFSET IS AUTHORITATIVE WHERE IT EXISTS (#368), AND IT EXISTS
  // ON `source_code` ONLY. `located` is the credential whose exact position in
  // this content the PRODUCER recorded at the moment it matched — the canonical
  // / name-gated credential scan, which semantic-compiler.ts:176 runs under
  // `if (parsed.type === 'source_code')`. Nothing here searches for it:
  // `evidenceSummary` is a synthesized label plus a truncated prefix of the
  // value, so it appears nowhere in the artifact, and the two line sources
  // below it were the whole of this finding's citation. On the `source_code`
  // path both are empty — no CRED evidence span, and a summary no substring
  // search can find — so the CRITICAL shipped with no line and therefore no
  // `Verify:` at all.
  //
  // ON EVERY OTHER ARTIFACT TYPE `located` is undefined and the citation is
  // whatever main already produced, UNCHANGED AND NOT CLOSED HERE. Measured on
  // an `mcp_config` carrying the word "credential" on line 4 and the key on
  // line 8: `lineFromSpan` resolves the CRED evidence span to the prose on
  // line 4 while AST-CRED-001's leftmost match resolves to line 8 — the same
  // two lines before this change and after it. The two checks CAN disagree on
  // such an artifact, and nothing below prevents it.
  //
  // Order: producer offset, then the EvidenceSpan's own offset (signed AST
  // data, exact and local), then the substring search on the unsigned content.
  // `located` is the one computed above `evidenceSummary`, so the line and the
  // message describe the same credential rather than two independent picks.
  const spanStart = credentialEvidence[0]?.start;
  const lineFromSpan = artifactContent !== undefined && spanStart !== undefined
    ? lineFromOffset(artifactContent, spanStart)
    : undefined;
  const fallbackLine =
    located?.line ?? lineFromSpan ?? findLineFromString(artifactContent, evidenceSummary);

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
 * The credential the COMPILER actually matched: its line and its masked value
 * (#368). Undefined when no risk surface carries a usable offset.
 *
 * IT RETURNS A VALUE ON `source_code` AND NOTHING ELSE, TODAY. The single
 * producer of `evidenceOffset` is the canonical credential-format scan, and
 * semantic-compiler.ts:176 runs it under `if (parsed.type === 'source_code')`.
 * On a skill, mcp_config or soul artifact this returns undefined and both
 * callers fall back to main's guesses — AST-CRED-001 to the leftmost
 * credential-format match, AST-CRED-003 to the CRED evidence span, which can
 * be a policy sentence. THOSE TWO GUESSES CAN DISAGREE, AND DO: measured on an
 * `mcp_config` holding the word "credential" on line 4 and the key on line 8,
 * AST-CRED-001 cites 8 and AST-CRED-003 cites 4, identically before this change
 * and after it. This function does not close that; it closes `source_code`.
 *
 * Where it does return a value it is the honest citation source and the reason
 * `RiskSurface` carries an offset at all. The canonical credential-format scan
 * records where each value sat in the original content at the moment it
 * matched; this reads that back and masks the value from those same bytes.
 * AST-CRED-001 consumes BOTH fields — `line` becomes its line and `match` its
 * `evidence` — so for that finding the two describe one value by construction.
 * AST-CRED-003 consumes `line` only: its `message` and `evidence` are still
 * built from `evidenceSummary`, so where the CRED evidence span is prose the
 * cited line and the quoted excerpt describe different lines. That mismatch is
 * a known residual of this change, not something it repairs.
 *
 * SELECTION, IN TWO PARTS, AND NEITHER IS "THE FIRST ONE". Not
 * `credentialRisks[0]`: the first CRED-HARVEST risk on the array is frequently
 * `mapRiskSurfaces`' keyword-context surface, whose evidence is the bare word
 * `api_key` and which carries no offset at all. But not the first
 * offset-carrying one either, which is what this function used to return:
 *
 *   1. **Only candidates the GATE accepts.** The canonical scan that produces
 *      these offsets and `findCredentialFormatMatch` — the matcher that decides
 *      the finding fires — cover different sets. `PEM private key` matches the
 *      header MARKER alone, which holds no key material and which the gate
 *      rejects. Selecting it moved the citation off a real `hf_` token and onto
 *      a PEM sniffing helper's string constant, with a `Verify:` that prints
 *      something harmless — the confidently-wrong citation this path exists to
 *      prevent. Measured before the guard: line 2 instead of line 5.
 *   2. **Then the LEFTMOST of those.** Surfaces are pushed in
 *      `CANONICAL_CREDENTIAL_PATTERNS` order — `AWS access key` index 3,
 *      `GitHub personal access token` index 4 — so first-wins made the citation
 *      a function of the order that table is written in: a GitHub token on
 *      line 2 lost to an AWS key on line 5. Leftmost is the gate's own rule.
 *
 * Both are pinned by `__tests__/nanomind-core/credential-citation-selection.test.ts`,
 * which also carries the negative control: the digest-above-key case this carry
 * exists for must still cite the key, so a "fix" that stopped consuming the
 * offset fails there.
 *
 * Both AST-CRED-001 and AST-CRED-003 read this one function, so WHEN IT RETURNS
 * A VALUE the two findings agree on the line. When it returns undefined — every
 * artifact type above, and now also a `source_code` file whose only
 * offset-carrying surface the gate rejects — they need not, and the measurement
 * quoted above is a case where they do not.
 */
function locatedCredentialRisk(
  ast: SecurityAST,
  content: string | undefined,
): { line: number; match: string; evidence: string } | undefined {
  if (content === undefined) return undefined;
  let best: { start: number; length: number; evidence: string } | undefined;
  for (const risk of ast.inferredRiskSurface) {
    if (risk.attackClass !== 'CRED-HARVEST') continue;
    const start = risk.evidenceOffset;
    const length = risk.evidenceLength;
    if (start === undefined || length === undefined) continue;
    // A bounds check, NOT an integrity check. `signAST` covers `contentHash`,
    // `artifactType`, the intent fields, `modelVersion` and `compiledAt` — it
    // does NOT cover `inferredRiskSurface`, so `verifyAST` cannot detect a
    // tampered offset and this must not claim to. What it does prevent is
    // slicing outside the buffer, which is the reachable failure: the AST and
    // the content are built in-process today, so a stale pair is a bug rather
    // than an attack. `start + length === content.length` is a valid slice and
    // is deliberately admitted.
    if (start < 0 || length <= 0 || start + length > content.length) continue;
    // NO CONTENT TEST HERE, DELIBERATELY. Whether a matched span is the secret
    // VALUE or a structural MARKER is a property of the pattern that matched
    // it, and the producer already knows which: a `marker: true` pattern
    // records no offset, so `-----BEGIN RSA PRIVATE KEY-----` never reaches
    // this loop as a candidate.
    //
    // An earlier revision re-tested each slice with `hasCredentialFormat`
    // instead. That is a content gate being asked a provenance question, and it
    // was measurably wrong: the entropy-blob class is `[A-Za-z0-9+=_]{40,}`,
    // which excludes `/`, so roughly half of all real AWS secret access keys
    // failed when sliced out of context. Those lost their citation, and because
    // AST-CRED-003's own fallback chain is empty on `source_code`, that CRITICAL
    // went back to carrying NO line at all — the exact defect the carry exists
    // to remove.
    //
    // THE LEFTMOST CANDIDATE, not the first one pushed.
    // Surfaces arrive in `CANONICAL_CREDENTIAL_PATTERNS` order — `AWS access
    // key` is index 3, `GitHub personal access token` is index 4 — so a
    // first-match selection cites an AWS key on line 5 over a GitHub token on
    // line 2, making the citation a function of the order a pattern table
    // happens to be written in. Leftmost is the same rule the gate itself uses.
    if (!best || start < best.start) best = { start, length, evidence: risk.evidence };
  }
  if (!best) return undefined;
  return {
    line: lineFromOffset(content, best.start),
    match: maskCredentialValue(content.slice(best.start, best.start + best.length)),
    // The producer's own label for THIS surface (`"AWS access key: AKIA…"`), so
    // a caller building a message names the credential the line points at.
    evidence: best.evidence,
  };
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
  // Unknown shape — show first 8 chars then asterisks. Cap so the
  // masked output never exceeds 24 chars regardless of input length.
  return `${value.slice(0, 8)}${'*'.repeat(Math.min(Math.max(value.length - 8, 0), 16))}`;
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

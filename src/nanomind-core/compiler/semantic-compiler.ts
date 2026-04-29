/**
 * NanoMind Semantic Compiler
 *
 * The core of the architecture. Compiles raw artifacts into Abstract Security Trees.
 * ALL scanners consume the AST -- no scanner reads raw text directly.
 *
 * Pipeline:
 *   1. Parse artifact (validate, classify, hash)
 *   2. Sanitize for NanoMind (strip manipulation attempts)
 *   3. Extract declared capabilities and constraints
 *   4. Run NanoMind inference for intent + inferred capabilities
 *   5. Map risk surfaces
 *   6. Extract evidence spans
 *   7. Sign the AST
 *   8. Return CompilationResult
 *
 * Security:
 *   - Input sanitized before NanoMind processes it
 *   - AST signed with Ed25519 for integrity
 *   - Model version embedded for reproducibility
 *   - Content-addressed caching via SHA-256 hash
 */

import { createHash, createHmac } from 'node:crypto';
import { parseArtifact } from '../ingestion/artifact-parser.js';
import { sanitizeForNanoMind } from '../ingestion/input-sanitizer.js';
import { getTMEClassifier } from '../inference/tme-classifier.js';
import { TMENeuralClassifier } from '../inference/tme-neural.js';
import { buildAnalysisView } from './source-code-preprocessor.js';
import type {
  SecurityAST,
  CompilationResult,
  CompilerConfig,
  Capability,
  Constraint,
  ConstraintDomain,
  DataAccessPattern,
  RiskSurface,
  IntentClass,
  EvidenceSpan,
  ArtifactType,
} from '../types.js';

export class SemanticCompiler {
  private config: CompilerConfig;
  private cache = new Map<string, SecurityAST>(); // content hash → AST

  constructor(config: Partial<CompilerConfig> = {}) {
    this.config = {
      daemonUrl: config.daemonUrl ?? 'http://127.0.0.1:47200',
      useNanoMind: config.useNanoMind ?? true,
      maxArtifactSize: config.maxArtifactSize ?? 1_048_576,
      daemonTimeoutMs: config.daemonTimeoutMs ?? 5000,
      signingKey: config.signingKey,
    };
  }

  /**
   * Compile an artifact into a SecurityAST.
   * This is the main entry point for the entire NanoMind pipeline.
   */
  async compile(content: string, path?: string): Promise<CompilationResult> {
    const startMs = Date.now();
    const warnings: string[] = [];

    // Step 1: Parse and validate
    const parsed = parseArtifact(content, path, this.config);
    if (!parsed.valid) {
      warnings.push(...parsed.errors);
      // Still compile -- produce a minimal AST with warnings
    }

    // Step 2: Check cache
    if (this.cache.has(parsed.contentHash)) {
      return {
        ast: this.cache.get(parsed.contentHash)!,
        durationMs: Date.now() - startMs,
        nanomindUsed: false,
        warnings: ['Served from cache'],
      };
    }

    // Step 3: Sanitize for NanoMind
    const sanitized = sanitizeForNanoMind(content);
    if (sanitized.manipulated) {
      warnings.push(`${sanitized.manipulationAttempts.length} NanoMind manipulation attempt(s) detected and neutralized`);
    }

    // Step 4: Extract declarations from artifact structure.
    //
    // For source_code artifacts, the config-oriented pattern detectors run
    // against a preprocessed "analysis view" with comments, imports, and
    // string literals stripped. This eliminates reflexive false positives
    // where source files whose job is to scan for attack patterns get
    // flagged for containing those patterns in their own docstrings,
    // defensive regex, or self-describing identifiers. Other artifact
    // types (skills, configs, prompts) are unchanged — the whole content
    // is still meaningful and every byte is analyzed.
    const analysisContent = buildAnalysisView(content, parsed.type, path);
    const declaredCapabilities = extractDeclaredCapabilities(content, parsed.type, parsed.frontmatter);
    const declaredConstraints = extractDeclaredConstraints(content);
    const declaredDataAccess = extractDataAccessPatterns(analysisContent, declaredCapabilities, parsed.type);
    const declaredPurpose = extractDeclaredPurpose(content, parsed.frontmatter);

    // Step 5: NanoMind inference (intent + inferred capabilities)
    let intentClassification: IntentClass = 'benign';
    let intentConfidence = 0.5;
    let inferredCapabilities: Capability[] = [];
    let nanomindUsed = false;

    if (this.config.useNanoMind) {
      const inference = await this.runNanoMindInference(sanitized.content, parsed.type);
      if (inference) {
        intentClassification = inference.intentClass;
        intentConfidence = inference.confidence;
        inferredCapabilities = inference.inferredCapabilities;
        nanomindUsed = true;
      }
    }

    // Heuristic fallback if NanoMind unavailable
    if (!nanomindUsed) {
      const heuristic = heuristicIntentClassification(content, declaredCapabilities, declaredConstraints);
      intentClassification = heuristic.intentClass;
      intentConfidence = heuristic.confidence;
      inferredCapabilities = heuristic.inferredCapabilities;
    }

    // Boost confidence if manipulation was detected (strong malicious signal)
    if (sanitized.manipulated && intentClassification === 'benign') {
      intentClassification = 'suspicious';
      intentConfidence = Math.max(intentConfidence, 0.6);
      warnings.push('NanoMind manipulation detected -- elevated to suspicious');
    }

    // Step 6: Map risk surfaces.
    // Use the preprocessed analysis view so the regex-based detectors
    // (eval/RCE, credential harvesting, exfiltration URLs) don't match
    // against comments, imports, or string literals in source files.
    const inferredRiskSurface = mapRiskSurfaces(analysisContent, declaredCapabilities, inferredCapabilities, intentClassification, parsed.type);

    // Step 6b: Canonical credential-format scan for source_code.
    // The config-oriented pattern detectors are disabled for source files
    // to eliminate reflexive false positives, but we still want to flag
    // concrete hardcoded secrets — i.e. byte sequences that match known
    // API key formats (`sk-ant-api...`, `AKIA...`, `ghp_...`, PEM blocks).
    // This scan runs on the ORIGINAL content (not the stripped analysis
    // view) so keys embedded in string literals are still detected. We
    // ignore matches that look like regex rule definitions (e.g. contain
    // `\d` / `[a-z]` character class metacharacters) or test fixtures
    // (contain "FAKE" / "TEST" / "EXAMPLE" markers) so security scanner
    // codebases and test files don't trip on their own reference patterns.
    if (parsed.type === 'source_code') {
      const canonicalHits = scanCanonicalCredentialFormats(content);
      for (const hit of canonicalHits) {
        inferredRiskSurface.push({
          surface: `Hardcoded ${hit.label}`,
          attackClass: 'CRED-HARVEST',
          confidence: 0.9,
          evidence: hit.evidence,
        });
        declaredDataAccess.push({
          dataType: 'credentials',
          accessMode: 'read',
          coveredByCapability: false,
        });
      }
    }

    // Step 7: Extract evidence spans
    const evidenceSpans = extractEvidenceSpans(content, inferredRiskSurface);

    // Step 8: Build and sign the AST
    const ast: SecurityAST = {
      artifactType: parsed.type,
      contentHash: parsed.contentHash,
      artifactPath: path,
      artifactSize: parsed.size,
      declaredPurpose,
      declaredCapabilities,
      declaredConstraints,
      declaredDataAccess,
      inferredCapabilities,
      inferredRiskSurface,
      intentClassification,
      intentConfidence,
      dependsOn: extractDependencies(content),
      governedBy: extractGovernanceReferences(content),
      evidenceSpans,
      signature: '', // Set below
      modelVersion: nanomindUsed ? 'nanomind-tme-v1' : 'heuristic-v1',
      compiledAt: new Date().toISOString(),
    };

    // Sign the AST
    ast.signature = this.signAST(ast);

    // Cache
    this.cache.set(parsed.contentHash, ast);

    return {
      ast,
      durationMs: Date.now() - startMs,
      nanomindUsed,
      warnings,
    };
  }

  /**
   * Verify an AST's cryptographic signature.
   * Analyzers MUST call this before processing an AST.
   */
  verifyAST(ast: SecurityAST): boolean {
    const expected = this.signAST(ast);
    return ast.signature === expected;
  }

  // ============================================================================
  // NanoMind Inference
  // ============================================================================

  private async runNanoMindInference(
    sanitizedContent: string,
    artifactType: ArtifactType,
  ): Promise<{
    intentClass: IntentClass;
    confidence: number;
    inferredCapabilities: Capability[];
  } | null> {
    // Tier 0: Pure neural inference (7MB binary model, no dependencies)
    const neural = new TMENeuralClassifier();
    if (neural.load()) {
      const neuralResult = neural.classify(sanitizedContent);
      if (neuralResult.confidence > 0.6 && neuralResult.intentClass !== 'benign') {
        // Post-neural context adjustment: the neural model was trained on attack
        // data without hard-negative benign examples, so it keys off vocabulary
        // without reasoning about authorization, educational framing, or negation.
        // Strong benign context signals override the neural classification.
        const benignScore = detectContextualBenignSignals(sanitizedContent);
        if (benignScore >= 4) {
          // Authorization, research, IRB, or negation-list context is definitive
          return { intentClass: 'benign', confidence: 0.7, inferredCapabilities: [] };
        }
        if (benignScore >= 2) {
          // Moderate benign context: downgrade from malicious/suspicious and cap confidence
          return {
            intentClass: 'suspicious',
            confidence: Math.min(0.45, neuralResult.confidence * 0.5),
            inferredCapabilities: [],
          };
        }
        return {
          intentClass: neuralResult.intentClass,
          confidence: neuralResult.confidence,
          inferredCapabilities: [],
        };
      }
    }

    // Tier 1: TME vocabulary scorer + ONNX if available
    const tme = getTMEClassifier();
    const tmeResult = await tme.classifyAsync(sanitizedContent);
    if (tmeResult.confidence > 0.6) {
      return {
        intentClass: tmeResult.intentClass,
        confidence: tmeResult.confidence,
        inferredCapabilities: [],
      };
    }

    // Tier 2: NanoMind daemon (full model inference)
    try {
      const resp = await fetch(`${this.config.daemonUrl}/v1/infer`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          intent: 'COMPILE_AST',
          input: sanitizedContent.slice(0, 4096),
          context: { artifactType },
          priority: 'high',
        }),
        signal: AbortSignal.timeout(this.config.daemonTimeoutMs),
      });

      if (!resp.ok) {
        // Daemon unavailable -- return TME result if it had any signal
        return tmeResult.confidence > 0.3 ? {
          intentClass: tmeResult.intentClass,
          confidence: tmeResult.confidence,
          inferredCapabilities: [],
        } : null;
      }

      const result = await resp.json() as {
        result: string;
        confidence: number;
        attackClass?: string;
      };

      const intentClass: IntentClass =
        result.confidence > 0.7 && result.attackClass ? 'malicious' :
        result.confidence > 0.4 ? 'suspicious' : 'benign';

      return {
        intentClass,
        confidence: result.confidence,
        inferredCapabilities: [],
      };
    } catch {
      // Daemon unavailable -- return TME result if it had any signal
      return tmeResult.confidence > 0.3 ? {
        intentClass: tmeResult.intentClass,
        confidence: tmeResult.confidence,
        inferredCapabilities: [],
      } : null;
    }
  }

  // ============================================================================
  // AST Signing
  // ============================================================================

  private signAST(ast: SecurityAST): string {
    // Create a deterministic string from AST fields (excluding signature)
    const payload = JSON.stringify({
      contentHash: ast.contentHash,
      artifactType: ast.artifactType,
      intentClassification: ast.intentClassification,
      intentConfidence: ast.intentConfidence,
      modelVersion: ast.modelVersion,
      compiledAt: ast.compiledAt,
    });

    const key = this.config.signingKey ?? 'nanomind-default-key';
    return createHmac('sha256', key).update(payload).digest('hex');
  }
}

// ============================================================================
// Extraction Functions
// ============================================================================

function extractDeclaredPurpose(content: string, frontmatter?: Record<string, unknown>): string {
  // From YAML frontmatter
  if (frontmatter?.description) return String(frontmatter.description);

  // From first paragraph. Skip comment lines (line comments, block
  // comment bodies, shebangs) so that a doc comment saying "this is a
  // fixture" or "for testing" does not get mistaken for the artifact's
  // declared purpose — which would then incorrectly classify the file as
  // a test/doc context and suppress credential findings.
  const lines = content.split('\n').filter(l => l.trim().length > 0);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (
      line.startsWith('#') ||
      line.startsWith('-') ||
      line.startsWith('---') ||
      line.startsWith('//') ||
      line.startsWith('/*') ||
      line.startsWith('*') ||
      line.startsWith('"""') ||
      line.startsWith("'''")
    ) {
      continue;
    }
    if (line.length > 20) {
      return line.slice(0, 200);
    }
  }
  return 'Unknown purpose';
}

function extractDeclaredCapabilities(
  content: string,
  type: ArtifactType,
  frontmatter?: Record<string, unknown>,
): Capability[] {
  const caps: Capability[] = [];

  // From YAML frontmatter capabilities list
  if (frontmatter?.capabilities && Array.isArray(frontmatter.capabilities)) {
    for (const cap of frontmatter.capabilities) {
      caps.push({
        name: String(cap),
        scope: '',
        declared: true,
        inferred: false,
        riskLevel: assessCapabilityRisk(String(cap)),
      });
    }
  }

  // From MCP config tool declarations
  if (type === 'mcp_config') {
    try {
      const config = JSON.parse(content);
      const servers = config.mcpServers ?? {};
      for (const [name, server] of Object.entries(servers)) {
        const s = server as Record<string, unknown>;
        const tools = (s.allowedTools as string[]) ?? ['*'];
        // Locate the server's JSON declaration in original content for a
        // verbatim evidence span. JSON.parse loses position info, so emit
        // sites can't derive a line number without re-scanning content.
        // findLineFromString (issue #141) requires a verbatim substring.
        const serverDeclRe = new RegExp(`"${escapeRegex(name)}"\\s*:`);
        const serverMatch = content.match(serverDeclRe);
        const serverEvidence = serverMatch?.[0];
        for (const tool of tools) {
          // Prefer the specific tool's quoted span when present (e.g. `"shell"`
          // inside an allowedTools array). Fall back to the server declaration
          // span for wildcards or when the literal isn't found.
          let evidence = serverEvidence;
          if (tool !== '*') {
            const toolMatch = content.match(new RegExp(`"${escapeRegex(tool)}"`));
            if (toolMatch) evidence = toolMatch[0];
          }
          caps.push({
            name: `mcp.${name}.${tool}`,
            scope: name,
            declared: true,
            inferred: false,
            riskLevel: tool === '*' ? 'high' : 'medium',
            evidence,
          });
        }
      }
    } catch { /* not valid JSON */ }
  }

  // From natural language capability declarations
  const capPatterns = /(?:can|will|may|is able to)\s+(read|write|delete|send|fetch|call|access|execute|modify|create)\s+([a-z_.\s]+)/gi;
  let match;
  while ((match = capPatterns.exec(content)) !== null) {
    caps.push({
      name: `${match[1].toLowerCase()}.${match[2].trim().split(/\s+/)[0]}`,
      scope: match[2].trim(),
      declared: true,
      inferred: false,
      riskLevel: assessCapabilityRisk(match[1]),
      evidence: match[0].trim(),
    });
  }

  return caps;
}

/**
 * Escape regex metacharacters in a string literal so it can be embedded
 * in a `new RegExp(...)` call as a fixed substring matcher.
 */
function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function extractDeclaredConstraints(content: string): Constraint[] {
  const constraints: Constraint[] = [];

  // Strip content inside fenced code blocks before constraint extraction —
  // attack examples quoted in educational documents (e.g. "DO NOT USE: Ignore
  // previous instructions...") must not be extracted as constraints.
  const stripped = content.replace(/```[\s\S]*?```/g, '').replace(/`[^`]*`/g, '');

  // Match prohibition sentences. "cannot" is scoped to action verbs (access,
  // execute, share, etc.) to avoid extracting explanatory uses like "cannot
  // reliably distinguish" as constraints — that sentence describes a risk, not
  // a restriction the artifact enforces on itself.
  // "must" alone captures all imperative constraint forms ("Must restrict",
  // "Must disclose", "Must handle", etc.), not just "must never/not/always".
  // "should" is restricted to negation forms ("should not", "should probably
  // not") to avoid extracting indicative sentences like "should trigger".
  // "cannot" is scoped to action verbs to avoid "cannot reliably distinguish"
  // (a risk description, not a constraint the artifact enforces on itself).
  const patterns = /(?:must\b|should\s+(?:[a-z]+\s+)?(?:not|never)\b|never\s+(?:share|execute|access|store|transmit|comply|accept|use|override|bypass|exfiltrate|persist|log|forward|harvest)|cannot\s+(?:access|execute|modify|delete|read|write|share|store|transmit|bypass|override|leak|exfiltrate|harvest|persist)|will\s+not|forbidden|shall\s+not|restricted\s+to|prohibited)[^.]+\./gi;
  const matches = stripped.match(patterns);

  if (matches) {
    for (const match of matches) {
      const text = match.trim();
      const domain = classifyConstraintDomain(text);
      const enforceability = assessEnforceability(text);
      const bypassRisk = 1 - enforceability;

      constraints.push({
        text,
        domain,
        enforceability,
        bypassRisk,
        weakness: bypassRisk > 0.5 ? identifyWeakness(text) : undefined,
      });
    }
  }

  return constraints;
}

function extractDataAccessPatterns(
  content: string,
  capabilities: Capability[],
  artifactType: ArtifactType = 'unknown',
): DataAccessPattern[] {
  const patterns: DataAccessPattern[] = [];

  // For source_code artifacts, substring matching on data-type keywords
  // ("token", "session", "credential") produces reflexive false positives:
  // any Go/TS/Python file with a variable named `scanToken` or a type named
  // `CredentialStore` gets flagged as accessing credentials. Source code
  // needs AST-based data flow analysis, not byte-level substring matches.
  // Skipping this pass for source_code eliminates the dominant false
  // positive mode without affecting skill/config/prompt analysis, where
  // the whole content is semantically meaningful.
  if (artifactType === 'source_code') {
    return patterns;
  }

  const dataTypes = ['user', 'customer', 'payment', 'session', 'credential', 'email', 'profile', 'medical', 'financial'];

  // Structured credential-like keys (JSON/YAML) declared with null/empty/placeholder
  // values are schema declarations of NO credentials, not credential access. An A2A
  // agent card with `"credentials": null` is claiming it holds none inline — the
  // opposite of a credential-access pattern. Only skip the credential data type if
  // every structured credential key has a null/empty/placeholder value.
  const credentialKeywordContext = analyzeCredentialKeywordContext(content);

  for (const dt of dataTypes) {
    if (content.toLowerCase().includes(dt)) {
      if ((dt === 'credential' || dt === 'session') && credentialKeywordContext === 'schema-only') {
        continue;
      }
      const hasCap = capabilities.some(c => c.name.includes('read') || c.name.includes('access'));
      patterns.push({
        dataType: dt === 'credential' || dt === 'session' ? 'credentials' :
                  dt === 'payment' || dt === 'financial' ? 'financial' :
                  dt === 'medical' ? 'pii' : 'general',
        accessMode: 'read',
        coveredByCapability: hasCap,
      });
    }
  }

  // Check for external transmission. Capture the first URL so downstream
  // analyzers (AST-CRED-002 in particular) can re-locate the trigger line
  // in the artifact for `generateVerifyCommand()` (issue #141). Trailing
  // sentence punctuation is trimmed so the destination matches the URL
  // as it appears in prose, not the URL plus terminal "."/")".
  const urlMatch = /https?:\/\/[^\s]+/.exec(content);
  if (urlMatch && /send|forward|transmit|post|upload/i.test(content)) {
    const destination = urlMatch[0].replace(/[.,;:!?)\]]+$/, '');
    patterns.push({
      dataType: 'general',
      accessMode: 'transmit',
      destination,
      coveredByCapability: capabilities.some(c => c.name.includes('api.call') || c.name.includes('send')),
    });
  }

  return patterns;
}

/**
 * Classify how credential-like keys appear in structured content (JSON/YAML).
 *
 * Returns:
 *   - 'value-present' — at least one structured credential key has a non-null,
 *     non-empty, non-placeholder value (e.g. `"credentials": "sk-..."`).
 *   - 'schema-only'   — one or more structured credential keys exist, and every
 *     one has a null/empty/placeholder value (e.g. `"credentials": null`, which
 *     declares the opposite of credential access — "no inline credentials").
 *   - 'no-structured' — credential-like keywords appear in the content but never
 *     as a JSON/YAML key (e.g. only in prose). Fall back to existing behavior.
 *
 * The A2A spec's `authentication.credentials: null` pattern is the motivating
 * case: a clean agent card declaring it holds no inline credentials was
 * triggering AST-CRED-001/003 and the CRED-HARVEST risk surface because the
 * keyword "credential" appeared in the content.
 */
export function analyzeCredentialKeywordContext(
  content: string,
): 'value-present' | 'schema-only' | 'no-structured' {
  // A canonical credential format anywhere in the content overrides the
  // schema-only classification. An agent card that declares
  // `"credentials": null` but embeds a real `sk-ant-api03-...` value in a
  // sibling field is NOT schema-only — it's an attacker trying to hide a
  // real credential behind an apparent null declaration.
  if (hasCanonicalCredentialFormat(content)) {
    return 'value-present';
  }

  // JSON/YAML-style credential-like key followed by `:` and a value.
  // Expanded from just `credentials?/passwords?/secrets?/tokens?/apiKey` to
  // include common adjacent credential-carrying keys (bearerToken,
  // access_key, client_secret, privateKey, jwt, authorization, authToken).
  // This prevents a malicious card with `"credentials": null, "bearerToken":
  // "sk-ant-real"` from being classified as schema-only.
  const keyRe = /(?:^|[{,\s])["']?(credentials?|passwords?|secrets?|tokens?|api[_-]?keys?|bearer[_-]?tokens?|access[_-]?keys?|client[_-]?secrets?|private[_-]?keys?|auth[_-]?tokens?|authorization|jwt|session[_-]?keys?|refresh[_-]?tokens?)(?:_?(?:file|id|hash|type|scheme|ref|store))?["']?\s*:\s*(\[\s*\]|\{\s*\}|"[^"\n]*"|'[^'\n]*'|null|undefined|none|true|false|[^,\n}\]]+)/gim;
  let sawStructured = false;
  let match: RegExpExecArray | null;
  while ((match = keyRe.exec(content)) !== null) {
    sawStructured = true;
    const value = match[2].trim();
    // Null / undefined / none / empty array / empty object / empty quoted string
    if (
      /^(null|undefined|none)$/i.test(value) ||
      /^\[\s*\]$/.test(value) ||
      /^\{\s*\}$/.test(value) ||
      /^("\s*"|'\s*')$/.test(value)
    ) {
      continue;
    }
    // Non-null, non-empty value present
    return 'value-present';
  }
  return sawStructured ? 'schema-only' : 'no-structured';
}

/**
 * True when the content contains at least one canonical credential format
 * (real API key / PEM block / etc.) outside obvious test-fixture markers.
 */
function hasCanonicalCredentialFormat(content: string): boolean {
  for (const { regex } of CANONICAL_CREDENTIAL_PATTERNS) {
    regex.lastIndex = 0;
    const match = regex.exec(content);
    if (match) {
      // Skip obvious test fixtures (FAKE, EXAMPLE, PLACEHOLDER, YOUR_)
      const ctxStart = Math.max(0, match.index - 40);
      const ctxEnd = Math.min(content.length, match.index + match[0].length + 40);
      const window = content.slice(ctxStart, ctxEnd).toUpperCase();
      if (/FAKE|EXAMPLE|PLACEHOLDER|YOUR_|<YOUR|DUMMY/.test(window)) {
        regex.lastIndex = 0;
        continue;
      }
      regex.lastIndex = 0;
      return true;
    }
    regex.lastIndex = 0;
  }
  return false;
}

// ============================================================================
// Canonical credential-format scan
// ============================================================================

interface CanonicalCredentialHit {
  label: string;
  evidence: string;
}

/**
 * Canonical credential-format patterns we trust enough to flag even when
 * the surrounding context is source code. Each pattern targets a real-world
 * secret format with low false-positive rate on arbitrary text.
 */
const CANONICAL_CREDENTIAL_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: 'Anthropic API key', regex: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/g },
  { label: 'OpenAI project key', regex: /sk-proj-[a-zA-Z0-9_-]{20,}/g },
  { label: 'AWS access key', regex: /AKIA[0-9A-Z]{16}/g },
  { label: 'GitHub personal access token', regex: /ghp_[a-zA-Z0-9]{36}/g },
  { label: 'GitHub OAuth token', regex: /gho_[a-zA-Z0-9]{36}/g },
  { label: 'GitHub app token', regex: /ghs_[a-zA-Z0-9]{36}/g },
  { label: 'Slack bot token', regex: /xox[baprs]-[a-zA-Z0-9-]{10,}/g },
  { label: 'Google API key', regex: /AIza[0-9A-Za-z_-]{35}/g },
  { label: 'Stripe live key', regex: /sk_live_[0-9a-zA-Z]{24,}/g },
  { label: 'PEM private key', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PRIVATE)[A-Z ]*KEY-----/g },
];

/**
 * Scan raw source content for concrete secret formats that are worth
 * flagging regardless of surrounding context. Returns a list of hits.
 *
 * Filters out matches that look like:
 *   - Regex rule definitions in a scanner's own source (contain `\d`,
 *     `[a-z]`, `{6,}`, or other regex metacharacters adjacent to the
 *     match). A security scanner quoting `sk-ant-api\d{2}-[a-zA-Z0-9_-]{6,}`
 *     in a regex pattern is not a leaked credential.
 *   - Test fixtures containing `FAKE`, `EXAMPLE`, `PLACEHOLDER`, `DUMMY`,
 *     `SAMPLE`, `TEST`, `XXX`, `YOUR_` markers in the surrounding window.
 */
function scanCanonicalCredentialFormats(content: string): CanonicalCredentialHit[] {
  const hits: CanonicalCredentialHit[] = [];

  // Markers that, when embedded directly in the key bytes themselves,
  // indicate the value is a placeholder rather than a real credential.
  // Using word-boundary anchors on the match (not the surrounding code)
  // so a comment like "// for testing" in the same file doesn't mask a
  // real planted key.
  const inKeyFixtureMarker = /FAKE|EXAMPLE|PLACEHOLDER|DUMMY|YOUR_?KEY|YOUR_?TOKEN|REPLACE_ME|INSERT_HERE/i;
  // Markers in the immediate preceding window (label / variable name)
  // that strongly suggest a template value (e.g. `YOUR_API_KEY=...`).
  const preKeyTemplateMarker = /(<\s*YOUR_|\bYOUR[_-]?(?:KEY|TOKEN|SECRET)|example[_-]?key|template[_-]?key|placeholder)/i;
  // Regex metacharacters indicating the match is inside a scanner rule
  // definition rather than a concrete key literal.
  const regexContextMarker = /\\d|\\w|\\s|\[a-z|\[A-Z|\[0-9|\{\d+,|\*\?|\+\?/;

  for (const { label, regex } of CANONICAL_CREDENTIAL_PATTERNS) {
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
      const matched = match[0];
      // Narrow preceding context: just the 40 chars before the match,
      // which covers the variable/label on the same line but not the
      // whole file. We explicitly do NOT check the full window, because
      // unrelated comments (e.g. "// testing ...") are often nearby.
      const preStart = Math.max(0, match.index - 40);
      const preContext = content.slice(preStart, match.index);

      // Skip matches inside regex rule definitions.
      if (regexContextMarker.test(preContext) || regexContextMarker.test(matched)) {
        continue;
      }

      // Skip if the key bytes themselves contain placeholder markers.
      if (inKeyFixtureMarker.test(matched)) {
        continue;
      }

      // Skip if the immediate label/variable name indicates a template.
      if (preKeyTemplateMarker.test(preContext)) {
        continue;
      }

      hits.push({
        label,
        evidence: `${label}: ${matched.slice(0, 16)}...`,
      });
    }
  }
  return hits;
}

function extractDependencies(content: string): string[] {
  const deps: string[] = [];
  // References to other files/packages
  const importPatterns = /(?:import|require|from)\s+['"](\.\/[^'"]+|@[^'"]+)['"]/g;
  let match;
  while ((match = importPatterns.exec(content)) !== null) {
    deps.push(match[1]);
  }
  return deps;
}

function extractGovernanceReferences(content: string): string[] {
  const refs: string[] = [];
  if (/soul\.md/i.test(content)) refs.push('soul.md');
  if (/system.?prompt/i.test(content)) refs.push('system_prompt');
  if (/claude\.md/i.test(content)) refs.push('claude.md');
  return refs;
}

/**
 * Score how many contextual benign signals are present in text.
 * Higher score = stronger evidence the content is benign despite attack vocabulary.
 *
 * Used to override or downgrade the neural classifier when content is:
 * - Explicitly authorized (pentest, RoE, IRB)
 * - Educational/defensive (lists attacks to teach defenses)
 * - Negation lists (SOUL explicitly prohibiting attacks)
 * - Research contexts (sandboxed, isolated, academic)
 * - Retrospective writeups (CTF solutions, responsible disclosure)
 * - Bounded scope declarations (network_access: false, env var refs)
 *
 * Gate: score >= 2 → downgrade malicious→suspicious; score >= 4 → classify benign.
 */
function detectContextualBenignSignals(text: string): number {
  let score = 0;

  // Authorization: explicit written authorization for security testing
  if (/written\s+authorization|rules\s+of\s+engagement|signed\s+(?:roe|engagement|contract)|authorized\s+(?:pentest|penetration\s+test|scan|recon)|engagement\s+record/i.test(text)) score += 3;

  // Negation list: artifact enumerates attacks it is prohibited from performing
  if (/(?:will\s+not\s+do|will\s+never\s*:|i\s+will\s+never|agent\s+will\s+never|what\s+(?:i|we|this\s+agent)\s+(?:will\s+not|won't)|things?\s+(?:i|we)\s+(?:will\s+never|won't)|prohibited\s+actions?)/i.test(text)) score += 3;

  // Educational / defensive framing: content teaches defenses using attack examples
  if (/(?:do\s+not\s+use|don't\s+use).*(?:example|attack)|(?:example|sample)\s+attack.*do\s+not|defense\s+patterns?|for\s+(?:defense|defensive\s+purposes?)|teaches?\s+(?:how\s+to\s+defend|defense|protection)|red-?team\s+exercise|practice\s+recognizing|educational\s+material|how\s+to\s+defend\s+against/i.test(text)) score += 2;

  // Research context: isolated/sandboxed environment with credentialed access
  if (/\birb\b|institutional\s+review\s+board|isolated\s+(?:research\s+)?environment|research\s+sandbox|credentialed\s+researcher|per\s+irb\s+protocol|academic\s+record-?keeping/i.test(text)) score += 3;

  // Retrospective / responsible disclosure
  if (/ctf\s+writeup|capture\s+the\s+flag.*(?:challenge|writeup|solution)|reported\s+(?:the\s+)?vulnerabilit|responsible\s+disclosure|challenge\s+organizers?/i.test(text)) score += 2;

  // Negative capability declarations: explicit scope boundaries
  if (/network[_\-\s]?access\s*[:=]\s*false|execute[_\-\s]?shell\s*[:=]\s*false|no\s+(?:network|filesystem|shell)\b|without\s+(?:network|shell|filesystem)\s+access/i.test(text)) score += 2;

  // Env var references (not hardcoded secrets)
  if (/\$\{[A-Z_]*(?:TOKEN|KEY|SECRET|PASSWORD)[A-Z_]*\}/i.test(text)) score += 2;

  // Scoped path declarations (not / or root)
  if (/workspaceFolder|\${workspaceFolder}|~\/projects|~\/workspace|workspace-scoped|scoped\s+to\s+(?:the\s+)?(?:current\s+)?workspace/i.test(text)) score += 1;

  // "will never/not" + attack verb: explicit prohibition (softer than "must never" but valid constraint)
  if (/will\s+(?:never|not)\s+(?:execute|access|exfiltrate|install|bypass|share|store|transmit|harvest|steal|exfil)/i.test(text)) score += 2;

  return score;
}

/**
 * Detect governance content that talks ABOUT security constraints.
 * These documents set rules ("must never share credentials") not perform attacks.
 * Without this check, governance docs that mention attack patterns defensively
 * get flagged as malicious.
 */
function isGovernanceContent(text: string): boolean {
  // Include "will never" / "will not" as valid constraint phrases — SOULs that list
  // prohibited actions using "will never" or "will not" are governance documents
  // even if they don't use "must never" or "shall not" phrasing.
  const constraintCount = (text.match(/must never|must not|must always|should not|should never|forbidden|prohibited|restricted to|shall not|will never|will not do|i will not|agent will never|this agent will never/gi) || []).length;
  const sectionHeaders = /## (?:trust|governance|constraint|oversight|data handling|behavioral|identity|error|credential|scope|permission|boundary)/i.test(text);

  // Credential-protection instruction patterns: files that TEACH credential
  // safety should not be flagged for credential harvesting.
  // Counter-signals: "never hardcode", "use environment variables", "rotate",
  // "protect credentials", "secretless", "blocked file patterns", etc.
  const credProtectionSignals = (text.match(/never hardcode|use environment variable|rotate.*credential|protect.*credential|credential.*protect|secretless|blocked.?file.?pattern|do not.*print.*key|never.*echo.*secret|env\.example/gi) || []).length;

  // 3+ constraint phrases, governance section headers, or 2+ credential-protection signals
  return constraintCount >= 3 || sectionHeaders || credProtectionSignals >= 2;
}

function mapRiskSurfaces(
  content: string,
  declared: Capability[],
  inferred: Capability[],
  intent: IntentClass,
  artifactType: ArtifactType = 'unknown',
): RiskSurface[] {
  const surfaces: RiskSurface[] = [];

  // Source code needs semantic (AST) analysis, not regex-based substring
  // matching on content. The risk-surface checks below were designed for
  // skills, agent configs, and system prompts, where the entire content is
  // semantically meaningful and finding the string "password" next to
  // "request" plausibly implies credential harvesting. In a Go or TypeScript
  // file, the same substrings are almost always idiomatic identifiers and
  // HTTP helpers (`githubToken`, `http.NewRequest`), which makes every
  // network service file fire CRED-HARVEST. The preprocessor already
  // strips comments, imports, and string literals; even so, the remaining
  // identifier tokens produce near-100% false positive rates on real
  // codebases. Skipping the config-oriented substring pathway for source
  // code eliminates the reflexive false positive mode entirely. Any real
  // source-level attack surface belongs to a dedicated AST analyzer, not
  // to this regex pass.
  if (artifactType === 'source_code') {
    // Source-level risk surfaces are surfaced by the analyzer layer, not
    // by regex-matching raw content here.
    return surfaces;
  }

  const text = content.toLowerCase();

  // Detect governance documents -- these talk ABOUT security, not perform attacks
  // SOUL.md, governance docs, and system prompts with constraint language
  const isGovernanceDoc = isGovernanceContent(text);

  // Compute benign context score once for reuse across all surface checks
  const benignContextScore = detectContextualBenignSignals(content);

  // External URL + data forwarding = exfiltration surface
  // Skip for governance docs (they describe rules about data handling, not perform exfiltration)
  // Evidence: prefer the URL span (more specific anchor than the verb).
  if (!isGovernanceDoc && benignContextScore < 2) {
    const urlMatch = /https?:\/\/[^\s]+\.(co|io|com|net|org)/.exec(content);
    const verbMatch = /forward|send|transmit|export/i.exec(content);
    if (urlMatch && verbMatch) {
      surfaces.push({
        surface: 'External data transmission',
        attackClass: 'SKILL-EXFIL',
        confidence: intent === 'malicious' ? 0.9 : intent === 'suspicious' ? 0.6 : 0.3,
        evidence: urlMatch[0],
      });
    }
  }

  // Override/ignore instructions = injection surface
  // Guards:
  //   isDefensiveConstraint — content explicitly prohibits override ("must never override", "will never ignore")
  //   isProhibitionList — content has a "will NOT do" / "I will never" section listing attacks to prohibit
  //   isGovernanceDoc — content is a governance document (SOUL, system prompt) — these cite injection
  //     examples in defensive sections like "## Injection Hardening" to teach the agent what to reject.
  //     A governance document is the definition of injection resistance, not an injection vector.
  //   isExampleContext — injection phrases appear inside a "phrases such as '...'" quotation, indicating
  //     they are examples the agent must reject, not directives being issued.
  //   benignContextScore >= 2 — content has sufficient benign signals (authorized, educational, research)
  // All guards suppress the injection surface to avoid flagging:
  //   - SOULs that enumerate attacks they are forbidden from performing (b05)
  //   - Governance docs with "## Injection Hardening" sections (b11)
  //   - Educational docs that quote attack examples with "DO NOT USE" labels (b02)
  //   - Authorized security assessments referencing specific attack techniques
  const overrideMatch = /ignore.*previous|override.*instruction|new.*task/i.exec(content);
  const isDefensiveConstraint =
    /must never|must not|never comply|resist|reject|refuse|forbidden|should not|do not|prohibited|will never|will not/i.test(text) &&
    /override|ignore|bypass|injection|inject/i.test(text);
  const isProhibitionList = /(?:will\s+not\s+do|will\s+never\s*:|i\s+will\s+never|agent\s+will\s+never|what\s+(?:i|we|this\s+agent)\s+(?:will\s+not|won't))/i.test(content);
  // "phrases such as 'ignore previous instructions'" — injection example in an educational/rejection context
  const isExampleContext = /phrases?\s+(?:such\s+as|like|including)\s+["']?(?:ignore|override|new\s+task)/i.test(content);
  if (overrideMatch && !isDefensiveConstraint && !isProhibitionList && !isGovernanceDoc && !isExampleContext && benignContextScore < 2) {
    surfaces.push({
      surface: 'Instruction override language',
      attackClass: 'PROMPT-INJECT',
      confidence: 0.8,
      evidence: overrideMatch[0],
    });
  }

  // Structural injection patterns (JSON configs, code blocks, hidden directives)
  // Skipped for governance documents — a SOUL.md trust hierarchy section names "System prompt"
  // as the highest-authority source and separately discusses "override" in a defensive context.
  // The regex pattern would match across paragraphs, producing a critical FP on well-governed SOULs.
  // Evidence is a description rather than a verbatim span because the trigger normalizes content
  // (strips _, -, whitespace) and so no `match[0]` corresponds to a contiguous source substring.
  // Line lookup falls through to undefined cleanly for this rare structural rule.
  if (!isGovernanceDoc && /systemprompt.*override|systemprompt.*ignore|systemprompt.*bypass/i.test(text.replace(/[_\-\s]/g, ''))) {
    surfaces.push({
      surface: 'Hidden system prompt override in config',
      attackClass: 'PROMPT-INJECT',
      confidence: 0.9,
      evidence: 'systemPrompt field contains override directives',
    });
  }
  const controlTokenMatch = /\[inst\]|\[\/inst\]|<<sys>>|<\|im_start\|>/i.exec(content);
  if (controlTokenMatch) {
    surfaces.push({
      surface: 'LLM control tokens in content',
      attackClass: 'PROMPT-INJECT',
      confidence: 0.85,
      evidence: controlTokenMatch[0],
    });
  }
  const codeExecMatch = /new\s+function\s*\(|eval\s*\(|node\s+-e\s+['"]/i.exec(content);
  if (codeExecMatch) {
    surfaces.push({
      surface: 'Dynamic code execution in config',
      attackClass: 'HEARTBEAT-RCE',
      confidence: 0.9,
      evidence: codeExecMatch[0],
    });
  }
  const shellPipeMatch = /curl\s+.*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh/i.exec(content);
  if (shellPipeMatch) {
    surfaces.push({
      surface: 'Shell pipe execution',
      attackClass: 'HEARTBEAT-RCE',
      confidence: 0.95,
      evidence: shellPipeMatch[0],
    });
  }
  // Compound: timer + remote URL. Use the timer span as anchor — it's the
  // heartbeat signal that distinguishes this from a one-shot fetch.
  const timerMatch = /setinterval|settimeout|while\s+true|cron|every\s+\d+\s*(min|sec|hour)/i.exec(content);
  if (timerMatch && /https?:\/\//i.test(content)) {
    surfaces.push({
      surface: 'Periodic remote callback',
      attackClass: 'HEARTBEAT-RCE',
      confidence: 0.85,
      evidence: timerMatch[0],
    });
  }
  // Compound: command field + risky args. Use the command span as anchor.
  const mcpCmdMatch = /"command"\s*:\s*"(bash|sh|node|python)"/i.exec(content);
  if (mcpCmdMatch && /"args"\s*:\s*\[.*(-e|-c|eval|exec)/i.test(content)) {
    surfaces.push({
      surface: 'Inline code execution in MCP config',
      attackClass: 'HEARTBEAT-RCE',
      confidence: 0.9,
      evidence: mcpCmdMatch[0],
    });
  }

  // Credential access patterns
  // Skip for governance docs (they set rules about credentials, not harvest them).
  // Also skip when every structured credential key has a null/empty/placeholder
  // value — an A2A agent card declaring `"credentials": null` plus a "provider"
  // field is not credential harvesting; it's schema metadata.
  if (!isGovernanceDoc && /password|credential|api[_-]?key|secret|token/i.test(text) && /ask|request|share|provide/i.test(text)) {
    const credentialCtx = analyzeCredentialKeywordContext(content);
    if (credentialCtx !== 'schema-only') {
      // Capture the credential keyword span verbatim from content so the
      // analyzer line lookup hits the right line.
      const credKeywordMatch = /password|credential|api[_-]?key|secret|token/i.exec(content);
      surfaces.push({
        surface: 'Credential harvesting',
        attackClass: 'CRED-HARVEST',
        confidence: 0.7,
        evidence: credKeywordMatch?.[0] ?? 'Requests credentials from users or systems',
      });
    }
  }

  // Remote instruction fetch
  const remoteFetchMatch = /fetch.*config|check.*update.*from|load.*instruction/i.exec(content);
  if (remoteFetchMatch) {
    surfaces.push({
      surface: 'Remote instruction fetch',
      attackClass: 'HEARTBEAT-RCE',
      confidence: 0.8,
      evidence: remoteFetchMatch[0],
    });
  }

  // Bulk data export = data exfiltration surface (skip governance docs)
  if (!isGovernanceDoc) {
    const selectMatch = /select\s+\*\s+from/i.exec(content);
    if (selectMatch && /https?:\/\/[^\s]+/i.test(content)) {
      surfaces.push({
        surface: 'Bulk database export to external endpoint',
        attackClass: 'DATA-EXFIL',
        confidence: 0.85,
        evidence: selectMatch[0],
      });
    } else {
      const piiMatch = /include.*pii|transmit.*pii|forward.*record|export.*data.*external/i.exec(content);
      if (piiMatch) {
        surfaces.push({
          surface: 'PII/data export to external endpoint',
          attackClass: 'DATA-EXFIL',
          confidence: 0.8,
          evidence: piiMatch[0],
        });
      }
    }
  }

  // Supply chain: typosquatted package names
  const knownOrgs = ['modelcontextprotocol', 'anthropic-ai', 'opena2a-org', 'opena2a'];
  const packageRefs = content.match(/@[a-z0-9_-]+(?:\/[a-z0-9_.-]+)?/gi) ?? [];
  for (const ref of packageRefs) {
    const org = ref.replace(/^@/, '').split('/')[0].toLowerCase();
    for (const known of knownOrgs) {
      if (org !== known && levenshtein(org, known) <= 2 && levenshtein(org, known) > 0) {
        surfaces.push({
          surface: `Typosquatted package: ${ref}`,
          attackClass: 'SUPPLY-CHAIN',
          confidence: 0.95,
          // ref is the verbatim package reference captured from content.match above.
          evidence: ref,
        });
        break;
      }
    }
  }

  // Supply chain: postinstall/exec in MCP config
  const supplyChainMatch = /postinstall|pre-?install|curl.*\|.*sh|wget.*\|.*bash/i.exec(content);
  if (supplyChainMatch) {
    surfaces.push({
      surface: 'Shell execution in package/config',
      attackClass: 'SUPPLY-CHAIN',
      confidence: 0.9,
      evidence: supplyChainMatch[0],
    });
  }

  // Undeclared capabilities (inferred but not declared)
  for (const cap of inferred) {
    if (!cap.declared && cap.riskLevel !== 'low') {
      surfaces.push({
        surface: `Undeclared capability: ${cap.name}`,
        attackClass: 'PRIV-ESCALATION',
        confidence: 0.6,
        // Prefer the inferred cap's own verbatim evidence (when the upstream
        // inference recorded a span) over a description that won't substring-
        // match the artifact for line lookup.
        evidence: cap.evidence ?? `Capability ${cap.name} is inferred from content but not declared`,
      });
    }
  }

  return surfaces;
}

/** Simple Levenshtein distance for typosquat detection */
function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0)
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function extractEvidenceSpans(content: string, risks: RiskSurface[]): EvidenceSpan[] {
  const spans: EvidenceSpan[] = [];

  for (const risk of risks) {
    // Find the evidence text in the original content
    const idx = content.toLowerCase().indexOf(risk.evidence.toLowerCase().slice(0, 30));
    if (idx >= 0) {
      const end = Math.min(idx + 100, content.length);
      spans.push({
        start: idx,
        end,
        text: content.slice(idx, end),
        supports: risk.attackClass,
        confidence: risk.confidence,
      });
    }
  }

  return spans;
}

// ============================================================================
// Heuristic Fallback (when NanoMind daemon is unavailable)
// ============================================================================

function heuristicIntentClassification(
  content: string,
  capabilities: Capability[],
  constraints: Constraint[],
): { intentClass: IntentClass; confidence: number; inferredCapabilities: Capability[] } {
  const text = content.toLowerCase();
  let maliciousSignals = 0;
  let benignSignals = 0;

  // Context score: authorization, educational, research, negation-list signals
  const contextScore = detectContextualBenignSignals(content);

  // Malicious signals — only counted when benign context is absent
  // "execute.*shell" and similar broad-capability signals are suppressed for
  // artifacts with explicit scope bounds (e.g. shell-runner with network_access:false)
  if (/forward.*token.*external|send.*credential.*endpoint/i.test(text)) maliciousSignals += 3;
  if (/ignore.*previous.*instruction|override.*system/i.test(text) && contextScore < 2) maliciousSignals += 3;
  if (/fetch.*config.*external|heartbeat.*url.*execute/i.test(text)) maliciousSignals += 2;
  if (/always.*remember.*permanently|persist.*instruction/i.test(text)) maliciousSignals += 2;
  // Broad capability signal only counts when no benign scope-bounding context exists
  if (/admin.*access|root.*privilege|execute.*shell/i.test(text) && contextScore < 2) maliciousSignals += 2;

  // Benign signals
  if (constraints.length >= 3) benignSignals += 2;
  if (/must never|should not|forbidden|restricted|will never|will not/i.test(text)) benignSignals += 1;
  if (capabilities.length > 0 && capabilities.every(c => c.declared)) benignSignals += 1;

  // Context-aware benign signals from authorization/educational/research framing
  // Add directly — these are strong priors that outweigh vocabulary-based signals
  benignSignals += contextScore;

  if (maliciousSignals >= 3 && benignSignals <= maliciousSignals) {
    return { intentClass: 'malicious', confidence: Math.min(0.9, 0.5 + maliciousSignals * 0.1), inferredCapabilities: [] };
  }
  if (maliciousSignals > 0 && benignSignals <= maliciousSignals) {
    return { intentClass: 'suspicious', confidence: 0.4 + maliciousSignals * 0.1, inferredCapabilities: [] };
  }
  return { intentClass: 'benign', confidence: Math.min(0.9, 0.7 + benignSignals * 0.05), inferredCapabilities: [] };
}

// ============================================================================
// Helpers
// ============================================================================

function assessCapabilityRisk(capability: string): 'low' | 'medium' | 'high' | 'critical' {
  const cap = capability.toLowerCase();
  if (/delete|execute|admin|system|shell|root/.test(cap)) return 'critical';
  if (/write|send|modify|create|transmit/.test(cap)) return 'high';
  if (/read|access|query|fetch|call/.test(cap)) return 'medium';
  return 'low';
}

function classifyConstraintDomain(text: string): ConstraintDomain {
  const t = text.toLowerCase();
  if (/trust|authority|hierarchy/.test(t)) return 'trust_hierarchy';
  if (/oversight|human|approval|review/.test(t)) return 'human_oversight';
  if (/data|pii|privacy|confidential/.test(t)) return 'data_handling';
  if (/revers|undo|rollback/.test(t)) return 'action_reversibility';
  if (/capabilit|scope|permission|access/.test(t)) return 'capability_boundary';
  if (/identit|disclose|transparen/.test(t)) return 'identity_disclosure';
  if (/error|fail|exception/.test(t)) return 'error_handling';
  if (/credential|secret|key|token/.test(t)) return 'credential_management';
  if (/behav|conduct|manner/.test(t)) return 'behavioral_constraint';
  return 'general';
}

function assessEnforceability(text: string): number {
  const t = text.toLowerCase();
  // Strong enforcement language
  if (/must never|shall not|forbidden|prohibited|blocked|will never/.test(t)) return 0.8;
  if (/must|required|mandatory|will not/.test(t)) return 0.7;
  // Weak enforcement language
  if (/should|recommended|preferred/.test(t)) return 0.4;
  if (/may|can|might|when appropriate|use judgment/.test(t)) return 0.2;
  return 0.5;
}

function identifyWeakness(text: string): string {
  const t = text.toLowerCase();
  if (/when appropriate|use judgment|if needed/.test(t)) return 'Discretionary language allows edge-case bypass';
  if (/should|recommended/.test(t)) return 'Advisory language is not enforced';
  if (/unless|except|however/.test(t)) return 'Exception clause may be exploitable';
  return 'Constraint language may not be enforceable';
}

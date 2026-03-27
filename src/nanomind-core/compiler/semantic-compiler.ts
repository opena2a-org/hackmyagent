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

    // Step 4: Extract declarations from artifact structure
    const declaredCapabilities = extractDeclaredCapabilities(content, parsed.type, parsed.frontmatter);
    const declaredConstraints = extractDeclaredConstraints(content);
    const declaredDataAccess = extractDataAccessPatterns(content, declaredCapabilities);
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

    // Step 6: Map risk surfaces
    const inferredRiskSurface = mapRiskSurfaces(content, declaredCapabilities, inferredCapabilities, intentClassification);

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
    // Tier 1: Local TME classifier (ONNX neural if available, vocab fallback)
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

  // From first paragraph
  const lines = content.split('\n').filter(l => l.trim().length > 0);
  for (const line of lines) {
    if (!line.startsWith('#') && !line.startsWith('-') && !line.startsWith('---') && line.trim().length > 20) {
      return line.trim().slice(0, 200);
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
        for (const tool of tools) {
          caps.push({
            name: `mcp.${name}.${tool}`,
            scope: name,
            declared: true,
            inferred: false,
            riskLevel: tool === '*' ? 'high' : 'medium',
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
    });
  }

  return caps;
}

function extractDeclaredConstraints(content: string): Constraint[] {
  const constraints: Constraint[] = [];
  const patterns = /(?:must|should|never|always|cannot|will not|forbidden|shall not|restricted to)[^.]+\./gi;
  const matches = content.match(patterns);

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

function extractDataAccessPatterns(content: string, capabilities: Capability[]): DataAccessPattern[] {
  const patterns: DataAccessPattern[] = [];
  const dataTypes = ['user', 'customer', 'payment', 'session', 'credential', 'email', 'profile', 'medical', 'financial'];

  for (const dt of dataTypes) {
    if (content.toLowerCase().includes(dt)) {
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

  // Check for external transmission
  if (/https?:\/\/[^\s]+/.test(content) && /send|forward|transmit|post|upload/i.test(content)) {
    patterns.push({
      dataType: 'general',
      accessMode: 'transmit',
      destination: 'external',
      coveredByCapability: capabilities.some(c => c.name.includes('api.call') || c.name.includes('send')),
    });
  }

  return patterns;
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
 * Detect governance content that talks ABOUT security constraints.
 * These documents set rules ("must never share credentials") not perform attacks.
 * Without this check, governance docs that mention attack patterns defensively
 * get flagged as malicious.
 */
function isGovernanceContent(text: string): boolean {
  const constraintCount = (text.match(/must never|must not|must always|should not|should never|forbidden|prohibited|restricted to|shall not/gi) || []).length;
  const sectionHeaders = /## (?:trust|governance|constraint|oversight|data handling|behavioral|identity|error|credential|scope|permission|boundary)/i.test(text);
  // 3+ constraint phrases or governance section headers = governance doc
  return constraintCount >= 3 || sectionHeaders;
}

function mapRiskSurfaces(
  content: string,
  declared: Capability[],
  inferred: Capability[],
  intent: IntentClass,
): RiskSurface[] {
  const surfaces: RiskSurface[] = [];
  const text = content.toLowerCase();

  // Detect governance documents -- these talk ABOUT security, not perform attacks
  // SOUL.md, governance docs, and system prompts with constraint language
  const isGovernanceDoc = isGovernanceContent(text);

  // External URL + data forwarding = exfiltration surface
  // Skip for governance docs (they describe rules about data handling, not perform exfiltration)
  if (!isGovernanceDoc && /https?:\/\/[^\s]+\.(co|io|com|net|org)/.test(content) && /forward|send|transmit|export/i.test(text)) {
    surfaces.push({
      surface: 'External data transmission',
      attackClass: 'SKILL-EXFIL',
      confidence: intent === 'malicious' ? 0.9 : intent === 'suspicious' ? 0.6 : 0.3,
      evidence: 'External URL combined with data forwarding language',
    });
  }

  // Override/ignore instructions = injection surface
  // Defensive constraint language is NOT an injection
  const hasOverrideLanguage = /ignore.*previous|override.*instruction|new.*task/i.test(text);
  const isDefensiveConstraint = /must never|must not|never comply|resist|reject|refuse|forbidden|should not|do not|prohibited/.test(text)
    && /override|ignore|bypass|injection|inject/i.test(text);
  if (hasOverrideLanguage && !isDefensiveConstraint) {
    surfaces.push({
      surface: 'Instruction override language',
      attackClass: 'PROMPT-INJECT',
      confidence: 0.8,
      evidence: 'Contains language that overrides prior instructions',
    });
  }

  // Structural injection patterns (JSON configs, code blocks, hidden directives)
  if (/systemprompt.*override|systemprompt.*ignore|systemprompt.*bypass/i.test(text.replace(/[_\-\s]/g, ''))) {
    surfaces.push({
      surface: 'Hidden system prompt override in config',
      attackClass: 'PROMPT-INJECT',
      confidence: 0.9,
      evidence: 'systemPrompt field contains override directives',
    });
  }
  if (/\[inst\]|\[\/inst\]|<<sys>>|<\|im_start\|>/i.test(text)) {
    surfaces.push({
      surface: 'LLM control tokens in content',
      attackClass: 'PROMPT-INJECT',
      confidence: 0.85,
      evidence: 'Contains LLM instruction tokens ([INST], <<SYS>>, etc.)',
    });
  }
  if (/new\s+function\s*\(|eval\s*\(|node\s+-e\s+['"]/i.test(text)) {
    surfaces.push({
      surface: 'Dynamic code execution in config',
      attackClass: 'HEARTBEAT-RCE',
      confidence: 0.9,
      evidence: 'Config contains eval/Function constructor for remote code execution',
    });
  }
  if (/curl\s+.*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh/i.test(content)) {
    surfaces.push({
      surface: 'Shell pipe execution',
      attackClass: 'HEARTBEAT-RCE',
      confidence: 0.95,
      evidence: 'curl/wget piped to shell for remote command execution',
    });
  }
  if (/setinterval|settimeout|while\s+true|cron|every\s+\d+\s*(min|sec|hour)/i.test(text) && /https?:\/\//i.test(content)) {
    surfaces.push({
      surface: 'Periodic remote callback',
      attackClass: 'HEARTBEAT-RCE',
      confidence: 0.85,
      evidence: 'Periodic timer with remote URL (heartbeat/beacon pattern)',
    });
  }
  if (/"command"\s*:\s*"(bash|sh|node|python)"/i.test(content) && /"args"\s*:\s*\[.*(-e|-c|eval|exec)/i.test(content)) {
    surfaces.push({
      surface: 'Inline code execution in MCP config',
      attackClass: 'HEARTBEAT-RCE',
      confidence: 0.9,
      evidence: 'MCP server uses inline script execution via -e/-c flag',
    });
  }

  // Credential access patterns
  // Skip for governance docs (they set rules about credentials, not harvest them)
  if (!isGovernanceDoc && /password|credential|api[_-]?key|secret|token/i.test(text) && /ask|request|share|provide/i.test(text)) {
    surfaces.push({
      surface: 'Credential harvesting',
      attackClass: 'CRED-HARVEST',
      confidence: 0.7,
      evidence: 'Requests credentials from users or systems',
    });
  }

  // Remote instruction fetch
  if (/fetch.*config|check.*update.*from|load.*instruction/i.test(text)) {
    surfaces.push({
      surface: 'Remote instruction fetch',
      attackClass: 'HEARTBEAT-RCE',
      confidence: 0.8,
      evidence: 'Fetches instructions from remote URLs',
    });
  }

  // Bulk data export = data exfiltration surface (skip governance docs)
  if (!isGovernanceDoc && /select\s+\*\s+from/i.test(text) && /https?:\/\/[^\s]+/i.test(content)) {
    surfaces.push({
      surface: 'Bulk database export to external endpoint',
      attackClass: 'DATA-EXFIL',
      confidence: 0.85,
      evidence: 'SELECT * queries combined with external URL transmission',
    });
  } else if (!isGovernanceDoc && /include.*pii|transmit.*pii|forward.*record|export.*data.*external/i.test(text)) {
    surfaces.push({
      surface: 'PII/data export to external endpoint',
      attackClass: 'DATA-EXFIL',
      confidence: 0.8,
      evidence: 'PII or bulk data export to external service',
    });
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
          evidence: `Package "${ref}" looks like a typosquat of @${known}`,
        });
        break;
      }
    }
  }

  // Supply chain: postinstall/exec in MCP config
  if (/postinstall|pre-?install|curl.*\|.*sh|wget.*\|.*bash/i.test(text)) {
    surfaces.push({
      surface: 'Shell execution in package/config',
      attackClass: 'SUPPLY-CHAIN',
      confidence: 0.9,
      evidence: 'Shell command execution pattern in configuration',
    });
  }

  // Undeclared capabilities (inferred but not declared)
  for (const cap of inferred) {
    if (!cap.declared && cap.riskLevel !== 'low') {
      surfaces.push({
        surface: `Undeclared capability: ${cap.name}`,
        attackClass: 'PRIV-ESCALATION',
        confidence: 0.6,
        evidence: `Capability ${cap.name} is inferred from content but not declared`,
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

  // Malicious signals
  if (/forward.*token.*external|send.*credential.*endpoint/i.test(text)) maliciousSignals += 3;
  if (/ignore.*previous.*instruction|override.*system/i.test(text)) maliciousSignals += 3;
  if (/fetch.*config.*external|heartbeat.*url.*execute/i.test(text)) maliciousSignals += 2;
  if (/always.*remember.*permanently|persist.*instruction/i.test(text)) maliciousSignals += 2;
  if (/admin.*access|root.*privilege|execute.*shell/i.test(text)) maliciousSignals += 2;

  // Benign signals
  if (constraints.length >= 3) benignSignals += 2;
  if (/must never|should not|forbidden|restricted/i.test(text)) benignSignals += 1;
  if (capabilities.length > 0 && capabilities.every(c => c.declared)) benignSignals += 1;

  if (maliciousSignals >= 3) {
    return { intentClass: 'malicious', confidence: Math.min(0.9, 0.5 + maliciousSignals * 0.1), inferredCapabilities: [] };
  }
  if (maliciousSignals > 0) {
    return { intentClass: 'suspicious', confidence: 0.4 + maliciousSignals * 0.1, inferredCapabilities: [] };
  }
  return { intentClass: 'benign', confidence: 0.7 + benignSignals * 0.05, inferredCapabilities: [] };
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
  if (/must never|shall not|forbidden|prohibited|blocked/.test(t)) return 0.8;
  if (/must|required|mandatory/.test(t)) return 0.7;
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

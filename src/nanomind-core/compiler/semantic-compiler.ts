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
import { redactSecretsForReport } from '../security/defense-in-depth.js';
import { getTMEClassifier } from '../inference/tme-classifier.js';
import { TMENeuralClassifier } from '../inference/tme-neural.js';
import { buildAnalysisView } from './source-code-preprocessor.js';
import {
  CREDENTIAL_NOUN,
  EXFIL_VERB,
  TRANSMIT_VERB,
  findStructuredCredentialTransmission,
  findStructuredFirstUrl,
  findStructuredVerbUrl,
  parseStructuredJson,
} from './structured-colocation.js';
import type {
  SecurityAST,
  CompilationResult,
  CompilerConfig,
  Capability,
  Constraint,
  ConstraintDomain,
  DataAccessPattern,
  DeterministicFinding,
  RiskSurface,
  IntentClass,
  EvidenceSpan,
  ArtifactType,
  VerdictAdjustment,
  VerdictAdjustmentSource,
} from '../types.js';

/**
 * What the deterministic exfiltration rule (an external URL plus a data-forwarding
 * verb) is worth on its own, with no model verdict in the input.
 *
 * It used to have no value of its own: the surface was pushed at
 * `intent === 'malicious' ? 0.9 : intent === 'suspicious' ? 0.6 : 0.3`, so the
 * SAME matched bytes were reported CRITICAL, HIGH or MEDIUM depending on what a
 * vocabulary scorer thought of the surrounding prose — and the capability
 * analyzer turns exactly that number into the severity a user reads. 0.6 is the
 * mid rung the rule already used when the classifier was undecided, which is the
 * honest reading of "this rule matched and nothing else has spoken yet". The
 * model may still raise it to 0.9; it may no longer take it to 0.3.
 */
export const DETERMINISTIC_EXFIL_CONFIDENCE = 0.6;

/**
 * One verdict-plus-confidence pair, with the downgrade a layer asked to apply
 * to it. `proposedDowngrade` is a REQUEST, not a decision — `applyDeterministicFloor`
 * decides, because only it knows what the deterministic layer found.
 */
interface ScoredVerdict {
  intentClass: IntentClass;
  confidence: number;
  inferredCapabilities: Capability[];
  proposedDowngrade?: VerdictAdjustment;
}

/** Everything `compile` caches for a content hash, not just the AST. */
interface CachedCompilation {
  ast: SecurityAST;
  deterministicFindings: DeterministicFinding[];
  verdictAdjustments: VerdictAdjustment[];
  refusedAdjustments: VerdictAdjustment[];
  /**
   * Whether the credential scan refused this content for size. Cached with the
   * rest of the compilation for the same reason the floor is: the refusal is a
   * property of the COMPILATION, and a cache hit is the one path on which it
   * would otherwise go unreported.
   */
  credentialScanRefused: boolean;
}

export class SemanticCompiler {
  private config: CompilerConfig;
  private cache = new Map<string, CachedCompilation>(); // content hash → compilation

  constructor(config: Partial<CompilerConfig> = {}) {
    this.config = {
      daemonUrl: config.daemonUrl ?? 'http://127.0.0.1:47200',
      useNanoMind: config.useNanoMind ?? true,
      maxArtifactSize: config.maxArtifactSize ?? 1_048_576,
      daemonTimeoutMs: config.daemonTimeoutMs ?? 5000,
      signingKey: config.signingKey,
      neuralClassifier: config.neuralClassifier,
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

    // Step 2: Check cache. Key on artifact TYPE + content hash, not content
    // alone: several detectors are type-gated (e.g. the source_code-only
    // credential scan), so byte-identical content parsed as a different type
    // must NOT serve a cached AST built under the other type's rules.
    const cacheKey = `${parsed.type}\x00${parsed.contentHash}`;
    const cached = this.cache.get(cacheKey);
    if (cached) {
      // The deterministic floor and the adjustment record are properties of the
      // COMPILATION, not decorations added afterwards, so they are cached with
      // the AST. Rebuilding the result without them would make a cache hit the
      // one path on which a downgrade goes unrecorded.
      return {
        ast: cached.ast,
        durationMs: Date.now() - startMs,
        nanomindUsed: false,
        warnings: cached.credentialScanRefused
          ? ['Served from cache', credentialScanRefusedWarning(cached.ast.artifactSize)]
          : ['Served from cache'],
        deterministicFindings: cached.deterministicFindings,
        verdictAdjustments: cached.verdictAdjustments,
        refusedAdjustments: cached.refusedAdjustments,
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
    // `declaredPurpose` is free text lifted verbatim out of the SCANNED
    // ARTIFACT — for a source file with no frontmatter, it is that file's
    // first non-comment line. When that line assigns an API key, the purpose
    // IS the credential, and at least nine call sites interpolate this field
    // into user-visible strings (fix-generator's CRED-EXPOSURE text, the
    // scope and capability analyzers' messages, the SOUL scaffold's `name:`,
    // the AST validator's evidence). 0.25.2 shipped 46 of a 49-character key
    // into stdout, `--json`, and the `-f html` "shareable compliance report"
    // through the first of those; 0.25.1 emitted none of it.
    //
    // Redaction lives INSIDE `extractDeclaredPurpose`, on both of its return
    // paths and before its 200-char slice — one guarantee point rather than
    // eleven presentation-site wrappers, so a future consumer of this field
    // cannot forget to wrap itself. It uses the REPORT boundary
    // (`redactSecretsForReport`), not the daemon one: the daemon variant
    // also redacts any long quoted value assigned to a key/token/secret
    // identifier, which destroys ordinary prose and measurably changed what
    // the scanner reported.
    const declaredPurpose = extractDeclaredPurpose(content, parsed.frontmatter);

    // Step 5: NanoMind inference (intent + inferred capabilities)
    // Step 4b: THE DETERMINISTIC LAYER, and it runs FIRST.
    //
    // Ordering is the whole fix. On the previous shape the classifier spoke
    // before any rule had, so by the time `mapRiskSurfaces` ran there was
    // already a verdict in scope to gate it — and a benign verdict deleted
    // findings derived from bytes the classifier never disputed. Here the
    // pattern rules read the artifact with no verdict available to them
    // (`intent: 'suspicious'` is the neutral rung, not a classification, and
    // `inferred: []` because inferred capabilities are the model's output),
    // and the benign-context gates are off: a score computed from the
    // artifact's own prose is not evidence about the artifact's own bytes.
    //
    // What comes out is the floor. Everything after this may add to it.
    //
    // The canonical credential-format scan (step 6b) belongs to this layer too
    // — a byte sequence that matches `sk-ant-api…` is the most deterministic
    // signal the compiler has — so it is run HERE and its hits are reused
    // below rather than rescanned. Running it after the verdict would have left
    // a hardcoded key out of the floor the verdict is measured against.
    //
    // The scan can also REFUSE: its patterns carry unbounded lower-bound
    // quantifiers that throw `RangeError` rather than merely running slowly on a
    // multi-megabyte same-alphabet run, so it declines content over
    // `MAX_CREDENTIAL_SCAN_BYTES` instead of handing it to them. That refusal is
    // reported below, never swallowed — an artifact nobody read is not an
    // artifact with no credentials in it.
    //
    // The SCAN is type-gated; the REFUSAL is not. For every non-source_code
    // type the same patterns still run inside `hasCanonicalCredentialFormat`
    // (via `extractDataAccessPatterns` above and `mapRiskSurfaces` below), and
    // that probe answers an oversize artifact with a silent `false`. So the
    // refusal is raised HERE from the same predicate for every artifact type:
    // without it, a 6 MB SOUL.md came back `benign` with zero findings — the C1
    // shape — while the byte-identical .py was loudly refused.
    const canonicalScan = parsed.type === 'source_code'
      ? scanCanonicalCredentialFormats(content)
      : { hits: [], refusedForSize: exceedsCredentialScanBytes(content) };
    const canonicalHits = canonicalScan.hits;
    if (canonicalScan.refusedForSize) {
      warnings.push(credentialScanRefusedWarning(parsed.size));
    }
    const deterministicSurfaces = [
      ...deterministicRiskSurfaces(analysisContent, declaredCapabilities, parsed.type),
      // The refusal enters the DETERMINISTIC list, not just `warnings`, because
      // that list is what `applyDeterministicFloor` reads: an entry here lifts
      // the artifact off `benign` and refuses any downgrade proposed over it. A
      // warnings-only refusal would still return `intentClassification: 'benign'`
      // with zero findings, which is the shape a credential-bearing file stamped
      // clean has.
      ...(canonicalScan.refusedForSize ? [credentialScanRefusedSurface(parsed.size)] : []),
      ...canonicalHits.map(hit => ({
        surface: `Hardcoded ${hit.label}`,
        attackClass: 'CRED-HARVEST',
        confidence: 0.9,
        evidence: hit.evidence,
        // Against `content`, which is what this scan read — not the stripped
        // analysis view `mapRiskSurfaces` works from. Every consumer that turns
        // this back into a line is handed the same `content`.
        offset: hit.index,
      })),
    ];
    const deterministicFindings = deterministicSurfaces.map(toDeterministicFinding);

    let intentClassification: IntentClass = 'benign';
    let intentConfidence = 0.5;
    let inferredCapabilities: Capability[] = [];
    let nanomindUsed = false;
    let proposedDowngrade: VerdictAdjustment | undefined;

    if (this.config.useNanoMind) {
      const inference = await this.runNanoMindInference(sanitized.content, parsed.type);
      if (inference) {
        intentClassification = inference.intentClass;
        intentConfidence = inference.confidence;
        inferredCapabilities = inference.inferredCapabilities;
        proposedDowngrade = inference.proposedDowngrade;
        nanomindUsed = true;
      }
    }

    // Heuristic fallback if NanoMind unavailable
    if (!nanomindUsed) {
      const heuristic = heuristicIntentClassification(content, declaredCapabilities, declaredConstraints);
      intentClassification = heuristic.intentClass;
      intentConfidence = heuristic.confidence;
      inferredCapabilities = heuristic.inferredCapabilities;
      proposedDowngrade = heuristic.proposedDowngrade;
    }

    // Step 5b: the floor decides whether the downgrade the scorer asked for is
    // allowed to land, and records the answer either way.
    const floored = applyDeterministicFloor(
      { intentClass: intentClassification, confidence: intentConfidence },
      proposedDowngrade,
      deterministicFindings,
    );
    intentClassification = floored.intentClass;
    intentConfidence = floored.confidence;
    for (const refused of floored.refused) {
      warnings.push(
        `Deterministic floor: refused a ${refused.source} downgrade ${refused.from} -> ${refused.to} `
        + `over ${deterministicFindings.length} deterministic finding(s)`,
      );
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
    //
    // The surfaces the classifier is allowed to influence, then the floor put
    // back underneath them: anything the deterministic pass raised is restored
    // if this pass dropped it and re-raised if this pass came in lower. The
    // model's contribution survives intact — `inferredCapabilities` still adds
    // PRIV-ESCALATION surfaces here, and a `malicious` verdict lifts the
    // exfiltration surface to 0.9 whenever the classifier pass still produced
    // it. When benign framing gated that pass's surface out, only the
    // deterministic floor (0.6) is restored, so a malicious-verdict artifact
    // wrapped in authorization prose reads HIGH here, not CRITICAL. Either way
    // the surface is never removed and never lowered: only the subtraction is gone.
    const inferredRiskSurface = enforceDeterministicSurfaceFloor(
      mapRiskSurfaces(analysisContent, declaredCapabilities, inferredCapabilities, intentClassification, parsed.type),
      deterministicSurfaces,
    );

    // Step 6b: data access implied by the canonical credential-format scan.
    // The scan itself ran in step 4b as part of the deterministic layer, and
    // its hits are already in `inferredRiskSurface` — the floor put them there.
    // What is left here is the read pattern each hit implies, which the
    // credential analyzer pairs with a transmit pattern.
    if (parsed.type === 'source_code') {
      for (const _hit of canonicalHits) {
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
      // Canonical classifier version. The bundled ONNX model is sha256-pinned in
      // tme-classifier.ts to nanomind-security-classifier 0.5.0 (verified against
      // nanomind/nanomind-models.json → versions["0.5.0"].sha256). Bump this in
      // lockstep with the pinned model sha on the next classifier release.
      modelVersion: nanomindUsed ? 'nanomind-tme-v0.5.0' : 'heuristic-v1',
      compiledAt: new Date().toISOString(),
    };

    // Sign the AST
    ast.signature = this.signAST(ast);

    // Cache (keyed on artifact type + content hash — see Step 2).
    this.cache.set(cacheKey, {
      ast,
      deterministicFindings,
      verdictAdjustments: floored.applied,
      refusedAdjustments: floored.refused,
      credentialScanRefused: canonicalScan.refusedForSize,
    });

    return {
      ast,
      durationMs: Date.now() - startMs,
      nanomindUsed,
      warnings,
      deterministicFindings,
      verdictAdjustments: floored.applied,
      refusedAdjustments: floored.refused,
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
  ): Promise<ScoredVerdict | null> {
    // Tier 0: Pure neural inference (7MB binary model, no dependencies)
    const neural = this.config.neuralClassifier ?? new TMENeuralClassifier();
    if (neural.load()) {
      const neuralResult = neural.classify(sanitizedContent);
      if (neuralResult.confidence > 0.6 && neuralResult.intentClass !== 'benign') {
        // Post-neural context adjustment: the neural model was trained on attack
        // data without hard-negative benign examples, so it keys off vocabulary
        // without reasoning about authorization, educational framing, or negation.
        // Strong benign context signals ASK to override the neural classification.
        //
        // They used to just do it, and that is the inversion this file was
        // reshaped to close: both branches below returned the lowered verdict
        // directly, so a paragraph of authorization prose written by whoever
        // wrote the artifact outranked every rule that had read the artifact's
        // bytes. The lowering is now a REQUEST carried out to `compile`, which
        // grants it only over an artifact the deterministic layer left alone,
        // and records it either way.
        const benignScore = detectContextualBenignSignals(sanitizedContent);
        if (benignScore >= 4) {
          // Authorization, research, IRB, or negation-list context is definitive
          return {
            intentClass: neuralResult.intentClass,
            confidence: neuralResult.confidence,
            inferredCapabilities: [],
            proposedDowngrade: {
              from: neuralResult.intentClass,
              to: 'benign',
              fromConfidence: neuralResult.confidence,
              toConfidence: 0.7,
              reason: `contextual benign signals scored ${benignScore} (>= 4): authorization, educational, research or negation-list framing`,
              source: 'contextual-benign',
            },
          };
        }
        if (benignScore >= 2) {
          // Moderate benign context: downgrade from malicious/suspicious and cap confidence
          return {
            intentClass: neuralResult.intentClass,
            confidence: neuralResult.confidence,
            inferredCapabilities: [],
            proposedDowngrade: {
              from: neuralResult.intentClass,
              to: 'suspicious',
              fromConfidence: neuralResult.confidence,
              toConfidence: Math.min(0.45, neuralResult.confidence * 0.5),
              reason: `contextual benign signals scored ${benignScore} (>= 2): moderate authorization or educational framing`,
              source: 'contextual-benign',
            },
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
  // Redaction happens on BOTH return paths below, and BEFORE the 200-char
  // slice. Order matters: slicing first can cut a secret that straddles the
  // boundary down to a fragment shorter than a pattern's minimum length, so
  // the redactor stops matching while the detector — which reads the full
  // content — still reports the finding. That combination leaves a partial
  // secret in a field the rest of this file treats as already clean.

  // From YAML frontmatter
  if (frontmatter?.description) return redactSecretsForReport(String(frontmatter.description));

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
      return redactSecretsForReport(line).slice(0, 200);
    }
  }
  return 'Unknown purpose';
}

/**
 * Normalise an MCP server's tool declaration to a list of tool names.
 *
 * #449 — returns `undefined` ONLY when no tool key is present at all, which is
 * the MCP ecosystem default and deliberately produces no wildcard finding. A
 * key that is present but malformed is still a declaration, and if it spells
 * `*` anywhere it is a wildcard the file really contains:
 *
 *   "allowedTools": "*"          -> ['*']   (string, not array)
 *   "tools": {"*": {}}           -> ['*']   (object keyed by tool name)
 *   "allowedTools": ["read"]     -> ['read']
 *   "allowedTools": null         -> []      (present, declares nothing)
 *   (no key)                     -> undefined
 *
 * A value that cannot express a tool list at all (`null`, `false`, `0`) maps
 * back to `undefined` — "this key declares nothing" — rather than to an empty
 * list. An empty list is not neutral here: it removes the server from the AST
 * entirely, which scores BETTER than the ecosystem default and is fail-open.
 * Real MCP hosts treat a null as an absent key, so absent is also the honest
 * reading.
 */
/**
 * Find the verbatim text of a TOP-LEVEL key's value in a JSON document.
 *
 * #449 — needed because `JSON.parse` throws away positions, and every
 * regex attempt at recovering them for `"permissions"` was wrong in a
 * different way. `"permissions"` is not unique in an MCP config: a SERVER may
 * be named `permissions`, or carry its own nested `permissions` object, and
 * anchoring on the first occurrence cited that server's narrow
 * `["read_file"]` allowlist as the evidence for a CRITICAL claiming
 * unrestricted access. Anchoring on the inner `"tools"` array instead made the
 * evidence the 5-character string `["*"]`, which collides with any server
 * declaring the same. And a `[^{}]*` body matched only one level of nesting,
 * so a deeper block produced no evidence and shipped a CRITICAL with no
 * `file:line` at all.
 *
 * A depth-aware scan has none of those failure modes: it tracks string state
 * and brace/bracket depth, so it can only ever return the value of a key at
 * depth 1. Returns undefined when the key is absent at the top level.
 */
function findTopLevelValueText(content: string, key: string): string | undefined {
  const needle = `"${key}"`;
  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let i = 0; i < content.length; i++) {
    const ch = content[i];

    if (inString) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }

    if (ch === '"') {
      // A key is only THIS key if it sits at depth 1 and is followed by `:`.
      if (depth === 1 && content.startsWith(needle, i)) {
        let j = i + needle.length;
        while (j < content.length && /\s/.test(content[j])) j++;
        if (content[j] === ':') {
          j++;
          while (j < content.length && /\s/.test(content[j])) j++;
          const start = j;
          let vDepth = 0;
          let vInString = false;
          let vEscaped = false;
          for (; j < content.length; j++) {
            const c = content[j];
            if (vInString) {
              if (vEscaped) vEscaped = false;
              else if (c === '\\') vEscaped = true;
              else if (c === '"') vInString = false;
              continue;
            }
            if (c === '"') vInString = true;
            else if (c === '{' || c === '[') vDepth++;
            else if (c === '}' || c === ']') {
              vDepth--;
              if (vDepth === 0) return content.slice(start, j + 1);
              if (vDepth < 0) return undefined; // value was a scalar
            } else if (vDepth === 0 && (c === ',' || c === '}')) {
              return content.slice(start, j);
            }
          }
          return undefined;
        }
      }
      inString = true;
      continue;
    }

    if (ch === '{' || ch === '[') depth++;
    else if (ch === '}' || ch === ']') depth--;
  }
  return undefined;
}

function normalizeToolDeclaration(value: unknown): string[] | undefined {
  if (value === undefined || value === null) return undefined;
  if (Array.isArray(value)) return value.filter((t): t is string => typeof t === 'string');
  if (typeof value === 'string') return [value];
  if (typeof value === 'object') return Object.keys(value);
  // number / boolean — a declaration that cannot name a tool.
  return undefined;
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

  // A skill's `## Permissions` bullet list is NOT read here, and #471 tracks
  // that gap rather than this branch closing it.
  //
  // The gap is real: the surface produces no capabilities, so `AST-SCOPE-001`
  // cannot fire from a skill however broad its grants, and the
  // `repo/malicious/kitchen-sink` expectation naming skills was being met
  // accidentally by the MCP branch's synthesized `['*']` — a wildcard credited
  // to a file that contained none. Removing the fabrication exposed it.
  //
  // An implementation was written here and removed after review measured what
  // it did to real skills. Markdown permission lists are not a parseable
  // grammar the way a JSON tool array is, and the attempt: raised a CRITICAL
  // "equivalent of running as root" on `- logs: /var/log/*.*` in a benign
  // log-rotation skill (63/100, "Not safe to ship"); missed most legitimate
  // spellings, including `## Permissions Required`, numbered lists, and any
  // trailing comment (`- shell: * # for build`), each a one-token bypass;
  // captured non-permission bullets such as `- Contact: security@example.com`
  // as declared capabilities; read fenced markdown EXAMPLES as real grants;
  // resolved no line number at all for the spaced spelling `- shell: *`, so
  // its findings carried no Verify command; and rebuilt the same
  // attacker-controlled quadratic this branch fixed for MCP — 40k permission
  // bullets in a downloaded SKILL.md took 27.5s.
  //
  // A check that fires hardest on the people writing ordinary skills is the
  // defect #449 is about, pointed at a new surface. It needs a corpus and a
  // grammar, not a regex pair bolted onto a false-positive fix.

  // From MCP config tool declarations
  if (type === 'mcp_config') {
    try {
      const config = JSON.parse(content);
      const servers = config.mcpServers ?? {};
      for (const [name, server] of Object.entries(servers)) {
        const s = server as Record<string, unknown>;
        // Locate the server's JSON declaration in original content for a
        // verbatim evidence span. JSON.parse loses position info, so emit
        // sites can't derive a line number without re-scanning content.
        // findLineFromString (issue #141) requires a verbatim substring.
        const serverDeclRe = new RegExp(`"${escapeRegex(name)}"\\s*:`);
        const serverMatch = content.match(serverDeclRe);
        const serverEvidence = serverMatch?.[0];

        // #449 — an ABSENT tool declaration is the MCP default, not a declared
        // wildcard, and compiling it to `['*']` made the two indistinguishable.
        // Every consumer downstream reads the capability NAME, so a synthesized
        // `mcp.<server>.*` is asserted as a wildcard that is not in the file:
        // `scope-analyzer` raised CRITICAL "Full Wildcard Tool Access" citing
        // the server-key line, `capability-analyzer` inherited `riskLevel:
        // 'high'` and added a MEDIUM, and the honestly-worded "Implicit
        // Wildcard" branch became unreachable. Benign and malicious MCP corpus
        // fixtures both scored exactly 69/100 — a CRITICAL whose output does
        // not vary with its input.
        //
        // `tools` is read alongside `allowedTools` deliberately. It is the key
        // the malicious corpus fixture actually uses, so honouring only
        // `allowedTools` would swap this false positive for a false negative on
        // the one fixture that must stay caught.
        //
        // "Declared but not an array" is a THIRD state and must not collapse
        // into "absent". `{"allowedTools": "*"}` and `{"tools": {"*": {}}}`
        // both write the wildcard into the file; treating a non-array as
        // absent scored them 96/100 exit 0 while the pre-#449 build scored 69
        // and failed — a one-character evasion of the very check this change
        // is about.
        //
        // The two keys are UNIONED rather than ranked. An earlier version took
        // the first key present, and that let a malformed `allowedTools`
        // shadow a well-formed one: `{"allowedTools": null, "tools": ["*"]}`
        // scored 100/100 exit 0 — worse than the defect it was fixing, because
        // an empty list also removes the server from the AST entirely. There is
        // no correct precedence between two keys that mean the same thing, so
        // there is no precedence: a wildcard written under either key fires.
        const fromAllowed = normalizeToolDeclaration(s.allowedTools);
        const fromTools = normalizeToolDeclaration(s.tools);
        const declaredTools =
          fromAllowed === undefined && fromTools === undefined
            ? undefined
            : [...new Set([...(fromAllowed ?? []), ...(fromTools ?? [])])];

        if (declaredTools === undefined) {
          // Server-level only: the AST still knows the server exists and that
          // its grant is unbounded, but the NAME no longer asserts a `*` that
          // is not in the file.
          //
          // `riskLevel` is 'medium', and that was measured rather than picked.
          // The purpose-mismatch analyzers (`AST-SCOPE-003`,
          // `capability-analyzer`'s `checkScopeMismatch`) select on
          // `riskLevel === 'high' || 'critical'`, so 'high' here fires a
          // purpose-mismatch finding on any config that merely omits the key —
          // it put the benign `mcp/benign/readonly-fs-mcp` fixture at 91/100
          // against a 95-100 band and dropped a bare default config to 69 with
          // a fail-direction verdict. That is the same false positive this
          // issue is about, relocated from AST-SCOPE-001 to AST-SCOPE-003.
          //
          // Omitting the key is the ecosystem default and is not by itself
          // evidence of risk. Where a tree really is dangerous, the risk is
          // usually carried by evidence that survives this: the skill
          // permission wildcards above, dangerous command and argument
          // detection, and the credential checks.
          //
          // "Usually" is doing real work in that sentence — see the KNOWN GAP
          // note in `scope-analyzer.ts`'s `checkWildcardToolAccess`. A keyless
          // server whose args grant an unbounded root, with nothing else wrong
          // in the file, is caught by none of them and now scores 96/100.
          caps.push({
            name: `mcp.${name}`,
            scope: name,
            declared: true,
            inferred: false,
            riskLevel: 'medium',
            evidence: serverEvidence,
          });
          continue;
        }

        // Evidence lookups are anchored at this server's own declaration and
        // must stay O(span), not O(file), per tool.
        //
        // Reading `tools` as well as `allowedTools` multiplies how many tools
        // reach this loop — a config of 800 servers with 40 tools each went
        // from 801 capabilities to 32,001. With a per-tool `new RegExp` scanned
        // from index 0, that measured 209ms -> 7,067ms at 1.2MB and grew
        // quadratically (114s at 5MB). `check <package>` scans downloaded
        // third-party trees, so that file is attacker-controlled: it is a
        // scanner hang, not a slow test. Anchoring at `from` and using
        // `indexOf` keeps the total proportional to the file, because a tool
        // literal sits inside the server object that declares it.
        const from = serverMatch?.index ?? 0;
        // `g` + explicit lastIndex rather than `content.slice(from)`, which
        // allocated a copy of the remainder for every wildcard server.
        const wildcardRe = /"(?:allowedTools|tools)"\s*:\s*\[[^\]]*"\*"[^\]]*\]/g;

        for (const tool of declaredTools) {
          // Prefer the specific tool's quoted span when present (e.g. `"shell"`
          // inside an allowedTools array). Fall back to the server declaration
          // span when the literal isn't found.
          let evidence = serverEvidence;
          if (tool === '*') {
            // Cite the line that actually holds the wildcard rather than the
            // server key, but ONLY when that citation can be resolved back to
            // this server.
            //
            // Evidence is a STRING, and the consumer re-derives the line with
            // `findLineFromString`, which returns the first occurrence. So an
            // evidence span that is not unique in the file resolves to whoever
            // wrote it first: two servers each declaring `"allowedTools":
            // ["*"]` both cited line 5, and the pre-#449 build got this right
            // (3 and 7) precisely because it cited the unique server key.
            // Anchoring the SEARCH at `from` cannot fix that — it selects the
            // text, and the offset is then thrown away.
            //
            // So the wildcard span is used only when it appears exactly once;
            // otherwise fall back to the server key, which is unique by
            // construction. Single-wildcard configs — the common case, and the
            // one in the issue — still cite the wildcard's own line.
            wildcardRe.lastIndex = from;
            const wildcardDecl = wildcardRe.exec(content);
            if (wildcardDecl && content.indexOf(wildcardDecl[0]) === content.lastIndexOf(wildcardDecl[0])) {
              evidence = wildcardDecl[0];
            }
          } else {
            const needle = `"${tool}"`;
            if (content.indexOf(needle, from) !== -1) evidence = needle;
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

      // A config-level `"permissions": {"tools": [...]}` block grants across
      // every server rather than within one.
      //
      // #449 — never read, and the omission was invisible because the
      // synthesized per-server `['*']` fired on these files anyway.
      // `repo/malicious/kitchen-sink/mcp.json` declares one at its top level,
      // and without this the tree went from 69/100 exit 1 to 96/100 exit 0
      // with a wildcard written verbatim in the file.
      const permissionsText = findTopLevelValueText(content, 'permissions');
      const configPermissions = normalizeToolDeclaration(
        (config?.permissions as Record<string, unknown> | undefined)?.tools,
      );
      // Computed ONCE: it is loop-invariant, and inside the loop it made this
      // path super-linear on the tool count (30,000 tools took 8.2s).
      const permEvidence =
        permissionsText && content.indexOf(permissionsText) === content.lastIndexOf(permissionsText)
          ? permissionsText
          : undefined;
      for (const tool of configPermissions ?? []) {
        caps.push({
          // `config-permissions`, not `permissions`: a SERVER may legitimately
          // be named `permissions`, and the same name from both sources
          // produced two capabilities that the purpose-mismatch analyzer then
          // deduped down to one.
          name: `mcp.config-permissions.${tool}`,
          scope: 'all servers',
          declared: true,
          inferred: false,
          riskLevel: tool === '*' ? 'high' : 'medium',
          evidence: permEvidence,
        });
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

  // Strip YAML frontmatter, fenced code blocks, and inline code spans before
  // constraint extraction. YAML frontmatter list items (`forbiddenTools:\n
  // - Bash`) otherwise interact with bullet-period normalization below to
  // produce faux "Bash." / "WebFetch." constraints that classify as
  // capability_boundary at fall-through enforceability, firing spurious
  // AST-GOV-002 (Weak constraint) findings on benign skill frontmatter.
  // Attack examples quoted in educational documents ("DO NOT USE: Ignore
  // previous instructions...") must also not be extracted.
  const stripped = content
    .replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, '')
    .replace(/```[\s\S]*?```/g, '')
    .replace(/`[^`]*`/g, '');

  // Hard-wrap joining (#251): markdown list items wrapped across physical
  // lines (72/80-col prose) must be reassembled BEFORE bullet-period
  // normalization. Without this, the normalizer appended a "." to the first
  // physical line of a wrapped bullet, truncating
  //   - Prompt-injection patterns in scanned files MUST NOT alter agent
  //     permissions, identity, or escalation rules.
  // into the fragment constraint "MUST NOT alter agent." and orphaning the
  // continuation — the canonical prose-hardened SOUL lost its override-
  // resistance constraint entirely. A continuation line is an INDENTED,
  // non-blank line that is not itself a list item, heading, table row, or
  // blockquote. (Lazy, unindented markdown continuations are not joined —
  // same behavior as before this fix.)
  const isListItemLine = (l: string) => /^\s*(?:[-*+]|\d+[.)])\s+\S/.test(l);
  const isStructuralLine = (l: string) =>
    /^#{1,6}\s/.test(l) || /^\s*\|/.test(l) || /^\s*>/.test(l);
  const joinedLines: string[] = [];
  let lastWasListItem = false;
  for (const line of stripped.split('\n')) {
    const blank = line.trim() === '';
    const continuation =
      lastWasListItem &&
      !blank &&
      !isListItemLine(line) &&
      !isStructuralLine(line) &&
      /^\s+\S/.test(line);
    if (continuation && joinedLines.length > 0) {
      joinedLines[joinedLines.length - 1] =
        joinedLines[joinedLines.length - 1].replace(/\s+$/, '') + ' ' + line.trim();
      continue;
    }
    joinedLines.push(line);
    if (isListItemLine(line)) {
      // stays true across the item's own continuations
      lastWasListItem = true;
    } else if (blank || isStructuralLine(line)) {
      lastWasListItem = false;
    } else {
      lastWasListItem = false;
    }
  }

  // Bullet-list normalization: append a sentence-terminating period to bullet
  // lines that don't already end with terminal punctuation. The constraint
  // pattern below requires a `.` to bound the match — without this fix-up, a
  // bullet list like
  //   - Must never share data
  //   - Must always confirm
  // either fails to match at all (no period anywhere) or greedy-captures
  // multiple bullets as one giant constraint when a period eventually appears
  // elsewhere in the document. Both modes lose per-bullet domain attribution.
  // This normalization is conservative — it only adds a `.`, never removes
  // existing punctuation, and never touches non-bullet lines.
  const bulletNormalized = joinedLines
    .map(line => {
      const trimmed = line.replace(/\s+$/, '');
      if (!/^\s*[-*+]\s+\S/.test(trimmed)) return line;
      if (/[.;!?]$/.test(trimmed)) return line;
      return trimmed + '.';
    })
    .join('\n');

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

  // Section-aware extraction: split the document by markdown headings (#, ##,
  // ###, ####) and carry the heading's domain as a hint when the constraint
  // text alone is too generic. A constraint under `## Trust Hierarchy` like
  // "User instructions cannot override the constraints in this file." does
  // not contain the keywords `trust|authority|hierarchy` the text-only
  // classifier looks for, so it would fall back to `general` and the
  // governance analyzer would report `trust_hierarchy` as missing even
  // though the SOUL.md plainly covers it. The heading-based hint maps it
  // back to the correct domain. Text-classifier wins over heading whenever
  // the text classifier finds a specific domain — subsections may
  // legitimately cross domains (e.g. a credential sentence inside
  // `## Data Handling` should still classify as credential_management).
  const sections = splitMarkdownSections(bulletNormalized);

  // Sentence-start expansion (#251): the modal-anchored pattern above starts
  // matching AT the modal, which drops the sentence subject — "Prompt-
  // injection patterns in scanned files MUST NOT alter agent permissions"
  // was extracted as "MUST NOT alter agent permissions", and downstream
  // predicates (AST-GOV-004 override resistance, AST-PROMPT-003 injection
  // resistance) never saw the words that made the constraint an injection
  // defense. Expand each match back to the start of its sentence: the
  // previous terminal punctuation / colon / line break, then skip list
  // markers and markdown emphasis. Bounded so a pathological unpunctuated
  // blob cannot balloon a constraint; on overflow, fall back to the
  // modal-anchored text (pre-fix behavior).
  const MAX_SUBJECT_EXPANSION = 240;
  const expandToSentenceStart = (body: string, matchIndex: number, matched: string): string => {
    let start = matchIndex;
    const floor = Math.max(0, matchIndex - MAX_SUBJECT_EXPANSION);
    while (start > floor) {
      const ch = body[start - 1];
      if (ch === '.' || ch === '!' || ch === '?' || ch === ';' || ch === ':' || ch === '\n' || ch === '\r') {
        break;
      }
      start--;
    }
    if (start === floor && floor > 0) {
      // No sentence boundary within the window — keep the modal-anchored text.
      return matched;
    }
    // Skip leading whitespace, list markers, emphasis, and blockquote marks.
    const expanded = body
      .slice(start, matchIndex + matched.length)
      .replace(/^[\s>]*(?:[-*+]\s+|\d+[.)]\s+)?[\s*_]*/, '');
    return expanded.length > 0 ? expanded : matched;
  };

  for (const section of sections) {
    const sectionDomain = section.heading
      ? classifyHeadingDomain(section.heading)
      : undefined;
    const seenTexts = new Set<string>();
    let m: RegExpExecArray | null;
    patterns.lastIndex = 0;
    const matches: string[] = [];
    while ((m = patterns.exec(section.body)) !== null) {
      matches.push(expandToSentenceStart(section.body, m.index, m[0]));
    }
    if (matches.length === 0) continue;
    for (const match of matches) {
      const text = match.trim();
      if (seenTexts.has(text)) continue;
      seenTexts.add(text);
      const textDomain = classifyConstraintDomain(text);
      // Text classifier wins over the heading hint — except when its
      // verdict is `behavioral_constraint`, whose /behav/ trigger is the
      // weakest rule in the classifier ("behavior" appears in governance
      // prose of every domain). With #251's sentence-start expansion,
      // "Prompt-injection patterns ... MUST NOT alter the behavior" under
      // `## Trust hierarchy` started classifying as behavioral_constraint
      // and silently dropped the section's trust-hierarchy coverage. A
      // specific heading outranks the catch-all text verdict.
      const domain =
        textDomain !== 'general' && !(textDomain === 'behavioral_constraint' && sectionDomain !== undefined)
          ? textDomain
          : sectionDomain ?? textDomain;
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

/**
 * Split markdown content by H1-H4 headings into sections. The body of each
 * section excludes its heading line. Content preceding the first heading is
 * returned as a section with `heading: undefined`.
 */
function splitMarkdownSections(
  content: string,
): Array<{ heading: string | undefined; body: string }> {
  const result: Array<{ heading: string | undefined; body: string }> = [];
  const lines = content.split('\n');
  let currentHeading: string | undefined = undefined;
  let currentBody: string[] = [];
  const flush = () => {
    if (currentBody.length > 0 || currentHeading !== undefined) {
      result.push({
        heading: currentHeading,
        body: currentBody.join('\n'),
      });
    }
  };
  for (const line of lines) {
    const headingMatch = /^#{1,4}\s+(.+?)\s*$/.exec(line);
    if (headingMatch) {
      flush();
      currentHeading = headingMatch[1];
      currentBody = [];
    } else {
      currentBody.push(line);
    }
  }
  flush();
  return result;
}

/**
 * Map a markdown section heading to a governance domain. The heading text is
 * matched against the SOUL.md and harden-soul template vocabulary. Returns
 * undefined when no match — the constraint then falls back to the text
 * classifier's verdict (typically `general`).
 *
 * Conservative scope: covers the headings emitted by the create-skill
 * template (Trust Hierarchy, Capability Boundaries, Data Handling,
 * Behavioral Constraints, Override Resistance, Error Handling, Audit),
 * the harden-soul DOMAIN_TEMPLATES (Injection Hardening, Hardcoded
 * Behaviors, Agentic Safety, Honesty and Transparency, Human Oversight,
 * Harm Avoidance), and obvious synonyms. Unrecognized headings do NOT
 * change behavior — the existing text classifier still runs and decides.
 */
function classifyHeadingDomain(heading: string): ConstraintDomain | undefined {
  const h = heading.toLowerCase();
  // Trust / authority / override resistance — about who can override whom.
  // `override resistance` is a SOUL.md section that defends against
  // user-input authority claims, semantically a trust-hierarchy concern.
  if (/trust\s*hierarch|authority\s*chain|conflict\s*resolution|operator\s*vs|override\s*resistance|principal\s*identity|trust\s*boundary/.test(h)) {
    return 'trust_hierarchy';
  }
  // Human oversight / approval gates / audit and monitoring.
  if (/human\s*oversight|approval\s*gate|approval\s*workflow|monitoring|escalation|audit|operator\s*identity/.test(h)) {
    return 'human_oversight';
  }
  // Credential management — most specific match before data_handling because
  // a `## Credential Management` heading is unambiguous.
  if (/credential|secret|api\s*key|token\s*handling/.test(h)) {
    return 'credential_management';
  }
  // Data handling / PII / data retention.
  if (/data\s*handling|pii|data\s*minimization|data\s*retention|data\s*classification|data\s*access|data\s*encryption|data\s*breach/.test(h)) {
    return 'data_handling';
  }
  // Action reversibility / rollback.
  if (/reversibilit|undo|rollback|reversibility\s*preference/.test(h)) {
    return 'action_reversibility';
  }
  // Capability boundary / scope / permissions / tool integration.
  if (/capabilit|scope|permission|boundar|tool\s*integration|rate\s*and\s*resource|least\s*privilege|allowed\s*action|denied\s*action|filesystem\s*and\s*network/.test(h)) {
    return 'capability_boundary';
  }
  // Identity disclosure / honesty / transparency.
  if (/identity\s*disclosure|honesty|transparen|disclosure|knowledge\s*boundary|confidence\s*level|training\s*data\s*recency|source\s*verification|limitations\s*acknowledged|uncertainty\s*acknowledg|no\s*fabrication/.test(h)) {
    return 'identity_disclosure';
  }
  // Error handling / recovery.
  if (/error\s*handling|error\s*recovery|exception\s*handling|fail\s*safe/.test(h)) {
    return 'error_handling';
  }
  // Behavioral / hardcoded / injection / harm / safety.
  if (/behavioral|conduct|hardcoded\s*behavior|injection\s*harden|harm\s*avoidance|agentic\s*safety|safety\s*immutable|emergency\s*stop|no\s*data\s*exfiltration|behavior\s*integrity|constraint\s*immutability/.test(h)) {
    return 'behavioral_constraint';
  }
  return undefined;
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

  // Structured artifacts (JSON, JSONC) pair by leaf string value, not by
  // paragraph: object keys such as `SessionStart`/`PostToolUse` are
  // identifiers, and pretty-printed JSON has no blank line for the paragraph
  // gate below to find, so on the prose engine every URL in a settings file
  // pairs with every verb (#541, #403). See `structured-colocation.ts`.
  const structuredRoot = parseStructuredJson(content);
  if (structuredRoot !== undefined) {
    return extractStructuredDataAccessPatterns(content, structuredRoot, capabilities, credentialKeywordContext);
  }

  const lower = content.toLowerCase();
  for (const dt of dataTypes) {
    const idx = lower.indexOf(dt);
    if (idx >= 0) {
      if ((dt === 'credential' || dt === 'session') && credentialKeywordContext === 'schema-only') {
        continue;
      }
      const hasCap = capabilities.some(c => c.name.includes('read') || c.name.includes('access'));
      patterns.push({
        dataType: dataTypeOfNoun(dt),
        accessMode: 'read',
        coveredByCapability: hasCap,
        // The first occurrence is the one the substring test matched, so the
        // finding can cite the word and line that fired (#403).
        matched: { scope: 'document', term: content.slice(idx, idx + dt.length), termOffset: idx },
      });
    }
  }

  // Check for external transmission. Pair a URL with a send-verb only when
  // the two are co-located in the same paragraph; otherwise the destination
  // falls back to the literal placeholder `'external'`. Without this
  // proximity gate, a non-doc artifact (`.clinerules`, `.cursorrules`, etc.)
  // that mentions a URL in one paragraph and a send-verb in an unrelated
  // paragraph would attribute the URL as the credential-exfil endpoint and
  // the AST-CRED-002 Verify hint would falsely point at the URL line
  // (issue #148). Trailing sentence punctuation is trimmed so the
  // destination matches the URL as it appears in prose. The outer verb
  // gate uses substring matching (matches "Resend", "reupload", etc. — the
  // adversarial real-world phrasings) and relies on the proximity check
  // inside `findCoLocatedTransmissionUrl` to suppress misattribution.
  const firstVerb = TRANSMIT_VERB.exec(content);
  if (firstVerb && /https?:\/\//.test(content)) {
    const coLocated = findCoLocatedTransmission(content, TRANSMIT_VERB);
    // Trailing punctuation belongs to the sentence; a closing quote or `>`
    // belongs to the YAML/markdown syntax around the URL (#559). Only the
    // TAIL is trimmed: quotes are legal inside a URL's userinfo component and
    // must stay in the span so the analyzer resolves the host the request
    // actually reaches.
    const destination = coLocated
      ? coLocated.url.replace(URL_TRAILING_PUNCTUATION, '')
      : 'external';
    patterns.push({
      dataType: 'general',
      accessMode: 'transmit',
      destination,
      coveredByCapability: capabilities.some(c => c.name.includes('api.call') || c.name.includes('send')),
      matched: coLocated
        ? { scope: 'document', verb: coLocated.verb, verbOffset: coLocated.verbOffset, destinationOffset: coLocated.urlOffset }
        : { scope: 'document', verb: firstVerb[0], verbOffset: firstVerb.index },
    });
  }

  return patterns;
}

const DATA_TYPE_NOUNS = ['user', 'customer', 'payment', 'session', 'credential', 'email', 'profile', 'medical', 'financial'];

function dataTypeOfNoun(dt: string): string {
  return dt === 'credential' || dt === 'session' ? 'credentials' :
         dt === 'payment' || dt === 'financial' ? 'financial' :
         dt === 'medical' ? 'pii' : 'general';
}

/** Trailing characters that belong to the surrounding text, not to a URL. */
const URL_TRAILING_PUNCTUATION = /[.,;:!?)\]>"']+$/;

/**
 * The JSON engine of `extractDataAccessPatterns` (hackmyagent #541 / #403):
 *
 *   - the data-type nouns are tested against leaf string VALUES only — a key
 *     named `SessionStart` is an identifier, not an access to a session;
 *   - a `credentials`/`transmit` pattern is emitted only for a leaf that holds
 *     BOTH a credential noun and a transmit verb (a scalar array counts as one
 *     leaf, so an argv-style `"args"` list still pairs), with the destination
 *     taken from that leaf or a sibling leaf;
 *   - a `general`/`transmit` pattern is emitted for a verb co-located with a
 *     URL, for the narratives that list where an artifact sends data.
 *
 * Every pattern carries `matched.scope === 'structured'`, which tells the
 * credential analyzer that the pairing is already resolved and must not be
 * redone document-wide. A noun in one leaf and a verb in another never pair
 * here, whatever their distance — the accepted trade: a package record whose
 * keywords carry `credential-protection` and `post-quantum` in separate
 * values is not forwarding anything.
 */
function extractStructuredDataAccessPatterns(
  content: string,
  root: unknown,
  capabilities: Capability[],
  credentialKeywordContext: 'value-present' | 'schema-only' | 'no-structured',
): DataAccessPattern[] {
  const patterns: DataAccessPattern[] = [];
  const lower = content.toLowerCase();
  const readCovered = capabilities.some(c => c.name.includes('read') || c.name.includes('access'));

  // The READ pass stays document-wide, keys included, exactly as on the prose
  // engine: a key named `sessionToken` holding a live JWT is a credential in
  // the artifact, and AST-CRED-001 (which additionally requires a
  // credential-format value) and four other consumers read these patterns.
  // Only the PAIRING below is leaf-scoped — a key never supplies the verb or
  // the noun of a forwarding claim. `analyzeCredentialKeywordContext` keeps
  // its existing role of reading `"credentials": null` as declaring none.
  for (const dt of DATA_TYPE_NOUNS) {
    const idx = lower.indexOf(dt);
    if (idx < 0) continue;
    if ((dt === 'credential' || dt === 'session') && credentialKeywordContext === 'schema-only') continue;
    patterns.push({
      dataType: dataTypeOfNoun(dt),
      accessMode: 'read',
      coveredByCapability: readCovered,
      matched: { scope: 'structured', term: content.slice(idx, idx + dt.length), termOffset: idx },
    });
  }

  const transmitCovered = capabilities.some(c => c.name.includes('api.call') || c.name.includes('send'));
  const credential = findStructuredCredentialTransmission(content, CREDENTIAL_NOUN, TRANSMIT_VERB);
  if (credential) {
    patterns.push({
      dataType: 'credentials',
      accessMode: 'transmit',
      destination: credential.url?.span ?? 'external',
      coveredByCapability: transmitCovered,
      matched: {
        scope: 'structured',
        term: credential.term,
        termOffset: credential.termOffset,
        verb: credential.verb,
        verbOffset: credential.verbOffset,
        destinationOffset: credential.url?.offset,
      },
    });
  }

  const verbUrl = findStructuredVerbUrl(content, TRANSMIT_VERB);
  if (verbUrl && verbUrl.url.span !== credential?.url?.span) {
    patterns.push({
      dataType: 'general',
      accessMode: 'transmit',
      destination: verbUrl.url.span,
      coveredByCapability: transmitCovered,
      matched: {
        scope: 'structured',
        verb: verbUrl.verb,
        verbOffset: verbUrl.verbOffset,
        destinationOffset: verbUrl.url.offset,
      },
    });
  }

  return patterns;
}

export interface CoLocatedTransmission {
  /** The URL span exactly as written, bounded by whitespace (untrimmed). */
  url: string;
  urlOffset: number;
  /** The verb that shares a paragraph with the URL, as written. */
  verb: string;
  verbOffset: number;
}

/**
 * Prose-engine co-location: the first URL in `content` (document order) that
 * shares a paragraph with a verb from `verbRe` — no blank-line break
 * (`\n\s*\n`) between the two spans. Returns the verb as well as the URL so a
 * finding can cite both tokens with their lines.
 */
export function findCoLocatedTransmission(
  content: string,
  verbRe: RegExp,
): CoLocatedTransmission | undefined {
  const URL = /https?:\/\/[^\s]+/g;
  const VERB = new RegExp(verbRe.source, 'gi');

  const verbs: Array<{ start: number; end: number }> = [];
  let vm: RegExpExecArray | null;
  while ((vm = VERB.exec(content)) !== null) {
    verbs.push({ start: vm.index, end: vm.index + vm[0].length });
  }
  if (verbs.length === 0) return undefined;

  let um: RegExpExecArray | null;
  while ((um = URL.exec(content)) !== null) {
    const u0 = um.index;
    const u1 = u0 + um[0].length;
    for (const v of verbs) {
      const lo = Math.min(u0, v.start);
      const hi = Math.max(u1, v.end);
      if (!/\n\s*\n/.test(content.slice(lo, hi))) {
        return { url: um[0], urlOffset: u0, verb: content.slice(v.start, v.end), verbOffset: v.start };
      }
    }
  }
  return undefined;
}

/**
 * Returns the first URL in `content` that appears in the same paragraph as
 * a send/forward/transmit/post/upload verb. Two regions are considered
 * "co-located" when no blank-line break (`\n\s*\n`) separates them — i.e.
 * they share a paragraph in the conventional markdown sense. When no URL
 * is co-located with any verb, returns `undefined` so the caller can fall
 * back to a placeholder destination instead of misattributing an unrelated
 * URL as a credential-exfil endpoint (issue #148).
 *
 * Iterates all URL matches, not only the first, so that a documentation
 * URL in an opening paragraph does not block a real exfil URL in a later
 * paragraph from being captured.
 */
export function findCoLocatedTransmissionUrl(content: string): string | undefined {
  // Substring match (no word-boundary anchor) so re-prefixed verbs like
  // "Resend"/"Reupload"/"Reposting" — common real-world malicious phrasings
  // — still pair with their URL. Mid-word matches like "compost" → "post"
  // are tolerated because the paragraph-level proximity gate is the real
  // anti-misattribution check. (Structured JSON is routed to the leaf engine
  // by `extractDataAccessPatterns` before this prose pass runs.)
  return findCoLocatedTransmission(content, TRANSMIT_VERB)?.url;
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
  // The same throw class as `scanCanonicalCredentialFormats`, on the same
  // regexes — and this is the entry point `compile()` reaches for every
  // NON-source_code artifact (`extractDataAccessPatterns` returns early only
  // for source_code), so without this gate a 6 MB SOUL.md threw where a 6 MB
  // .py file was refused. `false` is the only honest boolean here: no canonical
  // format was CONFIRMED. The loud per-artifact refusal is not this function's
  // job — `compile()` raises it from the same predicate, for every type.
  if (exceedsCredentialScanBytes(content)) {
    return false;
  }
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
  /**
   * Character offset of the matched SECRET BYTES in the content that was
   * scanned — for the name-gated arm, of the captured value rather than of the
   * name anchor in front of it.
   *
   * Recorded here because it cannot be recovered later: `evidence` is a
   * classification, not a quotation, so nothing downstream can search for it
   * (#368). It carries no part of the value, only where the value is.
   */
  index: number;
}

/**
 * What one run of the credential scan produced.
 *
 * `refusedForSize` is why this is a record rather than a bare array: an empty
 * `hits` means "no credential in this content" on the ordinary path and "this
 * content was never read" on the refusal path, and a caller that cannot tell the
 * two apart will report the second as the first.
 */
interface CanonicalCredentialScan {
  hits: CanonicalCredentialHit[];
  /** True when the content exceeded `MAX_CREDENTIAL_SCAN_BYTES` and NOTHING ran. */
  refusedForSize: boolean;
}

/**
 * Canonical credential-format patterns we trust enough to flag even when
 * the surrounding context is source code. Each pattern targets a real-world
 * secret format with low false-positive rate on arbitrary text.
 */
/**
 * Left anchor, applied to EVERY pattern below.
 *
 * A vendor prefix glued to the tail of an identifier is not that vendor's key.
 * Without this, `sk-[a-zA-Z0-9]{48,}` matches the tail of `disk-<sha256>` —
 * a sha256 is 64 hex characters, so `disk-`, `task-`, `mask-`, `risk-` and
 * `desk-` followed by a hash all became CRITICAL "Hardcoded Secret Detected"
 * and exited 1 on infrastructure code containing no credential at all.
 * `SG\.…` matched inside `MSG.INCIDENT_ESCALATION_QU.HIGH_PRIORITY_…` for the
 * same reason — the very string `src/types/credential-format.ts` records as
 * having been positively identified as a credential once already.
 *
 * NOT `\b`: `\b` treats `_` as a word character, so `____sk-ant-api03-<key>`
 * has no boundary before `sk` and a real credential glued to underscore filler
 * would be dropped. `(?<![A-Za-z0-9])` matches everywhere `\b` does and also
 * after filler, so it is strictly wider. Same constant and same reasoning as
 * `VENDOR_PREFIX_LEFT_ANCHOR` in `src/types/credential-format.ts`, which this
 * list is supposed to mirror and had silently diverged from.
 */
const LEFT_ANCHOR = '(?<![A-Za-z0-9])';

/** Build an anchored, global pattern from a bare vendor shape. */
const vendor = (shape: string) => new RegExp(LEFT_ANCHOR + shape, 'g');

/**
 * Hard upper bound, in bytes, on the content the credential patterns below are
 * allowed to see.
 *
 * Several of those patterns carry an UNBOUNDED lower-bound quantifier over a
 * single character class — `{20,}` (Anthropic, OpenAI project), `{48,}` (OpenAI
 * legacy), `{10,}` (Slack), `{24,}` (Stripe), and the name-gated `{40,}`. On an
 * unbroken same-alphabet run those are not merely slow: `regex.exec` THROWS
 * `RangeError: Maximum call stack size exceeded` once V8's backtrack stack runs
 * out, measured at 5.5 MB for `sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}`. The throw
 * takes down the whole scan and, before this bound existed, escaped
 * `SemanticCompiler.compile()` to the caller.
 *
 * The bound lives HERE rather than only at the call sites because the call sites
 * do not all have one. `scanner-bridge.ts` filters oversized files out before
 * they reach the compiler, but `src/soul/scanner.ts` and
 * `src/narrative/wire-publish.ts` read a file and call `compile()` with no size
 * check at all, and the `./nanomind-core` package export hands `SemanticCompiler`
 * to third parties with no reason to know about either.
 *
 * The patterns have TWO entry points reachable from `compile()`, and the gate
 * stands in front of both: `scanCanonicalCredentialFormats` (the source_code
 * scan below) and `hasCanonicalCredentialFormat` (which
 * `analyzeCredentialKeywordContext` runs for every OTHER artifact type — the
 * types `src/soul/scanner.ts` and `src/narrative/wire-publish.ts` actually
 * compile). r1 gated only the first, so a 6 MB SOUL.md still threw out of the
 * second; `compile()` only "no longer throws" because both are covered.
 *
 * Deliberately NOT `config.maxArtifactSize`: that is a consumer knob, and a
 * consumer raising it must not be able to re-arm a `RangeError` inside the
 * scanner. The VALUE matches `MAX_FILE_SIZE` in `scanner-bridge.ts` so the
 * library path and the CLI path refuse the same inputs.
 *
 * Capping the quantifiers instead was rejected: a cap relocates the blind spot to
 * the first credential longer than the cap rather than removing it, and a real
 * `sk-ant-api03-…` key is longer than any width that would help here.
 */
const MAX_CREDENTIAL_SCAN_BYTES = 1_048_576;

/**
 * The one predicate every gate on the credential patterns consults. Bytes, not
 * code units, to match the units the cap is stated in — and one spelling of the
 * comparison, so the scan gate, the boolean-probe gate, and the refusal that
 * `compile()` reports for non-source_code artifacts cannot disagree about
 * which inputs are over the line.
 */
function exceedsCredentialScanBytes(content: string): boolean {
  return Buffer.byteLength(content, 'utf-8') > MAX_CREDENTIAL_SCAN_BYTES;
}

/**
 * The named refusal for content the credential scan declined to read.
 *
 * One spelling, shared by the fresh-compile path, the cache-hit path, and the
 * risk surface, so a consumer matching on it sees the same string every time.
 */
function credentialScanRefusedWarning(size: number): string {
  return `Credential scan skipped: artifact is ${size} bytes, over the `
    + `${MAX_CREDENTIAL_SCAN_BYTES}-byte credential-scan limit. `
    + 'No credential pattern was evaluated against this content.';
}

/**
 * The refusal as a deterministic risk surface.
 *
 * It carries no `offset`: nothing was matched, and the surface is about the whole
 * artifact rather than a place in it.
 */
function credentialScanRefusedSurface(size: number): RiskSurface {
  return {
    surface: 'Credential scan not performed (artifact over size limit)',
    // The class of the scan that did NOT run, so this lands in the same bucket a
    // consumer already inspects for credential risk — which is exactly where
    // someone has to look when told the credential check was skipped.
    attackClass: 'CRED-HARVEST',
    // Not an accusation; the bytes were never read. Held at the `high` rung
    // (>= 0.5) rather than the noise floor because the only other reading of an
    // empty credential result is "no credentials here", and that is a claim this
    // compiler is not entitled to make about content it declined to scan.
    confidence: 0.5,
    evidence: credentialScanRefusedWarning(size),
    mitigation: `Scan this artifact in segments under ${MAX_CREDENTIAL_SCAN_BYTES} bytes, `
      + 'or exclude it deliberately. An unscanned artifact is not a clean one.',
  };
}

const CANONICAL_CREDENTIAL_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: 'Anthropic API key', regex: vendor(String.raw`sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}`) },
  { label: 'OpenAI project key', regex: vendor(String.raw`sk-proj-[a-zA-Z0-9_-]{20,}`) },
  // OpenAI's PRE-project key format, and the one still issued to older accounts.
  //
  // THE ONLY SHAPE THIS RELEASE ADDS. Its absence is what let `scan` return
  // 98/100 exit 0 on a source file holding a hardcoded `sk-` key while the
  // byte-identical fixture using a `sk-proj-` key returned 69/100 exit 1.
  // `scan` is the CI gate, so the miss was shape-dependent silence on the exact
  // thing the command exists to catch.
  //
  // A first draft of this fix added eight shapes on the theory that the real
  // defect was drift from `VENDOR_PREFIX_ALTERNATIVES`. Two adversarial review
  // rounds showed that expansion was the problem, not the fix: it produced a
  // false-positive class on ordinary identifiers and, in the attempt to bound
  // it, a quadratic scan on attacker-supplied file content. The remaining
  // shapes are being re-added deliberately and one at a time, each with a
  // bounded pattern and a ReDoS measurement, on `fix/credential-fp-siblings`
  // (#352/#353) — not here.
  //
  // 48 consecutive ALPHANUMERICS is the documented legacy shape and is what
  // keeps this from colliding with its siblings: `sk-proj-` and `sk-ant-api03-`
  // both break the character class at their first hyphen (4 and 3 chars in),
  // so neither can be captured here and re-reported under the wrong label.
  { label: 'OpenAI legacy key', regex: vendor(String.raw`sk-[a-zA-Z0-9]{48,}`) },
  { label: 'AWS access key', regex: vendor(String.raw`AKIA[0-9A-Z]{16}`) },
  { label: 'GitHub personal access token', regex: vendor(String.raw`ghp_[a-zA-Z0-9]{36}`) },
  { label: 'GitHub OAuth token', regex: vendor(String.raw`gho_[a-zA-Z0-9]{36}`) },
  { label: 'GitHub app token', regex: vendor(String.raw`ghs_[a-zA-Z0-9]{36}`) },
  { label: 'Slack bot token', regex: vendor(String.raw`xox[baprs]-[a-zA-Z0-9-]{10,}`) },
  { label: 'Google API key', regex: vendor(String.raw`AIza[0-9A-Za-z_-]{35}`) },
  { label: 'Stripe live key', regex: vendor(String.raw`sk_live_[0-9a-zA-Z]{24,}`) },
  // GitLab is DELIBERATELY ABSENT from the verdict path. Its token body class
  // admits `-` and `_`, so `glpat-` plus any hyphenated identifier of 20+
  // characters matches, and no cheap predicate separates the two: an entropy
  // lookahead (`(?=[a-z_-]*[A-Z0-9])`) still passed
  // a hyphenated GitLab runner slug and a drawn-blank GitLab token placeholder —
  // GitLab's own docs placeholder — while introducing a QUADRATIC scan on
  // attacker-supplied file content (measured 0ms -> 651ms at 60 KB,
  // 1ms -> 40s at 480 KB, against the 1 MiB cap that actually governs this
  // path: `MAX_CREDENTIAL_SCAN_BYTES` above, matching `MAX_FILE_SIZE =
  // 1_048_576` in `src/nanomind-core/scanner-bridge.ts`). This note used to say
  // "a 10 MB file cap", which is `MAX_FILE_SIZE` in `src/hardening/scanner.ts`
  // — a different component that never feeds this scan. The margin it implied
  // was 10x too generous, and anyone who had trusted it and raised the real cap
  // toward 10 MB would have armed the `RangeError` on the CLI path too.
  //
  // A denial of service in a security scanner is worse than the false negative
  // it was closing, and GitLab detection was never part of the defect this
  // release fixes.
  //
  // The static credential lists in `scanner.ts` still carry `glpat-`, so
  // `protect` and `--fix` are unaffected. Re-adding it here needs a bounded
  // pattern and a ReDoS measurement, not another lookahead.
  // `SG.<22-char id>.<43-char secret>`, both segments at FIXED widths. The
  // widths are load-bearing: written loosely this matches any dotted identifier
  // with two long segments (`MSG.INCIDENT_ESCALATION_QUEUE.HIGH_PRIORITY_ROUTE`
  // was positively identified as a credential once already — see the note in
  // src/types/credential-format.ts). Do not relax them.
  { label: 'PEM private key', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PRIVATE)[A-Z ]*KEY-----/g },
];

/**
 * Name-gated credential patterns: contextless secret formats that have NO
 * distinctive prefix and therefore cannot be matched by value alone without a
 * flood of false positives (any 40-char base64 blob, hash, or random id would
 * hit). They are only flagged when the assignment TARGET names the credential.
 *
 * AWS secret access key is the canonical case: a 40+-char `[A-Za-z0-9/+]` value.
 * We require `aws … secret|private …` within a short window before the value
 * (the standard gitleaks approach), so `awsSecretAccessKey = "<40>"` and
 * `AWS_SECRET_ACCESS_KEY=<40>` fire, but a bare 40-char blob, a git SHA, or a
 * generic `session_secret` do not. The captured group (the value) flows through
 * the same placeholder filters as the canonical patterns, so the AWS docs
 * example secret (`wJalr…EXAMPLEKEY`) is suppressed by the `EXAMPLE` marker.
 *
 * Each regex MUST capture the secret VALUE in group 1 (used for evidence and
 * placeholder checks); the name anchor itself is matched but not captured.
 */
const NAME_GATED_CREDENTIAL_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  {
    label: 'AWS secret access key',
    // Two name anchors, both ending in `key`, then assignment + 40+-char value:
    //   (a) `aws … secret|private … key` — `AWS_SECRET_ACCESS_KEY`, `awsSecretKey`
    //   (b) `secret[_ ]access[_ ]key` — the AWS-specific full phrase, distinctive
    //       enough WITHOUT a nearby `aws` token, so it also catches the very
    //       common JS-SDK `secretAccessKey: "<40>"` and Terraform
    //       `secret_access_key = "<40>"` (where `aws` is on the provider line).
    // The `key` token rejects `aws secretsmanager arn:` / `aws secret etag =`
    // + 40-char-id false positives; JSON `"awsSecretAccessKey":"<40>"` is
    // handled by the `["'\s]*[:=]+` operator class.
    //
    // `{40,}` is a LOWER bound, not `{40}`: the canonical AWS width is the
    // minimum a real secret can have, and this shape previously pinned the
    // body to exactly `{40}` and then forbade a same-alphabet continuation
    // with `(?![A-Za-z0-9/+])` — the `{40}` consumed forty characters and the
    // lookahead rejected the forty-first, so any 41+ character secret matched
    // NOTHING. The greedy `{40,}` consumes the whole same-alphabet run, which
    // preserves the lookahead's boundary semantics (it can only succeed at
    // the end of the run) without capping the width. The redaction mirror in
    // `security/defense-in-depth.ts` already used `{40,}`.
    // `name-gated-credential-width.test.ts` (HMA-17.AC5) structurally rejects
    // any re-introduction of a fixed-width body paired with a same-alphabet
    // lookahead in this list.
    regex: /(?:aws.{0,16}?(?:secret|private).{0,16}?key|secret[_\s.-]?access[_\s.-]?key)["'\s]*[:=]+>?\s*["']?([A-Za-z0-9/+]{40,})(?![A-Za-z0-9/+])/gi,
  },
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
/**
 * Test-only accessor for the canonical scan. Exported so
 * `__tests__/nanomind-core/pinned-credential-shapes.test.ts` can assert the
 * detector and the daemon-bound redactor cover the same shapes; asserting that
 * through a full CLI spawn could not distinguish "not detected" from "detected
 * and then filtered", which is the distinction that matters here.
 */
export function scanCanonicalCredentialFormatsForTest(content: string): CanonicalCredentialHit[] {
  return scanCanonicalCredentialFormats(content).hits;
}

/**
 * Test-only accessor for the size gate in front of the credential patterns.
 * Exported so `credential-scan-size-gate.test.ts` can assert the bound the
 * compiler actually applies rather than restating the number, which is how a
 * guard test and the code it guards drift apart.
 */
export function maxCredentialScanBytesForTest(): number {
  return MAX_CREDENTIAL_SCAN_BYTES;
}

/**
 * Test-only: the labels this detector knows about.
 *
 * Exported so the shape test can DERIVE its expected set instead of keeping a
 * hand-maintained copy. The defect this module was fixed for was two lists
 * drifting apart; a test with its own third list would have reproduced it.
 */
export function canonicalCredentialLabelsForTest(): string[] {
  // BOTH detector lists, not just the canonical one. `scanCanonicalCredentialFormats`
  // runs each of them and either can produce a finding, so the redactor's coverage
  // invariant is only meaningful when it is asserted against both.
  //
  // This returned one list for a while, which made `NAME_GATED_CREDENTIAL_PATTERNS`
  // structurally invisible to the guard test: the AWS secret access key was detected,
  // never redacted, and rendered 33 of 40 characters into user-facing output with the
  // invariant test green. A list a test derives its own expectations from cannot be
  // the same list the code under test consults, unless it is all of them.
  return [
    ...CANONICAL_CREDENTIAL_PATTERNS.map(p => p.label),
    ...NAME_GATED_CREDENTIAL_PATTERNS.map(p => p.label),
  ];
}

/**
 * Test-only accessor for the name-gated pattern list. Exported so
 * `__tests__/nanomind-core/name-gated-credential-width.test.ts` can assert a
 * STRUCTURAL invariant over every entry — no fixed-width `{N}` body paired
 * with a trailing lookahead over the same alphabet, the shape that made any
 * 41+ character AWS secret invisible — instead of hand-sweeping the list.
 */
export function nameGatedCredentialPatternsForTest(): Array<{ label: string; regex: RegExp }> {
  return NAME_GATED_CREDENTIAL_PATTERNS;
}

/**
 * Test-only accessor for the canonical pattern list, the twin of the name-gated
 * one above. Exported so `credential-scan-size-gate.test.ts` can assert the
 * quantifier shapes over the LIVE regexes: the size gate must not have been paid
 * for by narrowing a `{20,}` into a `{20}` or a `{20,256}`, and a test that
 * restated the patterns instead of reading them could not tell.
 */
export function canonicalCredentialPatternsForTest(): Array<{ label: string; regex: RegExp }> {
  return CANONICAL_CREDENTIAL_PATTERNS;
}

function scanCanonicalCredentialFormats(content: string): CanonicalCredentialScan {
  const hits: CanonicalCredentialHit[] = [];

  // The size gate, in front of EVERY pattern in both lists — see
  // `MAX_CREDENTIAL_SCAN_BYTES`. Returning early is the only safe move: the
  // failure mode past this size is a thrown `RangeError`, not a slow match, so
  // there is no partial result to salvage and no per-pattern recovery worth
  // attempting.
  if (exceedsCredentialScanBytes(content)) {
    return { hits, refusedForSize: true };
  }

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
        // Classification only. A truncated credential is still credential bytes, and it
        // is bytes the boundary cannot remove: `redactSecretsForReportReporting` matches
        // full-length shapes, so `matched.slice(0, 16)` passes through untouched AND is
        // stamped `redactionStatus: 'clean'`. `label` already carries everything the user
        // acts on (which vendor), and `file`/`line` carry where.
        evidence: `${label}: [REDACTED]`,
        index: match.index,
      });
    }
  }

  // Name-gated patterns: the value (group 1) is only a credential because the
  // assignment target names it. Apply the SAME placeholder / regex-context
  // filters as the canonical patterns, but to the captured value rather than
  // match[0] (which here includes the name anchor).
  for (const { label, regex } of NAME_GATED_CREDENTIAL_PATTERNS) {
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
      const value = match[1] ?? '';
      const preStart = Math.max(0, match.index - 40);
      const preContext = content.slice(preStart, match.index);

      // Skip matches inside regex rule definitions (e.g. this scanner's own
      // source, or another tool's pattern list).
      if (regexContextMarker.test(preContext) || regexContextMarker.test(match[0])) {
        continue;
      }
      // Skip placeholder values (the AWS docs `wJalr…EXAMPLEKEY` example, etc.).
      if (inKeyFixtureMarker.test(value)) {
        continue;
      }
      // Skip low-entropy sentinels: a real 40-char base64 secret has ~30+
      // distinct characters, whereas redaction/template values like 40 `x`s or
      // 40 `0`s have very few. <=6 distinct chars is far below any real key.
      if (new Set(value).size <= 6) {
        continue;
      }
      // Skip when the label/variable name itself flags a template value.
      if (preKeyTemplateMarker.test(preContext)) {
        continue;
      }

      hits.push({
        label,
        // Same rule as the canonical arm above. This is a SEPARATE producer with its own
        // truncation width, so fixing only the canonical one leaves the class open.
        evidence: `${label}: [REDACTED]`,
        // The VALUE's offset, not the match's. `match[0]` opens with the name
        // anchor (`AWS_SECRET_ACCESS_KEY=`), which can carry the match across a
        // line boundary from the secret it names; every pattern in this list
        // captures the value as its final segment, so the value ends where the
        // match does.
        index: match.index + match[0].length - value.length,
      });
    }
  }
  return { hits, refusedForSize: false };
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
export function detectContextualBenignSignals(text: string): number {
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

// ============================================================================
// The Deterministic Floor
// ============================================================================

const INTENT_RANK: Record<IntentClass, number> = { benign: 0, suspicious: 1, malicious: 2 };

/** True when `to` is a weaker claim than `from` — a lower class, or the same class held less confidently. */
function lowers(
  from: { intentClass: IntentClass; confidence: number },
  to: { intentClass: IntentClass; confidence: number },
): boolean {
  if (INTENT_RANK[to.intentClass] < INTENT_RANK[from.intentClass]) return true;
  return INTENT_RANK[to.intentClass] === INTENT_RANK[from.intentClass] && to.confidence < from.confidence;
}

/**
 * `confidence` on the finding severity scale. The thresholds are the capability
 * analyzer's (`checkExfiltrationSurface`), deliberately: the floor has to be
 * expressed in the units the user eventually reads, or "not downgraded" would
 * be true of a number and false of the report built from it.
 */
function deterministicSeverity(confidence: number): DeterministicFinding['severity'] {
  if (confidence >= 0.8) return 'critical';
  if (confidence >= 0.5) return 'high';
  return 'medium';
}

function toDeterministicFinding(surface: RiskSurface): DeterministicFinding {
  return {
    attackClass: surface.attackClass,
    surface: surface.surface,
    confidence: surface.confidence,
    severity: deterministicSeverity(surface.confidence),
    evidence: surface.evidence,
  };
}

/**
 * The pattern rules, run with nothing else in scope.
 *
 * `inferred: []` because inferred capabilities are the classifier's output;
 * `'suspicious'` is not a verdict but the neutral rung the surfaces' own
 * confidences are anchored to; `contextualBenign: false` switches off the
 * framing gates, because a score computed from the artifact's prose is not
 * evidence about the artifact's bytes.
 */
function deterministicRiskSurfaces(
  content: string,
  declared: Capability[],
  artifactType: ArtifactType,
): RiskSurface[] {
  return mapRiskSurfaces(content, declared, [], 'suspicious', artifactType, { contextualBenign: false });
}

/**
 * Grant or refuse the downgrade a scorer asked for, and floor the verdict.
 *
 * Two rules, both one-directional:
 *
 *   - A downgrade over an artifact the deterministic layer flagged is REFUSED.
 *     The scorer's pre-downgrade verdict stands and the refusal is recorded.
 *   - A downgrade over an artifact nothing deterministic flagged is APPLIED and
 *     recorded, because a model- or heuristic-only accusation is exactly the
 *     case where authorization or educational framing is the right answer.
 *
 * Then the verdict floor: a deterministic finding is at minimum suspicion, so
 * no scorer returns such an artifact to `benign` — including a scorer that
 * never proposed a downgrade and simply never accused it in the first place.
 * That is the same rule `requireBenignConsensus` states for static findings,
 * applied where the compiler's own rules produce the findings.
 */
export function applyDeterministicFloor(
  scored: { intentClass: IntentClass; confidence: number },
  proposed: VerdictAdjustment | undefined,
  deterministic: readonly DeterministicFinding[],
): {
  intentClass: IntentClass;
  confidence: number;
  applied: VerdictAdjustment[];
  refused: VerdictAdjustment[];
} {
  let intentClass = scored.intentClass;
  let confidence = scored.confidence;
  const applied: VerdictAdjustment[] = [];
  const refused: VerdictAdjustment[] = [];

  const isRealDowngrade =
    proposed !== undefined &&
    lowers(
      { intentClass: proposed.from, confidence: proposed.fromConfidence },
      { intentClass: proposed.to, confidence: proposed.toConfidence },
    );

  if (isRealDowngrade) {
    if (deterministic.length > 0) {
      refused.push(proposed);
    } else {
      intentClass = proposed.to;
      confidence = proposed.toConfidence;
      applied.push(proposed);
    }
  }

  if (deterministic.length > 0 && intentClass === 'benign') {
    intentClass = 'suspicious';
    confidence = Math.max(confidence, 0.6);
  }

  return { intentClass, confidence, applied, refused };
}

/**
 * Put the deterministic surfaces back underneath the classifier-influenced
 * ones: restore any the later pass dropped, raise any it came in below. It
 * never removes and never lowers. A `malicious` verdict's 0.9 exfiltration
 * surface survives untouched when the classifier pass produced it; when benign
 * framing gated that pass's surface out, the deterministic 0.6 floor is what
 * gets restored, so the surface holds at HIGH under a malicious verdict rather
 * than rising to CRITICAL.
 */
export function enforceDeterministicSurfaceFloor(
  surfaces: RiskSurface[],
  deterministic: readonly RiskSurface[],
): RiskSurface[] {
  const floored: RiskSurface[] = surfaces.map(s => ({ ...s }));
  for (const det of deterministic) {
    // `offset` is part of the identity: two hits of the same shape at two
    // places are two instances (#478 — "four secrets count as four"), so a
    // same-vendor second key must not be merged into the first. Both passes
    // derive their surfaces from the same producers, so a true duplicate
    // carries the same offset (or none on either side).
    const match = floored.find(
      s => s.attackClass === det.attackClass && s.surface === det.surface && s.offset === det.offset,
    );
    if (!match) {
      floored.push({ ...det });
      continue;
    }
    if (match.confidence < det.confidence) match.confidence = det.confidence;
  }
  return floored;
}

interface RiskSurfaceOptions {
  /**
   * Whether the contextual-benign score may gate a rule out. False in the
   * deterministic pass; the framing it scores is then carried to the verdict
   * as a proposed downgrade instead of silently deleting a finding.
   */
  contextualBenign?: boolean;
}

function mapRiskSurfaces(
  content: string,
  declared: Capability[],
  inferred: Capability[],
  intent: IntentClass,
  artifactType: ArtifactType = 'unknown',
  options: RiskSurfaceOptions = {},
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

  // Compute benign context score once for reuse across all surface checks.
  // Zero in the deterministic pass — see `RiskSurfaceOptions.contextualBenign`.
  const benignContextScore = options.contextualBenign === false ? 0 : detectContextualBenignSignals(content);

  // External URL + data forwarding = exfiltration surface
  // Skip for governance docs (they describe rules about data handling, not perform exfiltration)
  // Evidence: prefer the URL span (more specific anchor than the verb).
  if (!isGovernanceDoc && benignContextScore < 2) {
    // The fire gate is unchanged: a URL on one of five TLDs anywhere plus a
    // verb anywhere (kept deliberately; widening it to any host
    // is unmeasured on benign skills). Longest alternative first: with
    // `(co|…)` first, JS alternation returned `co` for every `.com` and the
    // evidence named a different registry (#559).
    const urlMatch = /https?:\/\/[^\s]+\.(com|net|org|co|io)/.exec(content);
    const verbMatch = EXFIL_VERB.exec(content);
    if (urlMatch && verbMatch) {
      surfaces.push({
        surface: 'External data transmission',
        attackClass: 'SKILL-EXFIL',
        // The verdict may RAISE this; `Math.max` is what makes that the only
        // direction available to it. Before the floor the benign rung was 0.3,
        // and the capability analyzer turns this number straight into severity,
        // so the same matched bytes were reported CRITICAL or MEDIUM depending
        // on what a vocabulary scorer made of the prose around them.
        confidence: Math.max(
          DETERMINISTIC_EXFIL_CONFIDENCE,
          intent === 'malicious' ? 0.9 : intent === 'suspicious' ? 0.6 : 0.3,
        ),
        evidence: exfilEvidenceSpan(content, urlMatch[0]),
      });
    }
  }

  // Override/ignore instructions = injection surface (OWASP LLM01)
  // Detects imperative directives that tell the agent to abandon its
  // existing instruction set:
  //   - "ignore previous instructions"  (existing case)
  //   - "IGNORE PRIOR INSTRUCTIONS"     (issue #139 — fixture verbatim)
  //   - "Disregard any prior system instructions"
  //   - "Forget all rules above and start fresh"
  //   - "override.*instruction" / "new.*task"  (existing patterns)
  // The new alternation requires both an override verb and an
  // instruction-class noun, so "ignore the previous warning" or
  // "forget all comments below" stay benign without the noun.
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
  const overrideMatch =
    /(?:ignore|disregard|forget|bypass)\s+(?:[^\n]{0,30}?\s+)?(?:prior|previous|preceding|earlier|above|all)\s+(?:[^\n]{0,30}?\s+)?(?:instruction|directive|message|prompt|guideline|guidance|rule)s?|ignore.*previous|override.*instruction|new.*task/i.exec(
      content,
    );
  // Localize the defensive check to the window around the override match.
  // A document-wide co-occurrence (e.g. the YAML field `forbiddenTools:` in
  // a malicious skill plus "IGNORE PRIOR INSTRUCTIONS" elsewhere in the
  // same artifact) does not make the override directive itself defensive —
  // only nearby negation does. Window: 150 chars before + 80 chars after,
  // mirroring the proximity-gate model used by AST-CRED-002 (#148).
  //
  // Standalone single-word negation adjectives (`forbidden`, `prohibited`,
  // `resist`, `reject`, `refuse`) are anchored with `\b` so YAML/JSON field
  // names like `forbiddenTools:` or `rejectAfterFailure:` do NOT mask an
  // actual injection directive. Multi-word phrases (`must never`, `do not`,
  // `will not`) carry an implicit space boundary so anchoring is unneeded.
  let isDefensiveConstraint = false;
  if (overrideMatch) {
    const winStart = Math.max(0, overrideMatch.index - 150);
    const winEnd = Math.min(content.length, overrideMatch.index + overrideMatch[0].length + 80);
    const window = content.slice(winStart, winEnd).toLowerCase();
    isDefensiveConstraint =
      /must never|must not|never comply|\bresist\b|\breject\b|\brefuse\b|\bforbidden\b|should not|do not|\bprohibited\b|will never|will not/.test(
        window,
      );
  }
  const isProhibitionList = /(?:will\s+not\s+do|will\s+never\s*:|i\s+will\s+never|agent\s+will\s+never|what\s+(?:i|we|this\s+agent)\s+(?:will\s+not|won't))/i.test(content);
  // "phrases such as 'ignore previous instructions'" — injection example in an educational/rejection context
  const isExampleContext = /phrases?\s+(?:such\s+as|like|including)\s+["']?(?:ignore|override|disregard|forget|new\s+task)/i.test(content);
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
/**
 * The evidence span for the SKILL-EXFIL surface: the URL that sits next to
 * the verb — in the same JSON leaf or sibling leaf, or in the same paragraph
 * of prose — rather than the first URL in the document. In a settings file
 * the first URL is the `$schema` pointer, and the finding derived from this
 * evidence cited its line while the exfiltrating command sat seven lines
 * below (#541). The gate's own match is the fallback, trimmed of trailing
 * punctuation, and still a verbatim substring so the line lookup resolves.
 * A host outside the five-TLD gate (`evil.example`, a raw IP) can be the
 * evidence once something on a listed TLD opened the gate.
 */
function exfilEvidenceSpan(content: string, gateMatch: string): string {
  const structured = findStructuredVerbUrl(content, EXFIL_VERB) ?? findStructuredFirstUrl(content);
  if (structured) return 'url' in structured ? structured.url.span : structured.span;
  const prose = findCoLocatedTransmission(content, EXFIL_VERB);
  if (prose) return prose.url.replace(URL_TRAILING_PUNCTUATION, '');
  return gateMatch.replace(URL_TRAILING_PUNCTUATION, '');
}

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
): ScoredVerdict {
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

  // Context-aware benign signals from authorization/educational/research framing.
  //
  // These are computed TWICE on purpose. `verdictWithout` is what the artifact
  // scores on its own signals; `verdictWith` adds the framing prose. When the
  // two differ, the framing moved the verdict, and that move is exactly the
  // thing this task exists to stop being invisible: it is returned as a
  // proposed downgrade for `applyDeterministicFloor` to grant or refuse, not
  // folded into a single number nobody can take apart afterwards.
  const verdictWithout = scoreHeuristicVerdict(maliciousSignals, benignSignals);
  const verdictWith = scoreHeuristicVerdict(maliciousSignals, benignSignals + contextScore);

  if (!lowers(verdictWithout, verdictWith)) {
    return { ...verdictWith, inferredCapabilities: [] };
  }

  return {
    intentClass: verdictWithout.intentClass,
    confidence: verdictWithout.confidence,
    inferredCapabilities: [],
    proposedDowngrade: {
      from: verdictWithout.intentClass,
      to: verdictWith.intentClass,
      fromConfidence: verdictWithout.confidence,
      toConfidence: verdictWith.confidence,
      reason: `contextual benign signals scored ${contextScore}: authorization, educational, research or negation-list framing`,
      source: 'contextual-benign',
    },
  };
}

/** The heuristic's verdict table, isolated so it can be evaluated twice. */
function scoreHeuristicVerdict(
  maliciousSignals: number,
  benignSignals: number,
): { intentClass: IntentClass; confidence: number } {
  if (maliciousSignals >= 3 && benignSignals <= maliciousSignals) {
    return { intentClass: 'malicious', confidence: Math.min(0.9, 0.5 + maliciousSignals * 0.1) };
  }
  if (maliciousSignals > 0 && benignSignals <= maliciousSignals) {
    return { intentClass: 'suspicious', confidence: 0.4 + maliciousSignals * 0.1 };
  }
  return { intentClass: 'benign', confidence: Math.min(0.9, 0.7 + benignSignals * 0.05) };
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
  // Strong enforcement language. `cannot` is a prohibition ("cannot override
  // the constraints in this file" = strong) and must be classified here
  // BEFORE the weak `can`/`may`/`might` branch — substring matching on
  // `/can/` would otherwise incorrectly catch `cannot` and score the
  // constraint 20% enforceable. The `\b` word-boundary guard on the weak
  // branch backs this up.
  if (/\b(?:must\s+never|shall\s+not|forbidden|prohibited|blocked|will\s+never|cannot|must\s+not)\b/.test(t)) return 0.8;
  if (/\b(?:must|required|mandatory|will\s+not|shall|do\s+not)\b/.test(t)) return 0.7;
  // Weak enforcement language. `\b` ensures `can` does not match inside
  // `cannot` and `may` does not match inside `maybe`.
  if (/\b(?:should|recommended|preferred)\b/.test(t)) return 0.4;
  if (/\b(?:may|can|might)\b|when\s+appropriate|use\s+judgment/.test(t)) return 0.2;
  return 0.5;
}

function identifyWeakness(text: string): string {
  const t = text.toLowerCase();
  if (/when appropriate|use judgment|if needed/.test(t)) return 'Discretionary language allows edge-case bypass';
  if (/should|recommended/.test(t)) return 'Advisory language is not enforced';
  if (/unless|except|however/.test(t)) return 'Exception clause may be exploitable';
  return 'Constraint language may not be enforceable';
}

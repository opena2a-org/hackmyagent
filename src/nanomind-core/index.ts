/**
 * NanoMind Core -- Semantic Security Compiler
 *
 * The foundational layer for ALL security scanning in HackMyAgent.
 * Compiles raw artifacts into Abstract Security Trees (ASTs) that
 * analyzers query instead of raw text.
 *
 * Architecture:
 *   Artifact → Ingestion (validate, sanitize) → Compiler (AST) → Analyzers (findings)
 *
 * Three principles:
 *   1. NanoMind is the foundation, not a post-processor
 *   2. Security-first: signed ASTs, input sanitization, sandboxed execution
 *   3. World-class design: compiler architecture, not regex patches
 */

// Core types
export type {
  SecurityAST,
  CompilationResult,
  CompilerConfig,
  ArtifactType,
  Capability,
  Constraint,
  ConstraintDomain,
  DataAccessPattern,
  RiskSurface,
  IntentClass,
  EvidenceSpan,
} from './types.js';
export { DEFAULT_COMPILER_CONFIG } from './types.js';

// Compiler
export { SemanticCompiler } from './compiler/semantic-compiler.js';

// Analyzers
export { analyzeCapabilities } from './analyzers/capability-analyzer.js';
export type { ASTFinding } from './analyzers/capability-analyzer.js';
export { analyzeCredentials } from './analyzers/credential-analyzer.js';
export { analyzeGovernance } from './analyzers/governance-analyzer.js';
export { analyzeScope } from './analyzers/scope-analyzer.js';
export { analyzePrompt } from './analyzers/prompt-analyzer.js';
export { analyzeCode } from './analyzers/code-analyzer.js';

// Verification
export { validateAST } from './verification/ast-validator.js';
export type { ASTValidationResult, ClaimValidation, Discrepancy } from './verification/ast-validator.js';

// Security
export { enforceSeverityFloor, validateEnhancement, requireBenignConsensus, redactSecretsForNanoMind, assertASTIntegrity, SecurityError, verifyTrainingProvenance, logSecurityEvent, getAuditEvents } from './security/defense-in-depth.js';
export { verifyAll, EventChain, generateManifest } from './security/integrity-verifier.js';

// Inference -- TME Classifier (ONNX, 10-class labels)
export { TMEClassifier, getTMEClassifier } from './inference/tme-classifier.js';
export type { TMEClassification } from './inference/tme-classifier.js';

// Inference -- Security Analyst (generative, structured JSON)
export {
  getAnalystStatus,
  isAnalystReady,
  setupAnalystModel,
  runAnalystInference,
  analyzeThreat,
  assessCredentialContext,
  assessFalsePositive,
  generateIntelReport,
} from './inference/security-analyst.js';
export type {
  AnalystTaskType,
  AnalystRequest,
  AnalystResponse,
  AnalystBackend,
  AnalystStatus,
  ThreatAnalysis,
  CredentialContext,
  FalsePositiveAssessment,
} from './inference/security-analyst.js';

// Analyst coverage routing (Phase A P1, CDS-023): posture-vs-attack + abstention
// layer that lets the analyst inform/escalate without auto-flipping the verdict.
// Wired into orchestrateNanoMind's coverage sweep under the abstention-gated
// policy (the only product-safe policy per the P3 corpus join, 2026-06-06):
// the analyst escalates structural misses for human review; raw analyst
// auto-verdict remains NO-GO (CDS-024).
export {
  routeAnalystVerdict,
  combineVerdict,
  namesAttackClass,
  isKnownAttackClass,
  NON_ATTACK_CLASSES,
  HIGH_SEVERITIES,
  MID_SEVERITIES,
  KNOWN_ATTACK_CLASSES,
} from './analyst-coverage.js';
export type {
  RoutedAnalystVerdict,
  CombinePolicy,
  AnalystVerdict,
  CombinedVerdict,
} from './analyst-coverage.js';

// Orchestration (scan-path entry: scanner-bridge + analyst stages + coverage sweep)
export {
  orchestrateNanoMind,
  runCoverageSweep,
  sweepIndicatesDaemonError,
  POSTURE_HARDENING_CHECKS,
} from './orchestrate.js';
export type {
  OrchestrationOptions,
  OrchestrationResult,
  AnalystEscalation,
  CoverageSweepStats,
  CoverageSweepOutcome,
} from './orchestrate.js';
export type { CoverageCandidate, NanoMindScanResult } from './scanner-bridge.js';
export { classifyArtifactForCoverage } from './inference/security-analyst.js';
export type { ArtifactCoverageVerdict } from './inference/security-analyst.js';

// Ingestion
export { parseArtifact, classifyArtifactType, computeHash } from './ingestion/artifact-parser.js';
export { sanitizeForNanoMind, detectManipulation } from './ingestion/input-sanitizer.js';
export type { ParsedArtifact } from './ingestion/artifact-parser.js';
export type { SanitizationResult, ManipulationAttempt } from './ingestion/input-sanitizer.js';

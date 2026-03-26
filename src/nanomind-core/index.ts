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

// Ingestion
export { parseArtifact, classifyArtifactType, computeHash } from './ingestion/artifact-parser.js';
export { sanitizeForNanoMind, detectManipulation } from './ingestion/input-sanitizer.js';
export type { ParsedArtifact } from './ingestion/artifact-parser.js';
export type { SanitizationResult, ManipulationAttempt } from './ingestion/input-sanitizer.js';

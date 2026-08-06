/**
 * HMA Attack Engine
 *
 * Derives an artifact's attack surface and generates target-specific attack
 * payloads. It does NOT execute them and reports no resilience score: no agent
 * runs, so nothing about resistance is measured (#369). See feedback-loop.ts.
 */

export { readTarget } from './target-reader.js';
export { generateInitialPayloads, generateAdaptedPayload } from './payload-generator.js';
export { runAttackSession, exportTrainingData } from './feedback-loop.js';
export type {
  SemanticTargetProfile,
  VulnerabilitySurfaceEntry,
  AttackCategory,
  AdaptivePayload,
  AttackOutcome,
  AttackEvaluation,
  AttackResult,
  DefenseMap,
  DefenseEntry,
  AttackSessionResult,
  VulnerabilityFinding,
  AttackEngineConfig,
} from './types.js';
export { DEFAULT_ATTACK_CONFIG } from './types.js';

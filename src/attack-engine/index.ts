/**
 * HMA Adaptive Attack Engine
 *
 * NanoMind-powered red team agent that generates target-specific
 * attack payloads, observes responses, adapts attacks, and iterates.
 * Replaces static payloads with semantic attack generation.
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
  AttackResult,
  DefenseMap,
  DefenseEntry,
  AttackSessionResult,
  VulnerabilityFinding,
  AttackEngineConfig,
} from './types.js';
export { DEFAULT_ATTACK_CONFIG } from './types.js';

/**
 * Attack Module
 * Adversarial security testing for AI agents
 */

export { AttackScanner } from './scanner';

export {
  AttackCategory,
  AttackIntensity,
  AttackSeverity,
  AttackPayload,
  AttackResult,
  AttackReport,
  AttackTarget,
  AttackOptions,
  ATTACK_CATEGORIES,
} from './types';

export {
  ALL_PAYLOADS,
  PAYLOAD_STATS,
  getPayloads,
  getPayloadById,
  getPayloadsByCategory,
  getPayloadsByIntensity,
  PROMPT_INJECTION_PAYLOADS,
  JAILBREAK_PAYLOADS,
  DATA_EXFILTRATION_PAYLOADS,
  CAPABILITY_ABUSE_PAYLOADS,
  CONTEXT_MANIPULATION_PAYLOADS,
} from './payloads';

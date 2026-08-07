/**
 * Attack Module
 * Adversarial security testing for AI agents
 */

export { AttackScanner } from './scanner';
export { parseCustomPayloads } from './custom-payloads';
export { shouldFail, attackExitCode } from './fail-policy';
export type { FailPolicy } from './fail-policy';

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

export type { CustomPayloadInput, CustomPayloadFile } from './types';

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
  MCP_EXPLOITATION_PAYLOADS,
  A2A_ATTACK_PAYLOADS,
  MEMORY_WEAPONIZATION_PAYLOADS,
  CONTEXT_WINDOW_PAYLOADS,
  SUPPLY_CHAIN_PAYLOADS,
  TOOL_SHADOW_PAYLOADS,
} from './payloads';

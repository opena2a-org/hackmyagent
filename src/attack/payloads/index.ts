/**
 * Attack Payloads Index
 */

import { AttackPayload, AttackCategory, AttackIntensity } from '../types';
import { PROMPT_INJECTION_PAYLOADS } from './prompt-injection';
import { JAILBREAK_PAYLOADS } from './jailbreak';
import { DATA_EXFILTRATION_PAYLOADS } from './data-exfiltration';
import { CAPABILITY_ABUSE_PAYLOADS } from './capability-abuse';
import { CONTEXT_MANIPULATION_PAYLOADS } from './context-manipulation';
import { MCP_EXPLOITATION_PAYLOADS } from './mcp-exploitation';
import { A2A_ATTACK_PAYLOADS } from './a2a-attacks';
import { MEMORY_WEAPONIZATION_PAYLOADS } from './memory-weaponization';
import { CONTEXT_WINDOW_PAYLOADS } from './context-window';
import { SUPPLY_CHAIN_PAYLOADS } from './supply-chain';
import { TOOL_SHADOW_PAYLOADS } from './tool-shadow';
import { PARSER_DIFFERENTIAL_PAYLOADS } from './parser-differential';
import { PERSISTENT_AGENT_PAYLOADS } from './persistent-agent';
import { FAKE_TOOL_PAYLOADS } from './fake-tool';

/** All available payloads */
export const ALL_PAYLOADS: AttackPayload[] = [
  ...PROMPT_INJECTION_PAYLOADS,
  ...JAILBREAK_PAYLOADS,
  ...DATA_EXFILTRATION_PAYLOADS,
  ...CAPABILITY_ABUSE_PAYLOADS,
  ...CONTEXT_MANIPULATION_PAYLOADS,
  ...MCP_EXPLOITATION_PAYLOADS,
  ...A2A_ATTACK_PAYLOADS,
  ...MEMORY_WEAPONIZATION_PAYLOADS,
  ...CONTEXT_WINDOW_PAYLOADS,
  ...SUPPLY_CHAIN_PAYLOADS,
  ...TOOL_SHADOW_PAYLOADS,
  ...PARSER_DIFFERENTIAL_PAYLOADS,
  ...PERSISTENT_AGENT_PAYLOADS,
  ...FAKE_TOOL_PAYLOADS,
];

/** Get payloads by category */
export function getPayloadsByCategory(category: AttackCategory): AttackPayload[] {
  return ALL_PAYLOADS.filter(p => p.category === category);
}

/** Get payloads by intensity level (includes lower levels) */
export function getPayloadsByIntensity(intensity: AttackIntensity): AttackPayload[] {
  const levels: AttackIntensity[] =
    intensity === 'passive' ? ['passive'] :
    intensity === 'active' ? ['passive', 'active'] :
    ['passive', 'active', 'aggressive'];

  return ALL_PAYLOADS.filter(p => levels.includes(p.intensity));
}

/** Get payloads by category and intensity */
export function getPayloads(
  categories?: AttackCategory[],
  intensity: AttackIntensity = 'active'
): AttackPayload[] {
  let payloads = getPayloadsByIntensity(intensity);

  if (categories && categories.length > 0) {
    payloads = payloads.filter(p => categories.includes(p.category));
  }

  return payloads;
}

/** Get payload by ID */
export function getPayloadById(id: string): AttackPayload | undefined {
  return ALL_PAYLOADS.find(p => p.id === id);
}

/** Payload statistics */
export const PAYLOAD_STATS = {
  total: ALL_PAYLOADS.length,
  byCategory: {
    'prompt-injection': PROMPT_INJECTION_PAYLOADS.length,
    'jailbreak': JAILBREAK_PAYLOADS.length,
    'data-exfiltration': DATA_EXFILTRATION_PAYLOADS.length,
    'capability-abuse': CAPABILITY_ABUSE_PAYLOADS.length,
    'context-manipulation': CONTEXT_MANIPULATION_PAYLOADS.length,
    'mcp-exploitation': MCP_EXPLOITATION_PAYLOADS.length,
    'a2a-attack': A2A_ATTACK_PAYLOADS.length,
    'memory-weaponization': MEMORY_WEAPONIZATION_PAYLOADS.length,
    'context-window': CONTEXT_WINDOW_PAYLOADS.length,
    'supply-chain': SUPPLY_CHAIN_PAYLOADS.length,
    'tool-shadow': TOOL_SHADOW_PAYLOADS.length,
    'parser-differential': PARSER_DIFFERENTIAL_PAYLOADS.length,
    'persistent-agent': PERSISTENT_AGENT_PAYLOADS.length,
    'fake-tool': FAKE_TOOL_PAYLOADS.length,
  } as Record<AttackCategory, number>,
  byIntensity: {
    passive: ALL_PAYLOADS.filter(p => p.intensity === 'passive').length,
    active: ALL_PAYLOADS.filter(p => p.intensity === 'active').length,
    aggressive: ALL_PAYLOADS.filter(p => p.intensity === 'aggressive').length,
  } as Record<AttackIntensity, number>,
};

export {
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
  PARSER_DIFFERENTIAL_PAYLOADS,
  PERSISTENT_AGENT_PAYLOADS,
  FAKE_TOOL_PAYLOADS,
};

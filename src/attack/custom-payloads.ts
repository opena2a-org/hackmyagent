/**
 * Custom Payload Parser
 * Parses and validates user-provided JSON payload files
 */

import {
  AttackPayload,
  AttackCategory,
  AttackIntensity,
  AttackSeverity,
  CustomPayloadInput,
} from './types';

const VALID_CATEGORIES: AttackCategory[] = [
  'prompt-injection', 'jailbreak', 'data-exfiltration',
  'capability-abuse', 'context-manipulation',
  'mcp-exploitation', 'a2a-attack', 'memory-weaponization',
  'context-window', 'supply-chain', 'tool-shadow',
  'parser-differential', 'persistent-agent', 'fake-tool',
];

const VALID_INTENSITIES: AttackIntensity[] = ['passive', 'active', 'aggressive'];

const VALID_SEVERITIES: AttackSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Parse a JSON string containing custom attack payloads.
 * Validates structure, compiles regex patterns, and applies defaults.
 */
export function parseCustomPayloads(jsonString: string): AttackPayload[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonString);
  } catch (e) {
    throw new Error(`Invalid JSON in payload file: ${e instanceof Error ? e.message : 'parse error'}`);
  }

  if (!parsed || typeof parsed !== 'object' || !Array.isArray((parsed as any).payloads)) {
    throw new Error('Payload file must contain a "payloads" array (e.g. { "payloads": [...] })');
  }

  const inputs: unknown[] = (parsed as any).payloads;
  if (inputs.length === 0) {
    throw new Error('Payload file "payloads" array must not be empty');
  }

  const seenIds = new Set<string>();
  const results: AttackPayload[] = [];

  for (let i = 0; i < inputs.length; i++) {
    const raw = inputs[i] as Record<string, unknown>;
    const label = `payloads[${i}]`;

    if (!raw || typeof raw !== 'object') {
      throw new Error(`${label}: must be an object`);
    }

    // Required fields
    if (typeof raw.id !== 'string' || raw.id.trim() === '') {
      throw new Error(`${label}: "id" is required and must be a non-empty string`);
    }
    if (typeof raw.payload !== 'string' || raw.payload.trim() === '') {
      throw new Error(`${label} (${raw.id}): "payload" is required and must be a non-empty string`);
    }

    const id = raw.id as string;

    // Duplicate check
    if (seenIds.has(id)) {
      throw new Error(`${label}: duplicate id "${id}"`);
    }
    seenIds.add(id);

    // Validate enum fields
    if (raw.category !== undefined) {
      if (!VALID_CATEGORIES.includes(raw.category as AttackCategory)) {
        throw new Error(`${label} (${id}): invalid category "${raw.category}". Use: ${VALID_CATEGORIES.join(', ')}`);
      }
    }
    if (raw.intensity !== undefined) {
      if (!VALID_INTENSITIES.includes(raw.intensity as AttackIntensity)) {
        throw new Error(`${label} (${id}): invalid intensity "${raw.intensity}". Use: ${VALID_INTENSITIES.join(', ')}`);
      }
    }
    if (raw.severity !== undefined) {
      if (!VALID_SEVERITIES.includes(raw.severity as AttackSeverity)) {
        throw new Error(`${label} (${id}): invalid severity "${raw.severity}". Use: ${VALID_SEVERITIES.join(', ')}`);
      }
    }

    // Compile regex patterns
    const successIndicators = compilePatterns(raw.successIndicators as string[] | undefined, label, id, 'successIndicators');
    const blockedIndicators = compilePatterns(raw.blockedIndicators as string[] | undefined, label, id, 'blockedIndicators');

    results.push({
      id,
      payload: raw.payload as string,
      name: (raw.name as string) || `Custom Payload ${id}`,
      description: (raw.description as string) || 'Custom attack payload',
      category: (raw.category as AttackCategory) || 'prompt-injection',
      intensity: (raw.intensity as AttackIntensity) || 'active',
      severity: (raw.severity as AttackSeverity) || 'medium',
      successIndicators,
      blockedIndicators,
      oasbControl: raw.oasbControl as string | undefined,
      cwe: raw.cwe as string | undefined,
      remediation: (raw.remediation as string) || 'Review agent response for unexpected behavior',
    });
  }

  return results;
}

function compilePatterns(
  patterns: string[] | undefined,
  label: string,
  id: string,
  field: string,
): RegExp[] {
  if (!patterns) return [];
  if (!Array.isArray(patterns)) {
    throw new Error(`${label} (${id}): "${field}" must be an array of strings`);
  }
  return patterns.map((p, j) => {
    if (typeof p !== 'string') {
      throw new Error(`${label} (${id}): ${field}[${j}] must be a string`);
    }
    try {
      return new RegExp(p, 'i');
    } catch (e) {
      throw new Error(`${label} (${id}): ${field}[${j}] is not a valid regex: "${p}"`);
    }
  });
}

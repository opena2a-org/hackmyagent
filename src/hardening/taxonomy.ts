/**
 * Attack Taxonomy Mapping
 * Maps HMA security check IDs to registry attack class identifiers.
 * These identifiers match the attack_classes table in the OpenA2A Registry.
 */

import type { SecurityFinding } from './security-check';

/** Maps HMA check ID prefixes and exact IDs to attack class identifiers */
const TAXONOMY_MAP: Record<string, string> = {
  // SOUL series
  'SOUL-TH-001': 'SOUL-POISON',
  'SOUL-TH-002': 'SOUL-POISON',
  'SOUL-TH-003': 'SOUL-DRIFT',
  'SOUL-TH-004': 'SOUL-DRIFT',
  'SOUL-TH-005': 'SOUL-INJECT',
  'SOUL-CB-001': 'SOUL-BOUNDARY',
  'SOUL-CB-002': 'SOUL-BOUNDARY',
  'SOUL-IH-001': 'SOUL-INJECT',
  'SOUL-IH-002': 'SOUL-INJECT',
  'PROMPT-001': 'SOUL-INJECT',
  'PROMPT-002': 'SOUL-INJECT',
  'PROMPT-003': 'SOUL-INJECT',
  'PROMPT-004': 'SOUL-INJECT',
  'SOUL-DH-001': 'SOUL-DELEGATE',
  'SOUL-DH-002': 'SOUL-DELEGATE',
  'SOUL-HB-001': 'SOUL-OVERRIDE',
  'SOUL-HB-002': 'SOUL-OVERRIDE',
  'SOUL-AS-001': 'SOUL-COLLUDE',
  'SOUL-AS-002': 'SOUL-COLLUDE',
  'SOUL-HT-001': 'SOUL-COLLUDE',
  'SOUL-HT-002': 'SOUL-COLLUDE',
  'SOUL-HO-001': 'SOUL-OVERRIDE',
  'SOUL-HO-002': 'SOUL-OVERRIDE',

  // Harm avoidance
  'SOUL-HV-001': 'HV-DECEPTION',
  'SOUL-HV-002': 'HV-MANIPULATION',
  'SOUL-HV-003': 'HV-UNSAFE-CODE',
  'SOUL-HV-004': 'HV-RESOURCE-ABUSE',

  // Credential exposure
  'CRED-001': 'CRED-HARVEST',
  'CRED-002': 'CRED-HARVEST',
  'CRED-003': 'CRED-HARVEST',
  'CRED-004': 'CRED-HARVEST',

  // Unicode steganography
  'UNICODE-STEGO-001': 'STEGO-INJECT',
  'UNICODE-STEGO-002': 'STEGO-INJECT',
  'UNICODE-STEGO-003': 'STEGO-INJECT',
  'UNICODE-STEGO-004': 'STEGO-INJECT',
  'UNICODE-STEGO-005': 'STEGO-INJECT',

  // OpenClaw persistence
  'HEARTBEAT-001': 'SOUL-PERSIST',
  'HEARTBEAT-002': 'SOUL-PERSIST',
  'HEARTBEAT-003': 'SOUL-PERSIST',
  'HEARTBEAT-004': 'SOUL-PERSIST',
  'HEARTBEAT-005': 'SOUL-PERSIST',
  'HEARTBEAT-006': 'SOUL-PERSIST',
  'SKILL-002': 'SOUL-PERSIST',
  'SKILL-003': 'SOUL-PERSIST',

  // Skill exfiltration
  'SKILL-006': 'SOUL-EXFIL',
  'NET-001': 'SOUL-EXFIL',
  'NET-002': 'SOUL-EXFIL',
  'NET-003': 'SOUL-EXFIL',

  // Supply chain
  'SUPPLY-001': 'ORG-SKILL-SUPPLY',
  'SUPPLY-002': 'ORG-SKILL-SUPPLY',
  'SUPPLY-003': 'ORG-SKILL-SUPPLY',
  'SUPPLY-004': 'ORG-SKILL-SUPPLY',
  'SUPPLY-005': 'ORG-SKILL-SUPPLY',
  'SUPPLY-006': 'ORG-SKILL-SUPPLY',
  'SUPPLY-007': 'ORG-SKILL-SUPPLY',
  'SUPPLY-008': 'ORG-SKILL-SUPPLY',
  'DEP-001': 'ORG-SKILL-SUPPLY',
  'DEP-002': 'ORG-SKILL-SUPPLY',
  'DEP-003': 'ORG-SKILL-SUPPLY',
  'DEP-004': 'ORG-SKILL-SUPPLY',

  // Memory/context
  'MEM-001': 'MEM-POISON',
  'MEM-002': 'MEM-POISON',
  'MEM-003': 'MEM-POISON',
  'MEM-004': 'MEM-POISON',
  'MEM-005': 'MEM-POISON',

  // RAG poisoning
  'RAG-001': 'RAG-POISON',
  'RAG-002': 'RAG-POISON',
  'RAG-003': 'RAG-POISON',
  'RAG-004': 'RAG-POISON',

  // Identity spoofing
  'AIM-001': 'IDENTITY-SPOOF',
  'AIM-002': 'IDENTITY-SPOOF',
  'AIM-003': 'IDENTITY-SPOOF',

  // Agent DNA forgery
  'DNA-001': 'DNA-FORGE',
  'DNA-002': 'DNA-FORGE',
  'DNA-003': 'DNA-FORGE',

  // Skill memory
  'SKILL-MEM-001': 'SKILL-MEM',

  // Adversarial skill
  'SKILL-001': 'SKILL-ADVERSARIAL',
  'SKILL-004': 'SKILL-ADVERSARIAL',
  'SKILL-005': 'SKILL-ADVERSARIAL',
  'SKILL-007': 'SKILL-ADVERSARIAL',
  'SKILL-008': 'SKILL-ADVERSARIAL',
  'SKILL-009': 'SKILL-ADVERSARIAL',
  'SKILL-010': 'SKILL-ADVERSARIAL',
  'SKILL-011': 'SKILL-ADVERSARIAL',
  'SKILL-012': 'SKILL-ADVERSARIAL',
  'SKILL-018': 'SKILL-ADVERSARIAL',
  'SKILL-019': 'SKILL-ADVERSARIAL',
  'HEARTBEAT-007': 'SKILL-ADVERSARIAL',

  // Gateway/config
  'GATEWAY-001': 'GATEWAY-EXPLOIT',
  'GATEWAY-002': 'GATEWAY-EXPLOIT',
  'GATEWAY-003': 'GATEWAY-EXPLOIT',
  'GATEWAY-004': 'GATEWAY-EXPLOIT',
  'GATEWAY-005': 'GATEWAY-EXPLOIT',
  'GATEWAY-006': 'GATEWAY-EXPLOIT',
  'GATEWAY-007': 'GATEWAY-EXPLOIT',
  'GATEWAY-008': 'GATEWAY-EXPLOIT',

  // MCP exploitation
  'MCP-001': 'MCP-EXPLOIT',
  'MCP-002': 'MCP-EXPLOIT',
  'MCP-003': 'MCP-EXPLOIT',
  'MCP-004': 'MCP-EXPLOIT',
  'MCP-005': 'MCP-EXPLOIT',
  'MCP-006': 'MCP-EXPLOIT',
  'MCP-007': 'MCP-EXPLOIT',
  'MCP-008': 'MCP-EXPLOIT',
  'MCP-009': 'MCP-EXPLOIT',
  'MCP-010': 'MCP-EXPLOIT',
};

/**
 * Look up the attack class for a given HMA check ID.
 * Returns undefined if no mapping exists.
 */
export function getAttackClass(checkId: string): string | undefined {
  return TAXONOMY_MAP[checkId];
}

/**
 * Enrich an array of SecurityFindings with their attack class mappings.
 * Modifies findings in place.
 */
export function enrichWithTaxonomy(findings: SecurityFinding[]): void {
  for (const finding of findings) {
    const attackClass = getAttackClass(finding.checkId);
    if (attackClass) {
      finding.attackClass = attackClass;
    }
  }
}

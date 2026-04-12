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
  'SOUL-TH-005': 'SOUL-IMPERSONATE',
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
  'SOUL-HB-001': 'PHANTOM-SOUL',
  'SOUL-HB-002': 'PHANTOM-SOUL',
  'SOUL-AS-001': 'SOUL-FORK',
  'SOUL-AS-002': 'SOUL-FORK',
  'SOUL-HT-001': 'SOUL-FORK',
  'SOUL-HT-002': 'SOUL-FORK',
  'SOUL-HO-001': 'SOUL-HIJACK',
  'SOUL-HO-002': 'SOUL-HIJACK',

  // Harm avoidance
  'SOUL-HV-001': 'SOUL-HV-001',
  'SOUL-HV-002': 'SOUL-HV-002',
  'SOUL-HV-003': 'SOUL-HV-003',
  'SOUL-HV-004': 'SOUL-HV-004',

  // Credential exposure
  'CRED-001': 'RETROACTIVE-PRIV',
  'CRED-002': 'RETROACTIVE-PRIV',
  'CRED-003': 'RETROACTIVE-PRIV',
  'CRED-004': 'RETROACTIVE-PRIV',

  // Unicode steganography
  'UNICODE-STEGO-001': 'UNICODE-STEGO',
  'UNICODE-STEGO-002': 'UNICODE-STEGO',
  'UNICODE-STEGO-003': 'UNICODE-STEGO',
  'UNICODE-STEGO-004': 'UNICODE-STEGO',
  'UNICODE-STEGO-005': 'UNICODE-STEGO',

  // OpenClaw persistence
  'HEARTBEAT-001': 'HEARTBEAT-RCE',
  'HEARTBEAT-002': 'HEARTBEAT-RCE',
  'HEARTBEAT-003': 'HEARTBEAT-RCE',
  'HEARTBEAT-004': 'HEARTBEAT-RCE',
  'HEARTBEAT-005': 'HEARTBEAT-RCE',
  'HEARTBEAT-006': 'HEARTBEAT-RCE',
  'SKILL-002': 'HEARTBEAT-RCE',
  'SKILL-003': 'HEARTBEAT-RCE',

  // Skill exfiltration
  'SKILL-006': 'SKILL-EXFIL',
  'NET-001': 'SKILL-EXFIL',
  'NET-002': 'SKILL-EXFIL',
  'NET-003': 'SKILL-EXFIL',

  // Supply chain
  'SUPPLY-001': 'ORG-SKILL-SPREAD',
  'SUPPLY-002': 'ORG-SKILL-SPREAD',
  'SUPPLY-003': 'ORG-SKILL-SPREAD',
  'SUPPLY-004': 'ORG-SKILL-SPREAD',
  'SUPPLY-005': 'ORG-SKILL-SPREAD',
  'SUPPLY-006': 'ORG-SKILL-SPREAD',
  'SUPPLY-007': 'ORG-SKILL-SPREAD',
  'SUPPLY-008': 'ORG-SKILL-SPREAD',
  'DEP-001': 'ORG-SKILL-SPREAD',
  'DEP-002': 'ORG-SKILL-SPREAD',
  'DEP-003': 'ORG-SKILL-SPREAD',
  'DEP-004': 'ORG-SKILL-SPREAD',

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
  'AIM-001': 'AGENT-IMPERSONATE',
  'AIM-002': 'AGENT-IMPERSONATE',
  'AIM-003': 'AGENT-IMPERSONATE',

  // Agent DNA forgery
  'DNA-001': 'BEHAVIORAL-IMPERSONATE',
  'DNA-002': 'BEHAVIORAL-IMPERSONATE',
  'DNA-003': 'BEHAVIORAL-IMPERSONATE',

  // Skill memory
  'SKILL-MEM-001': 'SKILL-MEM-AMP',

  // Adversarial skill / frontmatter injection
  'ASKILL-002': 'SKILL-FRONTMATTER',
  'SKILL-001': 'SKILL-FRONTMATTER',
  'SKILL-004': 'SKILL-FRONTMATTER',
  'SKILL-005': 'SKILL-FRONTMATTER',
  'SKILL-007': 'SKILL-FRONTMATTER',
  'SKILL-008': 'SKILL-FRONTMATTER',
  'SKILL-009': 'SKILL-FRONTMATTER',
  'SKILL-010': 'SKILL-FRONTMATTER',
  'SKILL-011': 'SKILL-FRONTMATTER',
  'SKILL-012': 'SKILL-FRONTMATTER',
  'SKILL-018': 'SKILL-FRONTMATTER',
  'SKILL-019': 'SKILL-FRONTMATTER',
  'HEARTBEAT-007': 'SKILL-FRONTMATTER',

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

  // NemoClaw sandbox security
  'HMA-NMC-001': 'NEMO-CRED-LEAK',
  'HMA-NMC-002': 'NEMO-CRED-LEAK',
  'HMA-NMC-003': 'NEMO-CRED-LEAK',
  'HMA-NMC-004': 'NEMO-CRED-LEAK',
  'HMA-NMC-005': 'NEMO-CRED-LEAK',
  'HMA-NMC-006': 'NEMO-CRED-LEAK',
  'HMA-NMC-010': 'NEMO-NETWORK-EXPOSE',
  'HMA-NMC-011': 'NEMO-NETWORK-EXPOSE',
  'HMA-NMC-012': 'NEMO-NETWORK-EXPOSE',
  'HMA-NMC-013': 'NEMO-NETWORK-EXPOSE',
  'HMA-NMC-014': 'NEMO-NETWORK-EXPOSE',
  'HMA-NMC-015': 'NEMO-NETWORK-EXPOSE',
  'HMA-NMC-020': 'NEMO-SUPPLY-CHAIN',
  'HMA-NMC-021': 'NEMO-SUPPLY-CHAIN',
  'HMA-NMC-022': 'NEMO-SUPPLY-CHAIN',
  'HMA-NMC-023': 'NEMO-SUPPLY-CHAIN',
  'HMA-NMC-024': 'NEMO-SUPPLY-CHAIN',
  'HMA-NMC-030': 'NEMO-SANDBOX-ESCAPE',
  'HMA-NMC-031': 'NEMO-SANDBOX-ESCAPE',
  'HMA-NMC-032': 'NEMO-SANDBOX-ESCAPE',
  'HMA-NMC-033': 'NEMO-SANDBOX-ESCAPE',
  'HMA-NMC-034': 'NEMO-SANDBOX-ESCAPE',
  'HMA-NMC-040': 'NEMO-OPENCLAW-INHERIT',
  'HMA-NMC-041': 'NEMO-OPENCLAW-INHERIT',
  'HMA-NMC-042': 'NEMO-OPENCLAW-INHERIT',
  'HMA-NMC-050': 'NEMO-NETWORK-EXPOSE',
  'HMA-NMC-051': 'NEMO-NETWORK-EXPOSE',
  'HMA-NMC-052': 'NEMO-NETWORK-EXPOSE',

  // AI infrastructure exposure (research gap coverage)
  'LLM-001': 'LLM-EXPOSE',
  'LLM-002': 'LLM-EXPOSE',
  'LLM-003': 'LLM-EXPOSE',
  'LLM-004': 'LLM-EXPOSE',
  'AITOOL-001': 'AITOOL-EXPOSE',
  'AITOOL-002': 'AITOOL-EXPOSE',
  'AITOOL-003': 'AITOOL-EXPOSE',
  'AITOOL-004': 'AITOOL-EXPOSE',
  'A2A-001': 'A2A-EXPOSE',
  'A2A-002': 'A2A-EXPOSE',
  'MCP-011': 'MCP-EXPLOIT',
  'WEBCRED-001': 'RETROACTIVE-PRIV',

  // Code injection, supply chain, operational security
  // CODEINJ-001 removed — deduplicated with NEMO-005
  'INSTALL-001': 'SUPPLY-CHAIN-INSTALL',
  'CLIPASS-001': 'RETROACTIVE-PRIV',
  'INTEGRITY-001': 'INTEGRITY-BYPASS',
  'TOCTOU-001': 'TOCTOU-RACE',
  // TMPPATH-001 removed — deduplicated with NEMO-006
  'DOCKERINJ-001': 'CODE-INJECTION',
  // ENVLEAK-001 removed — deduplicated with NEMO-007
  'SANDBOX-005': 'SANDBOX-ESCAPE',
  'WEBEXPOSE-001': 'RETROACTIVE-PRIV',
  'WEBEXPOSE-002': 'RETROACTIVE-PRIV',
  'WEBEXPOSE-003': 'RETROACTIVE-PRIV',
  'SOUL-OVERRIDE-001': 'SOUL-INJECT',
  'MEM-006': 'MEM-POISON',
  'AGENT-CRED-001': 'RETROACTIVE-PRIV',

  // NemoClaw novel threat checks (NEMO-00x series)
  'NEMO-001': 'NEMO-SUPPLY-CHAIN',
  'NEMO-002': 'NEMO-SUPPLY-CHAIN',
  'NEMO-003': 'NEMO-SANDBOX-ESCAPE',
  'NEMO-004': 'NEMO-CRED-LEAK',
  'NEMO-005': 'NEMO-SANDBOX-ESCAPE',
  'NEMO-006': 'NEMO-SANDBOX-ESCAPE',
  'NEMO-007': 'NEMO-CRED-LEAK',
  'NEMO-008': 'NEMO-SANDBOX-ESCAPE',
  'NEMO-009': 'NEMO-SUPPLY-CHAIN',
  'NEMO-010': 'NEMO-OPENCLAW-INHERIT',

  // Parser differential checks (Session 18)
  'PARSE-001': 'PARSER-DIFFERENTIAL',
  'PARSE-002': 'PARSER-DIFFERENTIAL',
  'PARSE-003': 'PARSER-DIFFERENTIAL',
  'PARSE-004': 'PARSER-DIFFERENTIAL',
  'PARSE-005': 'PARSER-DIFFERENTIAL',
  'PARSE-006': 'PARSER-DIFFERENTIAL',
  'PARSE-007': 'PARSER-DIFFERENTIAL',
  'PARSE-008': 'PARSER-DIFFERENTIAL',
  'PARSE-009': 'PARSER-DIFFERENTIAL',
  'PARSE-010': 'PARSER-DIFFERENTIAL',

  // Persistent agent state checks (Session 18)
  'PERSIST-001': 'PERSIST-STATE',
  'PERSIST-002': 'PERSIST-STATE',
  'PERSIST-003': 'PERSIST-STATE',
  'PERSIST-004': 'PERSIST-STATE',
  'PERSIST-005': 'PERSIST-STATE',
  'PERSIST-006': 'PERSIST-STATE',
  'PERSIST-007': 'PERSIST-STATE',
  'PERSIST-008': 'PERSIST-STATE',
  'PERSIST-009': 'PERSIST-STATE',
  'PERSIST-010': 'PERSIST-STATE',

  // Fake tool injection checks (Session 18)
  'FAKETOOL-001': 'FAKETOOL-INJECT',
  'FAKETOOL-002': 'FAKETOOL-INJECT',
  'FAKETOOL-003': 'FAKETOOL-INJECT',
  'FAKETOOL-004': 'FAKETOOL-INJECT',
  'FAKETOOL-005': 'FAKETOOL-INJECT',
  'FAKETOOL-006': 'FAKETOOL-INJECT',
  'FAKETOOL-007': 'FAKETOOL-INJECT',
  'FAKETOOL-008': 'FAKETOOL-INJECT',
  'FAKETOOL-009': 'FAKETOOL-INJECT',
  'FAKETOOL-010': 'FAKETOOL-INJECT',

  // Context lifecycle assembly checks (Session 20)
  'LIFECYCLE-001': 'ASSEMBLY-INJECT',
  'LIFECYCLE-002': 'ASSEMBLY-INJECT',
  'LIFECYCLE-003': 'ASSEMBLY-INJECT',
  'LIFECYCLE-004': 'ASSEMBLY-INJECT',
  'LIFECYCLE-005': 'ASSEMBLY-INJECT',
  'LIFECYCLE-006': 'ASSEMBLY-INJECT',
  'LIFECYCLE-007': 'ASSEMBLY-INJECT',
  'LIFECYCLE-008': 'ASSEMBLY-INJECT',
  'LIFECYCLE-009': 'ASSEMBLY-INJECT',
  'LIFECYCLE-010': 'ASSEMBLY-INJECT',
};

/**
 * Default severity by check ID prefix. Based on the security impact
 * of each category. Individual checks may override via SEVERITY_OVERRIDES.
 */
const PREFIX_SEVERITY: Record<string, string> = {
  CRED: 'critical',
  WEBCRED: 'critical',
  LLM: 'critical',
  AITOOL: 'critical',
  DEP: 'critical',
  GATEWAY: 'critical',
  HEARTBEAT: 'critical',
  FAKETOOL: 'critical',
  DOCKERINJ: 'critical',
  TOCTOU: 'critical',
  SANDBOX: 'critical',
  INSTALL: 'critical',
  INTEGRITY: 'critical',
  CLIPASS: 'critical',
  PERSIST: 'high',
  MEM: 'high',
  SOUL: 'high',
  SKILL: 'high',
  MCP: 'high',
  PROMPT: 'high',
  SUPPLY: 'high',
  LIFECYCLE: 'high',
  A2A: 'high',
  AIM: 'high',
  NET: 'high',
  GIT: 'high',
  AGENT: 'high',
  RAG: 'high',
  ASKILL: 'high',
  HMA: 'medium',
  NEMO: 'medium',
  PARSE: 'medium',
  UNICODE: 'medium',
  DNA: 'medium',
  WEBEXPOSE: 'medium',
};

/** Per-check severity overrides where the default prefix doesn't apply. */
const SEVERITY_OVERRIDES: Record<string, string> = {
  'HEARTBEAT-006': 'medium',
  'SKILL-005': 'medium',
  'SKILL-018': 'medium',
  'SUPPLY-002': 'medium',
  'SEM-MCP-006': 'low',
};

/**
 * Look up the default severity for a check ID.
 * Returns 'medium' if no mapping exists.
 */
export function getCheckSeverity(checkId: string): string {
  if (SEVERITY_OVERRIDES[checkId]) return SEVERITY_OVERRIDES[checkId];
  // Try progressively shorter prefixes: SEM-CRED -> SEM, SOUL-TH -> SOUL
  const parts = checkId.replace(/-\d+$/, '').split('-');
  for (let i = parts.length; i > 0; i--) {
    const prefix = parts.slice(0, i).join('-');
    if (PREFIX_SEVERITY[prefix]) return PREFIX_SEVERITY[prefix];
  }
  return 'medium';
}

/**
 * Look up the attack class for a given HMA check ID.
 * Returns undefined if no mapping exists.
 */
export function getAttackClass(checkId: string): string | undefined {
  return TAXONOMY_MAP[checkId];
}

/** Return a copy of the full taxonomy map (checkId -> attackClass). */
export function getTaxonomyMap(): Record<string, string> {
  return { ...TAXONOMY_MAP };
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

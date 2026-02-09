/**
 * OASB Upgrader
 *
 * Maps semantic check IDs to OASB benchmark controls.
 * When semantic checks are active, these IDs are added to the controls'
 * checkIds arrays, improving benchmark coverage.
 */

/**
 * Mapping from OASB control ID → semantic check IDs that verify it.
 */
export const SEMANTIC_OASB_MAPPINGS: Record<string, string[]> = {
  // 2.1 Explicit Capability Grants
  // Structural analysis checks MCP configs for capability manifests
  '2.1': ['SEM-MCP-001', 'SEM-MCP-004'],

  // 3.1 Prompt Injection Protection
  // Instruction analysis checks for injection defenses and permissive rules
  '3.1': ['SEM-INST-001', 'SEM-INST-003'],

  // 4.3 Data Exfiltration Prevention
  // MCP analysis reasons about tool permissions + exfiltration paths
  '4.3': ['SEM-MCP-005', 'SEM-INST-002'],

  // 5.1 No Hardcoded Credentials
  // Context-aware detection catches credentials regex misses
  '5.1': ['SEM-CRED-001', 'SEM-CRED-002', 'SEM-CRED-003', 'SEM-CRED-004'],

  // 5.2 Credential Rotation (structural detection of static credentials)
  '5.2': ['SEM-CRED-002'],

  // 2.2 Least Privilege Principle
  // Permission model + MCP scope analysis
  '2.2': ['SEM-PERM-001', 'SEM-PERM-002', 'SEM-MCP-001'],
};

/**
 * Get all semantic check IDs for a given OASB control.
 */
export function getSemanticCheckIds(controlId: string): string[] {
  return SEMANTIC_OASB_MAPPINGS[controlId] || [];
}

/**
 * Get all OASB control IDs that have semantic mappings.
 */
export function getUpgradedControlIds(): string[] {
  return Object.keys(SEMANTIC_OASB_MAPPINGS);
}

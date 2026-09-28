/**
 * OASB Upgrader
 *
 * Maps OASB-1 controls to the semantic check IDs that verify them.
 *
 * Documentation, not configuration (#645). The assessor reads the catalogue in
 * `src/benchmarks/oasb-1.ts`, where these mappings were folded into each
 * control's `checkIds`; nothing in the tool reads this map. It is kept because
 * it is library API, and it may only restate the catalogue: every entry must be
 * a subset of that control's `checkIds`, which
 * `__tests__/semantic/oasb-upgrader-catalogue-subset.test.ts` holds.
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

  // 5.2 Credential Rotation carries no semantic check: the catalogue verifies
  // it with MCP-006 and MCP-009. The `'5.2': ['SEM-CRED-002']` entry this map
  // used to hold was never read by the assessor and disagreed with it (#645).

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

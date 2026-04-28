/**
 * Finding tier ranker for `── Findings ──` rendering order.
 *
 * Closes opena2a-org/hackmyagent#134.
 *
 * Numeric severity alone made benign hygiene-only skills (3 hygiene HIGHs)
 * read identical at first glance to buggy capability-sprawl skills (3 hygiene
 * HIGHs + governance/jailbreak HIGHs). Re-rank by an attack-class tier first,
 * then by severity inside each tier.
 *
 *   1  Active malice            credential harvest, exfil, RCE, observed injection
 *   2  Capability / governance  capability sprawl, governance violations, jailbreak
 *   3  Missing-defense-in-depth no injection resistance, no trust hierarchy
 *   4  Hygiene                  incomplete frontmatter, unverified publisher, no hash
 *   5  Project-level            .gitignore, project chrome
 *
 * Resolution order: explicit `checkId` overrides for known absence-findings >
 * `attackClass` set membership > `checkId` prefix fallback > `category` >
 * tier 5 default.
 *
 * Why explicit overrides come first: several `attackClass` values are
 * overloaded between "we OBSERVED this attack pattern" (tier 1) and "the
 * artifact LACKS defense against this attack pattern" (tier 3). For example
 * `AST-PROMPT-003` "Missing Injection Resistance" emits `PROMPT-INJECT`, the
 * same attackClass that fires when a malicious skill literally contains
 * `IGNORE PRIOR INSTRUCTIONS`. Without the override, the absence-finding
 * would falsely tier-1.
 *
 * Coverage contract: every `attackClass` string emitted in this codebase
 * must tier ≤ 4. The test suite at `__tests__/ui/finding-tier-coverage.test.ts`
 * walks `getTaxonomyMap()` plus the TME classifier `CLASSES` constant and
 * fails if any value lands in tier 5. New analyzers MUST update the tier
 * sets when they introduce a new `attackClass` literal.
 */

export type FindingTier = 1 | 2 | 3 | 4 | 5;

export interface TierableFinding {
  checkId?: string;
  attackClass?: string;
  category?: string;
}

/**
 * checkIds whose semantics are "missing defense" (tier 3) regardless of the
 * (overloaded) attackClass they happen to emit.
 */
const TIER_3_CHECK_IDS = new Set<string>([
  'AST-PROMPT-003', // Missing Injection Resistance — emits PROMPT-INJECT
  'AST-PROMPT-004', // No Trust Hierarchy — emits AUTHORITY-CONFUSION
  'AST-PROMPT-005', // Override Resistance Gap — emits AUTHORITY-CONFUSION
  'SOUL-COMPLETENESS',
  'SOUL-CONSENT',
  'SOUL-UNVERIFIABLE-CLAIM',
]);

/**
 * checkIds whose semantics are "governance violation" (tier 2) regardless of
 * the attackClass they emit. AST-GOV-001 carries SOUL-GAP, AST-GOV-003 carries
 * SOUL-MISSING — both are genuine governance violations per the #134 spec.
 */
const TIER_2_CHECK_IDS = new Set<string>([
  'AST-GOV-001', // Critical Governance Domain Gap
  'AST-GOV-002',
  'AST-GOV-003', // No Governance Constraints
  'SOUL-OVERRIDE-001',
  'PERM-001',
  'PERM-002',
  'PERM-003',
  'MCP-TOOLS',
  'WEBEXPOSE-001',
  'WEBEXPOSE-002',
  'WEBEXPOSE-003',
]);

/**
 * Active-malice attackClasses. Stored in canonical form (UPPERCASE, dashes —
 * not underscores). The TME classifier emits lowercase / snake_case; lookups
 * normalize to this form before set membership.
 */
const TIER_1_ATTACK_CLASSES = new Set<string>([
  // Credential exposure / theft
  'CRED-HARVEST',
  'CRED-EXFIL',
  'CRED-EXPOSURE',
  'CRED-HARDCODED',
  'CRED-PERSIST',
  'CREDENTIAL-ABUSE', // TME class
  'NEMO-CRED-LEAK',
  'RETROACTIVE-PRIV', // CRED-001..004 + AGENT-CRED-001 in taxonomy
  'MCP-CRED',
  'MCP-CHAIN-EXFIL',
  // Data theft / exfiltration
  'DATA-EXFIL',
  'DATA-LEAK',
  'SKILL-EXFIL',
  'EXFILTRATION', // TME class
  'NEMO-NETWORK-EXPOSE',
  // Remote code / command execution
  'HEARTBEAT-RCE',
  'CMD-INJECT',
  'CODE-INJECTION',
  'INJECTION', // TME class
  // Observed prompt injection (the artifact contains injection content) —
  // tier 3 checkId overrides above prevent absence-findings from landing here.
  'PROMPT-INJECT',
  // Persistence / memory tampering
  'MEM-POISON',
  'PERSISTENCE', // also TME class
  'PERSIST-STATE',
  // Auth/path/priv attacks
  'AUTH-BYPASS',
  'PATH-TRAVERSAL',
  'PRIV-ESCALATION',
  'PRIVILEGE-ESCALATION', // TME canonical form
  'UNSAFE-DESER',
  // Sandbox escape / container privilege escape (HMA-NMC family)
  'SANDBOX-ESCAPE',
  'NEMO-SANDBOX-ESCAPE',
  'NEMO-OPENCLAW-INHERIT', // privilege inheritance through nemoclaw chains
  // Lateral movement / social engineering (TME categories — active behaviors)
  'LATERAL-MOVEMENT',
  'SOCIAL-ENGINEERING',
  // Steganography / scan evasion (active evasion / hidden malice)
  'UNICODE-STEGO',
  'STEGANOGRAPHY',
  'SCAN-EVASION',
  // Supply-chain malice
  'MCP-TYPOSQUAT',
  'MCP-SUPPLY-CHAIN',
  'NEMO-SUPPLY-CHAIN',
  'SUPPLY-CHAIN-INSTALL',
  // Identity / impersonation attacks
  'AGENT-IMPERSONATE',
  'BEHAVIORAL-IMPERSONATE',
  'SOUL-IMPERSONATE',
  'SOUL-HIJACK',
  'SOUL-INJECT',
  'SOUL-POISON',
  'PHANTOM-SOUL',
  // Active exploits
  'GATEWAY-EXPLOIT',
  'MCP-EXPLOIT',
  'INTEGRITY-BYPASS',
  'TOCTOU-RACE',
  'PARSER-DIFFERENTIAL',
  'FAKETOOL-INJECT',
  'RAG-POISON',
  // Live-tool exposure (LLM key, AI-tool, A2A interface exposed)
  'LLM-EXPOSE',
  'AITOOL-EXPOSE',
  'A2A-EXPOSE',
  // Assembly-injection family (all observed-malice patterns)
  'ASSEMBLY-INJECT',
  'ASSEMBLY-SPLIT',
  'ASSEMBLY-DISPLACE',
  'ASSEMBLY-DELIMITER',
  'ASSEMBLY-DILUTE',
  'ASSEMBLY-HIDDEN',
  'ASSEMBLY-HIJACK',
  'ASSEMBLY-CONFLICT',
  'ASSEMBLY-OVERFLOW',
  'ASSEMBLY-NOSAFETY',
]);

const TIER_2_ATTACK_CLASSES = new Set<string>([
  // Capability scope violations
  'SCOPE-WILDCARD',
  'SCOPE-UNDECLARED',
  'CAPABILITY-CREEP',
  'CAPABILITY-ABUSE',
  'MCP-SCOPE-WILDCARD',
  'MCP-SCOPE-EXPAND',
  'MCP-SCOPE-LEAK',
  'MCP-PRIV-ESC',
  'SKILL-MEM-AMP',
  // Governance violations (the SOUL has gaps in critical domains, or the
  // artifact contradicts/escapes/forks/drifts from its declared SOUL).
  'SOUL-BYPASS',
  'SOUL-ESCAPE-CLAUSE',
  'SOUL-CONTRADICTION',
  'SOUL-UNVERIFIABLE-CLAIM',
  'SOUL-GAP', // critical-domain gap is a governance violation
  'SOUL-MISSING', // entire SOUL absent on a capability-bearing artifact
  'SOUL-DRIFT',
  'SOUL-FORK',
  'SOUL-BOUNDARY',
  'SOUL-DELEGATE',
  // Authority / instruction-hierarchy attacks (jailbreak observed)
  'JAILBREAK',
  'AUTHORITY-CONFUSION', // tier 3 checkId overrides catch absence-findings
  'SEMANTIC-MISMATCH',
  // Network exposure of high-priv surfaces
  'NETWORK-EXPOSURE',
  // Supply-chain pinning/identity gaps
  'SUPPLY-CHAIN',
  // TME policy-violation classification — governance category
  'POLICY-VIOLATION',
]);

const TIER_3_ATTACK_CLASSES = new Set<string>([
  // SOUL defense-in-depth absences
  'SOUL-COMPLETENESS',
  'SOUL-CONSENT',
  // SOUL Harm-Avoidance domain checks (src/soul/scanner.ts) — control gaps
  // in pre-action risk, proportional response, etc. Defense-in-depth absence.
  'SOUL-HV-001',
  'SOUL-HV-002',
  'SOUL-HV-003',
  'SOUL-HV-004',
  // Logging / monitoring gaps
  'MONITORING-GAP',
]);

const TIER_4_ATTACK_CLASSES = new Set<string>([
  // Skill metadata / supply-chain hygiene
  'SKILL-FRONTMATTER',
  'ORG-SKILL-SPREAD',
]);

/**
 * Normalize an attackClass string for set lookup. Uppercase + underscores
 * to dashes. The TME classifier emits `'credential_abuse'`, `'privilege_
 * escalation'`, etc.; deterministic analyzers emit `'CRED-EXFIL'`, etc.
 * Both forms canonicalize to dash-uppercase.
 */
function canonicalAttackClass(ac: string): string {
  return ac.toUpperCase().replace(/_/g, '-');
}

/** Rank a finding into one of 5 tiers. */
export function findingTier(f: TierableFinding): FindingTier {
  const id = f.checkId ?? '';
  const acRaw = f.attackClass ?? '';
  const ac = canonicalAttackClass(acRaw);
  const cat = (f.category ?? '').toLowerCase();

  // Explicit checkId overrides first — these checks have semantics that the
  // generic attackClass set misclassifies.
  if (TIER_2_CHECK_IDS.has(id)) return 2;
  if (TIER_3_CHECK_IDS.has(id)) return 3;

  // attackClass-based tiers (canonicalized).
  if (TIER_1_ATTACK_CLASSES.has(ac)) return 1;
  if (TIER_2_ATTACK_CLASSES.has(ac)) return 2;
  if (TIER_3_ATTACK_CLASSES.has(ac)) return 3;
  if (TIER_4_ATTACK_CLASSES.has(ac)) return 4;

  // checkId fallback for findings that don't yet carry attackClass (issue #138).
  if (
    id.startsWith('AST-CRED-') ||
    id.startsWith('CRED-') ||
    id === 'SKILL-003' || // Heartbeat Installation
    id === 'SKILL-022' || // Environment Variable Exfiltration Risk
    id === 'AGENT-CRED-001'
  ) {
    return 1;
  }

  if (id.startsWith('AST-GOV-') || id.startsWith('AST-SCOPE-') || id.startsWith('SOUL-OVERRIDE')) {
    return 2;
  }

  if (id.startsWith('AST-PROMPT-')) {
    return 3;
  }

  if (
    id === 'SKILL-001' || // Unsigned Skill
    id === 'SKILL-002' ||
    id === 'SKILL-020' || // Incomplete Frontmatter
    id.startsWith('SUPPLY-') || // Unverified Publisher, Version Drift, Skill Not in Registry
    cat === 'supply' ||
    cat === 'metadata' ||
    cat === 'frontmatter'
  ) {
    return 4;
  }

  // Project-level chrome (.gitignore, dep listing, project structure).
  return 5;
}

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/**
 * Sort comparator: tier ascending (1 = most urgent), then severity descending
 * (critical first). Sort stability is provided by the runtime
 * (`Array.prototype.sort` is stable in ES2019+ / Node 24).
 */
export function compareFindingsByTier(
  a: TierableFinding & { severity?: string },
  b: TierableFinding & { severity?: string },
): number {
  const tierDelta = findingTier(a) - findingTier(b);
  if (tierDelta !== 0) return tierDelta;
  const sa = SEVERITY_WEIGHT[a.severity ?? ''] ?? 0;
  const sb = SEVERITY_WEIGHT[b.severity ?? ''] ?? 0;
  return sb - sa;
}

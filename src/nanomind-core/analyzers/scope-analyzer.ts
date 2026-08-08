/**
 * Scope Analyzer -- AST-based AST-SCOPE-* checks
 *
 * Queries the SecurityAST for MCP tool scope mismatches and A2A exposure.
 * Compares declared capabilities against inferred capabilities to detect
 * wildcard access, undeclared permissions, and scope-purpose mismatches.
 *
 * Checks:
 *   AST-SCOPE-001: Wildcard tool access in MCP configurations
 *   AST-SCOPE-002: Undeclared tool permissions (inferred but not declared)
 *   AST-SCOPE-003: Scope-purpose mismatch (capabilities inconsistent with purpose)
 */

import type { SecurityAST, Capability } from '../types.js';
import type { ASTFinding } from './capability-analyzer.js';
import type { ProjectType } from '../../hardening/security-check.js';
import { assertASTIntegrity } from '../security/defense-in-depth.js';
import { findLineFromString } from '../../types/text-position.js';

// ============================================================================
// Public API
// ============================================================================

/**
 * Analyze a SecurityAST for scope and permission issues.
 * Verifies AST integrity before processing.
 *
 * `artifactContent` is the raw source text the AST was compiled from. It
 * is unsigned and not part of the AST contract — callers pass it through
 * so emit sites can derive 1-based line numbers from substring offsets
 * (issue #147, extending #141). When omitted, findings still emit but
 * without a `line` field; `generateVerifyCommand()` will then return
 * undefined for them.
 */
export function analyzeScope(
  ast: SecurityAST,
  verifier: (ast: SecurityAST) => boolean,
  projectType?: ProjectType,
  artifactContent?: string,
): ASTFinding[] {
  assertASTIntegrity(ast, verifier);

  // SDKs and libraries don't declare tool access, permissions, or purpose
  // in the OASB sense. Scope checks only apply to agents.
  if (projectType === 'sdk' || projectType === 'library') {
    return [];
  }

  const findings: ASTFinding[] = [];

  findings.push(...checkWildcardToolAccess(ast, artifactContent));
  findings.push(...checkUndeclaredPermissions(ast, artifactContent));
  findings.push(...checkScopePurposeMismatch(ast, artifactContent));
  findings.push(...checkAdversarialConfigDirectives(ast, artifactContent));

  return findings;
}

// ============================================================================
// AST-SCOPE-001: Wildcard tool access
// ============================================================================

/**
 * Detects wildcard ("*") tool access in MCP configurations and agent configs.
 * Wildcard access grants the agent unlimited tool permissions, which is
 * the MCP equivalent of running as root.
 *
 * Also detects partial wildcards (e.g., "db.*") that grant broad access
 * within a domain.
 */
function checkWildcardToolAccess(ast: SecurityAST, artifactContent?: string): ASTFinding[] {
  const findings: ASTFinding[] = [];

  // Full wildcards: capabilities with "*" in the name
  const fullWildcards = ast.declaredCapabilities.filter(c => c.name.includes('*'));

  for (const cap of fullWildcards) {
    const isFullWildcard = cap.name.endsWith('.*') || cap.name === '*';
    const scope = cap.scope || 'all tools';

    findings.push({
      checkId: 'AST-SCOPE-001',
      name: isFullWildcard ? 'Full Wildcard Tool Access' : 'Partial Wildcard Tool Access',
      description: isFullWildcard
        ? `Wildcard capability "${cap.name}" grants unrestricted access to ${scope}. ` +
          'This is the MCP equivalent of running as root. Any tool in the server can be ' +
          'invoked, including dangerous operations like file deletion or code execution.'
        : `Partial wildcard "${cap.name}" grants broad access within ${scope}. ` +
          'While scoped to a domain, this still allows access to every tool in that domain ' +
          'including tools not needed for the declared purpose.',
      category: 'Scope Security',
      severity: isFullWildcard ? 'critical' : 'high',
      passed: false,
      message: `Wildcard access: ${cap.name} (scope: ${scope})`,
      fixable: false,
      file: ast.artifactPath,
      // Prefer the rich evidence span (e.g. JSON value with quotes) over the
      // bare capability name "*" — the latter is too short and could match
      // an unrelated occurrence in surrounding text.
      line: findLineFromString(artifactContent, cap.evidence),
      fix: isFullWildcard
        ? `Replace the wildcard "*" with an explicit allowlist in mcp.json — ` +
          `change "allowedTools": ["*"] to "allowedTools": ["tool1", "tool2"]. ` +
          'Run `opena2a mcp audit` to inventory tools first, then keep only what the agent needs.'
        : `Replace partial wildcard "${cap.name}" with specific tool names. ` +
          `List only the ${cap.name.split('.')[0]} tools the agent actually uses. ` +
          'Run `opena2a mcp audit` to see available tools.',
      guidance:
        'Principle of least privilege: grant only the minimum permissions needed. ' +
        'Wildcard access means a prompt injection attack can invoke any tool.',
      attackClass: 'SCOPE-WILDCARD',
      confidence: 0.95,
    });
  }

  // #449 — there is deliberately NO finding for a server that simply omits its
  // tool declaration.
  //
  // An "Implicit Wildcard MCP Access" HIGH used to sit here, gated on
  // `fullWildcards.length === 0`. It was unreachable: the compiler synthesized
  // `['*']` for exactly the configs it targeted, so `fullWildcards` was never
  // empty and the branch could not run. What users actually got was the
  // CRITICAL above, asserting a wildcard the file did not contain.
  //
  // It is not restored now that the compiler no longer synthesizes, because
  // omitting the key is the MCP ecosystem default — Sentry's official server
  // omits it — and a check that fires on the default has no discriminating
  // power. That is the defect this issue is about: benign and malicious corpus
  // fixtures both scored exactly 69/100. A CRITICAL whose output does not vary
  // with its input is a constant, not a measurement.
  //
  // The real risk in an unrestricted server is what the server can DO, and
  // that is measured where the evidence is: dangerous command and argument
  // detection, and the credential checks. The malicious fixture stays caught by
  // those on its own evidence, which is the point — this check now reports only
  // a wildcard that is really written in the file, at the line that really
  // holds it.
  //
  // KNOWN GAP, measured rather than assumed (#470). Those carriers do
  // NOT cover one shape: a server that declares no tool key AND whose own
  // arguments grant an unbounded filesystem root (`/`, `~`, `/Users`), with no
  // credential and no dangerous command in the file. `check` scores such a
  // config 96/100 "Usable with caveats", exit 0; the pre-#449 build scored it
  // 69 off the fabricated wildcard. This change makes that one case worse, and
  // it is disclosed in the CHANGELOG rather than left for a user to discover.
  //
  // It is deliberately not patched here by re-grading the capability 'high'.
  // That was built and measured: it restores the score, but the finding it
  // routes through is the purpose-mismatch analyzer, which reports
  // `"mcp.filesystem" does not match purpose ""args": ["-y", "@modelcontext…"`
  // — the "purpose" being a JSON fragment scraped from the config. Trading a
  // fabricated CRITICAL for an incoherent HIGH is the same defect in a new
  // costume. The correct fix is a check that says what it means, against a
  // corpus that can support it; today the corpus holds 2 real fixtures of this
  // shape and the signature bar is 3.

  return findings;
}

// ============================================================================
// AST-SCOPE-002: Undeclared tool permissions
// ============================================================================

/**
 * Detects capabilities that NanoMind inferred from the artifact content
 * but that were not explicitly declared. Undeclared permissions mean the
 * agent can do more than its manifest claims.
 *
 * This is the scope-specific version of AST-CAP-001 (undeclared capabilities).
 * While CAP-001 flags any undeclared capability, SCOPE-002 focuses on
 * tool permissions and access patterns.
 */
function checkUndeclaredPermissions(ast: SecurityAST, artifactContent?: string): ASTFinding[] {
  const findings: ASTFinding[] = [];

  // Build list of declared capability names (normalized)
  const declaredNamesList = ast.declaredCapabilities.map(c => normalizeCapName(c.name));

  // Find inferred capabilities not covered by declarations
  const undeclaredInferred = ast.inferredCapabilities.filter(c => {
    const normalized = normalizeCapName(c.name);
    // Check exact match
    if (declaredNamesList.includes(normalized)) return false;
    // Check if covered by a broader declared capability (e.g., "db.*" covers "db.read")
    for (const declared of declaredNamesList) {
      if (declared.endsWith('.*') && normalized.startsWith(declared.slice(0, -1))) {
        return false;
      }
    }
    return true;
  });

  for (const cap of undeclaredInferred) {
    const severity = cap.riskLevel === 'critical'
      ? 'critical'
      : cap.riskLevel === 'high'
        ? 'high'
        : 'medium';

    findings.push({
      checkId: 'AST-SCOPE-002',
      name: 'Undeclared Tool Permission',
      description:
        `Tool permission "${cap.name}" (scope: ${cap.scope || 'unscoped'}) was inferred ` +
        'from artifact content but is not declared in the capability manifest. ' +
        'The artifact exercises permissions beyond its declared scope.',
      category: 'Scope Security',
      severity,
      passed: false,
      message: `Undeclared permission: ${cap.name} (${cap.riskLevel}-risk)`,
      fixable: false,
      file: ast.artifactPath,
      line: findLineFromString(artifactContent, cap.evidence),
      fix:
        `Either declare "${cap.name}" in your capability manifest (if intended) ` +
        'or remove the code/instructions that exercise this permission. ' +
        'If declared, add a governance constraint for this capability.',
      guidance:
        'Every tool permission must be explicitly declared. Undeclared permissions are a ' +
        'supply chain risk: users and orchestrators cannot audit what the agent actually does.',
      attackClass: 'SCOPE-UNDECLARED',
      confidence: ast.intentConfidence,
      evidence: cap.evidence,
    });
  }

  return findings;
}

// ============================================================================
// AST-SCOPE-003: Scope-purpose mismatch
// ============================================================================

/**
 * Detects capabilities that are inconsistent with the artifact's declared
 * purpose. A "weather lookup" agent with file.delete capabilities is
 * suspicious regardless of whether the capability is declared.
 *
 * Uses semantic comparison between the declared purpose and each capability,
 * considering both declared and inferred capabilities.
 */
function checkScopePurposeMismatch(ast: SecurityAST, artifactContent?: string): ASTFinding[] {
  const findings: ASTFinding[] = [];

  const purpose = ast.declaredPurpose.toLowerCase();

  // Skip if purpose is generic / unknown
  if (
    purpose === 'unknown purpose' ||
    purpose.length < 10 ||
    purpose.includes('does whatever') ||
    purpose.includes('general purpose')
  ) {
    return findings;
  }

  // Extract purpose domain keywords
  const purposeKeywords = extractPurposeKeywords(purpose);

  if (purposeKeywords.size < 2) {
    return findings; // Not enough context to judge mismatch
  }

  // Check all capabilities (declared + inferred) for relevance to purpose
  const allCaps = [...ast.declaredCapabilities, ...ast.inferredCapabilities];

  // Deduplicate by name
  const seen = new Set<string>();
  const uniqueCaps: Capability[] = [];
  for (const cap of allCaps) {
    if (!seen.has(cap.name)) {
      seen.add(cap.name);
      uniqueCaps.push(cap);
    }
  }

  for (const cap of uniqueCaps) {
    // Only flag high/critical risk mismatches
    if (cap.riskLevel !== 'high' && cap.riskLevel !== 'critical') {
      continue;
    }

    const capKeywords = extractCapabilityKeywords(cap.name, cap.scope);
    const overlap = setIntersection(purposeKeywords, capKeywords);

    // If zero overlap between purpose and capability keywords, it's a mismatch
    if (overlap.size === 0 && capKeywords.size > 0) {
      findings.push({
        checkId: 'AST-SCOPE-003',
        name: 'Scope-Purpose Mismatch',
        description:
          `${cap.riskLevel}-risk capability "${cap.name}" (scope: ${cap.scope || 'unscoped'}) ` +
          `does not align with declared purpose: "${truncate(ast.declaredPurpose, 100)}". ` +
          'This could indicate a trojan capability hidden in an otherwise legitimate agent.',
        category: 'Scope Security',
        severity: cap.riskLevel === 'critical' ? 'critical' : 'high',
        passed: false,
        message: `"${cap.name}" does not match purpose "${truncate(ast.declaredPurpose, 50)}"`,
        fixable: false,
        file: ast.artifactPath,
        line: findLineFromString(artifactContent, cap.evidence),
        fix:
          `Either update the purpose description to explain why "${cap.name}" is needed, ` +
          `or remove this capability if it is not required. ` +
          'A clear purpose statement helps users and scanners trust the agent.',
        guidance:
          'Scope-purpose mismatches are a red flag for trojan agents that hide malicious ' +
          'capabilities behind a benign-sounding purpose. Even if the capability is legitimate, ' +
          'the purpose should explain why it is needed.',
        attackClass: 'SEMANTIC-MISMATCH',
        confidence: 0.65,
        evidence: cap.evidence,
      });
    }
  }

  return findings;
}

// ============================================================================
// AST-SCOPE-004: Adversarial configuration directives
// ============================================================================

/**
 * Detects explicit adversarial directives in agent_config / mcp_config
 * artifacts: configuration flags that disable a security control, escalate
 * privilege, evade audit/detection, or harvest credentials.
 *
 * Unlike AST-SCOPE-001 (which keys on a "*" wildcard) and AST-SCOPE-003
 * (which compares capability names against the declared purpose), this check
 * inspects the raw config structure for key/value pairs whose meaning is the
 * attack itself. A key named `allowEscalation`, `bypassRBAC`, `disableLogging`,
 * `HIDDEN_FROM_AUDIT`, or `COLLECT_PASSWORDS` set to a truthy value expresses
 * intent to defeat a control — these are not dual-use. The directive families
 * below were validated against the OASB benign corpus (190 samples incl. 40
 * hard-negative edge cases) with zero matches, so they do not raise benign FPR.
 *
 * Self-escalation and access-control bypass were previously invisible to the
 * structural analyzers: the compiler emitted no capabilities for a JSON
 * agent_config whose escalation lived in nested booleans (e.g. MAL-PRIV-007's
 * `permissions.allowEscalation: true`) rather than in a "*" capability.
 *
 * Only runs for agent_config and mcp_config — skill / soul / system_prompt are
 * natural-language artifacts where these patterns belong to the prompt analyzer
 * and the NanoMind semantic layer, not a structural key scan.
 *
 * Coverage limitation: the key scan requires JSON. A YAML agent config (rare in
 * practice — agent configs and MCP configs are JSON) is classified by path but
 * fails JSON.parse and returns no AST-SCOPE-004 findings. This is an additive
 * check; the limitation narrows coverage, it does not weaken any existing check.
 * Extending to YAML is a follow-up.
 */

interface DirectiveFamily {
  /** Match against a separator-stripped, lowercased config key. */
  keyPattern: RegExp;
  name: string;
  severity: 'critical' | 'high';
  attackClass: string;
  guidance: string;
}

// Families are ordered most-specific-attack first; the first family a key
// matches wins, so a key is attributed to a single attack class.
// IMPORTANT: every pattern here must be UNAMBIGUOUS — a key that has no
// legitimate meaning in a benign configuration. Dual-use IAM / cloud / perf
// keys are deliberately EXCLUDED to avoid false positives on real agent
// configs: `assumeRole` (AWS STS), `impersonate*` (GCP domain-wide delegation),
// `crossTenant*` / `crossAccountAccess` (multi-tenant SaaS, AWS cross-account),
// `grantAll*`, `bypassValidation` (CDN / schema toggles), `disableLogging`
// (a routine perf/debug flag), and `includeSecrets` / `includeCredentials`
// (build-artifact bundling) are NOT matched. The malicious corpus samples that
// carry those keys also carry an unambiguous directive below, so coverage is
// preserved without the FP surface. Do not re-add a dual-use key here.
const DIRECTIVE_FAMILIES: DirectiveFamily[] = [
  {
    // Self-escalation: an agent asking to raise its own privilege.
    keyPattern:
      /(allow|auto).*escalat|privilegeescalation|escalationtarget|allowscopeexpansion/,
    name: 'Self-Escalation Directive',
    severity: 'critical',
    attackClass: 'PRIV-ESCALATION',
    guidance:
      'An agent that can escalate its own privilege defeats the principle of least privilege. ' +
      'Escalation must be externally granted and audited, never self-asserted by configuration.',
  },
  {
    // Explicit bypass of a named access-control gate.
    keyPattern:
      /bypass(auth|rbac|rls|rowlevelsecurity|approval|tenantisolation|columnencryption|datamasking|scopevalidation|changemanagement|securitychecks|immutability)|authenticationbypass|allowsecurityoverrides|allowsystemoverrides|disablequeryrestrictions/,
    name: 'Security-Control Bypass Directive',
    severity: 'critical',
    attackClass: 'PRIV-ESCALATION',
    guidance:
      'Disabling authentication, RBAC, row-level security, tenant isolation, or approval gates removes the ' +
      'controls that contain a compromised agent. These flags should not exist in a production configuration.',
  },
  {
    // Audit / detection evasion and covert persistence.
    keyPattern:
      /hiddenfromaudit|hidefromdiff|modifyauditlogs|deleteauditentries|disableaudit|survivereset|surviveclear|persistacrossclones|injectintoallsessions|maintainpersistence/,
    name: 'Audit-Evasion / Covert-Persistence Directive',
    severity: 'high',
    attackClass: 'PERSIST',
    guidance:
      'Hiding from audit logs, surviving session resets, or re-injecting across clones lets an agent persist ' +
      'and operate without oversight. Persistence and logging must be controlled by the platform, not the agent config.',
  },
  {
    // Credential / secret harvesting switches.
    keyPattern:
      /collectpasswords|collectcredentials|collectprivatekeys|collectmfa|readproductionsecrets|copydatabasewithcredentials|harvestcredentials/,
    name: 'Credential-Harvesting Directive',
    severity: 'high',
    attackClass: 'CRED-HARVEST',
    guidance:
      'A configuration that collects passwords, MFA codes, private keys, or production secrets is exfiltrating ' +
      'credentials regardless of the pretext. No legitimate agent needs to gather user or production secrets.',
  },
];

// Privileged role/scope literals that escalate even when assigned as a value
// rather than toggled by a boolean (e.g. "defaultRole": "superuser").
const PRIVILEGED_ROLE_KEY = /^(default)?role$|defaultclaims/;
const PRIVILEGED_ROLE_VALUE = /\b(superuser|root|postgres|sysadmin)\b/i;

function checkAdversarialConfigDirectives(ast: SecurityAST, artifactContent?: string): ASTFinding[] {
  if (ast.artifactType !== 'agent_config' && ast.artifactType !== 'mcp_config') {
    return [];
  }
  if (!artifactContent) return [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(artifactContent);
  } catch {
    return []; // Not JSON — structural key scan does not apply.
  }

  // Flatten every key to { key, value }, INCLUDING object/array values. MCP env
  // blocks carry directives as string values ("true", "*"); agent configs carry
  // them as booleans; and a directive can be wrapped in a nested object
  // ("allowEscalation": { "enabled": true }) — recording the container key lets
  // isActiveDirectiveValue inspect the subtree so the wrapper does not evade.
  const leaves: Array<{ key: string; value: unknown }> = [];
  const walk = (node: unknown): void => {
    if (node === null || typeof node !== 'object') return;
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      leaves.push({ key, value });
      if (value !== null && typeof value === 'object') walk(value);
    }
  };
  walk(parsed);

  // Group matched directives by family so the artifact emits at most one
  // finding per attack family (a single config can trip several keys).
  const byFamily = new Map<string, { family: DirectiveFamily; keys: string[] }>();
  const addMatch = (family: DirectiveFamily, key: string) => {
    const entry = byFamily.get(family.name) ?? { family, keys: [] };
    if (!entry.keys.includes(key)) entry.keys.push(key);
    byFamily.set(family.name, entry);
  };

  for (const { key, value } of leaves) {
    const normKey = key.toLowerCase().replace(/[._\-\s]/g, '');
    if (isActiveDirectiveValue(value)) {
      for (const family of DIRECTIVE_FAMILIES) {
        if (family.keyPattern.test(normKey)) {
          addMatch(family, key);
          break;
        }
      }
    }
    // Privileged role assignment by value (string), independent of booleans.
    if (PRIVILEGED_ROLE_KEY.test(normKey) && typeof value === 'string' && PRIVILEGED_ROLE_VALUE.test(value)) {
      addMatch(DIRECTIVE_FAMILIES[0], key); // escalation family
    }
    // DEFAULT_CLAIMS / claims string carrying an embedded sudo/admin grant.
    if (/claims/.test(normKey) && typeof value === 'string' && /"sudo"\s*:\s*true|"scope"\s*:\s*"\*"|"role"\s*:\s*"(admin|root|superuser)"/i.test(value)) {
      addMatch(DIRECTIVE_FAMILIES[0], key);
    }
  }

  const findings: ASTFinding[] = [];
  for (const { family, keys } of byFamily.values()) {
    const evidenceKey = keys[0];
    const evidence = artifactContent.match(new RegExp(`"${escapeRegex(evidenceKey)}"`))?.[0];
    findings.push({
      checkId: 'AST-SCOPE-004',
      name: family.name,
      description:
        `The configuration sets ${keys.length === 1 ? 'directive' : 'directives'} ` +
        `${keys.map(k => `"${k}"`).join(', ')} that ${familyVerb(family.attackClass)}. ` +
        'This is an explicit adversarial directive, not a missing defense — the configuration ' +
        'is asking the agent to defeat a security control.',
      category: 'Scope Security',
      severity: family.severity,
      passed: false,
      message: `${family.name}: ${keys.join(', ')}`,
      fixable: false,
      file: ast.artifactPath,
      line: findLineFromString(artifactContent, evidence),
      fix:
        `Remove ${keys.length === 1 ? 'the' : 'every'} ${keys.map(k => `"${k}"`).join(', ')} ` +
        `${keys.length === 1 ? 'directive' : 'directives'} from the configuration. ` +
        'If a legitimate workflow appears to need it, route the action through an externally-granted, ' +
        'audited capability instead of a self-asserted config flag.',
      guidance: family.guidance,
      attackClass: family.attackClass,
      confidence: 0.95,
      evidence,
    });
  }

  return findings;
}

/**
 * A directive is "active" when its value turns the behavior on. Covers boolean
 * true, the numeric/string truthy forms an attacker might pick to dodge a
 * naive boolean check (1, "on", "y", ...), a non-empty array (e.g.
 * "authenticationBypass": ["/admin/*"]), and a nested object/array whose
 * subtree contains any active value (so wrapping a flag in { enabled: true }
 * does not evade detection).
 */
function isActiveDirectiveValue(value: unknown): boolean {
  if (value === true) return true;
  if (typeof value === 'number') return value === 1;
  if (typeof value === 'string') {
    const v = value.trim().toLowerCase();
    return v === 'true' || v === '*' || v === 'yes' || v === 'y' ||
      v === '1' || v === 'on' || v === 'enabled' || v === 'always';
  }
  if (Array.isArray(value)) {
    return value.length > 0 && (value.every(v => typeof v !== 'object') || value.some(isActiveDirectiveValue));
  }
  if (value !== null && typeof value === 'object') {
    return Object.values(value as Record<string, unknown>).some(isActiveDirectiveValue);
  }
  return false;
}

function familyVerb(attackClass: string): string {
  switch (attackClass) {
    case 'PRIV-ESCALATION':
      return 'escalate the agent\'s privilege or disable an access-control gate';
    case 'PERSIST':
      return 'evade audit logging or covertly persist across resets';
    case 'CRED-HARVEST':
      return 'collect credentials, secrets, or private keys';
    default:
      return 'defeat a security control';
  }
}

// ============================================================================
// Helpers
// ============================================================================

/**
 * Escape regex metacharacters so a literal key can be embedded in a RegExp.
 */
function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Normalize a capability name for comparison.
 * "MCP.github.issues_list" -> "mcp.github.issues_list"
 */
function normalizeCapName(name: string): string {
  return name.toLowerCase().replace(/-/g, '_');
}

/**
 * Extract meaningful keywords from a purpose string.
 * Filters out stop words and short tokens.
 */
function extractPurposeKeywords(purpose: string): Set<string> {
  const stopWords = new Set([
    'the', 'and', 'for', 'with', 'that', 'this', 'from', 'have', 'will',
    'can', 'not', 'are', 'was', 'been', 'being', 'has', 'had', 'does',
    'did', 'but', 'its', 'they', 'their', 'what', 'which', 'when',
    'where', 'who', 'whom', 'how', 'all', 'each', 'every', 'both',
    'few', 'more', 'most', 'other', 'some', 'such', 'than', 'too',
    'very', 'just', 'about', 'also', 'only', 'then', 'tool', 'agent',
    'help', 'users', 'user',
  ]);

  const result = new Set<string>();
  purpose
    .split(/[\s,.;:!?()[\]{}]+/)
    .map(w => w.toLowerCase())
    .filter(w => w.length > 3 && !stopWords.has(w))
    .forEach(w => result.add(w));
  return result;
}

/**
 * Extract keywords from a capability name and scope.
 * "db.read" + "customers table" -> {"read", "customers", "table", "database"}
 */
function extractCapabilityKeywords(name: string, scope: string): Set<string> {
  const parts = name.split(/[._-]/).filter(p => p.length > 2);

  // Expand abbreviations
  const expansions: Record<string, string[]> = {
    db: ['database', 'data'],
    api: ['interface', 'endpoint', 'service'],
    fs: ['file', 'filesystem'],
    mcp: ['tool', 'server'],
    auth: ['authentication', 'credential'],
    exec: ['execute', 'shell'],
    admin: ['administration', 'privilege'],
  };

  const keywords = new Set<string>();
  for (const part of parts) {
    keywords.add(part.toLowerCase());
    const expanded = expansions[part.toLowerCase()];
    if (expanded) {
      for (const e of expanded) {
        keywords.add(e);
      }
    }
  }

  // Add scope words
  if (scope) {
    for (const word of scope.split(/[\s,.]+/)) {
      if (word.length > 2) {
        keywords.add(word.toLowerCase());
      }
    }
  }

  return keywords;
}

function setIntersection<T>(a: Set<T>, b: Set<T>): Set<T> {
  const result = new Set<T>();
  a.forEach(item => {
    if (b.has(item)) {
      result.add(item);
    }
  });
  return result;
}

function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen - 3) + '...';
}

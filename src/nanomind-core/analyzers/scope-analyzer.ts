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

// ============================================================================
// Public API
// ============================================================================

/**
 * Analyze a SecurityAST for scope and permission issues.
 * Verifies AST integrity before processing.
 */
export function analyzeScope(
  ast: SecurityAST,
  verifier: (ast: SecurityAST) => boolean,
  projectType?: ProjectType,
): ASTFinding[] {
  assertASTIntegrity(ast, verifier);

  // SDKs and libraries don't declare tool access, permissions, or purpose
  // in the OASB sense. Scope checks only apply to agents.
  if (projectType === 'sdk' || projectType === 'library') {
    return [];
  }

  const findings: ASTFinding[] = [];

  findings.push(...checkWildcardToolAccess(ast));
  findings.push(...checkUndeclaredPermissions(ast));
  findings.push(...checkScopePurposeMismatch(ast));

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
function checkWildcardToolAccess(ast: SecurityAST): ASTFinding[] {
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

  // Also flag MCP configs where no allowedTools is specified (implicit wildcard)
  if (ast.artifactType === 'mcp_config') {
    const mcpCaps = ast.declaredCapabilities.filter(c => c.name.startsWith('mcp.'));
    // If there are MCP capabilities but none have explicit tool names (all are server-level)
    const hasOnlyServerLevel = mcpCaps.length > 0 && mcpCaps.every(c => {
      const parts = c.name.split('.');
      return parts.length <= 2; // "mcp.servername" without a tool name
    });

    if (hasOnlyServerLevel && fullWildcards.length === 0) {
      // MCP server declared without explicit tool restrictions
      for (const cap of mcpCaps) {
        findings.push({
          checkId: 'AST-SCOPE-001',
          name: 'Implicit Wildcard MCP Access',
          description:
            `MCP server "${cap.scope}" is configured without an explicit tool allowlist. ` +
            'When no allowedTools is specified, all tools on the server are accessible.',
          category: 'Scope Security',
          severity: 'high',
          passed: false,
          message: `Implicit wildcard: MCP server ${cap.scope}`,
          fixable: false,
          file: ast.artifactPath,
          fix:
            `Add an explicit "allowedTools" list to the "${cap.scope}" server config in mcp.json. ` +
            'Run `opena2a mcp audit` to inventory available tools, then restrict to the minimum needed.',
          guidance:
            'MCP servers can expose dangerous tools (file system, shell execution). ' +
            'Always restrict access to a named allowlist.',
          attackClass: 'SCOPE-WILDCARD',
          confidence: 0.8,
        });
      }
    }
  }

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
function checkUndeclaredPermissions(ast: SecurityAST): ASTFinding[] {
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
function checkScopePurposeMismatch(ast: SecurityAST): ASTFinding[] {
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
// Helpers
// ============================================================================

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

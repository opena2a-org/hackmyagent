/**
 * Declared-vs-Actual Capability Validation
 *
 * Compares what a SKILL.md declares in its frontmatter (capabilities/permissions)
 * against what the skill body actually does. Generates SKILL-018 findings for
 * undeclared capabilities.
 */

import type { SecurityFinding } from './security-check';

export interface SkillDeclaredCapabilities {
  capabilities: string[];
  permissions: Record<string, string[]>;
}

export interface InferredCapability {
  capability: string;
  evidence: string;
  lineNumber: number;
}

/**
 * Extract capabilities and permissions from YAML frontmatter.
 */
export function parseDeclaredCapabilities(content: string): SkillDeclaredCapabilities {
  const result: SkillDeclaredCapabilities = {
    capabilities: [],
    permissions: {},
  };

  const frontmatterMatch = content.match(/^---\s*\n([\s\S]*?)\n---/);
  if (!frontmatterMatch) return result;

  const frontmatter = frontmatterMatch[1];

  // Parse capabilities list
  result.capabilities = parseYamlList(frontmatter, 'capabilities');

  // Also include permissions keys as capabilities
  const permissionsBlock = extractYamlBlock(frontmatter, 'permissions');
  if (permissionsBlock) {
    const keyPattern = /^\s{2}(\S[^:]*?):\s*$/gm;
    let match;
    while ((match = keyPattern.exec(permissionsBlock)) !== null) {
      const key = match[1].trim();
      result.permissions[key] = [];
      // Find list items under this key
      const keyIdx = permissionsBlock.indexOf(match[0]);
      const afterKey = permissionsBlock.substring(keyIdx + match[0].length);
      const itemPattern = /^\s{4}-\s+(.+)$/gm;
      let itemMatch;
      while ((itemMatch = itemPattern.exec(afterKey)) !== null) {
        result.permissions[key].push(itemMatch[1].trim().replace(/^["']|["']$/g, ''));
      }
    }
  }

  // Also accept flat filesystem:/network: entries in capabilities
  for (const cap of result.capabilities) {
    if (cap.includes(':') && !result.permissions[cap.split(':')[0]]) {
      const [prefix, ...rest] = cap.split(':');
      const scope = rest.join(':');
      if (!result.permissions[prefix]) {
        result.permissions[prefix] = [];
      }
      if (scope) {
        result.permissions[prefix].push(scope);
      }
    }
  }

  return result;
}

/**
 * Scan skill body (NOT frontmatter) for capability indicators.
 */
export function inferActualCapabilities(content: string): InferredCapability[] {
  const inferred: InferredCapability[] = [];

  // Strip frontmatter to only analyze body
  const bodyContent = content.replace(/^---\s*\n[\s\S]*?\n---\s*\n?/, '');
  const lines = bodyContent.split('\n');

  // Find the offset for line numbers (account for stripped frontmatter)
  const frontmatterMatch = content.match(/^---\s*\n[\s\S]*?\n---\s*\n?/);
  const frontmatterLines = frontmatterMatch
    ? frontmatterMatch[0].split('\n').length - 1
    : 0;

  const sensitivePathPatterns: Array<{ pattern: RegExp; capability: string }> = [
    { pattern: /~\/\.ssh/g, capability: 'filesystem:~/.ssh' },
    { pattern: /~\/\.aws/g, capability: 'filesystem:~/.aws' },
    { pattern: /~\/\.kube/g, capability: 'filesystem:~/.kube' },
    { pattern: /~\/\.gnupg/g, capability: 'filesystem:~/.gnupg' },
    { pattern: /~\/\.config/g, capability: 'filesystem:~/.config' },
  ];

  const networkOutboundPatterns: Array<{ pattern: RegExp; capability: string }> = [
    { pattern: /\bcurl\b/g, capability: 'network:outbound' },
    { pattern: /\bwget\b/g, capability: 'network:outbound' },
    { pattern: /\bfetch\s*\(/g, capability: 'network:outbound' },
    { pattern: /\bhttp\.get\b/g, capability: 'network:outbound' },
    { pattern: /\baxios\b/g, capability: 'network:outbound' },
  ];

  const shellPatterns: Array<{ pattern: RegExp; capability: string }> = [
    { pattern: /\bshell\s*:/g, capability: 'shell:execute' },
    { pattern: /\bbash\s/g, capability: 'shell:execute' },
    { pattern: /\bexec\s*\(/g, capability: 'shell:execute' },
    { pattern: /\bspawn\s*\(/g, capability: 'shell:execute' },
  ];

  const networkInboundPatterns: Array<{ pattern: RegExp; capability: string }> = [
    { pattern: /\blisten\s*\(/g, capability: 'network:inbound' },
    { pattern: /\bcreateServer\b/g, capability: 'network:inbound' },
  ];

  const filesystemWildcardPatterns: Array<{ pattern: RegExp; capability: string }> = [
    { pattern: /filesystem:\s*\*/g, capability: 'filesystem:wildcard' },
  ];

  const allPatterns = [
    ...sensitivePathPatterns,
    ...networkOutboundPatterns,
    ...shellPatterns,
    ...networkInboundPatterns,
    ...filesystemWildcardPatterns,
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, capability } of allPatterns) {
      pattern.lastIndex = 0;
      if (pattern.test(line)) {
        // Avoid duplicate capabilities on same line
        if (!inferred.some(inf => inf.lineNumber === i + frontmatterLines + 1 && inf.capability === capability)) {
          inferred.push({
            capability,
            evidence: line.trim().substring(0, 100),
            lineNumber: i + frontmatterLines + 1,
          });
        }
      }
    }
  }

  return inferred;
}

/**
 * Compare declared vs inferred capabilities.
 * Generate SKILL-018 findings for undeclared capabilities.
 */
export function validateCapabilities(
  declared: SkillDeclaredCapabilities,
  inferred: InferredCapability[],
  filePath?: string
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const inf of inferred) {
    if (isCapabilityDeclared(inf.capability, declared)) {
      continue;
    }

    findings.push({
      checkId: 'SKILL-018',
      name: 'Undeclared Capability',
      description: 'Skill uses a capability not declared in its frontmatter',
      category: 'skill',
      severity: 'medium',
      passed: false,
      message: `Undeclared capability "${inf.capability}" detected: "${inf.evidence}"`,
      file: filePath,
      line: inf.lineNumber,
      fixable: false,
      fix: `Add "${inf.capability}" to the capabilities list in the skill frontmatter`,
    });
  }

  return findings;
}

/**
 * Check if a capability is covered by the declared capabilities/permissions.
 */
function isCapabilityDeclared(
  capability: string,
  declared: SkillDeclaredCapabilities
): boolean {
  // Direct match in capabilities list
  if (declared.capabilities.includes(capability)) {
    return true;
  }

  // Check by prefix (e.g., "filesystem:~/.ssh" is covered by "filesystem" capability)
  const [prefix] = capability.split(':');
  if (declared.capabilities.includes(prefix)) {
    return true;
  }

  // Check wildcard permissions (e.g., "filesystem:./**" covers filesystem access)
  if (declared.permissions[prefix]) {
    const scopes = declared.permissions[prefix];
    // Any declared scope for this prefix counts as declared
    if (scopes.length > 0) {
      return true;
    }
    // Empty scopes list means the prefix was declared without specific scopes
    return true;
  }

  // Check for broader capability declarations
  // "network" covers "network:outbound" and "network:inbound"
  if (declared.capabilities.some(cap => {
    const [capPrefix] = cap.split(':');
    return capPrefix === prefix;
  })) {
    return true;
  }

  return false;
}

/**
 * Parse a simple YAML list from frontmatter.
 */
function parseYamlList(frontmatter: string, field: string): string[] {
  // Inline format: field: [a, b, c]
  const inlineMatch = frontmatter.match(new RegExp(`^${field}:\\s*\\[([^\\]]*)]`, 'm'));
  if (inlineMatch) {
    return inlineMatch[1]
      .split(',')
      .map(item => item.trim().replace(/^["']|["']$/g, ''))
      .filter(item => item.length > 0);
  }

  // Block format
  const blockPattern = new RegExp(`^${field}:\\s*$`, 'm');
  const blockMatch = frontmatter.match(blockPattern);
  if (!blockMatch) return [];

  const startIdx = frontmatter.indexOf(blockMatch[0]) + blockMatch[0].length;
  const remaining = frontmatter.substring(startIdx);
  const items: string[] = [];
  for (const line of remaining.split('\n')) {
    const itemMatch = line.match(/^\s+-\s+(.+)$/);
    if (itemMatch) {
      items.push(itemMatch[1].trim().replace(/^["']|["']$/g, ''));
    } else if (line.trim() !== '' && !/^\s+-/.test(line)) {
      break; // End of list
    }
  }
  return items;
}

/**
 * Extract a YAML block (key + indented children) from frontmatter.
 */
function extractYamlBlock(frontmatter: string, field: string): string | null {
  const blockPattern = new RegExp(`^${field}:\\s*$`, 'm');
  const blockMatch = frontmatter.match(blockPattern);
  if (!blockMatch) return null;

  const startIdx = frontmatter.indexOf(blockMatch[0]);
  const remaining = frontmatter.substring(startIdx);
  const lines = remaining.split('\n');
  const blockLines = [lines[0]];
  for (let i = 1; i < lines.length; i++) {
    if (/^\s+/.test(lines[i]) || lines[i].trim() === '') {
      blockLines.push(lines[i]);
    } else {
      break;
    }
  }
  return blockLines.join('\n');
}

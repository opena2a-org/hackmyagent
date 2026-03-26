/**
 * Target Reader -- Semantic Vulnerability Surface Extraction
 *
 * NanoMind reads the target artifact semantically and extracts:
 * declared purpose, constraints, capabilities, data access patterns,
 * governance mechanisms, and a vulnerability surface map.
 *
 * The attack surface is derived from the target's own declarations.
 */

import type { SemanticTargetProfile, VulnerabilitySurfaceEntry, AttackCategory } from './types.js';

/**
 * Read a target artifact and extract its semantic vulnerability surface.
 */
export function readTarget(
  content: string,
  artifactType: SemanticTargetProfile['artifactType'],
  name: string = 'unknown',
): SemanticTargetProfile {
  const text = content.toLowerCase();

  // Extract declared purpose (first meaningful paragraph or description)
  const declaredPurpose = extractPurpose(content);

  // Extract capabilities from manifests, tool declarations, etc.
  const capabilities = extractCapabilities(content);

  // Extract constraints (must/should/never/always patterns)
  const constraints = extractConstraints(content);

  // Determine governance mechanism
  const governanceMechanism = detectGovernance(content);

  // Extract data access patterns
  const dataAccessPatterns = extractDataAccess(content, capabilities);

  // Build vulnerability surface from all extracted signals
  const vulnerabilitySurface = buildVulnerabilitySurface(
    declaredPurpose, capabilities, constraints, governanceMechanism, dataAccessPatterns, text,
  );

  return {
    artifactType,
    declaredPurpose,
    capabilities,
    constraints,
    governanceMechanism,
    dataAccessPatterns,
    vulnerabilitySurface,
  };
}

function extractPurpose(content: string): string {
  // Check YAML frontmatter
  const descMatch = content.match(/description:\s*(.+)/);
  if (descMatch) return descMatch[1].trim();

  // Check first heading + paragraph
  const lines = content.split('\n').filter(l => l.trim().length > 0);
  for (const line of lines) {
    if (!line.startsWith('#') && !line.startsWith('-') && !line.startsWith('---') && line.trim().length > 20) {
      return line.trim().slice(0, 200);
    }
  }
  return 'Unknown purpose';
}

function extractCapabilities(content: string): string[] {
  const caps: string[] = [];

  // YAML capabilities list
  const yamlCaps = content.match(/capabilities:\s*\n((?:\s+-\s+.+\n?)*)/);
  if (yamlCaps) {
    const items = yamlCaps[1].split('\n')
      .filter(l => l.trim().startsWith('-'))
      .map(l => l.replace(/^\s*-\s*/, '').trim());
    caps.push(...items);
  }

  // Tool-use patterns in content
  const toolPatterns = [
    /(?:can|will|may)\s+(read|write|delete|update|send|fetch|call|access|query|execute)\s+([a-z_.\s]+)/gi,
  ];
  for (const pattern of toolPatterns) {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      caps.push(`${match[1]}.${match[2].trim().split(/\s+/)[0]}`);
    }
  }

  return [...new Set(caps)];
}

function extractConstraints(content: string): string[] {
  const patterns = /(?:must|should|never|always|cannot|will not|forbidden|shall not|restricted)[^.]+\./gi;
  const matches = content.match(patterns);
  return matches ? [...new Set(matches.map(m => m.trim()))] : [];
}

function detectGovernance(content: string): string {
  if (/soul\.md/i.test(content)) return 'soul';
  if (/system.?prompt/i.test(content)) return 'system_prompt';
  if (/runtime.?check|enforcement/i.test(content)) return 'runtime_check';
  return 'none';
}

function extractDataAccess(content: string, capabilities: string[]): string[] {
  const patterns: string[] = [];
  const dataTypes = ['user', 'customer', 'payment', 'session', 'credential', 'email', 'profile', 'ticket', 'order', 'transaction'];

  for (const dt of dataTypes) {
    if (content.toLowerCase().includes(dt)) {
      patterns.push(dt);
    }
  }
  return patterns;
}

function buildVulnerabilitySurface(
  purpose: string,
  capabilities: string[],
  constraints: string[],
  governance: string,
  dataAccess: string[],
  text: string,
): VulnerabilitySurfaceEntry[] {
  const surface: VulnerabilitySurfaceEntry[] = [];

  // Each capability is a potential attack surface
  for (const cap of capabilities) {
    if (/write|send|call|execute|delete/i.test(cap)) {
      surface.push({
        surface: `Capability: ${cap}`,
        exploitApproach: `Exploit ${cap} to perform actions outside declared scope`,
        attackCategory: 'capability_abuse',
        estimatedSuccess: 0.3,
      });
    }
  }

  // Each constraint is a potential bypass surface
  for (const constraint of constraints) {
    if (/never|must not|forbidden/i.test(constraint)) {
      surface.push({
        surface: `Constraint: ${constraint.slice(0, 80)}`,
        exploitApproach: 'Craft input that satisfies constraint wording while violating intent',
        attackCategory: 'soul_bypass',
        estimatedSuccess: 0.4,
      });
    }
  }

  // Data access creates exfiltration surface
  if (dataAccess.length > 0) {
    surface.push({
      surface: `Data access: ${dataAccess.join(', ')}`,
      exploitApproach: 'Social engineering using the target\'s own data domain',
      attackCategory: 'social_engineering',
      estimatedSuccess: 0.5,
    });

    if (dataAccess.some(d => ['credential', 'session', 'payment'].includes(d))) {
      surface.push({
        surface: `Sensitive data: ${dataAccess.filter(d => ['credential', 'session', 'payment'].includes(d)).join(', ')}`,
        exploitApproach: 'Exfiltrate sensitive data via compliance framing',
        attackCategory: 'data_exfiltration',
        estimatedSuccess: 0.4,
      });
    }
  }

  // Weak governance
  if (governance === 'none') {
    surface.push({
      surface: 'No governance mechanism detected',
      exploitApproach: 'Direct instruction override without governance resistance',
      attackCategory: 'instruction_override',
      estimatedSuccess: 0.7,
    });
  }

  return surface;
}

/**
 * Agent Instruction Static Analysis (Layer 2)
 *
 * Analyzes CLAUDE.md, .cursorrules, .windsurfrules, .clinerules,
 * copilot-instructions.md for security issues:
 * - Overly permissive instructions
 * - Exfiltration enablement
 * - Missing security boundaries
 * - Large attack surface
 */

import type { SemanticFinding, AnalysisFile } from '../types';

/** Patterns that indicate overly permissive agent instructions */
const PERMISSIVE_PATTERNS = [
  { pattern: /always\s+execute/i, label: '"always execute"' },
  { pattern: /never\s+refuse/i, label: '"never refuse"' },
  { pattern: /full\s+access/i, label: '"full access"' },
  { pattern: /bypass\s+safety/i, label: '"bypass safety"' },
  { pattern: /ignore\s+restrictions/i, label: '"ignore restrictions"' },
  { pattern: /no\s+restrictions/i, label: '"no restrictions"' },
  { pattern: /skip\s+(?:security|safety|validation)/i, label: '"skip security/safety"' },
  { pattern: /disable\s+(?:security|safety|protection)/i, label: '"disable security"' },
  { pattern: /without\s+(?:asking|confirmation|approval)/i, label: '"without asking"' },
  { pattern: /unrestricted/i, label: '"unrestricted"' },
  { pattern: /override\s+(?:safety|security|policy)/i, label: '"override safety/policy"' },
];

/** Patterns that could enable data exfiltration */
const EXFILTRATION_PATTERNS = [
  { pattern: /webhook\.site/i, label: 'webhook.site URL' },
  { pattern: /requestbin/i, label: 'requestbin URL' },
  { pattern: /ngrok\.io/i, label: 'ngrok tunnel' },
  { pattern: /pipedream/i, label: 'pipedream URL' },
  { pattern: /send\s+(?:results?|data|output|response)\s+to\s+/i, label: '"send results to" directive' },
  { pattern: /post\s+(?:results?|data|output)\s+to\s+/i, label: '"post data to" directive' },
  { pattern: /forward\s+(?:to|all)\s+/i, label: '"forward to" directive' },
  { pattern: /exfiltrat/i, label: 'exfiltration reference' },
  { pattern: /curl\s+.*-X\s*POST/i, label: 'curl POST command' },
];

/** Security-related terms that should be present in instruction files */
const SECURITY_TERMS = [
  /security/i,
  /safe(?:ty|ly)?/i,
  /restrict(?:ed|ion)?/i,
  /permission/i,
  /authoriz/i,
  /sensitive/i,
  /credential/i,
  /secret/i,
  /protect/i,
  /boundary/i,
  /sandbox/i,
  /scope/i,
];

/** Max instruction file size before it becomes a concern */
const LARGE_INSTRUCTION_THRESHOLD = 10 * 1024; // 10KB

export class InstructionAnalyzer {
  analyze(files: AnalysisFile[]): SemanticFinding[] {
    const findings: SemanticFinding[] = [];

    const instructionFiles = files.filter(
      (f) => f.type === 'agent_instructions'
    );

    for (const file of instructionFiles) {
      findings.push(...this.checkPermissiveInstructions(file));
      findings.push(...this.checkExfiltrationEnablement(file));
      findings.push(...this.checkMissingSecurityBoundaries(file));
      findings.push(...this.checkLargeAttackSurface(file));
    }

    return findings;
  }

  private checkPermissiveInstructions(file: AnalysisFile): SemanticFinding[] {
    const findings: SemanticFinding[] = [];
    const lines = file.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      for (const { pattern, label } of PERMISSIVE_PATTERNS) {
        if (pattern.test(line)) {
          findings.push({
            id: 'SEM-INST-001',
            title: 'Overly permissive agent instruction',
            description: `Found ${label} pattern in ${file.path}. This instructs the agent to bypass security controls.`,
            rationale:
              'Permissive instructions weaken agent security boundaries. If an attacker achieves prompt injection, these instructions make it easier to escalate — the agent is already told to bypass safety checks.',
            category: 'instruction',
            severity: 'high',
            file: file.path,
            line: i + 1,
            recommendation:
              'Replace permissive instructions with specific, scoped permissions. Instead of "always execute", specify which operations are allowed and under what conditions.',
            layer: 2,
            autoFixable: false,
          });
          break; // One finding per line
        }
      }
    }

    return findings;
  }

  private checkExfiltrationEnablement(file: AnalysisFile): SemanticFinding[] {
    const findings: SemanticFinding[] = [];
    const lines = file.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      for (const { pattern, label } of EXFILTRATION_PATTERNS) {
        if (pattern.test(line)) {
          findings.push({
            id: 'SEM-INST-002',
            title: 'Exfiltration-enabling instruction',
            description: `Found ${label} in ${file.path}. This could enable data exfiltration by the agent.`,
            rationale:
              'Instructions that direct the agent to send data to external services can be exploited via prompt injection to exfiltrate sensitive data from the project.',
            category: 'instruction',
            severity: 'high',
            file: file.path,
            line: i + 1,
            recommendation:
              'Remove external URL references from agent instructions. If external communication is needed, scope it to specific trusted domains.',
            layer: 2,
            autoFixable: false,
          });
          break;
        }
      }
    }

    return findings;
  }

  private checkMissingSecurityBoundaries(file: AnalysisFile): SemanticFinding[] {
    // Only flag if the file is non-trivial (>200 chars)
    if (file.content.length < 200) return [];

    const hasSecurityTerms = SECURITY_TERMS.some((term) =>
      term.test(file.content)
    );

    if (!hasSecurityTerms) {
      return [
        {
          id: 'SEM-INST-003',
          title: 'No security boundaries in agent instructions',
          description: `${file.path} contains agent instructions but no security-related guidance. The agent has no explicit security constraints.`,
          rationale:
            'Without security boundaries, the agent relies on its default behavior which may be too permissive. Explicit security instructions help prevent prompt injection exploits.',
          category: 'instruction',
          severity: 'medium',
          file: file.path,
          recommendation:
            'Add security guidance to the instruction file. Include: allowed/denied operations, file access scope, network restrictions, and how to handle sensitive data.',
          layer: 2,
          autoFixable: false,
        },
      ];
    }

    return [];
  }

  private checkLargeAttackSurface(file: AnalysisFile): SemanticFinding[] {
    const size = Buffer.byteLength(file.content, 'utf-8');

    if (size > LARGE_INSTRUCTION_THRESHOLD) {
      const sizeKb = (size / 1024).toFixed(1);
      return [
        {
          id: 'SEM-INST-004',
          title: 'Large agent instruction file',
          description: `${file.path} is ${sizeKb}KB. Large instruction files increase the LLM context surface area for prompt injection.`,
          rationale:
            'Larger instruction files provide more context for an attacker to work with during prompt injection attacks. They also increase the chance of containing sensitive information.',
          category: 'instruction',
          severity: 'low',
          file: file.path,
          recommendation:
            'Review the instruction file for unnecessary content. Keep security-critical instructions concise and focused.',
          layer: 2,
          autoFixable: false,
        },
      ];
    }

    return [];
  }
}

/**
 * Permission Scope Analysis (Layer 2)
 *
 * Parses .claude/settings.json and similar config files to detect:
 * - Wildcard permissions (allow: ["*"])
 * - Bash tool with no restrictions
 * - Write/Edit granted outside project scope
 */

import type { SemanticFinding, AnalysisFile, ClaudeSettings } from '../types';

export class PermissionModelAnalyzer {
  analyze(files: AnalysisFile[]): SemanticFinding[] {
    const findings: SemanticFinding[] = [];

    for (const file of files) {
      if (file.type !== 'claude_settings') continue;

      let settings: ClaudeSettings;
      try {
        settings = JSON.parse(file.content);
      } catch {
        continue;
      }

      findings.push(...this.checkWildcardPermissions(settings, file));
      findings.push(...this.checkBashPermissions(settings, file));
      findings.push(...this.checkWriteScope(settings, file));
    }

    return findings;
  }

  private checkWildcardPermissions(
    settings: ClaudeSettings,
    file: AnalysisFile
  ): SemanticFinding[] {
    const allow = settings.permissions?.allow;
    if (!allow) return [];

    if (allow.includes('*')) {
      return [
        {
          id: 'SEM-PERM-001',
          title: 'Wildcard permission grant',
          description: `${file.path} grants permissions.allow: ["*"], allowing the agent unrestricted access to all tools.`,
          rationale:
            'Wildcard permissions disable all tool-level access controls. The agent can read, write, execute, and network without any restrictions.',
          category: 'permission',
          severity: 'critical',
          file: file.path,
          recommendation:
            'Replace wildcard with specific tool permissions: ["Read", "Glob", "Grep"] for read-only, adding "Edit", "Write", "Bash" only as needed.',
          layer: 2,
          autoFixable: false,
        },
      ];
    }

    return [];
  }

  private checkBashPermissions(
    settings: ClaudeSettings,
    file: AnalysisFile
  ): SemanticFinding[] {
    const allow = settings.permissions?.allow;
    if (!allow) return [];

    // Check for unrestricted Bash access
    const bashEntries = allow.filter(
      (p) => typeof p === 'string' && p.toLowerCase().startsWith('bash')
    );

    // If Bash is allowed without any pattern restriction
    const hasUnrestrictedBash = bashEntries.some((entry) => {
      // "Bash" or "Bash(*)" is unrestricted
      return entry === 'Bash' || entry === 'Bash(*)';
    });

    if (hasUnrestrictedBash) {
      return [
        {
          id: 'SEM-PERM-002',
          title: 'Unrestricted Bash access',
          description: `${file.path} grants unrestricted Bash tool access. The agent can execute any shell command.`,
          rationale:
            'Unrestricted Bash access allows arbitrary command execution including reading/writing any file, making network requests, installing packages, and modifying system configuration.',
          category: 'permission',
          severity: 'high',
          file: file.path,
          recommendation:
            'Restrict Bash to specific commands: "Bash(npm test)", "Bash(git *)" or use deny rules to block dangerous commands.',
          layer: 2,
          autoFixable: false,
        },
      ];
    }

    return [];
  }

  private checkWriteScope(
    settings: ClaudeSettings,
    file: AnalysisFile
  ): SemanticFinding[] {
    const allow = settings.permissions?.allow;
    if (!allow) return [];

    // Check for Write/Edit with paths outside the project
    const writeEntries = allow.filter((p) => {
      if (typeof p !== 'string') return false;
      const lower = p.toLowerCase();
      return lower.startsWith('write') || lower.startsWith('edit');
    });

    const outsidePaths = writeEntries.filter((entry) => {
      // Check if the permission references paths outside project
      return (
        entry.includes('/home/') ||
        entry.includes('/Users/') ||
        entry.includes('/etc/') ||
        entry.includes('/tmp/') ||
        entry.includes('/var/')
      );
    });

    if (outsidePaths.length > 0) {
      return [
        {
          id: 'SEM-PERM-003',
          title: 'Write access outside project scope',
          description: `${file.path} grants write access to paths outside the project directory: ${outsidePaths.join(', ')}`,
          rationale:
            'Write access outside the project directory allows the agent to modify system files, other projects, or user configuration. This significantly increases the blast radius of any compromise.',
          category: 'permission',
          severity: 'high',
          file: file.path,
          recommendation:
            'Scope write permissions to the project directory only. Remove paths outside the project from the allow list.',
          layer: 2,
          autoFixable: false,
        },
      ];
    }

    return [];
  }
}

import { describe, it, expect } from 'vitest';
import { PermissionModelAnalyzer } from '../structural/permission-model';
import type { AnalysisFile } from '../types';

const analyzer = new PermissionModelAnalyzer();

function makeSettingsFile(content: string): AnalysisFile {
  return { path: '.claude/settings.json', type: 'claude_settings', content, truncated: false };
}

describe('PermissionModelAnalyzer', () => {
  describe('wildcard permissions', () => {
    it('detects allow: ["*"]', () => {
      const file = makeSettingsFile(JSON.stringify({
        permissions: { allow: ['*'] },
      }));
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-PERM-001')).toBe(true);
      expect(findings[0].severity).toBe('critical');
    });

    it('does not flag specific permissions', () => {
      const file = makeSettingsFile(JSON.stringify({
        permissions: { allow: ['Read', 'Glob', 'Grep'] },
      }));
      const findings = analyzer.analyze([file]);
      expect(findings.filter((f) => f.id === 'SEM-PERM-001')).toHaveLength(0);
    });
  });

  describe('unrestricted Bash', () => {
    it('detects Bash in allow list', () => {
      const file = makeSettingsFile(JSON.stringify({
        permissions: { allow: ['Read', 'Bash'] },
      }));
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-PERM-002')).toBe(true);
    });

    it('detects Bash(*) wildcard', () => {
      const file = makeSettingsFile(JSON.stringify({
        permissions: { allow: ['Bash(*)'] },
      }));
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-PERM-002')).toBe(true);
    });

    it('does not flag scoped Bash', () => {
      const file = makeSettingsFile(JSON.stringify({
        permissions: { allow: ['Bash(npm test)', 'Bash(git status)'] },
      }));
      const findings = analyzer.analyze([file]);
      expect(findings.filter((f) => f.id === 'SEM-PERM-002')).toHaveLength(0);
    });
  });

  describe('write scope', () => {
    it('detects write access outside project', () => {
      const file = makeSettingsFile(JSON.stringify({
        permissions: { allow: ['Write(/Users/admin/.ssh/*)'] },
      }));
      const findings = analyzer.analyze([file]);
      expect(findings.some((f) => f.id === 'SEM-PERM-003')).toBe(true);
    });
  });

  describe('only processes settings files', () => {
    it('ignores non-settings files', () => {
      const file: AnalysisFile = {
        path: 'config.json',
        type: 'config_file',
        content: JSON.stringify({ permissions: { allow: ['*'] } }),
        truncated: false,
      };
      const findings = analyzer.analyze([file]);
      expect(findings).toHaveLength(0);
    });
  });
});

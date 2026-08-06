import { describe, it, expect } from 'vitest';
import { classifyArtifactType } from '../../src/nanomind-core/ingestion/artifact-parser';

/**
 * Regression tests for #410.
 *
 * The `skill` signature used `/^---\n[\s\S]*?capabilities:\s*\n/m`. The `m` flag makes `^`
 * match at EVERY line start, so the test really meant "a `---` line anywhere, then a line
 * ending in `capabilities:` anywhere later". In Markdown `---` is a horizontal rule and
 * `capabilities:` matches ordinary prose, so documentation classified as an executable skill
 * and drew CRITICAL findings from the skill analyzers on placeholder URLs and sample SQL.
 *
 * The boundary is "does the LEADING YAML frontmatter block declare a top-level `capabilities`
 * key" — not "do these two strings both appear somewhere".
 */
describe('#410 skill classifier: frontmatter must be anchored to the start of the file', () => {
  describe('documentation must NOT classify as a skill', () => {
    it('markdown with a horizontal rule and a prose line ending in "capabilities:"', () => {
      // The MCP_INTEGRATION.md shape: no frontmatter, horizontal rules, prose colon.
      const doc = [
        '# AIM + MCP (Model Context Protocol) Integration Guide',
        '',
        'This guide explains how to wire AIM into an MCP client.',
        '',
        '---',
        '',
        '## Change detection',
        '',
        'The SDK automatically detects when MCP servers change their capabilities:',
        '',
        '```python',
        'client.on_capability_change(handler)',
        '```',
        '',
      ].join('\n');

      expect(classifyArtifactType(doc, 'sdk/python/docs/MCP_INTEGRATION.md')).not.toBe('skill');
      expect(classifyArtifactType(doc, 'sdk/python/docs/MCP_INTEGRATION.md')).toBe('unknown');
    });

    it('leading frontmatter WITHOUT capabilities, plus a later code block whose line starts with "capabilities:"', () => {
      // This is the case that defeats the narrower "anchor + content.startsWith('---')" fix
      // suggested on the issue: startsWith('---') is true here, and `^capabilities:$` still
      // matches inside the fenced example. Only reading the LEADING BLOCK gets this right.
      const doc = [
        '---',
        'title: Writing a skill manifest',
        'audience: integrators',
        '---',
        '',
        '# Writing a skill manifest',
        '',
        'A skill manifest declares its capabilities like this:',
        '',
        '```yaml',
        'capabilities:',
        '  - read_files',
        '```',
        '',
      ].join('\n');

      expect(classifyArtifactType(doc, 'docs/authoring-skills.md')).not.toBe('skill');
    });

    it('horizontal rule followed by an indented "capabilities:" in a sample signature', () => {
      const doc = [
        '# API Reference',
        '',
        '---',
        '',
        'Example signature:',
        '',
        '    capabilities: List[str],',
        '',
      ].join('\n');

      expect(classifyArtifactType(doc, 'docs/api-reference.md')).not.toBe('skill');
    });
  });

  describe('genuine skills must STILL classify as a skill', () => {
    it('real leading frontmatter declaring capabilities', () => {
      const skill = [
        '---',
        'name: fitness-tracker',
        'description: Help users track their fitness goals',
        'capabilities:',
        '  - read_health_data',
        '  - write_summary',
        '---',
        '',
        '# Fitness Tracker',
        '',
        'Tracks goals.',
        '',
      ].join('\n');

      expect(classifyArtifactType(skill, 'skills/fitness/README.md')).toBe('skill');
    });

    it('leading frontmatter with capabilities as an inline list', () => {
      const skill = ['---', 'name: deploy', 'capabilities: [read_files, run_shell]', '---', '', '# Deploy', ''].join('\n');

      expect(classifyArtifactType(skill, 'skills/deploy/doc.md')).toBe('skill');
    });

    it('CRLF frontmatter declaring capabilities', () => {
      const skill = ['---', 'name: crlf-skill', 'capabilities:', '  - read_files', '---', '', '# CRLF', ''].join('\r\n');

      expect(classifyArtifactType(skill, 'skills/crlf/doc.md')).toBe('skill');
    });

    it('classifies by path regardless of content', () => {
      expect(classifyArtifactType('', 'SKILL.md')).toBe('skill');
      expect(classifyArtifactType('', 'deploy.skill.md')).toBe('skill');
      expect(classifyArtifactType('no frontmatter at all', 'a/b/SKILL.md')).toBe('skill');
      expect(classifyArtifactType('no frontmatter at all', 'a/b/deploy.skill.md')).toBe('skill');
    });
  });
});

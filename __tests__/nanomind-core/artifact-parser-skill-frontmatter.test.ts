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

    it('TWO horizontal rules with a "capabilities:" line between them', () => {
      // The shape that actually forces `^` to mean start-of-file. With a single rule the
      // block regex finds no closing fence and returns null whether or not it carries `m`,
      // so a one-rule fixture cannot tell the two spellings apart: restoring the `m` flag
      // leaves every other test in this file green. A document whose two rules bracket a
      // `capabilities:` line is a complete frontmatter block to a multiline `^`, and prose
      // between two rules is ordinary Markdown.
      const doc = [
        '# Skill manifest reference',
        '',
        'Every manifest key, in the order the loader reads them.',
        '',
        '---',
        '',
        'capabilities:',
        '',
        '- `read_files` — read from the workspace',
        '- `run_shell` — run a command',
        '',
        '---',
        '',
        '## See also',
        '',
      ].join('\n');

      expect(classifyArtifactType(doc, 'docs/manifest-reference.md')).not.toBe('skill');
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

  describe('the signature stays linear on hostile content', () => {
    // parseArtifact's default maxArtifactSize. It only APPENDS an error — nothing truncates
    // or skips the content — so a file this size reaches the signature either way.
    const ONE_MB = 1024 * 1024;

    it('classifies 1 MB of repeated fence lines in well under a second', () => {
      // The replaced regex was quadratic on exactly this input. Its `m` flag gave `^---` a
      // start position at every one of the 262,144 line starts, and from each one the lazy
      // body scanned to EOF for a `capabilities:` line that never comes. The leading-block
      // helper is anchored with no `m`, so it has one start position.
      //
      // Measured on the same machine, same payload: 4,960 ms before the fix, 0.1 ms after.
      // The bound sits between the two, so it fails on the old regex rather than merely
      // passing on the new one.
      const hostile = '---\n'.repeat(ONE_MB / 4);

      const started = performance.now();
      const type = classifyArtifactType(hostile, 'docs/hostile.md');
      const elapsed = performance.now() - started;

      expect(type).not.toBe('skill');
      expect(elapsed, `1 MB of fence lines took ${elapsed.toFixed(0)} ms`).toBeLessThan(2000);
    });

    it('still runs the frontmatter test at 1 MB, so the timing fixture above is not short-circuited', () => {
      // Without this, a future size guard that skipped classification for large files would
      // make the timing assertion above pass while measuring nothing.
      const bigSkill = ['---', 'name: big', 'capabilities: [read_files]', '---', '', 'x'.repeat(ONE_MB)].join('\n');

      expect(classifyArtifactType(bigSkill, 'docs/big-skill.md')).toBe('skill');
    });
  });
});

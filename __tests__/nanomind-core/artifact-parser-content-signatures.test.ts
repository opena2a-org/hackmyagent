import { describe, it, expect } from 'vitest';
import { classifyArtifactType } from '../../src/nanomind-core/ingestion/artifact-parser';

/**
 * Regression tests for #411, the siblings of #410.
 *
 * The `agent_config`, `a2a_card`, `system_prompt` and `credential_file` signatures each tested
 * an unanchored substring: `/"agentType"|"capabilities".*"constraints"/s` on the raw text,
 * `path.includes('claude.md')`, and key shapes anywhere in a document. Plain documentation
 * classified as those types and was routed to analyzers that do not apply to it.
 *
 * The boundary is structure: a top-level key of a JSON object, an exact basename, and a
 * non-Markdown file for a credential store.
 */
describe('#411 artifact classifier: content signatures decide from structure', () => {
  describe('documentation from the report classifies as unknown', () => {
    it('a guide with a JSON example containing "agentType"', () => {
      const doc = [
        '# Agent cards',
        '',
        'An example card:',
        '',
        '```json',
        '{ "agentType": "assistant", "name": "helper" }',
        '```',
        '',
      ].join('\n');
      expect(classifyArtifactType(doc, 'docs/cards.md')).toBe('unknown');
    });

    it('a guide naming "capabilities" and "constraints" fifty lines apart', () => {
      const filler = Array.from({ length: 50 }, (_, i) => `Paragraph ${i} of the field reference.`);
      const doc = [
        '# Fields',
        '',
        'The `"capabilities"` field lists the tools an agent may call.',
        ...filler,
        'The `"constraints"` field limits how they are called.',
        '',
      ].join('\n');
      expect(classifyArtifactType(doc, 'docs/fields.md')).toBe('unknown');
    });

    it('a changelog whose path merely contains "claude.md"', () => {
      const doc = '# Changelog\n\n- 1.0.0: initial release\n';
      expect(classifyArtifactType(doc, 'docs/about-claude.md.backup')).toBe('unknown');
      expect(classifyArtifactType(doc, 'docs/not-claude.md.old')).toBe('unknown');
      expect(classifyArtifactType(doc, 'prompts/system-prompt.md.bak')).toBe('unknown');
    });

    it('a Markdown page documenting the AWS key format', () => {
      const example = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
      const doc = `# Key formats\n\nAWS access key ids look like \`${example}\`.\n`;
      expect(classifyArtifactType(doc, 'docs/key-formats.md')).toBe('unknown');
      expect(classifyArtifactType(doc, 'docs/KEY-FORMATS.MD')).toBe('unknown');
    });
  });

  describe('agent_config and a2a_card read top-level JSON keys', () => {
    it('a JSON object with a top-level agentType is an agent config', () => {
      const config = JSON.stringify({ agentType: 'assistant', tools: ['search'] }, null, 2);
      expect(classifyArtifactType(config, 'config/assistant.json')).toBe('agent_config');
    });

    it('top-level capabilities and constraints are an agent config, however far apart', () => {
      const config = JSON.stringify(
        {
          capabilities: ['read_files'],
          notes: Array.from({ length: 50 }, (_, i) => `note ${i}`),
          constraints: { maxSteps: 5 },
        },
        null,
        2,
      );
      expect(classifyArtifactType(config, 'config/worker.json')).toBe('agent_config');
    });

    it('JSONC with comments, a leading BOM and a trailing comma still reads its keys', () => {
      const config = [
        '\uFEFF// agent definition',
        '{',
        '  /* the kind of agent */',
        '  "agentType": "assistant",',
        '  "url": "https://example.com/a//b",',
        '}',
      ].join('\n');
      expect(classifyArtifactType(config, 'config/assistant.jsonc')).toBe('agent_config');
    });

    it('agentType nested below the top level, or as a string value, does not count', () => {
      const nested = JSON.stringify({ examples: [{ agentType: 'assistant' }], meta: { constraints: 1 } });
      expect(classifyArtifactType(nested, 'data/examples.json')).toBe('unknown');
      const asValue = JSON.stringify({ field: 'agentType', other: '"capabilities": "constraints"' });
      expect(classifyArtifactType(asValue, 'data/fields.json')).toBe('unknown');
    });

    it('agent.json is still an A2A card by name', () => {
      expect(classifyArtifactType('{"name": "x"}', '.well-known/agent.json')).toBe('a2a_card');
    });
  });

  describe('system_prompt matches exact basenames', () => {
    it.each([
      'CLAUDE.md',
      '.claude/CLAUDE.md',
      'claude.md',
      '.cursorrules',
      '.windsurfrules',
      '.clinerules',
      '.clinerules/coding-style.md',
      'prompts/system-prompt.md',
      'SystemPrompt.txt',
      'system-prompt',
    ])('%s is a system prompt', (path) => {
      expect(classifyArtifactType('Follow the coding style.\n', path)).toBe('system_prompt');
    });
  });

  describe('system_prompt reads the name before the first dot, and a suffix after it', () => {
    it.each([
      'system-prompt.prod.md',
      'prompts/system-prompt.prod.md',
      'system-prompt-v2.txt',
      'agent/system-prompt.en.md',
      'system_prompt.md',
      'prompts/system_prompt-staging.txt',
    ])('%s is a system prompt', (path) => {
      expect(classifyArtifactType('Follow the coding style.\n', path)).toBe('system_prompt');
    });

    it.each([
      'system-prompt.md.bak',
      'system-prompt.md.backup',
      'system-prompt.md.old',
      'system-prompt.md.orig',
      'system-prompt.md~',
      'docs/about-claude.md.backup',
      'docs/about-system-prompt.md',
      'system-prompts.md',
    ])('%s is not', (path) => {
      expect(classifyArtifactType('Follow the coding style.\n', path)).toBe('unknown');
    });
  });

  describe('credential_file still names non-Markdown files carrying a key', () => {
    it('a YAML config with an AWS key', () => {
      const content = `aws:\n  accessKeyId: ${['AKIA', 'ABCDEFGHIJKLMNOP'].join('')}\n`;
      expect(classifyArtifactType(content, 'deploy/settings.yaml')).toBe('credential_file');
    });

    it('a private key file', () => {
      const header = ['-----BEGIN RSA', 'PRIVATE KEY-----'].join(' ');
      const content = `${header}\nMIIB\n`;
      expect(classifyArtifactType(content, 'keys/deploy_key')).toBe('credential_file');
    });
  });
});

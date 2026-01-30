import { describe, it, expect } from 'vitest';
import { parseSkillIdentifier, SkillIdentifier } from './skill-identifier';

describe('parseSkillIdentifier', () => {
  it('parses scoped npm-style identifier @publisher/skill', () => {
    const result = parseSkillIdentifier('@opena2a/security');

    expect(result).toEqual({
      publisher: 'opena2a',
      name: 'security',
      version: undefined,
      source: 'registry',
    });
  });

  it('parses identifier with version @publisher/skill@1.0.0', () => {
    const result = parseSkillIdentifier('@opena2a/security@1.0.0');

    expect(result).toEqual({
      publisher: 'opena2a',
      name: 'security',
      version: '1.0.0',
      source: 'registry',
    });
  });

  it('parses local file path', () => {
    const result = parseSkillIdentifier('./skills/my-skill');

    expect(result).toEqual({
      publisher: undefined,
      name: 'my-skill',
      version: undefined,
      source: 'local',
      path: './skills/my-skill',
    });
  });

  it('parses absolute file path', () => {
    const result = parseSkillIdentifier('/Users/dev/skills/custom');

    expect(result).toEqual({
      publisher: undefined,
      name: 'custom',
      version: undefined,
      source: 'local',
      path: '/Users/dev/skills/custom',
    });
  });

  it('parses GitHub URL', () => {
    const result = parseSkillIdentifier('https://github.com/opena2a/my-skill');

    expect(result).toEqual({
      publisher: 'opena2a',
      name: 'my-skill',
      version: undefined,
      source: 'github',
      url: 'https://github.com/opena2a/my-skill',
    });
  });

  it('throws on invalid identifier', () => {
    expect(() => parseSkillIdentifier('')).toThrow('Invalid skill identifier');
    expect(() => parseSkillIdentifier('   ')).toThrow('Invalid skill identifier');
  });

  it('throws on malformed scoped identifier', () => {
    expect(() => parseSkillIdentifier('@')).toThrow('Invalid skill identifier');
    expect(() => parseSkillIdentifier('@publisher')).toThrow('Invalid skill identifier');
    expect(() => parseSkillIdentifier('@/skill')).toThrow('Invalid skill identifier');
  });
});

/**
 * Skill identifier parser
 * Parses skill identifiers like @publisher/skill, ./local/path, or GitHub URLs
 */

export interface SkillIdentifier {
  publisher?: string;
  name: string;
  version?: string;
  source: 'registry' | 'local' | 'github';
  path?: string;
  url?: string;
}

export function parseSkillIdentifier(identifier: string): SkillIdentifier {
  const trimmed = identifier.trim();

  if (!trimmed) {
    throw new Error('Invalid skill identifier: empty string');
  }

  // GitHub URL
  if (trimmed.startsWith('https://github.com/')) {
    const match = trimmed.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)/);
    if (!match) {
      throw new Error('Invalid skill identifier: malformed GitHub URL');
    }
    return {
      publisher: match[1],
      name: match[2],
      version: undefined,
      source: 'github',
      url: trimmed,
    };
  }

  // Local path (relative or absolute)
  if (trimmed.startsWith('./') || trimmed.startsWith('/')) {
    const parts = trimmed.split('/');
    const name = parts[parts.length - 1];
    return {
      publisher: undefined,
      name,
      version: undefined,
      source: 'local',
      path: trimmed,
    };
  }

  // Scoped npm-style identifier @publisher/skill[@version]
  if (trimmed.startsWith('@')) {
    // Match @publisher/name or @publisher/name@version
    const match = trimmed.match(/^@([^/]+)\/([^@]+)(?:@(.+))?$/);
    if (!match || !match[1] || !match[2]) {
      throw new Error('Invalid skill identifier: malformed scoped identifier');
    }
    return {
      publisher: match[1],
      name: match[2],
      version: match[3],
      source: 'registry',
    };
  }

  const cli = process.env.HMA_CHECK_COMMAND ?? `${process.env.HMA_CLI_PREFIX ?? 'hackmyagent'} check`;
  throw new Error(
    'Invalid skill identifier: unrecognized format.\n' +
    'Expected one of:\n' +
    '  @publisher/skill-name    Scoped registry identifier\n' +
    '  https://github.com/...   GitHub URL\n' +
    '  ./path/to/skill          Local file or directory\n' +
    '\nExamples:\n' +
    `  ${cli} @anthropic/code-review\n` +
    `  ${cli} https://github.com/org/skill\n` +
    `  ${cli} ./skills/my-skill.md`
  );
}

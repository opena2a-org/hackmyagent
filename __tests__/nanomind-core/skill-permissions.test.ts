/**
 * Issue #471 — the grammar for a skill's `## Permissions` list.
 *
 * These pin the parser on its own. What the scope analyzer does with a grant
 * is pinned in `skill-permission-scope.test.ts`, through the real compiler.
 */

import { describe, it, expect } from 'vitest';
import {
  MAX_SKILL_PERMISSION_GRANTS,
  isUnboundedGrantValue,
  parseSkillPermissions,
} from '../../src/nanomind-core/compiler/skill-permissions';

/** domain/value/line triples, in file order. */
function grants(md: string): Array<[string, string, number]> {
  return parseSkillPermissions(md).grants.map(g => [g.domain, g.value, g.line]);
}

describe('#471 section headings', () => {
  it.each([
    ['## Permissions'],
    ['### permissions'],
    ['###### PERMISSIONS'],
    ['## Permissions:'],
    ['## Permissions :'],
    ['## Permissions Required'],
    ['## Required Permissions'],
    ['## Required  permissions:'],
    ['   ## Permissions'],
    ['##Permissions'],
    ['## Permissions ##'],
  ])('%j starts a section', heading => {
    expect(grants(`# Skill\n\n${heading}\n- shell: git status\n`)).toEqual([['shell', 'git status', 4]]);
  });

  it.each([
    ['# Permissions'],
    ['    ## Permissions'],
    ['####### Permissions'],
    ['## Permissions and conversation'],
    // Both from published skills: a heading that merely starts with the word.
    ['## Permissions / 权限'],
    ['### Permissions — one JNI sink, one C++ backend'],
    ['## Permission'],
  ])('%j does not start a section', heading => {
    expect(grants(`# Skill\n\n${heading}\n- shell: git status\n`)).toEqual([]);
  });

  it('a section ends at the next heading, with or without a space after the #s', () => {
    const md = [
      '## Permissions',
      '- shell: git status',
      '##Overview',
      '- network: api.example.com',
      '## Permissions',
      '- filesystem: ./data',
      '# Usage',
      '- env: HOME',
    ].join('\n');
    expect(grants(md)).toEqual([
      ['shell', 'git status', 2],
      ['filesystem', './data', 6],
    ]);
  });

  it('YAML frontmatter is not read as markdown', () => {
    const md = ['---', 'name: x', '## Permissions', '- shell: *', '---', '# X', ''].join('\n');
    expect(grants(md)).toEqual([]);
  });
});

describe('#471 items', () => {
  it('reads -, *, + and numbered bullets, and table rows', () => {
    const md = [
      '## Permissions',
      '- filesystem: ./a',
      '* shell: make',
      '+ network: example.com',
      '1. env: HOME',
      '12. database: reports',
      '| Permission | Why |',
      '|---|---|',
      '| browser: docs.example.com | reading docs |',
      '| filesystem | /var/log/*.log | rotation |',
      '**shell:** not a bullet',
    ].join('\n');
    expect(grants(md)).toEqual([
      ['filesystem', './a', 2],
      ['shell', 'make', 3],
      ['network', 'example.com', 4],
      ['env', 'HOME', 5],
      ['database', 'reports', 6],
      ['browser', 'docs.example.com', 9],
      ['filesystem', '/var/log/*.log', 10],
    ]);
  });

  it('the value runs to an unquoted " #" or " (" and keeps its spaces', () => {
    const md = [
      '## Permissions',
      '- shell: * # needed for build',
      '- network: * (egress)',
      '- filesystem: ~/Library/Application Support/My App',
      '- shell: "echo #1 (quoted)" # trailing',
      "- shell: the skill's build (npm)",
      '- filesystem:/',
    ].join('\n');
    expect(grants(md)).toEqual([
      ['shell', '*', 2],
      ['network', '*', 3],
      ['filesystem', '~/Library/Application Support/My App', 4],
      ['shell', 'echo #1 (quoted)', 5],
      ["shell", "the skill's build", 6],
      ['filesystem', '/', 7],
    ]);
  });

  it('reads the markup real skills put around the key', () => {
    const md = [
      '## Permissions',
      '- **filesystem**: For memory_backup, strategy_backtest (read/write CSVs, backups)',
      '- **Filesystem:** read_only — **/*.agent, **/*.md',
      '- `filesystem:read`',
      '- **`filesystem:write`**: Required to write registry JSON files',
      '| `EXEC: cp, mkdir` | Shell commands for taking snapshots |',
      '- `shell:*`',
      '- "shell:cmd=go*"',
    ].join('\n');
    expect(grants(md)).toEqual([
      ['filesystem', 'For memory_backup, strategy_backtest', 2],
      ['filesystem', 'read_only — **/*.agent, **/*.md', 3],
      ['filesystem', 'read', 4],
      ['filesystem', 'write', 5],
      ['shell', 'cp, mkdir', 6],
      ['shell', '*', 7],
      ['shell', 'cmd=go*', 8],
    ]);
  });

  // A published skill's grant, quoted verbatim (one line) from
  // https://github.com/e01n0/skillspec/blob/45c070927d61664c673029a49a891bb35d568cbe/skills/skill-writer/SKILL.md
  // line 39: a glob grant with a multi-word value.
  it('a published glob grant is read whole', () => {
    const line = '- **Filesystem:** read_only — **/*.agent, **/*.md';
    expect(grants(`## Permissions\n\n${line}\n`)).toEqual([['filesystem', 'read_only — **/*.agent, **/*.md', 3]]);
    expect(isUnboundedGrantValue('read_only — **/*.agent, **/*.md')).toBe(false);
  });

  it('a value that declines the capability is not a grant', () => {
    const md = [
      '## Permissions',
      '- network: none',
      '- **Network:** None',
      '| `exec: false` | — | no shell |',
      '| `filesystem: none` | — | no files |',
      '- shell: (none)',
      '- env: n/a',
    ].join('\n');
    expect(grants(md)).toEqual([]);
  });

  it('keys outside the domain list are not capabilities, and nothing of them is kept', () => {
    const md = [
      '## Permissions',
      '- Note: none',
      '- Contact: security@example.com',
      '- See: docs/PERMISSIONS.md',
      `- token: ${['sk', '-live-0000000000000000000000000000'].join('')}`,
      '- logs: /var/log/*.*',
      '- READ: ~/.openclaw/',
      '- shell: make',
    ].join('\n');
    const parsed = parseSkillPermissions(md);
    expect(parsed.grants.map(g => g.domain)).toEqual(['shell']);
    const kept = JSON.stringify(parsed);
    for (const s of ['security@example.com', 'PERMISSIONS.md', 'sk-live', '/var/log', 'Contact', 'Note']) {
      expect(kept).not.toContain(s);
    }
  });
});

describe('#471 fenced blocks', () => {
  it('an example section inside a fence is not read, with ``` or ~~~', () => {
    const md = [
      '# Writing skills',
      '',
      'An example:',
      '',
      '```markdown',
      '## Permissions',
      '- shell: *',
      '```',
      '',
      '~~~~',
      '## Permissions',
      '- network: *',
      '~~~',
      '- filesystem: /',
      '~~~~',
    ].join('\n');
    expect(grants(md)).toEqual([]);
  });

  it('a fence inside a real section hides its lines, not the rest of the section', () => {
    const md = [
      '## Permissions',
      '```yaml',
      '- shell: *',
      '```',
      '- shell: make test',
    ].join('\n');
    expect(grants(md)).toEqual([['shell', 'make test', 5]]);
  });

  it('an unclosed fence hides everything after it', () => {
    expect(grants('## Permissions\n```\n- shell: *\n')).toEqual([]);
  });

  it('a grant spelled the same as an example above it keeps its own line', () => {
    const md = [
      '```',
      '## Permissions',
      '- shell: *',
      '```',
      '## Permissions',
      '- shell: *',
    ].join('\n');
    expect(grants(md)).toEqual([['shell', '*', 6]]);
  });
});

describe('#471 bound and running time', () => {
  function bullets(n: number): string {
    const out = ['# Big', '', '## Permissions'];
    for (let i = 0; i < n; i++) out.push(`- shell: tool-${i}`);
    return out.join('\n') + '\n';
  }

  it(`reads at most ${MAX_SKILL_PERMISSION_GRANTS} grants and counts the rest as unread`, () => {
    const parsed = parseSkillPermissions(bullets(MAX_SKILL_PERMISSION_GRANTS + 50));
    expect(parsed.grants).toHaveLength(MAX_SKILL_PERMISSION_GRANTS);
    expect(parsed.unread).toBe(50);
    // 3 header lines, then one grant per line.
    expect(parsed.firstUnreadLine).toBe(3 + MAX_SKILL_PERMISSION_GRANTS + 1);
    expect(parsed.grants[MAX_SKILL_PERMISSION_GRANTS - 1].line).toBe(3 + MAX_SKILL_PERMISSION_GRANTS);
  });

  it('40,000 bullets parse in linear time', () => {
    const small = bullets(10_000);
    const large = bullets(40_000);
    const time = (md: string) => {
      let best = Infinity;
      for (let r = 0; r < 3; r++) {
        const t0 = performance.now();
        parseSkillPermissions(md);
        best = Math.min(best, performance.now() - t0);
      }
      return best;
    };
    time(small); // warm-up
    const tSmall = time(small);
    const tLarge = time(large);
    console.log(
      `#471 parse: 10,000 bullets (${small.length} bytes) ${tSmall.toFixed(1)}ms; ` +
        `40,000 bullets (${large.length} bytes) ${tLarge.toFixed(1)}ms`,
    );
    expect(parseSkillPermissions(large).unread).toBe(40_000 - MAX_SKILL_PERMISSION_GRANTS);
    // 4x the input: a linear parse is ~4x; the quadratic this replaces was ~16-19x.
    // The floor keeps sub-millisecond noise from failing the ratio.
    expect(tLarge).toBeLessThan(Math.max(tSmall * 8, 50));
    expect(tLarge).toBeLessThan(2_000);
  });

  it('long runs of markup, spaces or hashes stay linear', () => {
    const n = 200_000;
    const md = [
      '## Permissions',
      `- \`shell:${'*'.repeat(n)}x`,
      `## ${' '.repeat(n)}x`,
      `## Permissions${' '.repeat(n)}#x`,
      `| ${'*'.repeat(n)}x | y |`,
    ].join('\n');
    const t0 = performance.now();
    parseSkillPermissions(md);
    isUnboundedGrantValue(`${'*'.repeat(n)}x`);
    isUnboundedGrantValue(`${'/'.repeat(n)}x`);
    expect(performance.now() - t0).toBeLessThan(2_000);
  });
});

describe('#471 unbounded values', () => {
  it.each([
    '*', '**', '*.*', '*:*', '**/*', '/', '/*', '/**', '~', '~/', '~/**', '$HOME', '/Users/*',
    '/home', 'C:\\', 'c:/*', 'file:///', 'https://*', 'all', 'Any', 'unrestricted', 'full access',
    'read/write ALL paths', 'any host',
  ])('%j is unbounded', v => {
    expect(isUnboundedGrantValue(v)).toBe(true);
  });

  it.each([
    '/var/log/*.*', '/var/log/*.log', './data', '.', '~/.openclaw/', '*.example.com', 'api.example.com',
    'git status', 'cp, mkdir', '**/*.md', 'read', 'write:local', 'HYPERSTACK_API_KEY', '/etc', 'cmd=go*',
  ])('%j is bounded', v => {
    expect(isUnboundedGrantValue(v)).toBe(false);
  });
});

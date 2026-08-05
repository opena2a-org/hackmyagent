// The permission vocabulary shared by `detect` and `secure` (#363, #364).
//
// The defect this pins is not a missing spelling, it is a category error:
// `allow` and `deny` values are TEXTUALLY IDENTICAL, and a deny list is
// supposed to be full of wildcards. Measured on the shipped `56263f9`, before
// any change here:
//
//   findPermissionGrant('{"permissions":{"deny":["Read(*.key)","Bash(*)"]}}')
//     -> { line: 1, token: '"Bash(*)"' }
//
// `Read(*.key)` is the rule that stops an agent reading private keys, and the
// remediation printed alongside told the reader to replace it "with the
// specific commands or paths this agent needs". Across 36 real
// `.claude/settings*.json` in one workspace there are 389 deny entries
// containing `*`; that is the surface any text rule is pointed at.
//
// So the deny cases below are not edge cases. They are the reason this module
// exists, and `neverEvaluatesDeny` is the test that must never be deleted.
//
// The narrow-allowlist cases are quoted from those same real files rather than
// invented — 31 of the 148 real allow entries are colon-prefix Bash spellings
// that Claude Code writes itself. Re-flagging one of those re-opens #299 for
// the fourth time.
import { describe, it, expect } from 'vitest';
import {
  classifyPermissionEntry,
  isPermissionSyntax,
  walkConfigForGrants,
} from '../../src/scanner/permission-vocabulary';

/** Real allow entries, read out of `.claude/settings*.json` files on disk. */
const REAL_NARROW_ALLOW_ENTRIES = [
  'Bash(npm test)', 'Read(src/**)', 'Bash(ls:*)', 'Bash(find:*)', 'Bash(rm:*)',
  'Bash(brew list:*)', 'Bash(mdfind:*)', 'Bash(launchctl:*)', 'Bash(defaults read:*)',
  'Bash(pkill:*)', 'Bash(git add:*)', 'Bash(git commit:*)', 'Bash(chmod:*)',
  'Bash(npm run build)', 'Bash(npm run *)', 'Read(package.json)', 'Read(./src/**)',
  'Write(dist/**)', 'Edit(src/**/*.ts)', 'WebFetch(domain:example.com)',
  'mcp__github__get_issue', 'mcp__playwright__browser_click',
];

describe('a deny entry is never a grant (#364)', () => {
  it('never descends into a deny list, however many wildcards it holds', () => {
    const settings = {
      permissions: {
        deny: ['Read(*.key)', 'Read(*.env)', 'Read(*.pem)', 'Bash(rm -rf *)', 'Bash(*)', '*'],
      },
    };
    expect(walkConfigForGrants(settings)).toBeUndefined();
  });

  it.each(['deny', 'denied', 'denyList', 'disallow', 'blockedTools', 'ignore', 'ask'])(
    'prunes %s without evaluating it',
    (key) => {
      expect(walkConfigForGrants({ permissions: { [key]: ['Bash(*)', '*'] } })).toBeUndefined();
    },
  );

  // Two layers keep deny entries out, and this pins the second one.
  //
  // The layer that does the everyday work is the grant-key allowlist: a plain
  // `deny: ["Bash(*)"]` is a list of strings under a key nothing evaluates, so
  // it stays quiet even with the prune removed. The prune is what stops a
  // GRANT KEY NESTED UNDER a deny key from being read, which is the only shape
  // that can reach past the allowlist. Deleting `deny` from the prune list
  // makes exactly this test fail and no other.
  it('does not evaluate a grant key nested underneath a deny key', () => {
    expect(walkConfigForGrants({ permissions: { deny: { allow: ['Bash(*)'] } } })).toBeUndefined();
    expect(walkConfigForGrants({ rules: { blockedTools: { allowedTools: ['*'] } } })).toBeUndefined();
  });

  it('reports the allow entry and not the deny entry when a file carries both', () => {
    const settings = {
      permissions: { deny: ['Read(*.key)', 'Bash(*)'], allow: ['Bash(*:*)'] },
    };
    expect(walkConfigForGrants(settings)?.entry).toBe('Bash(*:*)');
  });

  // The specific shape that made the previous approach unfixable: the two keys
  // hold the same string, so only the key can decide.
  it('splits on the key alone when allow and deny hold the identical value', () => {
    expect(walkConfigForGrants({ permissions: { allow: ['Bash(*)'] } })).toBeDefined();
    expect(walkConfigForGrants({ permissions: { deny: ['Bash(*)'] } })).toBeUndefined();
  });

  // D1 in #364: the same document with two keys reordered produced two
  // different verdicts, because `deny` was itself the suppressing token.
  it('gives the same verdict whatever order the keys appear in', () => {
    const a = walkConfigForGrants({ permissions: { allow: ['Bash(*)'], deny: [] } });
    const b = walkConfigForGrants({ permissions: { ask: [], deny: [], allow: ['Bash(*)'] } });
    expect(a?.entry).toBe('Bash(*)');
    expect(b?.entry).toBe('Bash(*)');
  });
});

describe('a narrow allowlist is a restriction, not a grant (#299)', () => {
  it.each(REAL_NARROW_ALLOW_ENTRIES)('stays quiet on %j', (entry) => {
    expect(classifyPermissionEntry(entry)).toBeUndefined();
  });

  it('stays quiet on a whole real allow list', () => {
    expect(walkConfigForGrants({ permissions: { allow: REAL_NARROW_ALLOW_ENTRIES } })).toBeUndefined();
  });
});

describe('the bound is tool-specific, so the colon rule cannot be (#364)', () => {
  // A command name bounds a Bash entry exactly as a path prefix bounds a Read
  // entry. A scheme name bounds nothing.
  it('treats Bash(git commit:*) as bounded and WebFetch(domain:*) as unbounded', () => {
    expect(classifyPermissionEntry('Bash(git commit:*)')).toBeUndefined();
    expect(classifyPermissionEntry('WebFetch(domain:*)')).toBeDefined();
  });

  it.each([
    ['Read(src/**)', false], ['Read(./src/**)', false], ['Read(package.json)', false],
    ['Read(**)', true], ['Read(/**)', true], ['Read(//**)', true], ['Read(~/**)', true],
    ['Read(*)', true], ['Read(*.key)', true], ['Write(/**)', true], ['Glob(**)', true],
  ])('path %s unbounded=%s', (entry, unbounded) => {
    expect(Boolean(classifyPermissionEntry(entry))).toBe(unbounded);
  });

  it.each([
    ['Bash(npm test)', false], ['Bash(npm run *)', false], ['Bash(git add:*)', false],
    ['Bash(rm -rf *)', false], ['Bash(*)', true], ['Bash(*:*)', true], ['Bash( * )', true],
  ])('command %s unbounded=%s', (entry, unbounded) => {
    expect(Boolean(classifyPermissionEntry(entry))).toBe(unbounded);
  });

  // `Bash(rm -rf *)` above stays quiet HERE on purpose: `rm` bounds it, so it
  // is not a broad grant. It is a destructive one, which is CLAUDE-003's
  // question, asked on the same allow list.
  it('treats a delegating command as no bound at all, because its argument is another command', () => {
    expect(classifyPermissionEntry('Bash(sudo *)')).toBeDefined();
    expect(classifyPermissionEntry('Bash(sh -c *)')).toBeDefined();
    expect(classifyPermissionEntry('Bash(xargs *)')).toBeDefined();
    expect(classifyPermissionEntry('Bash(bash:*)')).toBeDefined();
    // Still one specific command, so still bounded.
    expect(classifyPermissionEntry('Bash(sudo apt install ripgrep)')).toBeUndefined();
  });

  // Found by running the classifier over 36 real `.claude/settings*.json`
  // rather than over fixtures: the first draft asked whether the argument
  // contained any GLOB metacharacter, and `{}` is xargs' placeholder. These are
  // complete literal commands with no wildcard, and flagging one is #299 again.
  it.each([
    "Bash(xargs -I {} sh -c 'echo \"=== {} ===\" && cat {}')",
    'Bash(sh -c \'test -f package.json && echo yes\')',
    'Bash(env NODE_ENV=test npm run build)',
    'Bash(find . -name "*.ts" -print)',
    // Also real, and also quiet: `xargs` delegates to `dirname`, which bounds
    // it. The first draft asked whether the whole remainder held a wildcard,
    // which read the trailing `*` as if it were in the command-name position.
    'Bash(xargs dirname *)',
    // A delegator with nothing to delegate to is just one command. `Bash(env)`
    // prints the environment; it is not a grant of everything. Also real — the
    // second draft flagged it by treating "no delegated command" as unbounded.
    'Bash(env)',
    'Bash(sudo)',
  ])('stays quiet on the literal command %j', (entry) => {
    expect(classifyPermissionEntry(entry)).toBeUndefined();
  });

  it('still fires when the delegated command itself is the wildcard', () => {
    expect(classifyPermissionEntry('Bash(xargs *)')).toBeDefined();
    expect(classifyPermissionEntry('Bash(sudo *)')).toBeDefined();
    expect(classifyPermissionEntry('Bash(sh -c *)')).toBeDefined();
    expect(classifyPermissionEntry('Bash(env *)')).toBeDefined();
  });
});

describe('a bare tool name is the broadest grant of that tool (#364)', () => {
  it.each(['Bash', 'Read', 'Write', 'Edit', 'Glob', 'Grep', 'WebFetch'])(
    'flags bare %s, which has a scoped form',
    (tool) => {
      const grant = classifyPermissionEntry(tool);
      expect(grant, `bare ${tool} grants every use of it`).toBeDefined();
      expect(grant!.fix).toContain('(');
    },
  );

  // A finding whose remediation does not exist is a dead end, and the project
  // standard forbids one. These tools have no scoped spelling, so bare is the
  // only spelling there is.
  it.each(['WebSearch', 'Task', 'TodoWrite', 'Agent'])(
    'stays quiet on bare %s, which has no scoped form to recommend',
    (tool) => {
      expect(classifyPermissionEntry(tool)).toBeUndefined();
    },
  );
});

describe('spellings that were silent before this landed (#363, #364)', () => {
  it.each([
    ['*', 'every tool'],
    ['Bash(*:*)', 'the published any-command-any-argument spelling'],
    ['mcp__*', 'every MCP server'],
    ['Read(//**)', 'a doubled root'],
    ['Read(/**)', 'the filesystem root'],
    ['WebFetch(domain:*)', 'any host'],
    ['Bash(sudo *)', 'root, with any argument'],
  ])('flags %j (%s)', (entry) => {
    expect(classifyPermissionEntry(entry)).toBeDefined();
  });

  it.each([
    [{ permissions: { defaultMode: 'bypassPermissions' } }, 'defaultMode: bypassPermissions'],
    [{ permissions: { defaultMode: 'acceptEdits' } }, 'defaultMode: acceptEdits'],
    [{ permissions: { additionalDirectories: ['/'] } }, '/'],
    [{ enableAllProjectMcpServers: true }, 'enableAllProjectMcpServers: true'],
    [{ dangerouslySkipPermissions: true }, 'dangerouslySkipPermissions: true'],
    [{ permissions: { allow: '*' } }, '*'],
  ])('flags the settings-level grant %#', (doc, entry) => {
    expect(walkConfigForGrants(doc)?.entry).toBe(entry);
  });

  it('leaves the restrictive defaultMode values alone', () => {
    for (const mode of ['default', 'plan', 'ask']) {
      expect(walkConfigForGrants({ permissions: { defaultMode: mode } })).toBeUndefined();
    }
  });

  it('leaves a scoped additionalDirectories alone', () => {
    expect(walkConfigForGrants({ permissions: { additionalDirectories: ['../shared', '/Users/me/project'] } }))
      .toBeUndefined();
  });

  it('does not read a false boolean as a grant', () => {
    expect(walkConfigForGrants({ enableAllProjectMcpServers: false })).toBeUndefined();
    // A string is not a boolean. An env var named AUTO_APPROVE is not a
    // permission key, and reading it as one is how a scanner starts reporting
    // findings on ordinary configuration.
    expect(walkConfigForGrants({ env: { AUTO_APPROVE: 'true' } })).toBeUndefined();
  });
});

describe('what this deliberately does not do', () => {
  // Recorded as a decision, not discovered as a bug: the walk is an allowlist
  // of grant keys, so an unrecognised key stays silent even holding `Bash(*)`.
  // Three releases have been blocked by this module's false positives and none
  // by its misses. A new schema key is a review trigger in the council ledger.
  it('stays silent on a grant under a key it does not recognise', () => {
    expect(walkConfigForGrants({ someFutureKey: ['Bash(*)'] })).toBeUndefined();
  });

  it('does not read a tools manifest as a grant', () => {
    expect(walkConfigForGrants({ tools: ['Bash', 'Read'] })).toBeUndefined();
  });

  it('stops descending before a deeply nested document can cost anything', () => {
    let doc: Record<string, unknown> = { permissions: { allow: ['Bash(*)'] } };
    for (let i = 0; i < 40; i++) doc = { nested: doc };
    expect(walkConfigForGrants(doc)).toBeUndefined();
  });
});

describe('every grant names a replacement that exists', () => {
  const grants = [
    classifyPermissionEntry('Bash(*)'),
    classifyPermissionEntry('Read(//**)'),
    classifyPermissionEntry('WebFetch(domain:*)'),
    classifyPermissionEntry('Read'),
    classifyPermissionEntry('mcp__*'),
    classifyPermissionEntry('*'),
    walkConfigForGrants({ permissions: { defaultMode: 'bypassPermissions' } }),
    walkConfigForGrants({ permissions: { additionalDirectories: ['/'] } }),
    walkConfigForGrants({ enableAllProjectMcpServers: true }),
  ];

  it.each(grants.map((g, i) => [i, g] as const))('grant %i carries a concrete fix', (_i, grant) => {
    expect(grant).toBeDefined();
    // Not "be more specific": the fix must name a scoped permission spelling,
    // an MCP entry template, a concrete value to set, or the key to remove.
    expect(grant!.fix).toMatch(/\w+\([^)]+\)|mcp__<server>__<tool>|"default"|false|project directory/);
    expect(grant!.reason.length).toBeGreaterThan(10);
  });
});

describe('isPermissionSyntax separates entries the tool understands from prose', () => {
  it.each(['Bash(*)', 'Read(src/**)', 'Bash', '*', 'mcp__github__get_issue'])(
    'accepts %j',
    (e) => expect(isPermissionSyntax(e)).toBe(true),
  );

  // A real entry, from a real `~/.claude/settings.json`. It grants nothing to
  // the tool, because no tool has that name — but the author wrote it under
  // `allow`, so it is still a statement of what they meant to permit.
  it.each([
    'Bash - Allow all bash commands without approval',
    'Read - Allow reading any file',
    '# allow everything',
  ])('rejects %j', (e) => expect(isPermissionSyntax(e)).toBe(false));
});

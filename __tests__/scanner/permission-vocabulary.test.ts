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

  // NESTED, deliberately. The flat shape `{deny: ['Bash(*)']}` passes with the
  // prune list entirely DELETED — `deny` is not a grant key, so the grant-key
  // allowlist alone keeps it quiet, and the test measured nothing about the
  // prune it was named for. Only the nested shape reaches past that layer, so
  // only the nested shape pins each spelling.
  it.each([
    'deny', 'denied', 'denyList', 'disallow', 'disallowed', 'disallowedTools',
    'block', 'blocked', 'blocklist', 'blockedTools', 'forbid', 'forbidden',
    'never', 'exclude', 'excluded', 'ignore', 'ignored', 'reject', 'rejected', 'ask',
  ])('prunes %s without evaluating what is under it', (key) => {
    expect(walkConfigForGrants({ [key]: ['Bash(*)', '*'] })).toBeUndefined();
    expect(walkConfigForGrants({ [key]: { allow: ['Bash(*)'] } })).toBeUndefined();
    expect(walkConfigForGrants({ rules: { [key]: { allowedTools: ['*'] } } })).toBeUndefined();
  });

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
    ['Read(*)', true], ['Write(/**)', true], ['Glob(**)', true],
    // Extension-bounded, so bounded — see the note below.
    ['Read(*.key)', false],
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

describe('defects an adversarial review found, each pinned (#364)', () => {
  // A 471-byte YAML alias chain hung `detect` for 28 seconds. js-yaml resolves
  // aliases to SHARED references, so a tiny document describes an object graph
  // with exponentially many paths, and the depth cap bounds depth rather than
  // breadth. Re-visiting a node cannot change the answer.
  it('walks a shared-reference graph once, not once per path', () => {
    let level: unknown = { leaf: 'x' };
    for (let d = 0; d < 10; d++) {
      const shared = level;
      level = { a: shared, b: shared, c: shared, d: shared, e: shared, f: shared };
    }
    const started = performance.now();
    expect(walkConfigForGrants({ permissions: { allow: ['Bash(npm test)'] }, blob: level })).toBeUndefined();
    // Exponential: 28s measured at nine levels. Linear: single-digit ms.
    expect(performance.now() - started).toBeLessThan(500);
  });

  // `alwaysAllow`/`autoApprove` hold MCP TOOL names, not permission syntax, and
  // the official MCP fetch server's tool is literally called `fetch`. Reading
  // it as bare `WebFetch` produced a HIGH whose fix — `fetch(domain:example.com)`
  // — is not valid in any MCP schema.
  it('does not read an MCP tool name as a bare tool grant', () => {
    const continueConfig = {
      mcpServers: { fetch: { command: 'uvx', args: ['mcp-server-fetch'], alwaysAllow: ['fetch'] } },
    };
    expect(walkConfigForGrants(continueConfig)).toBeUndefined();
    expect(walkConfigForGrants({ autoApprove: ['read', 'write', 'list_directory'] })).toBeUndefined();
    expect(walkConfigForGrants({ allowlist: ['read', 'grep', 'ls'] })).toBeUndefined();
    // A wildcard under those keys is still a wildcard, whatever the schema.
    expect(walkConfigForGrants({ mcpServers: { x: { alwaysAllow: ['*'] } } })).toBeDefined();
  });

  // A literal extension bounds a glob. The replacement previously recommended
  // for `Edit(**/*.md)` was `Edit(src/**)`, which grants every file type under
  // `src/` — wider than the entry it was flagging.
  it.each(['Edit(**/*.md)', 'Read(**/*.ts)', 'Glob(*.json)'])(
    'treats the file extension in %j as a bound',
    (entry) => expect(classifyPermissionEntry(entry)).toBeUndefined(),
  );

  it('still flags a path glob with no extension and no prefix', () => {
    expect(classifyPermissionEntry('Read(**)')).toBeDefined();
    expect(classifyPermissionEntry('Read(/**)')).toBeDefined();
  });

  // The sharp edge of the extension rule, stated rather than hidden:
  // `Read(*.key)` in an ALLOW list now stays quiet here. It is extension-bounded
  // like `Edit(**/*.md)`, and this check answers "how broad is this grant", not
  // "how sensitive is what it reaches". A private-key allowlist is a credential
  // question for a different check. In the wild `Read(*.key)` is a DENY entry —
  // it is one of the 389 wildcard deny entries measured across 36 real files —
  // and reporting deny entries is the defect this whole module exists to remove.
  it('leaves an extension-bounded entry to the check that owns sensitivity', () => {
    expect(classifyPermissionEntry('Read(*.key)')).toBeUndefined();
  });

  // The shared reason string was factually wrong for this key: it approves MCP
  // SERVERS without the trust prompt; tool calls still go through permissions.
  it('describes each boolean grant by what it actually does', () => {
    const mcp = walkConfigForGrants({ enableAllProjectMcpServers: true });
    expect(mcp?.reason).toContain('MCP server');
    expect(mcp?.reason).not.toContain('every tool call');
    expect(walkConfigForGrants({ dangerouslySkipPermissions: true })?.reason).toContain('every tool call');
  });

  it('collects entries out of a nested array under a grant key', () => {
    expect(walkConfigForGrants({ permissions: { allow: [['Bash(*)']] } })).toBeDefined();
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

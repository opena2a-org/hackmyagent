/**
 * #463 — the MCP server must not read or write outside the roots it was started
 * with, and must not offer the host model a file reader or a write flag at all.
 *
 * Measured on `c982b58` against a real stdio MCP session whose cwd was a small
 * project directory. All three read escapes returned the out-of-root file's full
 * contents with `isError` absent: an absolute path, a `../` traversal, and a
 * symlink inside the cwd pointing out of it. `deep_scan` did the same for a whole
 * directory, `benchmark` assessed one, and `scan {fix:true}` created
 * `.hackmyagent-backup/…` and rewrote `.gitignore` in a tree the server was never
 * pointed at (md5 `3d10912d…` → `c0498605…`).
 *
 * The tests below drive `handleToolCall` against the real filesystem rather than
 * asserting about it. `handleToolCall` was extracted from the `startMcpServer`
 * closure for exactly the reason the `#285` comment in `src/mcp-server.ts`
 * records: handlers built inside a closure that needs a transport are
 * unreachable from the suite, which is how an unconfined file reader shipped for
 * twenty-one minor versions with a green test run.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  handleToolCall,
  TOOL_DEFINITIONS_FOR_TEST,
  fixRequestedNote,
  unknownToolText,
} from '../../src/mcp-server';
import { resolveRoots, resolveWithinRoots, describeRootRefusal } from '../../src/mcp/roots';

let tmp: string;
let root: string;
let outside: string;

beforeAll(() => {
  // `realpathSync` because macOS puts `mkdtemp` under a symlinked `/var`, and a
  // containment check that compares unresolved paths refuses every legitimate
  // path under it. That over-correction is #270's recorded failure mode.
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hma-463-')));
  root = path.join(tmp, 'project');
  outside = path.join(tmp, 'elsewhere');
  fs.mkdirSync(root, { recursive: true });
  fs.mkdirSync(outside, { recursive: true });

  fs.writeFileSync(path.join(root, '.gitignore'), 'node_modules\n');
  fs.writeFileSync(
    path.join(root, 'mcp.json'),
    JSON.stringify({ mcpServers: { fs: { command: 'npx', args: ['-y', 'server-filesystem', '/'] } } }),
  );
  fs.writeFileSync(path.join(outside, 'app.config'), 'DB=postgres://u:CANARY-463@h/db\n');
  fs.symlinkSync(path.join(outside, 'app.config'), path.join(root, 'link-out.config'));

  // The fixture the entry-path tests could never exercise. `link-out.config` is
  // not a name discovery looks for, and it was passed AS the directory argument
  // — which is the entry path, and the entry path was already closed. The escape
  // that was still open ran through the WALK: a link at a real discovery
  // basename, with the ROOT ITSELF as the argument.
  fs.writeFileSync(path.join(outside, 'private.md'), '# private\nCANARY-463-WALK-do-not-leak\n');
  fs.symlinkSync(path.join(outside, 'private.md'), path.join(root, 'CLAUDE.md'));
});

afterAll(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

/** Every registered tool that takes a path, derived from the registry itself. */
const PATH_TOOLS = TOOL_DEFINITIONS_FOR_TEST.filter((t) =>
  Object.keys(t.inputSchema.properties ?? {}).includes('directory'),
).map((t) => t.name);

describe('#463 root confinement', () => {
  it('registers at least the three path-taking tools, so the table below is not empty', () => {
    // A table-driven test over an empty table passes and proves nothing. This is
    // the guard against that, and it also fails if a later tool drops its path
    // parameter without anyone noticing.
    expect(PATH_TOOLS).toEqual(
      expect.arrayContaining(['hackmyagent_scan', 'hackmyagent_deep_scan', 'hackmyagent_benchmark']),
    );
  });

  for (const tool of PATH_TOOLS) {
    describe(tool, () => {
      it('refuses an absolute path outside the root', async () => {
        const res = await handleToolCall(tool, { directory: outside }, [root]);
        expect(res.isError).toBe(true);
        expect(res.content[0].text).toContain('Path outside the allowed root');
        expect(res.content[0].text).not.toContain('CANARY-463');
      });

      it('refuses a `..` traversal', async () => {
        const res = await handleToolCall(tool, { directory: '../elsewhere' }, [root]);
        expect(res.isError).toBe(true);
        expect(res.content[0].text).toContain('Path outside the allowed root');
      });

      it('refuses a symlink inside the root that points out of it', async () => {
        const res = await handleToolCall(tool, { directory: 'link-out.config' }, [root]);
        expect(res.isError).toBe(true);
        expect(res.content[0].text).not.toContain('CANARY-463');
      });

      it('refuses everything when no root is configured, and names the fix', async () => {
        const res = await handleToolCall(tool, { directory: root }, []);
        expect(res.isError).toBe(true);
        expect(res.content[0].text).toContain('No project root is configured');
        expect(res.content[0].text).toContain('init-mcp --root');
      });

      // The over-correction guard. A confinement that refuses the root itself
      // would pass every test above while making the tool useless.
      it('still scans the root itself, addressed absolutely and as "."', async () => {
        const abs = await handleToolCall(tool, { directory: root }, [root]);
        expect(abs.isError).toBeUndefined();
        const dot = await handleToolCall(tool, { directory: '.' }, [root]);
        expect(dot.isError).toBeUndefined();
      });
    });
  }
});

describe('#463 the write flag is gone, not hidden', () => {
  it('performs no write when `fix` is passed anyway, and says so', async () => {
    const gitignore = path.join(root, '.gitignore');
    const before = fs.readFileSync(gitignore, 'utf-8');
    const entriesBefore = fs.readdirSync(root).sort();

    // A model passing a property that is not in the schema is the case that
    // matters: deleting the schema property alone would leave the capability
    // live and undocumented.
    const res = await handleToolCall('hackmyagent_scan', { directory: root, fix: true }, [root]);

    // Assert the FILESYSTEM, not the response text. A test that only checks the
    // note passes even if the write still happens.
    expect(fs.readFileSync(gitignore, 'utf-8')).toBe(before);
    expect(fs.readdirSync(root).sort()).toEqual(entriesBefore);
    expect(res.content[0].text).toContain('"fix" was requested and was not applied');
    expect(res.content[0].text).toContain('secure --fix');
    // The scan itself still ran — a refusal that also drops the results would be
    // a different defect.
    expect(res.content[0].text).toContain('Score:');
  });

  it('never advertises `fix` in the tool schema', () => {
    for (const tool of TOOL_DEFINITIONS_FOR_TEST) {
      expect(Object.keys(tool.inputSchema.properties ?? {})).not.toContain('fix');
    }
  });

  it('discloses a model-supplied suppression list instead of applying it silently', async () => {
    const res = await handleToolCall(
      'hackmyagent_scan',
      { directory: root, ignore: 'CRED-001,GIT-002' },
      [root],
    );
    expect(res.content[0].text).toContain('CRED-001');
    expect(res.content[0].text).toMatch(/suppressed at this tool's request/);
  });
});

describe('#463 the arbitrary-file reader is gone', () => {
  it('is not registered', () => {
    expect(TOOL_DEFINITIONS_FOR_TEST.map((t) => t.name)).not.toContain('hackmyagent_analyze_file');
  });

  // #502 — the 0.29.0 redirect stub is gone as of 0.31.0. The name now falls
  // through to the server's `default:` arm like any other unknown tool.
  it('falls through to the standard unknown-tool response, not the removal stub', async () => {
    const res = await handleToolCall('hackmyagent_analyze_file', { file: path.join(root, '.gitignore') }, [root]);

    // `isError` alone cannot tell the two apart: the stub set it and so does
    // `default:`. The text is the only thing that separates them.
    expect(res.isError).toBe(true);
    // The stable half of `unknownToolText`. The tool-name sentence it also emits
    // is generated from TOOL_DEFINITIONS, so pinning the whole string would go
    // red on any future tool addition.
    expect(res.content[0].text).toContain('Unknown tool: hackmyagent_analyze_file');
    expect(res.content[0].text).toContain('tools/list');
    // Removed, not reworded — the stub's redirect must be absent.
    expect(res.content[0].text).not.toContain('was removed in hackmyagent 0.29.0');
    // Not a crash: `handleToolCall`'s catch prefixes thrown errors with `Error:`.
    expect(res.content[0].text).not.toContain('Error:');
    // Still reads nothing. `.gitignore` in the fixture holds `node_modules`.
    expect(res.content[0].text).not.toContain('node_modules');
  });

  it('no longer ships the .env credential-enumeration guidance anywhere in the tool surface', () => {
    const surface = JSON.stringify(TOOL_DEFINITIONS_FOR_TEST);
    expect(surface).not.toContain('Check for ALL credential types');
  });
});

describe('#463 roots policy', () => {
  it('refuses the filesystem root even when passed explicitly', async () => {
    const outcome = await resolveRoots([path.parse(tmp).root]);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.refusal.kind).toBe('root-too-broad');
      expect(describeRootRefusal(outcome.refusal)).toContain('MCP-001');
    }
  });

  it('refuses a home directory even when passed explicitly', async () => {
    const outcome = await resolveRoots([tmp], { homedir: tmp });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.refusal.kind).toBe('root-too-broad');
  });

  it('never falls back to the inherited working directory', async () => {
    const outcome = await resolveRoots([], { cwd: root });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) expect(outcome.refusal.kind).toBe('no-root-configured');
  });

  it('accepts several roots and resolves a path in the second one', async () => {
    const other = path.join(tmp, 'second');
    fs.mkdirSync(other, { recursive: true });
    const outcome = await resolveRoots([root, other]);
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      const resolved = await resolveWithinRoots(outcome.roots, other);
      expect(resolved.ok).toBe(true);
    }
  });

  it('tells the model the boundary is not negotiable from inside the session', async () => {
    const refused = await resolveWithinRoots([root], outside);
    expect(refused.ok).toBe(false);
    if (!refused.ok) {
      const text = describeRootRefusal(refused.refusal);
      // Whitespace-normalised: the assertion is about what the sentence SAYS,
      // and the literal wraps across a line in the message.
      const flat = text.replace(/\s+/g, ' ');
      // Without this sentence a capable model reads the error as an obstacle and
      // tries the next spelling instead of telling the user (CPO).
      expect(flat).toContain('cannot be changed from inside this session');
      expect(text).toContain(root);
    }
  });
});

describe('#463 no dead ends', () => {
  it('names the available tools on an unknown one', () => {
    const text = unknownToolText('hackmyagent_analyse_file');
    expect(text).toContain('hackmyagent_scan');
    expect(text).toContain('tools/list');
  });

  it('cites a runnable rollback and fix command when `fix` is declined', () => {
    const note = fixRequestedNote('/tmp/x');
    expect(note).toContain('hackmyagent secure --fix /tmp/x');
    expect(note).toContain('hackmyagent rollback /tmp/x');
  });

  it('quotes a hostile directory name instead of splicing it into the command', () => {
    // #273 — a space retargets the command at a path that does not exist, and
    // `$(id)` runs on paste. The repo's source gate catches the shape; this
    // catches the behaviour.
    const note = fixRequestedNote('/tmp/my project$(id)');
    expect(note).not.toContain('--fix /tmp/my project$(id)');
    expect(note).toMatch(/--fix '.*'/);
  });

  it('quotes every root in the grant command the refusal offers', async () => {
    const hostile = path.join(tmp, 'a b');
    fs.mkdirSync(hostile, { recursive: true });
    const refused = await resolveWithinRoots([hostile], outside);
    expect(refused.ok).toBe(false);
    if (!refused.ok) {
      const text = describeRootRefusal(refused.refusal);
      const grantLine = text.split('\n').find((l) => l.includes('init-mcp'))!;
      expect(grantLine).not.toMatch(/--root \S*a b/);
    }
  });
});

describe('#463 confinement holds through the walk, not only at the entry path', () => {
  // Every one of these asks about a path that IS inside the root. The question
  // is never "may I scan here" — it is "whose bytes came back".
  for (const tool of PATH_TOOLS) {
    it(`${tool}: scanning the root returns nothing from a link that leaves it`, async () => {
      const res = await handleToolCall(tool, { directory: root }, [root]);
      const text = JSON.stringify(res);
      // The assertion the old test was missing entirely: it checked isError and
      // never looked at what the response CONTAINED.
      expect(text).not.toContain('CANARY-463-WALK-do-not-leak');
      expect(text).not.toContain('CANARY-463');
    });
  }

  it('still reads a file that is genuinely inside the root', async () => {
    // Without this, confining everything to nothing would pass the test above.
    const res = await handleToolCall('hackmyagent_deep_scan', { directory: root }, [root]);
    expect(JSON.stringify(res)).toContain('mcp.json');
  });

  it('says which files it withheld instead of dropping them silently', async () => {
    const res = await handleToolCall('hackmyagent_deep_scan', { directory: root }, [root]);
    const text = res.content?.[0]?.text ?? '';
    // Inside the JSON, not appended after it: a note concatenated onto
    // `JSON.stringify` made the payload unparseable for every client exactly
    // when something was withheld.
    const parsed = JSON.parse(text) as { notRead?: Array<{ path: string }> };
    expect(parsed.notRead?.map((n) => n.path)).toContain('CLAUDE.md');
    // Naming the file must not mean printing its contents.
    expect(text).not.toContain('CANARY-463');
  });
});

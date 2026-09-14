/**
 * HMA-39 — the MCP confinement witness the 0.33.0 release gates on, driven the
 * way a HOST drives it.
 *
 * The nine in-process files in this directory exercise `handleToolCall` and the
 * roots policy directly. None of them ever spawned the BUILT server over the
 * transport a host model uses, which is precisely how the original unconfined
 * reader shipped for twenty-one minor versions with a green run (#285, #463).
 * This file closes that class: a real `StdioClientTransport` session against
 * `dist/cli.js mcp-serve --root <fixture>`, the same entry `init-mcp` writes
 * into a client config.
 *
 * AC1 — every registered path-taking tool refuses the three escape shapes
 * (absolute, `../`, symlink-out) over the wire, each refusal naming the granted
 * root, while an in-root control still scans and reports a planted finding.
 *
 * AC2 — the same session leaves the world as it found it (fixture tree hash
 * unchanged, HOME writes enumerated against a committed allowlist), a
 * too-broad `--root` is refused at initialisation and that refusal is what the
 * transport returns, a second directory passed only in a tool argument grants
 * nothing, and a positive control proves the escape assertions bite: with
 * `resolveWithinRoots` replaced by an identity resolver in a SCRATCH copy of
 * dist/ (never the tree), the same escape calls come back unconfined.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import { createRequire } from 'module';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';

const REPO = path.resolve(__dirname, '../..');

/**
 * AC2's committed HOME-write allowlist. Measured over the delivered session
 * (quoted in the delivery report): a session that runs all three tools writes
 * exactly two files under a fresh HOME — the telemetry opt-in marker and the
 * NanoMind integrity event log. Any new write under HOME fails this witness
 * rather than passing unseen; if a future change legitimately writes there, it
 * must be added HERE, in review.
 */
const HOME_WRITE_ALLOWLIST: string[] = [
  '.config',
  '.config/opena2a',
  '.config/opena2a/telemetry.json',
  '.nanomind',
  '.nanomind/integrity-events.jsonl',
];

const PATH_TOOLS = ['hackmyagent_scan', 'hackmyagent_deep_scan', 'hackmyagent_benchmark'] as const;

type ToolText = { content: Array<{ type: string; text: string }>; isError?: boolean };

let tmp: string;
let root: string;
let outside: string;
let second: string;
let childHome: string;
let treeHashBefore: string;

let client: Client;
let sessionClosed = false;

/** Sorted relative paths plus contents (files hashed, symlink targets literal). */
function hashTree(base: string, exclude: Set<string>): string {
  const lines: string[] = [];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(dir, entry.name);
      const rel = path.relative(base, full);
      if (exclude.has(rel.split(path.sep)[0])) continue;
      if (entry.isSymbolicLink()) {
        lines.push(`L ${rel} -> ${fs.readlinkSync(full)}`);
      } else if (entry.isDirectory()) {
        lines.push(`D ${rel}`);
        walk(full);
      } else {
        const digest = crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex');
        lines.push(`F ${rel} ${digest}`);
      }
    }
  };
  walk(base);
  return crypto.createHash('sha256').update(lines.join('\n')).digest('hex');
}

/** Every path that exists under `base`, relative and sorted — dirs and files. */
function listCreatedPaths(base: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      out.push(path.relative(base, full));
      if (entry.isDirectory() && !entry.isSymbolicLink()) walk(full);
    }
  };
  walk(base);
  return out.sort();
}

/** A host-shaped session against the built CLI. HOME is caller-controlled. */
async function startSession(cliPath: string, rootArgs: string[], home: string): Promise<Client> {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [cliPath, 'mcp-serve', ...rootArgs.flatMap((r) => ['--root', r])],
    cwd: REPO,
    env: {
      PATH: process.env.PATH ?? '',
      HOME: home,
      // The suite-wide hermeticity contract (vitest.setup.ts): without it the
      // scan merges whatever AI-infra directories exist in the developer HOME.
      OPENA2A_CORPUS_DETERMINISTIC: '1',
    },
  });
  const c = new Client({ name: 'hma-39-witness', version: '0.0.0' });
  await c.connect(transport);
  return c;
}

async function call(c: Client, name: string, args: Record<string, unknown>): Promise<ToolText> {
  return (await c.callTool({ name, arguments: args })) as ToolText;
}

beforeAll(async () => {
  // AC1: a missing dist/cli.js is an ERROR naming the build step, never a
  // skip. `assertDistFresh` also refuses a stale build, which for a spawn
  // witness is worse than a missing one (#285).
  assertDistFresh();

  // `realpathSync` because macOS puts `mkdtemp` under a symlinked `/var`, and
  // a containment check comparing unresolved paths would refuse every
  // legitimate path under it (#270's recorded over-correction).
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hma39-witness-')));
  root = path.join(tmp, 'project');
  outside = path.join(tmp, 'elsewhere');
  second = path.join(tmp, 'second-project');
  childHome = path.join(tmp, 'child-home');
  for (const d of [root, outside, second, childHome]) fs.mkdirSync(d, { recursive: true });

  // The planted finding: an MCP server granted `/`, which the scanner reports
  // as MCP-001 (HIGH). The control call below must surface it over the wire.
  fs.writeFileSync(
    path.join(root, 'mcp.json'),
    JSON.stringify({ mcpServers: { fs: { command: 'npx', args: ['-y', 'server-filesystem', '/'] } } }),
  );
  fs.writeFileSync(path.join(root, '.gitignore'), 'node_modules\n');

  fs.writeFileSync(path.join(outside, 'app.config'), 'DB=postgres://u:CANARY-39@h/db\n');
  fs.writeFileSync(path.join(second, 'README.md'), '# second project, never granted\n');

  // The third escape shape: a symlink INSIDE the root whose target is outside.
  fs.symlinkSync(outside, path.join(root, 'link-out'));

  treeHashBefore = hashTree(tmp, new Set(['child-home']));

  client = await startSession(BUILT_CLI, [root], childHome);
});

afterAll(async () => {
  if (client && !sessionClosed) await client.close().catch(() => {});
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('HMA-39.AC1 stdio confinement witness', () => {
  for (const tool of PATH_TOOLS) {
    it(`HMA-39.AC1 ${tool} refuses an absolute path outside the root and names the granted root`, async () => {
      const res = await call(client, tool, { directory: outside });
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain(root);
      expect(res.content[0].text).not.toContain('CANARY-39');
    });

    it(`HMA-39.AC1 ${tool} refuses a ../ traversal from inside the root and names the granted root`, async () => {
      const res = await call(client, tool, { directory: '../elsewhere' });
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain(root);
      expect(res.content[0].text).not.toContain('CANARY-39');
    });

    it(`HMA-39.AC1 ${tool} refuses a symlink inside the root that resolves outside it and names the granted root`, async () => {
      const res = await call(client, tool, { directory: 'link-out' });
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain(root);
      expect(res.content[0].text).not.toContain('CANARY-39');
    });
  }

  it('HMA-39.AC1 hackmyagent_scan control inside the root scans and reports the planted MCP-001', async () => {
    const res = await call(client, 'hackmyagent_scan', { directory: root });
    expect(res.isError).toBeFalsy();
    expect(res.content[0].text).toContain('Score:');
    expect(res.content[0].text).toContain('MCP-001');
  });

  it('HMA-39.AC1 hackmyagent_deep_scan control inside the root returns the planted finding in its layer-1 payload', async () => {
    const res = await call(client, 'hackmyagent_deep_scan', { directory: root });
    expect(res.isError).toBeFalsy();
    const payload = JSON.parse(res.content[0].text);
    expect(JSON.stringify(payload)).toContain('MCP-001');
  });

  it('HMA-39.AC1 hackmyagent_benchmark control inside the root assesses and fails a control on the planted finding', async () => {
    const res = await call(client, 'hackmyagent_benchmark', { directory: root, level: 'L1' });
    expect(res.isError).toBeFalsy();
    expect(res.content[0].text).toContain('OASB-1');
    expect(res.content[0].text).toContain('[FAIL]');
  });
});

describe('HMA-39.AC2 the session leaves the world as it found it', () => {
  it('HMA-39.AC2 a second directory passed only in a tool argument grants nothing', async () => {
    // `second` is a perfectly grantable project directory. The only grant
    // channel is `--root` at start time; a tool argument must not become one.
    const res = await call(client, 'hackmyagent_scan', { directory: second });
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toContain(root);
    expect(res.content[0].text).not.toContain('second project, never granted');
  });

  it('HMA-39.AC2 tree hash unchanged and HOME writes equal the committed allowlist', async () => {
    await client.close();
    sessionClosed = true;

    expect(hashTree(tmp, new Set(['child-home']))).toBe(treeHashBefore);

    // Asserted EQUAL, not merely contained: a write missing from the
    // allowlist fails, so a new HOME write cannot pass unseen.
    expect(listCreatedPaths(childHome)).toEqual(HOME_WRITE_ALLOWLIST);
  });

  it('HMA-39.AC2 --root / is refused at initialisation and the refusal is what the transport returns', async () => {
    // The refusal is computed once at startup (`resolveRoots` in
    // `startMcpServer`). By deliberate design the connection still opens so
    // the refusal text is READABLE (src/mcp-server.ts records the reason:
    // a startup exit surfaces as an opaque "server failed to start"); the
    // initialisation error is then the only thing any tool call returns.
    const home = fs.mkdtempSync(path.join(tmp, 'home-neg-'));
    const c = await startSession(BUILT_CLI, ['/'], home);
    try {
      const res = await call(c, 'hackmyagent_scan', { directory: root });
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain('Root not accepted');
      expect(res.content[0].text).toContain('filesystem root');
      // Not even a path that WOULD be inside "/" is scanned: the grant never
      // happened, so the session has no roots at all.
      expect(res.content[0].text).not.toContain('Score:');
    } finally {
      await c.close();
    }
  });

  it("HMA-39.AC2 --root <the child's HOME> is refused at initialisation and the refusal is what the transport returns", async () => {
    const home = fs.mkdtempSync(path.join(tmp, 'home-neg2-'));
    const c = await startSession(BUILT_CLI, [home], home);
    try {
      const res = await call(c, 'hackmyagent_scan', { directory: home });
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain('Root not accepted');
      expect(res.content[0].text).toContain('home directory');
    } finally {
      await c.close();
    }
  });

  it('HMA-39.AC2 positive control: with resolveWithinRoots replaced by an identity resolver in a SCRATCH dist, the escape cases come back unconfined', async () => {
    // This is the proof the witness above has teeth. A scratch copy of dist/
    // (never the tree) gets `resolveWithinRoots` short-circuited to an
    // identity resolver; the same escape calls must then succeed, i.e. AC1's
    // assertions would be red against that binary and are green against the
    // real one.
    const scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hma39-sabotage-')));
    try {
      fs.cpSync(path.join(REPO, 'dist'), path.join(scratch, 'dist'), { recursive: true });
      // VERSION is read from `../package.json` relative to dist, and module
      // resolution walks up from the script path.
      fs.copyFileSync(path.join(REPO, 'package.json'), path.join(scratch, 'package.json'));
      fs.symlinkSync(path.join(REPO, 'node_modules'), path.join(scratch, 'node_modules'), 'dir');

      const rootsJs = path.join(scratch, 'dist', 'mcp', 'roots.js');
      const compiled = fs.readFileSync(rootsJs, 'utf-8');
      const marker = 'async function resolveWithinRoots(roots, requested) {';
      // Fail loudly if the compiled shape ever drifts — a control that
      // silently sabotages nothing would "prove" the witness with no evidence.
      expect(compiled).toContain(marker);
      fs.writeFileSync(
        rootsJs,
        compiled.replace(
          marker,
          marker +
            '\n    return { ok: true, path: path.isAbsolute(requested) ? requested : path.resolve(roots[0], requested) };',
        ),
      );
      // Rebuild the integrity manifest exactly as `npm run build` does, so the
      // scratch binary differs from the real one ONLY in the resolver.
      const scratchRequire = createRequire(path.join(scratch, 'dist', 'x.js'));
      const { generateManifest } = scratchRequire(
        path.join(scratch, 'dist', 'nanomind-core', 'security', 'integrity-verifier.js'),
      );
      const manifest = generateManifest(scratch);
      if (manifest) {
        fs.writeFileSync(path.join(scratch, 'dist', '.integrity-manifest.json'), JSON.stringify(manifest));
      }

      const home = fs.mkdtempSync(path.join(scratch, 'home-'));
      const c = await startSession(path.join(scratch, 'dist', 'cli.js'), [root], home);
      try {
        const escapes: Array<Record<string, unknown>> = [
          { directory: outside },
          { directory: '../elsewhere' },
          { directory: 'link-out' },
        ];
        for (const args of escapes) {
          const res = await call(c, 'hackmyagent_scan', args);
          // Unconfined: the refusal is gone and the out-of-root scan RAN.
          expect(res.isError).toBeFalsy();
          expect(res.content[0].text).toContain('Score:');
        }
      } finally {
        await c.close();
      }
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  });
});

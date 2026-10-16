/**
 * Deep analysis never sends a credential file to the analysis provider, and
 * removes credential values from every file it does send.
 *
 * The claim is about what leaves the process, so the built CLI is spawned, as a
 * user runs it, under `helpers/provider-capture.cjs`. That preload answers the
 * provider on this machine and records each request body, refuses every other
 * fetch, and (through `loopback-only.cjs`) refuses every socket to a host that
 * is not loopback. No request reaches a real provider. The key the child sees
 * is a placeholder, and the parent's own key, preload and proxy settings are
 * removed from the child's environment first.
 *
 * Every value planted in the fixture is built at runtime from a random UUID,
 * one per file and per position, so a value found in a recorded body says
 * exactly which file and which position it came from.
 *
 * The cells are the two ways to ask `secure` for deep analysis (`--deep` and
 * `--scan-depth deep`), `scan-soul --deep` on a governance file, and the
 * `hackmyagent_deep_scan` MCP tool, called in process through the server's own
 * handler. `scan-soul` sends one file, so it gets A, C, D and F.
 *
 *   A  at least one provider request was recorded, and the Layer 3 request for
 *      `CLAUDE.md` is among them. Zero recorded is a failure, never a skip:
 *      every assertion below would pass on a run that sent nothing.
 *   B  no recorded body holds any value from an env file, or from a config file.
 *   C  no recorded body holds a value planted under a credential-named key or
 *      as the password in a URL.
 *   D  a value under a neutral key is left as it is by the redaction, and is
 *      present in the recorded `CLAUDE.md` body. This proves the body read
 *      above is the body that was sent, so B and C are not vacuous.
 *   E  no recorded body carries a `File:` header for an env or config file.
 *   F  every recorded request came after a stderr line naming the host and the
 *      variable, and the request counts those lines give equal the number of
 *      requests recorded.
 *   G  the MCP tool's result holds no env-file value and no credential-keyed
 *      value, and does hold the neutral value (the same control as D).
 *
 * `HMA_EGRESS_CLI=<path to a dist/cli.js>` runs the spawned cells against that
 * build instead of this checkout's, which is how this file is shown to fail on a
 * build without the fix. The default is the checkout's own `dist/cli.js`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { redactTargetArtifact } from '../../src/attack-engine/target-reader';
import { handleToolCall } from '../../src/mcp-server';

const CLI = process.env.HMA_EGRESS_CLI || BUILT_CLI;
const PRELOAD = path.join(__dirname, '..', 'helpers', 'provider-capture.cjs');
const PROVIDER_HOST = 'api.anthropic.com';
const PLACEHOLDER_KEY = 'placeholder-not-a-key';

/** One value per file and position, built at runtime. */
function canary(label: string): string {
  return `canary-${label}-${randomUUID()}`;
}

interface Fixture {
  root: string;
  /** Values in `.env` files, under credential-named and neutral keys alike. */
  envValues: string[];
  /** Values in the config files, under credential-named and neutral keys alike. */
  configValues: string[];
  /** Values under a credential-named key in a file that is still sent. */
  keyedValues: string[];
  /** Passwords in a URL's user information, in a file that is still sent. */
  urlValues: string[];
  /** A value under a neutral key in `CLAUDE.md`, which is sent unchanged. */
  neutral: string;
  envPaths: string[];
  configPaths: string[];
}

function write(root: string, rel: string, content: string): void {
  const file = path.join(root, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

/** Every kind of file the deep layer selects, at the root and one level down. */
function buildFixture(): Fixture {
  const root = fs.realpathSync(tempDir('hma-deep-egress-'));
  const keyed = (label: string) => { const v = canary(label); keyedValues.push(v); return v; };
  const url = (label: string) => { const v = canary(label); urlValues.push(v); return v; };
  const keyedValues: string[] = [];
  const urlValues: string[] = [];
  const envValues: string[] = [];
  const configValues: string[] = [];
  const neutral = canary('neutral');

  write(root, 'CLAUDE.md', [
    '# Project notes',
    '',
    'Answer in short sentences and run the tests before every commit.',
    '',
    `greeting: ${neutral}`,
    '',
    `api_key: ${keyed('claude-md-key')}`,
    '',
    `Reports go to postgres://reporter:${url('claude-md-url')}@db.internal:5432/app`,
    '',
  ].join('\n'));
  write(root, '.cursorrules', `Follow the style guide.\nauth_token: ${keyed('cursorrules')}\n`);
  write(root, '.windsurfrules', 'Use two spaces for indentation.\n');
  write(root, '.clinerules', 'Prefer small commits.\n');
  write(root, '.github/copilot-instructions.md', `Write the test first.\nclient_secret: ${keyed('copilot')}\n`);

  write(root, 'mcp.json', JSON.stringify({
    mcpServers: {
      db: {
        command: 'node',
        args: ['server.js'],
        env: {
          API_TOKEN: keyed('mcp-json-token'),
          DATABASE_URL: `postgres://svc:${url('mcp-json-url')}@db.internal:5432/app`,
        },
      },
    },
  }, null, 2));
  write(root, '.mcp.json', JSON.stringify({
    mcpServers: { web: { command: 'node', args: ['web.js'], env: { SERVICE_SECRET: keyed('dot-mcp-json') } } },
  }, null, 2));
  write(root, '.cursor/mcp.json', JSON.stringify({
    mcpServers: { docs: { command: 'node', args: ['docs.js'], env: { ACCESS_TOKEN: keyed('cursor-mcp') } } },
  }, null, 2));
  write(root, '.vscode/mcp.json', JSON.stringify({
    servers: { notes: { command: 'node', args: ['notes.js'], env: { API_KEY: keyed('vscode-mcp') } } },
  }, null, 2));
  write(root, '.claude/settings.json', JSON.stringify({
    permissions: { allow: ['Read'] },
    env: { SERVICE_TOKEN: keyed('claude-settings') },
  }, null, 2));

  const envPaths = ['.env', '.env.local', '.env.development', '.env.production', 'sub/.env'];
  for (const rel of envPaths) {
    const secret = canary(`env-${rel}`);
    const plain = canary(`env-plain-${rel}`);
    envValues.push(secret, plain);
    write(root, rel, `DATABASE_PASSWORD=${secret}\nGREETING=${plain}\n`);
  }

  const configPaths = ['config.json', 'config.yaml', 'config.yml', 'settings.json'];
  for (const rel of configPaths) {
    const secret = canary(`config-${rel}`);
    const plain = canary(`config-plain-${rel}`);
    configValues.push(secret, plain);
    write(root, rel, rel.endsWith('.json')
      ? JSON.stringify({ region: plain, dbPassword: secret }, null, 2)
      : `region: ${plain}\ndb_password: ${secret}\n`);
  }

  return { root, envValues, configValues, keyedValues, urlValues, neutral, envPaths, configPaths };
}

interface Captured {
  host: string;
  tool: string | null;
  keySent: boolean;
  body: string;
  /** The labels of the send notices already on stderr when this request was made. */
  noticesBefore: string[];
  /** System prompt and message text, decoded from the body. */
  text: string;
}

interface Notice { label: string; files: number; host: string; requests: number }

interface Cell {
  status: number | null;
  stderr: string;
  captured: Captured[];
  notices: Notice[];
}

/** The send notice, as a user reads it on stderr. */
const NOTICE = /^(\[[^\]]+\]) Sending (\d+) files? to (\S+) in (\d+) requests?, because ANTHROPIC_API_KEY is set\./gm;

function noticesIn(stderr: string): Notice[] {
  return [...stderr.matchAll(NOTICE)].map((m) => ({
    label: m[1],
    files: Number(m[2]),
    host: m[3],
    requests: Number(m[4]),
  }));
}

function decode(body: string): string {
  try {
    const parsed = JSON.parse(body) as { system?: unknown; messages?: Array<{ content?: unknown }> };
    const parts = [typeof parsed.system === 'string' ? parsed.system : ''];
    for (const m of parsed.messages ?? []) parts.push(typeof m.content === 'string' ? m.content : JSON.stringify(m.content));
    return parts.join('\n');
  } catch {
    return body;
  }
}

/** Spawn the CLI under the capture preload, in a fresh working directory and HOME. */
function runCell(args: string[]): Cell {
  const cwd = tempDir('hma-deep-egress-cwd-');
  const home = tempDir('hma-deep-egress-home-');
  const log = path.join(tempDir('hma-deep-egress-log-'), 'provider.jsonl');
  const {
    ANTHROPIC_API_KEY: _key, NODE_OPTIONS: _opts, HMA_EXPORT_TRAINING: _train,
    HTTP_PROXY: _p1, HTTPS_PROXY: _p2, http_proxy: _p3, https_proxy: _p4, ALL_PROXY: _p5, all_proxy: _p6,
    NODE_USE_ENV_PROXY: _p7,
    ...base
  } = process.env;
  const res = spawnSync(process.execPath, [CLI, ...args], {
    cwd,
    encoding: 'utf8',
    timeout: 150_000,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...base,
      HOME: home,
      ANTHROPIC_API_KEY: PLACEHOLDER_KEY,
      OPENA2A_TELEMETRY: 'off',
      NO_COLOR: '1',
      NODE_OPTIONS: `--require ${JSON.stringify(PRELOAD)}`,
      HMA_TEST_PROVIDER_LOG: log,
    },
  });
  const lines = fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\n').filter(Boolean) : [];
  const captured = lines.map((line) => {
    const entry = JSON.parse(line) as Omit<Captured, 'text'>;
    return { ...entry, text: decode(entry.body) };
  });
  return { status: res.status, stderr: res.stderr ?? '', captured, notices: noticesIn(res.stderr ?? '') };
}

const isLayer3 = (c: Captured) => c.tool === 'report_findings';

/** A sparse governance file, so the local tier leaves controls for the provider. */
interface SoulFixture { root: string; keyed: string; url: string; neutral: string }

function buildSoulFixture(): SoulFixture {
  const root = fs.realpathSync(tempDir('hma-deep-egress-soul-'));
  const keyed = canary('soul-key');
  const url = canary('soul-url');
  const neutral = canary('soul-neutral');
  write(root, 'SOUL.md', [
    '# Assistant',
    '',
    'A helpful assistant for internal documentation.',
    '',
    `greeting: ${neutral}`,
    '',
    `service_token: ${keyed}`,
    '',
    `Notes are stored at postgres://notes:${url}@db.internal:5432/notes`,
    '',
  ].join('\n'));
  return { root, keyed, url, neutral };
}

let fixture: Fixture;
let soul: SoulFixture;
const cells: Record<string, Cell> = {};
let soulCell: Cell;
let mcpText = '';

beforeAll(async () => {
  // A missing or stale build is an error naming the build step, never a skip.
  assertDistFresh();
  if (!fs.existsSync(CLI)) throw new Error(`the CLI under test is missing: ${CLI}`);

  fixture = buildFixture();
  const secure = ['secure', fixture.root, '--format', 'json', '--no-contribute'];
  cells['--deep'] = runCell([...secure, '--deep']);
  cells['--scan-depth deep'] = runCell([...secure, '--scan-depth', 'deep']);

  soul = buildSoulFixture();
  soulCell = runCell(['scan-soul', soul.root, '--deep', '--json', '--no-contribute']);

  // The MCP tool never calls the provider. The key is removed for the call
  // anyway, so a regression that made it call out could not use a real one.
  const prior = process.env.ANTHROPIC_API_KEY;
  delete process.env.ANTHROPIC_API_KEY;
  try {
    const res = await handleToolCall('hackmyagent_deep_scan', { directory: fixture.root }, [fixture.root]);
    mcpText = res.content.map((c) => c.text ?? '').join('\n');
  } finally {
    if (prior !== undefined) process.env.ANTHROPIC_API_KEY = prior;
  }
}, 330_000);

for (const name of ['--deep', '--scan-depth deep']) {
  describe(`secure ${name} with ANTHROPIC_API_KEY set`, () => {
    it('ran to a verdict', () => {
      const cell = cells[name];
      expect([0, 1, 2], `exit ${cell.status}; stderr:\n${cell.stderr.slice(-2000)}`).toContain(cell.status);
    });

    it('A: sent at least one request, the Layer 3 request for CLAUDE.md among them', () => {
      const cell = cells[name];
      expect(cell.captured.length, 'no provider request was recorded, so nothing below measured anything').toBeGreaterThan(0);
      expect(cell.captured.every((c) => c.host === PROVIDER_HOST && c.keySent)).toBe(true);
      const claude = cell.captured.filter((c) => isLayer3(c) && c.text.includes('File: "CLAUDE.md"'));
      expect(claude.length).toBe(1);
    });

    it('B: no request holds a value from an env file or a config file', () => {
      const cell = cells[name];
      const found = [...fixture.envValues, ...fixture.configValues]
        .filter((v) => cell.captured.some((c) => c.body.includes(v)));
      expect(found).toEqual([]);
    });

    it('C: no request holds a credential-keyed value or a URL password', () => {
      const cell = cells[name];
      const found = [...fixture.keyedValues, ...fixture.urlValues]
        .filter((v) => cell.captured.some((c) => c.body.includes(v)));
      expect(found).toEqual([]);
    });

    it('D: the neutral value is left by the redaction and is in the CLAUDE.md body that was sent', () => {
      const line = `greeting: ${fixture.neutral}`;
      expect(redactTargetArtifact(line).text).toBe(line);
      const claude = cells[name].captured.find((c) => isLayer3(c) && c.text.includes('File: "CLAUDE.md"'));
      expect(claude?.text).toContain(fixture.neutral);
    });

    it('E: no request carries a File: header for an env or config file', () => {
      const cell = cells[name];
      const sent = [...fixture.envPaths, ...fixture.configPaths]
        .filter((rel) => cell.captured.some((c) => c.text.includes(`File: ${JSON.stringify(rel)}`)));
      expect(sent).toEqual([]);
    });

    it('F: a stderr line naming the host came before every request, and its counts equal the requests made', () => {
      const cell = cells[name];
      expect(cell.notices.length, `no send notice on stderr:\n${cell.stderr.slice(-2000)}`).toBeGreaterThan(0);
      for (const n of cell.notices) expect(n.host).toBe(PROVIDER_HOST);
      expect(cell.notices.reduce((sum, n) => sum + n.requests, 0)).toBe(cell.captured.length);

      const layer3 = cell.notices.filter((n) => n.label === '[Deep analysis]');
      expect(layer3).toHaveLength(1);
      expect(layer3[0].requests).toBe(cell.captured.filter(isLayer3).length);
      expect(layer3[0].files).toBe(layer3[0].requests);

      for (const c of cell.captured) {
        expect(c.noticesBefore, 'a request was made before its notice').toContain(isLayer3(c) ? '[Deep analysis]' : '[Simulation]');
      }
    });
  });
}

describe('scan-soul --deep with ANTHROPIC_API_KEY set', () => {
  it('ran to a verdict', () => {
    expect([0, 1, 2], `exit ${soulCell.status}; stderr:\n${soulCell.stderr.slice(-2000)}`).toContain(soulCell.status);
  });

  it('A: sent at least one request', () => {
    expect(soulCell.captured.length, 'no provider request was recorded, so nothing below measured anything').toBeGreaterThan(0);
    expect(soulCell.captured.every((c) => c.host === PROVIDER_HOST && c.keySent)).toBe(true);
  });

  it('C: no request holds the credential-keyed value or the URL password', () => {
    const found = [soul.keyed, soul.url].filter((v) => soulCell.captured.some((c) => c.body.includes(v)));
    expect(found).toEqual([]);
  });

  it('D: the neutral value is left by the redaction and is in every request', () => {
    const line = `greeting: ${soul.neutral}`;
    expect(redactTargetArtifact(line).text).toBe(line);
    expect(soulCell.captured.every((c) => c.body.includes(soul.neutral))).toBe(true);
  });

  it('F: one stderr line naming the host came before every request, and its count equals the requests made', () => {
    expect(soulCell.notices, `no send notice on stderr:\n${soulCell.stderr.slice(-2000)}`).toHaveLength(1);
    const [notice] = soulCell.notices;
    expect(notice.host).toBe(PROVIDER_HOST);
    expect(notice.files).toBe(1);
    expect(notice.requests).toBe(soulCell.captured.length);
    for (const c of soulCell.captured) expect(c.noticesBefore).toContain(notice.label);
  });
});

describe('the hackmyagent_deep_scan MCP tool', () => {
  it('G: returns no env-file value and no credential-keyed value, and does return the neutral value', () => {
    expect(mcpText, 'the tool returned nothing to read').not.toBe('');
    const found = [...fixture.envValues, ...fixture.configValues, ...fixture.keyedValues, ...fixture.urlValues]
      .filter((v) => mcpText.includes(v));
    expect(found).toEqual([]);
    expect(mcpText).toContain(fixture.neutral);
  });

  it('names each env and config file it left out, and returns none of their contents', () => {
    const result = JSON.parse(mcpText) as {
      filesForDeepAnalysis: Array<{ path: string }>;
      filesWithheld?: Array<{ path: string; reason: string }>;
    };
    const credentialFiles = [...fixture.envPaths, ...fixture.configPaths].sort();
    expect((result.filesWithheld ?? []).map((f) => f.path).sort()).toEqual(credentialFiles);
    expect(result.filesForDeepAnalysis.map((f) => f.path).filter((p) => credentialFiles.includes(p))).toEqual([]);
  });
});

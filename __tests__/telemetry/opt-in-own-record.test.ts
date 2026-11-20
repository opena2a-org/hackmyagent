/**
 * hackmyagent keeps the contribution setting in ~/.opena2a/config.json itself,
 * with no other package between it and the file.
 *
 *   (a) A yes records when it was given (`consentedAt`, ISO-8601) and the
 *       consent version (`consentVersion`, '1.0' unless the file already names
 *       one); a no sets `enabled` to false and clears `consentedAt`. Every
 *       other key already in the file is kept.
 *   (b) A config directory that does not exist yet is created private
 *       (0o700) by the first write, and the file is 0o600.
 *   (c) Reading the setting from the built module loads no copy of the shared
 *       opena2a config package: not one installed beside hackmyagent, and not
 *       one that only NODE_PATH reaches, as in a consumer tree that hoists it.
 *   (d) An explicit no in the file means no tip, with or without a dismissal
 *       recorded.
 *   (e) A file whose JSON value is not an object (null, an array, a string, a
 *       number, true) reads as empty: the setting reads as not configured
 *       without a throw, no tip is due, and the scan count writes an object
 *       in its place. With a file holding null, NanoMind's per-file step,
 *       which reads the setting ahead of the analyzers, still runs them.
 *
 * The other halves of the tip rule (fewer than 3 scans, an explicit yes, a
 * dismissal inside 30 days) are pinned in contribute.test.ts.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { tempDir } from '../helpers/temp-dir';
import { assertDistFresh } from '../helpers/dist-freshness';
import {
  saveContributeChoice,
  shouldPromptContribute,
  isContributeEnabled,
  incrementScanCount,
  _resetBackend,
} from '../../src/telemetry/opt-in';
import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';

const ROOT = path.resolve(__dirname, '../..');
const BUILT_OPT_IN = path.join(ROOT, 'dist', 'telemetry', 'opt-in.js');

/** The shared config package's scope and name, as path segments. */
const SHARED_SEGMENTS = ['@opena2a', 'shared'] as const;

let savedOpena2aHome: string | undefined;

beforeEach(() => {
  savedOpena2aHome = process.env.OPENA2A_HOME;
});

afterEach(() => {
  if (savedOpena2aHome === undefined) {
    delete process.env.OPENA2A_HOME;
  } else {
    process.env.OPENA2A_HOME = savedOpena2aHome;
  }
  _resetBackend();
});

function useHome(dir: string): string {
  process.env.OPENA2A_HOME = dir;
  _resetBackend();
  return path.join(dir, 'config.json');
}

function writeConfig(file: string, value: unknown): void {
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
}

function readConfig(file: string): Record<string, any> {
  return JSON.parse(fs.readFileSync(file, 'utf-8'));
}

describe('(a) the consent record hackmyagent writes', () => {
  it('a yes records consentedAt inside the call window and consentVersion 1.0, and keeps every other key', () => {
    const file = useHome(tempDir('hma-optin-a-'));
    const before = {
      version: 1,
      registry: { url: 'https://registry.example.invalid' },
      telemetry: { scanCount: 2 },
      contribute: { note: 'kept' },
      other: [1, 2, 3],
    };
    writeConfig(file, before);

    const windowStart = Date.now();
    saveContributeChoice(true);
    const windowEnd = Date.now();

    const after = readConfig(file);
    expect(after.contribute.enabled).toBe(true);
    expect(typeof after.contribute.consentedAt).toBe('string');
    // Canonical ISO-8601: the string round-trips through Date unchanged.
    expect(new Date(after.contribute.consentedAt).toISOString()).toBe(after.contribute.consentedAt);
    const consentedAt = Date.parse(after.contribute.consentedAt);
    expect(consentedAt).toBeGreaterThanOrEqual(windowStart);
    expect(consentedAt).toBeLessThanOrEqual(windowEnd);
    expect(after.contribute.consentVersion).toBe('1.0');

    expect(after.contribute.note).toBe('kept');
    expect(after.version).toBe(before.version);
    expect(after.registry).toEqual(before.registry);
    expect(after.telemetry).toEqual(before.telemetry);
    expect(after.other).toEqual(before.other);
  });

  it('a yes keeps a consentVersion the file already names', () => {
    const file = useHome(tempDir('hma-optin-a-'));
    writeConfig(file, { contribute: { enabled: false, consentedAt: null, consentVersion: '2.0' } });

    saveContributeChoice(true);

    const after = readConfig(file);
    expect(after.contribute.enabled).toBe(true);
    expect(typeof after.contribute.consentedAt).toBe('string');
    expect(after.contribute.consentVersion).toBe('2.0');
  });

  it('a no sets enabled to false, clears consentedAt, and keeps every other key', () => {
    const file = useHome(tempDir('hma-optin-a-'));
    const before = {
      version: 1,
      registry: { url: 'https://registry.example.invalid' },
      telemetry: { scanCount: 4 },
      contribute: { enabled: true, consentedAt: '2026-01-02T03:04:05.000Z', note: 'kept' },
      other: { nested: { value: 'kept' } },
    };
    writeConfig(file, before);

    saveContributeChoice(false);

    const after = readConfig(file);
    expect(after.contribute.enabled).toBe(false);
    expect(after.contribute.consentedAt).toBeNull();
    // The record names the consent version whichever way the choice went.
    expect(after.contribute.consentVersion).toBe('1.0');

    expect(after.contribute.note).toBe('kept');
    expect(after.version).toBe(before.version);
    expect(after.registry).toEqual(before.registry);
    expect(after.telemetry.scanCount).toBe(before.telemetry.scanCount);
    expect(after.other).toEqual(before.other);
  });
});

describe('(b) the config directory', () => {
  it('a config directory that does not exist is created 0o700 by the first write, and the file is 0o600', () => {
    const dir = path.join(tempDir('hma-optin-b-'), 'not-created-yet', '.opena2a');
    expect(fs.existsSync(dir)).toBe(false);
    const file = useHome(dir);

    // A fixed umask, so the result does not depend on the host's: under 0o022
    // a directory created without an explicit mode is 0o755.
    const previousUmask = process.umask(0o022);
    try {
      saveContributeChoice(true);
    } finally {
      process.umask(previousUmask);
    }

    expect((fs.statSync(dir).mode & 0o777).toString(8)).toBe('700');
    expect((fs.statSync(file).mode & 0o777).toString(8)).toBe('600');
  });
});

describe('(c) no copy of the shared config package is loaded', () => {
  beforeAll(() => {
    // This cell runs the built module: a build older than src/ would measure
    // code that is no longer under test.
    assertDistFresh();
  });

  it('reading the setting from the built module loads it from no tree, not even one only NODE_PATH reaches', () => {
    const base = tempDir('hma-optin-c-');
    const home = path.join(base, 'home');
    const cwd = path.join(base, 'cwd');
    const hoisted = path.join(base, 'hoisted', 'node_modules');
    const stubDir = path.join(hoisted, ...SHARED_SEGMENTS);
    fs.mkdirSync(home);
    fs.mkdirSync(cwd);
    fs.mkdirSync(stubDir, { recursive: true });
    fs.writeFileSync(
      path.join(stubDir, 'package.json'),
      JSON.stringify({ name: SHARED_SEGMENTS.join('/'), version: '0.0.0', main: 'index.js' }),
    );
    fs.writeFileSync(
      path.join(stubDir, 'index.js'),
      [
        'globalThis.__hmaSharedStubLoaded = true;',
        'exports.isContributeEnabled = () => true;',
        'exports.setContributeEnabled = () => {};',
        'exports.incrementScanCount = () => 0;',
        'exports.getScanCount = () => 0;',
        'exports.shouldPromptContribute = () => true;',
        'exports.dismissContributePrompt = () => {};',
        '',
      ].join('\n'),
    );

    // Runs in the child. `loaded` and `stubLoaded` are read before the
    // control, which requires the package by name from the child's own
    // directory to show the stub is reachable through NODE_PATH and that its
    // marker works.
    const childScript = [
      'const [modulePath, pathSegment, specifier] = process.argv.slice(1);',
      'const optIn = require(modulePath);',
      'const value = optIn.isContributeEnabled();',
      'const loaded = Object.keys(require.cache).filter((p) => p.includes(pathSegment));',
      'const stubLoaded = globalThis.__hmaSharedStubLoaded === true;',
      'let control;',
      'try { require(specifier); control = globalThis.__hmaSharedStubLoaded === true; }',
      'catch (err) { control = String(err && err.code); }',
      'process.stdout.write(JSON.stringify({ value: String(value), loaded, stubLoaded, control }));',
    ].join('\n');

    const result = spawnSync(
      process.execPath,
      ['-e', childScript, BUILT_OPT_IN, path.join(...SHARED_SEGMENTS), SHARED_SEGMENTS.join('/')],
      {
        cwd,
        // Built from scratch: no OPENA2A_HOME, so the module reads HOME.
        env: { PATH: process.env.PATH ?? '', HOME: home, NODE_PATH: hoisted },
        encoding: 'utf-8',
        timeout: 60_000,
      },
    );

    expect(result.status, result.stderr).toBe(0);
    const out = JSON.parse(result.stdout);
    expect(out.loaded, 'modules loaded from a path naming the shared config package').toEqual([]);
    expect(out.stubLoaded, 'the NODE_PATH stub was loaded').toBe(false);
    // No config file under HOME: not configured.
    expect(out.value).toBe('undefined');
    // Reading the setting creates nothing.
    expect(fs.existsSync(path.join(home, '.opena2a'))).toBe(false);
    // Control: the stub is reachable through NODE_PATH and sets its marker.
    expect(out.control).toBe(true);
  });
});

describe('(d) an explicit no in the file means no tip', () => {
  it('enabled false with no dismissal recorded and a scan count past 3 shows no tip; the same file with no choice does', () => {
    const file = useHome(tempDir('hma-optin-d-'));

    // Control: past the threshold, nothing decided, nothing dismissed.
    writeConfig(file, { telemetry: { scanCount: 5, contributePromptDismissedAt: null } });
    expect(shouldPromptContribute()).toBe(true);

    writeConfig(file, {
      contribute: { enabled: false, consentedAt: null, consentVersion: '1.0' },
      telemetry: { scanCount: 5, contributePromptDismissedAt: null },
    });
    expect(shouldPromptContribute()).toBe(false);
  });
});

describe('(e) a config file whose JSON value is not an object reads as empty', () => {
  /** [label, the file's whole text]: valid JSON, but not an object. */
  const NOT_AN_OBJECT: Array<[string, string]> = [
    ['null', 'null'],
    ['an array', '[]'],
    ['a string', '"text"'],
    ['a number', '42'],
    ['true', 'true'],
  ];

  it.each(NOT_AN_OBJECT)(
    'a file holding %s: the setting reads as not configured, no tip is due, and the scan count writes an object',
    (_label, text) => {
      const file = useHome(tempDir('hma-optin-e-'));
      fs.writeFileSync(file, text + '\n', { mode: 0o600 });

      const read = () => isContributeEnabled();
      expect(read).not.toThrow();
      expect(read()).toBeUndefined();
      expect(shouldPromptContribute()).toBe(false);

      expect(incrementScanCount()).toBe(1);
      expect(readConfig(file)).toEqual({ telemetry: { scanCount: 1 } });
    },
  );

  it('a file holding null: NanoMind still runs the analyzers on a scanned artifact', async () => {
    // The scanner reads the setting, to queue its classification statistic,
    // inside its per-file step and ahead of the analyzers; that step skips
    // the file on a throw.
    const file = useHome(tempDir('hma-optin-e-'));
    fs.writeFileSync(file, 'null\n', { mode: 0o600 });

    // An MCP server granted every tool: the scope analyzer flags it.
    const target = tempDir('hma-optin-e-target-');
    fs.writeFileSync(
      path.join(target, 'mcp.json'),
      JSON.stringify(
        {
          mcpServers: {
            filesystem: {
              command: 'npx',
              args: ['-y', '@modelcontextprotocol/server-filesystem'],
              allowedTools: ['*'],
            },
          },
        },
        null,
        2,
      ),
    );

    const result = await runNanoMindScan(target, []);

    expect(result.compiledArtifacts).toBe(1);
    const scope = result.astFindings.filter((f) => f.checkId.startsWith('AST-SCOPE') && !f.passed);
    expect(scope.length).toBeGreaterThan(0);
  });
});

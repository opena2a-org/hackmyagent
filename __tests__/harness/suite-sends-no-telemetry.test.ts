/**
 * #963 — the test suite sends no usage telemetry to the Registry.
 *
 * Telemetry is on by default and its install id lives under the home
 * directory. Spawn tests hand every run a fresh HOME, so each spawn registered
 * as a new install: on 2026-10-11, 197 of hackmyagent's 219 monthly install ids
 * had been active on one day only. One file in this suite meant to point its
 * runs at a discard port and named a variable the SDK does not read, so every
 * run of it posted to the production endpoint.
 *
 * Three claims, held here for the whole suite rather than per file:
 *
 *   - a spawn that inherits the worker's environment sends no event, because
 *     the worker carries a test-runner marker and the CLI keeps usage
 *     telemetry off under one (src/telemetry/automation.ts); the cells without
 *     the marker and with OPENA2A_TELEMETRY=on show the instrument can see an
 *     event at all;
 *   - vitest.setup.ts points the worker's telemetry at a loopback address, so a
 *     test that turns telemetry back on still sends nothing off the machine;
 *   - a test that turns telemetry on in a spawn environment pins
 *     OPENA2A_TELEMETRY_URL to a loopback address in the same object, and no
 *     test names an OPENA2A_TELEMETRY_* variable nothing reads.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { automationMarker, CI_MARKERS, TEST_RUNNER_MARKERS } from '../../src/telemetry/automation';

beforeAll(assertDistFresh);

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const DISCARD = 'http://127.0.0.1:9';
const LOOPBACK = /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?(\/|$)/;

/** The worker's environment with no telemetry choice of its own. */
function inherited(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.OPENA2A_TELEMETRY;
  return env;
}

/** The same environment with every CI and test-runner marker removed. */
function withoutMarkers(): NodeJS.ProcessEnv {
  const env = inherited();
  for (const name of [...CI_MARKERS, ...TEST_RUNNER_MARKERS, 'NODE_ENV']) delete env[name];
  return env;
}

interface Run { status: number | null; events: number; stderr: string }

function run(args: string[], base: NodeJS.ProcessEnv): Run {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 120_000,
    env: {
      ...base,
      HOME: tempDir('hma-963-home-'),
      XDG_CONFIG_HOME: tempDir('hma-963-xdg-'),
      NO_COLOR: '1',
      OPENA2A_TELEMETRY_DEBUG: 'print',
      OPENA2A_TELEMETRY_URL: DISCARD,
    },
  });
  const stderr = r.stderr ?? '';
  return { status: r.status, events: (stderr.match(/\[opena2a:telemetry\]/g) ?? []).length, stderr };
}

function project(): string {
  const dir = tempDir('hma-963-proj-');
  writeFileSync(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  return dir;
}

describe('a spawn that inherits the suite environment sends no usage event (#963)', { timeout: 300_000 }, () => {
  it('the worker carries a test-runner marker', () => {
    expect(automationMarker(process.env), 'vitest no longer marks its workers').toBeDefined();
  });

  it('RED-ON-BASE: secure sends no event', () => {
    const r = run(['secure', project()], inherited());
    expect(r.status, r.stderr).toBe(0);
    expect(r.events).toBe(0);
  });

  it('RED-ON-BASE: --version says Telemetry: off', () => {
    const r = run(['--version'], inherited());
    expect(r.stderr).toMatch(/Telemetry: off/);
  });

  it('without the markers the same run sends one event (the instrument works)', () => {
    const r = run(['secure', project()], withoutMarkers());
    expect(r.status, r.stderr).toBe(0);
    expect(r.events).toBe(1);
    expect(run(['--version'], withoutMarkers()).stderr).toMatch(/Telemetry: on/);
  });

  it('OPENA2A_TELEMETRY=on turns it back on under the marker', () => {
    const r = run(['secure', project()], { ...inherited(), OPENA2A_TELEMETRY: 'on', OPENA2A_TELEMETRY_URL: DISCARD });
    expect(r.status, r.stderr).toBe(0);
    expect(r.events).toBe(1);
  });
});

describe('vitest.setup.ts points telemetry at a loopback address (#963)', () => {
  it('the worker reaches no telemetry endpoint off this machine', () => {
    expect(process.env.OPENA2A_TELEMETRY_URL ?? '').toMatch(LOOPBACK);
  });
});

// ---------------------------------------------------------------------------
// Static half: what each test file puts in a spawn environment.
// ---------------------------------------------------------------------------

/** The OPENA2A_TELEMETRY_* variables something reads: the usage SDK and ARP. */
const READ_NAMES = new Set(['OPENA2A_TELEMETRY_URL', 'OPENA2A_TELEMETRY_DEBUG', 'OPENA2A_TELEMETRY_OPTOUT']);
const OPT_IN = new Set(['on', '1', 'true', 'yes']);

/** Every test source: `__tests__/**` and `src/**\/*.test.ts`, as vitest includes them. */
function testSources(): string[] {
  const out: string[] = [];
  const walk = (dir: string, keep: (f: string) => boolean): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules') continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full, keep);
      else if (keep(full)) out.push(full);
    }
  };
  walk(path.join(REPO_ROOT, '__tests__'), (f) => f.endsWith('.ts'));
  walk(path.join(REPO_ROOT, 'src'), (f) => f.endsWith('.test.ts'));
  return out;
}

function keyName(name: ts.PropertyName): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
  return undefined;
}

interface Finding { file: string; line: number; problem: string }

function scan(file: string): Finding[] {
  const text = readFileSync(file, 'utf8');
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const rel = path.relative(REPO_ROOT, file);
  const constants = new Map<string, string>();
  const objects: ts.ObjectLiteralExpression[] = [];
  const findings: Finding[] = [];
  const at = (node: ts.Node) => sf.getLineAndCharacterOfPosition(node.getStart()).line + 1;

  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer
      && ts.isStringLiteralLike(node.initializer)) {
      constants.set(node.name.text, node.initializer.text);
    }
    if (ts.isObjectLiteralExpression(node)) objects.push(node);
    let named: string | undefined;
    if (ts.isPropertyAssignment(node)) named = keyName(node.name);
    else if (ts.isPropertyAccessExpression(node)) named = node.name.text;
    if (named?.startsWith('OPENA2A_TELEMETRY_') && !READ_NAMES.has(named)) {
      findings.push({ file: rel, line: at(node), problem: `${named} is read by nothing` });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  const valueOf = (expr: ts.Expression): string | undefined => {
    if (ts.isStringLiteralLike(expr)) return expr.text;
    if (ts.isIdentifier(expr)) return constants.get(expr.text);
    return undefined;
  };

  for (const obj of objects) {
    const props = new Map<string, ts.Expression>();
    for (const p of obj.properties) {
      if (ts.isPropertyAssignment(p)) {
        const k = keyName(p.name);
        if (k) props.set(k, p.initializer);
      }
    }
    const telemetry = props.get('OPENA2A_TELEMETRY');
    const value = telemetry && valueOf(telemetry);
    if (!value || !OPT_IN.has(value.trim().toLowerCase())) continue;
    const url = props.get('OPENA2A_TELEMETRY_URL');
    const target = url && valueOf(url);
    if (!target || !LOOPBACK.test(target)) {
      findings.push({
        file: rel,
        line: at(obj),
        problem: 'turns usage telemetry on without OPENA2A_TELEMETRY_URL set to a loopback address in the same object',
      });
    }
  }
  return findings;
}

describe('a test that turns telemetry on keeps it on this machine (#963)', () => {
  it('pins OPENA2A_TELEMETRY_URL to loopback beside every OPENA2A_TELEMETRY=on, and names only variables something reads', () => {
    const findings = testSources().flatMap(scan);
    expect(findings.map((f) => `${f.file}:${f.line} ${f.problem}`)).toEqual([]);
  });

  it('the scan sees both problems (non-vacuity)', () => {
    const dir = tempDir('hma-963-scan-');
    const bad = path.join(dir, 'bad.test.ts');
    const unread = ['OPENA2A', 'TELEMETRY', 'ENDPOINT'].join('_');
    writeFileSync(bad, [
      "const DEAD = 'http://127.0.0.1:9';",
      "const remote = { OPENA2A_TELEMETRY: 'on', OPENA2A_TELEMETRY_URL: 'https://api.example.test/event' };",
      "const missing = { OPENA2A_TELEMETRY: 'on' };",
      `const misnamed = { OPENA2A_TELEMETRY: 'on', ${unread}: DEAD };`,
      "const ok = { OPENA2A_TELEMETRY: 'on', OPENA2A_TELEMETRY_URL: DEAD };",
      "const off = { OPENA2A_TELEMETRY: 'off' };",
      '',
    ].join('\n'));
    const problems = scan(bad).map((f) => `${f.line} ${f.problem}`).sort();
    expect(problems).toEqual([
      expect.stringMatching(/^2 turns usage telemetry on/),
      expect.stringMatching(/^3 turns usage telemetry on/),
      expect.stringMatching(new RegExp(`^4 ${unread} is read by nothing`)),
      expect.stringMatching(/^4 turns usage telemetry on/),
    ]);
  });
});

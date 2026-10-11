/**
 * #963 — the test suite sends no usage telemetry to the Registry.
 *
 * Telemetry is on by default, so every spawn of the CLI in this suite sent a
 * usage event. A fresh HOME did not make each one a new install: the install
 * id is a hash of the machine identifier, so the spawns on one machine carried
 * one id. One file in this suite meant to point its runs at a discard port and
 * named a variable the SDK does not read, so every run of it posted to the
 * production endpoint.
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
 *     test names an OPENA2A_TELEMETRY_* variable nothing reads;
 *   - a test that spawns the CLI with an environment object that REPLACES the
 *     worker's (no spread) carries the test-runner marker forward or sets
 *     OPENA2A_TELEMETRY in that object. Without either, the CLI sees no marker
 *     and sends a usage event: one file did exactly that, naming a variable
 *     nothing reads in place of OPENA2A_TELEMETRY. The object is followed
 *     through a variable, and a marker counts only with a value the CLI reads
 *     as one (#999).
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
/** A child_process call whose `env` option, given without a spread, replaces the worker's environment. */
const SPAWN_CALL = /(?:^|\.)(?:spawn|spawnSync|execFile|execFileSync|fork)$/;
/**
 * `exec` and `execSync` take the whole command as one string. Only the bare
 * names and a child_process namespace are read: `RE.exec(text)` is a regular
 * expression, not a spawn.
 */
const EXEC_CALL = /^(?:(?:cp|childProcess|child_process)\.)?(?:exec|execSync)$/;
/**
 * Names a test gives the built CLI in a spawn's command or argument list (#999:
 * only `CLI` and `BUILT_CLI` were read, so `CLI_PATH` and `bin` were not).
 * Any other name counts when its declaration in the file names the CLI's entry
 * file, and so does a string that names it.
 */
const CLI_NAME = /^(?:(?:[A-Z]+_)*CLI(?:_[A-Z]+)*|cli(?:Path|Js|Entry|File)?|bin(?:Path)?|BIN(?:_PATH)?|[A-Z]+_BIN)$/;
const CLI_FILE = /\bcli\.[cm]?[jt]s\b/;
/** A property that keeps a replaced environment from sending: a marker the CLI reads, or its own telemetry choice. */
const KEEPS_OFF = new Set([...CI_MARKERS, ...TEST_RUNNER_MARKERS, 'NODE_ENV', 'OPENA2A_TELEMETRY']);
/** `OPENA2A_TELEMETRY` values the SDK reads as off. */
const OPT_OUT = new Set(['off', '0', 'false', 'no']);
/** Arguments after which the CLI exits before any command arms telemetry: a `--version` run sends no event. */
const VERSION_ONLY = new Set(['-V', '-v', '--version']);

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

function unwrap(expr: ts.Expression): ts.Expression {
  let e = expr;
  while (ts.isParenthesizedExpression(e) || ts.isAsExpression(e) || ts.isSatisfiesExpression(e)
    || ts.isNonNullExpression(e) || ts.isTypeAssertionExpression(e)) e = e.expression;
  return e;
}

/** The initializer of the variable `name` declared in a block enclosing `from`, or undefined. */
function declaredValue(name: string, from: ts.Node): ts.Expression | undefined {
  for (let scope: ts.Node | undefined = from.parent; scope; scope = scope.parent) {
    if (!ts.isBlock(scope) && !ts.isSourceFile(scope) && !ts.isModuleBlock(scope)
      && !ts.isCaseClause(scope) && !ts.isDefaultClause(scope)) continue;
    for (const st of scope.statements) {
      if (!ts.isVariableStatement(st)) continue;
      for (const d of st.declarationList.declarations) {
        if (ts.isIdentifier(d.name) && d.name.text === name) return d.initializer && unwrap(d.initializer);
      }
    }
  }
  return undefined;
}

/** An object literal, given inline or as a variable declared around `from`. */
function objectAt(expr: ts.Expression, from: ts.Node): ts.ObjectLiteralExpression | undefined {
  const e = unwrap(expr);
  const value = ts.isIdentifier(e) ? declaredValue(e.text, from) : e;
  return value && ts.isObjectLiteralExpression(value) ? value : undefined;
}

/** What an `env` option sets: whether it carries the worker's environment, and each property's value expression. */
interface EnvShape { inherits: boolean; values: Map<string, ts.Expression | undefined> }

/**
 * The environment a spawn is handed, or undefined when this file does not say
 * (a parameter, a helper's return value). An `env` given as a variable is
 * followed to its declaration (#999: only an inline object literal was read),
 * a spread of another literal is merged in, and a property assigned to the
 * variable later (`env.CI = 'true'`) counts. A spread of anything else, such
 * as `process.env`, carries the worker's environment and its marker.
 */
function envShape(expr: ts.Expression, from: ts.Node, depth = 0): EnvShape | undefined {
  const e = unwrap(expr);
  const obj = objectAt(e, from);
  if (!obj || depth > 3) return undefined;
  const shape: EnvShape = { inherits: false, values: new Map() };
  for (const p of obj.properties) {
    if (ts.isSpreadAssignment(p)) {
      const inner = envShape(p.expression, from, depth + 1);
      if (!inner) shape.inherits = true;
      else {
        shape.inherits ||= inner.inherits;
        for (const [k, v] of inner.values) shape.values.set(k, v);
      }
    } else if (ts.isPropertyAssignment(p)) {
      const k = keyName(p.name);
      if (k) shape.values.set(k, p.initializer);
    } else if (ts.isShorthandPropertyAssignment(p)) {
      shape.values.set(p.name.text, undefined);
    }
  }
  if (ts.isIdentifier(e)) {
    const variable = e.text;
    const assigned = (node: ts.Node): void => {
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        const left = node.left;
        if (ts.isPropertyAccessExpression(left) && ts.isIdentifier(left.expression) && left.expression.text === variable) {
          shape.values.set(left.name.text, node.right);
        } else if (ts.isElementAccessExpression(left) && ts.isIdentifier(left.expression)
          && left.expression.text === variable && ts.isStringLiteralLike(left.argumentExpression)) {
          shape.values.set(left.argumentExpression.text, node.right);
        }
      }
      ts.forEachChild(node, assigned);
    };
    assigned(from.getSourceFile());
  }
  return shape;
}

/** Whether `args` name the built CLI: by a name tests give it, by a declaration naming its entry file, or in a string. */
function namesCli(args: readonly ts.Expression[], from: ts.Node): boolean {
  let hit = false;
  const visit = (n: ts.Node): void => {
    if (hit) return;
    if (ts.isIdentifier(n)) {
      const value = CLI_NAME.test(n.text) ? undefined : declaredValue(n.text, from);
      if (CLI_NAME.test(n.text) || (value && CLI_FILE.test(value.getText()))) hit = true;
    } else if ((ts.isStringLiteralLike(n) || ts.isTemplateHead(n) || ts.isTemplateMiddle(n) || ts.isTemplateTail(n))
      && CLI_FILE.test(n.text)) {
      hit = true;
    }
    ts.forEachChild(n, visit);
  };
  args.forEach(visit);
  return hit;
}

/** `[CLI, '--version']`: a run that exits before any command arms telemetry. */
function versionOnly(args: ts.Expression | undefined, from: ts.Node): boolean {
  if (!args || !ts.isArrayLiteralExpression(args)) return false;
  const rest = args.elements.filter((el) => !namesCli([el], from));
  return rest.length > 0 && rest.every((el) => ts.isStringLiteralLike(el) && VERSION_ONLY.has(el.text));
}

function scan(file: string): Finding[] {
  const text = readFileSync(file, 'utf8');
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const rel = path.relative(REPO_ROOT, file);
  const constants = new Map<string, string>();
  const objects: ts.ObjectLiteralExpression[] = [];
  const findings: Finding[] = [];
  const at = (node: ts.Node) => sf.getLineAndCharacterOfPosition(node.getStart()).line + 1;

  const collectConstants = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer
      && ts.isStringLiteralLike(node.initializer)) {
      constants.set(node.name.text, node.initializer.text);
    }
    ts.forEachChild(node, collectConstants);
  };
  collectConstants(sf);

  const valueOf = (expr: ts.Expression): string | undefined => {
    if (ts.isStringLiteralLike(expr)) return expr.text;
    if (ts.isIdentifier(expr)) return constants.get(expr.text);
    return undefined;
  };

  /**
   * Whether one property of a replaced environment keeps the run from
   * sending. A value this file does not spell out is taken at its word; a
   * spelled-out one is read the way the CLI reads it (#999: `CI: ''`,
   * `CI: 'false'` and `VITEST: '0'` counted as markers, and the CLI reads none
   * of them as one).
   */
  const keepsOff = (name: string, expr: ts.Expression | undefined): boolean => {
    if (!KEEPS_OFF.has(name)) return false;
    const value = expr && valueOf(unwrap(expr));
    if (value === undefined) return true;
    if (name === 'OPENA2A_TELEMETRY') {
      const choice = value.trim().toLowerCase();
      return OPT_OUT.has(choice) || OPT_IN.has(choice);
    }
    return automationMarker({ [name]: value }) !== undefined;
  };

  const visit = (node: ts.Node): void => {
    if (ts.isObjectLiteralExpression(node)) objects.push(node);
    let named: string | undefined;
    if (ts.isPropertyAssignment(node)) named = keyName(node.name);
    else if (ts.isPropertyAccessExpression(node)) named = node.name.text;
    if (named?.startsWith('OPENA2A_TELEMETRY_') && !READ_NAMES.has(named)) {
      findings.push({ file: rel, line: at(node), problem: `${named} is read by nothing` });
    }
    if (ts.isCallExpression(node)) {
      const callee = node.expression.getText();
      const isSpawn = SPAWN_CALL.test(callee);
      const isExec = !isSpawn && EXEC_CALL.test(callee);
      if ((isSpawn || isExec) && namesCli(node.arguments.slice(0, isExec ? 1 : 2), node)
        && !(isSpawn && versionOnly(node.arguments[1], node))) {
        const options = node.arguments.slice(1).map((a) => objectAt(a, node)).find((o) => o !== undefined);
        const env = options?.properties.find((p) => (ts.isPropertyAssignment(p) || ts.isShorthandPropertyAssignment(p))
          && keyName(p.name) === 'env');
        const given = env && (ts.isPropertyAssignment(env) ? env.initializer : env.name);
        const shape = given && envShape(given, node);
        if (given && shape && !shape.inherits && ![...shape.values].some(([k, v]) => keepsOff(k, v))) {
          findings.push({
            file: rel,
            line: at(given),
            problem: 'spawns the CLI with an environment that replaces the worker\'s and carries no CI or test-runner marker and no OPENA2A_TELEMETRY choice, so the run sends a usage event',
          });
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

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
  it('pins OPENA2A_TELEMETRY_URL to loopback beside every OPENA2A_TELEMETRY=on, names only variables something reads, and hands no CLI spawn a replaced environment without a marker or OPENA2A_TELEMETRY', () => {
    const findings = testSources().flatMap(scan);
    expect(findings.map((f) => `${f.file}:${f.line} ${f.problem}`)).toEqual([]);
  });

  it('the scan sees all three problems (non-vacuity)', () => {
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
      // Line 7: the CLI, an environment that replaces the worker's, no marker
      // and no telemetry choice: the shape that posted to production.
      "spawnSync(process.execPath, [CLI, 'check', 'left-pad', '--json'], { env: { PATH: '', HOME: '', HMA_TELEMETRY: '0' } });",
      // Not problems: the CLI with the environment inherited, with its own
      // telemetry choice, or with a marker carried forward; and a plain
      // `node -e` child, which runs no CLI.
      "spawn(process.execPath, [CLI, 'secure', '.'], { env: { ...process.env, HOME: '' } });",
      "spawnSync(process.execPath, [CLI, 'secure', '.'], { env: { PATH: '', OPENA2A_TELEMETRY: 'off' } });",
      "spawnSync(process.execPath, [CLI, 'secure', '.'], { env: { PATH: '', CI: 'true' } });",
      "spawnSync(process.execPath, ['-e', 'fetch(url)'], { env: { PATH: '', HOME: '' } });",
      '',
    ].join('\n'));
    const problems = scan(bad).map((f) => `${f.line} ${f.problem}`).sort();
    expect(problems).toEqual([
      expect.stringMatching(/^2 turns usage telemetry on/),
      expect.stringMatching(/^3 turns usage telemetry on/),
      expect.stringMatching(new RegExp(`^4 ${unread} is read by nothing`)),
      expect.stringMatching(/^4 turns usage telemetry on/),
      expect.stringMatching(/^7 spawns the CLI with an environment that replaces/),
    ]);
  });

  // #999 — each shape on lines 2-11 passed the scan before: an env given as a
  // variable, a marker spelled with a value the CLI does not read as one, a
  // CLI named CLI_PATH, bin or by its file, and execSync.
  it('the scan follows an env variable, reads marker values, and knows the other names of the CLI (non-vacuity)', () => {
    const dir = tempDir('hma-999-scan-');
    const bad = path.join(dir, 'bad.test.ts');
    // Assembled so this file does not read the CI variable itself, which
    // no-ci-short-circuit-in-tests.test.ts refuses anywhere under __tests__/.
    const ciRead = ['process', 'env', 'CI'].join('.');
    writeFileSync(bad, [
      "const replaced = { PATH: '', HOME: '' };",
      "spawnSync(process.execPath, [CLI, 'secure', '.'], { env: replaced });",
      "spawnSync(process.execPath, [CLI, 'secure', '.'], { env: { PATH: '', CI: '' } });",
      "spawnSync(process.execPath, [CLI, 'secure', '.'], { env: { PATH: '', CI: 'false', VITEST: '0' } });",
      "spawnSync(process.execPath, [CLI, 'secure', '.'], { env: { PATH: '', OPENA2A_TELEMETRY: '' } });",
      "execFileSync(process.execPath, [CLI_PATH, 'secure', '.'], { env: { PATH: '' } });",
      "execFileSync(bin, ['secure', '.'], { env: { PATH: '' } });",
      'execSync(`node ${CLI} secure .`, { env: { PATH: \'\' } });',
      "const ENTRY = path.join(ROOT, 'dist', 'cli.js');",
      "spawnSync(process.execPath, [ENTRY, 'secure', '.'], { env: { PATH: '' } });",
      "function run() { const env = { PATH: '' }; return spawnSync(process.execPath, [CLI, 'secure'], { env }); }",
      // Not problems: a marker assigned after the declaration or spread in
      // from another literal, a `--version` run (it exits before any command
      // arms telemetry), NODE_ENV=test, a value this file does not spell out,
      // a regular expression's exec, and the worker's environment spread in.
      "const marked = { PATH: '' }; marked.CI = 'true';",
      "spawnSync(process.execPath, [CLI, 'secure', '.'], { env: marked });",
      "const base = { PATH: '', VITEST: 'true' };",
      "spawnSync(process.execPath, [CLI, 'secure', '.'], { env: { ...base, HOME: '' } });",
      "spawnSync(process.execPath, [CLI, '-V'], { env: { PATH: '' } });",
      "spawnSync(process.execPath, [CLI, 'secure', '.'], { env: { PATH: '', NODE_ENV: 'test' } });",
      `spawnSync(process.execPath, [CLI, 'secure', '.'], { env: { PATH: '', CI: ${ciRead} } });`,
      'const m = /x/.exec(cliOutput);',
      "spawnSync(process.execPath, [CLI, 'secure', '.'], { env: { ...process.env, CI: '' } });",
      '',
    ].join('\n'));
    const found = scan(bad);
    expect(found.every((f) => /^spawns the CLI with an environment that replaces/.test(f.problem))).toBe(true);
    expect(found.map((f) => f.line).sort((a, b) => a - b)).toEqual([2, 3, 4, 5, 6, 7, 8, 10, 11]);
  });
});

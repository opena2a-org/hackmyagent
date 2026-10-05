/**
 * A suite whose only unmet precondition is the built CLI fails by name.
 *
 * `npm test` does not build. A suite that decided whether to run by asking
 * whether `dist/cli.js` exists therefore reported every one of its spawn cases
 * as skipped on a checkout that had not built, and `npm test` still exited 0:
 * measured on one checkout with `dist/` moved aside, five such files reported
 * 66 skipped and 31 passed. The skip is honest about nothing — the build is
 * not a property of the host the way a missing `lsof` or a non-POSIX shell is,
 * it is one command away, and the reader of a green run cannot tell "this was
 * measured" from "this was never attempted".
 *
 * So the build is asserted instead, through `assertDistFresh()` in
 * `__tests__/helpers/dist-freshness.ts`, whose message names the command:
 * "dist/cli.js missing — run `npm run build` before this suite".
 *
 * WHAT THIS GATE FLAGS
 *
 *   A conditional-execution gate whose ENTIRE condition is the existence of
 *   the built CLI, in each form this tree has used:
 *
 *     - a `runIf` / `skipIf` member call on a runner;
 *     - a conditional expression choosing a runner or its `.skip` member,
 *       including through a local alias;
 *
 *   where the condition is `existsSync(<built CLI>)`, a constant bound to it,
 *   or a zero-argument function returning it — through any chain of such
 *   bindings, and negated or not.
 *
 *   A condition that ALSO names something else (a platform, a fixture outside
 *   the tree, a binary on PATH) is not flagged: those suites have a second
 *   precondition a runner may genuinely lack, and splitting them is a separate
 *   change. Neither is an early `return` inside a case body; that form is
 *   tracked separately and is not counted here.
 *
 * This is a static gate on purpose. What it prevents is a run that reports
 * green while executing none of the gated cases, which no assertion inside
 * those cases can observe.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import ts from 'typescript';

const TESTS_ROOT = path.resolve(__dirname, '..');

/** Every `.test.ts` under `__tests__/`. */
function allTestFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) allTestFiles(full, out);
    else if (entry.name.endsWith('.test.ts')) out.push(full);
  }
  return out;
}

/**
 * Text that spells the built CLI's path, however it is assembled. Built from
 * fragments so this file's own source does not read as a spawn suite to the
 * sibling freshness gate.
 */
const BUILT_PATH_TEXT: readonly RegExp[] = [
  new RegExp(['dist', 'cli\\.js'].join('\\/')),
  new RegExp(`['"]dist['"]\\s*,\\s*['"]cli\\.js['"]`),
];
const BUILT_EXPORT = 'BUILT' + '_CLI';
const RUNNERS = new Set(['describe', 'it', 'test']);

function unwrap(e: ts.Expression): ts.Expression {
  let cur = e;
  while (ts.isParenthesizedExpression(cur) || ts.isAsExpression(cur) || ts.isNonNullExpression(cur)) {
    cur = cur.expression;
  }
  return cur;
}

interface DistGateSite {
  line: number;
  text: string;
}

/**
 * Every gate in `src` whose whole condition is the built CLI's existence.
 * `fileName` only labels the parse.
 */
function distOnlyGates(src: string, fileName = 'suite.ts'): DistGateSite[] {
  const sf = ts.createSourceFile(fileName, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);

  // Names bound to the built CLI's path.
  const pathNames = new Set<string>();
  const declarations: ts.Node[] = [];
  const collect = (node: ts.Node): void => {
    if (ts.isImportSpecifier(node) && (node.propertyName ?? node.name).text === BUILT_EXPORT) {
      pathNames.add(node.name.text);
    }
    if (ts.isVariableDeclaration(node) || ts.isFunctionDeclaration(node)) declarations.push(node);
    ts.forEachChild(node, collect);
  };
  collect(sf);
  for (const d of declarations) {
    if (ts.isVariableDeclaration(d) && ts.isIdentifier(d.name) && d.initializer) {
      const text = d.initializer.getText(sf);
      if (BUILT_PATH_TEXT.some((re) => re.test(text))) pathNames.add(d.name.text);
    }
  }

  const isBuiltPath = (e: ts.Expression): boolean => {
    const u = unwrap(e);
    if (ts.isIdentifier(u)) return pathNames.has(u.text);
    return BUILT_PATH_TEXT.some((re) => re.test(u.getText(sf)));
  };

  const isExistsOfBuilt = (e: ts.Expression): boolean => {
    const u = unwrap(e);
    if (!ts.isCallExpression(u) || u.arguments.length !== 1) return false;
    const callee = u.expression;
    const name = ts.isIdentifier(callee)
      ? callee.text
      : ts.isPropertyAccessExpression(callee) ? callee.name.text : '';
    return name === 'existsSync' && isBuiltPath(u.arguments[0]);
  };

  // Constants and zero-argument functions that answer "is it built?" and
  // nothing else, to a fixpoint so a predicate defined through another counts.
  const valuePreds = new Set<string>();
  const callPreds = new Set<string>();
  const isBuiltOnly = (e: ts.Expression): boolean => {
    const u = unwrap(e);
    if (isExistsOfBuilt(u)) return true;
    if (ts.isIdentifier(u)) return valuePreds.has(u.text);
    if (ts.isCallExpression(u) && u.arguments.length === 0 && ts.isIdentifier(u.expression)) {
      return callPreds.has(u.expression.text);
    }
    return false;
  };
  const returnsBuiltOnly = (body: ts.ConciseBody | undefined): boolean => {
    if (!body) return false;
    if (!ts.isBlock(body)) return isBuiltOnly(body);
    const [only, ...rest] = body.statements;
    return rest.length === 0 && !!only && ts.isReturnStatement(only) && !!only.expression && isBuiltOnly(only.expression);
  };
  for (let changed = true; changed; ) {
    changed = false;
    for (const d of declarations) {
      let name = '';
      let kind: 'value' | 'call' | '' = '';
      if (ts.isFunctionDeclaration(d) && d.name && d.parameters.length === 0 && returnsBuiltOnly(d.body)) {
        name = d.name.text;
        kind = 'call';
      } else if (ts.isVariableDeclaration(d) && ts.isIdentifier(d.name) && d.initializer) {
        const init = unwrap(d.initializer);
        if ((ts.isArrowFunction(init) || ts.isFunctionExpression(init)) && init.parameters.length === 0) {
          if (returnsBuiltOnly(init.body)) { name = d.name.text; kind = 'call'; }
        } else if (isBuiltOnly(init)) {
          name = d.name.text;
          kind = 'value';
        }
      }
      const set = kind === 'call' ? callPreds : kind === 'value' ? valuePreds : null;
      if (set && !set.has(name)) {
        set.add(name);
        changed = true;
      }
    }
  }

  const isBuiltGate = (e: ts.Expression): boolean => {
    let u = unwrap(e);
    if (ts.isPrefixUnaryExpression(u) && u.operator === ts.SyntaxKind.ExclamationToken) u = unwrap(u.operand);
    return isBuiltOnly(u);
  };
  const isRunnerSkip = (e: ts.Expression): boolean => {
    const u = unwrap(e);
    return ts.isPropertyAccessExpression(u)
      && u.name.text === 'skip'
      && ts.isIdentifier(u.expression)
      && RUNNERS.has(u.expression.text);
  };

  const sites: DistGateSite[] = [];
  const report = (node: ts.Node): void => {
    const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
    sites.push({ line: line + 1, text: node.getText(sf).split('\n')[0].slice(0, 120) });
  };
  const visit = (node: ts.Node): void => {
    if (
      ts.isCallExpression(node)
      && ts.isPropertyAccessExpression(node.expression)
      && (node.expression.name.text === 'runIf' || node.expression.name.text === 'skipIf')
      && node.arguments.length === 1
      && isBuiltGate(node.arguments[0])
    ) {
      report(node);
    } else if (
      ts.isConditionalExpression(node)
      && isBuiltGate(node.condition)
      && (isRunnerSkip(node.whenTrue) || isRunnerSkip(node.whenFalse))
    ) {
      report(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return sites;
}

describe('a suite whose only unmet precondition is the build fails by name', () => {
  const files = allTestFiles(TESTS_ROOT);

  it('scans the suites at all (the gate is not reading an empty set)', () => {
    expect(files.length).toBeGreaterThan(150);
  });

  it('no gate under __tests__/ skips on the built CLI alone', () => {
    const offenders = files
      .flatMap((f) => distOnlyGates(readFileSync(f, 'utf8'), f)
        .map((s) => `${path.relative(TESTS_ROOT, f)}:${s.line}  ${s.text}`))
      .sort();

    expect(
      offenders,
      'These gates skip their cases when the built CLI is absent, so a checkout that has\n'
      + 'not built reports them as skipped and `npm test` exits 0 without running them.\n'
      + 'Remove the gate and assert the build instead, in the block that spawns it:\n'
      + "  import { assertDistFresh } from '<rel>/helpers/dist-freshness';\n"
      + '  beforeAll(assertDistFresh);\n',
    ).toEqual([]);
  });

  // The detector's own predicate, in both directions. A detector that missed
  // a form would report zero offenders forever; one that flagged a mixed
  // condition would push a suite with a real second precondition into
  // failing for the wrong reason.
  const P = ['di', 'st'].join('');
  const DECL = `const CLI = join(ROOT, '${P}', 'cli.js');\n`;

  it('flags each form the tree has used', () => {
    const forms = [
      `${DECL}describe.runIf(existsSync(CLI))('s', () => {});`,
      `${DECL}it.skipIf(!existsSync(CLI))('c', () => {});`,
      `${DECL}it.skipIf(!fs.existsSync(CLI))('c', () => {});`,
      `${DECL}const canRun = () => existsSync(CLI);\nit.runIf(canRun())('c', () => {});`,
      `${DECL}function canRunSpawn(): boolean {\n  return existsSync(CLI);\n}\nit.skipIf(!canRunSpawn())('c', () => {});`,
      `${DECL}const built = existsSync(CLI);\nit.skipIf(!built)('c', () => {});`,
      `${DECL}const skipIfNoBuild = fs.existsSync(CLI) ? it : it.skip;\nskipIfNoBuild('c', () => {});`,
      `${DECL}const ok = existsSync(CLI);\nconst d = ok ? describe : describe.skip;\nd('s', () => {});`,
      `import { ${BUILT_EXPORT} as CLI } from '../helpers/x';\ndescribe.runIf(existsSync(CLI))('s', () => {});`,
      `const cli = join(__dirname, '../../${P}/cli.js');\nit.skipIf(!existsSync(cli))('c', () => {});`,
      // A predicate defined through another predicate.
      `${DECL}function a() { return existsSync(CLI); }\nconst b = () => a();\nit.runIf(b())('c', () => {});`,
    ];
    for (const src of forms) {
      expect(distOnlyGates(src).length, src).toBe(1);
    }
  });

  it('leaves a condition with a second precondition alone', () => {
    const mixed = [
      `${DECL}it.runIf(existsSync(CLI) && existsSync(FIXTURE))('c', () => {});`,
      `${DECL}describe.skipIf(process.platform === 'win32' || !existsSync(CLI))('s', () => {});`,
      `${DECL}function canRunSpawn(): boolean {\n  if (process.platform === 'win32') return false;\n  return existsSync(CLI);\n}\nit.runIf(canRunSpawn())('c', () => {});`,
      `${DECL}const available = existsSync(CLI) && existsSync(SKILL_MD);\ndescribe.skipIf(!available)('s', () => {});`,
      // Existence of something that is not the build.
      `const FIXTURE = join(ROOT, 'fixtures', 'x');\nit.runIf(existsSync(FIXTURE))('c', () => {});`,
      // The replacement form.
      `${DECL}beforeAll(assertDistFresh);\nit('c', () => {});`,
    ];
    for (const src of mixed) {
      expect(distOnlyGates(src), src).toEqual([]);
    }
  });

  it('reads code, not prose: a gate quoted in a comment or a string is not a gate', () => {
    expect(distOnlyGates(`${DECL}// it.runIf(existsSync(CLI))('c', () => {});\nit('c', () => {});`)).toEqual([]);
    expect(distOnlyGates(`${DECL}const s = "it.skipIf(!existsSync(CLI))";`)).toEqual([]);
  });

  it('the assertion it points at exists and names the command', async () => {
    const mod = await import('../helpers/dist-freshness');
    expect(typeof mod.assertDistFresh).toBe('function');
    const helper = readFileSync(path.join(TESTS_ROOT, 'helpers', 'dist-freshness.ts'), 'utf8');
    expect(helper).toContain('missing — run `npm run build` before this suite');
  });
});

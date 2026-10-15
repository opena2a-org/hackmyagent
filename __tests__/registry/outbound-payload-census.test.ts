/**
 * Every registry and telemetry payload that src/cli.ts sends is built by a
 * builder in src/registry/submissions.ts, from the run's own result.
 *
 * A payload field written inline at a send site in src/cli.ts is how a
 * submission came to carry a value the run never produced: a repository URL
 * with its user name and password, a target name with its query string, a
 * tree hash of the shell's working directory, a retry stamped with the time of
 * the retry and an empty findings list, a SOUL control sent as `medium`
 * whatever its own severity. Each was fixed at its one site while the next
 * site kept the same shape.
 *
 * This reads src/cli.ts and fails when an argument of a call that sends to the
 * registry or the telemetry endpoint (or builds what is sent there) is
 *   - an object or array literal, or a spread of one;
 *   - a variable declared with an object or array literal;
 *   - the result of a function declared in src/cli.ts, or a variable declared
 *     with one: a payload builder left behind in the command file.
 * For `fetch`, the request body is checked the same way.
 *
 * The allow-list is empty and stays empty: a new send site calls a builder.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import ts from 'typescript';

const CLI = path.resolve(__dirname, '..', '..', 'src', 'cli.ts');

/**
 * Calls that put a payload on the wire, queue one for it, or build one for
 * it. Matched by the called name, so `client.publishScan(...)` and
 * `publishScan(...)` are both found.
 */
const SENDERS = new Set([
  // registry publish and its scan token
  'publishScanResults',
  'buildPublishPayload',
  'reportPublishResult',
  'requestScanToken',
  'reportFindings',
  'reportRemediation',
  // community and version reports
  'reportCommunityResult',
  'reportScanResult',
  'buildScanReport',
  'buildCommunityReport',
  'buildAttackReport',
  'buildCommunityAttackReport',
  // CI submission
  'submitCIScanResult',
  // check's share and its retry queue
  'publishScan',
  'publishToRegistry',
  'shareCheckScan',
  'queuePendingScan',
  // contribution events
  'buildScanEvent',
  'handleContribution',
  'handleSoulContribution',
  'queueAndMaybeFlush',
  'queueEvent',
  'flushQueue',
  'submitBatch',
  'submitContribution',
  // package narrative
  'wireNarrativePublish',
  // usage telemetry
  'track',
  // NanoMind feedback and classification telemetry
  'submitFeedback',
  'confirmClassification',
  'correctClassification',
  'queueClassificationStat',
  // stub status write-back
  'buildPatchBody',
]);

/** Sites allowed to build a payload inline. Empty: every site calls a builder. */
const ALLOWED: readonly string[] = [];

/**
 * Arguments that say where to send, not what: the registry URL, which
 * src/cli.ts checks with its own `validateRegistryUrl`. Indexed from 0. Every
 * other argument of a sender, or of a builder whose result is sent, is
 * payload.
 */
const DESTINATION_ARGS: Record<string, readonly number[]> = {
  publishScanResults: [1],
  narrativeSubmission: [3],
};

interface Violation { site: string; line: number; reason: string }

function calleeName(call: ts.CallExpression): string | undefined {
  const e = call.expression;
  if (ts.isIdentifier(e)) return e.text;
  if (ts.isPropertyAccessExpression(e)) return e.name.text;
  return undefined;
}

function unwrap(e: ts.Expression): ts.Expression {
  let x = e;
  for (;;) {
    if (ts.isParenthesizedExpression(x) || ts.isAsExpression(x) || ts.isNonNullExpression(x)
      || ts.isTypeAssertionExpression(x) || ts.isSatisfiesExpression(x) || ts.isAwaitExpression(x)) {
      x = x.expression;
    } else {
      return x;
    }
  }
}

/** Names of every function declared in the file, at any depth. */
function localFunctions(sf: ts.SourceFile): Set<string> {
  const names = new Set<string>();
  const visit = (n: ts.Node): void => {
    if (ts.isFunctionDeclaration(n) && n.name) names.add(n.name.text);
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer) {
      const init = unwrap(n.initializer);
      if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) names.add(n.name.text);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return names;
}

/** The declaration `name` refers to at `from`: the nearest enclosing scope that declares it. */
function resolve(name: string, from: ts.Node): ts.VariableDeclaration | ts.ParameterDeclaration | undefined {
  for (let scope: ts.Node | undefined = from.parent; scope; scope = scope.parent) {
    if (ts.isFunctionLike(scope)) {
      for (const p of scope.parameters) if (ts.isIdentifier(p.name) && p.name.text === name) return p;
    }
    let found: ts.VariableDeclaration | undefined;
    const statements = ts.isBlock(scope) || ts.isSourceFile(scope) || ts.isModuleBlock(scope) || ts.isCaseClause(scope) || ts.isDefaultClause(scope)
      ? scope.statements
      : undefined;
    if (!statements) continue;
    for (const s of statements) {
      if (!ts.isVariableStatement(s)) continue;
      for (const d of s.declarationList.declarations) {
        if (ts.isIdentifier(d.name) && d.name.text === name) found = d;
      }
    }
    if (found) return found;
  }
  return undefined;
}

/**
 * Why `expr` is a payload built in src/cli.ts, or undefined when it is a value
 * computed elsewhere. `throughCalls` is false for a variable's initializer: a
 * variable set from an imported call holds what that call returned, and the
 * call's own arguments (scan options, say) are not the payload.
 */
function inlineConstruction(
  expr: ts.Expression,
  locals: Set<string>,
  seen: Set<ts.Node>,
  throughCalls = true,
): string | undefined {
  const e = unwrap(expr);
  if (seen.has(e)) return undefined;
  seen.add(e);
  if (ts.isObjectLiteralExpression(e)) return 'an object literal';
  if (ts.isArrayLiteralExpression(e)) return 'an array literal';
  if (ts.isSpreadElement(e)) return inlineConstruction(e.expression, locals, seen, throughCalls);
  if (ts.isConditionalExpression(e)) {
    return inlineConstruction(e.whenTrue, locals, seen, throughCalls) ?? inlineConstruction(e.whenFalse, locals, seen, throughCalls);
  }
  if (ts.isBinaryExpression(e) && [ts.SyntaxKind.QuestionQuestionToken, ts.SyntaxKind.BarBarToken, ts.SyntaxKind.AmpersandAmpersandToken].includes(e.operatorToken.kind)) {
    return inlineConstruction(e.left, locals, seen, throughCalls) ?? inlineConstruction(e.right, locals, seen, throughCalls);
  }
  if (ts.isCallExpression(e)) {
    const name = calleeName(e);
    if (name && ts.isIdentifier(e.expression) && locals.has(name)) return `built by ${name}() in src/cli.ts`;
    if (!throughCalls) return undefined;
    // An imported transform or builder given the payload directly
    // (JSON.stringify, emitFindings) passes it through: what it is given is
    // what is sent.
    for (const [i, a] of e.arguments.entries()) {
      if (name && DESTINATION_ARGS[name]?.includes(i)) continue;
      const r = inlineConstruction(a, locals, seen, true);
      if (r) return `${name ?? 'a call'}(${r})`;
    }
    return undefined;
  }
  // A deferred builder call: `() => buildX(run)`.
  if (ts.isArrowFunction(e) && !ts.isBlock(e.body)) return inlineConstruction(e.body, locals, seen, throughCalls);
  if (ts.isIdentifier(e)) {
    const decl = resolve(e.text, e);
    if (decl && ts.isVariableDeclaration(decl) && decl.initializer) {
      const r = inlineConstruction(decl.initializer, locals, seen, false);
      if (r) return `\`${e.text}\`, declared as ${r}`;
    }
  }
  return undefined;
}

function enclosingFunctionName(n: ts.Node): string {
  for (let p: ts.Node | undefined = n.parent; p; p = p.parent) {
    if (ts.isFunctionDeclaration(p) && p.name) return p.name.text;
    if ((ts.isArrowFunction(p) || ts.isFunctionExpression(p)) && ts.isVariableDeclaration(p.parent) && ts.isIdentifier(p.parent.name)) {
      return p.parent.name.text;
    }
    if (ts.isCallExpression(p) && ts.isPropertyAccessExpression(p.expression) && p.expression.name.text === 'action') {
      // program.command('<name>')...action(...)
      let c: ts.Expression = p.expression.expression;
      while (ts.isCallExpression(c) && ts.isPropertyAccessExpression(c.expression)) {
        if (c.expression.name.text === 'command' && c.arguments[0] && ts.isStringLiteral(c.arguments[0])) {
          return `${c.arguments[0].text.split(' ')[0]} action`;
        }
        c = c.expression.expression;
      }
    }
  }
  return 'module scope';
}

/** Every inline payload construction in `source` (the text of src/cli.ts). */
function inlinePayloads(source: string): Violation[] {
  const sf = ts.createSourceFile('cli.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const locals = localFunctions(sf);
  const out: Violation[] = [];
  const visit = (n: ts.Node): void => {
    if (ts.isCallExpression(n)) {
      const name = calleeName(n);
      const line = sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;
      const site = `${name}() in ${enclosingFunctionName(n)}`;
      if (name && SENDERS.has(name)) {
        n.arguments.forEach((a, i) => {
          if (DESTINATION_ARGS[name]?.includes(i)) return;
          const r = inlineConstruction(a, locals, new Set());
          if (r) out.push({ site, line, reason: `argument ${i + 1} is ${r}` });
        });
      } else if (name === 'fetch' && n.arguments[1]) {
        const init = unwrap(n.arguments[1]);
        const bodyProp = ts.isObjectLiteralExpression(init)
          ? init.properties.find((p) => p.name && ts.isIdentifier(p.name) && p.name.text === 'body')
          : undefined;
        if (bodyProp && ts.isPropertyAssignment(bodyProp)) {
          const r = inlineConstruction(bodyProp.initializer, locals, new Set());
          if (r) out.push({ site, line, reason: `the request body is ${r}` });
        } else if (bodyProp && ts.isShorthandPropertyAssignment(bodyProp)) {
          const r = inlineConstruction(bodyProp.name, locals, new Set());
          if (r) out.push({ site, line, reason: `the request body is ${r}` });
        }
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return out;
}

const format = (v: Violation): string => `src/cli.ts:${v.line} ${v.site}: ${v.reason}`;

describe('src/cli.ts builds no registry or telemetry payload inline', () => {
  it('every send site in src/cli.ts hands the sender a value a builder returned', () => {
    const found = inlinePayloads(readFileSync(CLI, 'utf8'))
      .filter((v) => !ALLOWED.includes(`${v.site}: ${v.reason}`))
      .map(format);
    expect(found, 'build the payload in src/registry/submissions.ts from the run\'s result, and call that builder here').toEqual([]);
  });

  it('the allow-list is empty', () => {
    expect(ALLOWED).toEqual([]);
  });

  // The census is only as good as what it sees. Each of these is a shape a
  // send site in src/cli.ts had; planted in a copy of the file, each is found.
  const planted: Array<[string, string]> = [
    ['an object literal passed to the publish', "publishScanResults({ packageName: 'planted', directory: process.cwd() }, 'https://registry.invalid');"],
    ['a spread of an object literal', "client.publishScan({ ...{ name: 'planted' }, findings: [] });"],
    ['a variable declared with an object literal', "{ const planted = { packageName: 'planted' }; publishScanResults(planted, 'u'); }"],
    ['an empty findings array', "handleContribution(undefined, '.', [], 0);"],
    ['a constant severity in an event', "buildScanEvent('planted', '.', [{ severity: 'medium' } as any], 0);"],
    ['a builder declared in src/cli.ts', "function plantedSubmission() { return 1; }\nshareCheckScan(plantedSubmission() as any);"],
    ['a request body built inline', "fetch('https://registry.invalid', { method: 'POST', body: JSON.stringify({ name: 'planted' }) });"],
    ['a usage event built inline', "tele.track('planted', { success: true, durationMs: Date.now() });"],
  ];
  it.each(planted)('a planted send site with %s is found', (_label, line) => {
    const source = readFileSync(CLI, 'utf8');
    const before = inlinePayloads(source).length;
    const after = inlinePayloads(`${source}\n${line}\n`);
    expect(after.length, after.map(format).join('\n')).toBe(before + 1);
  });
});

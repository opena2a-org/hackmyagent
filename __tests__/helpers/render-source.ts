/**
 * The rendering property asked of the SOURCE, not of a fixture (#339 follow-up).
 *
 * `report-render-safety.test.ts` plants a hostile filename, runs a command, and
 * reads what came back. That is the right instrument for the commands it runs,
 * and it is the reason `detect`, `scan-soul`, `harden-soul` and `wild` were
 * fixed. But it can only fail on a code path a fixture reaches, and a report has
 * hundreds of branches: an `ENOENT` message, a single-FILE target refusal, a
 * governance summary that only renders when a meter can still move. #339 swept
 * three call sites and left five more raw, in the same file, reachable by an
 * ordinary user mistake — `secure --fix <a file>` printed three pasteable
 * citations built straight out of `originalTarget`.
 *
 * Writing a fixture per branch is the expensive answer and it is never
 * finished. This is the cheap one and it is total over the file: read the
 * source, find every call that PRINTS, and require every path-bearing
 * expression inside it to have gone through a display escape. A new raw
 * `console.log(\`… ${targetDir}\`)` fails the build the moment it is written,
 * whether or not any test ever runs that branch.
 *
 * What it is NOT: a proof. Taint is followed one level into helpers declared in
 * the same file, and only far enough to see whether the helper escapes the
 * parameter it was handed. A path laundered through a local variable inside a
 * helper, or through another module, is invisible here. That is why the runtime
 * property still runs beside it: two instruments with different blind spots,
 * neither one trusted alone.
 */
import ts from 'typescript';
import { readFileSync } from 'node:fs';
import path from 'node:path';

/** Where a report actually reaches the terminal. */
const PRINTERS = new Set([
  'console.log',
  'console.error',
  'console.warn',
  'console.info',
  'process.stdout.write',
  'process.stderr.write',
]);

/**
 * The functions that make a tree-derived string safe to put on a line.
 *
 * `escapeForDisplay` / `escapePathForDisplay` make the hazards visible;
 * `citationPath` / `citationTarget` refuse to build a command for a path that
 * cannot be shown truthfully. `JSON.stringify` is here because it is a total
 * escape into a quoted literal — it is how the tool's own `--json` output and
 * several diagnostics render a name.
 *
 * `shellQuote` is deliberately ABSENT. It makes a path safe for a SHELL, not for
 * a terminal: a raw newline inside single quotes still splits the rendered line,
 * which is #324 exactly. Quoting is necessary for a citation and never
 * sufficient for a display.
 */
const SANITIZERS = new Set([
  'escapeForDisplay',
  'escapePathForDisplay',
  'citationPath',
  'citationTarget',
  'JSON.stringify',
]);

/**
 * The subset that makes a path safe to PASTE, as opposed to safe to look at.
 *
 * A display escape renders a path faithfully and is never enough inside a
 * command: `escapePathForDisplay` turns a newline into `\n`, so pasting the
 * line names a different file (#343), and it does not quote, so a directory
 * called `proj; touch $HOME/PWNED` produces a command that runs it. Only the
 * citation helpers quote, refuse a path that cannot be shown truthfully, and
 * make a leading `-` an operand.
 *
 * This distinction is the one the gate was missing when it passed
 *
 *     process.stderr.write(`  Rollback: \`${CLI_PREFIX} rollback ${displayDir}\``)
 *
 * in `secure --fix` — a live injection, in the flagship command.
 */
const CITATION_HELPERS = new Set(['citationPath', 'citationTarget']);

/**
 * Names that hold a filesystem path.
 *
 * Deliberately a NAME test rather than a type test. The values that reach these
 * printers are `string`, so a type cannot separate a path from a heading, and
 * the alternative — annotating every path in the codebase with a branded type —
 * is a refactor this gate cannot demand. A name test over-fires on a variable
 * called `path` that holds a URL component, and that is the right direction to
 * be wrong in: escaping a string that did not need it is a no-op, because
 * `escapeForDisplay` returns text without hazards unchanged.
 */
const PATH_NAME = new RegExp(
  '^(?:'
  + 'target|targetDir|targetPath|originalTarget|directory|dir|displayDir|'
  + 'file|filePath|filename|fileName|path|dirPath|dirname|basename|'
  + 'localPath|outputDir|outputPath|oraclePath|configPath|backupPath|'
  + 'archivePath|soulPath|scanPath|resolvedTarget|resolved|entry|entryPath|'
  // `location` and `loc` hold `<file>:<line>` built out of a finding's path.
  // They are path-bearing by CONTENT while carrying none of the spellings
  // above, so the name test could not see them and an unescaped one was live
  // at `src/cli.ts:625`.
  + 'location|loc'
  + ')$'
  // …plus the compound spellings: anything ending in Path/Dir/File/Target,
  // which is how this codebase names the rest of them (`soulFileName`,
  // `hardenFileName`, `backupPath`, `citeDirTarget`).
  + '|(?:Path|Dir|Directory|File|FileName|Filename|Target)$',
);

export interface RenderSite {
  file: string;
  line: number;
  /** The identifier or property whose value is an unescaped path. */
  name: string;
  /** The printing call, trimmed, for the failure message. */
  code: string;
  /** The command whose `.action` encloses this call, when there is one. */
  command: string | null;
}

interface FileAnalysis {
  source: ts.SourceFile;
  relative: string;
  /** Local function declarations by name, for one-level taint following. */
  helpers: Map<string, ts.FunctionLikeDeclaration>;
  /** Names whose every declaration in this file comes out of a sanitizer. */
  sanitizedNames: Set<string>;
}

/**
 * The dotted name of a call's callee, to any depth.
 *
 * It used to build the name from at most TWO levels, taking `obj.name.text` for
 * a nested property access — so `process.stderr.write` came back as
 * `stderr.write` and did not match `PRINTERS`. Two of the six printers were
 * dead, `src/` holds 156 `process.std*.write` calls, and the gate reported zero
 * unescaped sites while sixteen were live. One of them was a shell injection in
 * `secure --fix`.
 *
 * The lesson is not "two levels was too few" — it is that the printer list was
 * never checked against the source it was meant to cover. `finds-every-printer`
 * below asserts each entry matches something real.
 */
function calleeName(node: ts.CallExpression): string {
  return dottedName(node.expression);
}

function dottedName(e: ts.Expression): string {
  if (ts.isIdentifier(e)) return e.text;
  if (ts.isPropertyAccessExpression(e)) {
    const base = dottedName(e.expression);
    return base ? `${base}.${e.name.text}` : e.name.text;
  }
  return '';
}

/**
 * A name is treated as already-escaped only when EVERY declaration of it in the
 * file holds a value that carries no unescaped path — the same question asked of
 * a printer, asked of an initializer. `const escFile = escapePathForDisplay(f)`
 * qualifies; so does a template built out of escaped parts; `const targetDir =
 * resolve(directory)` does not.
 *
 * Every declaration, not any: one raw `const target = argv[2]` anywhere
 * disqualifies the name everywhere, so a shadowing declaration in another
 * function cannot launder a variable that happens to share its name.
 *
 * The answer feeds back into the question — a safe name makes the initializers
 * that mention it safe — so it is computed to a fixed point rather than in one
 * pass. The set only ever grows, and it is bounded by the number of names in
 * the file, so the loop terminates.
 */
function safeNames(source: ts.SourceFile, helpers: Map<string, ts.FunctionLikeDeclaration>): Set<string> {
  const declarations = new Map<string, ts.Expression[]>();
  const undeclarable = new Set<string>();
  const collect = (n: ts.Node): void => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name)
      && !(n.initializer && (ts.isArrowFunction(n.initializer) || ts.isFunctionExpression(n.initializer)))) {
      if (!n.initializer) {
        // `let x;` assigned later — nothing here to judge, so never safe.
        undeclarable.add(n.name.text);
      } else {
        const list = declarations.get(n.name.text) ?? [];
        list.push(n.initializer);
        declarations.set(n.name.text, list);
      }
    }
    ts.forEachChild(n, collect);
  };
  collect(source);

  const safe = new Set<string>();
  for (let round = 0; round < 8; round++) {
    let grew = false;
    for (const [name, inits] of declarations) {
      if (safe.has(name) || undeclarable.has(name)) continue;
      const analysis: FileAnalysis = { source, relative: '', helpers, sanitizedNames: safe };
      // An initializer must PROVE escaping, not merely fail to mention a path.
      //
      // Requiring only "no uncovered path reference" made the answer vacuously
      // true for any initializer with no path-named reference in it at all —
      // and the NAME is what put the variable in scope for this question. So
      // `const outputDir = options.output ?? result.dirName` was declared safe
      // (neither `options.output` nor `result.dirName` matches the path-name
      // test), and every raw `${outputDir}` in the file went invisible. Worst
      // of all, `const path = require('path')` was clean, which made every
      // `x.path` property in the file invisible — including `finding.path`,
      // remote data from `scan`, one of the sites this gate was written for.
      //
      // Now a name is safe only when every declaration of it runs through a
      // sanitizer AND leaves no path reference uncovered. An initializer that
      // mentions no sanitizer is not "safe", it is UNKNOWN, and unknown means
      // the references to it are still asked about at the point they print.
      // A name is safe when its value DEMONSTRABLY came from a path that was
      // escaped: at least one path reference, and every one of them either
      // inside a sanitizer or already a safe name.
      //
      // The "at least one" is what stops the vacuous answer. Requiring only
      // "no uncovered reference" made every initializer with no path-named
      // reference safe — `const outputDir = options.output ?? result.dirName`
      // qualified, because neither `options.output` nor `result.dirName`
      // matches the name test, and every raw `${outputDir}` in the file went
      // invisible. `const path = require('path')` qualified too, which hid
      // every `x.path` property in the file, `finding.path` among them.
      //
      // Counting has to see through safe names, or `const loc = shortFile + …`
      // reads as "no paths here" rather than "one path, already escaped".
      const clean = inits.every((init) => {
        const refs = valuePathRefs(init, analysis, true);
        return refs.length > 0 && refs.every((ref) => insideSanitizer(ref, init)
          || isSafeName(ref, safe));
      });
      if (clean) {
        safe.add(name);
        grew = true;
      }
    }
    if (!grew) break;
  }
  return safe;
}

/**
 * The path references in an expression that end up in its VALUE.
 *
 * A path in the condition of `result.file ? escape(result.file) : 'none'` is
 * being tested, not rendered, so it does not count — only the two branches do.
 * Reading the condition as a render is what made an escaped-at-the-source
 * variable look raw.
 */
function valuePathRefs(
  node: ts.Expression,
  analysis: FileAnalysis,
  includeSafe = false,
): ts.Node[] {
  if (ts.isConditionalExpression(node)) {
    return [
      ...valuePathRefs(node.whenTrue, analysis, includeSafe),
      ...valuePathRefs(node.whenFalse, analysis, includeSafe),
    ];
  }
  if (ts.isParenthesizedExpression(node)) {
    return valuePathRefs(node.expression, analysis, includeSafe);
  }
  return pathReferences(node, analysis, includeSafe);
}

function analyseFile(absolute: string, repoRoot: string): FileAnalysis {
  const source = ts.createSourceFile(
    absolute,
    readFileSync(absolute, 'utf8'),
    ts.ScriptTarget.Latest,
    true,
  );
  const helpers = new Map<string, ts.FunctionLikeDeclaration>();
  const walk = (n: ts.Node): void => {
    if (ts.isFunctionDeclaration(n) && n.name) helpers.set(n.name.text, n);
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer
      && (ts.isArrowFunction(n.initializer) || ts.isFunctionExpression(n.initializer))) {
      helpers.set(n.name.text, n.initializer);
    }
    ts.forEachChild(n, walk);
  };
  walk(source);

  return {
    source,
    relative: path.relative(repoRoot, absolute),
    helpers,
    sanitizedNames: safeNames(source, helpers),
  };
}

/**
 * Every path-bearing reference inside `node`, excluding the callee position of a
 * call — `citationTarget(directory)` names a sanitizer, not a path.
 */
function pathReferences(
  node: ts.Node,
  analysis: FileAnalysis,
  /**
   * Include references to names already known safe.
   *
   * The printer side skips them — that is what "already escaped" means. The
   * safe-name computation must NOT skip them, or it cannot tell "this
   * initializer had no path in it" from "this initializer's paths were all
   * safe", and those two need opposite answers.
   */
  includeSafe = false,
): ts.Node[] {
  const skip = (name: string): boolean => !includeSafe && analysis.sanitizedNames.has(name);
  const out: ts.Node[] = [];
  const walk = (n: ts.Node): void => {
    if (ts.isCallExpression(n)) {
      // Skip the callee, visit the arguments.
      for (const arg of n.arguments) walk(arg);
      // …but a method call ON a path still carries it: `file.split('/').pop()`.
      if (ts.isPropertyAccessExpression(n.expression)) walk(n.expression.expression);
      return;
    }
    if (ts.isPropertyAccessExpression(n)) {
      if (PATH_NAME.test(n.name.text) && !skip(n.name.text)) {
        out.push(n);
      } else {
        walk(n.expression);
      }
      return;
    }
    if (ts.isIdentifier(n)) {
      if (PATH_NAME.test(n.text) && !skip(n.text)) out.push(n);
      return;
    }
    ts.forEachChild(n, walk);
  };
  walk(node);
  return out;
}

/**
 * Is there a sanitizer call between `node` and `root`, INCLUSIVE of `root`?
 *
 * The inclusive part was missing, and it matters when `root` is the whole
 * initializer rather than a printer's argument: for
 * `const location = escapeForDisplay(f.file ? … : '')` the walk reached `root`
 * and stopped one node short of the only sanitizer in the expression, so a
 * correctly escaped value was reported as raw. The printer side never saw it
 * because there the sanitizer is always strictly inside the argument.
 */
function insideSanitizer(node: ts.Node, root: ts.Node): boolean {
  let cur: ts.Node = node;
  while (cur !== root && cur.parent) {
    const parent = cur.parent;
    if (ts.isCallExpression(parent) && parent.expression !== cur
      && SANITIZERS.has(calleeName(parent))) {
      return true;
    }
    cur = parent;
  }
  // `cur` is `root` (or the walk ran out). A ref reached by walking UP to a
  // sanitizer call is inside its arguments, which is the same answer.
  return ts.isCallExpression(cur) && SANITIZERS.has(calleeName(cur));
}

/**
 * A local helper handed a path: does it escape that parameter everywhere it
 * could reach output?
 *
 * "Could reach output" is a reference with a `return` or a printer above it.
 * `cleanFixText` builds a regex out of its `fileAlreadyShown` parameter and
 * never puts it on a line, so it passes; `keptLine` puts its parameter on a line
 * through `escapePathForDisplay` and `citationPath`, so it passes too. A helper
 * that returns its parameter raw fails, and is reported at the line inside the
 * helper where it does so.
 */
function helperRendersRaw(
  fn: ts.FunctionLikeDeclaration,
  parameterIndex: number,
  analysis: FileAnalysis,
  seen: Set<ts.Node>,
): ts.Node | null {
  if (seen.has(fn)) return null;
  seen.add(fn);
  const param = fn.parameters[parameterIndex];
  if (!param || !ts.isIdentifier(param.name) || !fn.body) return null;
  const name = param.name.text;

  let offender: ts.Node | null = null;
  const walk = (n: ts.Node): void => {
    if (offender) return;
    if (ts.isIdentifier(n) && n.text === name) {
      // Is this reference on a path that reaches output?
      let cur: ts.Node = n;
      let reachesOutput = false;
      while (cur.parent && cur !== fn) {
        const parent = cur.parent;
        if (ts.isReturnStatement(parent)) { reachesOutput = true; break; }
        if (ts.isArrowFunction(parent) && parent.body === cur) { reachesOutput = true; break; }
        if (ts.isCallExpression(parent) && PRINTERS.has(calleeName(parent))) {
          reachesOutput = true;
          break;
        }
        cur = parent;
      }
      if (reachesOutput && !insideSanitizer(n, fn)) offender = n;
      return;
    }
    ts.forEachChild(n, walk);
  };
  walk(fn.body);
  return offender;
}

/** The `.command('name')` whose `.action(…)` encloses this node, if any. */
function enclosingCommand(node: ts.Node): string | null {
  let cur: ts.Node | undefined = node;
  while (cur) {
    if (ts.isCallExpression(cur) && ts.isPropertyAccessExpression(cur.expression)
      && cur.expression.name.text === 'action') {
      // Walk back down the fluent chain to the `.command('name')` that started it.
      let chain: ts.Node = cur.expression.expression;
      while (ts.isCallExpression(chain)) {
        if (ts.isPropertyAccessExpression(chain.expression)
          && chain.expression.name.text === 'command'
          && chain.arguments.length > 0
          && ts.isStringLiteralLike(chain.arguments[0])) {
          return chain.arguments[0].text.split(' ')[0];
        }
        chain = ts.isPropertyAccessExpression(chain.expression)
          ? chain.expression.expression
          : chain.expression;
      }
    }
    cur = cur.parent;
  }
  return null;
}

/**
 * The literal text a template puts immediately before this interpolation,
 * back to the start of its line.
 */
function literalTextBefore(ref: ts.Node): string | null {
  let cur: ts.Node = ref;
  while (cur.parent && !ts.isTemplateExpression(cur.parent)) cur = cur.parent;
  const template = cur.parent;
  if (!template || !ts.isTemplateExpression(template)) return null;
  // A `TemplateSpan` starts AT its `${`, so the slice ends with those two
  // characters — and nothing anchored to the end of the line could ever match.
  const raw = template.getText().slice(0, cur.getStart() - template.getStart());
  const before = raw.endsWith('${') ? raw.slice(0, -2) : raw;
  return before.split('\\n').pop() ?? before;
}

/**
 * A command name, then zero or more arguments, then this interpolation.
 *
 * The first version of this test looked for BACKTICKS, on the theory that a
 * runnable command is always wrapped in them. Most are not:
 * `To rollback:${RESET()} ${CLI_PREFIX} rollback ${…}` has none, and it is a
 * command. Asked about the real sites, the backtick test fired on nothing at
 * all — it was a rule that could not fail, which is the defect it was written
 * to catch, one level up.
 *
 * So the question is POSITION: does the text immediately before the
 * interpolation read as "a command and its arguments so far"? That is what
 * makes the interpolation an argument, and an argument has to be a citation.
 *
 * BOUND, stated rather than implied: this sees the escape at the interpolation
 * itself. A path escaped into a local and then interpolated —
 * `const c = escapePathForDisplay(d); … \`${CLI_PREFIX} rollback ${c}\`` — is
 * not caught, because deciding it needs a second fixed point tracking WHICH
 * helper made each name safe. The direct form is the one that has actually
 * shipped twice; the indirect one is open work.
 */
const COMMAND_PREFIX = new RegExp(
  '(?:\\$\\{(?:CLI_PREFIX|prefix|cliName|secureCmd)\\}|\\bhackmyagent\\b|\\bopena2a(?:-cli)?\\b'
  + '|\\bnpx\\b|\\brm\\b|\\bcat\\b|\\bchmod\\b)'
  + '\\s+(?:--?[\\w-]+\\s+|[\\w:.@-]+\\s+)*$',
);

function inCommandArgumentPosition(ref: ts.Node): boolean {
  const before = literalTextBefore(ref);
  return before !== null && COMMAND_PREFIX.test(before);
}

/** Is the reference covered specifically by a citation helper? */
function insideCitationHelper(node: ts.Node, root: ts.Node): boolean {
  let cur: ts.Node = node;
  while (cur !== root && cur.parent) {
    const parent = cur.parent;
    if (ts.isCallExpression(parent) && parent.expression !== cur
      && CITATION_HELPERS.has(calleeName(parent))) {
      return true;
    }
    cur = parent;
  }
  return ts.isCallExpression(cur) && CITATION_HELPERS.has(calleeName(cur));
}

function refText(ref: ts.Node): string {
  return ts.isPropertyAccessExpression(ref) ? ref.name.text : ref.getText();
}

/** Every printed path in one file that never went through a display escape. */
function sitesIn(analysis: FileAnalysis): RenderSite[] {
  const sites: RenderSite[] = [];
  const record = (node: ts.Node, printer: ts.CallExpression, name: string): void => {
    const { line } = analysis.source.getLineAndCharacterOfPosition(node.getStart());
    sites.push({
      file: analysis.relative,
      line: line + 1,
      name,
      code: printer.getText().replace(/\s+/g, ' ').slice(0, 140),
      command: enclosingCommand(printer),
    });
  };

  const walk = (n: ts.Node): void => {
    if (ts.isCallExpression(n) && PRINTERS.has(calleeName(n))) {
      for (const arg of n.arguments) {
        for (const ref of pathReferences(arg, analysis)) {
          if (insideSanitizer(ref, arg)) {
            // Escaped — but escaped ENOUGH? In an argument position of a
            // command the reader is meant to paste, a display escape is #343
            // (the pasted path names a different file) and a shell injection
            // (nothing is quoted) at the same time.
            if (inCommandArgumentPosition(ref) && !insideCitationHelper(ref, arg)) {
              record(ref, n, `${refText(ref)} is display-escaped in a command argument`);
            }
            continue;
          }

          // The reference may be an argument to a helper declared in this file.
          // Follow it one level: the helper is what renders, so the helper is
          // where the escape has to be.
          const call = enclosingCall(ref, arg);
          if (call) {
            const helper = analysis.helpers.get(calleeName(call));
            if (helper) {
              const index = call.arguments.findIndex(
                (a) => a.pos <= ref.getStart() && a.end >= ref.getEnd(),
              );
              const raw = helperRendersRaw(helper, index, analysis, new Set());
              if (raw) {
                record(raw, n, `${calleeName(call)}() renders its argument raw`);
              }
              continue;
            }
          }
          const text = ts.isPropertyAccessExpression(ref) ? ref.name.text : ref.getText();
          record(ref, n, text);
        }
      }
    }
    ts.forEachChild(n, walk);
  };
  walk(analysis.source);
  return sites;
}

/** The innermost call expression that has `node` as an argument. */
function enclosingCall(node: ts.Node, root: ts.Node): ts.CallExpression | null {
  let cur: ts.Node = node;
  while (cur !== root && cur.parent) {
    const parent = cur.parent;
    if (ts.isCallExpression(parent) && parent.expression !== cur) return parent;
    cur = parent;
  }
  return null;
}

/**
 * The files that render a report.
 *
 * Not hand-kept as a list of files to CHECK — that would rot the way the
 * four-command assertion did. It is the whole of `src/`, minus the trees that
 * print no scanned path, each with the reason on the record.
 */
export const NOT_A_REPORT_SURFACE: Record<string, string> = {
  'src/arp/': 'the ARP protocol CLI, a separate binary; it renders agent ids and '
    + 'protocol state, and takes no filesystem target from a scanned tree',
  'src/eval/': 'the benchmark harness; it renders oracle ids and scores, and its '
    + 'paths come from the repo\'s own fixture tree, not from a user\'s target',
};

export function reportSurfaceFiles(repoRoot: string): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSyncSorted(dir)) {
      const full = path.join(dir, entry.name);
      const rel = `${path.relative(repoRoot, full)}${entry.isDirectory() ? '/' : ''}`;
      if (Object.keys(NOT_A_REPORT_SURFACE).some((skip) => rel.startsWith(skip))) continue;
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) out.push(full);
    }
  };
  walk(path.join(repoRoot, 'src'));
  return out.sort();
}

function readdirSyncSorted(dir: string): import('node:fs').Dirent[] {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { readdirSync } = require('node:fs') as typeof import('node:fs');
  return readdirSync(dir, { withFileTypes: true })
    .sort((a, b) => a.name.localeCompare(b.name));
}

/** Every unescaped printed path across the report surface. */
export function unescapedRenderSites(repoRoot: string): RenderSite[] {
  return reportSurfaceFiles(repoRoot)
    .flatMap((file) => sitesIn(analyseFile(file, repoRoot)));
}

/** Every command that prints a filesystem path at all, escaped or not. */
export function commandsThatRenderPaths(repoRoot: string): Set<string> {
  const commands = new Set<string>();
  const cli = path.join(repoRoot, 'src', 'cli.ts');
  const analysis = analyseFile(cli, repoRoot);
  const walk = (n: ts.Node): void => {
    if (ts.isCallExpression(n) && PRINTERS.has(calleeName(n))) {
      const command = enclosingCommand(n);
      if (command) {
        for (const arg of n.arguments) {
          // Escaped or not — the question here is whether a path is RENDERED,
          // which is what the classification claims about. `includeSafe` so a
          // command whose paths all go through an already-escaped local still
          // counts as rendering them.
          //
          // It used to also count "this argument mentions a sanitizer", which
          // is not the same question: `trust` escapes an error MESSAGE and
          // renders no filesystem path at all, and was being reported as a
          // classification mismatch on that basis.
          if (pathReferences(arg, analysis, true).length > 0) commands.add(command);
        }
      }
    }
    ts.forEachChild(n, walk);
  };
  walk(analysis.source);
  return commands;
}

/** Is this reference to a name already established as safe? */
function isSafeName(ref: ts.Node, safe: Set<string>): boolean {
  if (ts.isIdentifier(ref)) return safe.has(ref.text);
  if (ts.isPropertyAccessExpression(ref)) return safe.has(ref.name.text);
  return false;
}

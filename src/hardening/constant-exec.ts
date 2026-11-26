/**
 * NEMO-005 reports `exec(` / `execSync(` with an interpolated template
 * literal as command injection. A command built only from values the program
 * fixes itself carries nothing a user supplies, so it is not an injection
 * site, however its variables happen to be named. Test files are full of
 * these:
 *
 *   execSync(`${process.execPath} ${join(import.meta.dirname, 'cli.mjs')} --dir ${dir}`)
 *
 * where `dir` came from `mkdtempSync(...)`.
 *
 * An interpolated expression counts as constant when it is:
 *   - a string, number or template literal (whose own interpolations are constant),
 *   - `process.execPath`, `__dirname`, `__filename`, `import.meta.dirname`,
 *     `import.meta.filename` or `import.meta.url`,
 *   - a path or temp-directory call (`join`, `resolve`, `dirname`, `basename`,
 *     `fileURLToPath`, `tmpdir`, `mkdtemp`, `mkdtempSync`, `JSON.stringify`, ...)
 *     whose arguments are all constant,
 *   - a `+` concatenation of constant parts, or an `await` of a constant, or
 *   - an identifier bound once in the file, by a single-line `const` whose
 *     value is constant, and never assigned, imported, destructured or taken
 *     as a parameter anywhere in the file.
 *
 * Anything else (a parameter, `req.body.x`, `process.argv`, `process.env`, an
 * unknown call, a call spanning lines) is not constant, so the classification
 * only ever removes a call from NEMO-005, never adds one.
 */

import { matchingClose, stringEnd } from './regexp-exec';

const IDENT = '[A-Za-z_$][\\w$]*';
const IDENT_ONLY = new RegExp(`^${IDENT}$`);
const CALL_HEAD = new RegExp(`^(${IDENT}(?:\\s*\\.\\s*${IDENT})*)\\s*\\(`);
const EXEC_CALL = /\bexec(Sync)?\s*\(/g;
const NUMBER = /^-?\d+(?:\.\d+)?$/;
const CONST_DECLARATION = new RegExp(
  `^[ \\t]*(?:export[ \\t]+)?const[ \\t]+(${IDENT})[ \\t]*(?::[^=\\n]{0,200})?=(?![=>])[ \\t]*(.*?)[ \\t]*;?[ \\t]*$`,
  'gm',
);
const IDENT_MENTION = new RegExp(`(?<![\\w$.])(${IDENT})(?![\\w$])`, 'g');
// `import.meta` is not an import.
const IMPORT_OR_REQUIRE = /\bimport\b(?!\s*\.)|\brequire\b/;
// A parenthesised list followed by `=>` or `{` (a parameter list, or a
// condition such as `if (x) {`, which only makes the check more cautious).
const PARAM_LIST = /\(([^()]*)\)\s*(?::[^={};]{0,200})?(?:=>|\{)/g;
const DESTRUCTURING = /\b(?:const|let|var)\s*[{[]([^=]*)[}\]]\s*=/g;

const TRUSTED_VALUES = new Set([
  'process.execPath',
  '__dirname',
  '__filename',
  'import.meta.dirname',
  'import.meta.filename',
  'import.meta.url',
]);

// Calls whose result is fixed by their (constant) arguments: path builders,
// the temp-directory helpers and quoting.
const CONSTANT_FUNCTIONS = new Set([
  'join',
  'resolve',
  'dirname',
  'basename',
  'normalize',
  'relative',
  'fileURLToPath',
  'tmpdir',
  'mkdtemp',
  'mkdtempSync',
  'realpathSync',
  'JSON.stringify',
  'String',
]);
// Module objects those helpers are called through (`path.join`, `fs.mkdtempSync`).
const MODULE_QUALIFIER = /^(?:(?:path|posix|win32|fs|fsp|promises|os|url|nodePath|nodeFs|nodeOs|nodeUrl)\.)+/;

const MAX_DEPTH = 16;

/** Pieces of `text` split at top-level `separator`; null when a string or bracket is left open. */
function splitTopLevel(text: string, separator: string): string[] | null {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"' || c === "'" || c === '`') {
      i = stringEnd(text, i);
      if (i < 0) return null;
    } else if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      if (--depth < 0) return null;
    } else if (depth === 0 && c === separator) {
      // `++` and `+=` are not concatenation.
      if (separator === '+' && (text[i + 1] === '+' || text[i + 1] === '=' || text[i - 1] === '+')) return null;
      parts.push(text.slice(start, i));
      start = i + 1;
    }
  }
  if (depth !== 0) return null;
  parts.push(text.slice(start));
  return parts;
}

/** True when every `${...}` in the template literal `template` (backticks included) is constant. */
function templateIsConstant(template: string, constants: ReadonlySet<string>, depth: number): boolean {
  for (let i = 1; i < template.length - 1; i++) {
    const c = template[i];
    if (c === '\\') i++;
    else if (c === '$' && template[i + 1] === '{') {
      const close = matchingClose(template, i + 1);
      if (close < 0) return false;
      if (!isConstantExpression(template.slice(i + 2, close), constants, depth + 1)) return false;
      i = close;
    }
  }
  return true;
}

/** True when `expression` evaluates to a value the program fixes itself; see the module comment. */
export function isConstantExpression(expression: string, constants: ReadonlySet<string>, depth = 0): boolean {
  if (depth > MAX_DEPTH) return false;
  let e = expression.trim();
  if (e === '') return false;
  while (e.startsWith('(') && matchingClose(e, 0) === e.length - 1) e = e.slice(1, -1).trim();
  if (/^await\s/.test(e)) return isConstantExpression(e.slice(5), constants, depth + 1);

  const sum = splitTopLevel(e, '+');
  if (sum === null) return false;
  if (sum.length > 1) return sum.every((part) => isConstantExpression(part, constants, depth + 1));

  if (NUMBER.test(e)) return true;
  if (e[0] === '"' || e[0] === "'") return stringEnd(e, 0) === e.length - 1;
  if (e[0] === '`') return stringEnd(e, 0) === e.length - 1 && templateIsConstant(e, constants, depth);
  if (TRUSTED_VALUES.has(e)) return true;
  if (IDENT_ONLY.test(e)) return constants.has(e);

  const call = CALL_HEAD.exec(e);
  if (call) {
    const open = call[0].length - 1;
    if (matchingClose(e, open) !== e.length - 1) return false;
    const callee = call[1].replace(/\s+/g, '').replace(MODULE_QUALIFIER, '');
    if (!CONSTANT_FUNCTIONS.has(callee)) return false;
    const inner = e.slice(open + 1, -1);
    if (inner.trim() === '') return true;
    const args = splitTopLevel(inner, ',');
    if (args === null) return false;
    return args.every((arg) => isConstantExpression(arg, constants, depth + 1));
  }
  return false;
}

/**
 * `src` with comments, string literals and the text of template literals
 * blanked to spaces, keeping `${...}` expressions and every line break, so
 * offsets into the result are offsets into `src`.
 */
function codeOnly(src: string): string {
  const blank = (from: number, to: number) => src.slice(from, to).replace(/[^\n]/g, ' ');
  // Brace depth at which each open `${` started; its `}` resumes the template.
  const templates: number[] = [];
  let depth = 0;
  let out = '';
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    let j = i + 1;
    if (c === '/' && src[i + 1] === '/') {
      j = src.indexOf('\n', i);
      if (j < 0) j = src.length;
    } else if (c === '/' && src[i + 1] === '*') {
      j = src.indexOf('*/', i + 2);
      j = j < 0 ? src.length : j + 2;
    } else if (c === '"' || c === "'") {
      while (j < src.length && src[j] !== c && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
      j = Math.min(j + 1, src.length);
    } else if (c === '`' || (c === '}' && templates.length > 0 && templates[templates.length - 1] === depth)) {
      if (c === '}') templates.pop();
      while (j < src.length && src[j] !== '`' && !(src[j] === '$' && src[j + 1] === '{')) j += src[j] === '\\' ? 2 : 1;
      if (src[j] === '$') {
        templates.push(depth);
        j += 2;
      } else {
        j = Math.min(j + 1, src.length);
      }
    } else {
      if (c === '{') depth++;
      else if (c === '}') depth--;
      out += c;
      i = j;
      continue;
    }
    out += blank(i, j);
    i = j;
  }
  return out;
}

/**
 * Identifiers in `content` that hold a constant: bound by exactly one
 * single-line `const` with a constant value, and never assigned, imported,
 * required, destructured or taken as a parameter elsewhere in the file.
 */
export function constantIdentifiers(content: string): Set<string> {
  // Bindings are searched in the code alone, so a `--dir` flag inside a
  // command string or a word in a comment is not read as one.
  const code = codeOnly(content);
  const candidates = new Map<string, string>();
  const rebound = new Set<string>();
  for (const m of code.matchAll(CONST_DECLARATION)) {
    const declaration = new RegExp(CONST_DECLARATION.source).exec(content.slice(m.index!, m.index! + m[0].length));
    if (!declaration) continue;
    if (candidates.has(m[1])) rebound.add(m[1]);
    candidates.set(m[1], declaration[2]);
  }
  if (candidates.size === 0) return new Set();

  for (const name of candidates.keys()) {
    const escaped = name.replace(/\$/g, '\\$');
    const bindings = code.match(new RegExp(`\\b(?:const|let|var|function|class)\\s+${escaped}(?![\\w$])`, 'g'));
    const assignments = code.match(
      new RegExp(`(?<![\\w$.])${escaped}\\s*(?:[-+*/%&|^]|\\*\\*|\\?\\?|&&|\\|\\||<<|>>>?)?=(?![=>])`, 'g'),
    );
    const arrowParam = new RegExp(`(?<![\\w$.])${escaped}\\s*=>`).test(code);
    const updated = new RegExp(`(?:\\+\\+|--)\\s*${escaped}(?![\\w$])|(?<![\\w$.])${escaped}\\s*(?:\\+\\+|--)`).test(code);
    if ((bindings?.length ?? 0) > 1 || (assignments?.length ?? 0) > 1 || arrowParam || updated) rebound.add(name);
  }
  const mentionsIn = (text: string) => {
    for (const m of text.matchAll(IDENT_MENTION)) rebound.add(m[1]);
  };
  for (const m of code.matchAll(PARAM_LIST)) mentionsIn(m[1]);
  for (const m of code.matchAll(DESTRUCTURING)) mentionsIn(m[1]);
  for (const line of code.split('\n')) if (IMPORT_OR_REQUIRE.test(line)) mentionsIn(line);
  for (const name of rebound) candidates.delete(name);

  const constants = new Set<string>();
  for (let grew = true; grew; ) {
    grew = false;
    for (const [name, value] of candidates) {
      if (constants.has(name) || !isConstantExpression(value, constants)) continue;
      constants.add(name);
      grew = true;
    }
  }
  return constants;
}

/**
 * True when every `exec(` / `execSync(` call on `line` takes a template
 * literal as its first argument and every interpolation in it is constant.
 * A call that does not close on the line is not classified. `constants`
 * comes from `constantIdentifiers` over the same file.
 */
export function onlyConstantExecCalls(line: string, constants: ReadonlySet<string>): boolean {
  const calls = [...line.matchAll(EXEC_CALL)];
  if (calls.length === 0) return false;
  return calls.every((call) => {
    const open = call.index! + call[0].length - 1;
    const close = matchingClose(line, open);
    if (close < 0) return false;
    const args = splitTopLevel(line.slice(open + 1, close), ',');
    if (args === null) return false;
    const command = args[0].trim();
    if (command[0] !== '`' || stringEnd(command, 0) !== command.length - 1) return false;
    return templateIsConstant(command, constants, 0);
  });
}

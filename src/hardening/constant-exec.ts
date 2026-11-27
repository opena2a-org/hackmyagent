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
 *   - an identifier with exactly one binding in the whole file, that binding a
 *     top-level, single-line `const` whose value is constant.
 *
 * The bindings of an identifier are found by reading the file as tokens and
 * counting every place the name is bound: a parameter of any function,
 * method, arrow function or catch clause (whatever the shape of its
 * parameter list), a `const`, `let`, `var`, `using`, `function`, `class`,
 * `enum` or import of the name in any scope, an assignment or update, a
 * destructuring target and a loop variable. When the file cannot be read
 * that way (it is larger than MAX_SOURCE_LENGTH, a string, comment, template
 * or regular expression does not end, a bracket is left open or closed
 * twice, a `/` could start either a division or a regular expression, where
 * a regular expression ends depends on its flags, a character is not one the
 * reader knows, the file holds `<!--` or `-->`, or it calls `eval` or uses
 * `with`), no identifier in it counts as constant.
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

// ---------- Reading the file as tokens ----------

/** Files longer than this are not read for bindings; nothing in them counts as constant. */
export const MAX_SOURCE_LENGTH = 1024 * 1024;

type TokenKind = 'ident' | 'number' | 'string' | 'template' | 'regex' | 'punct';

interface Token {
  kind: TokenKind;
  text: string;
  start: number;
  end: number;
  /** Number of brackets (including template `${`) open around the token. */
  depth: number;
}

interface TokenList {
  tokens: Token[];
  /** For an opening or closing bracket, the index of its partner; -1 otherwise. */
  partner: number[];
}

const IDENT_AT = /[\p{ID_Start}$_][\p{ID_Continue}$\u200c\u200d]*/uy;
const IDENT_PART = /[\p{ID_Continue}$\u200c\u200d]/u;
const NUMBER_AT = /(?:\d|\.\d)[\w.]*/y;
const SPACE = /\s/u;
const LINE_TERMINATOR = /[\n\r\u2028\u2029]/;
// Longest first, so `>>>=` is read before `>>`.
const PUNCTUATORS = [
  '>>>=', '...', '===', '!==', '**=', '<<=', '>>=', '>>>', '&&=', '||=', '??=',
  '=>', '==', '!=', '<=', '>=', '**', '++', '--', '<<', '>>', '&&', '||', '??', '?.',
  '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=',
  '{', '}', '(', ')', '[', ']', ';', ',', '<', '>', '+', '-', '*', '/', '%', '&', '|',
  '^', '!', '~', '?', ':', '=', '.', '@', '#',
];
const OPENERS = new Set(['(', '[', '{']);
const CLOSER_OF: Record<string, string> = { '(': ')', '[': ']', '{': '}', '${': '}' };
// Words after which a `/` starts a regular expression.
const REGEX_AFTER_WORD = new Set([
  'return', 'typeof', 'instanceof', 'in', 'new', 'delete', 'void', 'throw', 'case', 'do', 'else', 'extends',
  'default',
]);
// Words after which a `/` may start either; see `slashStartsRegex`.
const AMBIGUOUS_WORDS = new Set(['of', 'yield', 'await']);
// Statement heads whose parenthesised part is a condition, not a parameter list.
const CONDITION_HEADS = new Set(['if', 'while', 'switch', 'with', 'for']);

/** End (exclusive) of the quoted string starting at `start`; -1 if a line or the file ends first. */
function quotedEnd(src: string, start: number): number {
  const quote = src[start];
  for (let j = start + 1; j < src.length; j++) {
    const c = src[j];
    if (c === '\\') {
      if (src[j + 1] === '\r' && src[j + 2] === '\n') j += 2;
      else j++;
    } else if (c === quote) return j + 1;
    else if (c === '\n' || c === '\r') return -1;
  }
  return -1;
}

/**
 * Index of the `/` that closes the body of the regular expression literal at
 * `start`, reading a `[` inside a class as a nested class when `nested` (the
 * `v` flag) and as a character otherwise; -1 if the line ends first.
 */
function regexBodyEnd(src: string, start: number, nested: boolean): number {
  let classes = 0;
  for (let j = start + 1; j < src.length; j++) {
    const c = src[j];
    if (LINE_TERMINATOR.test(c)) return -1;
    if (c === '\\') {
      j++;
      if (LINE_TERMINATOR.test(src[j] ?? '')) return -1;
    } else if (c === '[') {
      if (classes === 0 || nested) classes++;
    } else if (c === ']') {
      if (classes > 0) classes--;
    } else if (c === '/' && classes === 0) return j;
  }
  return -1;
}

/** End (exclusive) of the flags after the body end `bodyEnd`. */
function flagsEnd(src: string, bodyEnd: number): number {
  let e = bodyEnd + 1;
  while (e < src.length && IDENT_PART.test(src[e])) e++;
  return e;
}

/**
 * End (exclusive, flags included) of the regular expression literal at
 * `start`; -1 if the line ends first, or if where it ends depends on whether
 * its classes nest, which the `v` flag decides.
 */
function regexEnd(src: string, start: number): number {
  const flat = regexBodyEnd(src, start, false);
  if (flat < 0) return -1;
  const end = flagsEnd(src, flat);
  const nested = regexBodyEnd(src, start, true);
  if (nested === flat) return end;
  if (src.slice(flat + 1, end).includes('v')) return -1;
  if (nested >= 0 && src.slice(nested + 1, flagsEnd(src, nested)).includes('v')) return -1;
  return end;
}

function isPunct(token: Token | undefined, text: string): boolean {
  return token !== undefined && token.kind === 'punct' && token.text === text;
}

function isWord(token: Token | undefined, text: string): boolean {
  return token !== undefined && token.kind === 'ident' && token.text === text;
}

/** True when the token at `k` is a property name: after `.`, `?.` or `#`. */
function isProperty(tokens: Token[], k: number): boolean {
  const before = tokens[k - 1];
  return before !== undefined && before.kind === 'punct' && (before.text === '.' || before.text === '?.' || before.text === '#');
}

/**
 * Whether the `/` at `at` starts a regular expression, from the tokens before
 * it; null when it could start either and reading it one way or the other
 * would change what the rest of the line is.
 */
function slashStartsRegex(src: string, at: number, list: TokenList): boolean | null {
  const { tokens, partner } = list;
  const last = tokens.length - 1;
  const prev = tokens[last];
  if (!prev) return true;
  const ambiguous = () => {
    const lineEnd = src.indexOf('\n', at + 1);
    return src.slice(at + 1, lineEnd < 0 ? src.length : lineEnd).includes('/') ? null : false;
  };
  switch (prev.kind) {
    case 'number':
    case 'string':
    case 'template':
    case 'regex':
      return false;
    case 'ident':
      if (isProperty(tokens, last)) return false;
      if (REGEX_AFTER_WORD.has(prev.text)) return true;
      if (AMBIGUOUS_WORDS.has(prev.text)) return ambiguous();
      return false;
    default:
      if (prev.text === ']' || prev.text === '++' || prev.text === '--') return false;
      if (prev.text === ')') {
        // After the condition of `if (...)`, `while (...)`, `for (...)` a statement starts.
        const open = partner[last];
        const head = tokens[open - 1];
        if (head?.kind === 'ident' && CONDITION_HEADS.has(head.text) && !isProperty(tokens, open - 1)) return true;
        if (isWord(head, 'await') && isWord(tokens[open - 2], 'for')) return true;
        return false;
      }
      // A `}` ends either a block (a statement, so a regular expression may
      // follow) or an expression (a division may follow); a `>` may end a
      // type argument list.
      if (prev.text === '}' || prev.text === '>') return ambiguous();
      if (prev.text === '!') {
        // A `!` after a value is a non-null assertion, after which a
        // division may follow; otherwise it is a logical not.
        const before = tokens[last - 1];
        const afterValue =
          before !== undefined &&
          (before.kind !== 'punct' ? !(before.kind === 'ident' && REGEX_AFTER_WORD.has(before.text)) : [')', ']', '}'].includes(before.text));
        return afterValue ? ambiguous() : true;
      }
      return true;
  }
}

/**
 * The tokens of a TypeScript or JavaScript source, with every bracket paired.
 * Comments and whitespace are dropped; template literal text becomes
 * `template` tokens around the `${` ... `}` of each interpolation, whose
 * contents are tokens like any other code. Null when the source cannot be
 * read that way (see the module comment).
 */
function tokenize(src: string): TokenList | null {
  const tokens: Token[] = [];
  const partner: number[] = [];
  const open: number[] = [];
  const list: TokenList = { tokens, partner };
  const push = (kind: TokenKind, start: number, end: number): number => {
    tokens.push({ kind, text: src.slice(start, end), start, end, depth: open.length });
    partner.push(-1);
    return tokens.length - 1;
  };
  // Template text from `from` (an opening backtick, or just after the `}` of
  // an interpolation) to the closing backtick or the next `${`; returns the
  // position after it, or -1 when the file ends first.
  const templateText = (from: number, opening: boolean): number => {
    for (let j = opening ? from + 1 : from; j < src.length; j++) {
      const c = src[j];
      if (c === '\\') j++;
      else if (c === '`') {
        push('template', from, j + 1);
        return j + 1;
      } else if (c === '$' && src[j + 1] === '{') {
        if (j > from) push('template', from, j);
        open.push(push('punct', j, j + 2));
        return j + 2;
      }
    }
    return -1;
  };

  let i = 0;
  if (src.startsWith('#!')) {
    i = src.indexOf('\n');
    if (i < 0) i = src.length;
  }
  while (i < src.length) {
    const c = src[i];
    if (SPACE.test(c)) {
      i++;
      continue;
    }
    if (c === '/' && src[i + 1] === '/') {
      i += 2;
      while (i < src.length && !LINE_TERMINATOR.test(src[i])) i++;
      continue;
    }
    // `<!--` and `-->` start a comment in a script and not in a module.
    if (src.startsWith('<!--', i) || src.startsWith('-->', i)) return null;
    if (c === '/' && src[i + 1] === '*') {
      const e = src.indexOf('*/', i + 2);
      if (e < 0) return null;
      i = e + 2;
      continue;
    }
    if (c === '"' || c === "'") {
      const e = quotedEnd(src, i);
      if (e < 0) return null;
      push('string', i, e);
      i = e;
      continue;
    }
    if (c === '`') {
      i = templateText(i, true);
      if (i < 0) return null;
      continue;
    }
    if (c === '/') {
      const regex = slashStartsRegex(src, i, list);
      if (regex === null) return null;
      if (regex) {
        const e = regexEnd(src, i);
        if (e < 0) return null;
        push('regex', i, e);
        i = e;
        continue;
      }
    }
    IDENT_AT.lastIndex = i;
    const word = IDENT_AT.exec(src);
    if (word) {
      push('ident', i, i + word[0].length);
      i += word[0].length;
      continue;
    }
    NUMBER_AT.lastIndex = i;
    const number = NUMBER_AT.exec(src);
    if (number) {
      push('number', i, i + number[0].length);
      i += number[0].length;
      continue;
    }
    let p = PUNCTUATORS.find((candidate) => src.startsWith(candidate, i));
    // A backslash (a Unicode escape in a name) or any other character this
    // reader does not know leaves the file unread.
    if (p === undefined) return null;
    if (p === '?.' && /\d/.test(src[i + 2] ?? '')) p = '?';
    if (OPENERS.has(p)) {
      open.push(push('punct', i, i + 1));
    } else if (p === ')' || p === ']' || p === '}') {
      const o = open.pop();
      if (o === undefined || CLOSER_OF[tokens[o].text] !== p) return null;
      const k = push('punct', i, i + 1);
      partner[o] = k;
      partner[k] = o;
      if (tokens[o].text === '${') {
        i = templateText(i + 1, false);
        if (i < 0) return null;
        continue;
      }
    } else {
      push('punct', i, i + p.length);
    }
    i += p.length;
  }
  return open.length === 0 ? list : null;
}

// ---------- Where names are bound ----------

const ASSIGNMENT = new Set(['=', '+=', '-=', '*=', '/=', '%=', '**=', '<<=', '>>=', '>>>=', '&=', '|=', '^=', '&&=', '||=', '??=']);
const DECLARATION = new Set(['const', 'let', 'var', 'using']);
// Words followed by the name they bind.
const NAMING_WORDS = new Set([...DECLARATION, 'function', 'class', 'interface', 'type', 'enum', 'namespace', 'module']);
// Words that start a statement, ending a declaration list read without its `;`.
const STATEMENT_WORDS = new Set([
  ...DECLARATION, 'function', 'class', 'if', 'for', 'while', 'do', 'return', 'import', 'export', 'switch', 'try',
  'throw', 'break', 'continue',
]);

/**
 * Indices of every identifier token in a binding position. The positions are
 * read generously: a whole parameter list counts, default values and type
 * annotations included, so a name is never missed for being nested. Null
 * when the file calls `eval` or uses `with`, either of which can bind a name
 * no token shows.
 */
function bindingSites(list: TokenList): Set<number> | null {
  const { tokens, partner } = list;
  const sites = new Set<number>();
  // Tokens inside a bracket pair already counted whole.
  const counted = new Uint8Array(tokens.length);
  const mark = (k: number) => {
    if (tokens[k]?.kind === 'ident' && !isProperty(tokens, k)) sites.add(k);
  };
  const markGroup = (o: number) => {
    if (counted[o]) return;
    for (let k = o + 1; k < partner[o]; k++) {
      counted[k] = 1;
      mark(k);
    }
  };
  // A binding target (a name, or an object or array pattern) at `k`;
  // returns the index after it, or `k` when there is none.
  const markTarget = (k: number): number => {
    const t = tokens[k];
    if (t?.kind === 'ident') {
      mark(k);
      return k + 1;
    }
    if (isPunct(t, '{') || isPunct(t, '[')) {
      markGroup(k);
      return partner[k] + 1;
    }
    return k;
  };
  // `const a = 1, b = 2`: every target after a `,` of the same list.
  const markDeclarationList = (keyword: number) => {
    let j = markTarget(keyword + 1);
    if (j === keyword + 1) return;
    while (j < tokens.length) {
      const t = tokens[j];
      if (t.kind === 'punct') {
        if (partner[j] > j) {
          j = partner[j] + 1;
          continue;
        }
        if (t.text === ';' || partner[j] >= 0) return;
        if (t.text === ',') {
          j = Math.max(markTarget(j + 1), j + 1);
          continue;
        }
      } else if (t.kind === 'ident' && STATEMENT_WORDS.has(t.text) && !isProperty(tokens, j)) return;
      j++;
    }
  };
  // `for (name in o)`, `for ([a, b] of o)`: the first target of the head.
  const markLoopHead = (o: number) => {
    const first = tokens[o + 1];
    const after = first?.kind === 'ident' ? tokens[o + 2] : isPunct(first, '[') || isPunct(first, '{') ? tokens[partner[o + 1] + 1] : undefined;
    if (isWord(after, 'in') || isWord(after, 'of')) markTarget(o + 1);
  };

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const next = tokens[i + 1];
    const prev = tokens[i - 1];
    if (t.kind === 'ident') {
      if (isProperty(tokens, i)) continue;
      if (t.text === 'eval' || (t.text === 'with' && isPunct(next, '('))) return null;
      if (next?.kind === 'punct' && (ASSIGNMENT.has(next.text) || next.text === '=>' || next.text === '++' || next.text === '--')) mark(i);
      if (isPunct(prev, '++') || isPunct(prev, '--') || isWord(next, 'of')) mark(i);
      if (prev?.kind === 'ident' && NAMING_WORDS.has(prev.text) && !isProperty(tokens, i - 1)) mark(i);
      if (isPunct(prev, '*') && isWord(tokens[i - 2], 'function')) mark(i);
      if (DECLARATION.has(t.text)) markDeclarationList(i);
      if (t.text === 'import' && !isPunct(next, '(') && !isPunct(next, '.')) {
        // Every name up to the module specifier.
        for (let k = i + 1; k < tokens.length && tokens[k].kind !== 'string' && !isPunct(tokens[k], ';'); k++) mark(k);
      }
      continue;
    }
    if (t.kind !== 'punct' || partner[i] <= i || t.text === '${') continue;
    const after = tokens[partner[i] + 1];
    const assigned = after?.kind === 'punct' && ASSIGNMENT.has(after.text);
    if (t.text === '(') {
      const head = prev?.kind === 'ident' && !isProperty(tokens, i - 1) ? prev.text : '';
      if (head === 'catch') markGroup(i);
      else if (head === 'for' || (head === 'await' && isWord(tokens[i - 2], 'for'))) markLoopHead(i);
      else if (CONDITION_HEADS.has(head)) continue;
      // A parameter list: before an arrow, a body or a return type.
      else if (assigned || isPunct(after, '=>') || isPunct(after, '{') || isPunct(after, ':')) markGroup(i);
    } else {
      // `[a, b] = ...` and `{ a, b } = ...` are destructuring; `x[k] = ...` is not.
      const member =
        t.text === '[' &&
        prev !== undefined &&
        (prev.kind === 'number' || prev.kind === 'string' || prev.kind === 'template' || prev.kind === 'regex' ||
          (prev.kind === 'ident' && !REGEX_AFTER_WORD.has(prev.text)) ||
          isPunct(prev, ')') || isPunct(prev, ']'));
      if (!member && (assigned || isWord(after, 'of'))) markGroup(i);
    }
  }
  return sites;
}

/**
 * The value of the top-level `const` whose name is at `nameIndex`: the text
 * after `=` up to its `;` or the end of the line, when the declaration has
 * one target, stays on one line and cannot run on into the next one; null
 * otherwise.
 */
function singleLineValue(src: string, list: TokenList, nameIndex: number): string | null {
  const { tokens, partner } = list;
  let j = nameIndex + 1;
  if (isPunct(tokens[j], ':')) {
    // A type annotation.
    for (j++; j < tokens.length && !isPunct(tokens[j], '='); j++) {
      if (isPunct(tokens[j], ';') || isPunct(tokens[j], ',')) return null;
      if (partner[j] > j) j = partner[j];
    }
  }
  if (!isPunct(tokens[j], '=')) return null;
  let lineEnd = src.indexOf('\n', tokens[j].end);
  if (lineEnd < 0) lineEnd = src.length;
  const first = j + 1;
  let k = first;
  while (k < tokens.length && tokens[k].start < lineEnd && !isPunct(tokens[k], ';')) {
    if (isPunct(tokens[k], ',')) return null;
    if (partner[k] > k) k = partner[k];
    if (tokens[k].end > lineEnd) return null;
    k++;
  }
  if (k === first) return null;
  // Without a `;`, the next line must start a new statement rather than
  // continue the value (`+ x`, `(x)`, `.x`, a template, ...).
  const following = tokens[k];
  if (
    following !== undefined &&
    !isPunct(following, ';') &&
    !(following.kind === 'ident' && !['in', 'instanceof', 'as', 'satisfies'].includes(following.text)) &&
    following.kind !== 'string' &&
    following.kind !== 'number'
  ) {
    return null;
  }
  return src.slice(tokens[first].start, tokens[k - 1].end);
}

/**
 * Identifiers in `content` that hold a constant: each has exactly one binding
 * in the file, a top-level, single-line `const` whose value is constant, and
 * no other binding of any kind anywhere in the file. When the file cannot be
 * read for bindings, the set is empty.
 */
export function constantIdentifiers(content: string): Set<string> {
  if (content.length > MAX_SOURCE_LENGTH) return new Set();
  const list = tokenize(content);
  if (list === null) return new Set();
  const sites = bindingSites(list);
  if (sites === null) return new Set();
  const { tokens } = list;
  const bindingCount = new Map<string, number>();
  for (const k of sites) bindingCount.set(tokens[k].text, (bindingCount.get(tokens[k].text) ?? 0) + 1);

  const candidates = new Map<string, string>();
  for (let i = 0; i + 1 < tokens.length; i++) {
    if (!isWord(tokens[i], 'const') || tokens[i].depth !== 0 || isProperty(tokens, i)) continue;
    const name = tokens[i + 1];
    if (name.kind !== 'ident' || !sites.has(i + 1) || bindingCount.get(name.text) !== 1) continue;
    const value = singleLineValue(content, list, i + 1);
    if (value !== null) candidates.set(name.text, value);
  }
  if (candidates.size === 0) return new Set();

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

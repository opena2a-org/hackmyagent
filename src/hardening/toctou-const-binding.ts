/**
 * TOCTOU-001 constant-path suppression.
 *
 * Tier A/B of checkTOCTOU match `existsSync(id)` (or a stat) followed by an
 * exec sink on the same identifier. When `id` is a module-scope `const` bound
 * to a plain string literal (`const TOOL = '/usr/bin/true'`), the shape is the
 * same as `existsSync('/usr/bin/true')` followed by `spawn('/usr/bin/true')`,
 * which already passes because the identifier regex never matches a literal.
 *
 * The scanned file is attacker-authored, so the binding question is answered
 * on a CODE VIEW of the file, not on its raw text: comments, strings, regex
 * literals and template text are blanked by a lexer that bails out (returns
 * null, so the finding keeps firing) on every slash or unterminated token it
 * cannot read with certainty. On that view the name must have exactly one
 * binding — the `const` at brace depth zero — and every other mention must sit
 * in a position that can only be a read (a call argument, or the right side of
 * `=`). A parameter, a destructuring pattern, a `let`/`var` in an inner scope,
 * an import, a catch binding or any mention the rules do not recognise keeps
 * the finding: every unsure answer is "not constant".
 */

const ID_CHAR = /[\p{ID_Continue}$]/u;
const ID_START = /[\p{ID_Start}$_]/u;

/** Keywords after which a `/` opens a regex literal. */
const REGEX_AFTER_KEYWORDS = new Set([
  'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void',
  'throw', 'case', 'else', 'do', 'yield', 'await',
]);

/** A `)` followed by `/` opens a regex only when its `(` belongs to one of these. */
const REGEX_AFTER_PAREN_KEYWORDS = new Set(['if', 'while', 'for', 'with']);

/** Punctuators after which a `/` is unambiguously a regex opener. */
const REGEX_AFTER_PUNCTUATORS = new Set([
  '(', ',', '=', ':', '[', '&', '|', '?', ';', '{', '*', '%', '~', '^', '<', '+', '-',
]);

/** Words that start a statement on the next line rather than continue an expression. */
const CONTINUATION_WORDS = new Set(['as', 'in', 'instanceof', 'satisfies']);

interface CodeView {
  /** Same length as the source; non-code is blanked, each literal opens with `0`. */
  code: string;
  /** Start offset → end offset (exclusive) of each plain string literal. */
  plainStrings: Map<number, number>;
}

type PrevToken =
  | { kind: 'start' }
  | { kind: 'word'; word: string; afterDot: boolean }
  | { kind: 'value' }
  | { kind: 'punct'; ch: string; valueBefore: boolean; double: boolean }
  | { kind: 'closeParen'; keyword: string | null }
  | { kind: 'closeBrace' };

/**
 * Lex `src` into a code view, or return null when any token cannot be read
 * with certainty. Linear in the input.
 */
export function buildCodeView(src: string): CodeView | null {
  const out: string[] = new Array(src.length);
  const plainStrings = new Map<number, number>();
  const n = src.length;
  let i = 0;
  let prev: PrevToken = { kind: 'start' };
  // Each entry is the word in front of an open `(` (null when none).
  const parenWords: (string | null)[] = [];
  // Template interpolation stack: brace depth inside each open `${`.
  const interp: number[] = [];

  const blank = (from: number, to: number, marker: boolean): void => {
    for (let k = from; k < to; k++) out[k] = src[k] === '\n' ? '\n' : ' ';
    if (marker && from < to) out[from] = '0';
  };
  const isValue = (p: PrevToken): boolean =>
    p.kind === 'value' || p.kind === 'closeParen' || p.kind === 'closeBrace' ||
    (p.kind === 'word' && (p.afterDot || !REGEX_AFTER_KEYWORDS.has(p.word)));

  // Hashbang line.
  if (src.startsWith('#!')) {
    const nl = src.indexOf('\n');
    const end = nl < 0 ? n : nl;
    blank(0, end, false);
    i = end;
  }

  // Template text from `start` (just past a backtick or a closing `}`):
  // returns the index past the closing backtick, or the index past `${`
  // after pushing an interpolation, or -1 when unterminated.
  const lexTemplateText = (start: number): { end: number; interpolation: boolean } | null => {
    let k = start;
    while (k < n) {
      const c = src[k];
      if (c === '\\') { k += 2; continue; }
      if (c === '`') return { end: k + 1, interpolation: false };
      if (c === '$' && src[k + 1] === '{') return { end: k + 2, interpolation: true };
      k++;
    }
    return null;
  };

  while (i < n) {
    const c = src[i];

    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v' || c === '\u00a0' || c === '\ufeff') {
      out[i] = c === '\n' ? '\n' : ' ';
      i++;
      continue;
    }

    // Comments take precedence over any slash meaning.
    if (c === '/' && src[i + 1] === '/') {
      let k = i;
      while (k < n && src[k] !== '\n') k++;
      blank(i, k, false);
      i = k;
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      const close = src.indexOf('*/', i + 2);
      if (close < 0) return null;
      blank(i, close + 2, false);
      i = close + 2;
      continue;
    }

    if (c === '/') {
      let regex: boolean;
      if (prev.kind === 'start') regex = true;
      else if (prev.kind === 'word') regex = !prev.afterDot && REGEX_AFTER_KEYWORDS.has(prev.word);
      else if (prev.kind === 'value') regex = false;
      else if (prev.kind === 'closeParen') regex = prev.keyword !== null && REGEX_AFTER_PAREN_KEYWORDS.has(prev.keyword);
      else if (prev.kind === 'closeBrace') return null;
      else {
        // Punctuator. `!` after a value is a TypeScript non-null assertion,
        // `++`/`--` may be postfix, `>` may close a generic or an arrow.
        if (prev.ch === '!') {
          if (prev.valueBefore) return null;
          regex = true;
        } else if ((prev.ch === '+' || prev.ch === '-') && prev.double) {
          return null;
        } else if (REGEX_AFTER_PUNCTUATORS.has(prev.ch)) {
          regex = true;
        } else {
          return null;
        }
      }
      if (!regex) {
        out[i] = '/';
        prev = { kind: 'punct', ch: '/', valueBefore: true, double: false };
        i++;
        continue;
      }
      let k = i + 1;
      let inClass = false;
      for (;;) {
        if (k >= n || src[k] === '\n' || src[k] === '\r') return null;
        const r = src[k];
        if (r === '\\') { k += 2; continue; }
        if (inClass) { if (r === ']') inClass = false; k++; continue; }
        if (r === '[') { inClass = true; k++; continue; }
        if (r === '/') { k++; break; }
        k++;
      }
      while (k < n && ID_CHAR.test(src[k])) k++;
      blank(i, k, true);
      i = k;
      prev = { kind: 'value' };
      continue;
    }

    if (c === '\'' || c === '"') {
      let k = i + 1;
      for (;;) {
        if (k >= n) return null;
        const s = src[k];
        if (s === '\\') { k += 2; continue; }
        if (s === '\n' || s === '\r') return null;
        if (s === c) { k++; break; }
        k++;
      }
      plainStrings.set(i, k);
      blank(i, k, true);
      i = k;
      prev = { kind: 'value' };
      continue;
    }

    if (c === '`') {
      const text = lexTemplateText(i + 1);
      if (!text) return null;
      if (!text.interpolation) plainStrings.set(i, text.end);
      blank(i, text.end, true);
      if (text.interpolation) {
        interp.push(0);
        prev = { kind: 'punct', ch: '{', valueBefore: false, double: false };
      } else {
        prev = { kind: 'value' };
      }
      i = text.end;
      continue;
    }

    if (c === '}' && interp.length > 0 && interp[interp.length - 1] === 0) {
      interp.pop();
      const text = lexTemplateText(i + 1);
      if (!text) return null;
      blank(i, text.end, false);
      if (text.interpolation) {
        interp.push(0);
        prev = { kind: 'punct', ch: '{', valueBefore: false, double: false };
      } else {
        prev = { kind: 'value' };
      }
      i = text.end;
      continue;
    }

    if (ID_CHAR.test(c) || c === '#' || c === '\\') {
      if (c === '\\') return null; // unicode escape in an identifier
      let k = i + 1;
      while (k < n && ID_CHAR.test(src[k])) k++;
      for (let m = i; m < k; m++) out[m] = src[m];
      const word = src.slice(i, k);
      const afterDot: boolean = prev.kind === 'punct' && prev.ch === '.';
      if (/^[0-9]/.test(word) || c === '#') {
        // Numbers (with a possible `.5` / exponent tail) and private names
        // are values. A decimal point after digits is lexed as `.` + word,
        // both of which read as values for the slash rule.
        prev = { kind: 'value' };
      } else {
        prev = { kind: 'word', word, afterDot };
      }
      i = k;
      continue;
    }

    // Punctuators.
    out[i] = c;
    const valueBefore = isValue(prev);
    if (c === '(') {
      parenWords.push(prev.kind === 'word' && !prev.afterDot ? prev.word : null);
    } else if (c === ')') {
      const keyword = parenWords.length > 0 ? parenWords.pop()! : null;
      prev = { kind: 'closeParen', keyword };
      i++;
      continue;
    } else if (c === ']') {
      prev = { kind: 'value' };
      i++;
      continue;
    } else if (c === '{') {
      if (interp.length > 0) interp[interp.length - 1]++;
    } else if (c === '}') {
      if (interp.length > 0) interp[interp.length - 1]--;
      prev = { kind: 'closeBrace' };
      i++;
      continue;
    }
    const double = (c === '+' || c === '-') && src[i - 1] === c;
    prev = { kind: 'punct', ch: c, valueBefore, double };
    i++;
  }

  if (interp.length > 0) return null;
  return { code: out.join(''), plainStrings };
}

function prevNonSpace(code: string, idx: number): number {
  let k = idx - 1;
  while (k >= 0 && /\s/.test(code[k])) k--;
  return k;
}

function nextNonSpace(code: string, idx: number): number {
  let k = idx;
  while (k < code.length && /\s/.test(code[k])) k++;
  return k;
}

/** Index of the unmatched opener that encloses `idx`, or -1 at top level. */
function enclosingOpener(code: string, idx: number): number {
  let depth = 0;
  for (let k = idx - 1; k >= 0; k--) {
    const ch = code[k];
    if (ch === ')' || ch === ']' || ch === '}') depth++;
    else if (ch === '(' || ch === '[' || ch === '{') {
      if (depth === 0) return k;
      depth--;
    }
  }
  return -1;
}

/** Index of the closer that matches the opener at `open`, or -1. */
function matchingCloser(code: string, open: number): number {
  let depth = 0;
  for (let k = open; k < code.length; k++) {
    const ch = code[k];
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') {
      depth--;
      if (depth === 0) return k;
    }
  }
  return -1;
}

function wordEndingAt(code: string, end: number): string {
  let k = end;
  while (k >= 0 && ID_CHAR.test(code[k])) k--;
  return code.slice(k + 1, end + 1);
}

/**
 * Is the occurrence of `name` at `start` the `const` declaration at module
 * scope with a plain string literal initializer? Returns true only for that.
 */
function isModuleConstLiteralDeclaration(view: CodeView, name: string, start: number): boolean {
  const { code } = view;
  const kwEnd = prevNonSpace(code, start);
  if (kwEnd < 0 || wordEndingAt(code, kwEnd) !== 'const') return false;
  const kwStart = kwEnd - 'const'.length + 1;
  // Statement start: file start, `;`, `}`, `export`, or a line break (a
  // reserved word cannot continue the expression on the line before).
  const before = prevNonSpace(code, kwStart);
  if (before >= 0) {
    const ch = code[before];
    const lineBreak = code.slice(before + 1, kwStart).includes('\n');
    if (ID_CHAR.test(ch) && wordEndingAt(code, before) === 'export') {
      // `export const`
    } else if (ch !== ';' && ch !== '}' && !lineBreak) {
      return false;
    }
  }
  if (enclosingOpener(code, kwStart) !== -1) return false;

  let k = nextNonSpace(code, start + name.length);
  if (code[k] === ':') {
    k = nextNonSpace(code, k + 1);
    if (code.slice(k, k + 6) !== 'string' || ID_CHAR.test(code[k + 6] ?? '')) return false;
    k = nextNonSpace(code, k + 6);
  }
  if (code[k] !== '=' || code[k + 1] === '=' || code[k + 1] === '>') return false;
  k = nextNonSpace(code, k + 1);
  const litEnd = view.plainStrings.get(k);
  if (litEnd === undefined) return false;
  k = litEnd;
  let after = nextNonSpace(code, k);
  if (code.slice(after, after + 2) === 'as' && !ID_CHAR.test(code[after + 2] ?? '')) {
    const c2 = nextNonSpace(code, after + 2);
    if (code.slice(c2, c2 + 5) !== 'const' || ID_CHAR.test(code[c2 + 5] ?? '')) return false;
    k = c2 + 5;
    after = nextNonSpace(code, k);
  }
  if (after >= code.length || code[after] === ';' || code[after] === '}') return true;
  // No semicolon: the next token must be on a later line and must start a
  // new statement (automatic semicolon insertion), never continue the
  // initializer.
  if (!code.slice(k, after).includes('\n')) return false;
  if (!ID_START.test(code[after])) return false;
  let w = after;
  while (w < code.length && ID_CHAR.test(code[w])) w++;
  return !CONTINUATION_WORDS.has(code.slice(after, w));
}

/**
 * Can the occurrence of `name` at `start` only be a read of an existing
 * binding? Recognises a direct call argument and the right side of `=`.
 */
function isPlainRead(code: string, name: string, start: number): boolean {
  const p = prevNonSpace(code, start);
  const nIdx = nextNonSpace(code, start + name.length);
  const next = nIdx < code.length ? code[nIdx] : '';

  if (p >= 0 && code[p] === '=') {
    // `= name` is never a binding (declarator names come before the `=`).
    return next === '' || next === ';' || next === ')' || next === ',' || next === '}' ||
      code.slice(start + name.length, nIdx).includes('\n');
  }

  if (p < 0 || (code[p] !== '(' && code[p] !== ',')) return false;
  if (next !== ')' && next !== ',') return false;
  const open = enclosingOpener(code, start);
  if (open < 0 || code[open] !== '(') return false;
  const callee = prevNonSpace(code, open);
  if (callee < 0) return false;
  if (ID_CHAR.test(code[callee])) {
    const word = wordEndingAt(code, callee);
    if (word === 'function' || word === 'catch' || word === 'async') return false;
    const beforeWord = prevNonSpace(code, callee - word.length + 1);
    if (beforeWord >= 0) {
      if (code[beforeWord] === '*') return false;
      if (ID_CHAR.test(code[beforeWord]) && wordEndingAt(code, beforeWord) === 'function') return false;
    }
  } else if (code[callee] !== ')' && code[callee] !== ']') {
    return false;
  }
  // A parameter list is followed by a body, an arrow, or a return type.
  const close = matchingCloser(code, open);
  if (close < 0) return false;
  const afterClose = nextNonSpace(code, close + 1);
  const ch = code[afterClose] ?? '';
  if (ch === '{' || ch === ':') return false;
  if (ch === '=' && code[afterClose + 1] === '>') return false;
  return true;
}

/**
 * True when `name` in `src` is bound exactly once, by a module-scope
 * `const name = '<literal>'`, and every other code mention is a plain read.
 */
export function isConstStringLiteralBinding(src: string, name: string, view?: CodeView | null): boolean {
  if (!/^[A-Za-z_$][\w$]*$/.test(name)) return false;
  const cv = view === undefined ? buildCodeView(src) : view;
  if (!cv) return false;
  const { code } = cv;
  const re = new RegExp(`(?<![\\p{ID_Continue}$#])${name.replace(/\$/g, '\\$')}(?![\\p{ID_Continue}$])`, 'gu');
  let declarations = 0;
  for (const m of code.matchAll(re)) {
    const start = m.index!;
    const p = prevNonSpace(code, start);
    // Property access `obj.name` is not this binding; a rest/spread `...name` is.
    if (p >= 0 && code[p] === '.' && code[p - 1] !== '.') continue;
    if (isModuleConstLiteralDeclaration(cv, name, start)) {
      declarations++;
      continue;
    }
    if (!isPlainRead(code, name, start)) return false;
  }
  return declarations === 1;
}

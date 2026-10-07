/**
 * NEMO-005 reports `exec(` / `execSync(` on a line that also carries an
 * interpolated template literal. `RegExp.prototype.exec` shares the name but
 * runs a pattern match and never reaches a shell, so a line whose only exec
 * calls are made on a regular expression is not command execution.
 *
 * A receiver counts as a regular expression when it is:
 *   - a `new RegExp(...)` / `RegExp(...)` call written on the same line,
 *   - a regex literal (`/.../flags`), or
 *   - an identifier declared from one of those (or annotated `: RegExp`) and
 *     never assigned, imported or required as anything else in the file.
 *
 * Anything else (`child_process.exec`, a bare `exec(`, `execSync(`, a member
 * receiver such as `this.re`) is left to the check, so the classification only
 * ever removes a call from NEMO-005, never adds one.
 */

const IDENT = '[A-Za-z_$][\\w$]*';
const REGEXP_VALUE = String.raw`(?:new[ \t]+RegExp\b|RegExp[ \t]*\(|\/(?![*/]))`;
const REGEXP_DECLARATION = new RegExp(
  String.raw`^[ \t]*(?:export[ \t]+)?(?:const|let|var)[ \t]+(${IDENT})[ \t]*` +
    String.raw`(?::[ \t]*RegExp\b[ \t]*(?=[=;,\n]|$)|(?::[^=\n]{0,200})?=\s*${REGEXP_VALUE})`,
  'gm',
);
const EXEC_CALL = /\bexec(Sync)?\s*\(/g;
const REGEXP_CTOR = /(?<![\w$.])(?:new\s+)?RegExp\s*\(/g;
const REGEX_LITERAL_TAIL =
  /(?:^|[=(,:;!&|?{}[]|\breturn|\btypeof)\s*\/(?![*/])(?:\\.|\[(?:\\.|[^\]\\])*\]|[^/\\[])+\/[dgimsuyv]*$/;
const TRAILING_IDENT = new RegExp(`(?<![\\w$.])(${IDENT})$`);
const IMPORT_OR_REQUIRE = /\b(?:import|require)\b/;

function escapeIdent(name: string): string {
  return name.replace(/\$/g, '\\$');
}

/** Index of the string or template literal end that matches the quote at `start`; -1 if the line ends first. */
function stringEnd(line: string, start: number): number {
  const quote = line[start];
  for (let i = start + 1; i < line.length; i++) {
    const c = line[i];
    if (c === '\\') i++;
    else if (c === quote) return i;
    else if (quote === '`' && c === '$' && line[i + 1] === '{') {
      i = matchingClose(line, i + 1);
      if (i < 0) return -1;
    }
  }
  return -1;
}

/** Index of the `)` or `}` that closes the bracket at `open`, skipping string and template literals; -1 if the line ends first. */
function matchingClose(line: string, open: number): number {
  const opener = line[open];
  const closer = opener === '(' ? ')' : '}';
  let depth = 0;
  for (let i = open; i < line.length; i++) {
    const c = line[i];
    if (c === '"' || c === "'" || c === '`') {
      i = stringEnd(line, i);
      if (i < 0) return -1;
    } else if (c === opener) depth++;
    else if (c === closer && --depth === 0) return i;
  }
  return -1;
}

/**
 * Identifiers in `content` that hold a regular expression: declared from
 * `new RegExp(...)`, `RegExp(...)` or a regex literal (or annotated
 * `: RegExp`), with every other assignment also a regular expression and no
 * import or require binding the same name.
 */
export function regExpIdentifiers(content: string): Set<string> {
  const candidates = new Set<string>();
  for (const m of content.matchAll(REGEXP_DECLARATION)) candidates.add(m[1]);

  const result = new Set<string>();
  const lines = content.split('\n');
  for (const name of candidates) {
    const id = escapeIdent(name);
    const assignment = new RegExp(String.raw`(?<![\w$.])${id}[ \t]*(?::[^=;\n]{0,200})?=(?![=>])\s*`, 'g');
    const regExpValue = new RegExp(REGEXP_VALUE, 'y');
    let onlyRegExp = true;
    for (const m of content.matchAll(assignment)) {
      regExpValue.lastIndex = m.index! + m[0].length;
      // A `: RegExp` annotation vouches for the value it initialises.
      if (!regExpValue.test(content) && !/:[ \t]*RegExp[ \t]*=/.test(m[0])) {
        onlyRegExp = false;
        break;
      }
    }
    if (!onlyRegExp) continue;
    const mention = new RegExp(String.raw`(?<![\w$.])${id}(?![\w$])`);
    if (lines.some((line) => IMPORT_OR_REQUIRE.test(line) && mention.test(line))) continue;
    result.add(name);
  }
  return result;
}

/**
 * True when every `exec(` / `execSync(` call on `line` is `RegExp.prototype.exec`
 * on a regular-expression receiver. `regExpIdents` comes from
 * `regExpIdentifiers` over the same file.
 */
export function onlyRegExpExecCalls(line: string, regExpIdents: ReadonlySet<string>): boolean {
  const calls = [...line.matchAll(EXEC_CALL)];
  if (calls.length === 0) return false;

  const ctorCloses = new Set<number>();
  for (const m of line.matchAll(REGEXP_CTOR)) {
    const close = matchingClose(line, m.index! + m[0].length - 1);
    if (close >= 0) ctorCloses.add(close);
  }

  return calls.every((call) => {
    if (call[1]) return false; // execSync is never a RegExp method
    const prefix = line.slice(0, call.index!);
    const dot = /\??\.\s*$/.exec(prefix);
    if (!dot) return false;
    const receiver = prefix.slice(0, dot.index).trimEnd();
    if (receiver.endsWith(')')) return ctorCloses.has(receiver.length - 1);
    if (REGEX_LITERAL_TAIL.test(receiver)) return true;
    const ident = TRAILING_IDENT.exec(receiver);
    return ident !== null && regExpIdents.has(ident[1]);
  });
}

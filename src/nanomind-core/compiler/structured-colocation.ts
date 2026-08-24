/**
 * Structured co-location for the credential-forwarding heuristics.
 *
 * The prose heuristics in `semantic-compiler.ts` pair a credential noun, a
 * transmit verb and a URL by paragraph: two spans are co-located when no blank
 * line separates them. That notion is inert on JSON — pretty-printed JSON has
 * no blank lines, minified JSON has no newlines at all — so in a settings file
 * every URL pairs with every verb, and object KEYS such as `SessionStart` and
 * `PostToolUse` supply the noun and the verb (hackmyagent #541, #403).
 *
 * For content that parses as JSON the unit of co-location is the leaf string
 * value instead:
 *
 *   - object keys are identifiers and never count as evidence;
 *   - an array whose elements are all scalars is ONE leaf (argv semantics:
 *     `"args": ["-X", "POST", "https://…", "-d", "@~/.aws/credentials"]` is a
 *     single command line);
 *   - a credential noun and a transmit verb must sit in the SAME leaf;
 *   - the destination URL may sit in that leaf or in a sibling leaf of the
 *     same parent container (`"command"` next to `"args"`).
 *
 * Offsets returned here are character offsets into the ORIGINAL content, found
 * by locating the parsed string value verbatim. A value that carries JSON
 * escapes (`\"`, `\n`, `\uXXXX`) is not verbatim in the source, so its offset
 * is `undefined` and the caller reports no line for it rather than a wrong one.
 *
 * This engine handles JSON only; YAML and prose stay on the paragraph engine.
 */

/**
 * Credential nouns for the structured forwarding pairing. `credential` matches
 * bare; `session` must be qualified as an actual session-credential
 * (`sessionToken`, `session-id`, `session cookie`, …). Qualifying the noun
 * closed 10 measured real benign forwarding false positives on JSON that merely enumerates
 * lifecycle hooks or eval records (`SessionStart`, `session` in prose) beside a
 * verb and a URL, with no true-positive loss ON THE MEASURED CORPUS — the
 * malicious fixtures pair on `credential`, which stays bare. In general a bare
 * `session` exfil with no qualifier word is an accepted narrowing, as is the
 * cross-leaf split documented on `findStructuredCredentialTransmission` (#571).
 * The read pass (`DATA_TYPE_NOUNS`, for AST-CRED-001) keeps bare `session`;
 * only the forwarding pairing is narrowed.
 */
export const CREDENTIAL_NOUN = /credentials?|session[\s_-]?(?:token|cookie|id|key|secret)/i;

/**
 * Transmit verbs of the data-access pass, matched as WORD STEMS: an optional `re`/`re-`
 * prefix, an optional `s|ed|ing` suffix, and neither side glued to another
 * word-character or a hyphen. So `POST`, `Resend`, `re-send`, `Reposting`,
 * `Reupload`, `uploads` still match, while the identifiers that produced the
 * JSON false positives do not: `PostToolUse` (a hook key), `postflight`,
 * `post-quantum`, `post-session-summary`, `postgres`, `compost` — the trailing
 * `(?![A-Za-z0-9_-])` rejects `post-quantum` because the `-` follows the verb,
 * while `(?:re-?)?` accepts the `-` only as part of a leading `re-`. The
 * lookbehind/lookahead are zero-width, so `exec`/`test` on the whole string
 * still return the verb span itself.
 */
export const TRANSMIT_VERB = /(?<![A-Za-z0-9_-])(?:re-?)?(?:send|forward|transmit|post|upload)(?:s|ed|ing)?(?![A-Za-z0-9_-])/i;

/** Verbs of the SKILL-EXFIL risk surface ("External data transmission"), same word-stem shape. */
export const EXFIL_VERB = /(?<![A-Za-z0-9_-])(?:re-?)?(?:forward|send|transmit|export)(?:s|ed|ing)?(?![A-Za-z0-9_-])/i;

export interface StructuredLeaf {
  /** Each original string value in this leaf (one for a string, many for a scalar array). */
  segments: string[];
  /** The segments joined by a single space, for noun/verb tests. */
  text: string;
  /** Identity of the container that directly holds the leaf (or the scalar array). */
  parent: number;
}

export interface UrlSpan {
  /** The URL exactly as it appears in the artifact, trailing punctuation trimmed. */
  span: string;
  /** Offset of `span` in the original content, when it can be located verbatim. */
  offset?: number;
}

export interface StructuredMatch {
  /** The credential noun as written in the artifact. */
  term: string;
  termOffset?: number;
  /** The transmit verb as written in the artifact. */
  verb: string;
  verbOffset?: number;
  /** The destination URL from the same leaf or a sibling leaf, if any. */
  url?: UrlSpan;
}

export interface StructuredVerbUrl {
  verb: string;
  verbOffset?: number;
  url: UrlSpan;
}

/**
 * Parse JSON, tolerating a BOM, `//` and `/* *\/` comments and trailing commas
 * (the JSONC dialect used by `.vscode/settings.json` and `tsconfig.json`).
 * Returns `undefined` unless the document is an object or an array — a bare
 * string or number is not a structured artifact and stays on the prose engine.
 *
 * The tolerant pass runs only when strict `JSON.parse` fails, so a document
 * that is valid JSON is never altered before parsing.
 */
export function parseStructuredJson(content: string): unknown | undefined {
  const text = content.replace(/^\uFEFF/, '');
  const head = text.trimStart();
  if (!head.startsWith('{') && !head.startsWith('[')) return undefined;
  const strict = tryParse(text);
  if (strict !== NOT_JSON) return isContainer(strict) ? strict : undefined;
  const relaxed = tryParse(stripJsonc(text));
  if (relaxed === NOT_JSON) return undefined;
  return isContainer(relaxed) ? relaxed : undefined;
}

const NOT_JSON = Symbol('not-json');

function tryParse(text: string): unknown | typeof NOT_JSON {
  try {
    return JSON.parse(text);
  } catch {
    return NOT_JSON;
  }
}

function isContainer(value: unknown): boolean {
  return typeof value === 'object' && value !== null;
}

/**
 * Remove comments and trailing commas outside string literals. String
 * literals are copied byte-for-byte (escapes included) so the parsed values
 * are the same ones a strict parser would produce.
 */
export function stripJsonc(text: string): string {
  const out: string[] = [];
  let i = 0;
  let inString = false;
  let pendingComma = -1; // index in `out` of a comma that may turn out to be trailing
  while (i < text.length) {
    const ch = text[i];
    if (inString) {
      out.push(ch);
      if (ch === '\\' && i + 1 < text.length) {
        out.push(text[i + 1]);
        i += 2;
        continue;
      }
      if (ch === '"') inString = false;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inString = true;
      pendingComma = -1;
      out.push(ch);
      i += 1;
      continue;
    }
    if (ch === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end < 0 ? text.length : end + 2;
      continue;
    }
    if (ch === ',') {
      pendingComma = out.length;
      out.push(ch);
      i += 1;
      continue;
    }
    if (ch === '}' || ch === ']') {
      if (pendingComma >= 0) out.splice(pendingComma, 1);
      pendingComma = -1;
      out.push(ch);
      i += 1;
      continue;
    }
    if (!/\s/.test(ch)) pendingComma = -1;
    out.push(ch);
    i += 1;
  }
  return out.join('');
}

/**
 * Walk a parsed JSON document and return its leaf string values in document
 * order. Keys are dropped. Two structures collapse to a single leaf because
 * they are one command line, not independent values:
 *
 *   - an array whose elements are all scalars (an argv list);
 *   - an object that carries a string `command` alongside a scalar `args`
 *     array — the `command`/`args` pair MCP servers and Claude Code hooks use,
 *     where the verb may sit in `command` and the URL in `args`. This is the
 *     one cross-field merge kept;
 *     the general "any sibling leaf" pairing is refused, because it read a
 *     benign A2A card's `description` against its sibling `url`.
 */
export function collectStructuredLeaves(root: unknown): StructuredLeaf[] {
  const leaves: StructuredLeaf[] = [];
  let nextId = 0;

  const isScalar = (v: unknown): boolean =>
    v === null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean';
  const scalarStrings = (arr: unknown[]): string[] =>
    arr.filter((v): v is string => typeof v === 'string');

  const visit = (value: unknown, parent: number): void => {
    if (typeof value === 'string') {
      leaves.push({ segments: [value], text: value, parent });
      return;
    }
    if (Array.isArray(value)) {
      if (value.length > 0 && value.every(isScalar)) {
        const segments = scalarStrings(value);
        if (segments.length > 0) leaves.push({ segments, text: segments.join(' '), parent });
        return;
      }
      const id = nextId++;
      for (const item of value) visit(item, id);
      return;
    }
    if (value !== null && typeof value === 'object') {
      const obj = value as Record<string, unknown>;
      const id = nextId++;
      const command = obj.command;
      const args = obj.args;
      const argvMerge =
        typeof command === 'string' &&
        Array.isArray(args) &&
        args.length > 0 &&
        args.every(isScalar);
      if (argvMerge) {
        const segments = [command as string, ...scalarStrings(args as unknown[])];
        leaves.push({ segments, text: segments.join(' '), parent: id });
        for (const [k, v] of Object.entries(obj)) {
          if (k === 'command' || k === 'args') continue;
          visit(v, id);
        }
        return;
      }
      for (const item of Object.values(obj)) visit(item, id);
    }
  };

  visit(root, nextId++);
  return leaves;
}

/**
 * Locate a parsed string value verbatim in the original content. Returns the
 * offset of its first occurrence, or `undefined` when the value is not a
 * verbatim substring (it carried JSON escapes).
 */
export function locateSegment(content: string, segment: string): number | undefined {
  if (!segment) return undefined;
  // Prefer an occurrence in a VALUE position over one that is an object KEY (a
  // key's closing quote is followed by `:`). Without this, a string that also
  // appears earlier as a key or alias makes `indexOf` cite the key's line
  // instead of the value's — a confidently wrong line in the finding message.
  // Falls back to the first occurrence if every one is key-like.
  let from = 0;
  let firstAny = -1;
  for (;;) {
    const idx = content.indexOf(segment, from);
    if (idx < 0) break;
    if (firstAny < 0) firstAny = idx;
    if (!/^"\s*:/.test(content.slice(idx + segment.length))) return idx;
    from = idx + 1;
  }
  return firstAny < 0 ? undefined : firstAny;
}

/** Trailing characters that belong to the surrounding text, not to the URL. */
const TRAILING_PUNCTUATION = /[.,;:!?)\]>"']+$/;

/**
 * The first http(s) URL inside one string value, bounded by whitespace or the
 * end of the value and trimmed of trailing punctuation. Quote characters are
 * NOT excluded from the span itself: they are legal in the userinfo component
 * and `https://api.stripe.com'@evil.example/x` must stay one span so that
 * `urlOrigin` resolves it to the host the request actually reaches.
 */
export function extractUrlSpan(text: string): { span: string; index: number } | undefined {
  const m = /https?:\/\/\S+/.exec(text);
  if (!m) return undefined;
  const span = m[0].replace(TRAILING_PUNCTUATION, '');
  return span ? { span, index: m.index } : undefined;
}

/**
 * The origin (`scheme://host[:port]`) a URL span resolves to, or `undefined`
 * when the span does not parse as an http(s) URL. Parsing is what defeats the
 * userinfo masquerade: `new URL("https://api.stripe.com'@evil.example/x")`
 * reports host `evil.example`, not the legitimate-looking prefix.
 */
export function urlOrigin(span: string | undefined): string | undefined {
  if (!span) return undefined;
  try {
    const u = new URL(span);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return undefined;
    return u.origin;
  } catch {
    return undefined;
  }
}

function findInSegments(
  content: string,
  leaf: StructuredLeaf,
  re: RegExp,
): { text: string; offset?: number } | undefined {
  for (const segment of leaf.segments) {
    const m = new RegExp(re.source, re.flags.replace('g', '')).exec(segment);
    if (!m) continue;
    const base = locateSegment(content, segment);
    return { text: m[0], offset: base === undefined ? undefined : base + m.index };
  }
  return undefined;
}

function urlInLeaf(content: string, leaf: StructuredLeaf): UrlSpan | undefined {
  for (const segment of leaf.segments) {
    const hit = extractUrlSpan(segment);
    if (!hit) continue;
    const base = locateSegment(content, segment);
    return { span: hit.span, offset: base === undefined ? undefined : base + hit.index };
  }
  return undefined;
}

/**
 * The first leaf (document order) that carries a credential noun, a transmit
 * verb AND the destination URL, all in the ONE leaf. `undefined` when the
 * content is not structured JSON or no leaf qualifies.
 *
 * All three tokens must share the leaf. Two accepted trades follow: a noun/verb/URL split across
 * sibling leaves does not pair (a benign A2A card's `description` and `url`, a
 * package record's `credential-protection` and `post-quantum` keywords — but
 * also a genuine exfil that splits the credential PATH into an `env` value and
 * the verb+URL into the `command`, tracked as a false negative in #571), and
 * a forwarding instruction with no literal URL — an exfil command reading its
 * endpoint from `$EXFIL_URL` — is left to the defense-in-depth checks rather
 * than reported with an unknowable destination. The `command`/`args` shell
 * pair is already merged into one leaf by `collectStructuredLeaves`, so a URL
 * in `args` still counts as in-leaf; `env` is not merged (that is the #571 gap).
 */
export function findStructuredCredentialTransmission(
  content: string,
  nounRe: RegExp = CREDENTIAL_NOUN,
  verbRe: RegExp = TRANSMIT_VERB,
): StructuredMatch | undefined {
  const root = parseStructuredJson(content);
  if (root === undefined) return undefined;
  for (const leaf of collectStructuredLeaves(root)) {
    if (!nounRe.test(leaf.text) || !verbRe.test(leaf.text)) continue;
    const url = urlInLeaf(content, leaf);
    if (!url) continue;
    const term = findInSegments(content, leaf, nounRe);
    const verb = findInSegments(content, leaf, verbRe);
    if (!term || !verb) continue;
    return {
      term: term.text,
      termOffset: term.offset,
      verb: verb.text,
      verbOffset: verb.offset,
      url,
    };
  }
  return undefined;
}

/**
 * The first URL in any leaf string value, bounded by that value. The
 * evidence fallback for structured content: the gate regex of the SKILL-EXFIL
 * surface has no JSON-string terminator and runs through a minified document
 * (`https://evil.example/x","more":"tracker.com`, #559), while a leaf-bounded
 * span stops where the value stops.
 */
export function findStructuredFirstUrl(content: string): UrlSpan | undefined {
  const root = parseStructuredJson(content);
  if (root === undefined) return undefined;
  for (const leaf of collectStructuredLeaves(root)) {
    const url = urlInLeaf(content, leaf);
    if (url) return url;
  }
  return undefined;
}

/**
 * The first leaf (document order) that carries a verb from `verbRe` together
 * with a URL in the SAME leaf. Used for the transmit destination the
 * narratives list and for the SKILL-EXFIL evidence span, so the evidence
 * points at the URL that sits next to the verb rather than at the first URL in
 * the document (a `$schema` pointer, typically). No sibling fallback — the
 * `command`/`args` case is already one merged leaf.
 */
export function findStructuredVerbUrl(
  content: string,
  verbRe: RegExp,
): StructuredVerbUrl | undefined {
  const root = parseStructuredJson(content);
  if (root === undefined) return undefined;
  for (const leaf of collectStructuredLeaves(root)) {
    if (!verbRe.test(leaf.text)) continue;
    const verb = findInSegments(content, leaf, verbRe);
    if (!verb) continue;
    const url = urlInLeaf(content, leaf);
    if (!url) continue;
    return { verb: verb.text, verbOffset: verb.offset, url };
  }
  return undefined;
}

/**
 * What "this AI config grants broad permissions" is allowed to mean (#299, #364).
 *
 * The finding this feeds used to be a bare word test over the whole file:
 *
 *     /(?:allow|permit|grant|unrestricted|all\s+bash)/i.test(content)
 *
 * so a `CLAUDE.md` reading
 *
 *     The agent must never allow shell access to untrusted input.
 *     Do not permit writes outside the repository.
 *
 * was reported `HIGH — AI config files grant broad permissions`. The document
 * asserts the opposite of the finding, and governance documents are where the
 * words "allow" and "permit" live, so the rule fired hardest on exactly the
 * files whose presence is the good outcome (#299).
 *
 * That was replaced by a rule asking for a GRANT rather than a permissive
 * vocabulary — still matching text, over the whole file. #364 is why that could
 * not work for structured config, and the reason is not a tuning problem:
 *
 *   **`allow` and `deny` values are textually identical.** Only the key tells
 *   them apart, and a deny list is *supposed* to be full of wildcards.
 *
 * So a text rule aimed at permission entries is aimed at the deny list too, and
 * the remediation it prints — "replace `Read(*.key)` with the specific paths
 * this agent needs" — tells the reader to delete the rule that stops an agent
 * reading private keys. Measured on the shipped `56263f9`, before any change
 * here, `{"permissions":{"deny":["Read(*.key)","Bash(*)"]}}` already reported
 * HIGH: the `.` inside `Read(*.key)` opens a new "sentence", so the negation
 * guard never saw the word `deny`.
 *
 * ## The split
 *
 * **Structured files are parsed.** `.json`, `.yml` and `.yaml` configs go to
 * `walkConfigForGrants`, which descends only into keys that grant and prunes
 * `deny` without looking inside it. Parsing also closes an escape class no text
 * rule reaches: `"Bash(*)"` is valid JSON containing no `*`.
 *
 * **Prose files are matched, and only for prose constructions.** `CLAUDE.md`,
 * `.cursorrules`, `.windsurfrules` and `.github/copilot-instructions.md` carry
 * no schema, so text is the only option there. Permission-entry patterns are
 * NOT applied to them: without a key, `"Read(*.key)"` in a document could as
 * easily be a deny rule being documented as a grant being made.
 *
 * This half is a heuristic over text the scanned file controls, and that is
 * worth saying plainly rather than implying otherwise: a sentence can be
 * written to defeat it. The negation guard must GOVERN the match — same clause,
 * and close enough to bind it — which narrows the off switch without closing
 * it. What makes the structured half sound is that a VALUE cannot mean its own
 * opposite, because its key already carries the polarity. Prose has no key.
 *
 * `__tests__/scanner/permission-grant.test.ts` and
 * `__tests__/scanner/permission-vocabulary.test.ts` pin both directions.
 */
import * as yaml from 'js-yaml';
import { escapeForDisplay } from '../ui/display-safe';
import {
  classifyPermissionEntry,
  walkConfigForGrants,
  makeGrant,
  locateGrantLine,
  redactLikelySecrets,
  type UnboundedGrant,
} from './permission-vocabulary';

/** Where a config file grants broad permissions, and what said so. */
export interface PermissionGrant {
  /** 1-indexed line within the config file. */
  line: number;
  /**
   * The phrase or permission entry that matched, redacted and display-escaped.
   *
   * Both halves of that are load-bearing. The value comes out of the scanned
   * file and every renderer prints it, so a raw terminal control sequence in a
   * `CLAUDE.md` line or an allow entry would rewrite the reader's screen.
   */
  token: string;
  /** The whole matched line, trimmed, redacted, escaped and length-capped. */
  text: string;
  /** Why it is a grant, as one clause. Absent for prose, which quotes itself. */
  reason?: string;
  /**
   * What to replace it with, naming a concrete alternative.
   *
   * Absent for prose: a sentence in a `CLAUDE.md` has no mechanical
   * replacement, and inventing one would be worse than quoting the sentence and
   * letting the author rewrite it.
   */
  fix?: string;
}

/** Longest line this will quote back into a report. */
export const MAX_TEXT = 120;

/** Longest single token this will quote back into a report. */
export const MAX_TOKEN = 80;

/**
 * Longest line the prose matcher will look at.
 *
 * Retained after the permission-entry patterns moved out, even though the one
 * quadratic pattern moved out with them. A minified or generated line is not
 * prose, so nothing is lost, and the bound is what makes a future pattern's
 * worst case a bounded one. The ReDoS test measures the prose set directly,
 * WITHOUT this cap, so the cap cannot make that measurement vacuous.
 */
const MAX_LINE = 4096;

/**
 * Prose constructions that hand an agent broad authority.
 *
 * Every pattern matches a line in a corpus fixture or in #299's reproduction.
 * Two properties are load-bearing and neither is decorative:
 *
 * 1. **A grant is a construction, not a word.** `allow` is a direction-free
 *    verb — a sentence is only a grant when what is allowed is broad (`any`,
 *    `all`, `unrestricted`, `full`).
 * 2. **`no restrictions` and `never refuse` are grants that OPEN with a
 *    negative word**, so they are matched as whole phrases rather than
 *    assembled from a negation rule that would then suppress them.
 *
 * `without` is deliberately not a negation token: it heads several grant
 * phrases (`without restriction`, `without safety checks`).
 *
 * No pattern here contains an ambiguous quantifier pair. The one that did —
 * `\s*\[?\s*`, the `X*` `Y?` `X*` shape, measured at 8.1s on a 128k line with
 * the length cap lifted — was a permission-entry pattern, and permission
 * entries are the parser's job now.
 */
export const PROSE_GRANT_PATTERNS: readonly RegExp[] = [
  /\bunrestricted\b/i,
  /\bwithout\s+(?:any\s+)?(?:restrictions?|limitations?|limits?|question|approval|confirmation|asking|permission|safety\s+checks?|security\s+checks?)/i,
  /\bno\s+(?:restrictions?|limits?|limitations?|safety\s+checks?|security\s+checks?)\b/i,
  /\b(?:full|complete|unlimited|unfettered|total)\s+access\b/i,
  /\ball\s+bash\b/i,
  /\b(?:bypass|skip|disable|ignore|override)\s+(?:the\s+)?(?:safety|security|permission)/i,
  /\balways\s+(?:execute|run|comply|obey)\b/i,
  /\bnever\s+(?:refuse|decline)\b/i,
  /\bnever\s+ask\s+for\s+(?:permission|approval|confirmation)\b/i,
  /--dangerously-skip-permissions\b/,
  // A permissive verb whose object is broad. The distance bound keeps the two
  // halves in one clause: "allow the agent to run any command" is a grant,
  // "allow X" three sentences above the word "all" is not.
  /\b(?:allow|permit|grant|enable)\b[^.!?\n]{0,40}\b(?:any|all|every|anything|everything|unrestricted|full|arbitrary)\b/i,
];

/**
 * Words that reverse a grant when they GOVERN it.
 *
 * Applied to the text before the match only, and a grant phrase that opens with
 * a negative word carries that word inside the match, so it is not read as its
 * own negation.
 */
const NEGATIONS = /\b(?:never|not|n't|avoid|prohibit|prohibited|forbid|forbidden|disallow|disallowed|deny|denied|refuse|cannot|can't)\b/i;

/**
 * Clause boundaries, for scoping the negation test.
 *
 * `:` is here and `,` is not, and that pair is what separates the two shapes a
 * bare sentence scope cannot tell apart:
 *
 *   "Do not, under any circumstances, grant full access."  -> restriction
 *   "Do not worry: the agent has unrestricted access."     -> grant
 *
 * A colon introduces a new assertion, so a negation before it does not reach
 * past it. A comma does not, so a negation still governs across one.
 */
const CLAUSE_BREAK = /[.!?;:]/g;

/**
 * How many words a negation may sit before a match and still govern it.
 *
 * Measured rather than chosen: `__tests__/scanner/permission-grant.test.ts`
 * mutates it in both directions and pins real fixtures on each side. It cannot
 * be made sound — prose in a scanned file is attacker-controlled, and any
 * distance is a distance an attacker can pad past. It narrows the off switch;
 * the structured path is what closes it.
 */
export const NEGATION_REACH_WORDS = 6;

/** The start of the clause containing `index` within `line`. */
function clauseStart(line: string, index: number): number {
  CLAUSE_BREAK.lastIndex = 0;
  let start = 0;
  let m: RegExpExecArray | null;
  while ((m = CLAUSE_BREAK.exec(line)) !== null) {
    if (m.index >= index) break;
    start = m.index + 1;
  }
  return start;
}

/**
 * Does a negation in `before` govern a match that follows it?
 *
 * `before` is already clause-scoped by the caller; this adds the distance
 * bound, counted in words so that padding costs the attacker something visible.
 */
function negationGoverns(before: string): boolean {
  const words = before.split(/\s+/).filter(Boolean);
  return NEGATIONS.test(words.slice(-NEGATION_REACH_WORDS).join(' '));
}

/** The first prose grant on `line`, or undefined. Exported for the ReDoS probe. */
export function matchProseGrant(line: string): { token: string; index: number } | undefined {
  for (const pattern of PROSE_GRANT_PATTERNS) {
    const m = pattern.exec(line);
    if (!m) continue;
    if (negationGoverns(line.slice(clauseStart(line, m.index), m.index))) continue;
    return { token: m[0].trim(), index: m.index };
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Format routing
// ---------------------------------------------------------------------------

/**
 * Is `file` a config this can parse?
 *
 * Extension-driven rather than name-driven, so a new config family in
 * `AI_CONFIG_PATTERNS` gets the right half without a second list to keep in
 * sync. `.js`/`.ts` configs (`langchain.config.js`) are code, not data, and
 * take the prose path — which is also what keeps `arr.map(x => x * 2)` from
 * ever being read as a permission entry.
 */
function structuredFormat(file: string): 'json' | 'yaml' | undefined {
  const lower = file.toLowerCase();
  if (lower.endsWith('.json')) return 'json';
  if (lower.endsWith('.yml') || lower.endsWith('.yaml')) return 'yaml';
  return undefined;
}

/**
 * Parse a structured config, or give up.
 *
 * Giving up is deliberate. Falling back to text matching on a file that failed
 * to parse would reach the defect this module exists to remove, by the simple
 * route of writing invalid JSON — and a config that does not parse does not
 * load in the tool it configures either, so the grant it appears to make is not
 * live. The JSONC retry exists because editors write `//` comments and trailing
 * commas into settings files that the tools themselves accept.
 */
function parseStructured(rawContent: string, format: 'json' | 'yaml'): unknown {
  // A UTF-8 BOM is invisible, common on Windows-authored files, and makes
  // `JSON.parse` throw — which under the give-up rule below means total
  // silence on a file that loads fine everywhere else.
  const content = rawContent.charCodeAt(0) === 0xfeff ? rawContent.slice(1) : rawContent;
  if (format === 'yaml') {
    try { return yaml.load(content, { json: true }); } catch { return undefined; }
  }
  try { return JSON.parse(content); } catch { /* fall through to the JSONC retry */ }
  try { return JSON.parse(stripJsonComments(content)); } catch { return undefined; }
}

/** Remove `//` and block comments and trailing commas, respecting string literals. */
function stripJsonComments(s: string): string {
  let out = '';
  let inString = false;
  let escaped = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inString) {
      out += c;
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') { inString = true; out += c; continue; }
    if (c === '/' && s[i + 1] === '/') { while (i < s.length && s[i] !== '\n') i++; out += '\n'; continue; }
    if (c === '/' && s[i + 1] === '*') { i += 2; while (i < s.length && !(s[i] === '*' && s[i + 1] === '/')) i++; i++; continue; }
    out += c;
  }
  return out.replace(/,(\s*[}\]])/g, '$1');
}

/**
 * The first genuine broad-permission grant in `content`, or undefined.
 *
 * `file` selects the half: parsed for `.json`/`.yml`/`.yaml`, prose for
 * everything else. It is required rather than optional because a default would
 * silently put structured config back on the prose path, which is the bug.
 */
/**
 * Parse an AI config by filename, or undefined when it is not structured or
 * does not parse.
 *
 * Exported because `secure`'s `CLAUDE-002` must parse the SAME way `detect`
 * does. It used bare `JSON.parse`, so a `//` comment or trailing comma — which
 * Claude Code itself accepts — made the CI gate silent on a file `detect`
 * reported HIGH on (#363).
 */
export function parseAiConfig(content: string, file: string): unknown {
  const format = structuredFormat(file);
  return format ? parseStructured(content, format) : undefined;
}

/**
 * Read an allow-list entry that is not permission syntax as the author's own
 * statement of intent.
 *
 * Exported for the same reason as `parseAiConfig`: without it, `secure` was
 * blind to `"allow": ["Bash - Allow all bash commands without approval"]` while
 * `detect` reported it.
 */
export function proseAllowEntry(entry: string, key: string): UnboundedGrant | undefined {
  const m = matchProseGrant(entry);
  return m
    ? makeGrant(
      entry,
      `states a grant ("${m.token}") and is not valid permission syntax, so it grants nothing to the tool either`,
      `replace "${entry}" with the scoped entries you meant, e.g. "Bash(npm test)" or "Read(src/**)"`,
      key,
    )
    : undefined;
}

export function findPermissionGrant(content: string, file: string): PermissionGrant | undefined {
  const lines = content.split('\n');
  const format = structuredFormat(file);

  if (format) {
    const doc = parseStructured(content, format);
    if (doc === undefined) return undefined;
    // An allow-list entry that is not permission syntax still sits under a key
    // that proves it is not a deny, so the author's own prose is read there.
    // `"Bash - Allow all bash commands without approval"` is a real entry in a
    // real settings file: it grants nothing to the tool, and states everything
    // to the reader.
    const grant = walkConfigForGrants(doc, proseAllowEntry);
    if (!grant) return undefined;
    const line = locateGrantLine(lines, grant) || 1;
    return {
      line,
      token: forReport(grant.entry.trim(), MAX_TOKEN),
      text: forReport((lines[line - 1] ?? '').trim(), MAX_TEXT),
      // Both arrive redacted and escaped from `makeGrant`, so only the cap is
      // left. `reason` was uncapped, and it interpolates the entry — an entry
      // is as long as the scanned file chooses to make it.
      reason: capped(grant.reason, MAX_TEXT),
      fix: capped(grant.fix, MAX_TEXT),
    };
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > MAX_LINE) continue; // minified or generated; not prose
    const m = matchProseGrant(line);
    if (!m) continue;
    return {
      line: i + 1,
      token: forReport(m.token, MAX_TOKEN),
      text: forReport(line.trim(), MAX_TEXT),
    };
  }
  return undefined;
}

/** Re-exported so a caller needs one import for the shared vocabulary. */
export { classifyPermissionEntry, walkConfigForGrants };

/**
 * Redact, escape, then cap — in that order, for every value quoted back.
 *
 * Order matters: capping first could split a credential and leave half of it
 * visible, and escaping first would let the escape expansion push the real text
 * past the cap.
 */
export function forReport(s: string, max: number): string {
  return capped(escapeForDisplay(redactLikelySecrets(s)), max);
}

function capped(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/**
 * Re-exported, not defined here.
 *
 * It moved to `permission-vocabulary.ts` because the grant's own `reason` and
 * `fix` are built there and have to be redacted at construction: they
 * interpolate scanned text, and the report was printing the redacted copy and
 * the raw one in the same sentence. Applied to `token` as well as `text` — a
 * permission entry can carry a secret, and `token` is printed by all three
 * renderers AND interpolated into the Fix line.
 */
export { redactLikelySecrets };

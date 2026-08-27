/**
 * Binary-level CLI prefix resolution + command-citation rebranding.
 *
 * hackmyagent is bundled by parent CLIs (notably opena2a-cli) that spawn it and
 * set `HMA_CLI_PREFIX` so user-facing command citations read in the parent's
 * verb namespace (`opena2a secure …` instead of `hackmyagent secure …`). This
 * module is the single source of truth for that prefix so every surface — the
 * Commander program name, --help examples, next-step hints, and scanner-produced
 * `fix:` / `remediation:` strings — agrees.
 *
 * When `HMA_CLI_PREFIX` is unset, behavior is identical to before: the binary
 * cites itself as `hackmyagent` (or `opena2a scan` when invoked through that
 * wrapper's argv0), and `rebrandCommandCitations` is a no-op.
 */
import { citationPath } from './ui/shell-quote';
import { escapeForDisplay } from './ui/display-safe';

/**
 * Resolve the binary-level command prefix.
 *   1. Explicit `HMA_CLI_PREFIX` (a parent CLI overriding the citation namespace).
 *   2. argv0-derived: `opena2a`/`opena2a-*` → `opena2a scan`.
 *   3. Default: `hackmyagent`.
 */
/**
 * The prefix as configured: the VALUE, for data channels. The hardening
 * scanner composes its `fix` strings with it (`cliName`), and those strings
 * ship in `--json`, SARIF and HTML, which carry values, not renderings. Every
 * printing line that shows a scanner fix escapes it there.
 */
export function resolveRawCliPrefix(): string {
  if (process.env.HMA_CLI_PREFIX) return process.env.HMA_CLI_PREFIX;
  const argv1 = process.argv[1] || '';
  const basename = require('path').basename(argv1).replace(/\.[jt]s$/, '');
  if (basename === 'opena2a' || basename.startsWith('opena2a-')) {
    return 'opena2a scan';
  }
  return 'hackmyagent';
}

/**
 * The prefix for the text channel: `resolveRawCliPrefix()` made display-safe.
 *
 * #574 — the prefix is interpolated into footers, usage text and every
 * rebranded citation, and several of those sites rebrand AFTER escaping the
 * text they sit in. A value carrying a newline or an escape sequence forged
 * lines through them. It is escaped once here, so every interpolation of
 * `CLI_PREFIX` inherits the display-safe form; `escapeForDisplay` is
 * idempotent on already-escaped text, so sites that escape again render the
 * same bytes. The vector is the environment, not a scanned tree — bounded,
 * but the display contract holds nowhere if it does not hold here.
 */
export function resolveCliPrefix(): string {
  const raw = resolveRawCliPrefix();
  const safe = escapeForDisplay(raw);
  // Not silent: a prefix that had to be altered to be displayable is said so,
  // once, on stderr — the citations the user is about to read carry the
  // escaped form, and nothing else would tell them why.
  if (safe !== raw) {
    console.error('HMA_CLI_PREFIX contained control characters; command citations render it escaped.');
  }
  return safe;
}

export const CLI_PREFIX = resolveCliPrefix();
/** The configured value, for data channels (see `resolveRawCliPrefix`). */
export const RAW_CLI_PREFIX = resolveRawCliPrefix();

/**
 * hackmyagent verbs that may appear in user-facing command citations. Used to
 * verb-anchor the rebrander so a `hackmyagent <verb>` PAIR is rewritten but the
 * bare package name (URLs, `npm i -g hackmyagent`, import paths, the
 * `.hackmyagent-backup/` directory, MCP tool ids like `hackmyagent_scan`) is
 * left intact. Sorted longest-first at use so `secure-openclaw` wins over
 * `secure` and `scan-soul` over `scan`.
 */
const HMA_VERBS = [
  'secure-openclaw', 'secure-nemoclaw', 'harden-soul', 'harden-skill',
  'scan-soul', 'scan-history', 'fix-all', 'init-mcp', 'check-metadata',
  'pull-stubs', 'secure', 'scan', 'check', 'attack', 'detect', 'wild',
  'rollback', 'trust', 'telemetry', 'nanomind', 'harden', 'review',
  'protect', 'benchmark', 'oracle', 'init', 'verify',
] as const;

const ALT = [...HMA_VERBS].sort((a, b) => b.length - a.length).join('|');

// `(?:npx )?hackmyagent <verb>` where the verb is one we recognize. The left
// lookbehind `(?<![\w@/.-])` keeps embeddings (scoped names, paths, the
// `.hackmyagent-backup` dir, `hackmyagent_scan` ids) from matching; the right
// `(?![\w-])` keeps an unrecognized hyphenated subcommand from being half
// rewritten. Mirrors opena2a-cli's util/rebrand.ts discipline so the two stay
// byte-compatible and the consumer-side pass becomes a no-op.
const CITATION_RE = new RegExp(
  `(?:npx )?(?<![\\w@/.-])hackmyagent\\s+(${ALT})(?![\\w-])`,
  'g',
);

/**
 * npm package that ships the `opena2a` binary.
 *
 * The package name and the binary name differ: the package is `opena2a-cli`
 * and it installs a bin called `opena2a`. `npm i -g opena2a` is a 404 — the
 * name is unpublished (#201).
 */
export const OPENA2A_PACKAGE = 'opena2a-cli';

/**
 * True when `opena2a` is known to be on PATH.
 *
 * hackmyagent only knows this when it was spawned BY that CLI, which is
 * exactly when `HMA_CLI_PREFIX` / an `opena2a*` argv0 sets a non-default
 * prefix. A standalone `npm i hackmyagent` has no such guarantee, so any
 * `opena2a <verb>` we cite there would be a dead end.
 */
function opena2aIsOnPath(): boolean {
  return CLI_PREFIX !== 'hackmyagent';
}

/**
 * Sibling-CLI verbs that appear inside our finding-fix and explainer text.
 *
 * Deliberately narrow — only verbs actually cited in remediation strings.
 * Keeping it tight means prose like "opena2a is a separate CLI" or
 * "opena2a or hackmyagent" cannot be caught by the verb-anchored pattern.
 */
const OPENA2A_VERBS = ['protect', 'mcp'] as const;

// Same anchoring discipline as CITATION_RE: a left lookbehind so scoped
// names / paths / URLs never match, and a right boundary so an unrecognized
// hyphenated subcommand is not half-rewritten. `npx `-prefixed citations are
// absorbed so re-running the rewrite is idempotent.
const OPENA2A_CITATION_RE = new RegExp(
  `(?:npx ${OPENA2A_PACKAGE} )?(?<![\\w@/.-])opena2a\\s+(${OPENA2A_VERBS.join('|')})(?![\\w-])`,
  'g',
);

/**
 * Verbs whose citation is only runnable when it names the tree to act on.
 *
 * `hackmyagent secure --fix` with no target acts on the CURRENT directory, so
 * a user who ran `cd parent && hackmyagent secure ./proj` and pasted the fix
 * line got `.gitignore` and `.hackmyagent-backup/` created in `parent`, the
 * credential in `proj` untouched, and a success summary — a false signal that
 * the finding was resolved (#293). Same class as `harden-soul .` (#288).
 */
const TARGET_TAKING_VERBS = [
  'secure-openclaw', 'secure-nemoclaw', 'harden-soul', 'harden-skill',
  'scan-soul', 'fix-all', 'secure', 'scan', 'check', 'detect', 'rollback',
  'protect',
] as const;

const TARGET_VERB_ALT = [...TARGET_TAKING_VERBS].sort((a, b) => b.length - a.length).join('|');

/**
 * The tree the current scan is actually about, as the reader should type it.
 *
 * `undefined` means "no rewrite" — either nothing set it yet, or the scan
 * target IS the working directory, in which case the pathless form is already
 * correct and rewriting it would be noise.
 */
let citationTarget: string | undefined;

/**
 * Set the scan target used to complete pathless command citations.
 *
 * Pass the display form the rest of the output uses (`./proj`), NOT an
 * absolute path — the citation should read like something the user would type.
 *
 * For a REMOTE target (npm / PyPI / GitHub / a skill ref) there is no local
 * path any local-fix advice could correctly name, so pass `{ remote: true }`.
 * Citations then get the house-style `<dir>` placeholder rather than a path
 * that would silently mean "wherever you happen to be standing".
 *
 * Pass `undefined` when the target is the working directory.
 */
export function setCitationTarget(target: string | undefined, opts?: { remote?: boolean }): void {
  if (opts?.remote) {
    citationTarget = '<dir>';
    return;
  }
  // #328 — this string is spliced into commands the reader is told to paste, and
  // it is a path out of the scanned tree. Sanitised HERE, at the one place the
  // target enters the citation layer, rather than at each of the ~29 strings the
  // rewriter reaches: the alternative is escaping downstream of the splice,
  // which is what left raw ESC bytes in `check`'s report while `secure` had been
  // escaping since #324. Ordinary paths are returned unchanged, so nothing that
  // reads normally today starts reading like an incantation.
  //
  // #343 — `citationPath` returns null when the path cannot be both shown and
  // pasted: a name carrying a control character is displayed as a rendering, so
  // any command built from the real bytes would name something the reader cannot
  // see. The house-style `<dir>` placeholder is already the answer for a target
  // no local command can correctly name, so it is the answer here too — the
  // citation stays runnable once the reader fills it in, rather than becoming a
  // command that quietly acts on a different file.
  if (target === undefined) {
    citationTarget = undefined;
    return;
  }
  citationTarget = citationPath(target) ?? '<dir>';
}

/** Test seam — reset module state between cases. */
export function __resetCitationTargetForTests(): void {
  citationTarget = undefined;
}

/**
 * Where a command citation ends and prose begins.
 *
 * These strings are a command followed by an explanation, separated by a
 * double space or a dash: "protect .  — migrates hardcoded secrets…". Cutting
 * at the separator keeps the tokenizer from reading the prose as arguments.
 */
const COMMAND_TAIL_END = /( {2,}|\s+[—–]\s|\s+--\s|\n|`|$)/;

/**
 * Insert the scan target into citations that need one and do not have one.
 *
 * Deliberately conservative — it only acts when it can prove the citation is
 * targetless. A citation that already carries any non-flag argument (an
 * explicit path, a package name, a `<dir>` placeholder, a check list) is left
 * exactly as it is, so `secure --fix <dir>` and `check express` never get a
 * second target grafted on.
 */
function completeTargetlessCitations(text: string, prefix: string): string {
  if (!citationTarget) return text;

  const re = new RegExp(
    `((?:npx ${OPENA2A_PACKAGE}|${escapeRegExp(prefix)})\\s+(?:${TARGET_VERB_ALT})(?![\\w-]))([^\\n\`]*)`,
    'g',
  );

  return text.replace(re, (whole, head: string, tail: string) => {
    // Trim the tail at the command/prose boundary so an explanation is never
    // parsed as arguments.
    const cut = tail.search(COMMAND_TAIL_END);
    const cmdTail = cut === -1 ? tail : tail.slice(0, cut);
    const rest = cut === -1 ? '' : tail.slice(cut);

    const tokens = cmdTail.split(/\s+/).filter(Boolean);

    // A lone `.` is the wrong target spelled explicitly — replace it.
    const dotIndex = tokens.indexOf('.');
    if (dotIndex !== -1) {
      tokens[dotIndex] = citationTarget!;
      return head + ' ' + tokens.join(' ') + rest;
    }

    // Any other non-flag token means the citation already names something.
    if (tokens.some((t) => !t.startsWith('-'))) return whole;

    // Targetless: insert ahead of any flags so the command reads naturally.
    return head + ' ' + [citationTarget!, ...tokens].join(' ') + rest;
  });
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Rewrite command citations in a string so they are runnable for the reader.
 *
 * Two independent passes:
 *
 *  1. `hackmyagent <verb>` → the active `CLI_PREFIX`, so a bundled run cites
 *     the parent's verb namespace. No-op standalone.
 *  2. `opena2a <verb>` → `npx opena2a-cli <verb>`, but ONLY standalone, where
 *     `opena2a` is not on PATH. Bundled runs leave the citation alone because
 *     the binary is present and the shorter form is correct.
 *
 * Pass 2 closes #201: ~29 finding-fix and explainer strings cite
 * `opena2a protect .`, and a user who installed hackmyagent on its own got
 * `command not found` — a dead end under CISO Rule 11. Fixing it here rather
 * than at the 29 call sites keeps the citation policy in one place, and
 * matches how pass 1 already works.
 *
 * Human-readable text only — never call this on JSON / SARIF output.
 */
export function rebrandCommandCitations(text: string): string {
  if (!text) return text;
  let out = text;
  if (CLI_PREFIX !== 'hackmyagent') {
    // Replacer FUNCTION, not an interpolated string (#600): CLI_PREFIX is
    // environment-derived (HMA_CLI_PREFIX), and a `$&` / `$1` / `` $` `` / `$'`
    // inside a String.replace replacement STRING is a pattern, not text — so a
    // prefix carrying one rewrote the citation instead of prefixing it. A
    // function return is inserted literally; `verb` is the one capture group.
    out = out.replace(CITATION_RE, (_m, verb: string) => `${CLI_PREFIX} ${verb}`);
  }
  if (!opena2aIsOnPath()) {
    out = out.replace(OPENA2A_CITATION_RE, (_m, verb: string) => `npx ${OPENA2A_PACKAGE} ${verb}`);
  }
  // Pass 3 runs LAST, on purpose: passes 1 and 2 have already normalised the
  // tool name, so this only has to recognise `${CLI_PREFIX}` and
  // `npx opena2a-cli` rather than every spelling the call sites use.
  out = completeTargetlessCitations(out, CLI_PREFIX);
  return out;
}

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

/**
 * Resolve the binary-level command prefix.
 *   1. Explicit `HMA_CLI_PREFIX` (a parent CLI overriding the citation namespace).
 *   2. argv0-derived: `opena2a`/`opena2a-*` → `opena2a scan`.
 *   3. Default: `hackmyagent`.
 */
export function resolveCliPrefix(): string {
  if (process.env.HMA_CLI_PREFIX) return process.env.HMA_CLI_PREFIX;
  const argv1 = process.argv[1] || '';
  const basename = require('path').basename(argv1).replace(/\.[jt]s$/, '');
  if (basename === 'opena2a' || basename.startsWith('opena2a-')) {
    return 'opena2a scan';
  }
  return 'hackmyagent';
}

export const CLI_PREFIX = resolveCliPrefix();

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
    out = out.replace(CITATION_RE, `${CLI_PREFIX} $1`);
  }
  if (!opena2aIsOnPath()) {
    out = out.replace(OPENA2A_CITATION_RE, `npx ${OPENA2A_PACKAGE} $1`);
  }
  return out;
}

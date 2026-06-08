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
 * Rewrite `hackmyagent <verb>` command citations in a string to the active
 * `CLI_PREFIX`. No-op when the prefix is the default `hackmyagent`. Intended for
 * human-readable text only — never call it on JSON / SARIF output.
 */
export function rebrandCommandCitations(text: string): string {
  if (!text || CLI_PREFIX === 'hackmyagent') return text;
  return text.replace(CITATION_RE, `${CLI_PREFIX} $1`);
}

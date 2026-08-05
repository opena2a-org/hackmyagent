/**
 * One vocabulary for "this permission entry is unbounded", shared by the two
 * analyzers that ask the question (#363, #364).
 *
 * `detect` (`src/scanner/permission-grant.ts`) and `secure`'s `CLAUDE-002`
 * (`src/hardening/scanner.ts`) both decide whether an AI config hands out broad
 * authority, on the same `.claude/settings.json`, and they used to disagree in
 * direction on it: `detect` matched text and `CLAUDE-002` tested
 * `perm.includes('(*)')`, so a file whose only content was `Bash(*:*)` produced
 * a HIGH from one command and `no security issues found` from the other. Both
 * now call in here, so the next spelling is added once.
 *
 * ## Why this reads KEYS and not text
 *
 * `allow` and `deny` values are textually IDENTICAL — only the key tells them
 * apart — and a deny list is *supposed* to be full of wildcards. Measured
 * across 36 real `.claude/settings*.json`: 389 deny entries contain `*`. So a
 * text rule pointed at permission entries is pointed at the deny list, and the
 * remediation it prints ("replace `Read(*.key)` with the specific paths this
 * agent needs") tells the reader to delete the rule that stops an agent reading
 * private keys. That is not a hypothetical: on `56263f9` the shipped rule
 * already reported HIGH on `{"permissions":{"deny":["Read(*.key)","Bash(*)"]}}`.
 *
 * `walkConfigForGrants` therefore keeps deny entries out with two layers, and
 * it is worth being precise about which one carries the weight:
 *
 * 1. **The grant-key allowlist does the everyday work.** Entries are evaluated
 *    only under a key that is known to grant, so `deny: ["Bash(*)"]` is a list
 *    of strings under a key nothing reads. This is also why an unrecognised key
 *    holding `Bash(*)` stays silent — a deliberate trade, see below.
 * 2. **The prune covers nesting.** It is what stops a grant key that sits
 *    UNDERNEATH a deny key from being read, which is the one shape that can
 *    reach past layer 1.
 *
 * Deny is never weighed, not even to soften a finding — a deny list the scanned
 * file controls would be an off switch the attacker writes, which is the shape
 * #305/#309 already rejected.
 *
 * Parsing also closes an escape class no text rule reaches: `"Bash(*)"` is
 * valid JSON containing no `*`, and parses to `Bash(*)`.
 *
 * ## Why the bound is tool-specific
 *
 * A wildcard is only interesting when nothing bounds it, and what counts as a
 * bound depends on the tool:
 *
 * - `Read(src/**)` — the path prefix `src/` is the bound.
 * - `Bash(git commit:*)` — the COMMAND NAME is the bound, in exactly the same
 *   way. 31 of the 148 real allow entries measured are this shape, and Claude
 *   Code writes them itself; flagging them re-opens #299.
 * - `WebFetch(domain:*)` — genuinely unbounded. A scheme name bounds nothing.
 *
 * So the colon cannot be read tool-agnostically, and neither can a bare tool
 * name: `Read` has a scoped form so bare `Read` is the broadest grant of it,
 * while `WebSearch` has none, so flagging bare `WebSearch` would emit a finding
 * whose remediation does not exist.
 */

import { escapeForDisplay } from '../ui/display-safe';

/** An entry or setting that hands out authority nothing bounds. */
export interface UnboundedGrant {
  /**
   * The entry or `key: value`, exactly as the parsed document carried it.
   *
   * RAW, deliberately: the caller locates this string back in the file to cite
   * a line, which an escaped copy would not match. Anything that RENDERS it
   * must escape it — `detect` does that through `quoted()`.
   */
  entry: string;
  /**
   * Why it is unbounded, as one clause the report can quote.
   *
   * Already display-escaped, because it interpolates text out of the scanned
   * file and is printed verbatim by every renderer. A scanned config is
   * untrusted input, and a permission entry carrying a terminal control
   * sequence would otherwise rewrite the line the reader is looking at.
   */
  reason: string;
  /**
   * What to do about it, as an imperative naming a concrete replacement.
   *
   * Carried per-grant rather than written once at the call site because the
   * generic advice is wrong for half of these: "replace it with the specific
   * commands or paths this agent needs" is a dead end when the finding is
   * `defaultMode: acceptEdits`, which takes neither a command nor a path.
   *
   * Display-escaped for the same reason as `reason`.
   */
  fix: string;
  /**
   * The document key the entry was found under (`allow`, `defaultMode`, …).
   * Used to locate a line when the entry itself cannot be found in the raw
   * text — a JSON unicode escape parses to a value the file does not contain.
   */
  key: string;
}

/**
 * Tools whose permission entries take a scope specifier.
 *
 * Membership means two things at once: the bare spelling is an unbounded grant
 * of that tool, and `replace "Read" with "Read(src/**)"` is a remediation that
 * exists. `WebSearch`, `Task` and friends are deliberately absent — they have
 * no scoped form, so bare is their only spelling and a finding on it would be a
 * dead end.
 */
const PATH_TOOLS = new Set([
  'read', 'write', 'edit', 'multiedit', 'notebookedit', 'notebookread', 'glob', 'grep', 'ls',
]);

/** Tools whose specifier is a command line, bounded by the command name. */
const COMMAND_TOOLS = new Set(['bash', 'shell', 'execute', 'run', 'terminal']);

/** Tools whose specifier is `scheme:value`, where the scheme bounds nothing. */
const DOMAIN_TOOLS = new Set(['webfetch', 'fetch', 'url']);

/**
 * Commands whose own name is NOT a bound, because their argument is another
 * command. `Bash(sudo *)` reads as "sudo, bounded" only if you stop at the
 * first token; what it actually grants is every command, as root.
 */
const DELEGATING_COMMANDS = new Set([
  'sudo', 'doas', 'su', 'sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'csh',
  'env', 'eval', 'exec', 'command', 'xargs', 'nohup', 'setsid', 'nice', 'time', 'watch',
]);

/** Path prefixes that bound nothing — the filesystem root, or no prefix at all. */
const ROOT_PREFIXES = new Set(['', '/', '//', '\\', '~', '~/', '.', './', '..', '../']);

/**
 * Wildcard characters that end a PATH glob's literal prefix.
 *
 * Path-only, deliberately. In a command line these characters are ordinary
 * text: `{}` is xargs' placeholder, `[` opens a test expression, `?` is a
 * literal argument character. A real allow entry —
 * `Bash(xargs -I {} sh -c 'echo "=== {} ===" && cat {}')`, read out of a
 * `.claude/settings.local.json` on disk — is a complete literal command with no
 * wildcard in it, and treating its `{}` as one flagged it as a broad grant.
 * That is #299's false positive, so commands and schemes ask `WILDCARD` instead.
 */
const GLOB_META = /[*?[\]{}]/;

/** The only character that widens a command, scheme or MCP specifier. */
const WILDCARD = /\*/;

/** `Tool(specifier)`, tolerating whitespace the schema does not require. */
const ENTRY_SHAPE = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(([\s\S]*)\)\s*$/;

/** A bare tool name with no specifier at all. */
const BARE_TOOL = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*$/;

/**
 * Is `spec` a path glob that no prefix bounds?
 *
 * The bound is the literal text before the first wildcard. `src/**` is bounded
 * by `src/`; `**`, `/**`, `//**` and `~/**` are bounded by nothing, which is
 * what makes `Read(//**)` a grant and `Read(src/**)` a restriction.
 */
function isUnboundedPath(spec: string): boolean {
  const trimmed = spec.trim();
  if (trimmed === '') return true;
  const meta = trimmed.search(GLOB_META);
  const prefix = meta === -1 ? trimmed : trimmed.slice(0, meta);
  if (meta === -1) return ROOT_PREFIXES.has(prefix);
  // A prefix of only slashes or `~` is the root, however many slashes it has.
  if (/^[/\\]*$/.test(prefix) || /^~[/\\]*$/.test(prefix)) return true;
  return ROOT_PREFIXES.has(prefix);
}

// A replacement for an unbounded path spec that is NARROWER than what it
// replaces.
//
// Written as line comments because the globs it has to name contain `**/`,
// which would close a block comment.
//
// This exists because of the wrong fix for a real complaint. `Edit(**/*.md)`
// reaches every directory, so it IS unbounded by prefix and the finding is
// correct — but the generic advice printed against it was `Edit(src/**)`,
// which grants every file type under `src/` and is WIDER than the entry being
// flagged. The first attempt at that complaint declared any literal file
// extension a bound and returned `false` from `isUnboundedPath`, which
// silenced `Read(**/*.key)`, `Read(**/.env)` and `Write(**/*.env)` in an ALLOW
// list — deferring them to "the check that owns sensitivity", which the
// reviewer then proved does not exist anywhere in `secure`. Nothing reported
// them at all.
//
// So the classification stands and the SUGGESTION is what changes: keep the
// author's own glob and put a directory in front of it. `**/*.md` becomes
// `src/**/*.md`, a strict subset of what it replaces, for every spec this is
// reached with.
function narrowedPath(spec: string): string {
  const rest = spec.trim().replace(/^[~.]*[/\\]+/, '');
  return rest === '' || /^[.~]+$/.test(rest) ? 'src/**' : `src/${rest}`;
}

/**
 * Is `spec` a command line that no command name bounds?
 *
 * `git commit:*` and `npm run *` are bounded by `git` / `npm`. `*` and `*:*`
 * put the wildcard in the command-name position, so nothing is bounded, and a
 * delegating command bounds nothing either.
 */
function isUnboundedCommand(spec: string): boolean {
  const trimmed = spec.trim();
  if (trimmed === '') return true;
  // The command name is everything up to the first space or `:` separator.
  const name = trimmed.split(/[\s:]/, 1)[0];
  if (name === '' || WILDCARD.test(name)) return true;
  if (DELEGATING_COMMANDS.has(name.toLowerCase())) {
    // The delegated command is the real bound, so look at ITS name rather than
    // at the whole remainder. `sudo *` and `sh -c *` delegate to a wildcard and
    // are unbounded; `sudo apt install foo` and `xargs dirname *` — a real
    // entry — delegate to `apt` and `dirname`, which bound them exactly as any
    // other command name does.
    //
    // Flags are skipped, their VALUES are not, because arity is not knowable
    // from the outside: `sudo -u root *` reads as bounded by `root` and is a
    // known miss, recorded in the council ledger's pre-mortem. A miss is the
    // side to err on here — false positives are what have blocked releases.
    const delegated = trimmed
      .slice(name.length)
      .split(/[\s:]+/)
      .filter((t) => t !== '' && !t.startsWith('-'))[0];
    // No delegated command at all means the delegator runs alone — `Bash(env)`
    // is the single command `env`, not a grant of everything. Real entry.
    return delegated !== undefined && WILDCARD.test(delegated);
  }
  return false;
}

/**
 * Is `spec` a `scheme:value` specifier whose value is a wildcard?
 *
 * `domain:example.com` is bounded by the domain. `domain:*` is the documented
 * spelling for "any host", and the scheme name bounds nothing.
 */
function isUnboundedScheme(spec: string): boolean {
  const trimmed = spec.trim();
  if (trimmed === '') return true;
  const colon = trimmed.indexOf(':');
  const value = colon === -1 ? trimmed : trimmed.slice(colon + 1);
  const v = value.trim();
  return v === '' || WILDCARD.test(v);
}

/**
 * Classify ONE permission entry, already parsed out of a grant key.
 *
 * The caller must have established that this entry sits under a key that grants
 * — this function has no way to tell an allow entry from a deny entry, which is
 * the entire lesson of #364.
 */
export function classifyPermissionEntry(
  entry: string,
  key = 'allow',
  bareToolCounts = true,
): UnboundedGrant | undefined {
  const raw = entry.trim();
  if (raw === '') return undefined;

  const grant = (reason: string, fix: string): UnboundedGrant => makeGrant(entry, reason, fix, key);
  /** A worked replacement for a tool, so the fix is never "be more specific". */
  const example = (tool: string): string => {
    const t = tool.toLowerCase();
    if (COMMAND_TOOLS.has(t)) return `${tool}(npm test)`;
    if (DOMAIN_TOOLS.has(t)) return `${tool}(domain:example.com)`;
    return `${tool}(src/**)`;
  };

  // The broadest spelling there is: every tool, every argument.
  if (/^[*]+$/.test(raw)) {
    return grant(
      'grants every tool without restriction',
      `replace "${raw}" with one entry per tool the agent needs, each scoped (e.g. "Bash(npm test)", "Read(src/**)")`,
    );
  }

  // `mcp__*` is every server; `mcp__github__*` is every tool of one server,
  // which the server name bounds.
  if (raw.toLowerCase().startsWith('mcp__')) {
    const server = raw.slice('mcp__'.length).split('__', 1)[0];
    return WILDCARD.test(server) || server === ''
      ? grant(
        'grants every MCP server and every tool on it',
        `replace "${raw}" with the specific "mcp__<server>__<tool>" entries this agent calls`,
      )
      : undefined;
  }

  const bare = BARE_TOOL.exec(raw);
  if (bare) {
    const tool = bare[1].toLowerCase();
    const scoped = bareToolCounts
      && (PATH_TOOLS.has(tool) || COMMAND_TOOLS.has(tool) || DOMAIN_TOOLS.has(tool));
    return scoped
      ? grant(
        `grants every use of ${bare[1]}, with no scope at all`,
        `replace "${bare[1]}" with a scoped entry such as "${example(bare[1])}"`,
      )
      : undefined;
  }

  const m = ENTRY_SHAPE.exec(raw);
  if (!m) return undefined; // not permission syntax; the caller decides what that means
  const tool = m[1].toLowerCase();
  const spec = m[2];
  const narrow = `replace "${raw}" with "${example(m[1])}" or another entry the prefix bounds`;

  if (PATH_TOOLS.has(tool)) {
    // The author's own glob with a directory in front of it, never the generic
    // `Tool(src/**)` — see `narrowedPath`. A remediation wider than the entry
    // it replaces is worse than none.
    return isUnboundedPath(spec)
      ? grant(
        `grants ${m[1]} over paths no prefix bounds`,
        `replace "${raw}" with "${m[1]}(${narrowedPath(spec)})" or another entry a directory prefix bounds`,
      )
      : undefined;
  }
  if (COMMAND_TOOLS.has(tool)) {
    return isUnboundedCommand(spec)
      ? grant(`grants ${m[1]} with no command-name bound`, narrow)
      : undefined;
  }
  if (DOMAIN_TOOLS.has(tool)) {
    return isUnboundedScheme(spec)
      ? grant(`grants ${m[1]} against any host`, narrow)
      : undefined;
  }
  // An unrecognised tool: only the wholly unbounded spellings count. Guessing
  // at a tool whose grammar we do not know is how false positives get shipped.
  const s = spec.trim();
  return s === '' || /^[*](?::[*])?$/.test(s)
    ? grant(`grants ${m[1]} with no scope`, narrow)
    : undefined;
}

/**
 * Whether a permission entry is even valid permission syntax.
 *
 * An allow list carrying `"Bash - Allow all bash commands without approval"`
 * (a real entry, in a real `~/.claude/settings.json`) grants nothing, because
 * no tool has that name — but it is still the author stating what they meant to
 * permit, under a key that proves it is not a deny. The prose path handles
 * those; this is how it knows which ones to take.
 */
export function isPermissionSyntax(entry: string): boolean {
  const raw = entry.trim();
  return raw === '*' || BARE_TOOL.test(raw) || ENTRY_SHAPE.test(raw) || raw.toLowerCase().startsWith('mcp__');
}

// ---------------------------------------------------------------------------
// Key-aware document walk
// ---------------------------------------------------------------------------

/**
 * Build a grant with its report strings already display-escaped.
 *
 * Every `reason` and `fix` here interpolates a key or value out of the scanned
 * config, and all three renderers print both verbatim. `entry` stays raw
 * because the caller locates it back in the file to cite a line.
 */
export function makeGrant(entry: string, reason: string, fix: string, key: string): UnboundedGrant {
  return { entry, reason: forGrantText(reason), fix: forGrantText(fix), key };
}

/**
 * Redact, then escape, for every value quoted out of a scanned config.
 *
 * Escaping alone was not enough and the gap was visible in the output: the
 * report printed the redacted copy and the raw one in the same sentence —
 * `"allow AKIA[redacted] any" states a grant ("allow AKIA<the rest of it>
 * any")` — because `reason` and `fix` interpolate scanned text and only the
 * outer fields were redacted. That is #365's harm, "stop the scanner copying
 * credentials into its own reports", reappearing one field over.
 *
 * Order is redact-then-escape, matching `forReport`: escaping first would let
 * an escape expansion break up a credential run and leave it unredacted.
 */
function forGrantText(s: string): string {
  return escapeForDisplay(redactLikelySecrets(s));
}

/**
 * Mask credential-shaped runs before a scanned value is quoted into a report.
 *
 * Lives here rather than in `permission-grant.ts` because BOTH modules quote
 * scanned text: the grant's own `reason` and `fix` are built here, and
 * `permission-grant.ts` re-exports this for the fields it builds. A permission
 * entry can carry a secret — `Bash(curl -H "Authorization: Bearer sk-…" *)` is
 * a legal allow entry — so every field that quotes one passes through here.
 *
 * Deliberately local and small. It is a guard on quoted output, not a
 * credential scanner — `src/hardening/scanner.ts` owns that job, and reaching
 * into it (or into the NanoMind redactor) to reuse a regex would couple this
 * report to a detector that answers a different question.
 */
export function redactLikelySecrets(s: string): string {
  return s
    .replace(
      // The separator is `\s*` `[:=]` `\s*` `["']?` and nothing else, because
      // every optional atom added between the two `\s*` runs makes this pair
      // AMBIGUOUS and the match quadratic. A `(?:bearer|basic|token)?` group
      // was added here to reach `Authorization: Bearer <opaque>`, and it took
      // `detect` from 0.25s to 51s on a 200KB config — a larger denial of
      // service than the one the same commit removed, and reachable through
      // `secure`, which has no size cap in front of this at all.
      //
      // So the scheme word is deliberately NOT stepped over. An opaque bearer
      // token — no `sk-` prefix, no JWT dots — is a KNOWN GAP, filed rather
      // than closed here; a JWT is caught below by its own shape.
      // `__tests__/scanner/permission-grant.test.ts` gates every regex in this
      // module and in `permission-grant.ts` against the ambiguous pair.
      /\b(api[_-]?key|apikey|secret|token|password|passwd|pwd|authorization)(\s*[:=]\s*["']?)([A-Za-z0-9_\-.+/]{12,})/gi,
      (_all, key: string, sep: string) => `${key}${sep}[redacted]`,
    )
    .replace(/\b(sk-|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|xox[baprs]-|AKIA)[A-Za-z0-9_\-]{8,}/g, '$1[redacted]')
    // A JWT is self-identifying: three base64url runs separated by dots, with a
    // header that always begins `eyJ`. No key name is needed to recognise one.
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/g, '[redacted-jwt]');
}

/** Normalise a key for comparison: case and separators vary across schemas. */
function normKey(k: string): string {
  return k.toLowerCase().replace(/[_-]/g, '');
}

/**
 * Keys whose subtree is NEVER evaluated.
 *
 * `deny` and its synonyms are restrictions, and `ask` is a prompt — neither is
 * a grant, and a wildcard inside one is the point of it. Pruned rather than
 * negated: there is nothing here to weigh.
 *
 * This is the second of the two layers described in the module header, and its
 * job is nesting specifically: a plain `deny: ["Bash(*)"]` is already quiet
 * without it, because no grant key names that list. What it stops is
 * `deny: { allow: [...] }`. `__tests__/scanner/permission-vocabulary.test.ts`
 * pins that shape, so this list is not dead code.
 */
const PRUNED_KEYS = new Set([
  'deny', 'denied', 'denylist', 'disallow', 'disallowed', 'disallowedtools',
  'block', 'blocked', 'blocklist', 'blockedtools',
  'forbid', 'forbidden', 'never', 'exclude', 'excluded', 'ignore', 'ignored',
  'reject', 'rejected', 'ask',
].map(normKey));

/**
 * Grant keys whose entries are Claude-Code PERMISSION syntax, where a bare tool
 * name is the unscoped spelling of that tool.
 *
 * `autoApprove` and `alwaysAllow` are deliberately NOT here. Their entries are
 * MCP TOOL NAMES, and the official MCP fetch server's tool is literally called
 * `fetch` — reading that as bare `WebFetch` produced a HIGH whose remediation,
 * `fetch(domain:example.com)`, is not valid in any MCP schema. A finding whose
 * fix does not exist is a dead end.
 *
 * `allowedTools`, `allowlist` and `allowedCommands` ARE here, and excluding
 * them with the MCP pair was the same mistake in the other direction:
 * `allowedTools` is Claude Code's own key and takes `Bash`, `Read`, so
 * `{"allowedTools":["Bash","Read","Write"]}` — three unscoped grants — went
 * silent.
 */
const PERMISSION_SYNTAX_KEYS = new Set([
  'allow', 'allowed', 'allowedtools', 'allowedcommands', 'allowlist', 'permissions',
].map(normKey));

/**
 * Keys whose value is a list (or one) of permission entries.
 *
 * `tools` is deliberately absent. A `tools` array is a manifest at least as
 * often as it is a grant, and reading a manifest as a grant is how a scanner
 * starts reporting findings on ordinary configuration.
 */
const GRANT_LIST_KEYS = new Set([
  'allow', 'allowed', 'allowedtools', 'allowedcommands', 'allowedhosts',
  'allowlist', 'autoapprove', 'alwaysallow', 'permissions',
].map(normKey));

/**
 * Keys that grant wholesale when they are boolean `true`, and what each one
 * actually does.
 *
 * Per-key rather than one shared sentence, because the shared sentence was
 * false for at least one of them: `enableAllProjectMcpServers` approves the
 * project's MCP SERVERS without the trust prompt — tool calls from them still
 * go through `permissions`. Saying it "runs every tool call without a
 * permission prompt" overstates what the setting does, and a security finding
 * that overstates is one a reader learns to discount.
 */
const BOOLEAN_GRANT_KEYS = new Map<string, string>([
  ['dangerouslyskippermissions', 'runs every tool call without a permission prompt'],
  ['bypasspermissions', 'runs every tool call without a permission prompt'],
  ['skippermissions', 'runs every tool call without a permission prompt'],
  ['disablepermissions', 'runs every tool call without a permission prompt'],
  ['yolo', 'runs every tool call without a permission prompt'],
  ['autoapprove', 'approves every request without asking'],
  ['autoapproveall', 'approves every request without asking'],
  ['alwaysallow', 'approves every request without asking'],
  ['enableallprojectmcpservers', 'trusts every MCP server the project declares, with no prompt'],
].map(([k, v]) => [normKey(k), v] as [string, string]));

/** `defaultMode` values that turn the permission prompt off. */
const PERMISSIVE_MODES = new Map<string, string>([
  ['bypasspermissions', 'turns the permission prompt off entirely'],
  ['acceptedits', 'accepts file edits without asking'],
  ['dontask', 'accepts every tool call without asking'],
  ['auto', 'accepts every tool call without asking'],
]);

/**
 * Keys whose string values are a command line or its argument vector.
 *
 * These are read for one thing only — a wholesale-bypass FLAG — and never as
 * permission entries. That distinction is the point: `hooks[].command` holds a
 * shell command, not a `Tool(spec)` entry, so classifying it as a permission
 * would be reading a manifest as a grant.
 *
 * Why it exists at all: `--dangerously-skip-permissions` is the broadest
 * documented grant in the ecosystem, and moving structured config off the text
 * path silently dropped it. Base `50b2b18` matched the flag anywhere in the
 * file and so caught all three real shapes — `hooks[].command`,
 * `mcpServers.*.args`, and `.aider.conf.yml` `extra-args` — while the parsed
 * path reached none of them, because no GRANT key names a command. The flag
 * stays in `PROSE_GRANT_PATTERNS` for schemaless files; this is its structured
 * half.
 */
const COMMAND_VALUE_KEYS = new Set([
  'command', 'cmd', 'args', 'argv', 'arguments', 'extraargs', 'flags', 'run',
].map(normKey));

/**
 * Flags that turn the permission system off wholesale, whatever carries them.
 *
 * A token match, not a substring one, so `--dangerously-skip-permissions-off`
 * is not read as the flag it is not.
 */
const DANGEROUS_FLAGS = new Set(['--dangerously-skip-permissions']);

/** The bypass flag `s` passes as an argv token, in its CANONICAL spelling. */
function dangerousFlag(s: string): string | undefined {
  for (const token of s.split(/[\s=]+/)) {
    const canonical = token.toLowerCase();
    // The canonical spelling is returned rather than the token, so a scanned
    // file cannot choose the casing of the text this puts in a report.
    if (DANGEROUS_FLAGS.has(canonical)) return canonical;
  }
  return undefined;
}

/** Keys whose entries are directories added to the agent's reachable scope. */
const DIRECTORY_KEYS = new Set(['additionaldirectories', 'additionaldirs', 'workspacefolders'].map(normKey));

/** Values that mean "everything" wherever a grant key takes a string. */
const WHOLESALE_VALUES = new Set(['*', 'all', 'any', 'everything', 'unrestricted', 'full']);

/**
 * The first unbounded grant in a parsed config document, or undefined.
 *
 * Recursive, and deliberately an ALLOWLIST of grant keys rather than a
 * denylist of deny keys: a key this does not recognise stays silent even if its
 * value is `Bash(*)`. That trades a miss for a false positive on purpose —
 * three releases have been blocked by this module's false positives and none by
 * its misses — and a new schema key is a review trigger, recorded in the
 * council ledger, rather than a silent failure.
 *
 * `onProseEntry` receives allow-list entries that are not permission syntax, so
 * the caller can decide whether the author's prose states a grant.
 */
export function walkConfigForGrants(
  doc: unknown,
  onProseEntry?: (entry: string, key: string) => UnboundedGrant | undefined,
  depth = 0,
  seen: Set<object> = new Set(),
): UnboundedGrant | undefined {
  if (depth > 12 || doc === null || typeof doc !== 'object') return undefined;
  // YAML aliases resolve to SHARED references, not copies, so a 471-byte file
  // can describe an object graph with millions of paths through it — measured
  // at 28 seconds for a nine-deep alias chain, against a 1MB file cap that
  // cannot see it. The depth bound alone does not help: it bounds depth, and
  // this is breadth. Re-visiting a node cannot change the answer, so skipping
  // it collapses the walk back to linear in the number of distinct nodes.
  if (seen.has(doc)) return undefined;
  seen.add(doc);

  if (Array.isArray(doc)) {
    for (const item of doc) {
      const found = walkConfigForGrants(item, onProseEntry, depth + 1, seen);
      if (found) return found;
    }
    return undefined;
  }

  for (const [rawKey, value] of Object.entries(doc as Record<string, unknown>)) {
    const key = normKey(rawKey);
    if (PRUNED_KEYS.has(key)) continue; // never evaluated, for any purpose

    const booleanReason = BOOLEAN_GRANT_KEYS.get(key);
    if (booleanReason && value === true) {
      return makeGrant(`${rawKey}: true`, booleanReason, `set "${rawKey}" to false in this file, or remove the key`, rawKey);
    }

    if (key === normKey('defaultMode') && typeof value === 'string') {
      const reason = PERMISSIVE_MODES.get(normKey(value));
      if (reason) {
        return makeGrant(`${rawKey}: ${value}`, reason, `set "${rawKey}" to "default" so each tool call is asked for`, rawKey);
      }
    }

    if (COMMAND_VALUE_KEYS.has(key)) {
      for (const arg of asStringList(value)) {
        const flag = dangerousFlag(arg);
        if (flag) {
          return makeGrant(
            arg,
            'runs every tool call without a permission prompt',
            `remove "${flag}" from "${rawKey}" in this file`,
            rawKey,
          );
        }
      }
      // No `continue`: a command key can hold nested structure too, and the
      // walk below is what reaches it.
    }

    if (DIRECTORY_KEYS.has(key)) {
      for (const dir of asStringList(value)) {
        if (isUnboundedPath(dir)) {
          return makeGrant(dir, 'adds a directory no prefix bounds to the agent scope', `replace "${dir}" with the project directory this agent works in`, rawKey);
        }
      }
      continue;
    }

    if (GRANT_LIST_KEYS.has(key)) {
      const entries = asStringList(value);
      for (const entry of entries) {
        if (WHOLESALE_VALUES.has(entry.trim().toLowerCase())) {
          return makeGrant(entry, 'grants every tool without restriction', `replace "${entry}" with one scoped entry per tool the agent needs (e.g. "Bash(npm test)", "Read(src/**)")`, rawKey);
        }
        const found = isPermissionSyntax(entry)
          ? classifyPermissionEntry(entry, rawKey, PERMISSION_SYNTAX_KEYS.has(key))
          : onProseEntry?.(entry, rawKey);
        if (found) return found;
      }
      // `permissions` is also the object that HOLDS allow/deny, so keep walking.
    }

    const found = walkConfigForGrants(value, onProseEntry, depth + 1, seen);
    if (found) return found;
  }
  return undefined;
}

/**
 * The 1-indexed line carrying `grant` in `lines`, or 0 when it cannot be found.
 *
 * Shared by both analyzers, because both must cite `file:line` and both hit the
 * same two awkward cases. The parser discards positions, so the entry is located
 * back in the raw text — but a settings-level grant is synthesised
 * (`defaultMode: acceptEdits` is not a substring of `"defaultMode": "acceptEdits"`),
 * and a JSON unicode escape parses to a value the file does not contain at all.
 * Both fall back to the KEY's line, which is a true citation rather than an
 * invented one. `CLAUDE-002` rendered a HIGH with no line number before this
 * was shared.
 */
export function locateGrantLine(lines: readonly string[], grant: UnboundedGrant): number {
  const enclosing = enclosingKeys(lines);
  const ownKey = normKey(grant.key);
  const needles = [grant.entry, JSON.stringify(grant.entry).slice(1, -1)].filter(Boolean);

  const openLine = (i: number): boolean => !enclosing[i].some((k) => PRUNED_KEYS.has(k));

  const find = (needle: string, requireOwnKey: boolean): number => {
    for (let i = 0; i < lines.length; i++) {
      if (requireOwnKey && !enclosing[i].includes(ownKey)) continue;
      if (!openLine(i)) continue;
      const line = lines[i];
      if (!line.includes(needle)) continue;
      // Every occurrence on the line, against that line's key tokens —
      // computed once and consumed by a moving pointer, so a hostile line
      // carrying many occurrences stays linear rather than quadratic.
      const tokens = keyTokens(line);
      let t = 0;
      for (let at = line.indexOf(needle); at !== -1; at = line.indexOf(needle, at + 1)) {
        while (t < tokens.length && tokens[t].at < at) t++;
        if (!isPruned(t > 0 ? tokens[t - 1].key : undefined)) return i + 1;
      }
    }
    return 0;
  };

  // The entry, on a line the grant's OWN key encloses. This is the ordinary
  // case and it is exact.
  for (const needle of needles) {
    const found = find(needle, true);
    if (found) return found;
  }
  // The entry anywhere no restriction key covers. Reached when the key is
  // spelled in a way the raw text does not carry — a JSON-escaped `allow`
  // parses to `allow` and appears as `\u0061llow` — where the enclosure test is
  // still what decides, so an identical entry sitting in a `deny` list cannot
  // win the search.
  for (const needle of needles) {
    const found = find(needle, false);
    if (found) return found;
  }
  // A synthesised entry (`defaultMode: acceptEdits`) never appears literally.
  // The key's own line is a true citation for it.
  for (let i = 0; i < lines.length; i++) {
    if (openLine(i) && declaredKey(lines[i]) === ownKey) return i + 1;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Where a citation is allowed to land
// ---------------------------------------------------------------------------
//
// The classifier refuses to READ a deny list. The citation has to refuse to
// POINT at one, and that is a separate problem with a separate failure:
//
//     "deny":  ["Read(**/*.key)"],
//     "allow": ["Read(**/*.key)"]
//
// Both keys hold the identical string, so a text search for the offending
// entry returns whichever comes first — and the finding then prints
// `replace "Read(**/*.key)"` against the rule that stops the agent reading
// private keys, one line under guidance promising deny entries are never
// reported. The harm arrives through the evidence rather than through the
// classification.
//
// Anchoring the search at the grant key's first line does not close it. Three
// constructions walk past that anchor: a JSON-escaped `allow` key, which no
// text pattern matches; a `// allow:` comment sitting above the deny list; and
// an earlier BOUNDED `allow` whose line the anchor finds instead. Each leaves
// the search starting before a deny list that holds the same string.
//
// So the anchor is replaced by a rule about the DESTINATION, which does not
// care how the search got there: a citation may never land inside a subtree
// `PRUNED_KEYS` covers. Two things establish that, one per axis —
//
//   * `enclosingKeys` — which keys enclose each LINE, from indentation and
//     bracket closers, so a multi-line `deny` block covers its entries;
//   * `keyGoverning` — the nearest key named to the LEFT of the match within
//     its own line, so `{"deny":["Bash(*)"],"allow":["Bash(*)"]}` on one line
//     still separates into two halves.
//
// Both decode escapes with `JSON.parse` rather than reading the raw spelling,
// because `"\u0064eny"` is the key `deny` to every consumer that matters and a
// scanned file chooses its own spelling.
//
// This is a guard, not a parser: it can reject a candidate line, never invent
// one, and when it rejects every candidate the caller falls back to line 1
// rather than to a wrong line. Two residuals are known and recorded rather
// than papered over: a config minified onto a single line has one citable
// line and gets it, and a `deny` key written inside a quoted VALUE is read as
// a real key, which costs precision in the safe direction.

/**
 * The three spellings a key can take, as ONE fragment.
 *
 * Shared between the two patterns below so their capture groups cannot drift
 * apart — and they did: `KEY_DECL` was written with a leading `(\s*)` capture,
 * which pushed its key groups to 2/3/4 while `KEY_TOKEN`'s stayed at 1/2/3.
 * One reader served both, so every in-line key resolved to the empty string
 * and `{"deny":[…],"allow":[…]}` on a single line stopped separating.
 */
const KEY_SPELLINGS = String.raw`(?:"((?:\\.|[^"\\])*)"|'([^']*)'|([A-Za-z_$][A-Za-z0-9_$.-]*))\s*:`;

/** A key DECLARED at the head of a line — the only thing that opens a block. */
const KEY_DECL = new RegExp(`^\\s*(?:-\\s+)?${KEY_SPELLINGS}`);

/** Every `key:` token in a line, wherever it sits. */
const KEY_TOKEN = new RegExp(KEY_SPELLINGS, 'g');

/** A line that opens nothing and closes nothing: blank, or only a comment. */
const INERT_LINE = /^\s*(?:$|\/\/|\/\*|\*|#)/;

/** A line whose first character closes a JSON container. */
const CLOSER_LINE = /^\s*[\]}]/;

/**
 * The key a `KEY_DECL`/`KEY_TOKEN` match names, normalised, escapes decoded.
 *
 * `JSON.parse` does the decoding rather than a local unescaper, so this agrees
 * with the parser that produced the grant instead of approximating it.
 */
function matchedKey(m: RegExpExecArray): string {
  if (m[1] !== undefined) {
    try {
      return normKey(JSON.parse(`"${m[1]}"`) as string);
    } catch {
      return normKey(m[1]);
    }
  }
  return normKey(m[2] ?? m[3] ?? '');
}

function isPruned(key: string | undefined): boolean {
  return key !== undefined && PRUNED_KEYS.has(key);
}

/** The key this line declares, or undefined. */
function declaredKey(line: string): string | undefined {
  const m = KEY_DECL.exec(line);
  return m ? matchedKey(m) : undefined;
}

/** Every key named on this line, in order, with the offset it starts at. */
function keyTokens(line: string): { at: number; key: string }[] {
  KEY_TOKEN.lastIndex = 0;
  const out: { at: number; key: string }[] = [];
  let m: RegExpExecArray | null;
  while ((m = KEY_TOKEN.exec(line)) !== null) {
    out.push({ at: m.index, key: matchedKey(m) });
    // A zero-length match cannot happen here (every alternative consumes at
    // least the colon), but a global regex that failed to advance would spin.
    if (KEY_TOKEN.lastIndex === m.index) KEY_TOKEN.lastIndex++;
  }
  return out;
}

/**
 * For each line, the keys enclosing it, innermost last.
 *
 * Indentation-driven, which is what both formats have in common. Only a key
 * line or a bracket closer may pop a key at its OWN indent: a YAML sequence
 * item, or a JSON array element written at its key's indent, is INSIDE that key
 * and popping there would hand a `deny` entry a citable line. Blank and
 * comment-only lines change nothing — a blank line inside a `deny` block used
 * to pop the whole stack, which is exactly the wrong direction.
 */
function enclosingKeys(lines: readonly string[]): string[][] {
  const out: string[][] = [];
  const stack: { key: string; indent: number }[] = [];
  for (const line of lines) {
    if (INERT_LINE.test(line)) {
      out.push(stack.map((s) => s.key));
      continue;
    }
    const indent = line.length - line.trimStart().length;
    const decl = KEY_DECL.exec(line);
    const flush = decl !== null || CLOSER_LINE.test(line) ? indent : indent + 1;
    while (stack.length > 0 && stack[stack.length - 1].indent >= flush) stack.pop();
    if (decl) stack.push({ key: matchedKey(decl), indent });
    out.push(stack.map((s) => s.key));
  }
  return out;
}

/** The string entries of a value that may be one string or a list of them. */
function asStringList(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  // Flattened: `allow: [["Bash(*)"]]` loses its key context once the recursive
  // walk descends into the inner array, so the entries are collected here.
  if (Array.isArray(value)) return value.flat(4).filter((v): v is string => typeof v === 'string');
  return [];
}

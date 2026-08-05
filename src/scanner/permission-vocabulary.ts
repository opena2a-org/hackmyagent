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
export function classifyPermissionEntry(entry: string, key = 'allow'): UnboundedGrant | undefined {
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
    const scoped = PATH_TOOLS.has(tool) || COMMAND_TOOLS.has(tool) || DOMAIN_TOOLS.has(tool);
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
    return isUnboundedPath(spec)
      ? grant(`grants ${m[1]} over paths no prefix bounds`, narrow)
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
  return { entry, reason: escapeForDisplay(reason), fix: escapeForDisplay(fix), key };
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

/** Keys that grant wholesale when they are boolean `true`. */
const BOOLEAN_GRANT_KEYS = new Set([
  'dangerouslyskippermissions', 'bypasspermissions', 'skippermissions',
  'enableallprojectmcpservers', 'autoapprove', 'alwaysallow', 'autoapproveall',
  'disablepermissions', 'yolo',
].map(normKey));

/** `defaultMode` values that turn the permission prompt off. */
const PERMISSIVE_MODES = new Map<string, string>([
  ['bypasspermissions', 'turns the permission prompt off entirely'],
  ['acceptedits', 'accepts file edits without asking'],
  ['dontask', 'accepts every tool call without asking'],
  ['auto', 'accepts every tool call without asking'],
]);

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
): UnboundedGrant | undefined {
  if (depth > 12 || doc === null || typeof doc !== 'object') return undefined;

  if (Array.isArray(doc)) {
    for (const item of doc) {
      const found = walkConfigForGrants(item, onProseEntry, depth + 1);
      if (found) return found;
    }
    return undefined;
  }

  for (const [rawKey, value] of Object.entries(doc as Record<string, unknown>)) {
    const key = normKey(rawKey);
    if (PRUNED_KEYS.has(key)) continue; // never evaluated, for any purpose

    if (BOOLEAN_GRANT_KEYS.has(key) && value === true) {
      return makeGrant(`${rawKey}: true`, 'runs every tool call without a permission prompt', `set "${rawKey}" to false in this file, or remove the key`, rawKey);
    }

    if (key === normKey('defaultMode') && typeof value === 'string') {
      const reason = PERMISSIVE_MODES.get(normKey(value));
      if (reason) {
        return makeGrant(`${rawKey}: ${value}`, reason, `set "${rawKey}" to "default" so each tool call is asked for`, rawKey);
      }
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
          ? classifyPermissionEntry(entry, rawKey)
          : onProseEntry?.(entry, rawKey);
        if (found) return found;
      }
      // `permissions` is also the object that HOLDS allow/deny, so keep walking.
    }

    const found = walkConfigForGrants(value, onProseEntry, depth + 1);
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
  for (const needle of [grant.entry, JSON.stringify(grant.entry).slice(1, -1)]) {
    if (!needle) continue;
    const i = lines.findIndex((l) => l.includes(needle));
    if (i !== -1) return i + 1;
  }
  const keyPattern = new RegExp(`["']?${escapeRe(grant.key)}["']?\\s*:`);
  const keyIndex = lines.findIndex((l) => keyPattern.test(l));
  return keyIndex === -1 ? 0 : keyIndex + 1;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** The string entries of a value that may be one string or a list of them. */
function asStringList(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  return [];
}

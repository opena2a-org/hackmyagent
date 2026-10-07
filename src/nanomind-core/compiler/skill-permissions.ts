/**
 * Skill permission grants: the `## Permissions` list in a SKILL.md (#471).
 *
 * A skill declares what it needs as a markdown list:
 *
 *   ## Permissions
 *   - filesystem: ./reports
 *   - shell: git status   # read-only
 *   - network: api.example.com (status updates)
 *
 * Markdown is not a grammar the way a JSON tool array is, and the first
 * attempt at reading it was a regex pair that missed most real spellings,
 * read fenced EXAMPLES as real grants, turned any `Key: value` bullet into a
 * capability (a `- token: sk-live-...` line among them), and was quadratic on
 * attacker-sized lists. This module is the grammar that replaced it:
 *
 *   - A section starts at a level 2-6 ATX heading reading "Permissions",
 *     "Permissions Required" or "Required Permissions" (any case, optional
 *     trailing colon, up to 3 spaces of indent) and ends at the next heading,
 *     with or without a space after the `#`s.
 *   - Items are `-`, `*`, `+` or `N.` bullets, or table rows, outside fenced
 *     blocks.
 *   - An item is `domain: value`. The domain must be one of PERMISSION_DOMAINS;
 *     any other key (Note, Contact, See, token, ...) is not a capability and
 *     nothing from it is kept. The value runs to an unquoted ` #` or ` (` and
 *     may contain spaces.
 *   - At most MAX_SKILL_PERMISSION_GRANTS grants are read per file. The rest
 *     are counted, with the line of the first, so the scan can say what it did
 *     not read instead of passing it silently.
 *   - Every grant keeps its own source line, so a finding cites the line that
 *     holds the grant, not the first line that happens to spell it the same way.
 *
 * One pass over the lines, constant work per line apart from the item itself:
 * the parse is linear in the file.
 */

import type { ArtifactType, Capability } from '../types.js';
import { redactSecretsForReportReporting } from '../security/defense-in-depth.js';

/**
 * Most grants read from one file. The largest real list among the published
 * skills sampled for #471 has 7 items; the bound exists so a downloaded
 * SKILL.md with tens of thousands of bullets cannot turn every downstream
 * per-capability loop into the scanner's running time.
 */
export const MAX_SKILL_PERMISSION_GRANTS = 100;

/**
 * Longest grant value or evidence text kept on a capability. Real values are
 * a path, a host or a command; anything longer is truncated before it is
 * redacted and stored.
 */
const MAX_GRANT_TEXT_CHARS = 256;

/** `Capability.source` for a grant read from a skill's Permissions list. */
export const SKILL_PERMISSIONS_SOURCE = 'skill-permissions' as const;

/**
 * The domain spellings read as permissions, keyed to the canonical domain that
 * names the capability. Canonical names contain none of `read`, `access`,
 * `send` or `api.call`: the compiler's data-access coverage matches on those
 * substrings in capability names, and an author-written value never reaches
 * the name.
 */
export const PERMISSION_DOMAINS: Readonly<Record<string, string>> = {
  filesystem: 'filesystem',
  fs: 'filesystem',
  file: 'filesystem',
  files: 'filesystem',
  shell: 'shell',
  exec: 'shell',
  bash: 'shell',
  network: 'network',
  net: 'network',
  env: 'env',
  environment: 'env',
  database: 'database',
  db: 'database',
  browser: 'browser',
};

/**
 * Purpose words that show a skill's stated purpose involves a domain. Used by
 * the scope analyzer to decide whether an unbounded grant contradicts that
 * purpose. Words of 3 characters or fewer are omitted: the purpose keyword
 * extractor drops them, so they could never match.
 */
const DOMAIN_PURPOSE_WORDS: Readonly<Record<string, readonly string[]>> = {
  filesystem: [
    'file', 'files', 'filesystem', 'folder', 'folders', 'directory', 'directories',
    'path', 'paths', 'disk', 'document', 'documents', 'backup', 'backups', 'logs',
    'storage', 'archive', 'archives',
  ],
  shell: [
    'shell', 'command', 'commands', 'terminal', 'script', 'scripts', 'bash',
    'execute', 'executes', 'build', 'builds', 'install', 'installs', 'process',
    'processes', 'deploy', 'deploys',
  ],
  network: [
    'network', 'http', 'https', 'apis', 'fetch', 'fetches', 'download', 'downloads',
    'upload', 'uploads', 'request', 'requests', 'online', 'internet', 'remote',
    'server', 'servers', 'endpoint', 'endpoints', 'webhook', 'webhooks', 'website',
    'websites', 'send', 'sends', 'backend', 'backends', 'sync', 'syncs', 'cloud',
  ],
  env: [
    'environment', 'variable', 'variables', 'config', 'configuration', 'settings',
    'credential', 'credentials', 'token', 'tokens', 'keys', 'secret', 'secrets',
  ],
  database: [
    'database', 'databases', 'query', 'queries', 'table', 'tables', 'records',
    'record', 'data', 'postgres', 'mysql', 'sqlite',
  ],
  browser: [
    'browser', 'browse', 'browsing', 'page', 'pages', 'website', 'websites',
    'screenshot', 'screenshots', 'scrape', 'scraping',
  ],
};

export function permissionDomainPurposeWords(domain: string): readonly string[] {
  return DOMAIN_PURPOSE_WORDS[domain] ?? [];
}

export interface SkillPermissionGrant {
  /** Canonical domain from PERMISSION_DOMAINS. */
  domain: string;
  /** The granted value as written, without markup, quotes or trailing comment. */
  value: string;
  /** 1-based source line. */
  line: number;
  /** The source line, trimmed. */
  text: string;
}

export interface SkillPermissionParse {
  /** The first MAX_SKILL_PERMISSION_GRANTS grants, in file order. */
  grants: SkillPermissionGrant[];
  /** Grants past the bound, counted and not read. */
  unread: number;
  /** Line of the first unread grant, when there is one. */
  firstUnreadLine?: number;
}

const SECTION_TITLES = new Set(['permissions', 'permissions required', 'required permissions']);

// Any ATX heading ends a section, with or without a space after the `#`s.
// Seven or more `#`s is not a heading.
const HEADING_RE = /^ {0,3}(#{1,6})(?!#)(.*)$/;
const FENCE_OPEN_RE = /^ {0,3}(`{3,}|~{3,})(.*)$/;
const BULLET_RE = /^[ \t]*(?:[-*+]|\d{1,9}\.)[ \t]+(.*)$/;
const TABLE_ROW_RE = /^ {0,3}\|(.*)$/;
const KEY_RE = /^([*_`"']*)([A-Za-z][A-Za-z-]*)/;
const MARKUP = '*_`"\'';

// A value that grants nothing. `- network: none` declares the absence of a
// capability, and reading it as one would hand the governance checks a grant
// the skill explicitly declined.
const DENIAL_RE = /^(?:none|no|false|off|disabled|n\/a|na|not required|not needed|-|\u2013|\u2014)\.?$/i;

/** Parse every Permissions section of a markdown document. */
export function parseSkillPermissions(content: string): SkillPermissionParse {
  const grants: SkillPermissionGrant[] = [];
  let unread = 0;
  let firstUnreadLine: number | undefined;

  const lines = content.split('\n');
  let start = 0;
  // YAML frontmatter is not markdown: a `# comment` there is not a heading.
  if (lines.length > 0 && lines[0].replace(/\r$/, '').trim() === '---') {
    for (let i = 1; i < lines.length; i++) {
      const l = lines[i].replace(/\r$/, '').trim();
      if (l === '---' || l === '...') {
        start = i + 1;
        break;
      }
    }
  }

  let inSection = false;
  let fenceChar = '';
  let fenceLen = 0;

  for (let i = start; i < lines.length; i++) {
    const raw = lines[i].endsWith('\r') ? lines[i].slice(0, -1) : lines[i];

    if (fenceLen > 0) {
      const close = FENCE_OPEN_RE.exec(raw);
      if (close && close[1][0] === fenceChar && close[1].length >= fenceLen && close[2].trim() === '') {
        fenceLen = 0;
      }
      continue;
    }
    const open = FENCE_OPEN_RE.exec(raw);
    // A backtick fence's info string cannot contain a backtick; such a line
    // is inline code, not a fence.
    if (open && !(open[1][0] === '`' && open[2].includes('`'))) {
      fenceChar = open[1][0];
      fenceLen = open[1].length;
      continue;
    }

    const heading = HEADING_RE.exec(raw);
    if (heading) {
      inSection = heading[1].length >= 2 && SECTION_TITLES.has(normalizeTitle(heading[2]));
      continue;
    }
    if (!inSection) continue;

    const item = readItem(raw);
    if (!item) continue;

    if (grants.length >= MAX_SKILL_PERMISSION_GRANTS) {
      unread++;
      if (firstUnreadLine === undefined) firstUnreadLine = i + 1;
      continue;
    }
    grants.push({ domain: item.domain, value: item.value, line: i + 1, text: raw.trim() });
  }

  return { grants, unread, firstUnreadLine };
}

/**
 * The declared capabilities a skill's Permissions list contributes. Empty for
 * every artifact type but `skill`.
 *
 * A grant is a capability signal, not a malice signal, so every grant carries
 * `riskLevel: 'medium'`, below the `high`/`critical` selectors of the
 * purpose-mismatch analyzers, and `source: 'skill-permissions'`, which the
 * governance checks leave out of their capability counts. A declaration alone
 * reaches neither: the scope analyzer grades unbounded grants itself, against
 * the skill's stated purpose.
 */
export function skillPermissionCapabilities(content: string, type: ArtifactType): Capability[] {
  if (type !== 'skill') return [];
  return parseSkillPermissions(content).grants.map((g) => ({
    name: g.domain,
    scope: redactSecretsForReportReporting(clip(g.value)).text,
    declared: true,
    inferred: false,
    riskLevel: 'medium' as const,
    evidence: redactSecretsForReportReporting(clip(g.text)).text,
    line: g.line,
    source: SKILL_PERMISSIONS_SOURCE,
  }));
}

/**
 * Whether a grant value leaves its domain unbounded: a bare wildcard (`*`,
 * `**`, `*.*`, `*:*`), a filesystem root or home directory (`/`, `~`, `$HOME`,
 * `/Users`, `/home`, `C:\`), either followed only by wildcard segments, or a
 * word meaning everything. `/var/log/*.*` is bounded by `/var/log`; `none` is
 * not a grant at all.
 */
export function isUnboundedGrantValue(value: string): boolean {
  let v = value.trim().toLowerCase().replace(/\\/g, '/').replace(/\s+/g, ' ');
  if (UNBOUNDED_WORDS.has(v) || UNBOUNDED_PHRASE_RE.test(v)) return true;
  v = v.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  // A drive letter is a root, and its colon is not a wildcard separator.
  const drive = /^[a-z]:(?=\/|$)/.exec(v)?.[0] ?? '';
  let body = v.slice(drive.length);
  // A trailing run of wildcard segments (`/*`, `/**`, `*.*`, `:*`) adds no
  // bound. Scanned rather than matched: a nested-quantifier pattern for the
  // same run backtracks exponentially on a long run of `*`.
  const run = trimEndChars(body, '*/.:');
  if (body.slice(run.length).includes('*')) body = run;
  body = trimEndChars(body, '/');
  return body === '' || UNBOUNDED_ROOTS.has(body);
}

const UNBOUNDED_WORDS = new Set([
  'all', 'any', 'full', 'full access', 'unrestricted', 'unlimited', 'everything',
]);
const UNBOUNDED_PHRASE_RE =
  /^(?:(?:read|write|read\/write|read-write) )?(?:all|any|every) (?:paths?|files?|folders?|directories|hosts?|domains?|sites?|urls?|commands?|programs?)$/;
const UNBOUNDED_ROOTS = new Set(['~', '$home', '${home}', '/users', '/home']);

function normalizeTitle(text: string): string {
  // No title this module reads is long; a long heading is not one of them,
  // and is not worth normalizing.
  if (text.length > 64) return '';
  let t = text.trim();
  // An optional closing sequence: trailing `#`s after whitespace.
  const unhashed = trimEndChars(t, '#');
  if (unhashed.length < t.length && (unhashed === '' || /[ \t]$/.test(unhashed))) t = unhashed.trim();
  if (t.endsWith(':')) t = t.slice(0, -1).trim();
  return t.replace(/\s+/g, ' ').toLowerCase();
}

/**
 * `s` without its trailing run of `chars`. A loop, not `/[...]+$/`: the regex
 * form restarts at every position of a long run that is not at the end, which
 * is quadratic in the run's length.
 */
function trimEndChars(s: string, chars: string): string {
  let k = s.length;
  while (k > 0 && chars.includes(s[k - 1])) k--;
  return s.slice(0, k);
}

function trimStartChars(s: string, chars: string): string {
  let k = 0;
  while (k < s.length && chars.includes(s[k])) k++;
  return s.slice(k);
}

function clip(text: string): string {
  return text.length > MAX_GRANT_TEXT_CHARS ? `${text.slice(0, MAX_GRANT_TEXT_CHARS)}...` : text;
}

/** One bullet or table row, read as a grant; undefined when it is not one. */
function readItem(line: string): { domain: string; value: string } | undefined {
  const bullet = BULLET_RE.exec(line);
  if (bullet) return readGrant(bullet[1]);

  const row = TABLE_ROW_RE.exec(line);
  if (!row) return undefined;
  const cells = row[1].split(/(?<!\\)\|/).map((c) => c.trim());
  const first = cells[0] ?? '';
  const inCell = readGrant(first);
  if (inCell) return inCell;
  // `| filesystem | /var/log/*.log | ... |`: the domain in one cell and the
  // value in the next.
  const key = trimEndChars(trimEndChars(trimStartChars(first, MARKUP), MARKUP), ':').toLowerCase();
  const domain = PERMISSION_DOMAINS[key];
  if (!domain || cells.length < 2) return undefined;
  const value = finishValue(cells[1]);
  return value === undefined ? undefined : { domain, value };
}

/**
 * Read `domain: value` from an item's text. Inline markup around the key is
 * accepted in the shapes real skills use: `**filesystem**: x`,
 * `**Filesystem:** x`, `` `filesystem:read` ``, `` **`filesystem:read`**: why ``.
 */
function readGrant(text: string): { domain: string; value: string } | undefined {
  const key = KEY_RE.exec(text);
  if (!key) return undefined;
  const domain = PERMISSION_DOMAINS[key[2].toLowerCase()];
  if (!domain) return undefined;

  const open = key[1];
  const close = [...open].reverse().join('');
  let i = key[0].length;
  let closed = open === '';
  if (!closed && text.startsWith(close, i)) {
    i += close.length;
    closed = true;
  }
  while (text[i] === ' ' || text[i] === '\t') i++;
  if (text[i] !== ':') return undefined;
  i++;
  if (!closed && text.startsWith(close, i)) {
    i += close.length;
    closed = true;
  }

  let rest = text.slice(i);
  if (!closed) {
    // The markup opened before the key also wraps the value:
    // `` `shell:*` `` is the grant `*`.
    const end = rest.indexOf(close);
    rest = end >= 0 ? rest.slice(0, end) : trimEndChars(rest, MARKUP);
  }
  const value = finishValue(rest);
  return value === undefined ? undefined : { domain, value };
}

/**
 * Cut a value at its first unquoted ` #` or ` (`, trim it, and drop one pair
 * of surrounding quotes. Undefined when nothing is left or the value declines
 * the capability.
 */
function finishValue(rest: string): string | undefined {
  let quote = '';
  let end = rest.length;
  for (let j = 0; j < rest.length; j++) {
    const c = rest[j];
    if (quote) {
      if (c === quote) quote = '';
      continue;
    }
    if (c === '"' || c === '`') {
      quote = c;
      continue;
    }
    // An apostrophe opens a quote only at the start of a word, so "skill's"
    // does not swallow the rest of the line.
    if (c === "'" && (j === 0 || rest[j - 1] === ' ' || rest[j - 1] === '\t')) {
      quote = c;
      continue;
    }
    if ((c === ' ' || c === '\t') && (rest[j + 1] === '#' || rest[j + 1] === '(')) {
      end = j;
      break;
    }
  }
  let value = rest.slice(0, end).trim();
  if (value.length >= 2 && /^["'`]/.test(value) && value[value.length - 1] === value[0]) {
    value = value.slice(1, -1).trim();
  }
  if (value === '' || DENIAL_RE.test(value)) return undefined;
  return value;
}

/**
 * Secure Artifact Parser
 *
 * Every artifact enters the NanoMind pipeline through this parser.
 * It validates structure, classifies type, extracts metadata,
 * and computes content hashes for integrity tracking.
 *
 * Security: validates before processing. Rejects malformed, oversized,
 * or unrecognized artifacts before they reach NanoMind.
 */

import { createHash } from 'node:crypto';
import * as yaml from 'js-yaml';
import type { ArtifactClassification, ArtifactType, CompilerConfig, DEFAULT_COMPILER_CONFIG } from '../types.js';

export interface ParsedArtifact {
  /** Classified artifact type */
  type: ArtifactType;
  /**
   * How `type` was decided: `'path'` when the matching signature holds with
   * the content withheld, so the file's name alone named the kind; `'content'`
   * when the body had to be read. `unknown` is always `'content'`.
   */
  classifiedBy: ArtifactClassification;
  /** SHA-256 content hash */
  contentHash: string;
  /** Original content */
  content: string;
  /** File path (if from filesystem) */
  path?: string;
  /** File size in bytes */
  size: number;
  /** YAML frontmatter (if present) */
  frontmatter?: Record<string, unknown>;
  /** Whether the artifact passed validation */
  valid: boolean;
  /** Validation errors (if invalid) */
  errors: string[];
}

// ============================================================================
// Artifact Type Detection
// ============================================================================

// ----------------------------------------------------------------------------
// Leading frontmatter (#423)
//
// An artifact declares capabilities iff its leading YAML frontmatter block, parsed by a real
// YAML loader, holds a key named `capabilities` at depth <= 8. One js-yaml load of that block
// feeds BOTH the skill signature and `parseArtifact().frontmatter`, so the classifier and the
// parser cannot disagree about the same bytes. They did: the classifier tested
// `/^capabilities[ \t]*:/m` while the parser trimmed every line and flattened nesting, so a
// file could be typed `unknown` while its parsed frontmatter reported
// `capabilities: ["run_shell"]`, and `capabilities: [a, b]` reached the semantic compiler as
// the string "[a, b]" rather than a list.
// ----------------------------------------------------------------------------

/** The first line after BOM and blank lines must be this for the file to have frontmatter. */
const FRONTMATTER_OPEN = /^-{3,}[ \t]*$/;

/** Bytes of the block handed to the YAML loader. */
const FRONTMATTER_MAX_BYTES = 64 * 1024;

/** Deepest container level (the root mapping is 1) at which a `capabilities` key counts. */
const CAPABILITIES_MAX_DEPTH = 8;

/**
 * Values `parseArtifact().frontmatter` may expand to, counted as a tree. 64 KiB of YAML without
 * aliases cannot exceed it; an alias chain can (436 bytes expand to 2 * 10^8 characters under
 * `String()`), and the semantic compiler calls `String()` on `description` and on every
 * capability.
 */
const FRONTMATTER_MAX_EXPANDED_VALUES = 131_072;

/**
 * The fallback the loader leans on when it cannot read the whole block: the #410 test, a
 * column-0 `capabilities` key anywhere in the block. A block that fails to load still counts
 * as declaring capabilities when it says so, so a YAML error can only over-detect.
 */
const CAPABILITIES_LINE = /^capabilities[ \t]*:/m;

/** One line of the leading YAML run used when no line closes the block. */
const YAML_BLANK_OR_COMMENT = /^\s*(?:#.*)?$/;
const YAML_SEQUENCE_ITEM = /^[ \t]*-(?:[ \t]|$)/;
const YAML_MAPPING_KEY =
  /^[ \t]*(?:"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[A-Za-z0-9_$][\w$.-]*)[ \t]*:(?:[ \t]|$)/;
const YAML_BLOCK_SCALAR_HEADER = /(?::|^[ \t]*-)[ \t]+[|>][-+0-9]*[ \t]*(?:#.*)?$/;

interface LeadingFrontmatter {
  /** The block between the opening fence and its terminator, before truncation. */
  block: string;
  /** What js-yaml returned for the first 64 KiB of `block`; `undefined` when it threw. */
  value: unknown;
  /** The loader did not read all of `block`: it threw, or the block was truncated. */
  partial: boolean;
}

/**
 * The leading frontmatter block, or null when the file does not open with a fence.
 *
 * 1. Strip an optional BOM and skip whitespace-only lines.
 * 2. The next line must be `---` (three or more dashes, optional trailing spaces). Anything
 *    else means no frontmatter: a `---` further down a Markdown document is a horizontal rule,
 *    not a fence (#410).
 * 3. The block runs to the first later line whose trimmed form starts with `---` or `...`;
 *    text after the terminator on that line is ignored. With no such line, the block is the
 *    leading run of YAML-shaped lines (see `leadingYamlRun`).
 */
function extractLeadingFrontmatterBlock(content: string): string | null {
  let pos = content.charCodeAt(0) === 0xfeff ? 1 : 0;
  for (;;) {
    if (pos >= content.length) return null;
    const { line, next } = readLine(content, pos);
    pos = next;
    if (line.trim() === '') continue;
    if (!FRONTMATTER_OPEN.test(line)) return null;
    break;
  }

  const start = pos;
  while (pos < content.length) {
    const { line, next } = readLine(content, pos);
    const trimmed = line.trim();
    if (trimmed.startsWith('---') || trimmed.startsWith('...')) return content.slice(start, pos);
    pos = next;
  }
  return leadingYamlRun(content, start);
}

/**
 * The keys of the top-level object when the file IS a JSON object, or null when it is not.
 *
 * Structure, not substring (#411): a key counts only at depth 1 of a document that opens with
 * `{`, so a `"agentType"` inside a Markdown code sample, a nested object or a string value
 * never qualifies. Reads strings with their escapes and skips `//` and block comments, so
 * JSONC and trailing commas are accepted the way the mcp_config fallback accepts them.
 */
function topLevelJsonKeys(content: string): Set<string> | null {
  const text = content.replace(/^\uFEFF/, '');
  const n = text.length;
  let i = 0;
  const skipTrivia = (): void => {
    while (i < n) {
      const c = text[i];
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') {
        i++;
      } else if (c === '/' && text[i + 1] === '/') {
        const nl = text.indexOf('\n', i);
        i = nl === -1 ? n : nl + 1;
      } else if (c === '/' && text[i + 1] === '*') {
        const end = text.indexOf('*/', i + 2);
        i = end === -1 ? n : end + 2;
      } else {
        return;
      }
    }
  };

  skipTrivia();
  if (text[i] !== '{') return null;
  const keys = new Set<string>();
  let depth = 0;
  while (i < n) {
    const c = text[i];
    if (c === '"') {
      const start = ++i;
      while (i < n && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
      const value = text.slice(start, i);
      i++;
      if (depth === 1) {
        skipTrivia();
        if (text[i] === ':') keys.add(value);
      }
      continue;
    }
    if (c === '/' && (text[i + 1] === '/' || text[i + 1] === '*')) {
      skipTrivia();
      continue;
    }
    if (c === '{' || c === '[') {
      depth++;
    } else if (c === '}' || c === ']') {
      depth--;
      if (depth === 0) break;
    }
    i++;
  }
  return keys;
}

/**
 * Exact basenames of the developer instruction files, lowercased. Matched against the last
 * path segment, never as a substring of the path: `about-claude.md.backup` and
 * `docs/not-claude.md.old` are not instruction files (#411).
 */
const INSTRUCTION_FILE_BASENAMES: ReadonlySet<string> = new Set([
  'claude.md',
  '.cursorrules',
  '.clinerules',
  '.windsurfrules',
]);

/**
 * A system prompt file is named for what it is: the name before its first dot, or the whole
 * name, is `system-prompt`, `system_prompt` or `systemprompt`, alone or followed by `-`, `_`
 * or `.` and a suffix. So `system-prompt.prod.md`, `system-prompt-v2.txt` and
 * `system_prompt.en.md` are system prompts. Anchored at the start of the basename, so
 * `about-system-prompt.md` is not one, and `system-prompts.md` is not one either.
 *
 * Testing the whole basename covers the first-dot stem too: a stem that matches is followed
 * only by `.` and the rest of the name, which the optional suffix accepts.
 */
const SYSTEM_PROMPT_NAME = /^(?:system-prompt|system_prompt|systemprompt)(?:[-_.].*)?$/;

/** A backup copy is not the file it copies: `system-prompt.md.bak`, `system-prompt.md~`. */
const BACKUP_SUFFIX = /(?:\.(?:bak|backup|old|orig)|~)$/;

function isSystemPromptPath(path: string | undefined): boolean {
  if (!path) return false;
  const segments = path.toLowerCase().split(/[/\\]/);
  const basename = segments[segments.length - 1];
  if (INSTRUCTION_FILE_BASENAMES.has(basename)) return true;
  // Cline also reads every file under a `.clinerules/` directory.
  if (segments.slice(0, -1).includes('.clinerules')) return true;
  if (BACKUP_SUFFIX.test(basename)) return false;
  return SYSTEM_PROMPT_NAME.test(basename);
}

/** The line starting at `pos` without its line terminator, and where the next line starts. */
function readLine(content: string, pos: number): { line: string; next: number } {
  const newline = content.indexOf('\n', pos);
  const end = newline === -1 ? content.length : newline;
  return { line: content.slice(pos, end).replace(/\r$/, ''), next: newline === -1 ? content.length : newline + 1 };
}

/**
 * With no closing line, the block is the leading run of lines that are blank, `#` comments,
 * `- ` sequence items, `key:` / `key: value` (bare or quoted key, any indentation), or the
 * indented continuation of a `|` / `>` block scalar. It stops at the first line that is none
 * of these -- the first line of the Markdown body.
 */
function leadingYamlRun(content: string, start: number): string {
  let pos = start;
  let scalarIndent: number | null = null;
  while (pos < content.length) {
    const { line, next } = readLine(content, pos);
    const indent = line.length - line.replace(/^[ \t]+/, '').length;

    if (scalarIndent !== null && (line.trim() === '' || indent > scalarIndent)) {
      pos = next;
      continue;
    }
    scalarIndent = null;

    const isYamlLine =
      YAML_BLANK_OR_COMMENT.test(line) || YAML_SEQUENCE_ITEM.test(line) || YAML_MAPPING_KEY.test(line);
    if (!isYamlLine) break;
    if (YAML_BLOCK_SCALAR_HEADER.test(line)) scalarIndent = indent;
    pos = next;
  }
  return content.slice(start, pos);
}

/** The first `maxBytes` UTF-8 bytes of `text`, or `text` itself when it already fits. */
function truncateUtf8(text: string, maxBytes: number): string {
  if (text.length * 3 <= maxBytes) return text;
  const bytes = Buffer.from(text, 'utf-8');
  return bytes.length <= maxBytes ? text : bytes.subarray(0, maxBytes).toString('utf-8');
}

/** Steps 1-5: find the leading block, truncate it to 64 KiB and load it on js-yaml's default schema. */
function loadLeadingFrontmatter(content: string): LeadingFrontmatter | null {
  const block = extractLeadingFrontmatterBlock(content);
  if (block === null) return null;
  const loadable = truncateUtf8(block, FRONTMATTER_MAX_BYTES);
  try {
    return { block, value: yaml.load(loadable), partial: loadable !== block };
  } catch {
    return { block, value: undefined, partial: true };
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Object.prototype.toString.call(value) === '[object Object]';
}

/**
 * True when `root` is a mapping holding `key` at depth <= `maxDepth`. The root mapping is
 * depth 1, and every mapping or sequence below it adds one, so `metadata.openclaw.capabilities`
 * is at depth 3.
 *
 * Breadth-first with a visited set: every container is reached first at its shallowest depth
 * and expanded once, so an alias chain that reuses one node many times costs one visit, not
 * one per path to it.
 */
function hasKeyWithinDepth(root: unknown, key: string, maxDepth: number): boolean {
  if (!isPlainObject(root)) return false;
  const seen = new Set<object>([root]);
  let level: object[] = [root];
  for (let depth = 1; depth <= maxDepth && level.length > 0; depth++) {
    const next: object[] = [];
    for (const node of level) {
      if (!Array.isArray(node) && Object.prototype.hasOwnProperty.call(node, key)) return true;
      for (const child of Array.isArray(node) ? node : Object.values(node)) {
        if (child !== null && typeof child === 'object' && !seen.has(child)) {
          seen.add(child);
          next.push(child);
        }
      }
    }
    level = next;
  }
  return false;
}

/** True when `root`, expanded as a tree (aliases copied out), holds at most `limit` values. */
function expandsWithin(root: unknown, limit: number): boolean {
  const stack: unknown[] = [root];
  let count = 0;
  while (stack.length > 0) {
    const node = stack.pop();
    if (++count > limit) return false;
    if (node !== null && typeof node === 'object') {
      for (const child of Array.isArray(node) ? node : Object.values(node)) stack.push(child);
    }
  }
  return true;
}

/**
 * Step 6, with the fallback: the loaded block is a mapping holding `capabilities` at depth
 * <= 8, or the loader could not read the whole block and a column-0 `capabilities:` line is in
 * it. The second arm is why the classifier is a superset of the parser: a loader failure
 * leaves `frontmatter` undefined and can only widen what classifies as a skill.
 */
function declaresCapabilities(frontmatter: LeadingFrontmatter | null): boolean {
  if (frontmatter === null) return false;
  if (hasKeyWithinDepth(frontmatter.value, 'capabilities', CAPABILITIES_MAX_DEPTH)) return true;
  return frontmatter.partial && CAPABILITIES_LINE.test(frontmatter.block);
}

/** Step 7: the loaded mapping itself, when it is one and is safe to stringify. */
function frontmatterRecord(frontmatter: LeadingFrontmatter | null): Record<string, unknown> | undefined {
  if (frontmatter === null || !isPlainObject(frontmatter.value)) return undefined;
  return expandsWithin(frontmatter.value, FRONTMATTER_MAX_EXPANDED_VALUES) ? frontmatter.value : undefined;
}

/**
 * Step 8: `SKILL.md` and `*.skill.md`, the names the hardening scanner discovers skills by.
 * Independent of content and OR'd with it. Case-sensitive, as that discovery is: a lone
 * `skill.md` without capabilities is not a skill to either layer (#740).
 */
function isSkillPath(path?: string): boolean {
  if (!path) return false;
  return path.endsWith('SKILL.md') || path.endsWith('.skill.md');
}

/** The leading frontmatter, loaded at most once per classification. */
type FrontmatterSource = () => LeadingFrontmatter | null;

const NO_FRONTMATTER: FrontmatterSource = () => null;

const TYPE_SIGNATURES: Array<{
  test: (content: string, path: string | undefined, frontmatter: FrontmatterSource) => boolean;
  type: ArtifactType;
}> = [
  // Source code: recognized source extensions.
  //
  // IMPORTANT: Extension-based source classification runs first so that
  // content-based heuristics further down (a2a_card, agent_config,
  // credential_file, system_prompt) cannot misclassify source files.
  // A Go file containing the JSON tag string `"capabilities"` is still a
  // Go file, not an agent card. A security scanner's regex patterns that
  // match `sk-ant-api...` are still source code, not a credential dump.
  // The downstream pipeline uses the `source_code` classification to apply
  // language-aware preprocessing and AST-based credential analysis.
  {
    test: (_, path) => /\.(ts|tsx|js|jsx|mjs|cjs|py|pyi|go|rs|java|rb)$/.test(path ?? ''),
    type: 'source_code',
  },
  // Skills: a skill path, or LEADING YAML frontmatter declaring capabilities (#423).
  //
  // IMPORTANT: the frontmatter test must read the leading block, not the raw document.
  // This previously used `/^---\n[\s\S]*?capabilities:\s*\n/m`, whose `m` flag made `^`
  // match at every line start -- so it really meant "a `---` line anywhere, then a line
  // ending in `capabilities:` anywhere later". In Markdown `---` is a horizontal rule and
  // `capabilities:` matches ordinary prose, so documentation classified as an executable
  // skill and drew CRITICAL findings from the skill analyzers on placeholder URLs and
  // sample SQL (#410). The block is now loaded as YAML, so a key nested under `metadata:`,
  // a quoted key, an indented block, a BOM and a `...` terminator all count, and a block
  // that loads as prose rather than a mapping does not.
  {
    test: (content, path, frontmatter) => isSkillPath(path) || declaresCapabilities(frontmatter()),
    type: 'skill',
  },
  // MCP config: known basenames (mcp.json, .mcp.json, mcpServers.json)
  // or content containing an mcpServers object.
  //
  // IMPORTANT: match known basenames exactly, not any path ending in
  // a matching suffix. A bug-bounty target descriptor named
  // `salesforce-mcp.json` or a vendor target list like `github-mcp.json`
  // is NOT an agent config — it is metadata about another agent. Running
  // the agent analyzers on such files produces six-finding pileups
  // (governance + capability + scope all misfiring). The allowlist mirrors
  // the canonical MCP filenames referenced across the scanner codebase:
  // Claude Code project config (`.mcp.json`), client installs (`mcp.json`
  // in `.cursor/`, `.vscode/`, `.well-known/`), and assembly-scanner's
  // TOOL_DESC_FILES (`mcpServers.json`).
  {
    test: (content, path) => {
      const basename = path ? path.split(/[/\\]/).pop() : undefined;
      const isKnownMcpName =
        basename === 'mcp.json' ||
        basename === '.mcp.json' ||
        basename === 'mcpServers.json';
      if (isKnownMcpName) return true;
      // Content fallback: strip BOM and leading whitespace so JSONC /
      // pretty-printed files aren't missed. Require both an opening brace
      // and an mcpServers key — a loose substring check would false-match
      // target descriptors that merely discuss mcpServers in prose.
      const stripped = content.replace(/^\uFEFF/, '').trimStart();
      return stripped.startsWith('{') && /"mcpServers"\s*:/.test(stripped);
    },
    type: 'mcp_config',
  },
  // SOUL governance: SOUL.md
  {
    test: (_, path) => path?.toUpperCase().includes('SOUL.MD') || false,
    type: 'soul',
  },
  // System prompt: CLAUDE.md, .cursorrules, .clinerules, .windsurfrules, system-prompt*
  //
  // IMPORTANT: read from the basename, not path substrings. `includes('claude.md')` also
  // named `docs/about-claude.md.backup` a system prompt (#411).
  {
    test: (_, path) => isSystemPromptPath(path),
    type: 'system_prompt',
  },
  // Agent config: agent-config.yaml, *.agent.json, or a JSON object whose top-level keys
  // declare an agent.
  //
  // IMPORTANT: read the keys from the parsed structure. This previously used
  // `/"agentType"|"capabilities".*"constraints"/s` on the raw text: unanchored, and `s`
  // let `.*` bridge the two strings across any distance, so a guide with a JSON example or
  // two field names fifty lines apart classified as an agent config and drew the agent
  // analyzers (#411).
  {
    test: (content, path) => {
      if (path?.includes('agent-config') || path?.includes('.agent.')) return true;
      const keys = topLevelJsonKeys(content);
      return keys !== null &&
        (keys.has('agentType') || (keys.has('capabilities') && keys.has('constraints')));
    },
    type: 'agent_config',
  },
  // A2A card: agent.json (well-known), or a JSON object with top-level agentType and
  // capabilities keys.
  {
    test: (content, path) => {
      if (path?.endsWith('agent.json')) return true;
      const keys = topLevelJsonKeys(content);
      return keys !== null && keys.has('agentType') && keys.has('capabilities');
    },
    type: 'a2a_card',
  },
  // Env file: .env, .env.*
  {
    test: (_, path) => /\.env($|\.)/.test(path ?? ''),
    type: 'env_file',
  },
  // Credential file: contains API keys or secrets (non-source, non-env, non-Markdown)
  //
  // IMPORTANT: a Markdown document is never a credential store, so a key shape in one does
  // not make it this type. Textually, a page documenting a key format and a page leaking a
  // key are identical (#411); telling them apart is the credential analyzers' job, and they
  // read `.md` as documentation context. Classifying the page `credential_file` instead
  // marked it a place where credentials are expected.
  {
    test: (content, path) =>
      !/\.md$/i.test(path ?? '') &&
      /sk-ant-|sk-proj-|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|-----BEGIN .* KEY-----/.test(content),
    type: 'credential_file',
  },
];

/**
 * Parse and validate an artifact for NanoMind processing.
 *
 * Security: rejects artifacts that are:
 * - Larger than maxArtifactSize (default 1MB)
 * - Binary (non-text)
 * - Empty
 */
export function parseArtifact(
  content: string,
  path?: string,
  config?: Partial<typeof DEFAULT_COMPILER_CONFIG>,
): ParsedArtifact {
  const maxSize = config?.maxArtifactSize ?? 1_048_576;
  const errors: string[] = [];

  // Validation: size
  const size = Buffer.byteLength(content, 'utf-8');
  if (size > maxSize) {
    errors.push(`Artifact exceeds maximum size (${size} > ${maxSize} bytes)`);
  }
  if (size === 0) {
    errors.push('Artifact is empty');
  }

  // Validation: binary content
  if (containsBinaryData(content)) {
    errors.push('Artifact contains binary data');
  }

  // One load of the leading frontmatter feeds both the skill signature and the
  // `frontmatter` field, so the two cannot disagree about the same bytes (#423).
  // Invalid frontmatter is not an error -- the artifact may still be valid.
  const leading = loadLeadingFrontmatter(content);

  // Classify type, and record what decided it
  const { type, classifiedBy } = classifyWith(content, path, () => leading);

  // Compute content hash
  const contentHash = computeHash(content);

  const frontmatter = frontmatterRecord(leading);

  return {
    type,
    classifiedBy,
    contentHash,
    content,
    path,
    size,
    frontmatter,
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Classify artifact type from content and path, and say what decided it.
 * Tries each signature in order; returns 'unknown' if none match.
 *
 * `classifiedBy` is measured, not declared per signature: the signature that
 * matched is asked again with the content withheld. If it still matches, the
 * path alone named the kind (`SKILL.md`, `mcp.json`, `SOUL.md`, `agent.json`,
 * `agent-config.yaml`, a source extension); if it does not, a content
 * heuristic decided (`capabilities:` frontmatter on a `.md`, an `mcpServers`
 * key in an unnamed JSON file, an `agentType` field). The semantic layer's
 * sdk/library gate reads this so a path-named agent artifact nested under a
 * library root still reaches the agent families (#740).
 */
export function classifyArtifact(
  content: string,
  path?: string,
): { type: ArtifactType; classifiedBy: ArtifactClassification } {
  let leading: LeadingFrontmatter | null | undefined;
  return classifyWith(content, path, () => (leading === undefined ? (leading = loadLeadingFrontmatter(content)) : leading));
}

function classifyWith(
  content: string,
  path: string | undefined,
  frontmatter: FrontmatterSource,
): { type: ArtifactType; classifiedBy: ArtifactClassification } {
  for (const sig of TYPE_SIGNATURES) {
    if (sig.test(content, path, frontmatter)) {
      const byPath = path !== undefined && sig.test('', path, NO_FRONTMATTER);
      return { type: sig.type, classifiedBy: byPath ? 'path' : 'content' };
    }
  }
  return { type: 'unknown', classifiedBy: 'content' };
}

/** `classifyArtifact(...).type`, for callers that only want the kind. */
export function classifyArtifactType(content: string, path?: string): ArtifactType {
  return classifyArtifact(content, path).type;
}

/**
 * Compute SHA-256 hash of content for content-addressed caching and integrity.
 */
export function computeHash(content: string): string {
  return createHash('sha256').update(content, 'utf-8').digest('hex');
}

/**
 * Check for binary data in content (null bytes, control characters).
 */
function containsBinaryData(content: string): boolean {
  // Check first 8KB for null bytes or excessive control characters
  const sample = content.slice(0, 8192);
  let controlCount = 0;
  for (let i = 0; i < sample.length; i++) {
    const code = sample.charCodeAt(i);
    if (code === 0) return true; // Null byte = definitely binary
    if (code < 32 && code !== 9 && code !== 10 && code !== 13) {
      controlCount++;
    }
  }
  return controlCount > sample.length * 0.1; // > 10% control chars = binary
}

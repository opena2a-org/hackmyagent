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

/**
 * Extract the LEADING YAML frontmatter block, or null when the file does not open with one.
 *
 * Deliberately NOT `/m`: `^` must mean start-of-file here. A `---` further down a Markdown
 * document is a horizontal rule, not a frontmatter fence (#410). Tolerates CRLF and trailing
 * spaces on the fences.
 */
function extractLeadingFrontmatter(content: string): string | null {
  const match = /^---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)/.exec(content);
  return match ? match[1] : null;
}

/**
 * True when the leading frontmatter declares a top-level `capabilities` key.
 *
 * `m` IS correct on the inner test and was wrong on the outer one: the string being searched
 * is already bounded to the frontmatter block, so `^` can only reach frontmatter lines. Only
 * unindented keys count -- an indented `capabilities:` is a nested field or a code sample.
 * Matching the key alone (not `key` + newline) accepts both the block form and the inline
 * form `capabilities: [read_files, run_shell]`.
 */
function declaresCapabilities(content: string): boolean {
  const frontmatter = extractLeadingFrontmatter(content);
  return frontmatter !== null && /^capabilities[ \t]*:/m.test(frontmatter);
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

const TYPE_SIGNATURES: Array<{ test: (content: string, path?: string) => boolean; type: ArtifactType }> = [
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
  // Skills: SKILL.md, *.skill.md, or LEADING YAML frontmatter declaring capabilities.
  //
  // IMPORTANT: the frontmatter test must read the leading block, not the raw document.
  // This previously used `/^---\n[\s\S]*?capabilities:\s*\n/m`, whose `m` flag made `^`
  // match at every line start -- so it really meant "a `---` line anywhere, then a line
  // ending in `capabilities:` anywhere later". In Markdown `---` is a horizontal rule and
  // `capabilities:` matches ordinary prose, so documentation classified as an executable
  // skill and drew CRITICAL findings from the skill analyzers on placeholder URLs and
  // sample SQL (#410). The same regex also MISSED real skills: it required a newline
  // immediately after the colon, so the inline form `capabilities: [a, b]` never matched,
  // and its `\n` literal never matched CRLF frontmatter.
  {
    test: (content, path) =>
      (path?.endsWith('SKILL.md') || path?.endsWith('.skill.md') || false) ||
      declaresCapabilities(content),
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

  // Classify type, and record what decided it
  const { type, classifiedBy } = classifyArtifact(content, path);

  // Compute content hash
  const contentHash = computeHash(content);

  // Extract YAML frontmatter
  let frontmatter: Record<string, unknown> | undefined;
  // Same notion of "leading frontmatter" the skill classifier uses -- one spelling, not two.
  const fmBlock = extractLeadingFrontmatter(content);
  if (fmBlock !== null) {
    try {
      frontmatter = parseSimpleYAML(fmBlock);
    } catch {
      // Invalid frontmatter is not an error -- artifact may still be valid
    }
  }

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
  for (const sig of TYPE_SIGNATURES) {
    if (sig.test(content, path)) {
      const byPath = path !== undefined && sig.test('', path);
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

/**
 * Simple YAML parser for frontmatter (no dependency).
 * Handles key: value and key: [list] patterns.
 */
function parseSimpleYAML(yaml: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  const lines = yaml.split('\n');
  let currentKey: string | null = null;
  let currentList: string[] | null = null;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // List item
    if (trimmed.startsWith('- ') && currentKey && currentList) {
      currentList.push(trimmed.slice(2).trim());
      continue;
    }

    // Save previous list
    if (currentKey && currentList) {
      result[currentKey] = currentList;
      currentList = null;
    }

    // Key: value
    const kvMatch = trimmed.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.*)/);
    if (kvMatch) {
      currentKey = kvMatch[1];
      const value = kvMatch[2].trim();
      if (value === '' || value === '|' || value === '>') {
        // Start of list or multiline
        currentList = [];
      } else {
        result[currentKey] = value;
        currentKey = null;
      }
    }
  }

  if (currentKey && currentList) {
    result[currentKey] = currentList;
  }

  return result;
}

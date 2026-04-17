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
import type { ArtifactType, CompilerConfig, DEFAULT_COMPILER_CONFIG } from '../types.js';

export interface ParsedArtifact {
  /** Classified artifact type */
  type: ArtifactType;
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
  // Skills: SKILL.md, *.skill.md, or YAML frontmatter with capabilities
  {
    test: (content, path) =>
      (path?.endsWith('SKILL.md') || path?.endsWith('.skill.md') || false) ||
      /^---\n[\s\S]*?capabilities:\s*\n/m.test(content),
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
  // System prompt: CLAUDE.md, .cursorrules, .clinerules
  {
    test: (_, path) => {
      const p = path?.toLowerCase() ?? '';
      return p.includes('claude.md') || p.includes('.cursorrules') ||
        p.includes('.clinerules') || p.includes('.windsurfrules') ||
        p.includes('system-prompt') || p.includes('systemprompt');
    },
    type: 'system_prompt',
  },
  // Agent config: agent-config.yaml, *.agent.json
  {
    test: (content, path) =>
      (path?.includes('agent-config') || path?.includes('.agent.') || false) ||
      /"agentType"|"capabilities".*"constraints"/s.test(content),
    type: 'agent_config',
  },
  // A2A card: agent.json (well-known), contains agentType/capabilities
  {
    test: (content, path) =>
      (path?.endsWith('agent.json') || false) ||
      (content.startsWith('{') && /"agentType"/.test(content) && /"capabilities"/.test(content)),
    type: 'a2a_card',
  },
  // Env file: .env, .env.*
  {
    test: (_, path) => /\.env($|\.)/.test(path ?? ''),
    type: 'env_file',
  },
  // Credential file: contains API keys or secrets (non-source, non-env)
  {
    test: (content) =>
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

  // Classify type
  const type = classifyArtifactType(content, path);

  // Compute content hash
  const contentHash = computeHash(content);

  // Extract YAML frontmatter
  let frontmatter: Record<string, unknown> | undefined;
  const fmMatch = content.match(/^---\n([\s\S]*?)\n---/);
  if (fmMatch) {
    try {
      frontmatter = parseSimpleYAML(fmMatch[1]);
    } catch {
      // Invalid frontmatter is not an error -- artifact may still be valid
    }
  }

  return {
    type,
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
 * Classify artifact type from content and path.
 * Tries each signature in order; returns 'unknown' if none match.
 */
export function classifyArtifactType(content: string, path?: string): ArtifactType {
  for (const sig of TYPE_SIGNATURES) {
    if (sig.test(content, path)) {
      return sig.type;
    }
  }
  return 'unknown';
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

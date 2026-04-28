/**
 * Concept-explainer registry (skeleton).
 *
 * Curated, human-written copy for unfamiliar primitives that finding
 * fixes recommend (SOUL.md, Secretless vault, MCP tool isolation, etc.).
 *
 * The renderer dedupes by `ConceptId` per scan: first occurrence shows
 * the expanded `body`; subsequent occurrences collapse to `oneLineRef`.
 *
 * This file is the SKELETON — full body copy lands in #142 along with
 * the renderer dedupe logic. Every `ConceptId` must have an entry here
 * so a future finding tagged with that concept always resolves.
 */

import type { ConceptId } from '../types/finding-evidence';

export interface ConceptExplainer {
  id: ConceptId;
  /** Heading shown above the expanded body (first occurrence). */
  title: string;
  /** Expanded multi-line explainer rendered on first occurrence per scan. */
  body: string;
  /** One-line back-reference rendered on subsequent occurrences. */
  oneLineRef: string;
}

/**
 * Registry of all known concepts. Body copy is stubbed pending #142.
 * Adding a new `ConceptId` to the union requires adding an entry here —
 * `concept-explainers.test.ts` enforces this.
 */
export const CONCEPT_EXPLAINERS: Record<ConceptId, ConceptExplainer> = {
  'soul-governance': {
    id: 'soul-governance',
    title: 'Why SOUL.md',
    body: 'TODO — see hackmyagent#142. SOUL.md is the agent constitution; it governs SKILL/MCP capabilities and constrains runtime input.',
    oneLineRef: '(Why SOUL: see above)',
  },
  'secretless-vault': {
    id: 'secretless-vault',
    title: 'Why the Secretless vault',
    body: 'TODO — see hackmyagent#142. Hardcoded credentials live in source, configs, and version control history. The Secretless vault keeps them out of process memory and out of AI context.',
    oneLineRef: '(Why Secretless: see above)',
  },
  'mcp-tool-isolation': {
    id: 'mcp-tool-isolation',
    title: 'Why MCP tool isolation',
    body: 'TODO — see hackmyagent#142. Wildcard MCP tool grants give the agent everything; an explicit allowlist scopes capability to legitimate use.',
    oneLineRef: '(Why MCP isolation: see above)',
  },
  'injection-resistance': {
    id: 'injection-resistance',
    title: 'Why injection resistance',
    body: 'TODO — see hackmyagent#142. Without an immutability clause, instructions in user input, tool output, or retrieved documents can hijack the agent.',
    oneLineRef: '(Why injection resistance: see above)',
  },
  'trust-hierarchy': {
    id: 'trust-hierarchy',
    title: 'Why a trust hierarchy',
    body: 'TODO — see hackmyagent#142. The agent must rank sources: system prompt > user input > tool output > retrieved documents.',
    oneLineRef: '(Why trust hierarchy: see above)',
  },
  'signing-and-pinning': {
    id: 'signing-and-pinning',
    title: 'Why hash-pinning + signing',
    body: 'TODO — see hackmyagent#142. Pinned sha256 hashes prevent skill substitution; Ed25519 signatures bind a skill to a publisher.',
    oneLineRef: '(Why signing: see above)',
  },
};

/** Look up an explainer by concept id. Returns `undefined` if not registered. */
export function getConceptExplainer(id: ConceptId): ConceptExplainer | undefined {
  return CONCEPT_EXPLAINERS[id];
}

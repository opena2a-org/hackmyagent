/**
 * Agent Tier Detection
 *
 * Detects agent tier from SOUL.md / system prompt content by analyzing
 * capability indicators. The tier determines which governance controls
 * are applicable.
 */

import type { AgentTier } from './types';

/**
 * Keyword groups for each tier. Higher tiers subsume lower ones.
 * Detection checks from highest to lowest, returning the first match.
 */
const TIER_INDICATORS: { tier: AgentTier; keywords: string[][] }[] = [
  {
    tier: 'multi-agent',
    keywords: [
      ['sub-agent', 'delegate'],
      ['multi-agent', 'orchestrat'],
      ['agent coordination'],
      ['spawn', 'agent'],
      ['child agent'],
      ['agent-to-agent'],
      ['delegate to', 'agent'],
      ['swarm'],
      ['multi-agent system'],
    ],
  },
  {
    tier: 'agentic',
    keywords: [
      ['autonomous', 'plan'],
      ['multi-step', 'execut'],
      ['autonomous decision'],
      ['self-directed'],
      ['planning', 'execution'],
      ['agent loop'],
      ['iterative', 'reasoning'],
      ['autonomous', 'act'],
      ['chain of thought', 'action'],
      ['goal-directed'],
    ],
  },
  {
    tier: 'tool-using',
    keywords: [
      ['tool', 'use'],
      ['function call'],
      ['tool call'],
      ['api', 'call'],
      ['execute', 'command'],
      ['file', 'read'],
      ['file', 'write'],
      ['search', 'web'],
      ['database', 'query'],
      ['mcp', 'server'],
      ['tool', 'invok'],
    ],
  },
];

/**
 * Detect the agent tier from document content.
 *
 * Checks for multi-agent indicators first (highest tier), then agentic,
 * then tool-using. If none match, defaults to 'basic'.
 *
 * @param content - The SOUL.md or system prompt content to analyze
 * @returns The detected agent tier
 */
export function detectTier(content: string): AgentTier {
  const lower = content.toLowerCase();

  for (const { tier, keywords } of TIER_INDICATORS) {
    for (const group of keywords) {
      if (matchKeywordGroup(lower, group)) {
        return tier;
      }
    }
  }

  return 'basic';
}

/**
 * Get a human-readable label for a tier.
 */
export function getTierLabel(tier: AgentTier): string {
  const labels: Record<AgentTier, string> = {
    'basic': 'Basic (conversational)',
    'tool-using': 'Tool-Using',
    'agentic': 'Agentic (autonomous)',
    'multi-agent': 'Multi-Agent (orchestrated)',
  };
  return labels[tier];
}

/**
 * Get the tier hierarchy level (0 = basic, 3 = multi-agent).
 */
export function getTierLevel(tier: AgentTier): number {
  const levels: Record<AgentTier, number> = {
    'basic': 0,
    'tool-using': 1,
    'agentic': 2,
    'multi-agent': 3,
  };
  return levels[tier];
}

/**
 * Check if all keywords in a group appear within the content.
 * Uses substring matching (case-insensitive, content already lowercased).
 */
function matchKeywordGroup(lowerContent: string, group: string[]): boolean {
  return group.every(kw => lowerContent.includes(kw.toLowerCase()));
}

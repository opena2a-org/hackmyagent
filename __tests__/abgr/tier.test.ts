/**
 * Tests for OASB v2 agent tier detection.
 */

import { describe, it, expect } from 'vitest';
import { detectTier, getTierLabel, getTierLevel } from '../../src/abgr/tier';

describe('detectTier', () => {
  it('defaults to basic for empty content', () => {
    expect(detectTier('')).toBe('basic');
  });

  it('defaults to basic for generic content', () => {
    expect(detectTier('This is a helpful assistant that answers questions.')).toBe('basic');
  });

  it('detects tool-using from "tool use" keywords', () => {
    expect(detectTier('This agent can use tools to search the web and read files.')).toBe('tool-using');
  });

  it('detects tool-using from "function call" keywords', () => {
    expect(detectTier('The agent makes function calls to external APIs.')).toBe('tool-using');
  });

  it('detects tool-using from "api call" keywords', () => {
    expect(detectTier('This agent may make api calls to retrieve data.')).toBe('tool-using');
  });

  it('detects tool-using from "mcp server" keywords', () => {
    expect(detectTier('Configured to connect to an mcp server for tools.')).toBe('tool-using');
  });

  it('detects agentic from "autonomous plan" keywords', () => {
    expect(detectTier('This agent can autonomous plan and execute multi-step tasks.')).toBe('agentic');
  });

  it('detects agentic from "multi-step execution" keywords', () => {
    expect(detectTier('Capable of multi-step execution of complex workflows.')).toBe('agentic');
  });

  it('detects agentic from "self-directed" keyword', () => {
    expect(detectTier('This is a self-directed agent that operates independently.')).toBe('agentic');
  });

  it('detects multi-agent from "sub-agent delegate" keywords', () => {
    expect(detectTier('Can spawn a sub-agent and delegate tasks to it.')).toBe('multi-agent');
  });

  it('detects multi-agent from "multi-agent orchestration" keywords', () => {
    expect(detectTier('Part of a multi-agent orchestration system.')).toBe('multi-agent');
  });

  it('detects multi-agent from "agent-to-agent" keyword', () => {
    expect(detectTier('Supports agent-to-agent communication protocol.')).toBe('multi-agent');
  });

  it('detects multi-agent from "swarm" keyword', () => {
    expect(detectTier('Uses a swarm architecture for distributed processing.')).toBe('multi-agent');
  });

  it('prioritizes higher tier when multiple match', () => {
    // Contains both tool-using and agentic keywords
    const content = 'This agent can use tools via function calls and performs autonomous planning and execution.';
    expect(detectTier(content)).toBe('agentic');
  });

  it('multi-agent takes priority over all others', () => {
    const content = 'A multi-agent orchestration system that uses tools and performs autonomous planning.';
    expect(detectTier(content)).toBe('multi-agent');
  });

  it('is case-insensitive', () => {
    expect(detectTier('This agent uses TOOL CALLS to interact.')).toBe('tool-using');
    expect(detectTier('AUTONOMOUS PLANNING is enabled.')).toBe('agentic');
    expect(detectTier('MULTI-AGENT ORCHESTRATION platform.')).toBe('multi-agent');
  });
});

describe('getTierLabel', () => {
  it('returns correct label for each tier', () => {
    expect(getTierLabel('basic')).toContain('Basic');
    expect(getTierLabel('tool-using')).toContain('Tool');
    expect(getTierLabel('agentic')).toContain('Agentic');
    expect(getTierLabel('multi-agent')).toContain('Multi-Agent');
  });
});

describe('getTierLevel', () => {
  it('basic = 0', () => {
    expect(getTierLevel('basic')).toBe(0);
  });

  it('tool-using = 1', () => {
    expect(getTierLevel('tool-using')).toBe(1);
  });

  it('agentic = 2', () => {
    expect(getTierLevel('agentic')).toBe(2);
  });

  it('multi-agent = 3', () => {
    expect(getTierLevel('multi-agent')).toBe(3);
  });

  it('levels are monotonically increasing', () => {
    expect(getTierLevel('basic')).toBeLessThan(getTierLevel('tool-using'));
    expect(getTierLevel('tool-using')).toBeLessThan(getTierLevel('agentic'));
    expect(getTierLevel('agentic')).toBeLessThan(getTierLevel('multi-agent'));
  });
});

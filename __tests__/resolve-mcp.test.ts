import { describe, it, expect } from 'vitest';
import { resolveMcpShorthand, resolveAndLogMcpShorthand } from '../src/resolve-mcp';

describe('resolveMcpShorthand', () => {
  it('passes through scoped packages unchanged', () => {
    expect(resolveMcpShorthand('@modelcontextprotocol/server-filesystem')).toBe(
      '@modelcontextprotocol/server-filesystem'
    );
    expect(resolveMcpShorthand('@anthropic/claude-mcp')).toBe('@anthropic/claude-mcp');
  });

  it('resolves server-* shorthand', () => {
    expect(resolveMcpShorthand('server-filesystem')).toBe(
      '@modelcontextprotocol/server-filesystem'
    );
    expect(resolveMcpShorthand('server-fetch')).toBe(
      '@modelcontextprotocol/server-fetch'
    );
  });

  it('resolves mcp/server-* shorthand', () => {
    expect(resolveMcpShorthand('mcp/server-filesystem')).toBe(
      '@modelcontextprotocol/server-filesystem'
    );
  });

  it('resolves mcp-server-* shorthand', () => {
    expect(resolveMcpShorthand('mcp-server-fetch')).toBe(
      '@modelcontextprotocol/server-fetch'
    );
    expect(resolveMcpShorthand('mcp-server-slack')).toBe(
      '@modelcontextprotocol/server-slack'
    );
  });

  it('passes through regular package names unchanged', () => {
    expect(resolveMcpShorthand('express')).toBe('express');
    expect(resolveMcpShorthand('langchain')).toBe('langchain');
    expect(resolveMcpShorthand('my-mcp-tool')).toBe('my-mcp-tool');
  });
});

describe('resolveAndLogMcpShorthand', () => {
  it('writes to stderr when resolution changes the name', () => {
    const chunks: string[] = [];
    const origWrite = process.stderr.write;
    process.stderr.write = ((chunk: string) => {
      chunks.push(chunk);
      return true;
    }) as typeof process.stderr.write;

    const result = resolveAndLogMcpShorthand('server-filesystem');

    process.stderr.write = origWrite;

    expect(result).toBe('@modelcontextprotocol/server-filesystem');
    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toContain('Resolved: server-filesystem -> @modelcontextprotocol/server-filesystem');
  });

  it('does not write to stderr when name is unchanged', () => {
    const chunks: string[] = [];
    const origWrite = process.stderr.write;
    process.stderr.write = ((chunk: string) => {
      chunks.push(chunk);
      return true;
    }) as typeof process.stderr.write;

    const result = resolveAndLogMcpShorthand('express');

    process.stderr.write = origWrite;

    expect(result).toBe('express');
    expect(chunks).toHaveLength(0);
  });
});

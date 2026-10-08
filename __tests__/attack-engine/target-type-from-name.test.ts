/**
 * `red-team` reports a target's artifact type from the file NAME (#912).
 *
 * It matched `soul` / `mcp` anywhere in the path, so a `SKILL.md` inside a
 * directory whose name contained either word was reported as that type. The
 * output-hygiene suite writes `SKILL.md` into a `mkdtemp` directory, and once
 * in thousands of runs the random suffix spelled `mcp` and the case read
 * `mcp_tool` back.
 */
import { describe, it, expect } from 'vitest';
import { artifactTypeForTargetPath } from '../../src/attack-engine/target-reader';

describe('artifactTypeForTargetPath (#912)', () => {
  it('ignores the directories the file sits in', () => {
    expect(artifactTypeForTargetPath('/tmp/hma-253-rt-ok-xMCpab/SKILL.md')).toBe('skill');
    expect(artifactTypeForTargetPath('/home/dev/mcp-servers/tools/SKILL.md')).toBe('skill');
    expect(artifactTypeForTargetPath('/srv/soulful/agents/SKILL.md')).toBe('skill');
    expect(artifactTypeForTargetPath('/srv/soul/mcp/prompt.md')).toBe('skill');
  });

  it('still reads the type from the file name', () => {
    expect(artifactTypeForTargetPath('/srv/agents/SOUL.md')).toBe('soul');
    expect(artifactTypeForTargetPath('/srv/agents/mcp.json')).toBe('mcp_tool');
    expect(artifactTypeForTargetPath('/srv/agents/.mcp.json')).toBe('mcp_tool');
    expect(artifactTypeForTargetPath('relative/claude_mcp_config.json')).toBe('mcp_tool');
    expect(artifactTypeForTargetPath('SKILL.md')).toBe('skill');
  });
});

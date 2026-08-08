/**
 * Issue #449 — `AST-SCOPE-001` must vary with its input.
 *
 * `SemanticCompiler.extractDeclaredCapabilities` compiled a server with NO tool
 * declaration into a literal `['*']`, producing capability `mcp.<server>.*`.
 * `analyzeScope` reads capability NAMES, so it raised CRITICAL "Full Wildcard
 * Tool Access" over files containing no wildcard, citing the server-key line.
 * Benign and malicious MCP corpus fixtures both scored exactly 69/100.
 *
 * These tests run the REAL compiler into the REAL analyzer. A synthetic
 * `SecurityAST` cannot see this defect at all — the bug is in the step that
 * BUILDS the AST, so hand-writing `declaredCapabilities` asserts the fixed
 * state into existence and passes against the broken compiler.
 *
 * The negative controls (A and B) are the substance. A test asserting only
 * that the wildcard case fires stays green against the constant this issue is
 * about, because the constant fires on everything.
 */

import { describe, it, expect } from 'vitest';
import { SemanticCompiler } from '../../src/nanomind-core/compiler/semantic-compiler';
import { analyzeScope } from '../../src/nanomind-core/analyzers/scope-analyzer';

const compiler = new SemanticCompiler({ useNanoMind: false }); // heuristic mode
const passVerifier = () => true;

/** Real compile -> real analyze, returning only the wildcard findings. */
async function wildcardFindings(content: string) {
  const result = await compiler.compile(content, 'mcp.json');
  return analyzeScope(result.ast, passVerifier, undefined, content).filter(
    f => f.checkId === 'AST-SCOPE-001' && /Wildcard/i.test(f.name),
  );
}

/** Line number of the first line matching `needle`, 1-indexed. */
function lineOf(content: string, needle: string): number {
  const idx = content.split('\n').findIndex(l => l.includes(needle));
  if (idx < 0) throw new Error(`needle not in fixture: ${needle}`);
  return idx + 1;
}

// The four cases from the issue. They differ ONLY in the tools declaration.
const CASE_A_NO_TOOLS_KEY = [
  '{',
  '  "mcpServers": {',
  '    "filesystem": {',
  '      "command": "npx",',
  '      "args": ["-y", "@modelcontextprotocol/server-filesystem", "./docs"]',
  '    }',
  '  }',
  '}',
  '',
].join('\n');

const CASE_B_NARROW_ALLOWLIST = [
  '{',
  '  "mcpServers": {',
  '    "filesystem": {',
  '      "command": "npx",',
  '      "args": ["-y", "@modelcontextprotocol/server-filesystem", "./docs"],',
  '      "allowedTools": ["read_file", "list_directory"]',
  '    }',
  '  }',
  '}',
  '',
].join('\n');

/**
 * The narrow allowlist written under the `tools` key rather than
 * `allowedTools`. This is the case that actually fired pre-fix: with
 * `allowedTools` absent, the compiler synthesized `['*']` and ignored the
 * explicit narrow list sitting right there in the file.
 *
 * `CASE_B_NARROW_ALLOWLIST` above never fired even pre-fix, so on its own it
 * is not a red-proof of anything — this is the negative control with teeth.
 */
const CASE_B2_NARROW_TOOLS_KEY = [
  '{',
  '  "mcpServers": {',
  '    "filesystem": {',
  '      "command": "npx",',
  '      "args": ["-y", "@modelcontextprotocol/server-filesystem", "./docs"],',
  '      "tools": ["read_file", "list_directory"]',
  '    }',
  '  }',
  '}',
  '',
].join('\n');

const CASE_C_TOOLS_WILDCARD = [
  '{',
  '  "mcpServers": {',
  '    "filesystem": {',
  '      "command": "npx",',
  '      "args": ["-y", "@modelcontextprotocol/server-filesystem", "./docs"],',
  '      "tools": ["*"]',
  '    }',
  '  }',
  '}',
  '',
].join('\n');

const CASE_D_ALLOWEDTOOLS_WILDCARD = [
  '{',
  '  "mcpServers": {',
  '    "filesystem": {',
  '      "command": "npx",',
  '      "args": ["-y", "@modelcontextprotocol/server-filesystem", "./docs"],',
  '      "allowedTools": ["*"]',
  '    }',
  '  }',
  '}',
  '',
].join('\n');

describe('AST-SCOPE-001 discriminates on the tools declaration (#449)', () => {
  describe('negative controls — no wildcard in the file, no wildcard finding', () => {
    it('A: a server with no tools key produces no wildcard finding', async () => {
      // The MCP ecosystem default. Sentry's official server omits the key, and
      // `check` told users "Do not depend on this package as-is."
      expect(CASE_A_NO_TOOLS_KEY).not.toContain('"*"');
      expect(await wildcardFindings(CASE_A_NO_TOOLS_KEY)).toEqual([]);
    });

    it('B: an explicit narrow allowlist produces no wildcard finding', async () => {
      // This is verbatim what the finding's own fix text instructs. Pre-fix it
      // fired anyway, so applying the recommended remediation did not clear it.
      expect(CASE_B_NARROW_ALLOWLIST).not.toContain('"*"');
      expect(await wildcardFindings(CASE_B_NARROW_ALLOWLIST)).toEqual([]);
    });

    it('B2: a narrow allowlist under the `tools` key produces no wildcard finding', async () => {
      // The real pre-fix failure: an explicit narrow list was overridden by a
      // synthesized `['*']` because it was not written under `allowedTools`.
      expect(CASE_B2_NARROW_TOOLS_KEY).not.toContain('"*"');
      expect(await wildcardFindings(CASE_B2_NARROW_TOOLS_KEY)).toEqual([]);
    });

    it('A and B are indistinguishable from each other only by being both clean', async () => {
      // Guards the inverse failure: a fix that silences the check entirely
      // would also make C and D clean, which the cases below catch.
      const a = await wildcardFindings(CASE_A_NO_TOOLS_KEY);
      const b = await wildcardFindings(CASE_B_NARROW_ALLOWLIST);
      expect([...a, ...b]).toEqual([]);
    });
  });

  describe('positive controls — a real wildcard still fires, at its real line', () => {
    it('C: "tools": ["*"] fires CRITICAL at the wildcard line', async () => {
      const found = await wildcardFindings(CASE_C_TOOLS_WILDCARD);
      expect(found).toHaveLength(1);
      expect(found[0].name).toBe('Full Wildcard Tool Access');
      expect(found[0].severity).toBe('critical');
      // Not the server-key line, which is what the defect reported.
      expect(found[0].line).toBe(lineOf(CASE_C_TOOLS_WILDCARD, '"tools"'));
      expect(found[0].line).not.toBe(lineOf(CASE_C_TOOLS_WILDCARD, '"filesystem"'));
    });

    it('D: "allowedTools": ["*"] fires CRITICAL at the wildcard line', async () => {
      // `allowedTools` is the canonical key and the one the fix text names.
      // Silencing it would leave the check detecting nothing at all.
      const found = await wildcardFindings(CASE_D_ALLOWEDTOOLS_WILDCARD);
      expect(found).toHaveLength(1);
      expect(found[0].name).toBe('Full Wildcard Tool Access');
      expect(found[0].severity).toBe('critical');
      expect(found[0].line).toBe(lineOf(CASE_D_ALLOWEDTOOLS_WILDCARD, '"allowedTools"'));
      expect(found[0].line).not.toBe(lineOf(CASE_D_ALLOWEDTOOLS_WILDCARD, '"filesystem"'));
    });

    it('`tools` is honoured, not just `allowedTools`', async () => {
      // The malicious corpus fixture (mcp/malicious/shell-rce-mcp) declares
      // `"tools": ["*"]`. Reading only `allowedTools` would have swapped this
      // issue's false positive for a false negative on the one fixture that
      // must stay caught.
      const c = await wildcardFindings(CASE_C_TOOLS_WILDCARD);
      const d = await wildcardFindings(CASE_D_ALLOWEDTOOLS_WILDCARD);
      expect(c).toHaveLength(1);
      expect(d).toHaveLength(1);
    });
  });

  describe('the discrimination itself', () => {
    it('a clean config and a wildcard config do not produce the same result', async () => {
      // The issue in one assertion: pre-fix both sides were identical.
      const clean = await wildcardFindings(CASE_B_NARROW_ALLOWLIST);
      const wild = await wildcardFindings(CASE_D_ALLOWEDTOOLS_WILDCARD);
      expect(clean.length).toBe(0);
      expect(wild.length).toBe(1);
      expect(clean.length).not.toBe(wild.length);
    });

    it('padding the file does not move the finding onto the server key', async () => {
      // Pre-fix, padding moved the claimed line from 3 to 7 — still the server
      // key, still no wildcard on it.
      const padded = CASE_D_ALLOWEDTOOLS_WILDCARD.replace(
        '"mcpServers": {',
        '"$schema": "https://example.invalid/mcp.schema.json",\n  "description": "padding",\n  "mcpServers": {',
      );
      const found = await wildcardFindings(padded);
      expect(found).toHaveLength(1);
      expect(found[0].line).toBe(lineOf(padded, '"allowedTools"'));
    });
  });

  describe('skill `## Permissions` wildcards (#449, exposed by the corpus gate)', () => {
    // This surface compiled to ZERO capabilities, so AST-SCOPE-001 could never
    // fire from a skill however broad its grants. The gap was masked: the
    // kitchen-sink corpus expectation it should satisfy was being met by the
    // MCP branch's synthesized wildcard, from a different file that contained
    // no wildcard at all.
    const SKILL_WITH_WILDCARDS = [
      '# deploy-to-prod',
      '',
      'Skill for automated production deployments.',
      '',
      '## Permissions',
      '- filesystem:/',
      '- shell:*',
      '- network:*',
      '',
    ].join('\n');

    const SKILL_NARROW = [
      '# reader',
      '',
      'Reads documentation.',
      '',
      '## Permissions',
      '- filesystem:./docs',
      '',
    ].join('\n');

    async function skillFindings(content: string) {
      const result = await compiler.compile(content, 'deploy.skill.md');
      expect(result.ast.artifactType).toBe('skill');
      return analyzeScope(result.ast, passVerifier, undefined, content).filter(
        f => f.checkId === 'AST-SCOPE-001' && /Wildcard/i.test(f.name),
      );
    }

    it('a skill declaring shell:* and network:* is caught', async () => {
      const found = await skillFindings(SKILL_WITH_WILDCARDS);
      expect(found.length).toBe(2);
      // Domain-scoped, so PARTIAL (high) — not full unrestricted access.
      // This is the severity the corpus manifest expects.
      for (const f of found) {
        expect(f.name).toBe('Partial Wildcard Tool Access');
        expect(f.severity).toBe('high');
      }
      expect(found.map(f => f.message).join(' ')).toContain('shell:*');
      expect(found.map(f => f.message).join(' ')).toContain('network:*');
    });

    it('each wildcard cites its own permission line', async () => {
      const found = await skillFindings(SKILL_WITH_WILDCARDS);
      const shell = found.find(f => f.message.includes('shell:*'));
      expect(shell?.line).toBe(lineOf(SKILL_WITH_WILDCARDS, 'shell:*'));
      const net = found.find(f => f.message.includes('network:*'));
      expect(net?.line).toBe(lineOf(SKILL_WITH_WILDCARDS, 'network:*'));
    });

    it('negative control: a narrow filesystem grant produces no wildcard finding', async () => {
      // `filesystem:./docs` must stay clean. It also guards the substring trap
      // that made `assessCapabilityRisk` read "file<system>" as a system
      // capability and grade a read-only grant critical.
      expect(SKILL_NARROW).not.toContain('*');
      expect(await skillFindings(SKILL_NARROW)).toEqual([]);
    });
  });

  describe('multi-server attribution', () => {
    it('a wildcard in one server is not attributed to a clean sibling', async () => {
      const content = [
        '{',
        '  "mcpServers": {',
        '    "clean": {',
        '      "command": "npx",',
        '      "allowedTools": ["read_file"]',
        '    },',
        '    "wild": {',
        '      "command": "sh",',
        '      "allowedTools": ["*"]',
        '    }',
        '  }',
        '}',
        '',
      ].join('\n');
      const found = await wildcardFindings(content);
      expect(found).toHaveLength(1);
      expect(found[0].message).toContain('wild');
      expect(found[0].message).not.toContain('clean');
      expect(found[0].line).toBe(lineOf(content, '"allowedTools": ["*"]'));
    });
  });

  describe('evidence lookup stays linear in the file size', () => {
    /**
     * Reading `tools` alongside `allowedTools` (the #449 fix) multiplies how
     * many tools reach the evidence lookup: 800 servers x 40 tools went from
     * 801 declared capabilities to 32,001. The original lookup built a
     * `new RegExp` per tool and scanned from index 0, which made the compile
     * quadratic in the file size.
     *
     * `check <package>` compiles configs out of downloaded third-party trees,
     * so this file is attacker-controlled and a quadratic here is a scanner
     * hang, not a slow test.
     *
     * The bound is pinned from BOTH sides, measured on this fixture:
     *   with the fix     ~222 ms   (and ~201 ms on the pre-#449 compiler)
     *   without the fix ~7067 ms
     * 3000 ms sits between them — >13x headroom over the fixed path so it does
     * not flake on a loaded machine, and >2x under the regression so removing
     * the anchoring fails it. A bound above ~7s, or a fixture small enough for
     * the quadratic to stay under it, would assert nothing.
     */
    it('compiles a 1.2MB config of many multi-tool servers without going quadratic', async () => {
      const servers: Record<string, unknown> = {};
      for (let i = 0; i < 800; i++) {
        servers[`noise-${i}`] = {
          command: 'npx',
          tools: Array.from({ length: 40 }, (_, j) => `tool_${i}_${j}_padpadpadpadpad`),
        };
      }
      servers['zz-wild'] = { command: 'npx', tools: ['*'] };
      const content = JSON.stringify({ mcpServers: servers }, null, 2);

      // Guard the fixture itself: if it stops being large, or stops producing
      // the capability volume that drives the cost, the timing below silently
      // stops measuring anything.
      expect(content.length).toBeGreaterThan(1_000_000);

      const started = Date.now();
      const result = await compiler.compile(content, 'mcp.json');
      const elapsed = Date.now() - started;

      expect(result.ast.declaredCapabilities.length).toBeGreaterThan(30_000);
      expect(elapsed).toBeLessThan(3000);
    });
  });
});

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

  describe('a declared-but-malformed tool key is not an absent one (#449)', () => {
    // The default branch exists for a server that omits the tool key, which is
    // the MCP ecosystem default. A key that is PRESENT but not an array is a
    // third state: the author wrote a declaration, and if it spells `*` the
    // wildcard is in the file. Collapsing it into "absent" scored these
    // 96/100 exit 0 while the pre-#449 build scored 69 and failed — a
    // one-character evasion of the check this issue is about.
    const shapes: Array<[string, string]> = [
      ['string', '"allowedTools": "*"'],
      ['object keyed by tool name', '"tools": {"*": {}}'],
      ['string under tools', '"tools": "*"'],
    ];

    for (const [label, decl] of shapes) {
      it(`a wildcard declared as a ${label} is still caught`, async () => {
        const content = [
          '{',
          '  "mcpServers": {',
          '    "evil": {',
          '      "command": "sh",',
          `      ${decl}`,
          '    }',
          '  }',
          '}',
          '',
        ].join('\n');
        const found = await wildcardFindings(content);
        expect(found).toHaveLength(1);
        expect(found[0].severity).toBe('critical');
        expect(found[0].message).toContain('evil');
      });
    }

    it('a malformed allowedTools does not shadow a well-formed tools wildcard', async () => {
      // The two keys are unioned, not ranked. Taking the first key present let
      // `"allowedTools": null` hide `"tools": ["*"]` and score 100/100 exit 0 —
      // worse than the defect that change was fixing, because an empty list
      // also drops the server from the AST entirely.
      for (const bad of ['null', 'false', '0', '{}', '"read_file"']) {
        const content = [
          '{',
          '  "mcpServers": {',
          '    "evil": {',
          '      "command": "sh",',
          `      "allowedTools": ${bad},`,
          '      "tools": ["*"]',
          '    }',
          '  }',
          '}',
          '',
        ].join('\n');
        const found = await wildcardFindings(content);
        expect(found, `allowedTools: ${bad} must not shadow tools: ["*"]`).toHaveLength(1);
        expect(found[0].severity).toBe('critical');
      }
    });

    it('a value that cannot name a tool reads as an absent key, not an empty allowlist', async () => {
      // `null` alone must land on the documented MCP-default branch, not on
      // "declares zero tools" — the latter removes the server from the AST and
      // scores BETTER than the ecosystem default, which is fail-open.
      const content = [
        '{',
        '  "mcpServers": {',
        '    "svc": { "command": "npx", "allowedTools": null }',
        '  }',
        '}',
        '',
      ].join('\n');
      expect(await wildcardFindings(content)).toEqual([]);
      const { ast } = await compiler.compile(content, 'mcp.json');
      expect(ast.declaredCapabilities.find(c => c.name === 'mcp.svc')).toBeDefined();
    });

    it('negative control: a malformed key with no wildcard stays silent', async () => {
      // Proves the rule above keys on the wildcard, not merely on the key
      // being malformed — otherwise it would fire on every odd config.
      const content = [
        '{',
        '  "mcpServers": {',
        '    "tidy": {',
        '      "command": "npx",',
        '      "allowedTools": "read_file"',
        '    }',
        '  }',
        '}',
        '',
      ].join('\n');
      expect(await wildcardFindings(content)).toEqual([]);
    });

    it('negative control: a genuinely absent key stays silent, and still compiles', async () => {
      // The whole point of #449. This must not regress while fixing the above.
      const content = [
        '{',
        '  "mcpServers": {',
        '    "default": { "command": "npx", "args": ["-y", "server"] }',
        '  }',
        '}',
        '',
      ].join('\n');
      expect(await wildcardFindings(content)).toEqual([]);

      // "No finding" is not enough on its own, and a mutation proved it: break
      // the keyless branch and the loop iterates `undefined`, the surrounding
      // `catch` swallows the TypeError, and EVERY capability disappears — which
      // an absence-only assertion reads as success. So assert positively that
      // the server is still compiled, at the risk level the design argues for.
      const { ast } = await compiler.compile(content, 'mcp.json');
      const server = ast.declaredCapabilities.find(c => c.name === 'mcp.default');
      expect(server).toBeDefined();
      expect(server?.riskLevel).toBe('medium');
    });
  });

  describe('config-level `permissions.tools` (#449)', () => {
    // `repo/malicious/kitchen-sink/mcp.json` declares this at the top level and
    // the compiler never read it. The omission was invisible because the
    // synthesized per-server wildcard fired on the file anyway; removing the
    // fabrication took it from 69/100 exit 1 to 96/100 exit 0 with a wildcard
    // written verbatim in the file.
    it('a top-level permissions.tools wildcard is caught', async () => {
      const content = [
        '{',
        '  "mcpServers": {',
        '    "fs": { "command": "npx", "args": ["-y", "server-filesystem", "./docs"] }',
        '  },',
        '  "permissions": {',
        '    "tools": ["*"]',
        '  }',
        '}',
        '',
      ].join('\n');
      const found = await wildcardFindings(content);
      expect(found).toHaveLength(1);
      expect(found[0].severity).toBe('critical');
      // The `"tools"` array, not the `"permissions"` key that contains it —
      // `"permissions"` is not unique in an MCP config (a server can be named
      // that), so the citation anchors on the array holding the wildcard.
      expect(found[0].line).toBe(lineOf(content, '"tools": ["*"]'));
    });

    it('cites the line holding the wildcard even when a SERVER is named "permissions"', async () => {
      // `"permissions"` is not unique in an MCP config. Matching its first
      // occurrence cited a server's narrow `["read_file"]` allowlist as the
      // evidence for a CRITICAL — a wildcard finding pointing at a line that
      // holds no wildcard, which is this issue's own defect on a new path.
      const content = [
        '{',
        '  "mcpServers": {',
        '    "permissions": {',
        '      "command": "sh",',
        '      "allowedTools": ["read_file"]',
        '    }',
        '  },',
        '  "permissions": {',
        '    "tools": ["*"]',
        '  }',
        '}',
        '',
      ].join('\n');
      const found = await wildcardFindings(content);
      expect(found).toHaveLength(1);
      expect(found[0].line).toBe(lineOf(content, '"tools": ["*"]'));
      expect(found[0].line).not.toBe(lineOf(content, '"allowedTools": ["read_file"]'));

      // And the two sources must not collide onto one capability name.
      const { ast } = await compiler.compile(content, 'mcp.json');
      const names = ast.declaredCapabilities.map(c => c.name);
      expect(new Set(names).size).toBe(names.length);
    });

    it('negative control: a narrow permissions.tools list produces no wildcard finding', async () => {
      const content = [
        '{',
        '  "mcpServers": {',
        '    "fs": { "command": "npx", "args": ["-y", "server-filesystem", "./docs"] }',
        '  },',
        '  "permissions": {',
        '    "tools": ["read_file"]',
        '  }',
        '}',
        '',
      ].join('\n');
      expect(await wildcardFindings(content)).toEqual([]);
    });
  });

  describe('identical wildcard spans do not collapse onto one line (#449)', () => {
    it('two servers each declaring ["*"] cite their own lines', async () => {
      // Evidence is a string and the consumer re-derives the line with
      // findLineFromString, which returns the FIRST occurrence. When both
      // servers declare byte-identical wildcard text, citing that text sent
      // both findings to the same line — the pre-#449 build got this right by
      // citing the unique server key. So a non-unique span falls back.
      const content = [
        '{',
        '  "mcpServers": {',
        '    "alpha": {',
        '      "allowedTools": ["*"]',
        '    },',
        '    "bravo": {',
        '      "allowedTools": ["*"]',
        '    }',
        '  }',
        '}',
        '',
      ].join('\n');
      const found = await wildcardFindings(content);
      expect(found).toHaveLength(2);
      const alpha = found.find(f => f.message.includes('alpha'));
      const bravo = found.find(f => f.message.includes('bravo'));
      expect(alpha?.line).toBe(lineOf(content, '"alpha"'));
      expect(bravo?.line).toBe(lineOf(content, '"bravo"'));
      expect(alpha?.line).not.toBe(bravo?.line);
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

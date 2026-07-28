/**
 * #281 — CRED-001 and MCP-003 exempted a credential on a SUBSTRING test.
 *
 * CRED-001 tested `line.includes('${' + envVar + '}')` and MCP-003 the even
 * looser `!value.includes('${')`. Appending ` ${ANTHROPIC_API_KEY}` to a live
 * key therefore silenced a CRITICAL finding and moved the score — a one-token
 * suppression available to anyone who can edit the file being scanned, which
 * in a scanner is the attacker's own file.
 *
 * GATEWAY-003 was given an anchored whole-value predicate in 0.25.1; this
 * applies the same discipline to the two checks that still used substrings.
 *
 * Credential values are synthesised at runtime, never written as literals.
 */
import { describe, it, expect } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner, hasCredentialOutsideEnvRef } from '../../src/hardening/scanner';

const LIVE_ANTHROPIC = `sk-ant-api03-${'x'.repeat(40)}`;
const LIVE_GH = `ghp_${'a'.repeat(36)}`;
const ANTHROPIC_RE = /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/;
const AKIA_RE = /AKIA[0-9A-Z]{16}/;

describe('#281 anchored env-ref predicate', () => {
  describe('hasCredentialOutsideEnvRef', () => {
    it('detects a bare live credential', () => {
      expect(hasCredentialOutsideEnvRef(LIVE_ANTHROPIC, ANTHROPIC_RE)).toBe(true);
    });

    it('is NOT fooled by an env reference appended to a live credential', () => {
      // The exact #281 bypass.
      expect(
        hasCredentialOutsideEnvRef(`${LIVE_ANTHROPIC} \${ANTHROPIC_API_KEY}`, ANTHROPIC_RE)
      ).toBe(true);
    });

    it('is NOT fooled by an env reference prepended to a live credential', () => {
      expect(
        hasCredentialOutsideEnvRef(`\${ANTHROPIC_API_KEY} ${LIVE_ANTHROPIC}`, ANTHROPIC_RE)
      ).toBe(true);
    });

    it('exempts a genuine, whole-value env reference', () => {
      expect(hasCredentialOutsideEnvRef('${ANTHROPIC_API_KEY}', ANTHROPIC_RE)).toBe(false);
    });

    it('exempts a variable whose NAME happens to match a credential pattern', () => {
      // AKIA[0-9A-Z]{16} matches inside ${AKIAABCDEFGHIJKLMNOP} because shell
      // identifiers are alphanumeric. Removing the exemption outright would
      // invent a false positive on a legitimately-referenced variable.
      expect(hasCredentialOutsideEnvRef('${AKIAABCDEFGHIJKLMNOP}', AKIA_RE)).toBe(false);
    });

    it('does not accept a malformed reference as an exemption', () => {
      // `${FOO` has no closing brace, so it is not a reference at all.
      expect(hasCredentialOutsideEnvRef(`\${FOO ${LIVE_ANTHROPIC}`, ANTHROPIC_RE)).toBe(true);
    });

    it('does not accept a braced credential as an exemption', () => {
      // `${sk-ant-…}` is not a shell identifier — it is a key in braces.
      expect(hasCredentialOutsideEnvRef(`\${${LIVE_ANTHROPIC}}`, ANTHROPIC_RE)).toBe(true);
    });

    it('is not order-dependent across calls with a global pattern', () => {
      // A shared /g regex carries lastIndex; a stateful predicate would
      // alternate true/false on identical input.
      const g = /ghp_[a-zA-Z0-9]{36}/g;
      expect(hasCredentialOutsideEnvRef(LIVE_GH, g)).toBe(true);
      expect(hasCredentialOutsideEnvRef(LIVE_GH, g)).toBe(true);
      expect(hasCredentialOutsideEnvRef(LIVE_GH, g)).toBe(true);
    });
  });

  describe('CRED-001 end to end', () => {
    async function scoreFor(configBody: string) {
      const dir = await mkdtemp(path.join(tmpdir(), 'hma-281-'));
      try {
        await writeFile(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
        await writeFile(path.join(dir, 'config.json'), configBody);
        const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
        return {
          score: result.score,
          fires: result.findings.some((f) => f.checkId === 'CRED-001' && !f.passed),
        };
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    }

    it('still fires when an env reference is appended to a live key', async () => {
      const bare = await scoreFor(JSON.stringify({ apiKey: LIVE_ANTHROPIC }) + '\n');
      const bypass = await scoreFor(
        JSON.stringify({ apiKey: `${LIVE_ANTHROPIC} \${ANTHROPIC_API_KEY}` }) + '\n'
      );
      expect(bare.fires, 'baseline must fire').toBe(true);
      expect(bypass.fires, 'appending ${ENV} suppressed a CRITICAL').toBe(true);
      // And the suppression must not have bought a better score either.
      expect(bypass.score).toBe(bare.score);
    });

    it('does not fire on a properly referenced credential', async () => {
      const clean = await scoreFor(JSON.stringify({ apiKey: '${ANTHROPIC_API_KEY}' }) + '\n');
      expect(clean.fires).toBe(false);
    });
  });

  describe('MCP-003 end to end', () => {
    async function mcpFires(envValue: string) {
      const dir = await mkdtemp(path.join(tmpdir(), 'hma-281-mcp-'));
      try {
        // MCP-* checks are project-type gated (`'MCP-': ['mcp']`), so the
        // fixture must actually type as an MCP server. A bare package.json
        // types as generic and MCP-003 never runs — which reads as "the check
        // is dead" rather than "the fixture is wrong".
        await writeFile(
          path.join(dir, 'package.json'),
          JSON.stringify({
            name: 'p',
            version: '1.0.0',
            dependencies: { '@modelcontextprotocol/sdk': '^1.30.0' },
          }) + '\n'
        );
        await writeFile(
          path.join(dir, 'mcp.json'),
          JSON.stringify(
            { servers: { demo: { command: 'node', env: { ANTHROPIC_API_KEY: envValue } } } },
            null,
            2
          )
        );
        const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
        return result.findings.some((f) => f.checkId === 'MCP-003' && !f.passed);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    }

    it('fires on a bare live key', async () => {
      expect(await mcpFires(LIVE_ANTHROPIC)).toBe(true);
    });

    it('still fires when ${...} appears anywhere in the value', async () => {
      // MCP-003's guard was `!value.includes('${')` — looser than CRED-001's.
      expect(await mcpFires(`${LIVE_ANTHROPIC} \${ANTHROPIC_API_KEY}`)).toBe(true);
    });

    it('does not fire on a properly referenced value', async () => {
      expect(await mcpFires('${ANTHROPIC_API_KEY}')).toBe(false);
    });
  });
});

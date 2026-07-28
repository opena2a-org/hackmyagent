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
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner, hasCredentialOutsideEnvRef } from '../../src/hardening/scanner';

const LIVE_ANTHROPIC = `sk-ant-api03-${'x'.repeat(40)}`;
const LIVE_GH = `ghp_${'a'.repeat(36)}`;
const ANTHROPIC_RE = /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/;
const AKIA_RE = /AKIA[0-9A-Z]{16}/;
const GH_RE = /ghp_[a-zA-Z0-9]{36}/;

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

    it('exempts the reference syntax CRED-001\'s own fix writes', () => {
      // The exemption exists for these, and they are what must keep working:
      // a real variable name, including every name the auto-fix emits. None
      // is credential-shaped, so #301 does not touch them.
      expect(hasCredentialOutsideEnvRef('${ANTHROPIC_API_KEY}', ANTHROPIC_RE)).toBe(false);
      expect(hasCredentialOutsideEnvRef('${GITHUB_TOKEN}', GH_RE)).toBe(false);
      expect(hasCredentialOutsideEnvRef('${AWS_ACCESS_KEY_ID}', AKIA_RE)).toBe(false);
    });

    it('does not exempt a credential that has BECOME the reference', () => {
      // This assertion is the inverse of the one it replaces, which read
      // "exempts a variable whose NAME happens to match a credential
      // pattern" and pinned `${AKIAABCDEFGHIJKLMNOP}` to false. That case is
      // real, but it is not distinguishable from a live key in braces — and
      // the version that shipped chose the wrong side of it:
      //
      //   {"token":"ghp_aaa…"}      69/100, CRED-001 fires
      //   {"token":"${ghp_aaa…}"}   96/100, CRED-001 silent
      //
      // Two braces removed a CRITICAL, from inside the attacker's own file:
      // the exact one-token suppression #281 was filed about. A reference
      // wraps a NAME; a span whose name is itself credential-shaped is a
      // value wearing reference syntax, and earns no exemption.
      expect(hasCredentialOutsideEnvRef(`\${${LIVE_GH}}`, GH_RE)).toBe(true);
      expect(hasCredentialOutsideEnvRef('${AKIAABCDEFGHIJKLMNOP}', AKIA_RE)).toBe(true);
    });

    it('covers every identifier-legal pattern, not just the reported one', () => {
      // Five of the ten CREDENTIAL_PATTERNS are built entirely from
      // characters a shell identifier admits, so all five fit inside the
      // exemption span. The other five carry `-` or `.` and never could,
      // which is why a green suite meant nothing here. Fixing only `ghp_`
      // would have left four live bypasses behind.
      const identifierLegal: Array<[string, string, RegExp]> = [
        ['ghp_', LIVE_GH, GH_RE],
        ['github_pat_', `github_pat_${'a'.repeat(22)}_${'b'.repeat(59)}`,
          /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/],
        ['sk_live_', `sk_live_${'c'.repeat(24)}`, /sk_live_[0-9a-zA-Z]{24,}/],
        ['AKIA', `AKIA${'D'.repeat(16)}`, AKIA_RE],
        ['AIza (dash-free)', `AIza${'e'.repeat(35)}`, /AIza[0-9A-Za-z_-]{35}/],
      ];
      for (const [label, value, re] of identifierLegal) {
        expect(hasCredentialOutsideEnvRef(value, re), `${label}: baseline must fire`).toBe(true);
        expect(
          hasCredentialOutsideEnvRef(`\${${value}}`, re),
          `${label}: wrapping the key in braces suppressed it`,
        ).toBe(true);
      }
    });

    it('is not fooled by padding the name around the key', () => {
      // If the rule were "the whole identifier is the credential", a
      // one-character prefix would walk straight back through it.
      expect(hasCredentialOutsideEnvRef(`\${MY_${LIVE_GH}}`, GH_RE)).toBe(true);
      expect(hasCredentialOutsideEnvRef(`\${${LIVE_GH}_PROD}`, GH_RE)).toBe(true);
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

    it('#301 — braces around the key buy neither silence nor a better score', async () => {
      const bare = await scoreFor(JSON.stringify({ token: LIVE_GH }) + '\n');
      const braced = await scoreFor(JSON.stringify({ token: `\${${LIVE_GH}}` }) + '\n');
      expect(bare.fires, 'baseline must fire').toBe(true);
      expect(braced.fires, 'wrapping the key in ${} suppressed a CRITICAL').toBe(true);
      // The score is the half a user reads. 69 -> 96 was the shipped payoff
      // for typing two characters.
      expect(
        braced.score,
        `wrapping the key scored ${braced.score} against a bare ${bare.score}`,
      ).toBe(bare.score);
    });

    it('#301 — the fix unwraps the braces instead of nesting inside them', async () => {
      // Replacing only the inner match yields `"${${GITHUB_TOKEN}}"`, which
      // no shell expands and no reader wants. The finding is only half the
      // job; the repair has to leave a usable file.
      const dir = await mkdtemp(path.join(tmpdir(), 'hma-301-fix-'));
      try {
        await writeFile(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
        const target = path.join(dir, 'config.json');
        await writeFile(target, JSON.stringify({ token: `\${${LIVE_GH}}` }) + '\n');

        await new HardeningScanner().scan({ targetDir: dir, autoFix: true });

        const fixed = await readFile(target, 'utf-8');
        expect(fixed, 'the credential survived the fix').not.toContain(LIVE_GH);
        expect(fixed, 'the fix nested one reference inside another').not.toContain('${${');
        expect(fixed).toContain('${GITHUB_TOKEN}');
        // Still valid JSON — a config file the tool repaired has to load.
        expect(() => JSON.parse(fixed)).not.toThrow();
        expect(JSON.parse(fixed).token).toBe('${GITHUB_TOKEN}');
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
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

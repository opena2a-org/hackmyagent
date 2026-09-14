/**
 * `red-team <target> --json` must not echo the credentials it read
 * (advertised-command audit 2026-09-13, lane F).
 *
 * Measured on 0.33.0: `red-team ./.mcp.json --json` on a config whose first
 * long line is a `postgresql://user:password@host/db` connection string put
 * that line, password included, into `target.declaredPurpose`. The reader
 * treats the artifact as flat text, so the same text reaches `capabilities`,
 * `modalStatements`, `vulnerabilitySurface[].surface` and, through the payload
 * generator, every `results[].payloadInput`.
 *
 * The fix redacts the whole artifact at the REPORT boundary before any
 * extraction (the shape NanoMind's `extractDeclaredPurpose` already uses), plus
 * the one shape that boundary does not carry: userinfo in a URL of any scheme.
 */
import { describe, it, expect } from 'vitest';
import { readTarget } from '../../src/attack-engine/target-reader';
import { runAttackSession } from '../../src/attack-engine/feedback-loop';

const PASSWORD = 'S3cretLedgerPass-9x7Q';
const SLACK = 'xoxb-' + '2837465019-4827364510-DEMOfinanceBotTokenA1b2C3d4';
const MCP_CONFIG = `{
  "mcpServers": {
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://finance_rw:${PASSWORD}@finance-db.internal:5432/ledger"]
    },
    "reports": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-fetch", "https://svc-user:${PASSWORD}@reports.internal/api"]
    },
    "slack": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-slack"],
      "env": { "SLACK_BOT_TOKEN": "${SLACK}", "SLACK_TEAM_ID": "T02FINANCE" }
    }
  }
}
`;

describe('red-team target reader redaction', () => {
  it('declaredPurpose carries no credential from an MCP config', () => {
    const profile = readTarget(MCP_CONFIG, 'mcp_server', 'mcp.json');

    expect(profile.declaredPurpose).not.toContain(PASSWORD);
    expect(profile.declaredPurpose).toContain('[REDACTED');
    expect(profile.redaction).toEqual({ status: 'applied', shapes: expect.arrayContaining(['url-credential']) });
  });

  it('no field of the profile echoes a password or a token', () => {
    const profile = readTarget(MCP_CONFIG, 'mcp_server', 'mcp.json');
    const serialized = JSON.stringify(profile);

    expect(serialized).not.toContain(PASSWORD);
    expect(serialized).not.toContain(SLACK);
    expect(serialized).not.toContain(`finance_rw:${PASSWORD}`);
  });

  it('userinfo is masked for any URL scheme, and the host stays for the surface map', () => {
    const profile = readTarget(
      `description: Fetches nightly totals from https://svc-user:${PASSWORD}@reports.internal/api and posts them.\n`,
      'skill',
      'nightly',
    );

    expect(profile.declaredPurpose).not.toContain(PASSWORD);
    expect(profile.declaredPurpose).toContain('https://[REDACTED_URL_CREDENTIAL]@reports.internal/api');
  });

  it('a benign artifact is untouched and reports a clean redaction', () => {
    const profile = readTarget(
      `---\ndescription: Customer service chatbot\n---\nHelps customers with support tickets.\nMust never share customer data externally.\n`,
      'skill',
      'support-bot',
    );

    expect(profile.declaredPurpose).toBe('Customer service chatbot');
    expect(profile.redaction).toEqual({ status: 'clean', shapes: [] });
  });

  it('the JSON a --json run prints carries no credential, payloads included', async () => {
    const result = await runAttackSession(MCP_CONFIG, 'mcp_server', 'mcp.json', { maxIterations: 2 });
    const serialized = JSON.stringify(result);

    expect(serialized).not.toContain(PASSWORD);
    expect(serialized).not.toContain(SLACK);
  });
});

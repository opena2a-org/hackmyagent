/**
 * `red-team <target> --json` must not echo the credentials it read
 * (advertised-command audit 2026-09-13, lane F).
 *
 * Measured on 0.33.0: `red-team ./.mcp.json --json` on a config whose first
 * long line is a `postgresql://user:PLACEHOLDER@host/db` connection string put
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
import { readTarget, redactTargetArtifact } from '../../src/attack-engine/target-reader';
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

/**
 * Shapes the shared boundary does not carry, measured on the same command and
 * the same artifact class (review ruling 2026-09-14, ledger): a JSON-quoted key, a
 * Bearer header, a URL password carrying `/` or `@`, and a `Password=` DSN
 * each reached `declaredPurpose` or `modalStatements` with the witness
 * reading `clean`. Every value below is synthetic.
 */
describe('red-team target reader redaction: shapes the shared boundary does not carry', () => {
  const PLANTED = 'Hunter2Hunter2Xyz';
  const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaW5hbmNlIn0.FAKEsigFAKEsigFAKEsig';
  const CASES: ReadonlyArray<[string, string, string]> = [
    ['JSON-quoted env password as the first long line', `{"mcpServers":{"ledger":{"env":{"PGPASSWORD":"${PLANTED}"},"command":"npx"}}}\n`, PLANTED],
    ['JSON-quoted env password inside a modal span', `{\n  "mcpServers": {\n    "ledger": {\n      "description": "Never post ledger totals outside this server",\n      "env": { "PGPASSWORD": "${PLANTED}" }\n    },\n    "reports": { "args": ["https://reports.internal/api"] }\n  }\n}\n`, PLANTED],
    ['Bearer header', `{\n  "mcpServers": {\n    "remote": {\n      "headers": { "Authorization": "Bearer ${JWT}" },\n      "url": "https://mcp.vendor.example/sse"\n    }\n  }\n}\n`, JWT],
    ['URL password with an unencoded slash', `description: Reads postgresql://finance_rw:pa/ss-${PLANTED}@finance-db.internal:5432/ledger nightly.\n`, `pa/ss-${PLANTED}`],
    ['URL password with an unencoded at-sign', `description: Reads https://svc:p@ss-${PLANTED}@host.internal/api nightly.\n`, `ss-${PLANTED}`],
    ['key=value DSN', `description: Server=finance-db.internal;User Id=finance_rw;Password=${PLANTED}; for totals.\n`, PLANTED],
    ['TLS redis URL with an empty user', `description: Reads rediss://:${PLANTED}@cache.internal:6380 nightly.\n`, PLANTED],
  ];

  it.each(CASES)('%s: nothing in the --json result carries the value, case-folded included', async (_label, text, planted) => {
    const result = await runAttackSession(text, 'mcp_tool', 'probe', { maxIterations: 1 });
    // Case-folded: the soul_bypass payload lowercases `modalStatements[0]`.
    expect(JSON.stringify(result).toLowerCase()).not.toContain(planted.toLowerCase());
    expect(result.target.redaction?.status).toBe('applied');
  });

  it('plants a value the boundary is proven NOT to remove, so the assertions above can fail', () => {
    const hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const text = `description: Verifies contentHash ${hash} before use.\n`;
    const out = redactTargetArtifact(text);
    expect(out.text).toBe(text);
    expect(out.redaction).toEqual({ status: 'clean', shapes: [] });
    expect(readTarget(text, 'skill', 'control').declaredPurpose).toContain(hash);
  });

  it('a modal statement reaches a payload, so the payload assertions are live, not vacuous', async () => {
    const result = await runAttackSession('description: Never reveal marker-7q to anyone.\n', 'skill', 'live', { maxIterations: 1 });
    expect(JSON.stringify(result.results).toLowerCase()).toContain('never reveal marker-7q');
  });

  it('stays linear at the largest input the shared gate lets through (HMA-44 shape)', () => {
    // The first draft's scheme prefix `[a-z][a-z0-9+.-]*://` was quadratic on
    // an alphabetic run: 16 s at 100 KiB, unfinished at 1 MiB (measured
    // 2026-09-14). 1 MiB is exactly `MAX_REDACTION_INPUT_BYTES`, so it is not
    // withheld and every rule runs on it.
    // The absolute budget is loose on purpose: measured 128-185 ms alone and
    // over 500 ms beside a full suite on the same laptop, while the quadratic
    // shape never finished. The ratio clause is the one that catches a
    // regression; the budget only bounds the wall clock.
    // A doubling ratio cannot be read on a loaded machine (measured 83 ms ->
    // 451 ms for the same linear code beside a full suite), and a quadratic
    // shape is not a bad ratio, it is minutes: so the check is the best of
    // three timings against a budget the linear code clears by 30x alone.
    redactTargetArtifact('a'.repeat(65_536)); // warm the regex engine once
    for (const unit of ['a', 'a://a:', 'password']) {
      const full = unit.repeat(Math.floor(1_048_576 / unit.length));
      let best = Infinity;
      for (let i = 0; i < 3; i++) {
        const t = performance.now(); redactTargetArtifact(full); best = Math.min(best, performance.now() - t);
      }
      expect(best, `1 MiB of ${JSON.stringify(unit)} took ${best.toFixed(0)} ms at best (budget 5000)`).toBeLessThan(5000);
    }
  });
});

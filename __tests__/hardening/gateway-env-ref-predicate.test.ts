// GATEWAY-003's env-reference predicate: both directions.
//
// The check must stay quiet on its OWN remedy — the auto-fix writes
// `${OPENCLAW_AUTH_TOKEN}`, a non-empty string, and an earlier build re-fired
// on it forever so `fixVerified` was permanently false. The first predicate
// written for that accepted `${[^}]+}`: ANY braced content.
//
// So `${sk-ant-api03-<key>}` read as a reference and the check went silent on
// a config with a real key in it. A `${...}` wrapper does not un-leak a
// secret. Whether or not the gateway expands it at runtime, the bytes are on
// disk for anyone who can read the file, and "the app would not have
// authenticated with it anyway" is not the standard a credential scanner
// holds itself to.
//
// The bare form had the matching hole: `$ghp_<36>` is a syntactically valid
// reference to a variable *named* after a token.
//
// Contract: a reference is a `$NAME` / `${NAME}` shell identifier and nothing
// else, and a name opening with a known secret prefix is plaintext.

import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';

const dirs: string[] = [];

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

/** An OpenClaw gateway config carrying `token` at `gateway.auth.token`. */
function withGatewayToken(token: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'hma-envref-'));
  dirs.push(dir);
  mkdirSync(join(dir, '.openclaw'), { recursive: true });
  writeFileSync(
    join(dir, '.openclaw', 'config.json'),
    JSON.stringify({ gateway: { auth: { token } } }, null, 2),
  );
  writeFileSync(join(dir, 'package.json'), '{"name":"envref","version":"1.0.0"}\n');
  return dir;
}

async function gateway003Fires(token: string): Promise<boolean> {
  const dir = withGatewayToken(token);
  const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
  const all = result.allFindings ?? result.findings;
  return all.some(f => f.checkId === 'GATEWAY-003' && !f.passed);
}

describe('GATEWAY-003 env-reference predicate', { timeout: 240_000 }, () => {
  it('stays quiet on a genuine reference, including its own remedy', async () => {
    // If this direction breaks, the check re-fires on the file it just
    // repaired and `fixVerified` can never become true.
    expect(await gateway003Fires('${OPENCLAW_AUTH_TOKEN}')).toBe(false);
    expect(await gateway003Fires('$OPENCLAW_AUTH_TOKEN')).toBe(false);
    expect(await gateway003Fires('${my_gateway_token}')).toBe(false);
  });

  it('still fires when a credential is only wrapped in reference syntax', async () => {
    // Pre-fix these were silently accepted as references.
    expect(await gateway003Fires('${sk-ant-api03-' + 'A'.repeat(24) + '}')).toBe(true);
    expect(await gateway003Fires('$ghp_' + 'b'.repeat(36))).toBe(true);
    expect(await gateway003Fires('${AKIA' + 'C'.repeat(16) + '}')).toBe(true);
  });

  it('still fires on plaintext and on malformed reference syntax', async () => {
    expect(await gateway003Fires('plaintext-token-value')).toBe(true);
    // Mismatched braces are malformed, not a reference.
    expect(await gateway003Fires('${OPENCLAW_AUTH_TOKEN')).toBe(true);
    // A reference with a trailing payload is not "only" a reference.
    expect(await gateway003Fires('${OPENCLAW_AUTH_TOKEN} extra')).toBe(true);
  });
});

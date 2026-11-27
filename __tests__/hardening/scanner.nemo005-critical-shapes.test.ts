import { describe, it, expect, beforeEach } from 'vitest';
import { HardeningScanner } from '../../src/hardening/scanner';
import * as fs from 'fs/promises';
import * as path from 'path';
import { tempDir } from '../helpers/temp-dir';

// NEMO-005 reports exec() / execSync() whose template literal interpolates an
// expression naming one of: name, id, input, arg, param, flag, option (any
// case). Each fixture below is written to a temporary folder, scanned with no
// ignore file and no option, and must be reported at critical on its line.
describe('NEMO-005 reports at critical', () => {
  let scanner: HardeningScanner;
  let dir: string;

  beforeEach(() => {
    scanner = new HardeningScanner();
    dir = tempDir('hma-nemo005-shapes-');
  });

  async function nemo005(relPath: string, source: string) {
    const file = path.join(dir, relPath);
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, source);
    const result = await scanner.scan({ targetDir: dir });
    return result.findings.filter((f) => f.checkId === 'NEMO-005' && !f.passed);
  }

  function expectCritical(
    hits: Awaited<ReturnType<typeof nemo005>>,
    relPath: string,
    line: number,
  ) {
    expect(hits).toHaveLength(1);
    expect(hits[0].checkId).toBe('NEMO-005');
    expect(hits[0].severity).toBe('critical');
    expect(hits[0].file).toBe(relPath);
    expect(hits[0].line).toBe(line);
  }

  it('a call to a local function named like a path helper, with literal arguments', async () => {
    // The interpolated expression is `basename('/opt/tool/bin')`; the rule
    // reports it for `name` in `basename`.
    const ts = [
      "import { exec } from 'child_process';",
      'function basename(p: string): string {',
      "  return p.split('/').pop() ?? '';",
      '}',
      "exec(`ls /usr/local/${basename('/opt/tool/bin')}`);",
    ].join('\n');
    expectCritical(await nemo005('helper.ts', ts), 'helper.ts', 5);
  });

  it('a parameter after parentheses in the parameter list, named like a top-level constant', async () => {
    // The interpolated expression is `appName`, a parameter that shares its
    // name with the file's top-level constant. The parameter is declared with
    // a type and no default value, after a parameter whose type carries
    // parentheses. The rule reports it for `Name`.
    const ts = [
      "import { exec } from 'child_process';",
      "const appName = 'demo';",
      'export function deploy(done: (err: Error | null) => void, appName: string) {',
      '  exec(`deploy --app ${appName}`, (err) => done(err));',
      '}',
    ].join('\n');
    expectCritical(await nemo005('deploy.ts', ts), 'deploy.ts', 4);
  });

  it('a file whose path marks it as a test', async () => {
    // The interpolated expression is `pkgName`; the rule reports it for `Name`.
    const rel = path.join('__tests__', 'view.test.ts');
    const ts = [
      "import { execSync } from 'child_process';",
      'export function view(pkgName: string) {',
      '  return execSync(`npm view ${pkgName}`);',
      '}',
    ].join('\n');
    expectCritical(await nemo005(rel, ts), rel, 3);
  });
});

/**
 * A keyword argument that forwards a variable of the same name is not a
 * hardcoded secret.
 *
 * Reported: a four-line `report.py` whose call passes
 * `tokenizer_provenance=tokenizer_provenance, split_meta=split_meta,` drew a
 * HIGH `AST-CRED-003 Hardcoded Secret` on that line. The high-entropy
 * fallback's class carries `=`, so `name=name` is one 41-character run, and
 * the credential noun inside `tokenizer` licensed it.
 *
 * The rule is narrow on purpose: only a value that repeats its name is skipped.
 * An unquoted value that differs from its name is still a literal where the
 * file format says so, and `DB_PASSWORD=my_super_secret_database_password`
 * keeps its finding.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { findCredentialFormatMatch } from '../../src/types/credential-format';

beforeAll(assertDistFreshIfPresent);

const REPORT_PY = [
  'def write_report(tokenizer_provenance, split_meta):',
  '    return build(',
  '        tokenizer_provenance=tokenizer_provenance,',
  '        split_meta=split_meta,)',
  '',
].join('\n');

// Assembled at runtime so no credential-shaped literal sits in this source for
// HMA's own self-scan.
const LITERAL_LINE = ['DB_PASSWORD', 'my_super_secret_database_password'].join('=');

function secureCi(target: string) {
  const res = spawnSync(process.execPath, [CLI, 'secure', target, '--ci', '--json'], {
    encoding: 'utf-8',
    timeout: 240_000,
    env: {
      ...process.env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: tempDir('hma-same-name-home-'),
    },
  });
  const stdout = res.stdout ?? '';
  const body = JSON.parse(stdout.slice(stdout.indexOf('{')));
  const cred003 = (body.findings as Array<Record<string, unknown>>).filter(
    (f) => f.checkId === 'AST-CRED-003' && f.passed === false,
  );
  return { status: res.status, cred003 };
}

describe('credential-format: a same-name binding is not a credential value', () => {
  it('skips `name=name` runs', () => {
    expect(findCredentialFormatMatch('tokenizer_provenance=tokenizer_provenance,')).toBeUndefined();
    expect(findCredentialFormatMatch(REPORT_PY)).toBeUndefined();
  });

  it('still reports an unquoted literal whose value differs from its name', () => {
    expect(findCredentialFormatMatch(LITERAL_LINE)?.value).toBe(LITERAL_LINE);
    expect(findCredentialFormatMatch(`${LITERAL_LINE}\n`)).toBeDefined();
  });

  it('a same-name run does not hide a real value after it', () => {
    const text = `tokenizer_provenance=tokenizer_provenance\n${LITERAL_LINE}\n`;
    expect(findCredentialFormatMatch(text)?.value).toBe(LITERAL_LINE);
  });
});

describe('secure --ci: AST-CRED-003 on a same-name keyword argument', () => {
  it('the four-line report.py gives no AST-CRED-003 and exits 0', () => {
    const target = tempDir('hma-same-name-');
    fs.writeFileSync(path.join(target, 'report.py'), REPORT_PY);
    const { status, cred003 } = secureCi(target);
    expect(cred003).toEqual([]);
    expect(status).toBe(0);
  });

  it('a literal secret beside it is still flagged', () => {
    const target = tempDir('hma-same-name-');
    fs.writeFileSync(path.join(target, 'report.py'), REPORT_PY);
    fs.writeFileSync(path.join(target, 'settings.conf'), `DB_HOST=localhost\n${LITERAL_LINE}\n`);
    const { status, cred003 } = secureCi(target);
    expect(cred003.map((f) => `${f.file}:${f.line}`)).toEqual(['settings.conf:2']);
    expect(status).not.toBe(0);
  });
});

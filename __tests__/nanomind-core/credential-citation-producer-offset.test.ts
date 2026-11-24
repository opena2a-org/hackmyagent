/**
 * #497 — credential findings cite the value the producer matched, not a
 * re-searched lookalike.
 *
 * AST-CRED-001 derived its line by searching the file again for the leftmost
 * credential-SHAPED string, so a SHA-256 digest above the real key took the
 * citation. The canonical credential scan already records the offset of every
 * value it matches; both CRED findings now cite the leftmost of those offsets.
 *
 * An earlier attempt at this was withdrawn because each fix broke another
 * case, so the four are pinned here TOGETHER, on one shared fixture layout:
 *
 *   1. a digest above a real key does not take the citation;
 *   2. a PEM armor header used as a string constant does not take it (the PEM
 *      shape now matches the whole block and asks the body for key material,
 *      so a lone header is not a match at all);
 *   3. a real PEM private key still gets a citation (a freshly generated RSA
 *      key, so the body is whatever node:crypto produces — `/` and `+` included);
 *   4. an AWS secret access key containing `/` still gets one (the shared
 *      format matcher reads no 40-character alphanumeric run in it, which used
 *      to drop both findings).
 *
 * Every line assertion runs unconditionally: no `if (finding)` guard lets a
 * missing finding pass as "nothing to check".
 *
 * Keys are generated or assembled at run time and live only in temp trees, so
 * no committed line carries a credential-shaped literal.
 */

import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';

import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import { scanCanonicalCredentialFormatsForTest } from '../../src/nanomind-core/compiler/semantic-compiler';
import { generateVerifyCommand } from '../../src/ui/verify-command';
import { tempDir } from '../helpers/temp-dir';

const ALNUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

/** Deterministic string over `alphabet` from a fixed seed (a plain LCG, not randomness). */
function synth(seed: number, length: number, alphabet = ALNUM): string {
  let state = seed >>> 0;
  let out = '';
  for (let i = 0; i < length; i++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    out += alphabet[(state >>> 8) % alphabet.length];
  }
  return out;
}

const PEM_HEADER = ['-----BEGIN', 'RSA', 'PRIVATE', 'KEY-----'].join(' ');

function rsaPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return (privateKey.export({ type: 'pkcs1', format: 'pem' }) as string).trimEnd();
}

const OPENAI_KEY = 'sk-' + synth(20260810, 52);
const DIGEST = createHash('sha256').update('bundle').digest('hex');
// 40 characters with a `/` in the middle, so no 40-character alphanumeric run.
const AWS_SECRET = synth(7, 18, `${ALNUM}/+`) + '/' + synth(9, 21, `${ALNUM}/+`);
const AWS_NAME = ['aws', 'secret', 'access', 'key'].join('_');

/** The value sits on line 5 of every fixture; lines 1-4 hold the decoys. */
const VALUE_LINE = 5;

const CASES: Record<string, { lines: string[]; decoyLine?: number }> = {
  'digest above a real key': {
    lines: [
      '// Bundle configuration.',
      "export const SERVICE = 'widget-router';",
      `export const BUNDLE_DIGEST = '${DIGEST}';`,
      '',
      `export const openaiApiKey = '${OPENAI_KEY}';`,
      'export const client = { openaiApiKey };',
      '',
    ],
    decoyLine: 3,
  },
  'PEM header as a string constant above a real key': {
    lines: [
      '// Key-file sniffing helpers.',
      "export const SERVICE = 'widget-router';",
      `export const PEM_HEADER = '${PEM_HEADER}';`,
      '',
      `export const openaiApiKey = '${OPENAI_KEY}';`,
      'export const isKeyFile = (s: string) => s.startsWith(PEM_HEADER);',
      '',
    ],
    decoyLine: 3,
  },
  'a real PEM private key': {
    lines: [
      '// Release signer.',
      "export const SERVICE = 'widget-router';",
      '',
      '',
      ...`export const SIGNING_KEY = \`${rsaPem()}\`;`.split('\n'),
      'export const signer = { SIGNING_KEY };',
      '',
    ],
  },
  'an AWS secret containing /': {
    lines: [
      '// AWS client settings.',
      "export const SERVICE = 'widget-router';",
      "export const REGION = 'us-east-1';",
      '',
      `export const ${AWS_NAME} = '${AWS_SECRET}';`,
      'export const client = { region: REGION };',
      '',
    ],
  },
};

describe('#497: both credential findings cite the producer-located value', () => {
  it('the fixtures are what the cases claim', () => {
    expect(AWS_SECRET).toHaveLength(40);
    expect(AWS_SECRET).toContain('/');
    expect(CASES['digest above a real key'].lines[VALUE_LINE - 1]).toContain(OPENAI_KEY);
    expect(CASES['a real PEM private key'].lines[VALUE_LINE - 1]).toContain(PEM_HEADER);
    expect(CASES['an AWS secret containing /'].lines[VALUE_LINE - 1]).toContain(AWS_SECRET);
  });

  for (const [name, { lines, decoyLine }] of Object.entries(CASES)) {
    it(`${name}: AST-CRED-001 and AST-CRED-003 cite line ${VALUE_LINE} with a Verify command`, async () => {
      const dir = tempDir('hma-cred-cite-');
      await mkdir(join(dir, 'app'), { recursive: true });
      const content = lines.join('\n');
      await writeFile(join(dir, 'app', 'mod.ts'), content, 'utf-8');

      const result = await runNanoMindScan(dir, []);
      const failing = result.mergedFindings.filter(f => !f.passed && f.file === join('app', 'mod.ts'));

      for (const checkId of ['AST-CRED-001', 'AST-CRED-003']) {
        const rows = failing.filter(f => f.checkId === checkId);
        expect(rows, `${checkId} must report exactly the one value in this file`).toHaveLength(1);
        const [f] = rows;
        expect(f.line, `${checkId} cites the value's line`).toBe(VALUE_LINE);
        if (decoyLine !== undefined) expect(f.line).not.toBe(decoyLine);
        expect(generateVerifyCommand(f, dir)).toMatch(new RegExp(`^sed -n '${VALUE_LINE}p' `));
        // No byte of the value rides in the finding.
        const text = JSON.stringify(f);
        for (const secret of [OPENAI_KEY.slice(3), AWS_SECRET]) expect(text).not.toContain(secret);
      }
    });
  }
});

describe('#497: the PEM shape is the whole block, and only a marker-only body is a placeholder', () => {
  const pemHits = (content: string) =>
    scanCanonicalCredentialFormatsForTest(content).filter(h => h.label === 'PEM private key');

  it('an armor header with no key material after it is not a hit', () => {
    expect(pemHits(`const PEM_HEADER = '${PEM_HEADER}';\n`)).toEqual([]);
    expect(pemHits(`${PEM_HEADER}\n...\n${PEM_HEADER.replace('BEGIN', 'END')}\n`)).toEqual([]);
  });

  it('a real key is one hit at its armor header, with or without escaped newlines', () => {
    const pem = rsaPem();
    const multi = `const a = 1;\nconst KEY = \`${pem}\`;\n`;
    expect(pemHits(multi).map(h => h.index)).toEqual([multi.indexOf(PEM_HEADER)]);
    const escaped = `const a = 1;\nconst KEY = "${pem.split('\n').join('\\n')}";\n`;
    expect(pemHits(escaped).map(h => h.index)).toEqual([escaped.indexOf(PEM_HEADER)]);
  });

  it('a marker-only body is skipped', () => {
    const body = 'FAKEKEYFAKEKEY'.repeat(6);
    expect(pemHits(`${PEM_HEADER}\n${body}\n${PEM_HEADER.replace('BEGIN', 'END')}\n`)).toEqual([]);
  });

  it('a real body that happens to spell a marker is still reported', () => {
    for (const marker of ['fake', 'dummy']) {
      const lines = rsaPem().split('\n');
      // Overwrite four or five base64 characters of the second body line: still
      // a base64 body, still key material, now carrying the marker word.
      lines[2] = lines[2].slice(0, 20) + marker + lines[2].slice(20 + marker.length);
      const content = `const KEY = \`${lines.join('\n')}\`;\n`;
      expect(content.toLowerCase()).toContain(marker);
      expect(pemHits(content), `a body containing "${marker}"`).toHaveLength(1);
    }
  });
});

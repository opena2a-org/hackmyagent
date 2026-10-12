/**
 * #1045 — the Fix for a PEM private key found inside a file is key-specific.
 *
 * AST-CRED-003 gave every credential shape one Fix: `opena2a protect .` to
 * vault the value, then "After encrypting: rotate the credential". For key
 * material that is not the remedy. The key pair is replaced and the old key
 * revoked, wherever the key was found, so a PEM private key inside an app.py
 * or a SKILL.md now gets that Fix, and `git rm --cached <file>` is named only
 * when the file holds nothing but the key (for any other file it would
 * untrack the whole file).
 *
 * What does not move: the check id, the name, the severity, the masked
 * message, the BEGIN line, the Verify line, and every other shape's Fix (the
 * access-key case below pins that).
 *
 * The keys are minted in-process with node:crypto and live only in a temp
 * tree removed after each test. No committed line carries an armor header or
 * a credential-shaped literal: the access key is assembled from parts.
 */

import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, it, expect } from 'vitest';

import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import { SemanticCompiler } from '../../src/nanomind-core/compiler/semantic-compiler';
import { analyzeCredentials } from '../../src/nanomind-core/analyzers/credential-analyzer';
import type { ASTFinding } from '../../src/nanomind-core/analyzers/capability-analyzer';
import { enrichFindings } from '../../src/nanomind-core/fix-generator';
import { tempDir } from '../helpers/temp-dir';

function rsaPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ type: 'pkcs1', format: 'pem' }) as string;
}

function ed25519Pem(): string {
  const { privateKey } = generateKeyPairSync('ed25519');
  return privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
}

/** An access-key-id-shaped value, assembled so no committed line carries one. */
function accessKeyId(): string {
  return 'AK' + 'IA' + randomBytes(8).toString('hex').toUpperCase();
}

/** 1-based line of the armor header in `content`. */
function beginLine(content: string): number {
  const at = content.indexOf('-----BEGIN');
  return content.slice(0, at).split('\n').length;
}

const KEY_FIX = [
  'Remove the private key block',
  'Generate a new key pair, install the new public key wherever the old one was authorized, and revoke the old key.',
  'Keep the new private key outside the repository',
  'the old key stays in git history',
];

function expectKeyFix(fix: string | undefined): void {
  expect(fix).toBeDefined();
  for (const phrase of KEY_FIX) expect(fix).toContain(phrase);
  expect(fix).not.toContain('opena2a protect');
  expect(fix).not.toContain('After encrypting');
  expect(fix).toMatch(/\nVerify: hackmyagent secure \S+$/);
}

describe('#1045: a PEM private key inside a file gets a key-specific Fix', () => {
  it('a key in a source string and a key in a skill file: key Fix, no vault command, no git rm --cached; an access key keeps the generic Fix', async () => {
    const dir = tempDir('hma-pem-fix-');
    const pyKey = rsaPem();
    const app = [
      'import os',
      '',
      `SIGNING_KEY = """${pyKey}"""`,
      '',
      'def main():',
      '    return SIGNING_KEY',
      '',
    ].join('\n');
    // A key on one line, as a JavaScript string with escaped newlines.
    const jsKey = ed25519Pem().trimEnd().split('\n').join('\\n');
    const signer = [
      "const crypto = require('crypto');",
      `const SIGNING_KEY = "${jsKey}";`,
      'module.exports = { sign: (d) => crypto.sign(null, d, SIGNING_KEY) };',
      '',
    ].join('\n');
    const skill = [
      '---',
      'name: deploy',
      'description: Deploys the service',
      '---',
      '',
      '# Deploy',
      '',
      'Use this key to sign releases:',
      '',
      ed25519Pem(),
    ].join('\n');
    const settings = [
      '// Runtime configuration for the billing worker.',
      'export const settings = {',
      `  awsAccessKeyId: "${accessKeyId()}",`,
      "  region: 'us-east-1',",
      '};',
      '',
    ].join('\n');
    await mkdir(join(dir, 'skills', 'deploy'), { recursive: true });
    await writeFile(join(dir, 'app.py'), app, 'utf-8');
    await writeFile(join(dir, 'signer.js'), signer, 'utf-8');
    await writeFile(join(dir, 'skills', 'deploy', 'SKILL.md'), skill, 'utf-8');
    await writeFile(join(dir, 'settings.ts'), settings, 'utf-8');

    const result = await runNanoMindScan(dir, []);
    const cred = result.mergedFindings.filter(f => !f.passed && f.checkId === 'AST-CRED-003');
    const byFile = (file: string) => cred.filter(f => f.file === file);

    for (const [file, content] of [
      ['app.py', app],
      ['signer.js', signer],
      [join('skills', 'deploy', 'SKILL.md'), skill],
    ] as const) {
      const rows = byFile(file);
      expect(rows, `one AST-CRED-003 row for the key in ${file}`).toHaveLength(1);
      const [f] = rows;
      expect(f.severity).toBe('critical');
      expect(f.name).toBe('Hardcoded Secret Detected');
      expect(f.message).toBe('Hardcoded secret: PEM private key: [REDACTED]');
      expect(f.line).toBe(beginLine(content));
      expectKeyFix(f.fix);
      expect(f.fix, `${file} has other content, so untracking it would untrack that too`).not.toContain(
        'git rm --cached',
      );
    }

    const access = byFile('settings.ts');
    expect(access.length, 'the access key must be reported, or the control below measures nothing').toBeGreaterThan(0);
    for (const f of access) {
      expect(f.fix).toContain('opena2a protect .');
      expect(f.fix).toContain('After encrypting: rotate the credential immediately');
      expect(f.fix).not.toContain('Generate a new key pair');
    }
  });

  it('a key and an access key in one file each keep their own Fix', async () => {
    const dir = tempDir('hma-pem-fix-');
    const key = rsaPem();
    const content = [
      'import os',
      '',
      `AWS_ACCESS_KEY_ID = "${accessKeyId()}"`,
      `SIGNING_KEY = """${key}"""`,
      '',
    ].join('\n');
    await writeFile(join(dir, 'app.py'), content, 'utf-8');

    const result = await runNanoMindScan(dir, []);
    const cred = result.mergedFindings.filter(f => !f.passed && f.checkId === 'AST-CRED-003' && f.file === 'app.py');
    const pem = cred.filter(f => f.message === 'Hardcoded secret: PEM private key: [REDACTED]');
    const other = cred.filter(f => f.message !== 'Hardcoded secret: PEM private key: [REDACTED]');
    expect(pem).toHaveLength(1);
    expect(other.length).toBeGreaterThan(0);
    expect(pem[0].line).toBe(beginLine(content));
    expectKeyFix(pem[0].fix);
    for (const f of other) {
      expect(f.fix).toContain('opena2a protect .');
      expect(f.fix).not.toContain('Generate a new key pair');
    }
  });
});

describe('#1045: git rm --cached is named only for a file that holds nothing but the key', () => {
  const compiler = new SemanticCompiler({ useNanoMind: false });

  async function fixesFor(content: string, artifactPath: string): Promise<ASTFinding[]> {
    const { ast } = await compiler.compile(content, artifactPath);
    const findings = analyzeCredentials(ast, () => true, undefined, content);
    return enrichFindings(findings, ast, undefined, content).filter(
      f => !f.passed && f.checkId === 'AST-CRED-003',
    );
  }

  it('a key-only file names git rm --cached on that file', async () => {
    const findings = await fixesFor(rsaPem(), 'config/signing-key.yaml');
    expect(findings).toHaveLength(1);
    expectKeyFix(findings[0].fix);
    expect(findings[0].fix).toContain('stop tracking it: git rm --cached config/signing-key.yaml');
  });

  it('two key blocks and nothing else still count as key-only; a key beside other text does not', async () => {
    const twoKeys = await fixesFor(`${rsaPem()}\n${ed25519Pem()}`, 'keys.yaml');
    expect(twoKeys).toHaveLength(2);
    for (const f of twoKeys) expect(f.fix).toContain('git rm --cached keys.yaml');

    const withNote = await fixesFor(`# signing key\n${rsaPem()}`, 'README.md');
    expect(withNote).toHaveLength(1);
    expectKeyFix(withNote[0].fix);
    expect(withNote[0].fix).not.toContain('git rm --cached');
  });

  it('a hostile file name is quoted in the command, and one that cannot be shown truthfully falls back to prose', async () => {
    const quoted = await fixesFor(rsaPem(), 'keys/my key$(id).yaml');
    expect(quoted).toHaveLength(1);
    expect(quoted[0].fix).toContain("git rm --cached 'keys/my key$(id).yaml'");

    const unshowable = await fixesFor(rsaPem(), 'keys/a\nrm -rf ~.yaml');
    expect(unshowable).toHaveLength(1);
    expectKeyFix(unshowable[0].fix);
    expect(unshowable[0].fix).toContain(
      'git rm --cached on the file named above (its name cannot be shown truthfully in a command).',
    );
    expect(unshowable[0].fix).not.toContain('rm -rf');
  });
});

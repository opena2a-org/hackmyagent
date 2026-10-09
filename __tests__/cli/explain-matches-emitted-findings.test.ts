/**
 * `explain` answers for what `secure` reports under an id, not for
 * something else (#918).
 *
 * Measured before the fix:
 * - `explain SEM-LLM-NOT-ANALYZED` printed "Unknown check ID", suggested
 *   SEM-INST-001..003 and exited 1, while `secure --deep` reports that id
 *   (one record per unread file, or one for the run when the deep analysis
 *   tier could not run) and exits 2 on it.
 * - `explain CRED-002` described an OpenAI API key (sk-proj-...), while
 *   `secure` files CRED-002 as "Private key files found: <file>", including
 *   a JSON file whose field value holds a private key (#577).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { assertDistFresh, assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { STATIC_EXPLANATIONS, isKnownExplainId } from '../../src/explain-registry';
import { HardeningScanner } from '../../src/hardening/scanner';
import { DEEP_SCAN_NOT_RUN_FIX, DEEP_SCAN_NOT_RUN_NAME } from '../../src/hardening/settled-outcome';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFreshIfPresent);

const SCANNER_SRC = readFileSync(join(__dirname, '..', '..', 'src', 'hardening', 'scanner.ts'), 'utf-8');

type Finding = { checkId: string; name: string; passed: boolean; message: string; fix?: string };

describe('SEM-LLM-NOT-ANALYZED is explained', () => {
  it('the scanner still emits the id (non-vacuity)', () => {
    expect(SCANNER_SRC).toMatch(/checkId: 'SEM-LLM-NOT-ANALYZED'/);
  });

  it('is a known explain id with a written explanation', () => {
    expect(isKnownExplainId('SEM-LLM-NOT-ANALYZED')).toBe(true);
    expect(STATIC_EXPLANATIONS['SEM-LLM-NOT-ANALYZED']).toBeTruthy();
  });

  it('names both records the scanner writes under the id', () => {
    const text = STATIC_EXPLANATIONS['SEM-LLM-NOT-ANALYZED'];
    // The run-level record (#479) and the per-file record (#462), by the
    // names the scanner gives them.
    const perFileName = /checkId: 'SEM-LLM-NOT-ANALYZED',\s*name: '([^']+)'/.exec(SCANNER_SRC)?.[1];
    expect(perFileName).toBeTruthy();
    expect(text).toContain(perFileName!);
    expect(text).toContain(DEEP_SCAN_NOT_RUN_NAME);
  });

  it('states the exit code and the fix the run prints', () => {
    const text = STATIC_EXPLANATIONS['SEM-LLM-NOT-ANALYZED'];
    expect(text).toMatch(/exits? 2/);
    expect(text).toContain(DEEP_SCAN_NOT_RUN_FIX);
    expect(text).toMatch(/not a clean result/);
  });
});

describe('CRED-002 is explained as the finding secure reports', () => {
  async function cred002Finding(): Promise<Finding> {
    const dir = tempDir('hma918-');
    await mkdir(join(dir, 'certs'), { recursive: true });
    // A `.key` file is CRED-002 on its name alone; no key material needed.
    await writeFile(join(dir, 'certs', 'server.key'), 'FAKE-KEY-PLACEHOLDER\n');
    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    const finding = (result.findings as Finding[]).find((f) => f.checkId === 'CRED-002' && !f.passed);
    expect(finding, 'secure reported no failing CRED-002 for a .key file').toBeTruthy();
    return finding!;
  }

  it('describes a private key file, not an API key', async () => {
    const finding = await cred002Finding();
    expect(finding.message).toMatch(/private key/i);

    const text = STATIC_EXPLANATIONS['CRED-002'];
    expect(text).toMatch(/private key/i);
    expect(text).not.toMatch(/OpenAI|sk-proj|API key/i);
    expect(text).toMatch(/\.pem/);
    expect(text).toMatch(/\.key/);
    // #577: a JSON field value holding a key is filed under the same id.
    expect(text).toMatch(/JSON/);
  });

  it('gives the remedy the finding gives', async () => {
    const finding = await cred002Finding();
    expect(finding.fix).toMatch(/git rm --cached/);
    expect(STATIC_EXPLANATIONS['CRED-002']).toMatch(/git rm --cached/);
    expect(STATIC_EXPLANATIONS['CRED-002']).toMatch(/rotate/i);
  });
});

describe('explain on these ids (spawn)', () => {
  beforeAll(assertDistFresh);

  function runExplain(id: string) {
    const res = spawnSync(process.execPath, [CLI, 'explain', id], {
      encoding: 'utf-8',
      env: { ...process.env, NO_COLOR: '1', NANOMIND_URL: 'http://127.0.0.1:9' },
    });
    return { code: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
  }

  it('explain SEM-LLM-NOT-ANALYZED exits 0 and explains the coverage gap', () => {
    const { code, stdout, stderr } = runExplain('SEM-LLM-NOT-ANALYZED');
    expect(stderr).not.toMatch(/Unknown check ID/i);
    expect(stdout).toMatch('SEM-LLM-NOT-ANALYZED');
    expect(stdout).toContain(DEEP_SCAN_NOT_RUN_NAME);
    expect(code).toBe(0);
  });

  it('explain CRED-002 exits 0 and describes a private key file', () => {
    const { code, stdout } = runExplain('CRED-002');
    expect(stdout).toMatch(/private key/i);
    expect(stdout).not.toMatch(/OpenAI/);
    expect(code).toBe(0);
  });
});

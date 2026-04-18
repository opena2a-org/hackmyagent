/**
 * Regression tests for the three path-context exemptions shipped 2026-04-17.
 *
 * Each test maps to an entry in briefs/release-findings.md:
 *   - bug #5: UNICODE-STEGO-001 must skip training/corpus/** and datasets/**
 *   - bug #7: NEMO-007 (and TOCTOU-001) must skip test/fixtures paths
 *   - bug #3: AIM-002 must soften to MEDIUM inside examples/templates/docs/samples
 *
 * The fixtures are intentional (adversarial Unicode in a corpus, process.env
 * spread in a test setup, bearer-auth example without cryptographic binding).
 * The scanner MUST NOT flag them at HIGH/CRITICAL.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { HardeningScanner } from '../../src/hardening/scanner';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

describe('scanner path-context exemptions', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-path-context-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  describe('UNICODE-STEGO corpus exemption (bug #5)', () => {
    // Zero-width space (U+200B) — normally triggers UNICODE-STEGO-001 critical.
    const zeroWidthContent = JSON.stringify({
      text: `hello\u200Bworld with invisible codepoint`,
    });

    it('does not fire UNICODE-STEGO-001 on training/corpus/pretrain/*.json', async () => {
      const corpusDir = path.join(tempDir, 'training', 'corpus', 'pretrain');
      await fs.mkdir(corpusDir, { recursive: true });
      await fs.writeFile(path.join(corpusDir, '000001.json'), zeroWidthContent);

      const result = await scanner.scan({ targetDir: tempDir });
      const stegoFindings = result.findings.filter(
        (f) => f.checkId?.startsWith('UNICODE-STEGO') && !f.passed
      );
      expect(stegoFindings).toHaveLength(0);
    });

    it('does not fire UNICODE-STEGO-001 on training/datasets/*.json', async () => {
      const datasetDir = path.join(tempDir, 'training', 'datasets');
      await fs.mkdir(datasetDir, { recursive: true });
      await fs.writeFile(path.join(datasetDir, 'raw.json'), zeroWidthContent);

      const result = await scanner.scan({ targetDir: tempDir });
      const stegoFindings = result.findings.filter(
        (f) => f.checkId?.startsWith('UNICODE-STEGO') && !f.passed
      );
      expect(stegoFindings).toHaveLength(0);
    });

    it('STILL fires on bare top-level datasets/ (attacker-named bypass)', async () => {
      // Adversarial review 2026-04-17: a backdoored repo with a
      // top-level `datasets/` that is not actually ML training data
      // must not silently escape stego detection. The exemption
      // requires a `training/` prefix.
      const datasetDir = path.join(tempDir, 'datasets');
      await fs.mkdir(datasetDir, { recursive: true });
      await fs.writeFile(path.join(datasetDir, 'raw.js'), zeroWidthContent);

      const result = await scanner.scan({ targetDir: tempDir });
      const stegoFindings = result.findings.filter(
        (f) => f.checkId?.startsWith('UNICODE-STEGO') && !f.passed
      );
      expect(stegoFindings.length).toBeGreaterThan(0);
    });

    it('still fires UNICODE-STEGO-001 on non-corpus paths', async () => {
      // Sanity check: the exemption is path-scoped, not a blanket skip.
      const srcDir = path.join(tempDir, 'src');
      await fs.mkdir(srcDir, { recursive: true });
      await fs.writeFile(path.join(srcDir, 'leaked.js'), zeroWidthContent);

      const result = await scanner.scan({ targetDir: tempDir });
      const stegoFindings = result.findings.filter(
        (f) => f.checkId?.startsWith('UNICODE-STEGO') && !f.passed
      );
      expect(stegoFindings.length).toBeGreaterThan(0);
    });
  });

  describe('NEMO-007 test-path exemption (bug #7)', () => {
    const envSpreadContent = `
      import { spawn } from 'child_process';
      describe('mcp wrapper', () => {
        it('passes env', () => {
          spawn('node', ['server.js'], {
            env: { ...process.env, EXTRA: '1' },
          });
        });
      });
    `;

    it('does not fire NEMO-007 on *.test.ts', async () => {
      const srcDir = path.join(tempDir, 'src', 'mcp');
      await fs.mkdir(srcDir, { recursive: true });
      await fs.writeFile(path.join(srcDir, 'wrapper.test.ts'), envSpreadContent);

      const result = await scanner.scan({ targetDir: tempDir });
      const nemo007 = result.findings.filter(
        (f) => f.checkId === 'NEMO-007' && !f.passed
      );
      expect(nemo007).toHaveLength(0);
    });

    it('does not fire NEMO-007 inside __tests__/', async () => {
      const testsDir = path.join(tempDir, '__tests__');
      await fs.mkdir(testsDir, { recursive: true });
      await fs.writeFile(path.join(testsDir, 'e2e.ts'), envSpreadContent);

      const result = await scanner.scan({ targetDir: tempDir });
      const nemo007 = result.findings.filter(
        (f) => f.checkId === 'NEMO-007' && !f.passed
      );
      expect(nemo007).toHaveLength(0);
    });

    it('still fires NEMO-007 on production src/ files', async () => {
      // Sanity: the exemption is path-scoped.
      const srcDir = path.join(tempDir, 'src');
      await fs.mkdir(srcDir, { recursive: true });
      await fs.writeFile(path.join(srcDir, 'runner.ts'), envSpreadContent);

      const result = await scanner.scan({ targetDir: tempDir });
      const nemo007 = result.findings.filter(
        (f) => f.checkId === 'NEMO-007' && !f.passed
      );
      expect(nemo007.length).toBeGreaterThan(0);
    });
  });

  describe('TOCTOU-001 test-path exemption (bug #7 companion)', () => {
    const toctouContent = `
      import * as fs from 'fs';
      import { execSync } from 'child_process';
      export function load(filePath: string) {
        if (fs.existsSync(filePath)) {
          return fs.readFileSync(filePath, 'utf-8');
        }
        return '';
      }
      export function run(filePath: string) {
        fs.statSync(filePath);
        execSync(filePath);
      }
    `;

    it('does not fire TOCTOU-001 on *.test.ts', async () => {
      const srcDir = path.join(tempDir, 'src');
      await fs.mkdir(srcDir, { recursive: true });
      await fs.writeFile(path.join(srcDir, 'loader.test.ts'), toctouContent);

      const result = await scanner.scan({ targetDir: tempDir });
      const toctou = result.findings.filter(
        (f) => f.checkId === 'TOCTOU-001' && !f.passed
      );
      expect(toctou).toHaveLength(0);
    });

    it('still fires TOCTOU-001 on production src/ files', async () => {
      const srcDir = path.join(tempDir, 'src');
      await fs.mkdir(srcDir, { recursive: true });
      await fs.writeFile(path.join(srcDir, 'loader.ts'), toctouContent);

      const result = await scanner.scan({ targetDir: tempDir });
      const toctou = result.findings.filter(
        (f) => f.checkId === 'TOCTOU-001' && !f.passed
      );
      expect(toctou.length).toBeGreaterThan(0);
    });
  });

  describe('AIM-002 example-path softening (bug #3)', () => {
    const agentCardNoKey = JSON.stringify({
      name: 'example-agent',
      agentId: 'agent-001',
      authentication: { type: 'bearer' },
    });

    it('softens AIM-002 to MEDIUM when scan target is inside examples/', async () => {
      // The scanner only reads agent-card.json at the scan root, so the
      // "this is an example" signal has to come from the scan target's
      // path itself — mirrors how a user hits this IRL by pointing HMA
      // at `.../a2a-security-examples/examples/secure-agent-card/`.
      const exDir = path.join(tempDir, 'examples', 'secure-agent-card');
      await fs.mkdir(exDir, { recursive: true });
      await fs.writeFile(path.join(exDir, 'agent-card.json'), agentCardNoKey);

      const result = await scanner.scan({ targetDir: exDir });
      const aim002 = result.findings.filter(
        (f) => f.checkId === 'AIM-002' && !f.passed
      );
      expect(aim002.length).toBeGreaterThan(0);
      for (const f of aim002) {
        expect(f.severity).toBe('medium');
      }
    });

    it('keeps AIM-002 at HIGH outside examples/', async () => {
      await fs.writeFile(path.join(tempDir, 'agent-card.json'), agentCardNoKey);

      const result = await scanner.scan({ targetDir: tempDir });
      const aim002 = result.findings.filter(
        (f) => f.checkId === 'AIM-002' && !f.passed
      );
      expect(aim002.length).toBeGreaterThan(0);
      for (const f of aim002) {
        expect(f.severity).toBe('high');
      }
    });
  });
});

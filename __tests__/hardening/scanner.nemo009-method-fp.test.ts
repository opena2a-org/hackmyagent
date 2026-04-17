import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { HardeningScanner } from '../../src/hardening/scanner';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

describe('NEMO-009 method-call false positive (bug #8)', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-nemo009-fp-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  function nemo009(findings: Array<{ checkId?: string; passed?: boolean }>) {
    return findings.filter((f) => f.checkId === 'NEMO-009' && !f.passed);
  }

  describe('Python: PyTorch .eval() must not trigger NEMO-009', () => {
    it('does NOT fire on model.eval()', async () => {
      const py = [
        'from transformers import AutoModelForCausalLM',
        'model = AutoModelForCausalLM.from_pretrained("foo").eval()',
        'self._model = AutoModelForCausalLM.from_pretrained(',
        '    self.model_path,',
        ').eval()',
      ].join('\n');
      await fs.writeFile(path.join(tempDir, 'load.py'), py);
      const result = await scanner.scan({ targetDir: tempDir });
      expect(nemo009(result.findings)).toHaveLength(0);
    });

    it('does NOT fire on conn.exec() / cursor.exec()', async () => {
      const py = [
        'cursor.exec("SELECT 1")',
        'self.conn.exec(query)',
      ].join('\n');
      await fs.writeFile(path.join(tempDir, 'db.py'), py);
      const result = await scanner.scan({ targetDir: tempDir });
      expect(nemo009(result.findings)).toHaveLength(0);
    });

    it('STILL fires on bare eval(user_input)', async () => {
      const py = 'result = eval(user_input)';
      await fs.writeFile(path.join(tempDir, 'bad.py'), py);
      const result = await scanner.scan({ targetDir: tempDir });
      const hits = nemo009(result.findings);
      expect(hits.length).toBeGreaterThan(0);
    });

    it('STILL fires on bare exec(payload)', async () => {
      const py = 'exec(payload)';
      await fs.writeFile(path.join(tempDir, 'bad.py'), py);
      const result = await scanner.scan({ targetDir: tempDir });
      const hits = nemo009(result.findings);
      expect(hits.length).toBeGreaterThan(0);
    });
  });

  describe('TypeScript/JavaScript: .eval() method calls must not trigger NEMO-009', () => {
    it('does NOT fire on worker.eval(code) (Worker API method)', async () => {
      const ts = [
        'const worker = new Worker("./w.js");',
        'await worker.eval("1 + 1");',
      ].join('\n');
      await fs.writeFile(path.join(tempDir, 'worker.ts'), ts);
      const result = await scanner.scan({ targetDir: tempDir });
      expect(nemo009(result.findings)).toHaveLength(0);
    });

    it('STILL fires on bare eval(input)', async () => {
      const ts = 'const result = eval(input);';
      await fs.writeFile(path.join(tempDir, 'bad.ts'), ts);
      const result = await scanner.scan({ targetDir: tempDir });
      const hits = nemo009(result.findings);
      expect(hits.length).toBeGreaterThan(0);
    });
  });
});

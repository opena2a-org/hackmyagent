/**
 * `check <package>` reported DEP-001 (no lock file) and SANDBOX-001 (no
 * Dockerfile) on every downloaded package: npm never publishes a lock file,
 * and a Dockerfile describes where the consumer deploys, not what the package
 * ships. Both are filtered by check id alongside the local-only categories on
 * a downloaded package, and a scan of a local project tree still reports them.
 *
 * The fetched-tree half (`check` on a served archive) lives in
 * __tests__/cli/check-fetched-hmaignore.test.ts, and what a share sends in
 * __tests__/registry/outbound-check-detect-contract.test.ts.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import {
  PACKAGE_SCAN_LOCAL_ONLY_CHECK_IDS,
  isPackageScanLocalOnly,
} from '../../src/registry/submissions';
import { tempDir } from '../helpers/temp-dir';

describe('checks a downloaded package is not held to', () => {
  it('are DEP-001 and SANDBOX-001, and no other check of their categories', () => {
    expect([...PACKAGE_SCAN_LOCAL_ONLY_CHECK_IDS].sort()).toEqual(['DEP-001', 'SANDBOX-001']);
    expect(isPackageScanLocalOnly({ checkId: 'DEP-001', category: 'dependencies' })).toBe(true);
    expect(isPackageScanLocalOnly({ checkId: 'SANDBOX-001', category: 'sandboxing' })).toBe(true);
    expect(isPackageScanLocalOnly({ checkId: 'DEP-004', category: 'dependencies' })).toBe(false);
    expect(isPackageScanLocalOnly({ checkId: 'SANDBOX-002', category: 'sandboxing' })).toBe(false);
    expect(isPackageScanLocalOnly({ checkId: 'GIT-001', category: 'git' })).toBe(true);
  });
});

describe('a local project tree', () => {
  it('still fails DEP-001 and SANDBOX-001 when it has no lock file and no Dockerfile', async () => {
    const dir = tempDir('hma-274-local-');
    fs.writeFileSync(path.join(dir, 'package.json'), '{ "name": "fx274", "version": "1.0.0", "main": "index.js" }\n');
    fs.writeFileSync(path.join(dir, 'index.js'), 'module.exports = 1;\n');
    const result = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    const failed = result.allFindings
      .filter((f: any) => f.passed === false)
      .map((f: any) => f.checkId);
    expect(failed).toContain('DEP-001');
    expect(failed).toContain('SANDBOX-001');
  }, 120_000);
});

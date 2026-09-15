/**
 * The MCP `hackmyagent_benchmark` tool carries the zero-read floor the CLI
 * benchmark arm applies: a scan that read no file is `Not Assessed`, with a
 * `null` compliance, whatever the control statuses say. The shared assessor
 * takes the scan's own coverage record so both surfaces key on the same
 * `filesExamined` figure.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assessBenchmarkFindings, handleToolCall } from '../../src/mcp-server';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { ScanResult } from '../../src/hardening/security-check';

const SCAN_TIMEOUT = 240_000;

let root: string;
let empty: string;
let oneFile: string;
let emptyScan: ScanResult;
let oneFileScan: ScanResult;

beforeAll(async () => {
  // realpath: the confinement check compares resolved paths, and macOS's
  // tmpdir is a symlink (`/var` -> `/private/var`).
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hma-mcp-zero-read-')));
  empty = path.join(root, 'empty');
  fs.mkdirSync(empty);
  oneFile = path.join(root, 'one-file');
  fs.mkdirSync(oneFile);
  fs.writeFileSync(path.join(oneFile, 'README.md'), '# fixture\n');
  emptyScan = await new HardeningScanner().scan({ targetDir: empty });
  oneFileScan = await new HardeningScanner().scan({ targetDir: oneFile });
}, SCAN_TIMEOUT);

afterAll(() => {
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
});

describe('T3: the MCP benchmark tool on an empty directory', () => {
  it('premise: the scan read no file from the empty tree and one from the other', () => {
    expect(emptyScan.coverage?.filesExamined).toBe(0);
    expect(oneFileScan.coverage?.filesExamined).toBe(1);
  });

  it('the shared assessor withholds the rating when the coverage says zero files were read', () => {
    const a = assessBenchmarkFindings(emptyScan.allFindings ?? emptyScan.findings, 'L1', {
      filesExamined: emptyScan.coverage?.filesExamined ?? 0,
      directory: empty,
    });
    expect(a.rating).toBe('Not Assessed');
    expect(a.compliance).toBeNull();
    expect(a.text).toContain('not measured (Not Assessed)');
    expect(a.text).toContain(`no file was read from ${empty}`);
    // Statuses are kept: the records are true records.
    expect(a.passed).toBe(3);
    expect(a.notApplicable).toBe(4);
  });

  it('the tool returns the Not Assessed rating string for the empty directory', async () => {
    const res = await handleToolCall('hackmyagent_benchmark', { directory: empty, level: 'L1' }, [root]);
    expect(res.isError).toBeFalsy();
    const text = res.content[0].text;
    expect(text).toContain('OASB-1 L1 Assessment: not measured (Not Assessed)');
    expect(text).toContain(`no file was read from ${empty}`);
    expect(text).not.toContain('Certified');
  });

  it('a tree from which one file was read keeps its measured rating', async () => {
    const direct = assessBenchmarkFindings(oneFileScan.allFindings ?? oneFileScan.findings, 'L1');
    const res = await handleToolCall('hackmyagent_benchmark', { directory: oneFile, level: 'L1' }, [root]);
    expect(res.isError).toBeFalsy();
    const text = res.content[0].text;
    expect(direct.rating).not.toBe('Not Assessed');
    expect(text).toContain(`(${direct.rating})`);
    expect(text).not.toContain('no file was read');
  });
});

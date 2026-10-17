/**
 * #1123: a process listing larger than 1 MiB is read, not reported as unread.
 *
 * `execSync` keeps 1 MiB of output by default and throws ENOBUFS past it.
 * `detect` read `ps aux` with that default, so on a host whose listing was
 * larger it counted the process surface as unread although `ps` ran, and the
 * NemoClaw checks that read `ps aux` reported that they could not inspect the
 * running processes.
 *
 * This file makes the listing larger than 1 MiB by starting idle processes
 * with long command lines, and first shows that a default `execSync` of
 * `ps aux` fails on it.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execSync, spawn, type ChildProcess } from 'node:child_process';
import { didProcessScanFail, scanProcesses } from '../../src/scanner/detect';
import { NemoClawScanner } from '../../src/hardening/nemoclaw-scanner';

const ONE_MIB = 1024 * 1024;
// Linux refuses one argument longer than 128 KiB (spawn fails with E2BIG),
// and macOS caps a command line and its environment together at 1 MiB. So
// each process carries one argument under the smaller cap, and enough of
// them are started for the listing to pass 1 MiB on either: ten processes of
// 120,000 bytes each put 1.2 MB of command lines in it.
const PADDING = 'x'.repeat(120_000);
const PADDED_PROCESSES = 10;

const started: ChildProcess[] = [];

beforeAll(async () => {
  for (let i = 0; i < PADDED_PROCESSES; i++) {
    started.push(spawn(process.execPath, ['-e', 'setTimeout(() => {}, 120000)', `hma-1123-pad-${i}-${PADDING}`], { stdio: 'ignore' }));
  }
  await Promise.all(started.map((p) => new Promise<void>((resolve, reject) => {
    p.once('spawn', () => resolve());
    p.once('error', reject);
  })));
});

afterAll(() => {
  for (const p of started) p.kill();
});

describe('#1123 the process listing is read when it is larger than 1 MiB', () => {
  it('harness: the listing is larger than 1 MiB, and a default execSync of ps aux fails on it', () => {
    let code: string | undefined;
    try {
      execSync('ps aux', { encoding: 'utf-8', timeout: 5000 });
    } catch (err) {
      code = (err as NodeJS.ErrnoException).code;
    }
    expect(code).toBe('ENOBUFS');
    const listing = execSync('ps aux', { encoding: 'utf-8', timeout: 5000, maxBuffer: 64 * ONE_MIB });
    expect(Buffer.byteLength(listing)).toBeGreaterThan(ONE_MIB);
    expect(listing).toContain(`hma-1123-pad-0-${PADDING.slice(0, 1000)}`);
  });

  it('detect reads the process surface', () => {
    scanProcesses();
    expect(didProcessScanFail()).toBe(false);
  });

  it('HMA-NMC-030 inspects the running processes', () => {
    // What the check then reports depends on the processes this host runs;
    // the message for an unread listing is the one it no longer gives.
    const finding = (new NemoClawScanner() as unknown as { checkNMC030(): { checkId: string; message: string } }).checkNMC030();
    expect(finding.checkId).toBe('HMA-NMC-030');
    expect(finding.message).not.toBe('Could not inspect running processes');
  });
});

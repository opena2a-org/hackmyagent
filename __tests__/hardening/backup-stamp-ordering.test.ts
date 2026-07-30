/**
 * #332 — the backup directory name must sort in creation order.
 *
 * `rollback` selects the latest backup with `readdir().sort().reverse()[0]`, and
 * the code comment said so: "the stamp has to remain time-ordered". Adding an
 * unguessable random suffix (#320) broke that inside one second, and nothing
 * tested the invariant the comment described. Measured at the primitive level,
 * two `createBackup` calls in the same second, six trials: five selected the
 * OLDER backup.
 *
 * When it happens, run 2's generated files are not removed AND run 1's copies
 * are deleted, leaving only run 2's — which hold already-redacted content. A
 * second `rollback` then restores the redaction, which is #317's shape.
 *
 * The clock is pinned rather than raced. Two runs landing in the same
 * millisecond is what the defect is about, and waiting for it to happen by
 * chance is how an invariant test becomes a flake.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';

type Probe = HardeningScanner & {
  createRunBackupDir(baseReal: string): Promise<string>;
};

/** What `rollback` does to choose a backup, verbatim. */
const selectLatest = async (base: string): Promise<string> =>
  (await readdir(base)).filter((b) => !b.startsWith('.')).sort().reverse()[0];

describe('#332 backup names sort in creation order', () => {
  let dir: string;
  let base: string;

  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'hma-332-'));
    base = path.join(dir, '.hackmyagent-backup');
    await mkdir(base, { recursive: true });
    // Only Date is faked. Faking timers wholesale would also fake the ones the
    // filesystem promises rely on.
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-01-02T03:04:05.678Z'));
  });

  afterEach(async () => {
    vi.useRealTimers();
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  /**
   * A backup written by an earlier version, in the same second, whose random
   * suffix happens to be high. Nothing exotic: `ffffffff` is one of 2^32 equally
   * likely values, and the old format made it beat every later backup from that
   * second.
   */
  it('is selected over an earlier backup from the same second', async () => {
    const legacySibling = '2026-01-02-030405-ffffffff';
    await mkdir(path.join(base, legacySibling));
    await writeFile(path.join(base, legacySibling, '.manifest.json'), '{}');

    const created = await (new HardeningScanner() as unknown as Probe).createRunBackupDir(base);

    expect(
      await selectLatest(base),
      'the backup just created does not sort highest, so `rollback` would select the older one',
    ).toBe(path.basename(created));
  });

  /**
   * Two runs inside ONE millisecond — the tie the millisecond stamp cannot
   * break. Sequential creation is deterministic because the first is on disk
   * before the second chooses its name.
   */
  it('orders two backups created in the same millisecond', async () => {
    const probe = new HardeningScanner() as unknown as Probe;
    const first = path.basename(await probe.createRunBackupDir(base));
    const second = path.basename(await probe.createRunBackupDir(base));

    expect(first, 'the two runs produced the same name').not.toBe(second);
    expect(
      [first, second].sort().reverse()[0],
      'the second backup does not sort above the first, so `rollback` would '
      + 'restore from the older one and delete the newer',
    ).toBe(second);
    expect(await selectLatest(base), 'selection disagrees with creation order').toBe(second);
  });

  /**
   * The property the random component exists for (#320) has to survive the fix:
   * the name must still not be predictable from the clock alone.
   */
  it('keeps a component the scanned tree cannot predict', async () => {
    const probe = new HardeningScanner() as unknown as Probe;
    const a = path.basename(await probe.createRunBackupDir(base));
    const b = path.basename(await probe.createRunBackupDir(base));

    // Same pinned clock, so anything a tree could compute from the time is
    // identical in both names. What differs is what it cannot compute.
    const tailOf = (n: string) => n.slice(n.lastIndexOf('-') + 1);
    expect(tailOf(a).length, 'the unguessable component is gone').toBeGreaterThanOrEqual(8);
    expect(tailOf(a), 'two runs produced the same unguessable component').not.toBe(tailOf(b));
  });
});

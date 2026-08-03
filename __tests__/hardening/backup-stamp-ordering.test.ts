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
import { HardeningScanner, stampSequenceField } from '../../src/hardening/scanner';

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
   * #347.2 — the case above is a COIN FLIP, and this is the one that is not.
   *
   * With the sequence mechanism removed (`nextStampSequence` mutated to
   * `return 0`) the two names differ only in random hex, so the sort above
   * catches the regression about half the time: measured twelve runs of that
   * mutant, 6 passed and 6 failed. A test that passes half the time on a build
   * with the mechanism deleted is not testing the mechanism.
   *
   * The sequence FIELD is what the ordering is made of, so it is what is
   * asserted: two backups created inside one pinned millisecond must carry
   * sequence 0 and 1. That fails on `return 0` every time, whatever the hex does.
   */
  it('gives same-millisecond siblings consecutive sequence numbers', async () => {
    const probe = new HardeningScanner() as unknown as Probe;
    const names = [
      path.basename(await probe.createRunBackupDir(base)),
      path.basename(await probe.createRunBackupDir(base)),
      path.basename(await probe.createRunBackupDir(base)),
    ];

    // `<stamp>-<seq>-<hex>`: the stamp carries no `-` after the date, so the
    // sequence is the second-to-last dash-separated field.
    const seqOf = (n: string): string => n.split('-').slice(-2)[0];
    expect(
      names.map(seqOf),
      'same-millisecond backups do not carry consecutive sequence numbers, so their '
      + 'order is decided by the random component and `rollback` picks at chance',
    ).toEqual(['000', '001', '002']);

    // The stamp really was the same millisecond, or the sequence was never the
    // thing under test.
    const stampOf = (n: string): string => n.split('-').slice(0, -2).join('-');
    expect(
      new Set(names.map(stampOf)).size,
      'the clock moved between creations, so this case never exercised the tie the '
      + 'sequence exists to break',
    ).toBe(1);
  });

  /**
   * #347.6 — the sequence field is fixed-width, and the retry loop could push it
   * past three characters.
   *
   * `nextStampSequence` capped at 998 and `createRunBackupDir` then added
   * `attempt` (up to 7) before padding, so a 999th same-millisecond sibling
   * yielded a four-character field — breaking both the sort invariant the name
   * exists for and the three-character parse that reads it back. Unreachable in
   * practice; the invariant is stated as absolute, so it is asserted absolutely.
   */
  it('keeps the sequence field three characters wide at the cap', async () => {
    // Asserted against the EXPRESSION the name is built from, not a copy of it:
    // the width range is unreachable through `createRunBackupDir`, which would
    // need 999 directories inside one millisecond plus two `EEXIST` collisions
    // on four random bytes. A test that restated `Math.min(seq + attempt, 999)`
    // would agree with any implementation, including the broken one.
    for (let seq = 995; seq <= 999; seq++) {
      for (let attempt = 0; attempt < 8; attempt++) {
        expect(
          stampSequenceField(seq, attempt),
          `the sequence field is not three characters at seq=${seq}, attempt=${attempt}`,
        ).toHaveLength(3);
      }
    }
    // Still sorts: the cap is a ceiling, not a wrap.
    expect(stampSequenceField(0, 0) < stampSequenceField(1, 0)).toBe(true);
    expect(stampSequenceField(998, 0) < stampSequenceField(998, 1)).toBe(true);

    // And the name the code actually builds carries that field.
    const probe = new HardeningScanner() as unknown as Probe;
    const name = path.basename(await probe.createRunBackupDir(base));
    expect(name.split('-').slice(-2)[0]).toHaveLength(3);
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

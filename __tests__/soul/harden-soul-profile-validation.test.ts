/**
 * `harden-soul --profile` refuses a value that is not a profile (#611).
 *
 * The profile is written into the file's `<!-- soul:profile=… -->` marker, and
 * `scan-soul` trusts that marker to decide which governance domains apply. An
 * unknown value was cast and written verbatim: `harden-soul --profile bogus`
 * exited 0 and minted `soul:profile=bogus`. The writer now refuses before it
 * reads or writes anything, naming the accepted set.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SoulScanner, PROFILE_DOMAINS } from '../../src/soul/scanner';
import { UsageError } from '../../src/checker/errors';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const CLI = join(__dirname, '..', '..', 'dist', 'cli.js');
const MINIMAL_SOUL = '# SOUL.md\n## Identity\nA minimal agent.\n';

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'hma-611-'));
  writeFileSync(join(dir, 'SOUL.md'), MINIMAL_SOUL);
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('hardenSoul refuses an unknown profile (#611)', () => {
  for (const bogus of ['bogus', '', 'tool agent', 'custom-->']) {
    it(`refuses ${JSON.stringify(bogus)} and writes nothing`, async () => {
      const before = readdirSync(dir);
      const err = await new SoulScanner().hardenSoul(dir, { profile: bogus }).then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(err, 'an unknown profile was accepted').toBeInstanceOf(UsageError);
      expect((err as Error).message).toContain('Accepted: ');
      for (const p of Object.keys(PROFILE_DOMAINS)) expect((err as Error).message).toContain(p);
      expect(readdirSync(dir)).toEqual(before);
      expect(readFileSync(join(dir, 'SOUL.md'), 'utf-8')).toBe(MINIMAL_SOUL);
    });
  }

  for (const profile of Object.keys(PROFILE_DOMAINS)) {
    it(`still writes the ${profile} profile into the marker`, async () => {
      await new SoulScanner().hardenSoul(dir, { profile: profile.toUpperCase() });
      expect(readFileSync(join(dir, 'SOUL.md'), 'utf-8')).toContain(`soul:profile=${profile}`);
    });
  }
});

describe.runIf(existsSync(CLI))('harden-soul --profile bogus exits 1 from the CLI (#611)', () => {
  it('names the accepted set on stderr and leaves the file untouched', () => {
    const home = mkdtempSync(join(tmpdir(), 'hma-611-home-'));
    try {
      const r = spawnSync(process.execPath, [CLI, 'harden-soul', '--profile', 'bogus', dir], {
        encoding: 'utf8',
        timeout: 120_000,
        env: { ...process.env, HOME: home, OPENA2A_HOME: home },
      });
      expect(r.status, `${r.stdout}${r.stderr}`).toBe(1);
      expect(r.stderr).toContain("Unknown --profile 'bogus'");
      expect(r.stderr).toContain('tool-agent');
      expect(readFileSync(join(dir, 'SOUL.md'), 'utf-8')).toBe(MINIMAL_SOUL);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  // #861 — the refusal came from `hardenSoul`, after the CLI had already taken
  // its backup: every refused run left a `.hackmyagent-backup/<run>/` holding a
  // manifest and a copy of the governance file.
  it('refuses before the backup, so the target directory is left as it was (#861)', () => {
    const home = mkdtempSync(join(tmpdir(), 'hma-861-home-'));
    try {
      const r = spawnSync(process.execPath, [CLI, 'harden-soul', dir, '--profile', 'bogus'], {
        encoding: 'utf8',
        timeout: 120_000,
        env: { ...process.env, HOME: home, OPENA2A_HOME: home },
      });
      expect(r.status, `${r.stdout}${r.stderr}`).toBe(1);
      expect(r.stderr).toContain("Unknown --profile 'bogus'");
      expect(readdirSync(dir)).toEqual(['SOUL.md']);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});

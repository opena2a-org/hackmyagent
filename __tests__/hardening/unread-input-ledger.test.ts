/**
 * The unit `secure`'s completeness gate is derived from: inputs discovered
 * inside the target and not read (#438).
 *
 * This layer is unconditional on purpose. The end-to-end half
 * (`__tests__/cli/secure-unread-input-gate.test.ts`) needs a file the process
 * cannot read, and `chmod 000` does not deny root — so in a root CI container
 * that suite skips, and everything it pins would go unpinned. These tests drive
 * the ledger directly and hold regardless of who runs them.
 *
 * Measured behaviour being pinned, from the #438 investigation:
 * a tree holding a benign source file and a `src/secrets.js` with an `sk-` key
 * scored `69/100 exit 1` readable and `98/100 exit 0` at mode 000. The score
 * went UP because the unread file left the assessment entirely.
 */
import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import * as fs from 'node:fs';
import * as os from 'node:os';
import { CoverageLedger, countsAsUnread } from '../../src/hardening/coverage-ledger';

const TARGET = path.join(path.sep, 'tmp', 'hma-unread-target');
const inside = (p: string) => path.join(TARGET, p);

/** Drive one failed read attributed to a registered check. */
async function withFailure(
  ledger: CoverageLedger,
  fn: (l: CoverageLedger) => void,
  method = 'checkCredentialExposure',
): Promise<void> {
  await ledger.run(method, async () => { fn(ledger); });
}

describe('#438 countsAsUnread — which errnos mean an input was lost', () => {
  // The three exclusions are the whole discrimination, and each was MEASURED
  // rather than reasoned about. Pinned individually so a future edit to the set
  // has to state which one it is changing.
  it.each(['ENOENT', 'EISDIR', 'ENOTDIR'])(
    '%s means nothing of the kind sought is there, so it is not a lost input',
    (code) => {
      expect(countsAsUnread(code)).toBe(false);
    },
  );

  it.each(['EACCES', 'EPERM', 'EIO', 'ELOOP', 'EMFILE'])(
    '%s means something IS there and its bytes never arrived',
    (code) => {
      expect(countsAsUnread(code)).toBe(true);
    },
  );

  it('counts an errno nobody anticipated, so the unknown case fails closed', () => {
    // The direction matters more than the example. Admitting only a known-good
    // list would make a novel errno a SILENT false negative — the exact defect
    // class this unit exists to close.
    expect(countsAsUnread('ESOMETHINGNEW')).toBe(true);
    expect(countsAsUnread('UNKNOWN')).toBe(true);
  });
});

describe('#438 CoverageLedger records inputs discovered but not read', () => {
  it('records an EACCES inside the target as one unreadable input', async () => {
    const ledger = new CoverageLedger(TARGET);
    await withFailure(ledger, (l) => l.noteReadFailure(inside('secrets.js'), 'EACCES'));

    // Presence first, then content: `expect(x?.count)` would pass against a
    // fix that removed the field entirely.
    const unread = ledger.unreadableInputs;
    expect(unread).toBeDefined();
    expect(unread.count).toBe(1);
    expect(unread.codes).toEqual({ EACCES: 1 });
  });

  it('does NOT record ENOENT, so probing for absent config spellings stays free', async () => {
    const ledger = new CoverageLedger(TARGET);
    await withFailure(ledger, (l) => {
      l.noteReadFailure(inside('.env.production'), 'ENOENT');
      l.noteReadFailure(inside('compose.yaml'), 'ENOENT');
    });
    expect(ledger.unreadableInputs.count).toBe(0);
  });

  it('does NOT record EISDIR — measured to fire on every real repository', async () => {
    // 9 on hackmyagent's own tree, 10 on atlas, 5 on ai-trust, and 1 on a clean
    // two-file fixture, because checks probe `.claude` / `.github` /
    // `node_modules` as files and get a directory back. #438's design brief
    // named EISDIR as a code that SHOULD gate; counting it is a gate that fails
    // every target.
    const ledger = new CoverageLedger(TARGET);
    await withFailure(ledger, (l) => {
      l.noteReadFailure(inside('.claude'), 'EISDIR');
      l.noteReadFailure(inside('node_modules'), 'EISDIR');
    });
    expect(ledger.unreadableInputs.count).toBe(0);
  });

  it('counts twelve probes of ONE unreadable file as one input, not twelve', async () => {
    // The unit is files, not attempts. Several checks probe the same path.
    const ledger = new CoverageLedger(TARGET);
    await withFailure(ledger, (l) => {
      for (let i = 0; i < 12; i++) l.noteReadFailure(inside('secrets.js'), 'EACCES');
    });
    expect(ledger.unreadableInputs.count).toBe(1);
  });

  it('ignores a failure OUTSIDE the target root', async () => {
    const ledger = new CoverageLedger(TARGET);
    await withFailure(ledger, (l) => {
      l.noteReadFailure(path.join(path.sep, 'etc', 'shadow'), 'EACCES');
      // Separator-boundary check: a sibling directory whose name merely starts
      // with the target's is not inside it.
      l.noteReadFailure(`${TARGET}-sibling/x.js`, 'EACCES');
    });
    expect(ledger.unreadableInputs.count).toBe(0);
  });

  it('subtracts a path the SAME check later read successfully, in BOTH orderings', async () => {
    const failFirst = new CoverageLedger(TARGET);
    await failFirst.run('checkCredentialExposure', async () => {
      failFirst.noteReadFailure(inside('retried.js'), 'EACCES');
      failFirst.noteRead(inside('retried.js'));
    });
    expect(failFirst.unreadableInputs.count).toBe(0);

    const readFirst = new CoverageLedger(TARGET);
    await readFirst.run('checkCredentialExposure', async () => {
      readFirst.noteRead(inside('retried.js'));
      readFirst.noteReadFailure(inside('retried.js'), 'EACCES');
    });
    expect(readFirst.unreadableInputs.count).toBe(0);
  });

  it('a DIFFERENT check reading the path does not clear the failure', async () => {
    // The subtraction is per (method, path), not per path. `checkCredential-
    // Exposure` never saw those bytes, so its blindness is real however many
    // other checks managed to open the file — and subtracting scan-globally
    // let one check's success launder another's. Reachable non-adversarially:
    // 16 distinct checks read one fixture file, so any mid-scan mode change
    // opens it.
    const ledger = new CoverageLedger(TARGET);
    await ledger.run('checkCredentialExposure', async () => {
      ledger.noteReadFailure(inside('secrets.js'), 'EACCES');
    });
    await ledger.run('checkClaudeMd', async () => {
      ledger.noteRead(inside('secrets.js'));
    });
    expect(ledger.unreadableInputs.count).toBe(1);
  });

  describe('directory case (#588): a listing that failed is a lost input of the directory kind', () => {
    it('records a readdir EACCES inside the target as one unreadable input, counted in `count` and in `directories`', async () => {
      const ledger = new CoverageLedger(TARGET);
      await withFailure(ledger, (l) => l.noteListFailure(inside('cfg'), 'EACCES'));
      expect(ledger.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 1 });
      expect(ledger.unreadablePaths()).toEqual([{ path: inside('cfg'), code: 'EACCES', kind: 'directory' }]);
    });

    it('emits `directories: 0` on an empty ledger — a consumer must never have to infer the field', () => {
      expect(new CoverageLedger(TARGET).unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
    });

    it.each(['ENOENT', 'ENOTDIR'])('%s on a listing is not a lost directory — same NOT_THERE policy, no second list', async (code) => {
      const ledger = new CoverageLedger(TARGET);
      await withFailure(ledger, (l) => l.noteListFailure(inside('gone'), code));
      expect(ledger.unreadableInputs).toEqual({ count: 0, codes: {}, directories: 0 });
    });

    it('a file record keeps kind `file`, and the two kinds add up in `count`', async () => {
      const ledger = new CoverageLedger(TARGET);
      await withFailure(ledger, (l) => {
        l.noteReadFailure(inside('secrets.js'), 'EACCES');
        l.noteListFailure(inside('cfg'), 'EPERM');
      });
      expect(ledger.unreadableInputs).toEqual({ count: 2, codes: { EACCES: 1, EPERM: 1 }, directories: 1 });
      expect(ledger.unreadablePaths().map((p) => p.kind).sort()).toEqual(['directory', 'file']);
    });

    it('subtracts a directory the SAME check later listed successfully, in both orderings', async () => {
      const failFirst = new CoverageLedger(TARGET);
      await withFailure(failFirst, (l) => {
        l.noteListFailure(inside('cfg'), 'EACCES');
        l.noteInspect(inside('cfg'));
      });
      expect(failFirst.unreadableInputs.directories).toBe(0);
      const listFirst = new CoverageLedger(TARGET);
      await withFailure(listFirst, (l) => {
        l.noteInspect(inside('cfg'));
        l.noteListFailure(inside('cfg'), 'EACCES');
      });
      expect(listFirst.unreadableInputs.directories).toBe(0);
    });

    it('ignores a listing failure OUTSIDE the target root', async () => {
      const ledger = new CoverageLedger(TARGET);
      await withFailure(ledger, (l) => l.noteListFailure(path.join(path.sep, 'etc'), 'EACCES'));
      expect(ledger.unreadableInputs.directories).toBe(0);
    });

    it('records a listing failure raised outside any check — the semantic walker runs unattributed', () => {
      const ledger = new CoverageLedger(TARGET);
      ledger.noteListFailure(inside('cfg'), 'EACCES');
      expect(ledger.unreadableInputs.directories).toBe(1);
    });

    it('coalesces a lost file onto the lost directory above it — one obstruction, one unit', async () => {
      // `chmod 000 cfg`: the walker cannot list cfg/, and a check that probes
      // cfg/secrets.js by name gets EACCES too. Clearing cfg/ clears both.
      const ledger = new CoverageLedger(TARGET);
      await withFailure(ledger, (l) => {
        l.noteListFailure(inside('cfg'), 'EACCES');
        l.noteReadFailure(inside('cfg/secrets.js'), 'EACCES');
        l.noteReadFailure(inside('cfg/deeper/key.pem'), 'EACCES');
      });
      expect(ledger.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 1 });
      expect(ledger.unreadablePaths()).toEqual([{ path: inside('cfg'), code: 'EACCES', kind: 'directory' }]);
    });

    it('coalesces a lost directory onto a lost ancestor directory', async () => {
      const ledger = new CoverageLedger(TARGET);
      await withFailure(ledger, (l) => {
        l.noteListFailure(inside('a'), 'EACCES');
        l.noteListFailure(inside('a/b'), 'EACCES');
      });
      expect(ledger.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 1 });
    });

    it('the scan root itself, unlistable, is ONE record that absorbs every probe beneath it', async () => {
      // Measured before this change: a mode-000 root produced ~64 findings,
      // one per fixed-path probe, and named none of them as the root.
      const ledger = new CoverageLedger(TARGET);
      await withFailure(ledger, (l) => {
        l.noteListFailure(TARGET, 'EACCES');
        for (const p of ['.env', 'package.json', '.claude/settings.json', 'cfg/secrets.js']) l.noteReadFailure(inside(p), 'EACCES');
      });
      expect(ledger.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 1 });
      expect(ledger.unreadablePaths()).toEqual([{ path: TARGET, code: 'EACCES', kind: 'directory' }]);
    });

    it('does NOT coalesce onto a sibling, nor onto an ancestor that is not itself a recorded obstruction', async () => {
      // `chmod 600 a/`: a/ lists fine (not recorded), a/b/ cannot be entered
      // and a/x.js cannot be read. Two records; the remedy names a/ for both,
      // but the ledger does not invent an obstruction it never observed.
      const ledger = new CoverageLedger(TARGET);
      await withFailure(ledger, (l) => {
        l.noteListFailure(inside('a/b'), 'EACCES');
        l.noteReadFailure(inside('a/x.js'), 'EACCES');
        l.noteListFailure(inside('other'), 'EACCES');
      });
      expect(ledger.unreadableInputs).toEqual({ count: 3, codes: { EACCES: 3 }, directories: 2 });
    });

    it('a lost directory that does not COUNT (ENOENT) coalesces nothing', async () => {
      const ledger = new CoverageLedger(TARGET);
      await withFailure(ledger, (l) => {
        l.noteListFailure(inside('cfg'), 'ENOENT');
        l.noteReadFailure(inside('cfg/secrets.js'), 'EACCES');
      });
      expect(ledger.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 0 });
    });

    it('one path recorded on BOTH channels counts once, as the directory', async () => {
      // A mode-000 directory rejects the walker's readdir AND a check's readFile
      // probe of the same path; that is one obstruction, not two.
      const ledger = new CoverageLedger(TARGET);
      await withFailure(ledger, (l) => {
        l.noteReadFailure(inside('cfg'), 'EACCES');
        l.noteListFailure(inside('cfg'), 'EACCES');
      });
      expect(ledger.unreadableInputs).toEqual({ count: 1, codes: { EACCES: 1 }, directories: 1 });
      expect(ledger.unreadablePaths()).toEqual([{ path: inside('cfg'), code: 'EACCES', kind: 'directory' }]);
    });
  });

  it('records a failure raised outside any check — dropping it would overstate', async () => {
    // The one place the failure channel MUST diverge from `note()`. Dropping an
    // unattributable SUCCESS understates coverage (safe); dropping an
    // unattributable FAILURE asserts nothing was lost (forbidden). Measured:
    // the semantic layer runs outside every `coverage.run()` frame, and while
    // failures required a method its EACCES was dropped.
    const ledger = new CoverageLedger(TARGET);
    ledger.noteReadFailure(inside('semantic-only.js'), 'EACCES');
    expect(ledger.unreadableInputs.count).toBe(1);
  });

  it('a NEW readable file cannot clear an unread input — the self-satisfying-gate proof', async () => {
    // This is the whole reason the unit is "discovered but not read" and not
    // any files-read threshold. The reverted fix gated on files-read, which
    // moved the bar from 0 files to 1, and `secure --fix` then satisfied its
    // own gate by writing a `.gitignore` into the target and scoring 100/100
    // with the unreadable credential file still sitting there.
    const ledger = new CoverageLedger(TARGET);
    await ledger.run('checkCredentialExposure', async () => {
      ledger.noteReadFailure(inside('secrets.js'), 'EACCES');
    });
    await ledger.run('checkGitSecurity', async () => {
      ledger.noteRead(inside('.gitignore'));      // what `--fix` writes
      ledger.noteRead(inside('another.js'));
      ledger.noteRead(inside('yet-another.js'));
    });

    expect(ledger.filesExamined).toBe(3);         // coverage genuinely grew
    expect(ledger.unreadableInputs.count).toBe(1); // and the hole is still open
  });

  it('keeps a symlink resolving INSIDE the target and drops one escaping it', async () => {
    // Containment is decided on the REAL path, so a committable
    // `src/evil.js -> /etc/master.passwd` is not a lost input — the read that
    // failed never touched the scanned tree.
    //
    // Both directions are pinned HERE, at a root passed through `realpathSync`,
    // because the end-to-end suite cannot pin the keep direction: it builds
    // fixtures under `os.tmpdir()`, which on macOS resolves through
    // `/var -> /private/var`, so EVERY fixture path satisfies
    // `real !== resolved`. A mutant that dropped every symlinked path — inside
    // or out — is invisible there and would be invisible on a Linux CI runner
    // whose tmpdir is not a symlink. This test is what kills it.
    const real = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'hma-ledger-')));
    try {
      const target = path.join(real, 'src');
      fs.mkdirSync(target, { recursive: true });
      fs.writeFileSync(path.join(target, 'real.js'), 'module.exports={};\n');
      fs.symlinkSync('real.js', path.join(target, 'inside-link.js'));

      // A path that exists outside the target, for the escape direction.
      const outsideFile = path.join(real, 'outside.js');
      fs.writeFileSync(outsideFile, 'module.exports={};\n');
      const escaping = path.join(target, 'escape-link.js');
      fs.symlinkSync(outsideFile, escaping);

      const ledger = new CoverageLedger(target);
      await ledger.run('checkCredentialExposure', async () => {
        ledger.noteReadFailure(path.join(target, 'inside-link.js'), 'EACCES');
        ledger.noteReadFailure(escaping, 'EACCES');
      });

      // Presence first, then the discrimination.
      const unread = ledger.unreadableInputs;
      expect(unread).toBeDefined();
      expect(unread.count).toBe(1);
      expect(ledger.unreadablePaths().map((u) => path.basename(u.path)))
        .toEqual(['inside-link.js']);
    } finally {
      fs.rmSync(real, { recursive: true, force: true });
    }
  });

  it('reports counts and errno codes but never a path', async () => {
    // `ScanResult.coverage` is serialized wholesale into `--json`, and a
    // single-file scan normalises its target into a generated temp directory.
    // Emitting read paths there once leaked that name.
    const ledger = new CoverageLedger(TARGET);
    await withFailure(ledger, (l) => l.noteReadFailure(inside('secrets.js'), 'EACCES'));

    const serialized = JSON.stringify(ledger.unreadableInputs);
    expect(serialized).not.toContain('secrets.js');
    expect(serialized).not.toContain(TARGET);
    // The paths ARE available, on the channel that is allowed to carry them.
    expect(ledger.unreadablePaths().map((u) => u.path)).toEqual([inside('secrets.js')]);
  });
});

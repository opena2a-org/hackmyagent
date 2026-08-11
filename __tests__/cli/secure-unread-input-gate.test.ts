/**
 * `secure` must not report a passing verdict over a tree it could not read
 * (#438), on ANY output channel.
 *
 * Measured on `890084d` (0.29.0, published `latest`), one fixture and one
 * `chmod`. The tree holds a benign `src/util.js`, a `.gitignore`, and a
 * `src/secrets.js` containing an `sk-` API key:
 *
 *   src/secrets.js mode 644  ->  69/100  exit 1   (the credential is found)
 *   src/secrets.js mode 000  ->  98/100  exit 0   (text, json, sarif, html, asff)
 *
 * The score went UP and the gate flipped open because the unread file left the
 * assessment. `secure --fix` then wrote a `.gitignore` into that tree and the
 * next run scored 100/100 exit 0 with the credential file still unreadable.
 *
 * ## Why this suite is shaped the way it is
 *
 * Every assertion below is paired with a control, because a gate that fires on
 * everything is not a gate. The controls are: the SAME tree fully readable
 * (must keep its old exit code and its old score), a clean tree, and a tree
 * whose only read failures are EISDIR — the case #438's own design brief said
 * should gate, and which fires on every real repository.
 *
 * `chmod 000` does not deny root, so the end-to-end cases probe for real
 * unreadability and skip when they cannot get it. The ledger-level rules are
 * pinned unconditionally in `__tests__/hardening/unread-input-ledger.test.ts`
 * so a root CI container does not leave this class unpinned.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

const CLI = path.join(__dirname, '..', '..', 'dist', 'cli.js');

/** Measured, and the result is one the command promises to fail on. */
const EXIT_FAIL = 1;
/** The run did not examine everything it found. */
const EXIT_INCOMPLETE = 2;

const SK_KEY = `sk-proj-${'A'.repeat(48)}`;

let root: string;
/** Directories whose modes must be restored before the tree can be removed. */
const restore: string[] = [];

function run(args: string[]) {
  const res = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 240_000,
    env: {
      ...process.env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-')),
    },
  });
  return { status: res.status, out: `${res.stdout ?? ''}${res.stderr ?? ''}` };
}

function json(args: string[]) {
  const res = run([...args, '--format', 'json']);
  try {
    return { status: res.status, body: JSON.parse(res.out.slice(res.out.indexOf('{'))) as any };
  } catch {
    return { status: res.status, body: null as any };
  }
}

/**
 * Build the fixture. The readable file is BENIGN on purpose: if it carried a
 * finding of its own the tree would already exit 1 for that reason, and every
 * exit-code assertion here would pass without the gate existing at all.
 */
function makeTree(name: string): string {
  const dir = path.join(root, name);
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'src', 'util.js'), 'function add(a,b){return a+b;}\nmodule.exports={add};\n');
  fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n.env\n*.pem\n*.key\n');
  fs.writeFileSync(path.join(dir, 'src', 'secrets.js'), `const K = "${SK_KEY}";\nmodule.exports={K};\n`);
  return dir;
}

/** Make a path unreadable and PROVE it. Returns false when the OS declined. */
function makeUnreadable(file: string): boolean {
  fs.chmodSync(file, 0o000);
  restore.push(file);
  try {
    fs.readFileSync(file);
    return false; // root, or a filesystem without permission support
  } catch {
    return true;
  }
}

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-438-'));
});

afterAll(() => {
  // Restore BEFORE removing, or the tree cannot be removed. In afterAll rather
  // than a try/finally in the test body: a vitest timeout skips a `finally`.
  for (const p of restore) {
    try { fs.chmodSync(p, 0o644); } catch { /* already gone */ }
  }
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
});

describe('#438 secure settles one verdict over a tree it could not read', () => {
  // Each output channel is its own `return` inside the action, and each one
  // shipped its own copy of the exit rule. `--fail-below` is already silently
  // inert on three of them (#494) for exactly that reason, so the channels are
  // enumerated rather than sampled.
  const CHANNELS: [string, string[]][] = [
    ['text', []],
    ['json', ['--format', 'json']],
    ['sarif', ['--format', 'sarif']],
    ['html', ['--format', 'html']],
    ['asff', ['--format', 'asff']],
  ];

  it.each(CHANNELS)('%s: an unreadable input is not a pass', (_name, extra) => {
    const dir = makeTree(`chan-${_name}`);
    if (!makeUnreadable(path.join(dir, 'src', 'secrets.js'))) {
      console.warn('skipped: this process can read a mode-000 file (running as root?)');
      return;
    }
    const res = run(['secure', dir, ...extra]);
    expect(res.status).toBe(EXIT_INCOMPLETE);
  });

  it.each(CHANNELS)(
    '%s CONTROL: the same tree fully readable keeps its old exit code',
    (_name, extra) => {
      // Without this, a fix that returned non-zero unconditionally would pass
      // every assertion above.
      const dir = makeTree(`ctl-${_name}`);
      const res = run(['secure', dir, ...extra]);
      expect(res.status).toBe(EXIT_FAIL);
    },
  );

  it('CONTROL: a clean readable tree still exits 0', () => {
    const dir = path.join(root, 'clean');
    fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'src', 'util.js'), 'module.exports={};\n');
    fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n.env\n*.pem\n*.key\n');
    expect(run(['secure', dir]).status).toBe(0);
  });

  it('CONTROL: directories named like files (EISDIR) do not trip the gate', () => {
    // The false-positive guard, and the reason the errno set was measured
    // instead of taken from the design brief. Counting EISDIR fires on every
    // real repository — 9 on hackmyagent's own tree, 10 on atlas — because
    // checks probe `.claude`, `.github` and `node_modules` as files.
    const dir = path.join(root, 'eisdir');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n.env\n*.pem\n*.key\n');
    for (const d of ['.env', 'package.json', 'CLAUDE.md', '.claude']) {
      fs.mkdirSync(path.join(dir, d), { recursive: true });
    }
    const res = json(['secure', dir]);
    expect(res.body).not.toBeNull();
    expect(res.body.coverage?.unreadableInputs).toBeDefined();
    // The gate's input: no EISDIR is counted as a lost input.
    expect(res.body.coverage.unreadableInputs.count).toBe(0);
    // The gate's output. Deliberately `not 2` rather than `0`: a directory
    // named `.env` earns a real PERM-001 HIGH, so this tree exits 1 on its own
    // merits and always did. Asserting 0 here would pin an unrelated fact and
    // would go red the next time a check learns something about this shape.
    // The exit-0 direction is controlled separately by the clean-tree case.
    expect(res.status).not.toBe(EXIT_INCOMPLETE);
  });
});

describe('#438 the run says which input it could not read', () => {
  it('names the file in a finding and offers a runnable fix', () => {
    const dir = makeTree('discloses');
    if (!makeUnreadable(path.join(dir, 'src', 'secrets.js'))) {
      console.warn('skipped: this process can read a mode-000 file (running as root?)');
      return;
    }
    const res = json(['secure', dir]);
    expect(res.body).not.toBeNull();

    // Presence before content, and no optional chaining on the assertion
    // itself: `expect(f?.file)` would pass against a fix that removed the
    // finding altogether.
    const finding = (res.body.findings ?? []).find((f: any) => f.checkId === 'SCAN-UNREAD-001');
    expect(finding).toBeDefined();
    expect(finding.file).toContain('secrets.js');
    expect(finding.fix).toMatch(/chmod u\+r/);

    // The coverage block answers the machine question without carrying paths.
    expect(res.body.coverage.unreadableInputs.count).toBe(1);
    expect(Object.keys(res.body.coverage.unreadableInputs.codes)).toContain('EACCES');
    expect(JSON.stringify(res.body.coverage.unreadableInputs)).not.toContain('secrets.js');
  });

  it('still reports a numeric score, because the tree WAS partly measured', () => {
    // Not a `NOT MEASURED` withholding: two files were read. The score is an
    // upper bound and the exit code is what says the run did not finish.
    // A release-smoke harness treats a non-numeric score as a hard failure.
    const dir = makeTree('scored');
    if (!makeUnreadable(path.join(dir, 'src', 'secrets.js'))) {
      console.warn('skipped: this process can read a mode-000 file (running as root?)');
      return;
    }
    const res = json(['secure', dir]);
    expect(res.body).not.toBeNull();
    expect(typeof res.body.score).toBe('number');
  });
});

describe('#438 the gate is deterministic and names every path', () => {
  it('returns 2 on every one of N consecutive runs', () => {
    // A gate that fires most of the time is not a gate, and the miss is a
    // silent pass on exactly the defect. 60 runs were measured by hand at 0
    // misses; this keeps a cheap standing check on it.
    const dir = makeTree('determinism');
    if (!makeUnreadable(path.join(dir, 'src', 'secrets.js'))) {
      console.warn('skipped: this process can read a mode-000 file (running as root?)');
      return;
    }
    const codes = Array.from({ length: 5 }, () => run(['secure', dir]).status);
    expect(codes).toEqual([2, 2, 2, 2, 2]);
  }, 240_000);

  it('emits one finding per unreadable path, not one naming the first of N', () => {
    // `file` is a single field and SARIF/ASFF consumers key on it, so a summary
    // finding leaves every path after the first in no structured field.
    const dir = makeTree('twofiles');
    fs.writeFileSync(path.join(dir, 'src', 'other.js'), `const B = "${SK_KEY}";\n`);
    const a = makeUnreadable(path.join(dir, 'src', 'secrets.js'));
    const b = makeUnreadable(path.join(dir, 'src', 'other.js'));
    if (!a || !b) {
      console.warn('skipped: this process can read a mode-000 file (running as root?)');
      return;
    }
    const res = json(['secure', dir]);
    expect(res.body).not.toBeNull();
    const named = (res.body.findings ?? [])
      .filter((f: any) => f.checkId === 'SCAN-UNREAD-001')
      .map((f: any) => f.file)
      .sort();
    expect(named).toEqual(['src/other.js', 'src/secrets.js']);
    expect(res.body.coverage.unreadableInputs.count).toBe(2);
  }, 240_000);
});

describe('#438 the gate cannot be satisfied by writing into the target', () => {
  it('--fix writing a .gitignore does not clear an unread input', () => {
    // The hazard that killed the reverted files-read gate: `secure --fix`
    // wrote a `.gitignore`, re-read it, and thereby satisfied its own coverage
    // threshold — scoring 100/100 exit 0 with the unreadable credential file
    // still present. An unread count cannot be cleared that way.
    const dir = makeTree('selfsat');
    fs.rmSync(path.join(dir, '.gitignore'));
    if (!makeUnreadable(path.join(dir, 'src', 'secrets.js'))) {
      console.warn('skipped: this process can read a mode-000 file (running as root?)');
      return;
    }
    run(['secure', dir, '--fix']);
    expect(fs.existsSync(path.join(dir, '.gitignore'))).toBe(true); // --fix did write

    const after = json(['secure', dir]);
    expect(after.body).not.toBeNull();
    expect(after.body.coverage.unreadableInputs.count).toBe(1);
    expect(after.status).toBe(EXIT_INCOMPLETE);
  });
});

describe('#438 the unit counts only paths the scan is responsible for', () => {
  it('a symlink whose target escapes the tree is not a lost input', () => {
    // Found by adversarial review. `src/evil.js -> /etc/master.passwd` needs no
    // chmod and no privileges — any contributor can commit it — and the read
    // that failed never touched the scanned tree. Counting it gated ordinary
    // repositories at exit 2 permanently, with a `chmod` remedy that reports
    // success and changes nothing, because the file it names is not the file
    // that was read.
    const dir = path.join(root, 'symlink-escape');
    fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'src', 'ok.js'), 'module.exports={};\n');
    fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n.env\n*.pem\n*.key\n');
    // A path that exists and this process cannot read, OUTSIDE the target.
    const outside = '/etc/master.passwd';
    let unreadableOutside = false;
    try { fs.readFileSync(outside); } catch { unreadableOutside = fs.existsSync(outside); }
    if (!unreadableOutside) {
      console.warn('skipped: no unreadable path outside the target on this host');
      return;
    }
    fs.symlinkSync(outside, path.join(dir, 'src', 'evil.js'));

    const res = json(['secure', dir]);
    expect(res.body).not.toBeNull();
    expect(res.body.coverage.unreadableInputs.count).toBe(0);
    expect(res.status).toBe(0);
  }, 240_000);

  it('CONTROL: a symlink to an unreadable file INSIDE the tree still counts', () => {
    // Without this, the fix above is indistinguishable from "stop counting
    // anything reached through a symlink", which would switch the gate off for
    // any tree that uses them. The link resolves to a real file inside the
    // target, so the input genuinely was discovered and not read.
    const dir = makeTree('symlink-inside');
    if (!makeUnreadable(path.join(dir, 'src', 'secrets.js'))) {
      console.warn('skipped: this process can read a mode-000 file (running as root?)');
      return;
    }
    fs.symlinkSync('secrets.js', path.join(dir, 'src', 'link.js'));
    const res = json(['secure', dir]);
    expect(res.body).not.toBeNull();
    expect(res.body.coverage.unreadableInputs.count).toBeGreaterThan(0);
    expect(res.status).toBe(EXIT_INCOMPLETE);
  }, 240_000);

  it('an .hmaignore PATH rule does NOT scope an unread input out of the gate', () => {
    // A path rule legitimately scopes findings ABOUT a file's contents — but it
    // cannot make the scan's own claim about what it READ true, and exit 0 here
    // is only defensible if the run says what it dropped. It cannot: `outOfScope`
    // renders as a bare count on text and --json and NOT AT ALL on sarif, asff
    // and html, so honouring the rule produced exit 0 with nothing said on three
    // of five channels — on the channels a CI consumer reads.
    //
    // Two earlier shapes of this were tried and both traded one direction for
    // another: filtering the finding out went silent on every channel, and
    // routing it through `outOfScope` went silent on the machine ones. The unit
    // stays un-scopeable until the disclosure exists everywhere.
    const dir = makeTree('hmaignore-scope');
    if (!makeUnreadable(path.join(dir, 'src', 'secrets.js'))) {
      console.warn('skipped: this process can read a mode-000 file (running as root?)');
      return;
    }
    fs.writeFileSync(path.join(dir, '.hmaignore'), 'src/secrets.js\n');

    const scoped = json(['secure', dir]);
    expect(scoped.body).not.toBeNull();
    expect(scoped.body.coverage.unreadableInputs.count).toBe(1);
    expect(scoped.status).toBe(EXIT_INCOMPLETE);

    // And it is NAMED, not reduced to a count — on the machine channels too.
    const named = (scoped.body.findings ?? []).filter((f: any) => f.checkId === 'SCAN-UNREAD-001');
    expect(named.length).toBe(1);
    expect(named[0].file).toContain('secrets.js');
    expect(run(['secure', dir, '--format', 'sarif']).out).toContain('SCAN-UNREAD-001');
  }, 240_000);

  it('--ignore <checkId> does NOT clear the gate — suppressing a check is not scoping', () => {
    // #450's distinction, and the reason the case above is not a laundering
    // hole: narrowing the scanned SCOPE is a disclosed statement about what the
    // run covered; suppressing a CHECK is a request not to be shown a finding,
    // and it may not move the verdict.
    const dir = makeTree('ignore-flag');
    if (!makeUnreadable(path.join(dir, 'src', 'secrets.js'))) {
      console.warn('skipped: this process can read a mode-000 file (running as root?)');
      return;
    }
    expect(run(['secure', dir, '--ignore', 'SCAN-UNREAD-001']).status).toBe(EXIT_INCOMPLETE);
  }, 240_000);

  it('an .hmaignore CHECK-ID rule does NOT clear the gate either', () => {
    // A different code path from `--ignore` (`hmaIgnore.checkIds`, not the
    // flag). Unpinned, it would open the laundering hole with a green suite the
    // first time someone folded check-ID rules into the path-scoping filter.
    const dir = makeTree('hmaignore-checkid');
    if (!makeUnreadable(path.join(dir, 'src', 'secrets.js'))) {
      console.warn('skipped: this process can read a mode-000 file (running as root?)');
      return;
    }
    fs.writeFileSync(path.join(dir, '.hmaignore'), '!SCAN-UNREAD-001\n');
    expect(run(['secure', dir]).status).toBe(EXIT_INCOMPLETE);
  }, 240_000);
});

describe('#438 --fail-below cannot bypass the settlement', () => {
  it('a threshold that passes does not restore exit 0 over an unread input', () => {
    // The #390 round-1 shape, and the reason the settlement is above the
    // channel branch: both `--fail-below` early returns sit ABOVE each
    // channel's own critical/high line and `return` before reaching it. A gate
    // placed at those lines is bypassed whenever the threshold is supplied.
    const dir = makeTree('failbelow');
    if (!makeUnreadable(path.join(dir, 'src', 'secrets.js'))) {
      console.warn('skipped: this process can read a mode-000 file (running as root?)');
      return;
    }
    for (const extra of [[], ['--format', 'json']]) {
      const res = run(['secure', dir, '--fail-below', '1', ...extra]);
      expect(res.status).not.toBe(0);
    }
  });
});

/**
 * #499 — the same settlement, at every `--scan-depth`.
 *
 * #438 closed the gate at `standard` and `deep` and left `quick` open, so a
 * documented flag was a one-token bypass of the completeness floor. Measured on
 * `67e6f04` (0.30.0, published `latest`), the fixture below:
 *
 *   mode 000 --scan-depth quick     ->  98/100  exit 0   unreadableInputs 0
 *   mode 000 --scan-depth standard  ->  93/100  exit 2   unreadableInputs 1
 *   mode 000 --scan-depth deep      ->  93/100  exit 2   unreadableInputs 1
 *
 * At quick depth 55 of the 61 orchestrated checks are skipped and the ONLY
 * reader of the file is the NanoMind semantic layer, which ran after
 * `scanInner` had already returned — outside the coverage ledger's window, and
 * through the raw `fs` namespace rather than the tracked one. Two independent
 * bypasses stacked: the ambient ledger was null, and the reads were untracked.
 *
 * The depths are read out of `src/cli.ts`'s own `validDepths` rather than
 * written here, so a fourth depth cannot be added without either extending this
 * suite or failing it.
 */
const VALID_DEPTHS: string[] = (() => {
  const src = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'cli.ts'), 'utf-8');
  const m = src.match(/const validDepths = \[([^\]]+)\]/);
  if (!m) throw new Error('cannot locate validDepths in src/cli.ts — the enumeration source moved');
  const depths = m[1].split(',').map((s) => s.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean);
  // A silently-empty parse would enumerate nothing and pass every case.
  if (depths.length < 3) throw new Error(`validDepths parsed to ${JSON.stringify(depths)} — refusing to run a vacuous enumeration`);
  return depths;
})();

describe('#499 the completeness floor holds at every scan depth', () => {
  it.each(VALID_DEPTHS)('%s: an unreadable input is not a pass', (depth) => {
    const dir = makeTree(`depth-${depth}`);
    if (!makeUnreadable(path.join(dir, 'src', 'secrets.js'))) {
      console.warn('skipped: this process can read a mode-000 file (running as root?)');
      return;
    }
    expect(run(['secure', dir, '--scan-depth', depth]).status).toBe(EXIT_INCOMPLETE);
  }, 240_000);

  it.each(VALID_DEPTHS)('%s: the unread input is NAMED, on every channel', (depth) => {
    const dir = makeTree(`depth-named-${depth}`);
    if (!makeUnreadable(path.join(dir, 'src', 'secrets.js'))) {
      console.warn('skipped: this process can read a mode-000 file (running as root?)');
      return;
    }
    // A count with no name is the shape #438 rejected: `outOfScope` rendered as
    // a bare number on two channels and not at all on three.
    const body = json(['secure', dir, '--scan-depth', depth]);
    expect(body.body).not.toBeNull();
    const named = (body.body.findings ?? []).filter((f: any) => f.checkId === 'SCAN-UNREAD-001');
    expect(named.length).toBe(1);
    expect(named[0].file).toContain('secrets.js');
    expect(run(['secure', dir, '--scan-depth', depth, '--format', 'sarif']).out).toContain('SCAN-UNREAD-001');
  }, 240_000);

  it.each(VALID_DEPTHS)('%s CONTROL: the same tree fully readable keeps exit 1', (depth) => {
    // Without this the suite would pass on a change that gated every tree.
    //
    // At `quick` the exit 1 is earned by AST-CRED-001/003 from the SEMANTIC
    // layer — the static pass never reads `secrets.js` at that depth. So a
    // "fix" that closed the gap by disabling NanoMind at quick turns this
    // control red, which is correct: it would trade a false pass for a blind
    // one.
    const dir = makeTree(`depth-control-${depth}`);
    expect(run(['secure', dir, '--scan-depth', depth]).status).toBe(EXIT_FAIL);
  }, 240_000);

  it.each(VALID_DEPTHS)('%s CONTROL: a clean readable tree still exits 0', (depth) => {
    // The negative control that keeps this a gate rather than a blanket fail.
    //
    // Ruled 2026-08-11 (Abdel, on a CPO/CISO split): `--scan-depth quick` KEEPS
    // its ability to exit 0. CISO argued a run that skipped 55 of 61 checks may
    // never pass; the ruling is that #438's unit is "inputs discovered and not
    // read", not "every check ran", and a user passing `--scan-depth quick`
    // consented to the reduced depth. That objection is tracked separately, not
    // absorbed here.
    const dir = path.join(root, `depth-clean-${depth}`);
    fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'src', 'util.js'), 'function add(a,b){return a+b;}\nmodule.exports={add};\n');
    fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules/\n.env\n*.pem\n*.key\n');
    expect(run(['secure', dir, '--scan-depth', depth]).status).toBe(0);
  }, 240_000);
});

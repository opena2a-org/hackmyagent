/**
 * HMA-40 — scripts/release-artifact-review.mjs, executed against tarballs
 * built to fail: red first, per check, then green.
 *
 * One poisoned tarball per blocking class in the contract (a dotfile entry, a
 * fixtures/ entry, a postinstall script, a caret on an `@opena2a/` dependency,
 * a dist/cli.js that exits 1 on `--version`, an integrity manifest that is
 * absent, and one whose `files` set omits a shipped file), each asserting the
 * script exits non-zero with THAT check and only that check failing. Then the
 * green side: a clean fixture passes 11/11, and the tarball packed from the
 * delivered tree has no failing check at all.
 *
 * The poisoned tarballs carry a dependency-free stand-in CLI rather than the
 * real dist: the poison under test is in the TARBALL SHAPE, and a stand-in
 * with no dependencies installs into the temp global prefix without touching
 * the registry, so every red row runs offline and in seconds. The real dist
 * is exercised by the delivered-tree row, which packs the repository with
 * `npm pack` exactly as the release build job does.
 *
 * BD12 rows: a check that cannot run is an ERROR — the no-dist tarball exits
 * non-zero with `precondition` in its output and zero failing checks — and
 * the census line names every check on every outcome, so a check can never
 * silently vanish from a run.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// #285 — the delivered-tree row packs the repository, dist/ included, so a
// stale build here would review (and pass) a binary that is no longer the
// code under review.
beforeAll(assertDistFreshIfPresent);

const ROOT = path.join(__dirname, '..', '..');
const SCRIPT = path.join(ROOT, 'scripts', 'release-artifact-review.mjs');

/** Must match CHECKS in the script; the census row below asserts the correspondence. */
const CHECK_NAMES = [
  'entry-allowlist',
  'no-dotfiles',
  'no-test-paths',
  'no-lifecycle-scripts',
  'pinned-first-party',
  'smoke-version',
  'smoke-help',
  'smoke-secure-ci',
  'credential-control',
  'self-check-live',
  'audit-high',
];

let work: string;
beforeAll(() => {
  work = fs.mkdtempSync(path.join(os.tmpdir(), 'hma40-review-'));
});
afterAll(() => {
  fs.rmSync(work, { recursive: true, force: true });
});

/**
 * The stand-in CLI. It honours the exact surface the review script drives:
 * `--version`, `--help`, and `secure --ci [--format json] <dir>` with the
 * real CLI's exit-code contract (0 clean, 1 on findings) and the real JSON
 * shape (`{ findings: [{ checkId, file }] }`), plus the real CLI's startup
 * self-check: every file the shipped `dist/integrity-manifest.json` lists is
 * hashed before any command is served, a mismatch quarantines (exit 3,
 * INTEGRITY CHECK FAILED on stderr), and an absent manifest is dev-mode
 * CLEAN — which is exactly the fail-open class `self-check-live` exists to
 * catch. The credential marker is assembled at runtime so no
 * credential-shaped literal sits in this file — same idiom as
 * obstruction-disclosure.test.ts.
 */
const FIXTURE_CLI = `#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const manifestPath = path.join(__dirname, 'integrity-manifest.json');
if (fs.existsSync(manifestPath)) {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  for (const [rel, expected] of Object.entries(manifest.files || {})) {
    let actual = null;
    try {
      actual = crypto.createHash('sha256').update(fs.readFileSync(path.join(__dirname, rel))).digest('hex');
    } catch {}
    if (actual !== expected) {
      console.error('INTEGRITY CHECK FAILED: ' + rel + ' tampered');
      process.exit(3);
    }
  }
}
const a = process.argv.slice(2);
if (a[0] === '--version') { console.log('0.0.0-fixture'); process.exit(0); }
if (a[0] === '--help') { console.log('Usage: hackmyagent <command>'); process.exit(0); }
if (a[0] === 'secure') {
  const dir = a.filter((x) => !x.startsWith('--') && x !== 'json').slice(1).pop() || '.';
  const json = a.includes('--format') && a[a.indexOf('--format') + 1] === 'json';
  const marker = ['sk-', 'proj-'].join('');
  const findings = [];
  (function walk(d) {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else {
        let t = '';
        try { t = fs.readFileSync(p, 'utf8'); } catch {}
        if (t.includes(marker)) findings.push({ checkId: 'CRED-001', severity: 'critical', file: p });
      }
    }
  })(path.resolve(dir));
  if (json) console.log(JSON.stringify({ findings }));
  else console.log(findings.length + ' finding(s)');
  process.exit(findings.length ? 1 : 0);
}
process.exit(0);
`;

const BASE_PKG = {
  name: 'hackmyagent',
  version: '0.0.0-fixture',
  bin: { hackmyagent: 'dist/cli.js' },
  dependencies: {} as Record<string, string>,
};

interface FixtureManifest {
  version: string;
  files: Record<string, string>;
}

/**
 * How a tarball gets its integrity manifest. `'auto'` (the default) computes
 * it from the final file record exactly as the build script does — every
 * dist/ file hashed, the manifest itself excluded — so each poisoned row
 * stays one mutation away from the clean one. `'absent'` drops it, and a
 * mutator poisons it, which are the two `self-check-live` red classes.
 */
type ManifestMode = 'auto' | 'absent' | ((m: FixtureManifest) => FixtureManifest);

function makeTarball(
  name: string,
  files: Record<string, string>,
  manifestMode: ManifestMode = 'auto',
): string {
  const full = { ...files };
  if (manifestMode !== 'absent') {
    const hashes: Record<string, string> = {};
    for (const [p, c] of Object.entries(full)) {
      if (p.startsWith('dist/')) {
        hashes[p.slice('dist/'.length)] = createHash('sha256').update(c).digest('hex');
      }
    }
    let manifest: FixtureManifest = {
      version: JSON.parse(full['package.json']).version,
      files: hashes,
    };
    if (typeof manifestMode === 'function') manifest = manifestMode(manifest);
    full['dist/integrity-manifest.json'] = JSON.stringify(manifest);
  }
  const stage = path.join(work, `stage-${name}`);
  fs.rmSync(stage, { recursive: true, force: true });
  for (const [p, c] of Object.entries(full)) {
    const fp = path.join(stage, 'package', p);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, c);
  }
  const out = path.join(work, `${name}.tgz`);
  execFileSync('tar', ['-czf', out, '-C', stage, 'package']);
  return out;
}

function baseFiles(): Record<string, string> {
  return {
    'package.json': JSON.stringify(BASE_PKG),
    'README.md': 'fixture\n',
    LICENSE: 'Apache-2.0\n',
    'dist/cli.js': FIXTURE_CLI,
    'dist/index.js': 'module.exports = {};\n',
  };
}

interface Review {
  status: number;
  stdout: string;
  fails: string[];
  preconditions: string[];
  census: string;
}

function review(tarball: string): Review {
  // npm_config_* stripped: `npm test` exports its own configuration to every
  // child, and the script's inner `npm install -g` / `npm audit` must see the
  // environment the release review job gives them, not vitest's.
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined && !/^npm_/i.test(k)) env[k] = v;
  }
  const r = spawnSync(process.execPath, [SCRIPT, '--tarball', tarball], {
    encoding: 'utf8',
    env,
    timeout: 570_000,
    maxBuffer: 64 * 1024 * 1024,
  });
  const stdout = r.stdout ?? '';
  return {
    status: r.status ?? -1,
    stdout,
    fails: [...stdout.matchAll(/^check (\S+): FAIL/gm)].map((m) => m[1]),
    preconditions: [...stdout.matchAll(/^check (\S+): precondition/gm)].map((m) => m[1]),
    census: /^census: (.*)$/m.exec(stdout)?.[1] ?? '',
  };
}

function expectFullCensus(r: Review): void {
  for (const name of CHECK_NAMES) {
    expect(r.census, `census line is missing ${name}`).toContain(`${name}=`);
  }
}

describe('HMA-40: release-artifact-review over poisoned and clean tarballs', { timeout: 600_000 }, () => {
  it('HMA-40.AC3 a dotfile entry fails the review naming no-dotfiles and nothing else', () => {
    const r = review(makeTarball('dotfile', { ...baseFiles(), 'dist/.cache': 'x\n' }));
    expect(r.status).not.toBe(0);
    expect(r.fails).toEqual(['no-dotfiles']);
    expectFullCensus(r);
  });

  it('HMA-40.AC3 a fixtures/ entry fails the review naming no-test-paths and nothing else', () => {
    const r = review(makeTarball('fixtures', { ...baseFiles(), 'dist/fixtures/sample.js': 'x\n' }));
    expect(r.status).not.toBe(0);
    expect(r.fails).toEqual(['no-test-paths']);
    expectFullCensus(r);
  });

  it('HMA-40.AC3 a postinstall script fails the review naming no-lifecycle-scripts and nothing else', () => {
    const r = review(
      makeTarball('postinstall', {
        ...baseFiles(),
        'package.json': JSON.stringify({ ...BASE_PKG, scripts: { postinstall: 'echo hi' } }),
      }),
    );
    expect(r.status).not.toBe(0);
    expect(r.fails).toEqual(['no-lifecycle-scripts']);
    expectFullCensus(r);
  });

  it('HMA-40.AC3 a caret on an @opena2a/ dependency fails the review naming pinned-first-party and nothing else', () => {
    const r = review(
      makeTarball('caret', {
        ...baseFiles(),
        'package.json': JSON.stringify({
          ...BASE_PKG,
          dependencies: { '@opena2a/aim-core': '^0.1.2' },
        }),
      }),
    );
    expect(r.status).not.toBe(0);
    expect(r.fails).toEqual(['pinned-first-party']);
    expectFullCensus(r);
    // A tarball that failed static review is never executed: the smoke checks
    // must be preconditions here, not passes and not installs.
    for (const name of ['smoke-version', 'smoke-help', 'smoke-secure-ci', 'credential-control', 'self-check-live']) {
      expect(r.preconditions).toContain(name);
    }
  });

  it('HMA-40.AC3 a dist/cli.js that exits 1 on --version fails the review naming smoke-version and nothing else', () => {
    const broken = FIXTURE_CLI.replace(
      "console.log('0.0.0-fixture'); process.exit(0);",
      "console.error('version unavailable'); process.exit(1);",
    );
    expect(broken).not.toBe(FIXTURE_CLI); // the mutation applied; a no-op here would test nothing
    const r = review(makeTarball('brokenver', { ...baseFiles(), 'dist/cli.js': broken }));
    expect(r.status).not.toBe(0);
    expect(r.fails).toEqual(['smoke-version']);
    expectFullCensus(r);
  });

  it('HMA-40.AC3 an absent integrity manifest fails the review naming self-check-live and nothing else', () => {
    // The fail-open class the rework ruling names: with the manifest absent
    // the CLI's own startup check answers dev-mode CLEAN, every smoke check
    // passes, and only self-check-live stands between that tarball and a
    // publish.
    const r = review(makeTarball('nomanifest', baseFiles(), 'absent'));
    expect(r.status).not.toBe(0);
    expect(r.fails).toEqual(['self-check-live']);
    expectFullCensus(r);
  });

  it('HMA-40.AC3 a manifest with one files key removed fails the review naming self-check-live and nothing else', () => {
    // A file the manifest does not list is a file the self-check never
    // verifies — undetectably tamperable in every install.
    const r = review(
      makeTarball('gappedmanifest', baseFiles(), (manifest) => {
        expect(manifest.files['index.js']).toBeDefined(); // the deletion below deletes something real
        delete manifest.files['index.js'];
        return manifest;
      }),
    );
    expect(r.status).not.toBe(0);
    expect(r.fails).toEqual(['self-check-live']);
    expectFullCensus(r);
  });

  it('HMA-40.AC3 a tarball with no dist/ exits non-zero with precondition in its output, and zero failing checks', () => {
    const files = baseFiles();
    delete files['dist/cli.js'];
    delete files['dist/index.js'];
    // 'absent' so nothing at all ships under dist/ — an auto manifest would
    // itself be a dist/ entry and turn this into a different class.
    const r = review(makeTarball('nodist', files, 'absent'));
    expect(r.status).not.toBe(0);
    expect(r.fails).toEqual([]);
    expect(r.stdout).toContain('precondition');
    for (const name of ['smoke-version', 'smoke-help', 'smoke-secure-ci', 'credential-control', 'self-check-live']) {
      expect(r.preconditions).toContain(name);
    }
    expectFullCensus(r);
  });

  it('HMA-40.AC2 a clean fixture passes every check and exits 0, with the whole census as pass', () => {
    // Green against the same base the red rows poison: each red row above is
    // exactly one mutation away from this run, which is what makes them
    // per-check rather than per-tarball.
    const r = review(makeTarball('clean', baseFiles()));
    expect(r.stdout).toContain('result: pass');
    expect(r.status).toBe(0);
    expect(r.fails).toEqual([]);
    expect(r.preconditions).toEqual([]);
    expectFullCensus(r);
    // The planted credential control really ran against the artifact bytes.
    expect(r.census).toContain('credential-control=pass');
    // And the tamper probe really corrupted an install and saw it quarantine.
    expect(r.census).toContain('self-check-live=pass');
  });

  it('HMA-40.AC2+AC3 the tarball packed from the delivered tree has no failing check, and exits 0 exactly when nothing was a precondition', () => {
    // `npm pack` exactly as the release build job runs it. Where a
    // precondition holds (no dist/ built, or no registry from this runner)
    // the script must report it and exit non-zero — a green that skipped a
    // check is the thing BD12 forbids — so this row accepts either a full
    // pass or a disclosed precondition, and never a FAIL.
    const packOut = execFileSync('npm', ['pack', '--pack-destination', work], {
      cwd: ROOT,
      encoding: 'utf8',
      env: Object.fromEntries(
        Object.entries(process.env).filter(([k, v]) => v !== undefined && !/^npm_/i.test(k)),
      ) as Record<string, string>,
    })
      .trim()
      .split('\n');
    const tarball = path.join(work, packOut[packOut.length - 1]);
    const r = review(tarball);
    expect(r.fails).toEqual([]);
    expectFullCensus(r);
    if (r.preconditions.length === 0) {
      expect(r.status).toBe(0);
      expect(r.stdout).toContain('result: pass');
    } else {
      // Disclosed, named, and NOT a pass.
      expect(r.status).not.toBe(0);
      expect(r.stdout).toContain('precondition');
    }
  });
});

#!/usr/bin/env node
/**
 * HMA-40 — review the RELEASE ARTIFACT: the CI-packed tarball, never the tree.
 *
 *   node scripts/release-artifact-review.mjs --tarball <path>
 *
 * `.github/workflows/release.yml` runs this in the `review` job between
 * `build` (which packed the tarball and recorded its sha256) and `publish`
 * (which holds `id-token: write` and publishes exactly these bytes). The tree
 * is already covered by `npm test`; this script exists because the tarball is
 * what users install, and the tarball is not the tree: packing selects files,
 * the packed package.json is what npm executes lifecycle scripts from, and
 * `overrides` do not travel (see scripts/audit-consumer-resolution.mjs).
 *
 * Checks, in census order:
 *
 *   entry-allowlist       every entry is package/dist/**, package/README.md,
 *                         package/LICENSE or package/package.json — the
 *                         `files` list in package.json, spelled as an
 *                         allowlist over the actual entries.
 *   no-dotfiles           no dotfile or dot-directory entry anywhere.
 *   no-test-paths         no entry path containing `__tests__`, `fixtures`
 *                         or `test/`.
 *   no-lifecycle-scripts  no preinstall / install / postinstall in the packed
 *                         package.json.
 *   pinned-first-party    no caret or tilde range on any dependency named
 *                         `aim-sdk` or starting `@opena2a/` — first-party
 *                         resolution is pinned, not floated.
 *   smoke-version         from a clean global prefix (`npm install -g
 *   smoke-help            <tarball> --ignore-scripts` into a temp prefix),
 *   smoke-secure-ci       with an empty HOME and the network cut off,
 *                         `hackmyagent --version` / `--help` / `secure --ci
 *                         <benign fixture>` exit 0 and print no stack trace.
 *   credential-control    on a scratch copy of the extracted tarball's dist/
 *                         with one planted credential file, `hackmyagent
 *                         secure --ci` must report the planted control —
 *                         zero credential findings means the shipped scanner
 *                         cannot see the one thing it ships to find.
 *   self-check-live       the shipped integrity self-check, proven live over
 *                         the shipped bytes. Static half: the tarball carries
 *                         package/dist/integrity-manifest.json, its version
 *                         is the packed package.json version, and its `files`
 *                         key set is exactly the dist/ file entries minus the
 *                         manifest itself (an absent `signature` is recorded
 *                         as "unsigned", not failed). Executing half, run
 *                         LAST of the executing checks because it corrupts
 *                         the prefix: append `\n//x\n` to the installed
 *                         dist/index.js and require `hackmyagent --version`
 *                         to quarantine — exit 3 with INTEGRITY CHECK FAILED
 *                         on stderr. A manifest that goes missing must never
 *                         fail open as a silent CLEAN.
 *   audit-high            `npm audit --omit=dev` at high-or-above over the
 *                         packed package.json's resolution.
 *
 * BD12: a check that cannot run is an ERROR, never a pass. Every check name
 * appears in the single `census:` line whether it passed, failed or hit a
 * precondition. The registry-dependent checks report
 * `precondition: registry unreachable` when the registry cannot be reached,
 * and the artifact-executing checks refuse to run (as a precondition) over a
 * tarball that already failed a static check.
 *
 * Exit codes:
 *   0  every check ran and passed
 *   1  at least one check FAILED
 *   2  no check failed, but at least one could not run (precondition)
 *   3  usage or setup error (bad arguments, unreadable tarball)
 */

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const CHECKS = [
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

const STATIC_CHECKS = new Set([
  'entry-allowlist',
  'no-dotfiles',
  'no-test-paths',
  'no-lifecycle-scripts',
  'pinned-first-party',
]);

/** Checks that execute code out of the artifact. Never run after a static FAIL. */
const EXECUTING_CHECKS = [
  'smoke-version',
  'smoke-help',
  'smoke-secure-ci',
  'credential-control',
  'self-check-live',
];

// name -> { status: 'pass' | 'FAIL' | 'precondition', detail: string }
const results = new Map();
function record(name, status, detail) {
  results.set(name, { status, detail });
}

/**
 * "Unreachable" includes "reachable but refusing": a curated proxy that
 * answers 403 for a package it has not vetted leaves this run just as unable
 * to audit or install as a dead network does, and BD12 forbids reading either
 * as a pass.
 */
const NETWORK_ERROR = /(ENOTFOUND|EAI_AGAIN|ETIMEDOUT|ECONNRESET|ECONNREFUSED|ENETUNREACH|EHOSTUNREACH|EPROTO|ERR_SOCKET|socket hang up|fetch failed|network request|E403|ENOAUDIT|registry\b.{0,40}(?:unreachable|error|refused))/i;

/** V8 stack frames start with whitespace + `at `; finding lists (file:line:col) do not. */
const STACK_TRACE = /^\s+at\s.+(?:\(|:\d+:\d+)/m;

const scratchDirs = [];
function mkScratch(tag) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `hma-release-review-${tag}-`));
  scratchDirs.push(dir);
  return dir;
}

function sh(cmd, args, opts = {}) {
  return spawnSync(cmd, args, {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    ...opts,
  });
}

function usage(msg) {
  process.stderr.write(`${msg}\nusage: node scripts/release-artifact-review.mjs --tarball <path>\n`);
  process.exit(3);
}

// ---------------------------------------------------------------- arguments

const argv = process.argv.slice(2);
let tarball = null;
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--tarball') {
    tarball = argv[i + 1];
    i++;
  } else {
    usage(`unknown argument: ${argv[i]}`);
  }
}
if (!tarball) usage('missing --tarball <path>');
tarball = path.resolve(tarball);
if (!fs.existsSync(tarball)) usage(`no such file: ${tarball}`);

// ---------------------------------------------------------------- tar reads

let entries;
{
  const r = sh('tar', ['-tzf', tarball]);
  if (r.status !== 0) usage(`tarball unreadable: ${(r.stderr || '').trim().split('\n')[0]}`);
  // Directory entries keep their trailing slash for display but are checked
  // on the stripped form, so `package/dist/` is not read as a dotfile or an
  // out-of-allowlist file.
  entries = r.stdout.split('\n').filter(Boolean);
}

function extractText(entryPath) {
  const r = sh('tar', ['-xzOf', tarball, entryPath]);
  return r.status === 0 ? r.stdout : null;
}

const packedPkgRaw = extractText('package/package.json');
let packedPkg = null;
try {
  packedPkg = packedPkgRaw === null ? null : JSON.parse(packedPkgRaw);
} catch {
  packedPkg = null;
}

// ---------------------------------------------------------------- statics

{
  const bad = entries.filter((e) => {
    const p = e.replace(/\/$/, '');
    if (p === 'package') return false;
    if (p === 'package/package.json' || p === 'package/README.md' || p === 'package/LICENSE') {
      return false;
    }
    return !(p === 'package/dist' || p.startsWith('package/dist/'));
  });
  record(
    'entry-allowlist',
    bad.length ? 'FAIL' : 'pass',
    bad.length
      ? `entry outside package/dist|README.md|LICENSE|package.json: ${bad[0]}${bad.length > 1 ? ` (+${bad.length - 1} more)` : ''}`
      : `${entries.length} entries, all within the files allowlist`,
  );
}

{
  const dotted = entries.filter((e) =>
    e.replace(/\/$/, '').split('/').some((seg) => seg.startsWith('.')),
  );
  record(
    'no-dotfiles',
    dotted.length ? 'FAIL' : 'pass',
    dotted.length
      ? `dotfile entry: ${dotted[0]}${dotted.length > 1 ? ` (+${dotted.length - 1} more)` : ''}`
      : 'no dotfile or dot-directory entries',
  );
}

{
  const testish = entries.filter(
    (e) => e.includes('__tests__') || e.includes('fixtures') || e.includes('test/'),
  );
  record(
    'no-test-paths',
    testish.length ? 'FAIL' : 'pass',
    testish.length
      ? `test-shaped entry: ${testish[0]}${testish.length > 1 ? ` (+${testish.length - 1} more)` : ''}`
      : 'no __tests__, fixtures or test/ entries',
  );
}

if (!packedPkg) {
  record('no-lifecycle-scripts', 'FAIL', 'package/package.json missing or unparsable');
  record('pinned-first-party', 'FAIL', 'package/package.json missing or unparsable');
} else {
  const scripts = packedPkg.scripts ?? {};
  const lifecycle = ['preinstall', 'install', 'postinstall'].filter((s) => s in scripts);
  record(
    'no-lifecycle-scripts',
    lifecycle.length ? 'FAIL' : 'pass',
    lifecycle.length
      ? `install-time script in packed package.json: ${lifecycle.join(', ')}`
      : 'no preinstall/install/postinstall in packed package.json',
  );

  const floated = [];
  for (const section of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [name, range] of Object.entries(packedPkg[section] ?? {})) {
      const firstParty = name === 'aim-sdk' || name.startsWith('@opena2a/');
      if (firstParty && /^[~^]/.test(String(range).trim())) {
        floated.push(`${name}@${range}`);
      }
    }
  }
  record(
    'pinned-first-party',
    floated.length ? 'FAIL' : 'pass',
    floated.length
      ? `caret/tilde range on first-party dependency: ${floated.join(', ')}`
      : 'every @opena2a/* and aim-sdk dependency is pinned',
  );
}

// ---------------------------------------------------------------- dynamics

const staticFailures = [...results.entries()]
  .filter(([name, r]) => STATIC_CHECKS.has(name) && r.status === 'FAIL')
  .map(([name]) => name);
const hasDist = entries.some((e) => e.startsWith('package/dist/'));

/**
 * `unshare -rn` gives the child an empty network namespace, which is a real
 * "no network", not an environment-variable suggestion. Where user namespaces
 * are unavailable (macOS, hardened kernels) the runs still get an empty HOME
 * and a poisoned proxy environment; the census detail names which of the two
 * this run had, so a reader is never left assuming the stronger one.
 */
const canUnshare = (() => {
  try {
    return sh('unshare', ['-rn', 'true']).status === 0;
  } catch {
    return false;
  }
})();

function hermeticRun(nodeArgs, timeoutMs = 180_000) {
  const home = mkScratch('home');
  const tmp = mkScratch('tmp');
  const env = {
    PATH: process.env.PATH,
    HOME: home,
    USERPROFILE: home,
    TMPDIR: tmp,
    NO_COLOR: '1',
    // Belt for the non-unshare arm: anything that honours proxy variables
    // dials a closed port instead of the world.
    HTTP_PROXY: 'http://127.0.0.1:9',
    HTTPS_PROXY: 'http://127.0.0.1:9',
    http_proxy: 'http://127.0.0.1:9',
    https_proxy: 'http://127.0.0.1:9',
    NO_PROXY: '',
  };
  const cmd = canUnshare ? 'unshare' : process.execPath;
  const args = canUnshare ? ['-rn', process.execPath, ...nodeArgs] : nodeArgs;
  return sh(cmd, args, { env, timeout: timeoutMs, cwd: tmp });
}

const isolationNote = canUnshare ? 'network cut via unshare -rn' : 'no netns available; proxy-poisoned env only';

function cliProblem(r) {
  if (r.error) return `spawn failed: ${r.error.message}`;
  if (r.status !== 0) {
    const firstErr = `${r.stderr || r.stdout || ''}`.trim().split('\n')[0] || '(no output)';
    return `exit ${r.status}: ${firstErr}`;
  }
  if (STACK_TRACE.test(`${r.stdout}\n${r.stderr}`)) return 'printed a stack trace';
  return null;
}

/**
 * self-check-live, static half: the shipped manifest names the shipped bytes.
 * With the manifest absent the CLI's startup self-check returns dev-mode
 * CLEAN, so an artifact that silently drops it fails OPEN — this is the check
 * that makes that class a named FAIL instead.
 */
function selfCheckManifestProblem() {
  const manifestEntry = 'package/dist/integrity-manifest.json';
  if (!entries.some((e) => e === manifestEntry)) {
    return { problem: `${manifestEntry} is not an entry in the tarball` };
  }
  let manifest = null;
  try {
    const raw = extractText(manifestEntry);
    manifest = raw === null ? null : JSON.parse(raw);
  } catch {
    manifest = null;
  }
  if (!manifest || typeof manifest !== 'object') {
    return { problem: 'integrity manifest present but unreadable or unparsable' };
  }
  if (!packedPkg) {
    return { problem: 'packed package.json unreadable; manifest version cannot be compared' };
  }
  if (manifest.version !== packedPkg.version) {
    return {
      problem: `manifest version ${manifest.version} is not the packed package.json version ${packedPkg.version}`,
    };
  }
  const shipped = entries
    .filter((e) => !e.endsWith('/') && e.startsWith('package/dist/'))
    .map((e) => e.slice('package/dist/'.length))
    .filter((p) => p !== 'integrity-manifest.json')
    .sort();
  const listed = Object.keys(manifest.files ?? {}).sort();
  if (shipped.length !== listed.length || shipped.some((p, i) => p !== listed[i])) {
    const unlisted = shipped.filter((p) => !listed.includes(p));
    const unshipped = listed.filter((p) => !shipped.includes(p));
    const parts = [];
    if (unlisted.length) parts.push(`shipped but not in manifest: dist/${unlisted[0]}${unlisted.length > 1 ? ` (+${unlisted.length - 1} more)` : ''}`);
    if (unshipped.length) parts.push(`in manifest but not shipped: dist/${unshipped[0]}${unshipped.length > 1 ? ` (+${unshipped.length - 1} more)` : ''}`);
    return { problem: `manifest files do not match the shipped dist/ — ${parts.join('; ')}` };
  }
  return {
    problem: null,
    signed: typeof manifest.signature === 'string' ? 'signed' : 'unsigned',
  };
}

if (staticFailures.length) {
  for (const name of EXECUTING_CHECKS) {
    record(
      name,
      'precondition',
      `refusing to execute the artifact: static checks failed (${staticFailures.join(', ')})`,
    );
  }
} else if (!hasDist) {
  for (const name of EXECUTING_CHECKS) {
    record(name, 'precondition', 'no dist/ in tarball; nothing to execute');
  }
} else {
  // Clean global prefix, named with the --prefix flag rather than npm's
  // prefix environment variable: that variable's name is a credential-shape
  // guard literal (the npm token prefix), and this file may not carry one.
  // The install itself may use the network (the packed dependencies resolve
  // from the registry) and the ambient npm cache; the CLI RUNS are what get
  // the empty HOME and the cut network.
  const prefix = mkScratch('prefix');
  const install = sh(
    'npm',
    ['install', '-g', tarball, '--ignore-scripts', '--no-audit', '--no-fund', '--prefix', prefix],
    { timeout: 600_000 },
  );

  if (install.status !== 0) {
    const firstErr = `${install.stderr || ''}`.trim().split('\n').find((l) => l.includes('npm error')) ||
      `${install.stderr || install.stdout || ''}`.trim().split('\n')[0] || '(no output)';
    const network = NETWORK_ERROR.test(`${install.stdout}\n${install.stderr}`);
    for (const name of EXECUTING_CHECKS) {
      record(
        name,
        network ? 'precondition' : 'FAIL',
        network ? 'registry unreachable during global install' : `global install failed: ${firstErr}`,
      );
    }
  } else {
    const binLink =
      process.platform === 'win32'
        ? path.join(prefix, 'hackmyagent')
        : path.join(prefix, 'bin', 'hackmyagent');
    let bin = null;
    try {
      bin = fs.realpathSync(binLink);
    } catch {
      for (const name of EXECUTING_CHECKS) {
        record(name, 'FAIL', `global install exposed no hackmyagent bin at ${binLink}`);
      }
    }

    if (bin) {
      {
        const r = hermeticRun([bin, '--version']);
        const problem = cliProblem(r) ?? (r.stdout.trim() ? null : 'printed nothing');
        record(
          'smoke-version',
          problem ? 'FAIL' : 'pass',
          problem ?? `--version printed ${r.stdout.trim()} (${isolationNote})`,
        );
      }
      {
        const r = hermeticRun([bin, '--help']);
        const problem = cliProblem(r) ?? (r.stdout.trim() ? null : 'printed nothing');
        record('smoke-help', problem ? 'FAIL' : 'pass', problem ?? `--help printed usage (${isolationNote})`);
      }
      {
        const fixture = mkScratch('fixture');
        fs.writeFileSync(
          path.join(fixture, 'README.md'),
          'Benign fixture for the release artifact review smoke check.\n',
        );
        const r = hermeticRun([bin, 'secure', '--ci', fixture], 240_000);
        const problem = cliProblem(r);
        record(
          'smoke-secure-ci',
          problem ? 'FAIL' : 'pass',
          problem ?? `secure --ci scanned a benign fixture clean (${isolationNote})`,
        );
      }
      {
        // The planted control: one credential file the shipped scanner MUST
        // find, dropped into a scratch copy of the artifact's own dist/. The
        // key is assembled at runtime so no credential-shaped literal sits in
        // this repository.
        const extract = mkScratch('extract');
        sh('tar', ['-xzf', tarball, '-C', extract]);
        const scratch = mkScratch('cred-scan');
        fs.cpSync(path.join(extract, 'package', 'dist'), path.join(scratch, 'dist'), {
          recursive: true,
        });
        const plantedName = 'planted-control.env';
        const key = ['sk-', 'proj-'].join('') + 'A'.repeat(48);
        fs.writeFileSync(path.join(scratch, plantedName), `OPENAI_API_KEY=${key}\n`);

        const r = hermeticRun([bin, 'secure', '--ci', '--format', 'json', scratch], 240_000);
        let credFindings = [];
        let parseNote = null;
        try {
          const body = JSON.parse(r.stdout.slice(r.stdout.indexOf('{')));
          const findings = body.findings ?? body.allFindings ?? [];
          credFindings = findings.filter((f) => /CRED/i.test(String(f.checkId ?? '')));
        } catch {
          parseNote = 'secure --ci --format json produced no parsable JSON';
        }
        const plantedFound = credFindings.some((f) => String(f.file ?? '').includes(plantedName));
        let problem = null;
        if (parseNote) problem = parseNote;
        else if (credFindings.length === 0) problem = 'zero credential findings over a planted control';
        else if (!plantedFound) problem = `credential findings present but none names ${plantedName}`;
        record(
          'credential-control',
          problem ? 'FAIL' : 'pass',
          problem ??
            `planted control found (${credFindings.length} credential finding(s), ${isolationNote})`,
        );
      }
      {
        // self-check-live, last of the executing checks BECAUSE it corrupts
        // the installed prefix: every check after it would be measuring the
        // corruption, not the artifact.
        const manifest = selfCheckManifestProblem();
        if (manifest.problem) {
          record('self-check-live', 'FAIL', manifest.problem);
        } else if (results.get('smoke-version')?.status !== 'pass') {
          record(
            'self-check-live',
            'precondition',
            'the tamper probe needs a passing --version baseline, and smoke-version did not pass',
          );
        } else {
          // `bin` is the realpath of the installed bin link, i.e.
          // <prefix>/lib/node_modules/hackmyagent/dist/cli.js — so index.js
          // sits beside it in the installed dist/.
          const target = path.join(path.dirname(bin), 'index.js');
          if (!fs.existsSync(target)) {
            record('self-check-live', 'precondition', `installed prefix has no ${target}; nothing to corrupt`);
          } else {
            fs.appendFileSync(target, '\n//x\n');
            const r = hermeticRun([bin, '--version']);
            const stderr = `${r.stderr ?? ''}`;
            if (r.status === 3 && stderr.includes('INTEGRITY CHECK FAILED')) {
              record(
                'self-check-live',
                'pass',
                `corrupted dist/index.js quarantined: exit 3 with INTEGRITY CHECK FAILED (manifest ${manifest.signed}, ${isolationNote})`,
              );
            } else {
              const firstErr = stderr.trim().split('\n')[0] || '(no stderr)';
              record(
                'self-check-live',
                'FAIL',
                `corrupted dist/index.js was not quarantined: exit ${r.status}, stderr: ${firstErr}`,
              );
            }
          }
        }
      }
    }
  }
}

// ---------------------------------------------------------------- audit

if (!packedPkg) {
  record('audit-high', 'precondition', 'packed package.json unreadable; nothing to resolve');
} else {
  // The packed package.json is the root of the resolution, so its `overrides`
  // apply exactly as they do for this repository's own installs. The tree a
  // CONSUMER resolves (where overrides do NOT travel) is the separate
  // audit:consumer gate; this check keeps the artifact's own resolution
  // clean at high-or-above.
  const auditDir = mkScratch('audit');
  fs.writeFileSync(path.join(auditDir, 'package.json'), packedPkgRaw);
  const resolve = sh(
    'npm',
    ['install', '--package-lock-only', '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund'],
    { cwd: auditDir, timeout: 600_000 },
  );
  if (resolve.status !== 0) {
    const network = NETWORK_ERROR.test(`${resolve.stdout}\n${resolve.stderr}`);
    record(
      'audit-high',
      'precondition',
      network
        ? 'registry unreachable'
        : `lockfile resolution failed: ${`${resolve.stderr || ''}`.trim().split('\n')[0]}`,
    );
  } else {
    const audit = sh('npm', ['audit', '--omit=dev', '--audit-level=high', '--json'], {
      cwd: auditDir,
      timeout: 600_000,
    });
    let meta = null;
    try {
      meta = JSON.parse(audit.stdout).metadata?.vulnerabilities ?? null;
    } catch {
      meta = null;
    }
    if (meta) {
      const highPlus = (meta.high ?? 0) + (meta.critical ?? 0);
      record(
        'audit-high',
        highPlus > 0 ? 'FAIL' : 'pass',
        highPlus > 0
          ? `${meta.high ?? 0} high, ${meta.critical ?? 0} critical advisories (npm audit --omit=dev)`
          : 'no high-or-above advisories (npm audit --omit=dev)',
      );
    } else if (NETWORK_ERROR.test(`${audit.stdout}\n${audit.stderr}`)) {
      record('audit-high', 'precondition', 'registry unreachable');
    } else {
      record(
        'audit-high',
        'precondition',
        `npm audit produced no parsable report: ${`${audit.stderr || ''}`.trim().split('\n')[0] || '(no output)'}`,
      );
    }
  }
}

// ---------------------------------------------------------------- census

for (const dir of scratchDirs) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch {
    /* best-effort cleanup */
  }
}

console.log(`release-artifact-review: ${path.basename(tarball)}`);
for (const name of CHECKS) {
  const r = results.get(name) ?? { status: 'precondition', detail: 'check never ran (reviewer defect)' };
  results.set(name, r);
  console.log(`check ${name}: ${r.status} — ${r.detail}`);
}
console.log(`census: ${CHECKS.map((n) => `${n}=${results.get(n).status}`).join(' ')}`);

const failed = CHECKS.filter((n) => results.get(n).status === 'FAIL');
const blocked = CHECKS.filter((n) => results.get(n).status === 'precondition');
if (failed.length) {
  console.log(`result: FAIL (${failed.join(', ')})`);
  process.exit(1);
} else if (blocked.length) {
  console.log(`result: error — preconditions unmet, not a pass (${blocked.join(', ')})`);
  process.exit(2);
} else {
  console.log(`result: pass (${CHECKS.length}/${CHECKS.length} checks)`);
  process.exit(0);
}

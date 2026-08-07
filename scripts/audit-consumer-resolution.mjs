#!/usr/bin/env node
/**
 * #432 — audit the tree a CONSUMER resolves, not the tree this repo pins.
 *
 * `.github/workflows/dependency-audit.yml` runs `npm audit --package-lock-only`
 * against this repo's lockfile and reports 0. That number is correct and it is
 * not the number a user gets:
 *
 *   $ npm install hackmyagent@0.26.1 && npm audit --audit-level=high
 *   4 high severity vulnerabilities
 *
 * The `overrides` block in package.json pins `adm-zip` for THIS tree. npm
 * applies `overrides` only to the tree that declares them, and they are not
 * carried in the published tarball, so the artifact we audit resolves
 * differently from the artifact we ship. 0.26.0 added that gate because
 * "nothing in CI would have caught either recurrence"; this is the same lesson
 * one level out, and the gate still could not see it, because it audits the
 * wrong tree.
 *
 * So this script packs the repo, resolves the tarball as a dependency of an
 * empty scratch package, and audits THAT.
 *
 * ## Why it never installs
 *
 * The existing job avoids `npm ci` deliberately: it runs on `pull_request`,
 * which includes forks, and installing a fork's branch executes whatever that
 * branch put in a `postinstall` — least acceptable in the CI of a tool whose
 * subject is supply-chain risk. That argument does not weaken just because
 * this gate needs a consumer tree, so both `npm pack` and the resolve run with
 * `--ignore-scripts`, and the resolve is `--package-lock-only`: npm computes
 * the tree and writes a lockfile without fetching or executing a package.
 *
 * Verified equivalent to the real thing before being adopted: on 0.26.1's
 * dependency set the lock-only form and a genuine `npm install` of the tarball
 * both report the same 4 high and the same single advisory, and with the
 * `ai-trust` edge removed both report the same 3.
 *
 * ## Why the gate is an allowlist and not a count
 *
 * One advisory in the consumer tree has no fix available at any version:
 * `onnxruntime-node@1.27.0` is the latest release and pins `adm-zip: ^0.5.16`,
 * while the patched `adm-zip` is `0.6.0` — a caret on `0.5.x` cannot reach it,
 * and no `overrides` we write reaches a consumer. A gate that can only be red
 * gets switched off within a release, so it would protect nothing.
 *
 * Instead every high/critical advisory must be named in ALLOWED below with a
 * reason and a review date. Anything unlisted fails. An entry that stops
 * matching also fails, so the list cannot quietly accumulate advisories that
 * were fixed years ago — a stale waiver reads exactly like a considered one.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Advisories accepted in the consumer tree, keyed by GHSA id.
 *
 * An entry is a statement that a user installing this tool gets this advisory
 * and we decided to ship anyway. It needs to survive a reader asking "why is
 * my audit red because of your CLI", so `reason` names the blocker, not the
 * severity.
 */
const ALLOWED = [
  {
    id: 'GHSA-xcpc-8h2w-3j85',
    package: 'adm-zip',
    reason:
      'adm-zip <0.6.0, reached only through onnxruntime-node, which HackMyAgent ' +
      'needs for local NanoMind inference. onnxruntime-node@1.27.0 is the latest ' +
      'release and pins adm-zip ^0.5.16; the patched 0.6.0 is outside that caret, ' +
      'so no version of the dependency resolves clean and `overrides` do not reach ' +
      'a consumer. Tracked upstream at microsoft/onnxruntime. The extract path that ' +
      'carries the advisory runs in onnxruntime-node postinstall when it downloads ' +
      'execution-provider binaries; the base package ships those binaries, so the ' +
      'script exits before requiring adm-zip on a default install.',
    reviewBy: '2026-11-01',
  },
];

/** Packages that must never appear in a consumer tree, at any version. */
const FORBIDDEN_PACKAGES = [
  {
    name: 'hackmyagent',
    where: 'nested',
    reason:
      'A second, older copy of this tool. 0.26.1 shipped `ai-trust` as a runtime ' +
      'dependency, which depends back on hackmyagent@0.17.11, so every consumer ' +
      'resolved a nine-month-old copy and read its deprecation notice — describing ' +
      'defects in a version they never asked for — as the first screen after install.',
  },
];

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opts });
}

/** Resolve a consumer's tree for `spec` and return npm's audit report. */
function auditConsumerTree(spec, scratch) {
  writeFileSync(
    path.join(scratch, 'package.json'),
    JSON.stringify({ name: 'consumer-resolution-probe', version: '1.0.0', private: true }) + '\n'
  );
  run('npm', [
    'install',
    '--package-lock-only',
    '--ignore-scripts',
    '--no-audit',
    '--no-fund',
    spec,
  ], { cwd: scratch });

  let raw;
  try {
    raw = run('npm', ['audit', '--package-lock-only', '--json'], { cwd: scratch });
  } catch (e) {
    // `npm audit` exits non-zero when it finds anything. The report is still
    // on stdout and is the entire point of the call.
    raw = e.stdout ?? '';
  }

  let report;
  try {
    report = JSON.parse(raw);
  } catch {
    // A gate that could not take its measurement has not passed. `npm audit`
    // reaches the live advisory database, so an unreachable registry, a proxy,
    // or a rate limit all land here — and every one of them would otherwise
    // surface as a raw SyntaxError that reads like a bug in this script.
    throw new Error(
      'npm audit produced no parseable report, so the consumer tree was never measured. ' +
        'This is not a pass. Check network access to the npm advisory database and re-run.\n' +
        `npm said: ${(raw || '(nothing)').slice(0, 500)}`
    );
  }
  const lock = JSON.parse(readFileSync(path.join(scratch, 'package-lock.json'), 'utf8'));
  return { report, lock };
}

/** Every GHSA id at `high` or `critical`, with the package it lands on. */
function highAndCritical(report) {
  const out = new Map();
  for (const [name, v] of Object.entries(report.vulnerabilities ?? {})) {
    if (v.severity !== 'high' && v.severity !== 'critical') continue;
    for (const via of v.via ?? []) {
      if (typeof via !== 'object' || !via.url) continue;
      const id = via.url.split('/').pop();
      if (!out.has(id)) out.set(id, { id, severity: via.severity ?? v.severity, packages: new Set() });
      out.get(id).packages.add(name);
    }
  }
  return out;
}

/**
 * Copies of `name` that are not the root package under test.
 *
 * Read off the lockfile rather than the audit report on purpose: a nested old
 * copy is wrong whether or not it currently carries an advisory, and reading
 * it from the advisory list would make the check disappear the day upstream
 * patches something.
 */
function nestedCopies(lock, name) {
  return Object.keys(lock.packages ?? {}).filter(
    (p) => p !== `node_modules/${name}` && p.endsWith(`node_modules/${name}`)
  );
}

function main() {
  const argv = process.argv.slice(2);
  const targetArg = argv.indexOf('--target');
  const explicitTarget = targetArg !== -1 ? argv[targetArg + 1] : null;

  const scratch = mkdtempSync(path.join(tmpdir(), 'hma-consumer-audit-'));
  const failures = [];
  try {
    let spec = explicitTarget;
    if (!spec) {
      const tarball = run('npm', ['pack', '--ignore-scripts', '--pack-destination', scratch], {
        cwd: REPO_ROOT,
      })
        .trim()
        .split('\n')
        .pop();
      spec = path.join(scratch, tarball);
      console.log(`Packed ${tarball}`);
    }
    console.log(`Resolving a consumer tree for: ${explicitTarget ?? path.basename(spec)}\n`);

    const probe = path.join(scratch, 'probe');
    mkdirSync(probe, { recursive: true });
    const { report, lock } = auditConsumerTree(spec, probe);

    const counts = report.metadata?.vulnerabilities ?? {};
    console.log(
      `Consumer resolution: ${counts.critical ?? 0} critical, ${counts.high ?? 0} high, ` +
        `${counts.moderate ?? 0} moderate, ${counts.low ?? 0} low`
    );
    console.log('(This repo\'s own lockfile is audited separately and reports fewer — ' +
      '`overrides` are not published.)\n');

    const found = highAndCritical(report);
    const allowedById = new Map(ALLOWED.map((a) => [a.id, a]));

    // 1. Every high/critical advisory must be allowlisted.
    for (const adv of found.values()) {
      const allow = allowedById.get(adv.id);
      if (!allow) {
        failures.push(
          `Unlisted ${adv.severity} advisory in the consumer tree: ${adv.id} ` +
            `(via ${[...adv.packages].join(', ')}).\n` +
            `    A consumer installing this tool inherits it. Either raise the floor to a ` +
            `patched version, drop the dependency, or add it to ALLOWED in ${path.relative(REPO_ROOT, fileURLToPath(import.meta.url))} ` +
            `with a reason a user would accept and a review date.`
        );
        continue;
      }
      // No silent caps: say what was waived, every run.
      console.log(`  allowed  ${adv.id}  ${allow.package}  (review by ${allow.reviewBy})`);
      console.log(`           ${allow.reason.replace(/\s+/g, ' ')}\n`);
    }

    // 2. An allowlist entry that no longer matches is removed, not left to rot.
    for (const allow of ALLOWED) {
      if (found.has(allow.id)) continue;
      failures.push(
        `Stale allowlist entry: ${allow.id} (${allow.package}) is no longer in the consumer ` +
          `tree. Delete it — a waiver nobody rechecks reads the same as a considered one.`
      );
    }

    // 3. Allowlist entries expire.
    const today = new Date().toISOString().slice(0, 10);
    for (const allow of ALLOWED) {
      if (allow.reviewBy >= today) continue;
      failures.push(
        `Allowlist entry ${allow.id} (${allow.package}) passed its review date ` +
          `${allow.reviewBy}. Re-check whether upstream now resolves clean, then either ` +
          `fix it or move the date with a fresh reason.`
      );
    }

    // 4. Forbidden packages, advisory or not.
    for (const forbidden of FORBIDDEN_PACKAGES) {
      const copies = nestedCopies(lock, forbidden.name);
      if (copies.length === 0) continue;
      const versions = copies.map((p) => `${lock.packages[p]?.version ?? '?'} at ${p}`);
      failures.push(
        `Nested copy of \`${forbidden.name}\` in the consumer tree: ${versions.join(', ')}.\n` +
          `    ${forbidden.reason.replace(/\s+/g, ' ')}`
      );
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }

  if (failures.length > 0) {
    console.error('\nConsumer-resolution audit FAILED:\n');
    for (const f of failures) console.error(`  - ${f}\n`);
    process.exit(1);
  }
  console.log('Consumer-resolution audit passed.');
}

main();

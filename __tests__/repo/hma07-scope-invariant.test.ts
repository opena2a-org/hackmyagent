/**
 * HMA-07.AC5 — scope invariant for the static-scanner walk widening.
 *
 * HMA-07 widens `src/hardening/scanner.ts` and nothing else. Two neighbouring
 * areas are explicitly out of bounds and both are live work by other hands:
 *
 *   src/nanomind-core/**        HMA-06 is in the semantic compiler and its
 *                               scanner bridge; the semantic layer's own
 *                               `SKIP_DIRS` drop is a separate follow-up.
 *   src/hardening/tracked-fs.ts HMA-04's out-of-tree link confinement (#685),
 *                               which AC4 depends on being unedited.
 *
 * And the wider walk is not opt-in: no new CLI flag anywhere in the command
 * surface. A `--deep-skills` escape hatch would mean the default scan still
 * reports a false clean on `.claude/skills`, which is the whole defect.
 *
 * The frozen manifests below are the always-on half of this guard, and they are
 * deliberately byte-level rather than "does the file exist": a scope violation
 * is a change to those files, and only their bytes can witness it. The
 * `git diff` test is the direct reading of the acceptance criterion and runs
 * wherever `origin/main` is fetched; it returns early in a clone that has no
 * such ref, which is why it is not the only assertion here.
 *
 * Updating a frozen value is a SCOPE DECISION, not test maintenance. If a later
 * change legitimately edits `src/nanomind-core/**` or `tracked-fs.ts`, retire
 * this suite with that change rather than re-baselining it silently.
 */
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import * as path from 'node:path';

const REPO_ROOT = path.resolve(__dirname, '..', '..');

/** Recorded at HMA-07 intake, against origin/main 957bb65. */
const TRACKED_FS_SHA256 = 'bf6566fa2dfab6877ebed88b67b0d28e518e013d2ca164d5640aa5c472586389';
const NANOMIND_CORE_FILE_COUNT = 62;
const NANOMIND_CORE_TREE_SHA256 = '17fa55dc4def9231fe27ae15ea783f401240aa9f964449491b0a98df801c1aca';

/** Long flags registered anywhere under `src/`, recorded at HMA-07 intake. */
const REGISTERED_LONG_FLAGS = [
  '--a2a-recipient', '--a2a-sender', '--analm', '--api-format', '--at', '--atx',
  '--audit', '--aws-account-id', '--aws-region', '--batch', '--benchmark',
  '--broker-socket', '--broker-token', '--category', '--ci', '--ci-publish',
  '--contribute', '--deep', '--delay', '--directory', '--dry-run', '--explain',
  '--export-csv', '--export-training', '--fail-below', '--fail-on-gate',
  '--fail-on-vulnerable', '--fix', '--format', '--grant', '--grant-agent-id',
  '--header', '--ignore', '--intensity', '--iterations', '--json', '--level',
  '--local', '--mcp-tool', '--min-trust', '--model', '--name', '--nanomind',
  '--no-color', '--no-contribute', '--no-machine-posture', '--no-registry',
  '--no-scan', '--offline', '--output', '--payload-file', '--ports', '--profile',
  '--publish', '--registry-key', '--registry-report', '--registry-url',
  '--rescan', '--root', '--scan-depth', '--scan-only', '--static-only',
  '--status', '--stop-on-success', '--surface', '--system-prompt',
  '--target-type', '--tier', '--timeout', '--tool', '--type', '--verbose',
  '--version', '--version-id', '--with-aim',
];

/** Paths HMA-07 is allowed to touch, as `git diff --stat` names them. */
const ALLOWED_DIFF_PATHS = [
  /^src\/hardening\/scanner\.ts$/,
  /^__tests__\//,
  /^test-fixtures\//,
  /^CHANGELOG\.md$/,
];

function sha256(bytes: Buffer | string): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function filesUnder(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) filesUnder(full, acc);
    else if (entry.isFile()) acc.push(full);
  }
  return acc;
}

/** Path-and-content digest of a directory, stable across platforms. */
function treeDigest(dir: string): { count: number; hash: string } {
  const files = filesUnder(dir)
    .map(f => path.relative(REPO_ROOT, f).split(path.sep).join('/'))
    .sort();
  const h = createHash('sha256');
  for (const rel of files) {
    h.update(rel);
    h.update('\0');
    h.update(sha256(readFileSync(path.join(REPO_ROOT, rel))));
    h.update('\n');
  }
  return { count: files.length, hash: h.digest('hex') };
}

/** Every `--long-flag` registered through a commander `.option(...)` under `src/`. */
function registeredLongFlags(): { flags: string[]; files: string[] } {
  const flags = new Set<string>();
  const files = new Set<string>();
  for (const full of filesUnder(path.join(REPO_ROOT, 'src'))) {
    if (!full.endsWith('.ts')) continue;
    const src = readFileSync(full, 'utf8');
    for (const call of src.matchAll(/\.option\(\s*[`'"]([^`'"]+)[`'"]/g)) {
      for (const flag of call[1].matchAll(/--[a-z0-9][a-z0-9-]*/g)) {
        flags.add(flag[0]);
        files.add(path.relative(REPO_ROOT, full).split(path.sep).join('/'));
      }
    }
  }
  return { flags: [...flags].sort(), files: [...files].sort() };
}

/** `origin/main`, or null where the ref is not fetched (shallow or detached clones). */
function originMain(): string | null {
  try {
    return execFileSync('git', ['rev-parse', '--verify', 'origin/main'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    return null;
  }
}

describe('HMA-07.AC5 scope invariant', () => {
  it('HMA-07.AC5 src/hardening/tracked-fs.ts is byte-identical to origin/main (HMA-04 confinement untouched)', () => {
    const file = path.join(REPO_ROOT, 'src', 'hardening', 'tracked-fs.ts');
    expect(statSync(file).isFile()).toBe(true);
    expect(sha256(readFileSync(file))).toBe(TRACKED_FS_SHA256);
  });

  it('HMA-07.AC5 src/nanomind-core/** is byte-identical to origin/main (HMA-06 area untouched)', () => {
    const digest = treeDigest(path.join(REPO_ROOT, 'src', 'nanomind-core'));
    // Reported separately so a file added or deleted names itself in the failure.
    expect(digest.count).toBe(NANOMIND_CORE_FILE_COUNT);
    expect(digest.hash).toBe(NANOMIND_CORE_TREE_SHA256);
  });

  it('HMA-07.AC5 no new CLI flag exists anywhere in the command surface (the wider walk is not opt-in)', () => {
    const { flags, files } = registeredLongFlags();
    expect(files).toEqual(['src/cli.ts']);
    expect(flags).toEqual(REGISTERED_LONG_FLAGS);
  });

  it('HMA-07.AC5 git diff --stat origin/main names only scanner.ts, tests, fixtures and CHANGELOG.md', () => {
    const base = originMain();
    if (!base) return; // no origin/main fetched here; the frozen manifests above still hold.

    const out = execFileSync('git', ['diff', '--name-only', base, '--'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    });
    const changed = out.split('\n').map(s => s.trim()).filter(Boolean);

    const outOfScope = changed.filter(p => !ALLOWED_DIFF_PATHS.some(rx => rx.test(p)));
    expect(outOfScope).toEqual([]);
  });
});

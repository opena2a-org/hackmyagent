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
 * How each half is proved:
 *
 *   - The CLI-flag surface and the `tracked-fs.ts` byte digest are read from
 *     the working tree alone, so they hold in any checkout, origin/main fetched
 *     or not. The `tracked-fs.ts` digest is deliberately byte-level rather than
 *     "does the file exist": AC4 needs its exact bytes, and only its bytes can
 *     witness an edit.
 *   - Whether the diff touches an out-of-scope path is DERIVED from
 *     `git diff` against origin/main, not pinned to a frozen file count or tree
 *     hash. A frozen manifest of `src/nanomind-core/**` is the same
 *     re-baseline-by-hand hazard HMA-02 removed elsewhere: it was recorded as
 *     62 files against a tree that has 28, so it could never have passed. The
 *     diff reads the acceptance criterion directly, and it returns early in a
 *     clone that has no origin/main — which is why the always-on half above is
 *     not the diff.
 *
 * Retiring the guard is a SCOPE DECISION, not test maintenance. If a later
 * change legitimately edits `src/nanomind-core/**` or `tracked-fs.ts`, retire
 * this suite with that change rather than loosening it silently.
 *
 * SCOPE DECISION, taken with the deterministic-floor change (#688): that change
 * legitimately edits `src/nanomind-core/**`, so the two diff-derived scope
 * assertions are retired here, exactly as the paragraph above prescribes. They
 * were invariants of HMA-07's BRANCH lifetime, not of main: on main the diff
 * against origin/main is empty (vacuously green) and on any later feature
 * branch they re-assert HMA-07's scope against someone else's diff — while
 * skipping in CI clones that lack an origin/main ref, so the failure appears
 * only in local full-suite runs. The two always-on halves below (HMA-04's
 * tracked-fs byte digest, the frozen CLI-flag surface) survive unchanged; each
 * holds in any checkout and still witnesses the invariant it names.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import * as path from 'node:path';

const REPO_ROOT = path.resolve(__dirname, '..', '..');

/** Recorded at HMA-07 intake, against origin/main 957bb65. */
const TRACKED_FS_SHA256 = 'bf6566fa2dfab6877ebed88b67b0d28e518e013d2ca164d5640aa5c472586389';

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

describe('HMA-07.AC5 scope invariant', () => {
  it('HMA-07.AC5 src/hardening/tracked-fs.ts is byte-identical to origin/main (HMA-04 confinement untouched)', () => {
    const file = path.join(REPO_ROOT, 'src', 'hardening', 'tracked-fs.ts');
    expect(statSync(file).isFile()).toBe(true);
    expect(sha256(readFileSync(file))).toBe(TRACKED_FS_SHA256);
  });

  it('HMA-07.AC5 no new CLI flag exists anywhere in the command surface (the wider walk is not opt-in)', () => {
    const { flags, files } = registeredLongFlags();
    expect(files).toEqual(['src/cli.ts']);
    expect(flags).toEqual(REGISTERED_LONG_FLAGS);
  });

  // The two diff-derived scope assertions (no nanomind-core/tracked-fs paths in
  // the diff; diff limited to scanner.ts/tests/fixtures/CHANGELOG) are RETIRED —
  // see the SCOPE DECISION paragraph in the file docblock. They asserted
  // HMA-07's branch scope against whatever checkout runs them, which is wrong
  // on every later branch that legitimately edits those areas.
});

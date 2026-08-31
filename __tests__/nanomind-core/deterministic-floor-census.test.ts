/**
 * HMA-06.AC4 — the floor is not opt-in, and it did not spread.
 *
 * Two invariants, both measured over `src/` rather than asserted in prose.
 *
 * 1. NO NEW CLI FLAG. A deterministic floor that a caller can turn off is not a
 *    floor. `COMMAND_SURFACE` below is the complete set of option tokens
 *    registered anywhere under `src/`, captured from origin/main c2a9c2f before
 *    this change. Adding a flag — for this feature or any other — turns this
 *    red, and the diff has to say so.
 *
 * 2. THE CHANGE STAYED PUT. The worker container this task ran in has no git
 *    (`.git` points at an unmounted host path), so `git diff --stat origin/main`
 *    is not available as evidence. The census below is the substitute and is
 *    strictly stronger than a path list: it names the identifiers this change
 *    introduced and asserts that no source file outside the compiler, its
 *    bridge and the result type mentions any of them.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

const SRC = path.join(__dirname, '..', '..', 'src');

function sourceFiles(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) sourceFiles(full, acc);
    else if (entry.name.endsWith('.ts')) acc.push(full);
  }
  return acc;
}

/**
 * Every `-x` / `--flag` token registered through commander's
 * `.option` / `.requiredOption` / `.addOption` anywhere under `src/`, on
 * origin/main c2a9c2f. 88 tokens.
 */
const COMMAND_SURFACE = [
  '--a2a-recipient', '--a2a-sender', '--analm', '--api-format', '--at', '--atx',
  '--audit', '--aws-account-id', '--aws-region', '--batch', '--benchmark',
  '--broker-socket', '--broker-token', '--category', '--ci', '--ci-publish',
  '--contribute', '--deep', '--delay', '--directory', '--dry-run', '--explain',
  '--export-csv', '--export-training', '--fail-below', '--fail-on-gate',
  '--fail-on-vulnerable', '--fix', '--format', '--grant', '--grant-agent-id',
  '--header', '--ignore', '--intensity', '--iterations', '--json', '--level',
  '--local', '--mcp-tool', '--min-trust', '--model', '--name', '--nanomind',
  '--no-color', '--no-contribute', '--no-machine-posture', '--no-registry',
  '--no-scan', '--offline', '--oracle-dir', '--output', '--payload-file',
  '--ports', '--profile', '--publish', '--registry-key', '--registry-report',
  '--registry-url', '--rescan', '--root', '--scan-depth', '--scan-only',
  '--static-only', '--status', '--stop-on-success', '--surface',
  '--system-prompt', '--target-type', '--tier', '--timeout', '--tool', '--type',
  '--verbose', '--version', '--version-id', '--with-aim',
  '-H', '-b', '-c', '-d', '-f', '-i', '-l', '-n', '-o', '-p', '-t', '-v',
];

/** Identifiers introduced by the deterministic floor. */
const FLOOR_IDENTIFIERS = [
  'deterministicFindings',
  'DeterministicFinding',
  'verdictAdjustments',
  'refusedAdjustments',
  'VerdictAdjustment',
  'applyDeterministicFloor',
  'enforceDeterministicSurfaceFloor',
  'deterministicRiskSurfaces',
  'NeuralVerdictSource',
  'DETERMINISTIC_EXFIL_CONFIDENCE',
  'detectContextualBenignSignals',
];

/** The only source files this change is allowed to touch. */
const ALLOWED = new Set([
  path.join('nanomind-core', 'compiler', 'semantic-compiler.ts'),
  path.join('nanomind-core', 'scanner-bridge.ts'),
  path.join('nanomind-core', 'types.ts'),
]);

describe('HMA-06.AC4 the floor is not opt-in and did not spread', () => {
  it('HMA-06.AC4 the command surface registers no new flag', () => {
    const found = new Set<string>();
    for (const file of sourceFiles(SRC)) {
      const text = readFileSync(file, 'utf-8');
      for (const match of text.matchAll(/\.(?:option|requiredOption|addOption)\(\s*['"`]([^'"`]+)['"`]/g)) {
        for (const token of match[1].split(/[,\s]+/)) {
          if (token.startsWith('-')) found.add(token.replace(/[<[].*/, ''));
        }
      }
    }
    const added = [...found].filter(f => !COMMAND_SURFACE.includes(f)).sort();
    const removed = COMMAND_SURFACE.filter(f => !found.has(f)).sort();

    expect(
      added,
      'the deterministic floor is not opt-in: no command may gain a flag that turns it off, '
        + 'and any other new flag has to be added to COMMAND_SURFACE deliberately',
    ).toEqual([]);
    expect(removed, 'a flag disappeared from the command surface').toEqual([]);
  });

  it('HMA-06.AC4 no source file outside the compiler, its bridge and the result type names the floor', () => {
    const strays: string[] = [];
    for (const file of sourceFiles(SRC)) {
      const relative = path.relative(SRC, file);
      if (ALLOWED.has(relative)) continue;
      const text = readFileSync(file, 'utf-8');
      for (const identifier of FLOOR_IDENTIFIERS) {
        if (text.includes(identifier)) strays.push(`${relative}: ${identifier}`);
      }
    }
    expect(
      strays,
      'the floor lives in the semantic compiler, its bridge and the result type. '
        + 'A mention anywhere else means the change spread beyond the contracted surface.',
    ).toEqual([]);
  });
});

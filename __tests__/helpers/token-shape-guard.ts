/**
 * The provider-token-shape guard (HMA-16).
 *
 * Walks the repository from the repo root and reports every line whose bytes
 * match the provider-token shape set — the same seven alternates the
 * repository push gate blocks. There is NO allowlist: a marker word
 * (`FAKE`, `EXAMPLE`, …) exempts nothing, because a marker-suppressed fixture
 * is exactly the state that creates the temptation to lean on the push
 * gate's marker allowlist. The one exemption mechanism
 * is the committed registry at `security/credential-shape-exemptions.json`:
 * an entry names a path and the exact number of matching lines it is allowed
 * to carry, plus a reason from a closed vocabulary. An entry never carries a
 * matched value — this file, its test and the registry are themselves inside
 * the walk and are scanned with the same pattern set.
 *
 * The registry cannot be used to register a convertible file out of the
 * drain: an entry whose path ends in `.ts`/`.js`/`.mjs`/`.tsx` is rejected
 * unless it carries reason `escalated` with a `decisionRef` naming a public
 * issue or pull request in this repository,
 * because a source line in those languages can always be rebuilt with the
 * runtime-assembly idiom (`['ghp', '_…'].join('')`,
 * `__tests__/types/credential-format.test.ts`) so the source no longer
 * matches while the runtime string is byte-identical.
 *
 * Deliberately hermetic — a plain directory walk and per-line regex, no `rg`,
 * no shelling out — so it behaves identically in CI and on a developer
 * machine (precedent: `credential-literal-scan.ts`).
 */
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

/**
 * Byte-identical to the provider-token pattern set the repository push gate
 * enforces. Do not widen it here:
 * the URL-userinfo alternate and the private-key alternate are deferred —
 * adding them would make this guard red on arrival over 111 unclassified
 * lines (measured 2026-08-31: 100 + 11).
 *
 * The regex source itself does not match any of its own alternates: every
 * literal prefix in it is immediately followed by `[`, which none of the
 * alternates' body classes admit at that position.
 */
export const TOKEN_SHAPE_PATTERN_SOURCE =
  '(gh[posru]_[A-Za-z0-9]{20,})|(github_pat_[A-Za-z0-9_]{20,})|(xox[baprs]-[A-Za-z0-9-]{10,})|((AKIA|ASIA)[0-9A-Z]{16})|(sk-[A-Za-z0-9_-]{20,})|(AIza[0-9A-Za-z_-]{35})|(npm_[A-Za-z0-9]{36})';

/** Repo-relative path of the exemption registry. */
export const REGISTRY_PATH = 'security/credential-shape-exemptions.json';

/**
 * Directory names never walked. Exclusions only — the walk itself starts at
 * the repo root, never at a hardcoded subdirectory list, so a token-shape
 * line in a NEW directory is caught. `dist`/`build`/`coverage` are untracked
 * build artifacts (CI runs `npm run build` before `npm test`, so `dist`
 * exists when this guard runs there).
 */
const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  'coverage',
  '.nyc_output',
  '.turbo',
  '.cache',
  '.idea',
  '.vscode',
]);

/** Closed reason vocabulary. A reason outside this set rejects the entry. */
export const EXEMPTION_REASONS = [
  // The file is scanned as raw bytes by a committed test or demo, so the
  // token cannot be assembled at runtime without changing what is measured.
  'byte-literal-fixture',
  // CHANGELOG or docs text that must not be rewritten.
  'historical-record',
  // Anything else. Requires a decisionRef: a public issue or pull request
  // in this repository recording the decision.
  'escalated',
] as const;

export interface ExemptionEntry {
  /** Repo-relative POSIX path. */
  readonly path: string;
  /**
   * Exact number of lines in the file that match the pattern set. The
   * non-reversible discriminator: it identifies the exempted state without
   * carrying a byte of any matched value. More hits than expected is an
   * unregistered growth; fewer is a stale entry. Both fail.
   */
  readonly expectedHits: number;
  readonly reason: (typeof EXEMPTION_REASONS)[number];
  /** Human context. Never a matched value. */
  readonly note?: string;
  /**
   * Required for `escalated`: the URL of a public issue or pull request in
   * this repository recording the decision.
   */
  readonly decisionRef?: string;
}

export interface ExemptionRegistry {
  readonly entries: readonly ExemptionEntry[];
}

export interface ScanViolation {
  readonly kind: 'unregistered' | 'count-drift' | 'stale-entry';
  readonly path: string;
  /** 1-indexed line numbers of matching lines. Never the matched text. */
  readonly lines: readonly number[];
  readonly expectedHits?: number;
  readonly actualHits?: number;
}

export interface ScanResult {
  readonly ok: boolean;
  /** Total matching lines seen in the walk. */
  readonly matchedLineCount: number;
  /** Matching lines not covered by a registry entry. 0 on a clean tree. */
  readonly unregisteredLineCount: number;
  readonly violations: readonly ScanViolation[];
}

const CONVERTIBLE_EXT = /\.(ts|js|mjs|tsx)$/;

const DECISION_REF_PATTERN = /^https:\/\/github\.com\/opena2a-org\/hackmyagent\/(issues|pull)\/\d+$/;

/**
 * Validate the registry shape and policy. Returns human-readable errors;
 * empty array means valid. Enforced BEFORE scanning, so a malformed registry
 * can never make the scan pass vacuously.
 */
export function validateRegistry(registry: ExemptionRegistry): string[] {
  const errors: string[] = [];
  const seen = new Set<string>();
  if (!registry || !Array.isArray(registry.entries)) {
    return ['registry must be an object with an `entries` array'];
  }
  for (const entry of registry.entries) {
    const where = `entry for '${entry?.path}'`;
    if (typeof entry.path !== 'string' || entry.path.length === 0) {
      errors.push('entry with missing path');
      continue;
    }
    if (seen.has(entry.path)) errors.push(`${where}: duplicate path`);
    seen.add(entry.path);
    if (!Number.isInteger(entry.expectedHits) || entry.expectedHits < 1) {
      errors.push(`${where}: expectedHits must be a positive integer`);
    }
    if (!EXEMPTION_REASONS.includes(entry.reason)) {
      errors.push(`${where}: unknown reason '${entry.reason}'`);
    }
    if (entry.reason === 'escalated' && !DECISION_REF_PATTERN.test(entry.decisionRef ?? '')) {
      errors.push(`${where}: escalated requires a decisionRef: the URL of a public issue or pull request in this repository`);
    }
    if (CONVERTIBLE_EXT.test(entry.path) && entry.reason !== 'escalated') {
      errors.push(
        `${where}: a ${entry.path.match(CONVERTIBLE_EXT)?.[0]} file is convertible with the ` +
          `runtime-assembly idiom and cannot be registered; use the idiom, or escalate with a ` +
          `decisionRef naming a public issue or pull request`,
      );
    }
    const text = JSON.stringify(entry);
    if (new RegExp(TOKEN_SHAPE_PATTERN_SOURCE).test(text)) {
      errors.push(`${where}: entry carries a token-shape value; entries key on path + hit count only`);
    }
  }
  return errors;
}

/** Load the committed registry from `rootDir`. Missing file = empty registry. */
export function loadRegistry(rootDir: string): ExemptionRegistry {
  const file = join(rootDir, REGISTRY_PATH);
  if (!existsSync(file)) return { entries: [] };
  return JSON.parse(readFileSync(file, 'utf8')) as ExemptionRegistry;
}

function walk(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(full, out);
      continue;
    }
    if (entry.isFile()) out.push(full);
  }
}

/** Mirror of `grep -I`: treat a NUL byte in the first 8 KiB as binary. */
function isBinary(buf: Buffer): boolean {
  return buf.subarray(0, 8192).includes(0);
}

/**
 * Scan every text file under `rootDir` against the pattern set and resolve
 * the hits against `registry`. Reports paths and line numbers only — never
 * matched text.
 */
export function scanRepository(rootDir: string, registry: ExemptionRegistry): ScanResult {
  const registryErrors = validateRegistry(registry);
  if (registryErrors.length > 0) {
    throw new Error(`invalid exemption registry:\n  ${registryErrors.join('\n  ')}`);
  }

  const files: string[] = [];
  walk(rootDir, files);

  const hits = new Map<string, number[]>();
  // No `g` flag: `test` is then stateless, and one compiled regex serves the
  // whole walk.
  const pattern = new RegExp(TOKEN_SHAPE_PATTERN_SOURCE);
  for (const file of files) {
    const buf = readFileSync(file);
    if (isBinary(buf)) continue;
    const lines = buf.toString('utf8').split('\n');
    const matching: number[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (pattern.test(lines[i])) matching.push(i + 1);
    }
    if (matching.length > 0) {
      hits.set(relative(rootDir, file).split(sep).join('/'), matching);
    }
  }

  const violations: ScanViolation[] = [];
  const byPath = new Map(registry.entries.map((e) => [e.path, e]));

  let matchedLineCount = 0;
  let unregisteredLineCount = 0;
  for (const [path, lines] of hits) {
    matchedLineCount += lines.length;
    const entry = byPath.get(path);
    if (!entry) {
      unregisteredLineCount += lines.length;
      violations.push({ kind: 'unregistered', path, lines });
      continue;
    }
    if (lines.length !== entry.expectedHits) {
      if (lines.length > entry.expectedHits) {
        unregisteredLineCount += lines.length - entry.expectedHits;
      }
      violations.push({
        kind: 'count-drift',
        path,
        lines,
        expectedHits: entry.expectedHits,
        actualHits: lines.length,
      });
    }
  }
  for (const entry of registry.entries) {
    if (!hits.has(entry.path)) {
      violations.push({ kind: 'stale-entry', path: entry.path, lines: [], expectedHits: entry.expectedHits, actualHits: 0 });
    }
  }

  violations.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { ok: violations.length === 0, matchedLineCount, unregisteredLineCount, violations };
}

/** One line per violation, path:line form only. */
export function formatViolations(result: ScanResult): string[] {
  const out: string[] = [];
  for (const v of result.violations) {
    if (v.kind === 'unregistered') {
      for (const line of v.lines) out.push(`unregistered token-shape line: ${v.path}:${line}`);
    } else if (v.kind === 'count-drift') {
      out.push(
        `count drift: ${v.path} has ${v.actualHits} matching lines (registry says ${v.expectedHits}); ` +
          `matching lines: ${v.lines.join(', ')}`,
      );
    } else {
      out.push(`stale registry entry: ${v.path} has no matching lines; delete the entry`);
    }
  }
  return out;
}

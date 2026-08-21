/**
 * The E4 enumeration guard's scanner.
 *
 * Walks `src/`, counts occurrences of every credential-shape guard literal the
 * registry declares, and reports them per file. The registry file itself is
 * excluded — it is the one place these literals are supposed to live — and so
 * is `__tests__`, where fixtures legitimately carry them.
 *
 * WHY THIS EXISTS. Programmatic enumeration of the credential vocabulary was
 * impossible before the registry: the tables were `const` arrays and inline
 * regex literals inside function bodies, and the NanoMind redactor was eighteen
 * inline `.replace()` calls with no enumerable form at all. So a fifteenth copy
 * of `ghp_[a-zA-Z0-9]{36}` could be added to any file and nothing would notice
 * until the copy drifted below the detector's floor and started leaking.
 *
 * The guard does not stop a copy being written. It stops one being written
 * SILENTLY: a new literal fails the frozen allowlist and the author has to
 * either adopt the registry or say, in the allowlist, why they did not.
 *
 * Deliberately hermetic — a plain directory walk and `indexOf`, no `rg`, no
 * shelling out — so it behaves identically in CI and on a developer machine.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

/** Directory names never walked. */
const SKIP_DIRS = new Set(['__tests__', 'node_modules', 'dist']);

/** Files whose literals are the registry itself, not a copy of it. */
export const REGISTRY_FILES: readonly string[] = ['src/types/credential-format.ts'];

/**
 * Shape literals that appear in `src` and belong to NO registry shape.
 *
 * Both are guarded here rather than added to the registry, because adding a
 * shape changes what is detected and this unit does not make a detection
 * change — but leaving them unguarded would let a second copy appear silently,
 * which is the whole failure mode.
 *
 *   - `ghr_` — a real GitHub token prefix carried by
 *     `scanner/permission-vocabulary.ts:418` and known to no detector in the
 *     tree: not in `VENDOR_PREFIX_ALTERNATIVES`, not in
 *     `CANONICAL_CREDENTIAL_PATTERNS`, not in `redactCredentialShapes`.
 *   - `nvapi-` — NVIDIA, carried by `hardening/nemoclaw-scanner.ts:34` in that
 *     scanner's own private `NVAPI_PATTERNS` table, and by nothing else.
 *
 * These two are the ONLY literals in the prior baseline's wider vocabulary that
 * this guard would otherwise miss. That was measured rather than assumed: the
 * prior baseline's own recorded command also carries `sk-or-v1`, `ASIA…`,
 * `rk_live_` and `shpat_`, and each of those returns zero hits in `src`, so
 * omitting them narrows nothing.
 */
export const UNOWNED_SHAPE_LITERALS: readonly string[] = ['ghr_', 'nvapi-'];

export interface LiteralScanResult {
  /** repo-relative path -> total guard-literal occurrences in that file. */
  readonly counts: Readonly<Record<string, number>>;
  /** repo-relative path -> which literals were seen, for the failure message. */
  readonly witnesses: Readonly<Record<string, readonly string[]>>;
}

function walk(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(full, out);
      continue;
    }
    if (/\.(ts|js|mts|cts|mjs|cjs)$/.test(entry.name)) out.push(full);
  }
}

/** Count occurrences of `needle` in `haystack`. Literal, not regex. */
function countOccurrences(haystack: string, needle: string): number {
  let n = 0;
  let i = haystack.indexOf(needle);
  while (i !== -1) {
    n++;
    i = haystack.indexOf(needle, i + needle.length);
  }
  return n;
}

/**
 * Scan `srcRoot` for credential-shape guard literals.
 *
 * `literals` is passed in rather than imported so the caller decides what the
 * vocabulary is — the test passes the registry's own guards, which is what
 * makes a newly added shape extend the guard automatically.
 */
export function scanForCredentialLiterals(
  repoRoot: string,
  srcRoot: string,
  literals: readonly string[],
): LiteralScanResult {
  const files: string[] = [];
  walk(srcRoot, files);

  const counts: Record<string, number> = {};
  const witnesses: Record<string, string[]> = {};

  for (const file of files) {
    const rel = relative(repoRoot, file).split(sep).join('/');
    if (REGISTRY_FILES.includes(rel)) continue;
    const content = readFileSync(file, 'utf8');
    let total = 0;
    const seen: string[] = [];
    for (const literal of literals) {
      const n = countOccurrences(content, literal);
      if (n > 0) {
        total += n;
        seen.push(`${literal}x${n}`);
      }
    }
    if (total > 0) {
      counts[rel] = total;
      witnesses[rel] = seen;
    }
  }

  return { counts, witnesses };
}

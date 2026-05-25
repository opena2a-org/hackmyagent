/**
 * Path-context classifiers used to suppress false positives where a scanner
 * rule would otherwise fire on non-production files.
 *
 * Every helper takes a forward-slash-normalized RELATIVE path from the scan
 * root (use `path.relative(targetDir, file).replace(/\\\\/g, '/')` before
 * calling) and returns a boolean.
 *
 * Design principles (established 2026-04-17 after adversarial self-review):
 *  - All matches are case-insensitive (cross-platform filesystems differ).
 *  - Bare `node_modules/` subtrees never match any exemption — an attacker
 *    can ship a package named `@tests/x` and would otherwise inherit test
 *    suppression.
 *  - Exemptions require EITHER an unambiguous extension (e.g. `.test.ts`,
 *    `.safetensors`) OR a first-segment directory match. Middle-of-path
 *    `/tests/` in user code does NOT exempt — it could be a real repo path.
 *  - Generic top-level `corpus/` or `docs/` does not exempt — those are
 *    common directory names with ambiguous semantics. Require a specific
 *    prefix (`training/corpus`) or narrower directory (`examples/`).
 *
 * Rules (per CSR/CDS decisions in briefs/release-findings.md):
 *  - [CSR-003] + [CDS-023] training/corpus/** and training/datasets/** are
 *    intentionally full of adversarial Unicode; UNICODE-STEGO-* skips them.
 *  - [CSR-004 revised] unambiguous test paths (`*.test.ts`, `*.spec.ts`,
 *    `_test.go`, `__tests__/`) deliberately contain what they test;
 *    NEMO-007 and TOCTOU-001 skip them. Generic `tests/` or `fixtures/`
 *    middle-of-path is NOT exempt.
 *  - [CSR-002 revised] examples/templates/samples are schema demos;
 *    AIM-002 softens severity inside them. docs/ and fixtures/ dropped
 *    from the list — too often contain real configs.
 */

const normalize = (relativePath: string): string =>
  relativePath.replace(/\\/g, '/').toLowerCase();

/**
 * True when the path is inside an installed dependency tree. Never
 * exempt — attacker-controlled package names can otherwise forge any
 * exemption by matching a directory name (e.g. `@tests/malicious`).
 */
function isInstalledDep(p: string): boolean {
  return /(^|\/)(node_modules|vendor|bower_components|\.pnpm)\//.test(p);
}

/**
 * True when the path points into an ML training corpus or dataset. Must
 * be under a `training/` prefix — bare top-level `corpus/` or
 * `datasets/` is too common a directory name in non-ML projects to
 * assume adversarial-unicode-by-design.
 */
export function isCorpusPath(relativePath: string): boolean {
  const p = normalize(relativePath);
  if (isInstalledDep(p)) return false;
  if (/(^|\/)training\/corpus\//.test(p)) return true;
  if (/(^|\/)training\/datasets?\//.test(p)) return true;
  if (/(^|\/)training\/data\//.test(p)) return true;
  // Dataset sharded-binary formats are binary files; UTF-8 stego rules
  // can't hit them anyway, but matching here prevents future textual
  // check classes (e.g. NEMO deserialization) from firing on them too.
  if (/\.(parquet|arrow|tfrecord|safetensors)$/.test(p)) return true;
  return false;
}

/**
 * True when the path points into a test file. Only unambiguous
 * patterns match:
 *  - Files with explicit test/spec extensions (`.test.ts`, `.spec.ts`,
 *    `_test.go`, `.test.py`, etc.). These extensions are conventional
 *    enough that a malicious actor renaming production code to
 *    `.test.ts` is itself a supply-chain smell.
 *  - Paths whose FIRST segment is `__tests__`. The double-underscore
 *    Jest convention is unlikely to be a scoped-npm package name or
 *    middle-of-path collision.
 *
 * Note: generic `tests/`, `test/`, `fixtures/`, `spec/` directories
 * are NOT exempted by this helper. A production project can legitimately
 * live under `tests/` (e.g. as the root of a test framework), and an
 * attacker package can legitimately contain a `tests/` directory of
 * planted secrets. Narrow patterns only.
 */
export function isTestPath(relativePath: string): boolean {
  const p = normalize(relativePath);
  if (isInstalledDep(p)) return false;
  if (/^__tests__\//.test(p)) return true;
  if (/\.(test|spec)\.[cm]?[tj]sx?$/.test(p)) return true;
  if (/\.(test|spec)\.py$/.test(p)) return true;
  if (/_test\.go$/.test(p)) return true;
  if (/_test\.py$/.test(p)) return true;
  return false;
}

/**
 * True when the path points to an integrity / model manifest file. These
 * JSON files describe artifact layouts and ship SHA-256 / SHA-512 hex
 * digests under `sha256`, `sha512`, `integrity`, or `checksum` keys; the
 * 64-hex digest shape matches the credential-format high-entropy fallback
 * regex (40+ word-character run), which would otherwise fire AST-CRED-001
 * and AST-CRED-003 on every manifest entry. Recognize the file by name
 * so the credential analyzer can treat these contents as documentation
 * rather than a credential surface.
 *
 * Names:
 *  - `manifest.json` / `models.json` at any depth.
 *  - Any basename ending in `-manifest.json` or `-models.json` (e.g.
 *    `nanomind-models.json`, `release-manifest.json`).
 *
 * Pure-hex hash shape detection (32/40/64/128 hex) is the second gate
 * inside the credential analyzer; this helper covers the file-naming
 * convention.
 */
export function isIntegrityManifestPath(relativePath: string): boolean {
  const p = normalize(relativePath);
  if (isInstalledDep(p)) return false;
  const basename = p.split('/').pop() ?? '';
  if (basename === 'manifest.json' || basename === 'models.json') return true;
  if (/-manifest\.json$/.test(basename) || /-models\.json$/.test(basename)) {
    return true;
  }
  return false;
}

/**
 * True when the path points into an examples/templates/samples directory.
 * Files in these directories are schema documentation — agent-card.json
 * under `examples/` is a demonstration of the shape, not a production
 * identity. Checks that over-tune on schema completeness (AIM-002)
 * soften severity inside them.
 *
 * Note: `docs/` and `fixtures/` are intentionally NOT included —
 * real projects ship production configs under those names (e.g.
 * `docs/config/prod.json`, `fixtures/canary/identity.json`).
 *
 * Exemption requires the directory to appear ANYWHERE in the path —
 * this is the scan target's path shape, which often includes the
 * examples/ segment without it being the first segment.
 */
export function isExamplePath(relativePath: string): boolean {
  const p = normalize(relativePath);
  if (isInstalledDep(p)) return false;
  if (/(^|\/)examples?\//.test(p)) return true;
  if (/(^|\/)templates?\//.test(p)) return true;
  if (/(^|\/)samples?\//.test(p)) return true;
  return false;
}

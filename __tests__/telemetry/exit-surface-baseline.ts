/**
 * The exit-surface ratchet's registry (#350). THIS LIST ONLY SHRINKS.
 *
 * Every bare `process.exit(...)` call and bare `process.exitCode` assignment
 * in `src/` carries either an `// exit-unsettled(#350/S<id>)` annotation
 * whose id lives here, or an `// exit-no-event(<tag>)` claim from the closed
 * vocabulary below. A NEW id is a new dark exit site — the #350 inversion
 * re-opening — and needs a CISO-lane ruling, not a list edit. A migration
 * deletes the site's annotation AND its id here in the same diff.
 *
 * Ids are stable names, not locations: they travel with the code through
 * refactors, so this list never churns and never trains anyone to
 * regenerate it mechanically.
 */
export const UNSETTLED_EXIT_IDS: ReadonlySet<string> = new Set([
  // Pre-work refusals (Class R) — events await the schema reason field (#525):
  'S001', 'S002', 'S003', 'S004', 'S005', 'S006', 'S007', 'S008', 'S009', 'S010',
  'S012', 'S013', 'S014', 'S016', 'S017', 'S018', 'S019', 'S020', 'S021', 'S022',
  'S023', 'S024', 'S025', 'S026', 'S027', 'S031', 'S035', 'S037', 'S039', 'S041',
  'S042', 'S043', 'S044', 'S045',
  // Bare `process.exitCode` assignments outside the funnel — migrate to raiseExitCode:
  'S011', 'S015', 'S028', 'S029', 'S030', 'S032', 'S033', 'S034', 'S036', 'S038',
  'S040', 'S046', 'S047', 'S048', 'S049', 'S050', 'S051', 'S052', 'S053', 'S054',
  'S055',
  // benchmark-report.ts's category refusal (reached from the tracked benchmark command):
  'S056',
]);

/**
 * The closed exemption vocabulary. Each tag names the PREDICATE that makes
 * its sites event-free — the annotation licenses the claim, not the
 * citation. Adding a tag is a gate-semantics change (CISO lane).
 *
 * - `pre-action`: runs before any command action arms telemetry
 *   (`recordTelemetry` no-ops without `currentCommandName`); structurally
 *   checked — the site must not be inside a `.action(` callback.
 * - `non-tracked-command`: inside an action of a command in
 *   NON_TRACKED_TELEMETRY_COMMANDS. No members today.
 * - `post-record`: after `recordTelemetry` already fired for this run
 *   (once-only). The one trust+review residue. No members today.
 * - `separate-entrypoint`: a module never imported into the
 *   telemetry-bearing process (src/arp/cli) — SELF-REVOKING via the
 *   standing no-import assertion in the test.
 * - `exit-funnel`: the funnel's own writes, additionally keyed by
 *   enclosing named function.
 */
export const EXEMPTION_TAGS: ReadonlySet<string> = new Set([
  'pre-action',
  'non-tracked-command',
  'post-record',
  'separate-entrypoint',
  'exit-funnel',
]);

/** The funnel's named functions — the only writers permitted without an annotation. */
export const FUNNEL_FUNCTIONS: ReadonlySet<string> = new Set([
  'finishWithFindings',
  'raiseExitCode',
  'exitRecorded',
]);

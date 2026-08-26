/**
 * The exit-surface ratchet's registry (#350). THIS LIST ONLY SHRINKS.
 *
 * Every bare `process.exit(...)` call and bare `process.exitCode` assignment
 * in `src/` carries either an `// exit-unsettled(#350/S<id>)` annotation
 * whose id lives here, or an `// exit-no-event(<tag>/L<id>)` claim whose id
 * is registered below with its tag. A NEW id of either kind is a new dark
 * exit site — the #350 inversion re-opening — and needs a CISO-lane ruling,
 * not a list edit. A migration deletes the site's annotation AND its id here
 * in the same diff.
 *
 * Ids are stable names, not locations: they travel with the code through
 * refactors, so this list has no reason to churn and nobody learns to
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
  // UsageError branches of the converted catch template — refusals, not
  // crashes: the run did no work, and an event that cannot say "refused"
  // would land in the crash bucket (#525 converts these with the rest):
  'S057', 'S058', 'S059', 'S060', 'S061', 'S062', 'S063', 'S064', 'S065',
  'S066', 'S067', 'S068',
]);

/**
 * Every `exit-no-event` claim, by registered id → the ONLY tag that id may
 * carry. The annotation licenses the CLAIM, not the citation: the test
 * checks each tag's predicate structurally where it can (pre-action must
 * not sit inside a `.action(` callback; separate-entrypoint only inside
 * src/arp/cli/, which a standing assertion holds un-imported), and holds
 * the member list closed everywhere it cannot — a new member is a
 * baseline edit reviewed as a gate-semantics change (CISO lane), never a
 * one-line comment.
 *
 * Tags with no registered member (`non-tracked-command`, `post-record`)
 * are thereby unusable until a member is deliberately registered here.
 * The funnel's own exits carry no annotation at all: their exemption is
 * structural (enclosing function ∈ FUNNEL_FUNCTIONS, in src/cli.ts, exact
 * count pinned by the test).
 */
export const NO_EVENT_EXIT_SITES: ReadonlyMap<string, string> = new Map([
  // Lifecycle sites in src/cli.ts that run before any command action arms
  // telemetry (`recordTelemetry` no-ops without `currentCommandName`):
  ['L001', 'pre-action'], // integrity self-check failure, exit 3
  ['L002', 'pre-action'], // option:version handler
  ['L003', 'pre-action'], // no-args help path
  // The ARP standalone binary (src/arp/cli/index.ts) — never imported into
  // the telemetry-bearing process; self-revoking via the no-import assertion:
  ['L004', 'separate-entrypoint'],
  ['L005', 'separate-entrypoint'],
  ['L006', 'separate-entrypoint'],
  ['L007', 'separate-entrypoint'],
  ['L008', 'separate-entrypoint'],
  ['L009', 'separate-entrypoint'],
]);

/**
 * The closed exemption vocabulary. Each tag names the PREDICATE that makes
 * its sites event-free. Adding a tag is a gate-semantics change (CISO lane).
 *
 * - `pre-action`: runs before any command action arms telemetry;
 *   structurally checked — the site must not be inside a `.action(`
 *   callback — AND member-closed via the registry above (the lexical check
 *   alone is satisfiable by a helper a command action calls).
 * - `non-tracked-command`: inside an action of a command in
 *   NON_TRACKED_TELEMETRY_COMMANDS. No members today, so no id carries it.
 * - `post-record`: after `recordTelemetry` already fired for this run
 *   (once-only). The one trust+review residue. No members today.
 * - `separate-entrypoint`: a module never imported into the
 *   telemetry-bearing process (src/arp/cli/) — SELF-REVOKING via the
 *   standing no-import assertion in the test.
 */
export const EXEMPTION_TAGS: ReadonlySet<string> = new Set([
  'pre-action',
  'non-tracked-command',
  'post-record',
  'separate-entrypoint',
]);

/** The funnel's named functions — the only writers permitted without an annotation. */
export const FUNNEL_FUNCTIONS: ReadonlySet<string> = new Set([
  'finishWithFindings',
  'raiseExitCode',
  'exitRecorded',
]);

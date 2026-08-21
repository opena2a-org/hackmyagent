/**
 * Shared credential-format detection.
 *
 * Two independent signals decide whether a substring "looks like a credential":
 *
 *   1. A curated vendor prefix (`sk-`, `sk_live_`, `ghp_`, `ghs_`, `hf_`,
 *      `glpat-`, `npm_`, `AKIA…`, `AIza…`, `xox[abprs]-`, `SG.`, `eyJ…` JWT).
 *      These are positively identified by their prefix and are accepted on
 *      shape alone.
 *
 *   2. A high-entropy fallback: a 40+ word-character run, anchored on word
 *      boundaries, excluding `-` and `/` so URL slugs and slug-style
 *      identifiers do not match.
 *
 * Signal 2 was a pure LENGTH test, so a fill-in-the-blank form rule
 * (`Local Office: _______________________________________________`) read as a
 * credential. That produced a HIGH "Hardcoded Secret Detected" on a public
 * incident-response contact-sheet template whose only "secret" was the heading
 * "U.S. Secret Service (Cyber Fraud)" sitting next to two form blanks.
 *
 * See `isCredibleEntropyBlob` for the rule that separates the two classes, and
 * `findCredibleWindowOffset` for why that rule is applied to a sliding WINDOW
 * rather than to the whole greedy run.
 *
 * Bare-keyword mentions ("credentials", "API key", "token") in descriptive text
 * do NOT count as either signal. Placeholder / env-var reference values
 * (`$OPENAI_API_KEY`, `${OPENAI_API_KEY}`, `<YOUR_KEY>`) fail the fallback
 * because the leading `$`/`<` are not word characters.
 *
 * ## Why there is no length bound and no work budget in this file
 *
 * Three consecutive adversarial passes killed three designs here, and all three
 * failed the same way: a bound added to stop a quadratic ALSO narrowed a gate
 * that lifts suppression, so a real credential went undetected and the score
 * ROSE. A bounded JWT header silenced a live token planted in a corpus path; a
 * character budget on the filler walk lost an anonymous secret behind 12 KB of
 * padding. Both were invisible to the whole test suite because neither
 * `test/hma` nor the adversarial corpus contains an oversized JWT, an anonymous
 * high-entropy secret, or a long padded run.
 *
 * So the performance defense here is LINEARITY, never truncation:
 *
 *   - the JWT is matched by a linear scan (`findJwtMatch`), not by a regex, so
 *     it needs no segment bound;
 *   - each blob run is judged exactly once by a sliding window, so the walk
 *     needs no resume and therefore no budget.
 *
 * If a future change to this file reaches for a cap, that is the signal to
 * check which negated or suppression-lifting gate the cap just narrowed.
 */

/* ------------------------------------------------------------------ *
 * Vendor prefixes
 * ------------------------------------------------------------------ */

/**
 * Every JWT begins with the base64url encoding of `{"`.
 *
 * Declared here rather than beside `findJwtMatch` because
 * `VENDOR_PREFIX_MATCHERS` below needs it at module-initialisation time, and a
 * `const` is not hoisted.
 */
const JWT_PREFIX = 'eyJ';

/* ------------------------------------------------------------------ *
 * The credential shape registry
 * ------------------------------------------------------------------ */

/**
 * The surfaces a credential shape can reach.
 *
 * These are the four places in the tree that decide, independently, whether a
 * run of bytes is a credential. They are named here so that a shape's ABSENCE
 * from one of them is data rather than an accident nobody can see:
 *
 *   - `format-scan`        this module's `findCredentialFormatMatch` /
 *                          `hasCredentialFormat` — vendor alternation, JWT scan
 *                          and the entropy fallback.
 *   - `vendor-alternation` membership in `VENDOR_PREFIX_ALTERNATIVES`, i.e. the
 *                          regex alternation the format scan and its callers
 *                          compose.
 *   - `ast-canonical`      `CANONICAL_CREDENTIAL_PATTERNS` and
 *                          `NAME_GATED_CREDENTIAL_PATTERNS` in
 *                          `nanomind-core/compiler/semantic-compiler.ts`.
 *   - `nanomind-redaction` `redactCredentialShapes` in
 *                          `nanomind-core/security/defense-in-depth.ts`.
 *
 * Every membership recorded below was read off those three files, not inferred.
 */
export type Surface =
  | 'format-scan'
  | 'vendor-alternation'
  | 'ast-canonical'
  | 'nanomind-redaction';

/** Every shape this tree can detect or redact, by id. */
export type ShapeId =
  | 'anthropic-key'
  | 'openai-project-key'
  | 'openai-key'
  | 'stripe-live'
  | 'stripe-test'
  | 'github-pat'
  | 'github-oauth'
  | 'github-server'
  | 'github-user'
  | 'github-fine-grained'
  | 'huggingface-token'
  | 'gitlab-pat'
  | 'npm-token'
  | 'aws-access-key-id'
  | 'google-api-key'
  | 'slack-token'
  | 'sendgrid-key'
  | 'jwt'
  | 'entropy-blob'
  | 'pem-private-key'
  | 'aws-secret-access-key'
  | 'connection-string';

/**
 * A credential body: either one run of a character class, or fixed-width
 * segments joined by a separator (SendGrid, and nothing else today).
 *
 * `min`/`max` are the DETECTOR's floor and ceiling, deliberately — see
 * `shapeAlternation`.
 */
export type ShapeBody =
  | { readonly kind: 'run'; readonly class: string; readonly min: number; readonly max?: number }
  | {
      readonly kind: 'segments';
      readonly separator: string;
      readonly segments: readonly { readonly class: string; readonly length: number }[];
    };

interface ShapeCommon {
  readonly id: ShapeId;
  /** Display only. NEVER enumerate by this — see `slack-token`. */
  readonly label: string;
  /**
   * Literal substrings that identify a hand-written COPY of this shape in
   * source. One entry per spelling: `SG.` and `SG\.` are the same shape written
   * two ways and a single-spelling guard sees only one of them.
   */
  readonly guards: readonly string[];
  readonly surfaces: ReadonlySet<Surface>;
  /**
   * The measured reason this shape does not reach every surface. REQUIRED
   * whenever `surfaces` is not the full set — enforced at load, below.
   */
  readonly rationale?: string;
}

/** A shape identified by a vendor-issued prefix. */
export interface VendorShape extends ShapeCommon {
  readonly kind: 'vendor';
  /**
   * The recognisable head, as regex source, carrying NO quantifier: `ghp_`,
   * `sk-ant-api[0-9]`, `xox[abprs]-`. Unquantified classes are part of the head
   * because they are part of what makes the token recognisable.
   */
  readonly head: string;
  readonly body: ShapeBody;
}

/** A shape with no vendor prefix: self-describing, or gated by a key name. */
export interface StructuralShape extends ShapeCommon {
  readonly kind: 'structural';
  /**
   * Full regex source, or the empty string for a shape matched by a scan rather
   * than by a regex (the JWT).
   */
  readonly source: string;
  /** The key-name regex a name-gated shape requires before it will fire. */
  readonly nameGate?: string;
}

export type CredentialShape = VendorShape | StructuralShape;

const ALL_SURFACES: readonly Surface[] = [
  'format-scan',
  'vendor-alternation',
  'ast-canonical',
  'nanomind-redaction',
];

const EVERY_SURFACE: ReadonlySet<Surface> = new Set(ALL_SURFACES);

/**
 * Why five shapes are missing from `ast-canonical`, in one place because it is
 * ONE reason and repeating it per shape would read as five findings.
 *
 * It is NOT a measured exclusion, and saying so is the point. The canonical
 * list is short by process, not by judgement: a first draft added eight shapes
 * at once, two adversarial rounds measured a false-positive class on ordinary
 * identifiers plus a quadratic scan introduced while trying to bound it, and
 * the rest are being re-added ONE AT A TIME on `fix/credential-fp-siblings`
 * (#352/#353). The history is written down at
 * `__tests__/nanomind-core/pinned-credential-shapes.test.ts:9-14`.
 *
 * So for each shape carrying this string: nobody has measured its false-
 * positive cost, and nobody has decided it should be absent. It is an
 * UNDECLARED GAP with a known cause, which is a different thing from a
 * deliberate exclusion like `gitlab-pat`'s, and a reader has to be able to tell
 * them apart. Closing them is the widening step, and it is separately gated.
 *
 * Note what the gap actually costs, because it is not "the shape is unknown":
 * `credential-analyzer.ts:116-121` wires the shared matcher as a GATE
 * (`if (!credLocation) return findings;`) and never as a producer, so these
 * shapes are matched by the vocabulary and then dropped rather than never seen.
 */
const NOT_YET_RE_ADDED_TO_CANONICAL =
  'UNDECLARED GAP, not a measured exclusion: absent from CANONICAL_CREDENTIAL_PATTERNS ' +
  '(semantic-compiler.ts:1279-1330) only because that list is being re-populated one shape at a ' +
  'time on fix/credential-fp-siblings (#352/#353) after a first draft of eight measured an FP ' +
  'class and a quadratic scan — see __tests__/nanomind-core/pinned-credential-shapes.test.ts:9-14. ' +
  'No FP measurement exists for this shape. Contrast gitlab-pat, whose absence IS measured.';

/**
 * ONE floor per shape, and it is the DETECTOR's.
 *
 * The reason is measured. `defense-in-depth` hand-wrote its own body counts —
 * `ghp_…{36}`, `github_pat_…{60,}`, `hf_…{34,}`, `npm_…{36}`, `sk_live_…{24,}`
 * — while this module's detector uses `{20,}`. Every gap between the two is a
 * band in which a token is DETECTED and then NOT redacted: the scanner proves
 * the secret is real and forwards it verbatim. Deriving a redactor quantifier
 * from `body.min` closes that band mechanically. Nothing derives from it yet —
 * this registry is data first — but the floor lives in exactly one place now,
 * so the adoption cannot re-create the drift it removes.
 */
export const CREDENTIAL_SHAPES: readonly CredentialShape[] = [
  {
    kind: 'vendor',
    id: 'anthropic-key',
    label: 'Anthropic API key',
    head: 'sk-ant-api[0-9]',
    body: { kind: 'run', class: '[a-zA-Z0-9_-]', min: 16 },
    guards: ['sk-ant'],
    surfaces: EVERY_SURFACE,
  },
  {
    kind: 'vendor',
    id: 'openai-project-key',
    label: 'OpenAI project key',
    head: 'sk-proj-',
    body: { kind: 'run', class: '[a-zA-Z0-9_-]', min: 16 },
    guards: ['sk-proj'],
    surfaces: EVERY_SURFACE,
  },
  {
    kind: 'vendor',
    id: 'openai-key',
    label: 'OpenAI legacy key',
    head: 'sk-',
    body: { kind: 'run', class: '[a-zA-Z0-9_-]', min: 20 },
    // `sk-` on its own matches `task-`, `risk-` and `disk-` and would make the
    // enumeration guard useless. The two spellings a copy actually takes are a
    // character class (`sk-[a-zA-Z0-9…`) and an alternation branch (`sk-|…`).
    guards: ['sk-[', 'sk-|'],
    surfaces: EVERY_SURFACE,
  },
  {
    kind: 'vendor',
    id: 'stripe-live',
    label: 'Stripe live key',
    head: 'sk_live_',
    body: { kind: 'run', class: '[a-zA-Z0-9]', min: 20 },
    guards: ['sk_live_'],
    surfaces: EVERY_SURFACE,
  },
  {
    kind: 'vendor',
    id: 'stripe-test',
    label: 'Stripe test key',
    head: 'sk_test_',
    body: { kind: 'run', class: '[a-zA-Z0-9]', min: 20 },
    guards: ['sk_test_'],
    surfaces: new Set<Surface>(['format-scan', 'vendor-alternation', 'nanomind-redaction']),
    rationale: NOT_YET_RE_ADDED_TO_CANONICAL,
  },
  {
    kind: 'vendor',
    id: 'github-pat',
    label: 'GitHub personal access token',
    head: 'ghp_',
    body: { kind: 'run', class: '[a-zA-Z0-9]', min: 20 },
    guards: ['ghp_'],
    surfaces: EVERY_SURFACE,
  },
  {
    kind: 'vendor',
    id: 'github-oauth',
    label: 'GitHub OAuth token',
    head: 'gho_',
    body: { kind: 'run', class: '[a-zA-Z0-9]', min: 20 },
    guards: ['gho_'],
    surfaces: EVERY_SURFACE,
  },
  {
    kind: 'vendor',
    id: 'github-server',
    label: 'GitHub app token',
    head: 'ghs_',
    body: { kind: 'run', class: '[a-zA-Z0-9]', min: 20 },
    guards: ['ghs_'],
    surfaces: EVERY_SURFACE,
  },
  {
    kind: 'vendor',
    id: 'github-user',
    label: 'GitHub user-to-server token',
    head: 'ghu_',
    body: { kind: 'run', class: '[a-zA-Z0-9]', min: 20 },
    guards: ['ghu_'],
    surfaces: new Set<Surface>(['format-scan', 'vendor-alternation', 'nanomind-redaction']),
    rationale: NOT_YET_RE_ADDED_TO_CANONICAL,
  },
  {
    kind: 'vendor',
    id: 'github-fine-grained',
    label: 'GitHub fine-grained token',
    head: 'github_pat_',
    body: { kind: 'run', class: '[a-zA-Z0-9_]', min: 20 },
    guards: ['github_pat_'],
    surfaces: new Set<Surface>(['format-scan', 'vendor-alternation', 'nanomind-redaction']),
    rationale: NOT_YET_RE_ADDED_TO_CANONICAL,
  },
  {
    kind: 'vendor',
    id: 'huggingface-token',
    label: 'Hugging Face token',
    head: 'hf_',
    body: { kind: 'run', class: '[a-zA-Z0-9]', min: 20 },
    guards: ['hf_'],
    surfaces: new Set<Surface>(['format-scan', 'vendor-alternation', 'nanomind-redaction']),
    rationale: NOT_YET_RE_ADDED_TO_CANONICAL,
  },
  {
    kind: 'vendor',
    id: 'gitlab-pat',
    label: 'GitLab personal access token',
    head: 'glpat-',
    body: { kind: 'run', class: '[a-zA-Z0-9_-]', min: 20 },
    guards: ['glpat-'],
    surfaces: new Set<Surface>(['format-scan', 'vendor-alternation', 'nanomind-redaction']),
    rationale:
      'DELIBERATELY excluded from CANONICAL_CREDENTIAL_PATTERNS and the exclusion is measured ' +
      '(semantic-compiler.ts:1310-1324): the body class admits `-` and `_`, so `glpat-` plus any ' +
      'hyphenated identifier matches, and the entropy lookahead tried to separate them went ' +
      'QUADRATIC on attacker-supplied content — 0ms -> 651ms at 60 KB, 1ms -> 40s at 480 KB — ' +
      'while still passing `glpat-' + 'shared-linux-docker-runner-1`. Do not flatten this into the ' +
      'canonical list without a bounded pattern AND a ReDoS measurement.',
  },
  {
    kind: 'vendor',
    id: 'npm-token',
    label: 'npm access token',
    head: 'npm_',
    body: { kind: 'run', class: '[a-zA-Z0-9]', min: 20 },
    guards: ['npm_'],
    surfaces: new Set<Surface>(['format-scan', 'vendor-alternation', 'nanomind-redaction']),
    rationale: NOT_YET_RE_ADDED_TO_CANONICAL,
  },
  {
    kind: 'vendor',
    id: 'aws-access-key-id',
    label: 'AWS access key ID',
    head: 'AKIA',
    body: { kind: 'run', class: '[0-9A-Z]', min: 16, max: 16 },
    guards: ['AKIA'],
    surfaces: EVERY_SURFACE,
  },
  {
    kind: 'vendor',
    id: 'google-api-key',
    label: 'Google API key',
    head: 'AIza',
    body: { kind: 'run', class: '[0-9A-Za-z_-]', min: 35, max: 35 },
    guards: ['AIza'],
    surfaces: EVERY_SURFACE,
  },
  {
    kind: 'vendor',
    id: 'slack-token',
    label: 'Slack token',
    // The class is part of the head on purpose: `xoxb-`, `xoxp-`, `xoxa-`,
    // `xoxr-` and `xoxs-` are five distinct token types that this tree reports
    // under the SINGLE label "Slack bot token". That is why enumeration is by
    // pattern and never by label — narrowing this to `xoxb-` is invisible to
    // any label-set assertion.
    head: 'xox[abprs]-',
    body: { kind: 'run', class: '[0-9A-Za-z-]', min: 10 },
    guards: ['xox'],
    surfaces: EVERY_SURFACE,
  },
  {
    kind: 'vendor',
    id: 'sendgrid-key',
    label: 'SendGrid API key',
    head: 'SG\\.',
    // FIXED widths, and they are load-bearing. Written as `SG\.<16,>\.<16,>`
    // this matched any dotted identifier with two long segments, so
    // `MSG.INCIDENT_ESCALATION_QUEUE.HIGH_PRIORITY_ROUTE` was positively
    // identified as a credential on a benign taxonomy document. A real SendGrid
    // secret is 43 characters and clears the 40-character blob fallback on its
    // own; this shape is what NAMES it. Do not relax the widths.
    body: {
      kind: 'segments',
      separator: '\\.',
      segments: [
        { class: '[A-Za-z0-9_-]', length: 22 },
        { class: '[A-Za-z0-9_-]', length: 43 },
      ],
    },
    guards: ['SG.', 'SG\\.'],
    surfaces: new Set<Surface>(['format-scan', 'vendor-alternation', 'nanomind-redaction']),
    rationale:
      'Absent from CANONICAL_CREDENTIAL_PATTERNS: semantic-compiler.ts:1325-1329 carries the ' +
      'explanatory comment for this shape but no entry beneath it, so the comment reads as ' +
      'coverage that is not there.',
  },
  {
    kind: 'structural',
    id: 'jwt',
    label: 'JSON Web Token',
    // Matched by a linear scan, not by a regex alternative. Expressing the JWT
    // as an alternative is what made every consumer either quadratic or
    // truncating, so `findJwtMatch` owns it and there is no source here.
    source: '',
    guards: ['eyJ'],
    surfaces: new Set<Surface>(['format-scan']),
    rationale:
      'Detected only by this module (findJwtMatch, and the JWT_PREFIX entry in ' +
      'VENDOR_PREFIX_MATCHERS). It is NOT in CANONICAL_CREDENTIAL_PATTERNS and it is NOT in ' +
      'redactCredentialShapes — defense-in-depth.ts:181-231 has no eyJ rule at all. ' +
      'A JWT reaching redactCredentialShapes today is passed through verbatim.',
  },
  {
    kind: 'structural',
    id: 'entropy-blob',
    label: 'High-entropy secret',
    source: '\\b[A-Za-z0-9+=_]{40,}\\b',
    guards: ['[A-Za-z0-9+=_]{40,}'],
    surfaces: new Set<Surface>(['format-scan']),
    rationale:
      'The anonymous fallback (credential-format.ts:873 ENTROPY_BLOB_ALTERNATIVE), gated by ' +
      'isCredibleEntropyBlob at credential-format.ts:995. Deliberately confined to this module: ' +
      'it has no vendor name to report, so promoting it to the redactor or to ' +
      'CANONICAL_CREDENTIAL_PATTERNS (semantic-compiler.ts:1279-1330) is an FP question nobody ' +
      'has measured.',
  },
  {
    kind: 'structural',
    id: 'pem-private-key',
    label: 'PEM private key',
    source: '-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PRIVATE)[A-Z ]*KEY-----',
    guards: ['-----BEGIN'],
    surfaces: new Set<Surface>(['ast-canonical', 'nanomind-redaction']),
    rationale:
      'Not a vendor prefix and not part of this module: detected by ' +
      'CANONICAL_CREDENTIAL_PATTERNS (semantic-compiler.ts:1330) and redacted by ' +
      'defense-in-depth.ts:227. Listed here because a shape absent from the registry cannot be ' +
      'guarded against being copied a fourth time.',
  },
  {
    kind: 'structural',
    id: 'aws-secret-access-key',
    label: 'AWS secret access key',
    source: '[A-Za-z0-9/+=]{40,}',
    nameGate: '(?:aws.{0,16}?(?:secret|private).{0,16}?key|secret[_\\s.-]?access[_\\s.-]?key)',
    guards: ['secret_access_key', 'secret[_\\s.-]?access'],
    surfaces: new Set<Surface>(['ast-canonical', 'nanomind-redaction']),
    rationale:
      'Name-gated: a bare 40-character blob is a git SHA as often as a secret, so it fires only ' +
      'when the assignment target names it. Lives in NAME_GATED_CREDENTIAL_PATTERNS ' +
      '(semantic-compiler.ts:1350-1364), not the canonical list, and has no vendor prefix, so it ' +
      'is on neither of this module`s surfaces.',
  },
  {
    kind: 'structural',
    id: 'connection-string',
    label: 'Connection string with embedded credentials',
    source: '(?:postgres|mysql|mongodb|redis)://[^\\s\'"]+',
    guards: ['postgres://', 'mongodb://'],
    surfaces: new Set<Surface>(['nanomind-redaction']),
    rationale:
      'Redacted by defense-in-depth but detected by neither this module nor the canonical list. ' +
      'Note the scheme sets already disagree: the redactor covers 4 schemes while ' +
      'credential-context.ts:35 URL_CREDENTIAL_PATTERN covers 10 (adding postgresql, amqp, ' +
      'rabbitmq, ftp, sftp, http, https), so six schemes are located and never redacted here.',
  },
];

/**
 * Compose a shape's alternation source from its own parts.
 *
 * THE RECORD STORES A BARE ALTERNATION AND EACH ROLE COMPOSES ITS OWN ANCHOR.
 * The detector left-anchors (`anchoredVendorAlternation`); the redactor is
 * deliberately unanchored, with a written reason — anchoring broke
 * `ghp_<36>ghp_<36>`, redacting the first and leaving the second, because the
 * replacement consumed the boundary the next match needed. Storing an anchored
 * regex would force one of the two roles to be wrong.
 */
export function shapeAlternation(shape: CredentialShape): string {
  if (shape.kind === 'structural') return shape.source;
  const { body } = shape;
  if (body.kind === 'segments') {
    return (
      shape.head +
      body.segments.map(s => `${s.class}{${s.length}}`).join(body.separator)
    );
  }
  const quantifier =
    body.max === undefined
      ? `{${body.min},}`
      : body.max === body.min
        ? `{${body.min}}`
        : `{${body.min},${body.max}}`;
  return `${shape.head}${body.class}${quantifier}`;
}

/**
 * The marker each shape redacts to.
 *
 * A `Record<ShapeId, string>` rather than a field on the shape, so that the
 * TYPE is what forces totality: adding a member to `ShapeId` without adding a
 * marker is a compile error, before any test runs. The load-time check below is
 * the second layer, for the JavaScript consumer the type never reaches.
 *
 * A shape cannot become detectable without becoming redactable in the same
 * edit. That is the whole mechanism: `defense-in-depth` used to carry sixteen
 * hand-written vendor rules with their own body counts, and a `ghp_` token with
 * a 44-character body had its first 36 characters consumed by the labelled rule
 * and shipped the remaining 8 verbatim to stdout, `--json`, SARIF and HTML.
 */
export const CREDENTIAL_REDACTION_MARKERS: Readonly<Record<ShapeId, string>> = {
  'anthropic-key': '[REDACTED_ANTHROPIC_KEY]',
  'openai-project-key': '[REDACTED_OPENAI_KEY]',
  'openai-key': '[REDACTED_OPENAI_KEY]',
  'stripe-live': '[REDACTED_STRIPE_KEY]',
  'stripe-test': '[REDACTED_STRIPE_KEY]',
  'github-pat': '[REDACTED_GITHUB_TOKEN]',
  'github-oauth': '[REDACTED_GITHUB_TOKEN]',
  'github-server': '[REDACTED_GITHUB_TOKEN]',
  'github-user': '[REDACTED_GITHUB_TOKEN]',
  'github-fine-grained': '[REDACTED_GITHUB_TOKEN]',
  'huggingface-token': '[REDACTED_HUGGINGFACE_TOKEN]',
  'gitlab-pat': '[REDACTED_GITLAB_TOKEN]',
  'npm-token': '[REDACTED_NPM_TOKEN]',
  'aws-access-key-id': '[REDACTED_AWS_KEY]',
  'google-api-key': '[REDACTED_GOOGLE_KEY]',
  'slack-token': '[REDACTED_SLACK_TOKEN]',
  'sendgrid-key': '[REDACTED_SENDGRID_KEY]',
  jwt: '[REDACTED_JWT]',
  'entropy-blob': '[REDACTED_SECRET]',
  'pem-private-key': '[REDACTED_PRIVATE_KEY]',
  'aws-secret-access-key': '[REDACTED_AWS_SECRET]',
  'connection-string': '[REDACTED_CONNECTION_STRING]',
};

/**
 * Load-time totality, in both directions, plus the rationale rule.
 *
 * Runs at module initialisation so a registry that cannot satisfy its own
 * contract fails loudly at import rather than silently at the first redaction.
 */
(function assertRegistryTotality(): void {
  const ids = new Set<ShapeId>();
  for (const shape of CREDENTIAL_SHAPES) {
    if (ids.has(shape.id)) {
      throw new Error(`credential-format: duplicate shape id ${shape.id}`);
    }
    ids.add(shape.id);
    if (CREDENTIAL_REDACTION_MARKERS[shape.id] === undefined) {
      throw new Error(
        `credential-format: no redaction marker for shape ${shape.id}. Add one to ` +
          'CREDENTIAL_REDACTION_MARKERS — a detectable shape must be nameable when it is redacted.',
      );
    }
    if (shape.guards.length === 0) {
      throw new Error(
        `credential-format: shape ${shape.id} has no enumeration guard. A shape with no guard ` +
          'literal can be copied into another file without the enumeration test seeing it.',
      );
    }
    const total = ALL_SURFACES.every(s => shape.surfaces.has(s));
    if (!total && (shape.rationale === undefined || shape.rationale.length === 0)) {
      throw new Error(
        `credential-format: shape ${shape.id} reaches only ` +
          `${[...shape.surfaces].join(', ')} and carries no rationale. A surface a shape does ` +
          'not reach is either a measured decision or a defect, and the record has to say which.',
      );
    }
  }
  for (const id of Object.keys(CREDENTIAL_REDACTION_MARKERS) as ShapeId[]) {
    if (!ids.has(id)) {
      throw new Error(
        `credential-format: orphan redaction marker for ${id} — no such shape in ` +
          'CREDENTIAL_SHAPES. Markers and shapes are one vocabulary, not two.',
      );
    }
  }
})();

/** Every shape that reaches `surface`, in registry order. */
export function shapesFor(surface: Surface): readonly CredentialShape[] {
  return CREDENTIAL_SHAPES.filter(s => s.surfaces.has(surface));
}

/**
 * Vendor-prefixed credential shapes, in one place.
 *
 * DERIVED from `CREDENTIAL_SHAPES` — this array used to be the source of truth
 * and is now a VIEW of it, byte-identical to the literal it replaced
 * (`__tests__/types/credential-shape-registry.test.ts` pins every entry against
 * a hand-written expectation). Keeping separate hand-maintained lists meant a
 * token could be "vendor-known" to one gate and anonymous to another, which is
 * how `hf_`, `ghs_`, `ghu_`, `glpat-` and `npm_` ended up subject to the
 * entropy fallback in one code path and exempt in the next.
 *
 * Order is registry order and it is load-bearing: `sk-ant-api…` and `sk-proj-…`
 * must be tested before the generic `sk-…`, or a project key is reported under
 * the legacy label.
 *
 * The JWT is deliberately NOT here — it is the one shape whose segments are
 * unbounded, and expressing it as a regex alternative is what made every
 * consumer either quadratic or truncating. `findJwtMatch` covers it for all of
 * them; `hasAnchoredVendorCredential`, `hasAnyCredentialCandidate` and
 * `findCredentialFormatMatch` each call both.
 *
 * Alternatives are NOT anchored here. See `anchoredVendorAlternation` for who
 * anchors and who deliberately does not.
 */
export const VENDOR_PREFIX_ALTERNATIVES = shapesFor('vendor-alternation').map(shapeAlternation);

/**
 * Key names that mark a value as a credential when the value itself has no
 * recognisable shape.
 *
 * The union of the four vocabularies that encode this list today, each of which
 * was read to build it:
 *
 *   - `scanner/detect.ts:496`               api[_-]?key, secret, token, password
 *   - `scanner/permission-vocabulary.ts:415` + apikey, passwd, pwd, authorization
 *   - `nanomind-core/security/defense-in-depth.ts:270` password, secret, token, key
 *   - `semantic/structural/credential-context.ts:29` the 20-name list
 *
 * WARNING FOR THE ADOPTION STEP: this union is WIDER than three of the four
 * consumers, and `key` alone (from defense-in-depth) is the widest member of
 * all. Adopting this list at a narrow site widens what that site reports, which
 * is a detection change and not a refactor. `keyNamesFor` records which sites
 * carry which name so that widening is a measured decision rather than a
 * side effect.
 */
export const CREDENTIAL_KEY_NAMES: readonly string[] = [
  'api_key',
  'apikey',
  'secret',
  'token',
  'password',
  'passwd',
  'pwd',
  'authorization',
  'auth',
  'credential',
  'key',
  'access_key',
  'private_key',
  'client_secret',
  'signing_key',
  'encryption_key',
  'master_key',
  'jwt_secret',
  'session_secret',
  'db_password',
  'database_password',
];

/**
 * The separator between a credential key name and its value, in one place.
 *
 * `\s*` `[:=]` `\s*` `["']?` and NOTHING ELSE. Every optional atom added
 * between the two `\s*` runs makes the pair ambiguous and the match quadratic:
 * a `(?:bearer|basic|token)?` group added here took `detect` from 0.25s to 51s
 * on a 200 KB config, reachable through `secure`, which has no size cap in
 * front of it. An opaque bearer token is a KNOWN GAP, not something to close by
 * stepping over the scheme word.
 *
 * Returns a fresh RegExp each call: a shared `g`-flagged instance carries
 * `lastIndex` between callers.
 */
export function keyNameDelimiterPattern(): RegExp {
  return /\s*[:=]\s*["']?/;
}

/**
 * Left anchor for a vendor prefix: the prefix must not be glued to the tail of
 * an alphanumeric identifier.
 *
 * NOT `\b`. `\b` counts `_` as a word character, and the whole point of this
 * unit is that documents are full of underscore filler — `'_'x38 +
 * 'sk-ant-api03-<real key>'` has no word boundary before `sk`, so `\b` silently
 * dropped a real credential glued to a form blank. `origin/main` uses `\b` here
 * and has that bug; `(?<![A-Za-z0-9])` matches everywhere `\b` does and also
 * after filler, so it is strictly wider than main.
 */
const VENDOR_PREFIX_LEFT_ANCHOR = '(?<![A-Za-z0-9])';

/** The vendor alternation, unanchored. */
export function vendorAlternation(): string {
  return `(?:${VENDOR_PREFIX_ALTERNATIVES.join('|')})`;
}

/**
 * The vendor alternation with its left anchor.
 *
 * ANCHORING IS CHOSEN BY GATE POLARITY, NOT APPLIED UNIFORMLY, and the choice
 * has been wrong in both directions on this branch:
 *
 *   - In a NEGATED gate (`!predicate(content)`), narrowing the predicate makes
 *     the suppression carve-out fire MORE often, so every value the anchor
 *     rejects becomes a place to hide a secret. Those callers take
 *     `vendorAlternation()` and stay deliberately trigger-happy.
 *
 *   - In the primary DETECTION path, anchoring is a pure narrowing with no
 *     remaining benefit: it dropped `tokenghp_…`, `v1AKIA…` and
 *     `prefixsk-ant-…`, all of which `origin/main` detects, while the false
 *     positives it was added for (`MSG.…`) are removed by the SendGrid fixed
 *     lengths above. So detection uses `vendorAlternation()` and matches main.
 *
 * What is left is `hasAnchoredVendorCredential`, the one gate `origin/main`
 * anchors: a POSITIVE gate whose result BLOCKS suppression.
 */
export function anchoredVendorAlternation(): string {
  return `${VENDOR_PREFIX_LEFT_ANCHOR}${vendorAlternation()}`;
}

/**
 * Per-vendor "recognisable prefix" matchers, derived from the alternatives.
 *
 * Derived, never hand-written. A hand-maintained copy of this list lived in
 * `maskCredentialValue` and had fallen five entries behind (`SG.`, `hf_`,
 * `glpat-`, `npm_`, `ghu_`), so those tokens took the "unknown shape" masking
 * branch, which exposes the first 8 characters. For `hf_…` that is 5
 * characters of live secret body printed into a finding's `evidence` — the one
 * thing the masking layer exists to prevent. Deriving the list means a new
 * vendor prefix cannot become detectable without also becoming maskable.
 *
 * The head is taken up to (not including) the first QUANTIFIED atom, which is
 * where the secret body begins. Unquantified single-character classes are kept,
 * so `xox[abprs]-` preserves the full `xoxb-` rather than a bare `xox` — the
 * evidence line has to stay recognisable as a Slack BOT token to be useful.
 */
const VENDOR_PREFIX_MATCHERS: readonly RegExp[] = [
  ...VENDOR_PREFIX_ALTERNATIVES.map(alt => {
    const isQuantifier = (c: string | undefined) => c === '{' || c === '+' || c === '*' || c === '?';
    let head = '';
    let i = 0;
    while (i < alt.length) {
      const ch = alt[i];
      if (ch === '\\') {
        // An escaped metacharacter is a literal. Keep the escape as written.
        if (i + 1 >= alt.length || isQuantifier(alt[i + 2])) break;
        head += alt.slice(i, i + 2);
        i += 2;
        continue;
      }
      if (ch === '[') {
        const close = alt.indexOf(']', i + 1);
        if (close === -1 || isQuantifier(alt[close + 1])) break;
        head += alt.slice(i, close + 1);
        i = close + 1;
        continue;
      }
      if ('(){}+*?|^$.'.includes(ch)) break;
      if (isQuantifier(alt[i + 1])) break;
      head += ch.replace(/[-]/, '\\$&');
      i++;
    }
    return new RegExp(`^${head}`);
  }),
  // The JWT is detected by scan rather than by an alternative, so its prefix
  // has to be added here explicitly. Leaving it out would send every detected
  // JWT down the unknown-shape masking branch, which prints the first 8
  // characters — 5 bytes of live header past `eyJ`.
  new RegExp(`^${JWT_PREFIX}`),
];

/**
 * The longest recognisable vendor prefix of `value`, or undefined when the
 * value matches no vendor shape. Longest wins, so `sk-ant-api0` beats `sk-`.
 */
export function matchVendorPrefix(value: string): string | undefined {
  let longest: string | undefined;
  for (const re of VENDOR_PREFIX_MATCHERS) {
    const m = re.exec(value);
    if (m && m[0].length > (longest?.length ?? 0)) longest = m[0];
  }
  return longest;
}

/* ------------------------------------------------------------------ *
 * JWT: a linear scan, not a regex alternative
 * ------------------------------------------------------------------ */

const CHAR_DOT = 46;
const CHAR_e = 101;
const CHAR_y = 121;
const CHAR_J = 74;

/** `[A-Za-z0-9_-]`, the base64url alphabet a JWT segment is drawn from. */
function isBase64UrlCode(c: number): boolean {
  return (
    (c >= 48 && c <= 57) || // 0-9
    (c >= 65 && c <= 90) || // A-Z
    (c >= 97 && c <= 122) || // a-z
    c === 45 || // -
    c === 95 // _
  );
}

/** `[A-Za-z0-9]`, the class the vendor left anchor forbids. */
function isAlphanumericCode(c: number): boolean {
  return (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
}

/**
 * The leftmost `eyJ<header>.<payload>.<signature>` in `text`, with UNBOUNDED
 * segments — identical in what it accepts to `origin/main`'s
 * `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`, and linear rather than
 * quadratic in what it costs.
 *
 * Why this is not a regex. The segment class contains `-`, so on adversarial
 * filler (`eyJ-eyJ-eyJ-…`) the greedy run reaches end-of-file and the engine
 * then walks back looking for a `.` that is not there — at every one of the
 * O(n) `eyJ` offsets. Measured: 13.5 s at 256 KB, ~215 s extrapolated at the
 * 1 MB scanner cap.
 *
 * The previous fix bounded the header at 256 characters, and that bound leaked
 * into `VENDOR_PREFIX_CONTENT_RE` — the single gate that LIFTS the corpus and
 * integrity-manifest carve-outs. A DPoP proof (550-character header carrying an
 * embedded JWK) or an `x5c` certificate-chain header stopped matching, so a
 * live token planted in a corpus path was fully suppressed, `AST-CRED-002`
 * CRITICAL included. Truncation is not available to this predicate. Linearity
 * is.
 *
 * The scan walks maximal base64url runs. Everything after the header's
 * terminating `.` is a property of the RUN, not of the `eyJ` inside it, so the
 * payload and signature are resolved once per run rather than once per `eyJ` —
 * that is what removes the quadratic without removing any input.
 */
export function findJwtMatch(
  text: string,
  anchored: boolean,
): { value: string; index: number } | undefined {
  const n = text.length;
  let i = 0;
  while (i < n) {
    if (!isBase64UrlCode(text.charCodeAt(i))) {
      i++;
      continue;
    }
    // [i, runEnd) is a maximal base64url run — a candidate header segment.
    let runEnd = i;
    while (runEnd < n && isBase64UrlCode(text.charCodeAt(runEnd))) runEnd++;

    if (runEnd < n && text.charCodeAt(runEnd) === CHAR_DOT) {
      let payloadEnd = runEnd + 1;
      while (payloadEnd < n && isBase64UrlCode(text.charCodeAt(payloadEnd))) payloadEnd++;
      if (payloadEnd > runEnd + 1 && payloadEnd < n && text.charCodeAt(payloadEnd) === CHAR_DOT) {
        let signatureEnd = payloadEnd + 1;
        while (signatureEnd < n && isBase64UrlCode(text.charCodeAt(signatureEnd))) signatureEnd++;
        if (signatureEnd > payloadEnd + 1) {
          // Leftmost `eyJ` in this run that still leaves a non-empty header
          // segment. Each is checked against the anchor separately: `_` and `-`
          // are base64url characters but not alphanumeric, so an `eyJ` in the
          // middle of a run can clear an anchor that the run's first one fails.
          for (let p = i; p + JWT_PREFIX.length < runEnd; p++) {
            if (
              text.charCodeAt(p) !== CHAR_e ||
              text.charCodeAt(p + 1) !== CHAR_y ||
              text.charCodeAt(p + 2) !== CHAR_J
            ) {
              continue;
            }
            if (anchored && p > 0 && isAlphanumericCode(text.charCodeAt(p - 1))) continue;
            return { value: text.slice(p, signatureEnd), index: p };
          }
        }
      }
    }
    i = runEnd;
  }
  return undefined;
}

/* ------------------------------------------------------------------ *
 * The high-entropy fallback
 * ------------------------------------------------------------------ */

/** High-entropy fallback: 40+ word characters, word-boundary anchored. */
const ENTROPY_BLOB_ALTERNATIVE = '\\b[A-Za-z0-9+=_]{40,}\\b';

/**
 * Width of the window the filler rules judge. Also the fallback's own length
 * floor, so a window is exactly the smallest run that could be a credential.
 */
const CREDENTIAL_WINDOW_CHARS = 40;

/**
 * The sliding walk's own counters, separate from `SPAN_CHAR_COUNTS` above and
 * hoisted so a file of many blob runs does not allocate per run.
 *
 * `WINDOW_COUNT_BUCKETS[c]` is how many distinct characters occur exactly `c`
 * times in the current window; it is what makes the running maximum O(1) to
 * maintain, since a maximum can only fall when the last character holding it
 * leaves. Both are reset at the top of every walk, so no state survives a call.
 */
const WINDOW_CHAR_COUNTS = new Uint32Array(128);
const WINDOW_COUNT_BUCKETS = new Uint32Array(CREDENTIAL_WINDOW_CHARS + 2);

/**
 * Longest period treated as filler, and the number of times that unit must
 * repeat before the run is called filler rather than a short coincidence.
 *
 * Four covers every observed false positive (`_`, `_=`, `01`, `de`, `a1`) while
 * three full repetitions keeps the rule off short values, where a small period
 * arises by chance: `abcdabcd` is 8 characters with period 4 but only two
 * repeats, so it is NOT filler.
 */
const MAX_FILLER_PERIOD = 4;
const MIN_FILLER_REPEATS = 3;

/**
 * Share of the span a single character may occupy before the span is filler.
 *
 * A form blank with one stray mark (`'_'x46 + '1'`) is aperiodic, so the period
 * rule alone does not reach it. At 40 characters a genuine secret cannot be 90%
 * one symbol: even a base-4 secret sits near 25% per symbol, and the
 * probability of a random 40-character draw reaching 90% is negligible.
 */
const MAX_DOMINANT_CHAR_SHARE = 0.9;

/**
 * True when `[start, start+len)` is some unit of at most `MAX_FILLER_PERIOD`
 * characters repeated at least `MIN_FILLER_REPEATS` times.
 *
 * Tests each period directly instead of computing the minimal period, which is
 * the same predicate (a span with minimal period m <= 4 and length >= 3m is
 * exactly a span with SOME period p <= 4 and length >= 3p) without the
 * per-window array allocation that made a sliding judgement unaffordable.
 */
function hasFillerPeriod(s: string, start: number, len: number): boolean {
  for (let p = 1; p <= MAX_FILLER_PERIOD; p++) {
    if (len < p * MIN_FILLER_REPEATS) break;
    let periodic = true;
    for (let i = p; i < len; i++) {
      if (s.charCodeAt(start + i) !== s.charCodeAt(start + i - p)) {
        periodic = false;
        break;
      }
    }
    if (periodic) return true;
  }
  return false;
}

/**
 * Reused across calls; the blob class is ASCII, so 128 slots always suffice.
 *
 * DELIBERATELY NOT SHARED with the sliding walk's counter below. This one is
 * filled from scratch on every call, and the walk maintains its own
 * incrementally ACROSS iterations while calling into this function — so a
 * single shared buffer would have the callee zero and rebuild the caller's live
 * state mid-walk. That happens to be harmless today, because the two always
 * count the same span, but it is a trap set for the next edit: the moment the
 * spans differ the walk silently corrupts and starts skipping windows, which is
 * a detection loss with no visible symptom. Two buffers, no coupling.
 */
const SPAN_CHAR_COUNTS = new Uint32Array(128);

/** True when one character occupies more than 90% of `[start, start+len)`. */
function isDominatedBySingleChar(s: string, start: number, len: number): boolean {
  SPAN_CHAR_COUNTS.fill(0);
  let max = 0;
  for (let i = 0; i < len; i++) {
    const next = ++SPAN_CHAR_COUNTS[s.charCodeAt(start + i)];
    if (next > max) max = next;
  }
  return max > len * MAX_DOMINANT_CHAR_SHARE;
}

/**
 * True when `[start, start+len)` could carry entropy at all.
 *
 * Two rules, both aimed at the same class: text used as visual filler.
 *
 *   1. The span is a short unit repeated at least three times
 *      (`'_'x47`, `'_='x25`, `'01'x20`, `'de'x24`, `'a1'x24`).
 *   2. One character occupies more than 90% of the span (`'_'x46 + '1'`).
 *
 * Two weaker rules were tried first and rejected, both by adversarial review:
 *
 *   - A floor of 5 DISTINCT characters. Distinct-character count is not an
 *     entropy measure: four symbols carry two bits each, so a 64-character
 *     base-4 blob holds 128 bits and would have been discarded. It silenced a
 *     planted `AST-CRED-002` CRITICAL whose only unusual property was a
 *     four-letter alphabet, and dropped real `hf_`, `ghs_` and `npm_` tokens
 *     with repetitive bodies.
 *   - "Not a single repeated character" (distinct >= 2). One character from
 *     failing: `'_'x46 + '1'` and `'_='x25` both still read as credentials.
 *
 * The rules above admit a genuine low-alphabet secret — random base-4 text has
 * no short period and no dominant symbol — which is the property the distinct-
 * character floor could not express.
 */
function isCredibleSpan(s: string, start: number, len: number): boolean {
  if (len === 0) return false;
  if (hasFillerPeriod(s, start, len)) return false;
  return !isDominatedBySingleChar(s, start, len);
}

/** `isCredibleSpan` over a whole value. */
export function isCredibleEntropyBlob(value: string): boolean {
  return isCredibleSpan(value, 0, value.length);
}

/**
 * Offset of the leftmost 40-character window of `run` that could carry entropy,
 * or undefined when no window can.
 *
 * WHY A WINDOW AND NOT THE WHOLE RUN. The fallback is greedy over a class
 * containing `_`, so filler glued to a secret is absorbed into one candidate:
 * `'_'x361 + <40-char secret>` is a single 401-character run in which the
 * underscores are 90.02% of the total, just over the dominance threshold. The
 * run was rejected whole, and the secret with it. `'_'x300` happened to sit
 * under the threshold, which is the only reason the defect looked fixed — and
 * the one test covering the shape used `'_'x400 + '=' + secret`, tuned to the
 * single variant that survived, because `=` is a non-word character and so gave
 * the walk an interior `\b` to restart from. Delete the `=` and it failed.
 *
 * Judging a window instead removes the whole family: a secret is credible in
 * its own right no matter how much filler is glued to it, and no interior word
 * boundary is needed to find it. It also removes the two mechanisms that were
 * added to compensate — the "resume one character past a rejected candidate"
 * walk and the character budget that had to bound it — because each run is now
 * examined exactly once. That budget was itself a CRITICAL detection hole: 12 KB
 * of `('a'x40 + '=')` padding ahead of an anonymous secret exhausted it and the
 * score went UP.
 *
 * Cost is O(40n) worst case and linear in practice: the whole-run periodicity
 * check below disposes of uniform filler in one pass, and the dominance rule is
 * maintained incrementally, so the expensive full predicate runs only on
 * windows that are not already dominated.
 */
function findCredibleWindowOffset(run: string): number | undefined {
  const w = CREDENTIAL_WINDOW_CHARS;
  const n = run.length;
  if (n < w) return isCredibleSpan(run, 0, n) ? 0 : undefined;

  // If the run itself is a repeated short unit then so is every window of it —
  // period is inherited by substrings — so a megabyte of `'_'` or `'ab'` filler
  // costs one linear pass instead of n window judgements.
  if (hasFillerPeriod(run, 0, n)) return undefined;

  // Sliding dominance count. `bucket[c]` is how many distinct characters occur
  // exactly c times in the window, which keeps the running max O(1) per step:
  // a max can only fall when the last character holding it leaves.
  WINDOW_CHAR_COUNTS.fill(0);
  WINDOW_COUNT_BUCKETS.fill(0);
  let max = 0;
  for (let i = 0; i < w; i++) {
    const code = run.charCodeAt(i);
    const before = WINDOW_CHAR_COUNTS[code]++;
    if (before > 0) WINDOW_COUNT_BUCKETS[before]--;
    WINDOW_COUNT_BUCKETS[before + 1]++;
    if (before + 1 > max) max = before + 1;
  }

  const dominanceLimit = w * MAX_DOMINANT_CHAR_SHARE;
  for (let k = 0; ; k++) {
    // The incremental counter is an ACCELERATOR for `isCredibleSpan`, never a
    // second opinion: `max <= dominanceLimit` is exactly the negation of the
    // dominance rule, so skipping on it can only skip windows the full
    // predicate would reject anyway. `credential-format.test.ts` cross-checks
    // the two over randomised runs.
    if (max <= dominanceLimit && isCredibleSpan(run, k, w)) return k;
    if (k + w >= n) return undefined;

    const leaving = run.charCodeAt(k);
    const had = WINDOW_CHAR_COUNTS[leaving]--;
    WINDOW_COUNT_BUCKETS[had]--;
    WINDOW_COUNT_BUCKETS[had - 1]++;
    if (had === max && WINDOW_COUNT_BUCKETS[had] === 0) max = had - 1;

    const entering = run.charCodeAt(k + w);
    const has = WINDOW_CHAR_COUNTS[entering]++;
    if (has > 0) WINDOW_COUNT_BUCKETS[has]--;
    WINDOW_COUNT_BUCKETS[has + 1]++;
    if (has + 1 > max) max = has + 1;
  }
}

/* ------------------------------------------------------------------ *
 * Entry points
 * ------------------------------------------------------------------ */

/** Leftmost wins; on a tie the vendor match wins, as in `origin/main`. */
function leftmost(
  a: { value: string; index: number } | undefined,
  b: { value: string; index: number } | undefined,
): { value: string; index: number } | undefined {
  if (!a) return b;
  if (!b) return a;
  return b.index < a.index ? b : a;
}

/**
 * Find the first credential-format substring in `text`.
 *
 * Vendor prefixes and the JWT are matched over the whole input, unanchored and
 * unbounded, exactly as `origin/main` matches them. The high-entropy fallback
 * then walks maximal blob runs, judging each by sliding window.
 *
 * The reported value starts at the leftmost credible WINDOW and runs to the end
 * of its blob run. Starting at the run start would report the filler that
 * swallowed the secret; stopping at the window's own 40th character would cut a
 * longer secret in half. The index is the window's, so the derived line number
 * points at the secret rather than at the form blank preceding it.
 */
export function findCredentialFormatMatch(
  text: string,
): { value: string; index: number } | undefined {
  const vendorRe = new RegExp(vendorAlternation(), 'g');
  const vm = vendorRe.exec(text);
  let best = leftmost(
    vm ? { value: vm[0], index: vm.index } : undefined,
    findJwtMatch(text, false),
  );

  const blobRe = new RegExp(ENTROPY_BLOB_ALTERNATIVE, 'g');
  let m: RegExpExecArray | null;
  while ((m = blobRe.exec(text)) !== null) {
    // Runs are disjoint and left to right, so nothing from here on can be
    // leftmost.
    if (best && m.index >= best.index) break;
    const offset = findCredibleWindowOffset(m[0]);
    if (offset !== undefined) {
      const index = m.index + offset;
      if (!best || index < best.index) best = { value: m[0].slice(offset), index };
      break;
    }
  }
  return best;
}

/** True when `text` contains at least one accepted credential-format value. */
export function hasCredentialFormat(text: string): boolean {
  return findCredentialFormatMatch(text) !== undefined;
}

/**
 * The candidate matcher for NEGATED gates: same alternation, vendor prefixes
 * left UNANCHORED on purpose, entropy floor NOT applied.
 */
const CANDIDATE_RE_FOR_NEGATED_GATE = new RegExp(
  `${vendorAlternation()}|${ENTROPY_BLOB_ALTERNATIVE}`,
);

/**
 * True when `text` contains any credential-format CANDIDATE, entropy floor NOT
 * applied.
 *
 * This exists for the suppression vetoes (the taxonomy and corpus carve-outs),
 * which ask the opposite question from the detection gates. There the
 * predicate is negated — "suppress only if there is NO credential-shaped value
 * here" — so a stricter predicate makes suppression fire MORE often, and any
 * value the floor discards becomes a place to hide a secret. A taxonomy of
 * category labels has no legitimate reason to carry a 40-character run at all,
 * so the veto is intentionally trigger-happy: any candidate at all blocks the
 * carve-out, and vendor prefixes are matched UNANCHORED here for the same
 * reason.
 *
 * Being trigger-happy is not licence to be wrong about the SHAPE. `SG\.` with
 * open-ended segments made this predicate fire on
 * `MSG.INCIDENT_ESCALATION_QUEUE.HIGH_PRIORITY_ROUTE`, which blocked the
 * taxonomy carve-out and raised a CRITICAL on a benign document — a false
 * positive the anchor could not reach precisely because this gate must stay
 * unanchored. The fix belongs in the pattern, not the anchoring.
 */
export function hasAnyCredentialCandidate(text: string): boolean {
  return CANDIDATE_RE_FOR_NEGATED_GATE.test(text) || findJwtMatch(text, false) !== undefined;
}

/** Module-level and deliberately without `g`, so `.test()` carries no state. */
const ANCHORED_VENDOR_RE = new RegExp(anchoredVendorAlternation());

/**
 * True when `text` carries a positively-identified vendor credential.
 *
 * This is the gate that LIFTS the corpus and integrity-manifest suppression, so
 * every narrowing of it suppresses MORE — the same trap as a negated gate, one
 * gate over, and the one a bounded JWT header fell into. It must see exactly
 * what `origin/main` sees, at minimum.
 */
export function hasAnchoredVendorCredential(text: string): boolean {
  return ANCHORED_VENDOR_RE.test(text) || findJwtMatch(text, true) !== undefined;
}

/* ------------------------------------------------------------------ *
 * Form blanks in KEY-NAMED config values
 * ------------------------------------------------------------------ */

/**
 * Characters a document uses to DRAW rather than to encode: form blanks, dot
 * leaders, rules, redaction bars.
 */
const FILLER_CHARS = new Set(['_', '-', '.', '*', '#', '~', '?', '=', ' ', '\t']);

/**
 * Length at which a consecutive filler run stops being punctuation and becomes
 * something someone DREW.
 *
 * This is the distinction the whole rule turns on, and dropping it is what
 * broke `dev_pass`. Filler characters appear inside real secrets constantly,
 * but as SEPARATORS, one at a time — `dev_pass`, `pass-123`, `api.key1`,
 * `super-secret-jwt-key-2024`, a UUID, `sk-ant-api03-…`. Nobody writes four in
 * a row unless they are drawing a line. So a run this long is subtracted from
 * the value and anything shorter is part of it.
 */
const MIN_DRAWN_RUN_CHARS = 4;

/**
 * Characters a value must carry, once the drawn runs are removed, to be a value.
 *
 * Matches the 8-character floor `looksLikeSecretValue` already applies to the
 * value as a whole, so a secret is judged by the same minimum whether or not
 * someone drew a line next to it.
 */
const MIN_SECRET_CORE_CHARS = 8;

/**
 * True when `value` is visual filler rather than a secret, for values that
 * arrive WITH a key name (`password:`, `api_key =`).
 *
 * Deliberately a different test from `isCredibleEntropyBlob`, because the
 * evidence is different. The entropy blob is an anonymous 40+ character run
 * found anywhere in a document, so structure is all there is to go on and a run
 * of one repeated symbol is filler. Here a key name has already said "this is a
 * secret", so the only question left is whether the VALUE is a drawn blank —
 * and the structural rules are far too blunt for that at 8 characters. They
 * dropped `Ab12Ab12Ab12…` (period 4) and the base64 of an all-zero AES key
 * (`'A'x43`), both of which are weak but entirely real secrets that a scanner
 * exists to find.
 *
 * Keying on the filler CHARACTERS instead separates the classes exactly: `_`,
 * `-` and `.` draw blanks and never carry key material in bulk, while `A` and
 * `1` do.
 *
 * `minCore` is how much value must survive the drawn runs. It defaults to the
 * caller's own 8-character floor, but a caller that applies NO length floor of
 * its own must pass a smaller one — otherwise this function silently becomes a
 * length gate for it. SEM-CRED-004 hit exactly that: routed through the
 * 8-character default it stopped reporting `supersecretpassword` and
 * `hunt3r`, real MCP env secrets that `origin/main` reported, and the score
 * rose. A gate added to suppress drawn blanks must suppress drawn blanks and
 * nothing else.
 */
export function isVisualFiller(value: string, minCore = MIN_SECRET_CORE_CHARS): boolean {
  if (value.length === 0) return true;
  // A redaction bar. `x` is not a filler character in general — it appears in
  // real base64 — but a value that is nothing else is a mask, not a key.
  if (/^x+$/i.test(value)) return true;
  // Subtract what was DRAWN — the long runs — and apply the same 8-character
  // floor the caller applies to the whole value. Separators survive, because
  // they are part of the value.
  //
  // THREE rules were tried here before this one, each failing in its own
  // direction. They are recorded because the shape of the mistake repeated:
  //
  //   - The filler SHARE of the whole value. The same whole-value judgement
  //     `findCredibleWindowOffset` exists to avoid, and it failed at the
  //     identical threshold: `'_'x361 + <40-char secret>` is 90.02%
  //     underscores, so it was called a blank and the secret dropped, while
  //     `'_'x360 + secret` was reported. A dashed trailing comment did it too,
  //     since the YAML/env value is the rest of the line. Any rule whose
  //     verdict moves with how MUCH filler is present has this bug.
  //   - The longest contiguous non-filler STRETCH. Reads every separator as a
  //     boundary, so `super-secret-jwt-key-2024` — longest stretch `secret`,
  //     six characters — stopped being a secret.
  //   - Counting non-filler characters with no notion of a run. Strictly
  //     stricter than the caller's length floor rather than equal to it, so
  //     every 8-character password carrying ONE separator went silent:
  //     `dev_pass`, `prod_key`, `pass-123`, `api.key1`, `pw#12345`. The score
  //     rose 27 points on a lost CRITICAL.
  //
  // The RUN length is what separates a drawn blank from punctuation, so it is
  // the thing to measure. Pinned in both directions: `dev_pass` (8 characters,
  // one separator, a secret) and `'_'x47` (a blank).
  let core = 0;
  let run = 0;
  for (const ch of value) {
    if (FILLER_CHARS.has(ch)) {
      run++;
      continue;
    }
    if (run > 0 && run < MIN_DRAWN_RUN_CHARS) core += run; // punctuation, kept
    run = 0;
    if (++core >= minCore) return false;
  }
  return true
}

/**
 * HMA-15 — shared harness for the credential-byte render property test.
 *
 * The property (HMA-15.AC3): plant runtime-minted synthetic values in a
 * fixture of EVERY analyzed ArtifactType, run BOTH user-facing commands over
 * each fixture tree in EVERY reachable output format, and assert that no byte
 * surface of any cell — stdout, an `-o` output file, or any string leaf of
 * the emitted JSON — holds a contiguous run of ANY planted value longer than
 * that cell's MEASURED noise floor (HMA-15.AC4).
 *
 * Every fixture plants TWO values (HMA-15.AC5 r2):
 *
 *   - a COVERED control — a shape the report redaction boundary removes
 *     (name-gated quoted, the AWS-shape assignment, or a vendor prefix). It
 *     stays so a future fix cannot delete the boundary unnoticed.
 *   - an UNCOVERED value — a form the boundary does NOT remove, proven in
 *     the same run by calling `redactSecretsForReport` on the planted line
 *     and asserting it comes back UNCHANGED (the property test performs that
 *     call; this module stays src-free). The r1 matrix planted only covered
 *     shapes and passed 73/73 on a build rendering a complete credential —
 *     a vocabulary, unlike a predicate, rots silently.
 *
 * The uncovered axis is the QUOTING of the value and the JSON-quoted
 * identifier form, not the identifier vocabulary: a quoted value after any
 * `password`/`secret`/`token`/`key` identifier IS covered (the name-gated
 * rule has no left word boundary), so the uncovered forms are the JWT, the
 * anonymous high-entropy blob, JSON-quoted `"token": "<value>"`, unquoted
 * YAML `token: <value>`, and unquoted env `TOKEN=<value>` — all five present
 * across the matrix, at least one per fixture.
 *
 * Two ordered gates per cell (HMA-15.AC5): the cell must DETECT (produce at
 * least one credential-class finding) before non-render is asserted, and an
 * unreached cell FAILS the run naming itself — a value the detector cannot
 * see must never stand in for a value the redactor removed. That vacuous
 * green is how this class survived the v0.25.2 and v0.32.0 patches.
 *
 * PRODUCER-AGNOSTIC (HMA-15.AC6): this module imports NOTHING from `src/` —
 * node builtins only. It names no producer function, no analyzer, no check
 * id. The tool is reached exclusively through the built CLI, and the render
 * assertion walks every string leaf of whatever JSON comes back rather than
 * a named field list. (The one src import the property TEST makes is the
 * report boundary itself, because AC5 r2 mandates proving the uncovered
 * predicate against it in the same run — it is the boundary under test, not
 * a producer.)
 *
 * VALUE HYGIENE (HMA-15.AC7). Every planted value is minted at run time with
 * `crypto.randomInt`; fixtures are written to an OS temp directory, never the
 * repository; and no code path in this file ever puts value bytes into an
 * error message, a failure string, or a log — failures name the cell, the
 * field or JSON path, the planted KIND, and observed run LENGTHS only.
 */

import { randomInt } from 'node:crypto';
import { createHash } from 'node:crypto';
import {
  mkdtempSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// ============================================================================
// The matrix axes
// ============================================================================

/** Every value `classifyArtifactType` can return, one fixture per row. */
export const CELL_ARTIFACT_TYPES = [
  'source_code',
  'skill',
  'mcp_config',
  'soul',
  'system_prompt',
  'agent_config',
  'a2a_card',
  'env_file',
  'credential_file',
  'unknown',
] as const;
export type CellArtifactType = (typeof CELL_ARTIFACT_TYPES)[number];

/**
 * `secure`'s five reachable formats on a plain directory with no `-b`
 * (`asp` needs `-b oasb-1`; `asff` is refused WITH a `-b`), and `check`'s
 * two (default text, `--json` — it has no `-f/--format` option at all).
 */
export const SECURE_FORMATS = ['text', 'json', 'sarif', 'html', 'asff'] as const;
export const CHECK_FORMATS = ['text', 'json'] as const;

export interface CellSpec {
  /** `<artifactType>/<command>/<format>` — the name every failure carries. */
  cell: string;
  artifactType: CellArtifactType;
  command: 'secure' | 'check';
  format: string;
  /** Whether this cell's primary output parses as one JSON document. */
  jsonOutput: boolean;
}

/** The full 10 × (5 + 2) = 70-cell matrix. */
export function allCellSpecs(): CellSpec[] {
  const specs: CellSpec[] = [];
  for (const artifactType of CELL_ARTIFACT_TYPES) {
    for (const format of SECURE_FORMATS) {
      specs.push({
        cell: `${artifactType}/secure/${format}`,
        artifactType,
        command: 'secure',
        format,
        jsonOutput: format === 'json' || format === 'sarif' || format === 'asff',
      });
    }
    for (const format of CHECK_FORMATS) {
      specs.push({
        cell: `${artifactType}/check/${format}`,
        artifactType,
        command: 'check',
        format,
        jsonOutput: format === 'json',
      });
    }
  }
  return specs;
}

// ============================================================================
// Value minting (HMA-15.AC5 / AC7 — construction is PINNED)
// ============================================================================

const VALUE_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const BASE64URL_ALPHABET = VALUE_ALPHABET + '-_';

/**
 * Substrings a minted value must never contain.
 *
 * The detector suppresses values whose own bytes carry placeholder markers,
 * so a value that randomly spelled one would make its cell UNREACHABLE for a
 * reason the harness would misreport; and the harness's detection predicate
 * for unstructured formats keys on the tool's own credential-class vocabulary
 * (`/cred/i`), so no fixture byte — planted value included — may spell it.
 */
const FORBIDDEN_IN_VALUE = /FAKE|EXAMPLE|PLACEHOLDER|DUMMY|REPLACE|INSERT|TEST|SAMPLE|XXX|CRED/i;

/**
 * Exactly 40 characters, alphanumeric, minted with `crypto.randomInt`.
 *
 * The length is load-bearing and pinned, not left to chance (HMA-15.AC5,
 * contract §7): the name-gated detector matches exactly 40 value characters
 * and REFUSES a longer run outright (its trailing lookahead fails the whole
 * match), so a 41+-character plant would be detected by nothing, emitted by
 * nothing, and would turn every non-render assertion vacuously green — the
 * exact failure mode that let this class survive two patches. 40 is also the
 * anonymous-blob detector's floor, so the same length serves the uncovered
 * blob forms. Alphanumeric only, so the value survives JSON/YAML/HTML
 * encoding byte-identically and a contiguous-run measurement means what it
 * says.
 */
export function mintSyntheticValue(): string {
  for (;;) {
    let v = '';
    for (let i = 0; i < 40; i++) v += VALUE_ALPHABET[randomInt(VALUE_ALPHABET.length)];
    if (FORBIDDEN_IN_VALUE.test(v)) continue;
    // The detector rejects low-entropy sentinels (<= 6 distinct characters).
    if (new Set(v).size <= 6) continue;
    if (v.length !== 40) throw new Error('minted value has drifted from the pinned 40-char construction');
    return v;
  }
}

/**
 * A JWT-shaped value: `eyJ` + three base64url segments, 67 characters total,
 * minted with `crypto.randomInt`. The shape the JWT scan accepts (three
 * non-empty dot-joined base64url runs opening `eyJ`), and one of the two
 * shapes the report boundary's own table documents as deliberately absent —
 * which is exactly why it is planted (HMA-15.AC5 r2).
 */
export function mintJwtValue(): string {
  const seg = (n: number): string => {
    let s = '';
    for (let i = 0; i < n; i++) s += BASE64URL_ALPHABET[randomInt(BASE64URL_ALPHABET.length)];
    return s;
  };
  for (;;) {
    const v = `eyJ${seg(17)}.${seg(24)}.${seg(21)}`;
    if (FORBIDDEN_IN_VALUE.test(v)) continue;
    if (v.length !== 67) throw new Error('minted JWT has drifted from the pinned construction');
    return v;
  }
}

// ============================================================================
// Fixtures — one per ArtifactType, written to an OS temp dir, never the repo
// ============================================================================

export type PlantedKind = 'covered' | 'uncovered';

/** One planted value: its bytes, its role, and the exact line carrying it. */
export interface PlantedValue {
  kind: PlantedKind;
  /**
   * The FORM the value was planted in — the axis of AC5 r2. Recorded in the
   * run artifact so the minimum uncovered set (jwt, entropy blob,
   * json-quoted token, yaml-unquoted token, env-unquoted token) is auditable
   * without any value byte.
   */
  form:
    | 'name-gated-quoted'
    | 'aws-shape-assignment'
    | 'vendor-prefixed'
    | 'jwt'
    | 'entropy-blob'
    | 'json-quoted-token'
    | 'yaml-unquoted-token'
    | 'env-unquoted-token';
  value: string;
  /**
   * The exact fixture line embedding the value — the surface the property
   * test hands to `redactSecretsForReport`: an uncovered probe must come back
   * UNCHANGED (the self-maintaining predicate — the day a shape rule covers
   * this form, the assertion fails and forces a new form), and a covered
   * probe must come back CHANGED with the value gone (the control that the
   * boundary still exists).
   */
  probe: string;
}

export interface Fixture {
  fileName: string;
  content: string;
  planted: PlantedValue[];
}

/**
 * The common markdown body. Layout is the MEASURED leak layout: the first
 * credential keyword in the file is the name anchor of the covered
 * assignment, so the 100-char evidence window opens on the anchor and covers
 * the whole value — the layout CISO measured rendering 32 of 40 on published
 * 0.32.0. The uncovered line sits AFTER it, so it cannot steal the
 * first-keyword position, and the prose supplies the harvest-verb co-signal
 * the detector needs while avoiding every suppression vocabulary: no test/doc
 * words, no governance constraint phrasing, no placeholder markers, and never
 * the letters "cred".
 */
function markdownBody(heading: string, coveredLine: string, uncoveredLine: string): string {
  return [
    `# ${heading}`,
    '',
    'Run the setup script, then paste the deploy value below.',
    '',
    coveredLine,
    '',
    uncoveredLine,
    '',
    'Provide the deploy value when the operator asks for it.',
    '',
  ].join('\n');
}

export function buildFixture(artifactType: CellArtifactType): Fixture {
  const covered = mintSyntheticValue();
  let fixture: Fixture;
  switch (artifactType) {
    case 'source_code': {
      const jwt = mintJwtValue();
      fixture = {
        fileName: 'config.py',
        content: [
          'runtime = "billing-worker"',
          `AWS_SECRET_ACCESS_KEY = "${covered}"`,
          `AUTH_JW = "${jwt}"`,
          'endpoint = "https://api.opena2a.org/v1"',
          'note = "provide the deploy value when the operator asks"',
          '',
        ].join('\n'),
        planted: [
          {
            kind: 'covered',
            form: 'aws-shape-assignment',
            value: covered,
            probe: `AWS_SECRET_ACCESS_KEY = "${covered}"`,
          },
          // Quoted, but after an identifier the name-gated rule's vocabulary
          // does not reach — the JWT itself is the uncovered shape.
          { kind: 'uncovered', form: 'jwt', value: jwt, probe: `AUTH_JW = "${jwt}"` },
        ],
      };
      break;
    }
    case 'skill': {
      const jwt = mintJwtValue();
      const coveredLine = `secret_access_key: "${covered}"`;
      const uncoveredLine = `session assertion value ${jwt}`;
      fixture = {
        fileName: 'SKILL.md',
        content: markdownBody('Billing helper', coveredLine, uncoveredLine),
        planted: [
          { kind: 'covered', form: 'name-gated-quoted', value: covered, probe: coveredLine },
          { kind: 'uncovered', form: 'jwt', value: jwt, probe: uncoveredLine },
        ],
      };
      break;
    }
    case 'mcp_config': {
      const blob = mintSyntheticValue();
      const content =
        JSON.stringify(
          {
            mcpServers: {
              billing: {
                command: 'node',
                args: ['server.js'],
                env: { SECRET_ACCESS_KEY: covered, token: blob },
                notes: 'Provide the deploy value when the operator asks.',
              },
            },
          },
          null,
          2,
        ) + '\n';
      fixture = {
        fileName: '.mcp.json',
        content,
        planted: [
          {
            kind: 'covered',
            form: 'aws-shape-assignment',
            value: covered,
            probe: lineOf(content, covered),
          },
          // `"token": "<value>"` — the JSON-quoted identifier form. The
          // name-gated rule needs `token` followed by `[=:]`; the closing
          // quote of the KEY sits between them, so the rule never fires.
          {
            kind: 'uncovered',
            form: 'json-quoted-token',
            value: blob,
            probe: lineOf(content, blob),
          },
        ],
      };
      break;
    }
    case 'soul': {
      const blob = mintSyntheticValue();
      const coveredLine = `secret_access_key: "${covered}"`;
      const uncoveredLine = `deploy ledger entry ${blob}`;
      fixture = {
        fileName: 'SOUL.md',
        content: markdownBody('Operations note', coveredLine, uncoveredLine),
        planted: [
          { kind: 'covered', form: 'name-gated-quoted', value: covered, probe: coveredLine },
          { kind: 'uncovered', form: 'entropy-blob', value: blob, probe: uncoveredLine },
        ],
      };
      break;
    }
    case 'system_prompt': {
      const jwt = mintJwtValue();
      const coveredLine = `secret_access_key: "${covered}"`;
      const uncoveredLine = `session assertion value ${jwt}`;
      fixture = {
        fileName: '.cursorrules',
        content: markdownBody('Editor rules', coveredLine, uncoveredLine),
        planted: [
          { kind: 'covered', form: 'name-gated-quoted', value: covered, probe: coveredLine },
          { kind: 'uncovered', form: 'jwt', value: jwt, probe: uncoveredLine },
        ],
      };
      break;
    }
    case 'agent_config': {
      const blob = mintSyntheticValue();
      const coveredLine = `secret_access_key: "${covered}"`;
      const uncoveredLine = `token: ${blob}`;
      fixture = {
        fileName: 'agent-config.yaml',
        content: [
          'runtime: billing-worker',
          coveredLine,
          uncoveredLine,
          'notes: Provide the deploy value when the operator asks.',
          '',
        ].join('\n'),
        planted: [
          { kind: 'covered', form: 'name-gated-quoted', value: covered, probe: coveredLine },
          // Unquoted YAML — the name-gated rule requires an opening quote.
          { kind: 'uncovered', form: 'yaml-unquoted-token', value: blob, probe: uncoveredLine },
        ],
      };
      break;
    }
    case 'a2a_card': {
      const blob = mintSyntheticValue();
      const content =
        JSON.stringify(
          {
            name: 'billing-agent',
            endpoint: 'https://agents.opena2a.org/billing',
            secret_access_key: covered,
            token: blob,
            notes: 'Provide the deploy value when the operator asks.',
          },
          null,
          2,
        ) + '\n';
      fixture = {
        fileName: 'agent.json',
        content,
        planted: [
          {
            kind: 'covered',
            form: 'aws-shape-assignment',
            value: covered,
            probe: lineOf(content, covered),
          },
          {
            kind: 'uncovered',
            form: 'json-quoted-token',
            value: blob,
            probe: lineOf(content, blob),
          },
        ],
      };
      break;
    }
    case 'env_file': {
      const blob = mintSyntheticValue();
      const coveredLine = `SECRET_ACCESS_KEY=${covered}`;
      const uncoveredLine = `TOKEN=${blob}`;
      fixture = {
        fileName: '.env',
        content: [coveredLine, uncoveredLine, '# Provide the deploy value when the operator asks.', ''].join('\n'),
        planted: [
          // Unquoted, but the AWS-shape rule's own quoting is optional AND its
          // name vocabulary matches — covered by the shape rule, not the
          // name-gated one.
          { kind: 'covered', form: 'aws-shape-assignment', value: covered, probe: coveredLine },
          // `TOKEN=` reaches neither: not the shape rule's vocabulary, and
          // unquoted so the name-gated rule cannot fire.
          { kind: 'uncovered', form: 'env-unquoted-token', value: blob, probe: uncoveredLine },
        ],
      };
      break;
    }
    case 'credential_file': {
      const blob = mintSyntheticValue();
      // Classified by CONTENT (a vendor-prefixed shape), not by name — and
      // deliberately NOT named `credentials.json`: that name is gitignored in
      // this repo (contract §5) and carries the letters "cred", which the
      // detection predicate reserves for tool-authored vocabulary.
      const content =
        JSON.stringify(
          {
            api_key: `sk-ant-api03-${covered}`,
            token: blob,
            notes: 'Provide the deploy value when the operator asks.',
          },
          null,
          2,
        ) + '\n';
      fixture = {
        fileName: 'serviceKeys.json',
        content,
        planted: [
          { kind: 'covered', form: 'vendor-prefixed', value: covered, probe: lineOf(content, covered) },
          {
            kind: 'uncovered',
            form: 'json-quoted-token',
            value: blob,
            probe: lineOf(content, blob),
          },
        ],
      };
      break;
    }
    case 'unknown': {
      const blob = mintSyntheticValue();
      // The artifact type CISO measured leaking 32 of 40 on published 0.32.0.
      const coveredLine = `secret_access_key: "${covered}"`;
      const uncoveredLine = `deploy ledger entry ${blob}`;
      fixture = {
        fileName: 'AGENTS.md',
        content: markdownBody('Team onboarding', coveredLine, uncoveredLine),
        planted: [
          { kind: 'covered', form: 'name-gated-quoted', value: covered, probe: coveredLine },
          { kind: 'uncovered', form: 'entropy-blob', value: blob, probe: uncoveredLine },
        ],
      };
      break;
    }
  }
  assertFixtureInvariants(artifactType, fixture);
  return fixture;
}

/** The single content line containing `value` — probe surface for a fixture. */
function lineOf(content: string, value: string): string {
  const line = content.split('\n').find((l) => l.includes(value));
  if (line === undefined) throw new Error('planted value not found on any fixture line');
  return line;
}

/**
 * Non-vacuity pins (HMA-15.AC5): a fixture that cannot be detected, or that
 * the walk cannot classify as its row, would silently hollow out its seven
 * cells. Each violated invariant throws — with no fixture bytes in the
 * message beyond the file name, the artifact type, and the planted kind.
 */
function assertFixtureInvariants(artifactType: CellArtifactType, f: Fixture): void {
  const fail = (why: string): never => {
    throw new Error(`fixture ${artifactType}/${f.fileName} invalid: ${why}`);
  };
  const kinds = new Set(f.planted.map((p) => p.kind));
  if (!kinds.has('covered') || !kinds.has('uncovered')) {
    fail('every fixture plants one covered control and at least one uncovered value (AC5 r2)');
  }
  for (const p of f.planted) {
    // Pinned constructions, per form family.
    if (p.form === 'jwt') {
      if (!/^eyJ[A-Za-z0-9_-]{17}\.[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{21}$/.test(p.value)) {
        fail(`${p.kind} jwt value has drifted from the pinned construction`);
      }
    } else if (p.value.length !== 40 || !/^[A-Za-z0-9]{40}$/.test(p.value)) {
      fail(`${p.kind} value is not the pinned 40-character construction`);
    }
    if (!f.content.includes(p.value)) fail(`${p.kind} value is not embedded`);
    if (f.content.indexOf(p.value) !== f.content.lastIndexOf(p.value)) {
      fail(`${p.kind} value embedded twice`);
    }
    if (!p.probe.includes(p.value)) fail(`${p.kind} probe line does not carry its value`);
    if (!f.content.includes(p.probe)) fail(`${p.kind} probe is not a fixture line`);
  }
  const covered = f.planted.find((p) => p.kind === 'covered')!;
  for (const p of f.planted) {
    if (p.kind !== 'covered' && f.content.indexOf(p.value) < f.content.indexOf(covered.value)) {
      fail('an uncovered value precedes the covered anchor — it would steal the first-keyword window');
    }
  }
  // The detection predicate for unstructured formats keys on /cred/i being
  // tool vocabulary; a fixture byte spelling it would forge gate one.
  if (/cred/i.test(f.content)) fail('fixture content spells the reserved detection vocabulary');
  // The compile-path detector needs a harvest co-verb somewhere in the text.
  if (!/ask|request|share|provide/i.test(f.content)) fail('missing harvest co-signal verb');
  // The measured leak layout: the FIRST credential keyword must be the
  // covered assignment's own anchor, close enough that the 100-char evidence
  // window covers the whole value.
  const keywordIdx = f.content.search(/password|credential|api[_-]?key|secret|token/i);
  const valueIdx = f.content.indexOf(covered.value);
  if (keywordIdx < 0) fail('no credential keyword');
  if (keywordIdx > valueIdx) fail('first credential keyword sits after the covered value');
  if (valueIdx - keywordIdx > 55) fail('anchor-to-value distance exceeds the evidence window');
  // No suppression vocabulary anywhere: these words flip the analyzer into
  // doc/test context or placeholder handling and silently unreach the cell.
  if (/\b(test|example|documentation|fixture|demo|placeholder)\b/i.test(f.content)) {
    fail('fixture content carries doc/test suppression vocabulary');
  }
}

/** Write a one-fixture tree under an OS temp dir and return its paths. */
export function writeFixtureTree(artifactType: CellArtifactType): {
  treeDir: string;
  filePath: string;
  fixture: Fixture;
} {
  const fixture = buildFixture(artifactType);
  // Directory name carries no suppression vocabulary ("test", "fixture", …):
  // the analyzers read paths as context.
  const treeDir = mkdtempSync(join(tmpdir(), `hma15-${artifactType.replace(/_/g, '-')}-`));
  const filePath = join(treeDir, fixture.fileName);
  writeFileSync(filePath, fixture.content, 'utf8');
  return { treeDir, filePath, fixture };
}

// ============================================================================
// Contiguous-run measurement
// ============================================================================

/**
 * The longest contiguous run of ANY of `values` that appears in `output`.
 *
 * Binary search over the run length: if some length-L substring of some value
 * appears in the output, then so does some length-(L-1) substring (any window
 * of the L-gram), so existence is monotone in L and the maximum is exactly
 * the largest L for which the joint L-gram set intersects the output. This is
 * equal to `max over v of longestRun(v, output)` — measuring "each value's
 * longest run and taking the maximum" (HMA-15.AC4) in one pass.
 */
export function longestSharedRun(values: readonly string[], output: string): number {
  const maxLen = values.reduce((m, v) => Math.max(m, v.length), 0);
  const runExists = (len: number): boolean => {
    if (len === 0) return true;
    const grams = new Set<string>();
    for (const v of values) {
      for (let i = 0; i + len <= v.length; i++) grams.add(v.slice(i, i + len));
    }
    if (grams.size === 0) return false;
    for (let i = 0; i + len <= output.length; i++) {
      if (grams.has(output.slice(i, i + len))) return true;
    }
    return false;
  };
  let lo = 0;
  let hi = maxLen;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (runExists(mid)) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

/**
 * How many null-control values are drawn PER PLANTED FORM FAMILY
 * (HMA-15.AC4: "at least 200"). This is the DRAW COUNT, not the threshold:
 * the threshold a cell asserts against is always the measured maximum run of
 * these never-planted values in that cell's own output, computed per run and
 * never written as a literal.
 */
export const NULL_CONTROL_DRAWS = 200;

/**
 * Mint the per-cell null control: values never planted anywhere, drawn from
 * the SAME construction families as the planted values, so family-constant
 * bytes (the `eyJ` prefix a masked JWT legitimately renders, the `.`-joined
 * segment geometry) land in the measured floor rather than being mistaken
 * for planted material.
 */
export function mintNullControl(planted: readonly PlantedValue[]): string[] {
  const values = new Set(planted.map((p) => p.value));
  const nulls: string[] = [];
  const families: Array<() => string> = [mintSyntheticValue];
  if (planted.some((p) => p.form === 'jwt')) families.push(mintJwtValue);
  for (const mint of families) {
    let drawn = 0;
    while (drawn < NULL_CONTROL_DRAWS) {
      const v = mint();
      if (values.has(v)) continue;
      nulls.push(v);
      drawn++;
    }
  }
  return nulls;
}

// ============================================================================
// JSON leaf walk
// ============================================================================

/** Visit every string leaf of a JSON-shaped value with its JSON path. */
export function walkStringLeaves(
  value: unknown,
  visit: (path: string, leaf: string) => void,
  path = '$',
  seen: WeakSet<object> = new WeakSet(),
): void {
  if (typeof value === 'string') {
    visit(path, value);
    return;
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) return;
    seen.add(value);
    value.forEach((v, i) => walkStringLeaves(v, visit, `${path}[${i}]`, seen));
    return;
  }
  if (value !== null && typeof value === 'object') {
    if (seen.has(value as object)) return;
    seen.add(value as object);
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      walkStringLeaves(v, visit, `${path}.${k}`, seen);
    }
  }
}

// ============================================================================
// Cell execution
// ============================================================================

export interface CellOutput {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  /** Contents of the `-o` output file, when the cell writes one. */
  outputFile?: string;
}

/**
 * Run one cell against the built CLI. Offline and hermetic: scratch HOME (no
 * keys, no config), telemetry off, registry fetch stubbed at the process
 * boundary, `--no-registry` on both commands. Nothing a cell does can put a
 * planted value on a wire.
 */
export function runCliCell(
  cliPath: string,
  spec: CellSpec,
  treeDir: string,
  scratchDir: string,
): CellOutput {
  const repoRoot = join(__dirname, '..', '..');
  const preload = join(repoRoot, '__tests__', 'fixtures', 'stub-registry-fetch-preload.cjs');
  const fakeHome = join(scratchDir, 'home');
  mkdirSync(fakeHome, { recursive: true });

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: fakeHome,
    OPENA2A_TELEMETRY: 'off',
    OPENA2A_CORPUS_DETERMINISTIC: '1',
  };
  delete env.ANTHROPIC_API_KEY;
  if (existsSync(preload)) {
    // Stub the process's global fetch: every cell runs `--no-registry` and
    // offline anyway, but the preload makes that structural — no byte of a
    // fixture can leave the machine, and any attempted request is captured
    // (the capture stays in the scratch dir with the other run debris).
    env.NODE_OPTIONS = `--require ${preload}`;
    env.HMA_STUB_REGISTRY_CAPTURE = join(scratchDir, 'network-capture.jsonl');
  }

  let args: string[];
  let outPath: string | undefined;
  if (spec.command === 'secure') {
    outPath = join(scratchDir, `out-${spec.cell.replace(/\//g, '_')}.${spec.format}`);
    args = [cliPath, 'secure', treeDir, '--ci', '--no-registry', '--format', spec.format, '-o', outPath];
  } else {
    args = [cliPath, 'check', treeDir, '--no-registry'];
    if (spec.format === 'json') args.push('--json');
  }

  const res = spawnSync('node', args, {
    encoding: 'utf8',
    timeout: 170_000,
    maxBuffer: 64 * 1024 * 1024,
    env,
  });

  let outputFile: string | undefined;
  if (outPath && existsSync(outPath)) outputFile = readFileSync(outPath, 'utf8');
  return { exitCode: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '', outputFile };
}

// ============================================================================
// Cell evaluation — the two ordered gates (HMA-15.AC5)
// ============================================================================

export interface CellEvaluation {
  cell: string;
  status: 'pass' | 'unreachable' | 'rendered';
  /** Gate one's verdict: did this cell produce a credential-class finding? */
  detected: boolean;
  /** The cell's measured null-control maximum — THE threshold. */
  nullFloor: number;
  /** Longest contiguous run of ANY planted value in the cell's output. */
  plantedRun: number;
  /** The same measurement, split by planted kind — names, never bytes. */
  runsByKind: Record<string, number>;
  /** The planted kind whose run is `plantedRun`, on failure. */
  worstKind?: PlantedKind;
  /** JSON path or byte surface of the worst leaf, on failure. */
  worstPath?: string;
  /**
   * Credential-class findings countable in this cell's JSON output, recorded
   * for the HMA-15.AC9 baseline comparison. -1 when the cell's format has no
   * countable machine channel.
   */
  credentialFindingCount: number;
  exitCode: number | null;
}

/**
 * Gate-one predicate. Fixtures are pinned never to spell "cred" (see
 * `assertFixtureInvariants`), so the letters can only come from the tool's
 * own credential-class vocabulary: a category ("Credential Security" /
 * "Credential Protection" / "credentials"), an attack class ("CRED-…"), or
 * finding prose ("Hardcoded credentials are exposed…", "Rotate any
 * credentials…") — all of which render only when a credential-class finding
 * does. Producer-agnostic: no check id, no producer name, no field list.
 */
const CREDENTIAL_VOCABULARY = /cred/i;

/** Count credential-class findings in a parsed JSON doc, by class metadata. */
function countCredentialFindings(doc: unknown): number {
  let count = 0;
  const stack: unknown[] = [doc];
  const seen = new WeakSet<object>();
  while (stack.length > 0) {
    const v = stack.pop();
    if (Array.isArray(v)) {
      if (seen.has(v)) continue;
      seen.add(v);
      for (const item of v) stack.push(item);
      continue;
    }
    if (v !== null && typeof v === 'object') {
      if (seen.has(v as object)) continue;
      seen.add(v as object);
      const o = v as Record<string, unknown>;
      const classy =
        (typeof o.attackClass === 'string' && CREDENTIAL_VOCABULARY.test(o.attackClass)) ||
        (typeof o.category === 'string' && CREDENTIAL_VOCABULARY.test(o.category));
      if (classy) count++;
      for (const inner of Object.values(o)) stack.push(inner);
    }
  }
  return count;
}

/**
 * Evaluate one cell: gate one (DETECTED), then gate two (no planted value
 * RENDERED above the cell's own measured noise floor). Pure — callable with
 * stubbed output, which is how the harness-honesty suite proves AC4/AC5/AC7
 * about it.
 */
export function evaluateCell(
  spec: CellSpec,
  output: CellOutput,
  planted: readonly PlantedValue[],
  nullValues: readonly string[],
): CellEvaluation {
  const combined = output.stdout + '\n' + (output.outputFile ?? '');

  // The threshold is MEASURED here, from values never planted in the fixture,
  // against this very output. There is no constant to fall back to.
  const nullFloor = longestSharedRun(nullValues, combined);
  const runsByKind: Record<string, number> = {};
  let plantedRun = 0;
  let worstKind: PlantedKind | undefined;
  let worstValue = '';
  for (const p of planted) {
    const run = longestSharedRun([p.value], combined);
    runsByKind[p.kind] = Math.max(runsByKind[p.kind] ?? 0, run);
    if (run > plantedRun) {
      plantedRun = run;
      worstKind = p.kind;
      worstValue = p.value;
    }
  }

  let parsed: unknown;
  if (spec.jsonOutput) {
    const primary = spec.command === 'secure' ? output.outputFile ?? output.stdout : output.stdout;
    try {
      parsed = JSON.parse(primary);
    } catch {
      parsed = undefined;
    }
  }

  const credentialFindingCount =
    parsed !== undefined && (spec.format === 'json') ? countCredentialFindings(parsed) : -1;

  // Gate one — DETECTED. json cells must carry countable credential-class
  // findings. Every other format renders the same scan, so its predicate is
  // the tool's credential-class vocabulary (reserved: fixtures are pinned
  // never to spell it) CO-SIGNED by the failing exit the finding forces —
  // a category summary printing "Credentials: clear" beside exit 0 cannot
  // forge detection. Stated limit: on a non-json format this measures that a
  // credential-class finding RENDERED, which is the same scan the json cell
  // counts; it does not re-parse prose into findings.
  const detected =
    parsed !== undefined && spec.format === 'json'
      ? credentialFindingCount > 0
      : CREDENTIAL_VOCABULARY.test(combined) && output.exitCode === 1;

  if (!detected) {
    return {
      cell: spec.cell,
      status: 'unreachable',
      detected: false,
      nullFloor,
      plantedRun,
      runsByKind,
      credentialFindingCount,
      exitCode: output.exitCode,
    };
  }

  // Gate two — not RENDERED. The whole-byte-surface scan subsumes any field
  // list; the leaf walk exists to NAME the offending path without ever
  // naming its bytes.
  if (plantedRun > nullFloor) {
    let worstPath: string =
      output.outputFile !== undefined && longestSharedRun([worstValue], output.outputFile) >= plantedRun
        ? 'output-file'
        : 'stdout';
    if (parsed !== undefined) {
      let worstLeafRun = -1;
      walkStringLeaves(parsed, (path, leaf) => {
        const run = longestSharedRun([worstValue], leaf);
        if (run > worstLeafRun) {
          worstLeafRun = run;
          if (run > nullFloor) worstPath = path;
        }
      });
    }
    return {
      cell: spec.cell,
      status: 'rendered',
      detected: true,
      nullFloor,
      plantedRun,
      runsByKind,
      worstKind,
      worstPath,
      credentialFindingCount,
      exitCode: output.exitCode,
    };
  }

  return {
    cell: spec.cell,
    status: 'pass',
    detected: true,
    nullFloor,
    plantedRun,
    runsByKind,
    credentialFindingCount,
    exitCode: output.exitCode,
  };
}

/**
 * One failure line. Carries the cell name, the surface (field name or JSON
 * path), the planted KIND, and observed LENGTHS — never a byte of any value
 * (HMA-15.AC7).
 */
export function formatCellFailure(e: CellEvaluation): string {
  if (e.status === 'unreachable') {
    return (
      `HMA-15 cell ${e.cell} UNREACHABLE: the cell produced no credential-class finding ` +
      `(exit=${e.exitCode ?? 'null'}), so its non-render assertion would be vacuous. ` +
      `An unreached cell fails the run.`
    );
  }
  if (e.status === 'rendered') {
    return (
      `HMA-15 cell ${e.cell} RENDERED a planted value` +
      (e.worstKind !== undefined ? ` (${e.worstKind})` : '') +
      `: longest contiguous run ${e.plantedRun} exceeds the measured null-control floor ${e.nullFloor}` +
      (e.worstPath !== undefined ? ` at ${e.worstPath}` : '') +
      `.`
    );
  }
  return `HMA-15 cell ${e.cell} pass (run ${e.plantedRun} <= floor ${e.nullFloor}).`;
}

/** The run verdict: every cell must pass; any unreached or rendering cell fails. */
export function assessMatrix(evaluations: readonly CellEvaluation[]): {
  ok: boolean;
  failures: CellEvaluation[];
} {
  const failures = evaluations.filter((e) => e.status !== 'pass');
  return { ok: failures.length === 0, failures };
}

// ============================================================================
// Run artifact (HMA-15.AC3 / AC5 / AC6 / AC9 / AC10 evidence)
// ============================================================================

export function sha256File(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/**
 * A stable hash of a whole directory tree: sorted relative paths, each with
 * its file sha256. AC10 r2 measured sha256(dist/cli.js) IDENTICAL between the
 * leaking build and its fix — the change never touches `src/cli.ts` — so
 * artifact identity is pinned on the tree, where the changed files are.
 */
export function sha256Dir(dir: string): string {
  const files: string[] = [];
  const walk = (rel: string): void => {
    for (const entry of readdirSync(join(dir, rel), { withFileTypes: true })) {
      const relPath = rel === '' ? entry.name : `${rel}/${entry.name}`;
      if (entry.isDirectory()) walk(relPath);
      else if (entry.isFile()) files.push(relPath);
    }
  };
  walk('');
  files.sort();
  const hash = createHash('sha256');
  for (const relPath of files) {
    hash.update(relPath);
    hash.update('\0');
    hash.update(sha256File(join(dir, relPath)));
    hash.update('\n');
  }
  return hash.digest('hex');
}

/** Where this run's artifact goes: env override for QA, temp dir otherwise. */
export function runArtifactPath(): string {
  if (process.env.HMA15_RUN_ARTIFACT) return process.env.HMA15_RUN_ARTIFACT;
  const dir = mkdtempSync(join(tmpdir(), 'hma15-evidence-'));
  return join(dir, 'property-run.json');
}

/** Per-fixture record: forms and boundary-predicate outcomes, never bytes. */
export interface FixtureEvidence {
  artifactType: CellArtifactType;
  plantedForms: { kind: PlantedKind; form: PlantedValue['form'] }[];
  /**
   * The AC5 r2 predicate, evaluated by the property test in the same run:
   * the covered probe came back CHANGED with its value gone, and every
   * uncovered probe came back byte-identical from `redactSecretsForReport`.
   */
  boundary: { coveredRemoved: boolean; uncoveredUnchanged: boolean };
}

export interface RunArtifact {
  task: 'HMA-15';
  startedAt: string;
  finishedAt: string;
  cli: {
    path: string;
    sha256: string;
    /** Identity of the WHOLE built tree the cell ran (AC10 r2). */
    distTreeSha256: string;
  };
  fixtures: FixtureEvidence[];
  cells: CellEvaluation[];
  verdict: { ok: boolean; failedCells: string[] };
}

export function writeRunArtifact(path: string, artifact: RunArtifact): void {
  writeFileSync(path, JSON.stringify(artifact, null, 2) + '\n', 'utf8');
}

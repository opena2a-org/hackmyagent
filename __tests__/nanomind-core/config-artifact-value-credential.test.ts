/**
 * HMA-27 — a value-shaped credential route for config artifacts.
 *
 * The gap (measured at ee5da9e, base of this branch): the canonical
 * credential-format scan in `semantic-compiler.ts` ran only for
 * `source_code` artifacts, and the only CRED-HARVEST signal a non-source
 * artifact could earn was prose-derived (a credential noun AND a harvesting
 * verb — `ask|request|share|provide` — co-occurring). So a `config.toml`
 * whose only credential content is a canonical Anthropic-shaped VALUE, or a
 * name-gated `secret_access_key = "<40 hex>"` assignment, produced ZERO
 * credential findings from every layer: CRED-001 never reads a root-level
 * `.toml` (`CONFIG_CANDIDATE_NAMES` has no `.toml` entry), the Layer-2
 * semantic discovery globs carry no `.toml`, and AST-CRED-003's signal gate
 * (`credential-analyzer.ts` `hasCredentialSignals`) had nothing to read.
 *
 * The route under test is VALUE-shaped: detection for non-source artifacts
 * is decided by the same canonical value formats the source path uses
 * (`CANONICAL_CREDENTIAL_PATTERNS` / `NAME_GATED_CREDENTIAL_PATTERNS`),
 * never by prose and never by a path or filename regex — the fixture is
 * still detected renamed and moved, and in a file with no prose at all.
 *
 * The fixtures are COMMITTED at `test-fixtures/config-value-credential/`
 * and read as raw bytes (T1 carries a token-shape line and is registered in
 * `security/credential-shape-exemptions.json`). Nothing in this file spells
 * a token-shape value as a source literal.
 *
 * The CLI is driven through `src/cli.ts` with the repo's own `tsx`, not the
 * compiled binary, for the reason `name-gated-credential-width.test.ts`
 * documents: a spawn suite gated on the built entry can silently skip, and
 * a criterion whose evidence can silently skip is not evidence.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { SemanticCompiler } from '../../src/nanomind-core/compiler/semantic-compiler';
import { analyzeCredentials } from '../../src/nanomind-core/analyzers/credential-analyzer';

const REPO_ROOT = path.join(__dirname, '..', '..');
const TSX = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');
const CLI_SRC = path.join(REPO_ROOT, 'src', 'cli.ts');
const FIXTURES = path.join(REPO_ROOT, 'test-fixtures', 'config-value-credential');

const T1 = readFileSync(path.join(FIXTURES, 't1', 'config.toml'), 'utf-8');
const N4 = readFileSync(path.join(FIXTURES, 'n4', 'config.toml'), 'utf-8');
const GUARD_SHA = readFileSync(path.join(FIXTURES, 'guards', 'config.toml'), 'utf-8');
const GUARD_I18N = readFileSync(path.join(FIXTURES, 'guards', 'locales.toml'), 'utf-8');

/** 1-based line of the fixture line that starts with `key`, or -1. */
function lineOf(content: string, key: string): number {
  const idx = content.split('\n').findIndex((l) => l.startsWith(key));
  return idx < 0 ? -1 : idx + 1;
}

/** The quoted value on the fixture line that starts with `key`. */
function valueOf(content: string, key: string): string {
  const line = content.split('\n').find((l) => l.startsWith(key)) ?? '';
  const m = /"([^"]+)"/.exec(line);
  if (!m) throw new Error(`fixture line for ${key} carries no quoted value`);
  return m[1];
}

const T1_LINE = lineOf(T1, 'api_key');
const N4_LINE = lineOf(N4, 'secret_access_key');
/** The T1 value alone — used for the rename/move and no-prose variants. */
const T1_VALUE = valueOf(T1, 'api_key');

interface ReportFinding {
  checkId?: string;
  id?: string;
  severity: string;
  passed?: boolean;
  file?: string;
  line?: number;
}

/**
 * Every failed credential finding from every layer: the static checks
 * (CRED-*, WEBCRED-*, CLAUDE-001 reports under CRED ids), the AST layer
 * (AST-CRED-*), and Layer-2 semantic (SEM-CRED-*) all carry `CRED` in their
 * check id, so one predicate covers the union without hand-listing layers.
 */
function failedCredentialFindings(all: ReportFinding[]): ReportFinding[] {
  return all.filter((f) => f.passed === false && (f.checkId ?? f.id ?? '').includes('CRED'));
}

function runCli(target: string): { failedCred: ReportFinding[] } {
  const run = spawnSync(TSX, [CLI_SRC, 'secure', target, '--no-registry', '--json'], {
    encoding: 'utf-8',
    timeout: 180_000,
    env: { ...process.env, NO_COLOR: '1' },
  });
  const stdout = run.stdout ?? '';
  const start = stdout.indexOf('{');
  // Fail loudly rather than returning an empty finding list: the guard
  // fixtures below assert AGAINST zero, and a spawn that never ran would
  // satisfy them silently.
  if (start < 0) {
    throw new Error(
      `the scanner produced no JSON for ${target} (status ${run.status}, signal ${run.signal}); `
        + `stderr: ${(run.stderr ?? '').slice(0, 400)}`,
    );
  }
  const parsed = JSON.parse(stdout.slice(start));
  const all: ReportFinding[] = parsed.allFindings ?? parsed.findings ?? [];
  return { failedCred: failedCredentialFindings(all) };
}

let root: string;
let t1Cred: ReportFinding[] = [];
let n4Cred: ReportFinding[] = [];
let movedCred: ReportFinding[] = [];
let noProseCred: ReportFinding[] = [];
let guardShaCred: ReportFinding[] = [];
let guardI18nCred: ReportFinding[] = [];

const MOVED_REL = path.join('nested', 'inner', 'pipeline-settings.toml');

beforeAll(() => {
  root = mkdtempSync(path.join(tmpdir(), 'hma27-'));
  const tree = (name: string, files: Record<string, string>): string => {
    const dir = path.join(root, name);
    for (const [rel, body] of Object.entries(files)) {
      const full = path.join(dir, rel);
      mkdirSync(path.dirname(full), { recursive: true });
      writeFileSync(full, body);
    }
    return dir;
  };

  t1Cred = runCli(tree('t1', { 'config.toml': T1 })).failedCred;
  n4Cred = runCli(tree('n4', { 'config.toml': N4 })).failedCred;
  // AC2(a): same bytes, renamed AND moved below two directories.
  movedCred = runCli(tree('moved', { [MOVED_REL]: T1 })).failedCred;
  // AC2(b): no prose at all — the file is the value and nothing else.
  noProseCred = runCli(tree('no-prose', { 'blob.toml': `${T1_VALUE}\n` })).failedCred;
  guardShaCred = runCli(tree('guard-sha', { 'config.toml': GUARD_SHA })).failedCred;
  guardI18nCred = runCli(tree('guard-i18n', { 'locales.toml': GUARD_I18N })).failedCred;
}, 1_200_000);

afterAll(() => {
  if (root) rmSync(root, { recursive: true, force: true });
});

describe('HMA-27 value-shaped credential route for config artifacts', () => {
  it('HMA-27.AC1 T1: a config.toml whose only credential content is a canonical Anthropic-shaped value reports exactly one credential finding, at the value line', () => {
    expect(T1_LINE).toBeGreaterThan(0);
    expect(
      t1Cred.length,
      `expected exactly one credential finding across every layer, got `
        + `[${t1Cred.map((f) => `${f.checkId}@${f.file}:${f.line}`).join(', ')}]`,
    ).toBe(1);
    expect(t1Cred[0].checkId).toBe('AST-CRED-003');
    expect(t1Cred[0].line, 'the finding must sit on the value line').toBe(T1_LINE);
  }, 30_000);

  it('HMA-27.AC1 N4: a config.toml carrying a name-gated 40-hex secret_access_key reports exactly one credential finding, at the value line', () => {
    expect(N4_LINE).toBeGreaterThan(0);
    expect(
      n4Cred.length,
      `expected exactly one credential finding across every layer, got `
        + `[${n4Cred.map((f) => `${f.checkId}@${f.file}:${f.line}`).join(', ')}]`,
    ).toBe(1);
    expect(n4Cred[0].checkId).toBe('AST-CRED-003');
    expect(n4Cred[0].line, 'the finding must sit on the value line').toBe(N4_LINE);
  }, 30_000);

  it('HMA-27.AC2 the T1 value is still detected when the fixture is renamed and moved to a different directory', () => {
    expect(
      movedCred.length,
      'detection must be value-shaped: the same bytes at nested/inner/pipeline-settings.toml '
        + 'must report the same single finding — a basename or directory gate fails here',
    ).toBe(1);
    expect(movedCred[0].checkId).toBe('AST-CRED-003');
    expect(movedCred[0].file).toBe(MOVED_REL);
    expect(movedCred[0].line).toBe(T1_LINE);
  }, 30_000);

  it('HMA-27.AC2 the value is detected in a file containing no prose at all', () => {
    expect(
      noProseCred.length,
      'a file whose entire content is the value must still be detected: with zero words '
        + 'there is no prose signal for any keyword gate to read',
    ).toBe(1);
    expect(noProseCred[0].checkId).toBe('AST-CRED-003');
    expect(noProseCred[0].line).toBe(1);
  }, 30_000);

  it("HMA-27.AC2 AST-CRED-003's prose-derived signal gate is not the deciding input: a no-prose artifact carries zero prose-derived credential signals and the value-derived surface alone decides", async () => {
    const compiler = new SemanticCompiler({ useNanoMind: false });
    const content = `${T1_VALUE}\n`;
    const { ast } = await compiler.compile(content, 'blob.toml');

    // No prose-derived signal exists: no CRED-HARVEST/CRED-EXFIL evidence
    // span and no keyword-derived 'Credential harvesting' surface. These are
    // exactly the inputs the gate at credential-analyzer.ts
    // (`hasCredentialSignals`) reads on the prose route.
    const proseSpans = ast.evidenceSpans.filter(
      (e) => e.supports === 'CRED-HARVEST' || e.supports === 'CRED-EXFIL',
    );
    expect(proseSpans, 'no prose-derived credential evidence span may exist').toEqual([]);
    expect(
      ast.inferredRiskSurface.some((r) => r.surface === 'Credential harvesting'),
      "the keyword-derived 'Credential harvesting' surface must be absent",
    ).toBe(false);

    // The deciding input is the canonical VALUE match: a deterministic
    // 'Hardcoded …' surface carrying the value's offset.
    const valueSurfaces = ast.inferredRiskSurface.filter(
      (r) => r.attackClass === 'CRED-HARVEST' && r.surface.startsWith('Hardcoded '),
    );
    expect(
      valueSurfaces.length,
      'the canonical value scan must contribute the deciding CRED-HARVEST surface',
    ).toBe(1);
    expect(typeof valueSurfaces[0].offset).toBe('number');

    // And that surface alone produces the finding.
    const findings = analyzeCredentials(ast, (a) => compiler.verifyAST(a), undefined, content)
      .filter((f) => f.checkId === 'AST-CRED-003');
    expect(findings).toHaveLength(1);
    expect(findings[0].line).toBe(1);

    // The inert twin — same file with the value line replaced — earns no
    // credential signal from any input, so the value is the only decider.
    const inert = await compiler.compile('region = "us-east-1"\n', 'blob.toml');
    expect(
      inert.ast.inferredRiskSurface.filter((r) => r.attackClass === 'CRED-HARVEST'),
    ).toEqual([]);
  }, 30_000);

  it('HMA-27.AC3 a git commit SHA (40 hex) as a config value reports zero credential findings', () => {
    expect(
      guardShaCred.map((f) => `${f.checkId}@${f.file}:${f.line}`),
      'a 40-hex commit pin is not a credential: the name-gated shape must not fire without '
        + 'a secret-access-key-named assignment target, and the entropy blob must stay off '
        + 'the canonical route',
    ).toEqual([]);
  }, 30_000);

  it('HMA-27.AC3 a base64-ish 40+ char string in an i18n-style string table reports zero credential findings', () => {
    expect(
      guardI18nCred.map((f) => `${f.checkId}@${f.file}:${f.line}`),
      'a long ENTROPY_BLOB_ALTERNATIVE-alphabet string under an i18n key is not a '
        + 'credential: the value-shaped route is the canonical vendor + name-gated set, '
        + 'never the anonymous entropy fallback',
    ).toEqual([]);
  }, 30_000);
});

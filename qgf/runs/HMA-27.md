# HMA-27 run artifact — value-shaped credential route for config artifacts

Worker base: `ee5da9e` ("Examine credential-store files by the predicates the scanner
already owns (#712)"), branch `fleet/HMA-27-config-value-only-credential`. The contract's
cited base `d6fade15` is not present in this clone's history; every anchor was re-located
by content at `ee5da9e` before the red run (canonical Anthropic shape at
`src/hardening/scanner.ts:885`, prose-signal gate at
`src/nanomind-core/analyzers/credential-analyzer.ts:441-445`, `ENTROPY_BLOB_ALTERNATIVE`
at `src/types/credential-format.ts:902`, and the `source_code`-only gate on
`scanCanonicalCredentialFormats` in `src/nanomind-core/compiler/semantic-compiler.ts`).

Fixtures are committed at `test-fixtures/config-value-credential/`:
- `t1/config.toml` — CSR row T1: only credential content is a canonical Anthropic-shaped
  value (`sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}`), no harvesting-verb prose anywhere.
  Registered in `security/credential-shape-exemptions.json` (1 token-shape line,
  `byte-literal-fixture`).
- `n4/config.toml` — CSR row N4: `secret_access_key = "<40 lowercase hex>"`.
- `guards/config.toml` — AC3(a): a git commit SHA (40 hex) as a config value.
- `guards/locales.toml` — AC3(b): a 44-char base64-ish string (the
  `ENTROPY_BLOB_ALTERNATIVE` alphabet) in an i18n-style string table.

Tests: `__tests__/nanomind-core/config-artifact-value-credential.test.ts`. Each scan
drives `src/cli.ts secure <dir> --no-registry --json` via the repo's own `tsx` and counts
every failed finding whose check id carries `CRED` — the union of the static (CRED-*,
WEBCRED-*), AST (AST-CRED-*) and Layer-2 semantic (SEM-CRED-*) vocabularies — so
"zero from any layer" and "exactly one" are measured over all layers at once.

## Run 1 — BASE (red), at ee5da9e before the fix

`npx vitest run __tests__/nanomind-core/config-artifact-value-credential.test.ts`
(exit 1):

```
 RUN  v4.1.10 /fleet/work/csnp-abdel/HMA-27

 ❯ __tests__/nanomind-core/config-artifact-value-credential.test.ts (7 tests | 5 failed) 21278ms
     × HMA-27.AC1 T1: a config.toml whose only credential content is a canonical Anthropic-shaped value reports exactly one credential finding, at the value line 4ms
     × HMA-27.AC1 N4: a config.toml carrying a name-gated 40-hex secret_access_key reports exactly one credential finding, at the value line 1ms
     × HMA-27.AC2 the T1 value is still detected when the fixture is renamed and moved to a different directory 0ms
     × HMA-27.AC2 the value is detected in a file containing no prose at all 0ms
     × HMA-27.AC2 AST-CRED-003's prose-derived signal gate is not the deciding input: a no-prose artifact carries zero prose-derived credential signals and the value-derived surface alone decides 7ms

 Test Files  1 failed (1)
      Tests  5 failed | 2 passed (7)
   Start at  11:53:22
   Duration  21.45s (transform 99ms, setup 11ms, import 108ms, tests 21.28s, environment 0ms)
```

Failure detail (verbatim from the same run) — the base reports ZERO credential findings
from every layer on both CSR rows, which is the MUST-FAIL-first evidence:

```
 FAIL  __tests__/nanomind-core/config-artifact-value-credential.test.ts > HMA-27 value-shaped credential route for config artifacts > HMA-27.AC1 T1: a config.toml whose only credential content is a canonical Anthropic-shaped value reports exactly one credential finding, at the value line
AssertionError: expected exactly one credential finding across every layer, got []: expected +0 to be 1 // Object.is equality

 FAIL  __tests__/nanomind-core/config-artifact-value-credential.test.ts > HMA-27 value-shaped credential route for config artifacts > HMA-27.AC1 N4: a config.toml carrying a name-gated 40-hex secret_access_key reports exactly one credential finding, at the value line
AssertionError: expected exactly one credential finding across every layer, got []: expected +0 to be 1 // Object.is equality

 FAIL  __tests__/nanomind-core/config-artifact-value-credential.test.ts > HMA-27 value-shaped credential route for config artifacts > HMA-27.AC2 the T1 value is still detected when the fixture is renamed and moved to a different directory
AssertionError: detection must be value-shaped: the same bytes at nested/inner/pipeline-settings.toml must report the same single finding — a basename or directory gate fails here: expected +0 to be 1 // Object.is equality

 FAIL  __tests__/nanomind-core/config-artifact-value-credential.test.ts > HMA-27 value-shaped credential route for config artifacts > HMA-27.AC2 the value is detected in a file containing no prose at all
AssertionError: a file whose entire content is the value must still be detected: with zero words there is no prose signal for any keyword gate to read: expected +0 to be 1 // Object.is equality

 FAIL  __tests__/nanomind-core/config-artifact-value-credential.test.ts > HMA-27 value-shaped credential route for config artifacts > HMA-27.AC2 AST-CRED-003's prose-derived signal gate is not the deciding input: a no-prose artifact carries zero prose-derived credential signals and the value-derived surface alone decides
AssertionError: the canonical value scan must contribute the deciding CRED-HARVEST surface: expected +0 to be 1 // Object.is equality
```

The two tests already green at base are the AC3 guard fixtures: the git-SHA config value
and the base64-ish i18n string both report zero credential findings at base, pinning the
"before" side of the 0 -> 0 guard count.

## Run 2 — FIX (green), after widening the canonical scan to every artifact type

The fix: `src/nanomind-core/compiler/semantic-compiler.ts` — `scanCanonicalCredentialFormats`
(the canonical + name-gated value lists) now runs for every artifact type instead of
`source_code` only. Its hits enter the deterministic risk-surface floor with the value's
offset, and AST-CRED-003 emits one finding per located offset at the value's line. The
`declaredDataAccess` push (step 6b) stays source-only, so AST-CRED-001 does not double-report
the same value on config artifacts.

`npx vitest run __tests__/nanomind-core/config-artifact-value-credential.test.ts --reporter=verbose`
(exit 0):

```
 RUN  v4.1.10 /fleet/work/csnp-abdel/HMA-27

 ✓ __tests__/nanomind-core/config-artifact-value-credential.test.ts > HMA-27 value-shaped credential route for config artifacts > HMA-27.AC1 T1: a config.toml whose only credential content is a canonical Anthropic-shaped value reports exactly one credential finding, at the value line 1ms
 ✓ __tests__/nanomind-core/config-artifact-value-credential.test.ts > HMA-27 value-shaped credential route for config artifacts > HMA-27.AC1 N4: a config.toml carrying a name-gated 40-hex secret_access_key reports exactly one credential finding, at the value line 0ms
 ✓ __tests__/nanomind-core/config-artifact-value-credential.test.ts > HMA-27 value-shaped credential route for config artifacts > HMA-27.AC2 the T1 value is still detected when the fixture is renamed and moved to a different directory 0ms
 ✓ __tests__/nanomind-core/config-artifact-value-credential.test.ts > HMA-27 value-shaped credential route for config artifacts > HMA-27.AC2 the value is detected in a file containing no prose at all 0ms
 ✓ __tests__/nanomind-core/config-artifact-value-credential.test.ts > HMA-27 value-shaped credential route for config artifacts > HMA-27.AC2 AST-CRED-003's prose-derived signal gate is not the deciding input: a no-prose artifact carries zero prose-derived credential signals and the value-derived surface alone decides 10ms
 ✓ __tests__/nanomind-core/config-artifact-value-credential.test.ts > HMA-27 value-shaped credential route for config artifacts > HMA-27.AC3 a git commit SHA (40 hex) as a config value reports zero credential findings 0ms
 ✓ __tests__/nanomind-core/config-artifact-value-credential.test.ts > HMA-27 value-shaped credential route for config artifacts > HMA-27.AC3 a base64-ish 40+ char string in an i18n-style string table reports zero credential findings 0ms

 Test Files  1 passed (1)
      Tests  7 passed (7)
   Start at  11:54:40
   Duration  21.67s (transform 142ms, setup 17ms, import 158ms, tests 21.42s, environment 0ms)
```

## Criterion mapping

- **HMA-27.AC1** — `HMA-27.AC1 T1 …` and `HMA-27.AC1 N4 …`: red at base (0 findings from
  any layer, both rows), green at fix (exactly one AST-CRED-003 each, at the value's line —
  T1 line 9, N4 line 6). Both runs pasted above.
- **HMA-27.AC2** — `HMA-27.AC2 …renamed and moved…` (a), `…no prose at all` (b), and
  `…prose-derived signal gate is not the deciding input` (c): detection is decided by the
  canonical value formats; same bytes fire at a different basename and directory, in a file
  with zero words, and the compiled AST shows zero CRED-HARVEST/CRED-EXFIL evidence spans
  and no keyword-derived surface while the value-derived `Hardcoded …` surface (with the
  value's offset) alone produces the finding.
- **HMA-27.AC3** — both guard tests: 0 credential findings at base AND at fix; the exact
  before/after count on the guard set is 0 -> 0.

## Whole-tree run

Full suite at the fix (`npm run build` then `npx vitest run`, container):
17 failed | 5097 passed | 45 skipped | 10 todo. Every failure is in the pre-existing
environmental set — this container has no `ps` binary and no network, which fails
`detect-citation-target` (4), `governance-cross-surface` (3), `E2E-002.live-process-detection`
(3), `check-not-found-json` (3), `verdict-requires-measurement` (2),
`deep-scan-incomplete-verdict` (1) and `check-pip-prefix-registry-query` (1). The four
non-obviously-environmental files were re-run at the base commit with the fix stashed and
fail with the identical test list there, so the fix introduces zero regressions.

One committed test changed its observable:
`__tests__/nanomind-core/compiler/aws-secret-name-gated.test.ts`'s cache-leak case used
"non-source compile does not carry the AWS surface" as its probe for type+hash cache
keying. That observable is removed by design here (both types now flag the value), so the
case now probes the ASTs' still-type-dependent fields (`artifactType`, and the
source-only `dataType: 'credentials'` read pattern) — the cache-keying property it pins
is unchanged.

Note carried from the RUN seat: the unit's "17 of 320" corpus figure is a CSR-corpus count
not reachable in this lane; the committed guard fixtures stand in for it and the corpus
re-measure is HOST-SIDE by the seat at close-out.

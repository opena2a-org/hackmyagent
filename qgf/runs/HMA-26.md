# Run artifact: HMA-26 — per-scan-context CoverageLedger

Task branch: `fleet/HMA-26-per-scan-ledger`. Fix commit: `4150fbb`
(`coverage-ledger: carry the active ledger per scan context via
AsyncLocalStorage`), AC3 test strengthened in `508843b`.

## The change

`src/hardening/coverage-ledger.ts` no longer holds the active ledger in a
module global (`let activeLedger: CoverageLedger | null = null;`, :1166 at the
base). `withActiveLedger` now runs its callback inside an
`AsyncLocalStorage<CoverageLedger>` store, and every namespace function
(`noteRead`, `noteInspect`, `noteReadFailure`, `noteListed`,
`noteListFailure`, `withholdOutOfTree`, `currentLedger`) resolves the ledger
of its own calling context. Both existing installer call sites are unchanged
(`src/hardening/scanner.ts` `scan()` and `src/cli.ts` single-file mode), and
the nested save/restore semantics the `--fix` verify pass documents fall out
of `AsyncLocalStorage.run`.

## Criterion evidence (leaf test names carry the criterion id)

- `HMA-26.AC1` — `__tests__/hardening/per-scan-ledger-context.test.ts`:
  nested install attributes inner reads to the inner ledger and the outer
  resumes intact (including on inner throw); two interleaved contexts each
  consult their own ledger, never whichever installed last.
- `HMA-26.AC2` — `__tests__/hardening/concurrent-scan-isolation.test.ts`
  (+ `__tests__/helpers/concurrent-scan-driver.cjs`): two concurrent
  `HardeningScanner.scan()` calls over disjoint all-basenames link fixtures in
  ONE process, under the HMA-04 reach recorder
  (`__tests__/helpers/fs-reach-recorder.cjs` preloaded before `dist` loads,
  confined to both roots). Asserts each scan withholds exactly what its own
  sequential control withholds, every withheld link resolves into its own
  fixture's out-of-tree directory, and the recorder saw 0 out-of-tree reaches.
- `HMA-26.AC3` — `__tests__/mcp/concurrent-scan-cross-disclosure.test.ts`:
  two overlapping `hackmyagent_scan` calls (`handleToolCall`,
  `src/mcp-server.ts`) against disjoint granted roots, both fixtures planting
  the same nine rels with different resolved targets. Asserts each call's text
  discloses every one of its own rel-keyed records with its own resolved
  target (an overwrite would surface the other tree's target under the same
  key), neither text names any path under the other fixture's base, and no
  out-of-tree bytes (the fixture canary) came back to either caller.

## AC2 red run (pre-fix tree)

Base substitution, disclosed: the contract's base is
`d6fade15f747a9c01a74f22e4b8eb23359b84309`, but this worktree is a depth-1
shallow clone whose only commit is `e340dcd` (origin/main at task cut), and
the worker gate denies `git fetch`, so a literal checkout of d6fade15 is not
possible here. The red run was therefore executed against the pre-fix tree at
`e340dcd`, after verifying the mechanism the contract pins is unchanged
between the two commits:

```
$ git rev-parse HEAD            # before the fix commit
e340dcd9ffe48efd5c73e5d518f77192372a1bc0
$ grep -n "let activeLedger" src/hardening/coverage-ledger.ts
1166:let activeLedger: CoverageLedger | null = null;
$ grep -rl AsyncLocalStorage src | wc -l
0
```

Procedure: with the tests committed, `git checkout HEAD~1 --
src/hardening/coverage-ledger.ts` restored the module-global implementation,
`npm run build` rebuilt `dist`, and the AC2 suite ran:

```
 RUN  v4.1.10 /fleet/work/devsecflow-abdel/HMA-26

 ❯ __tests__/hardening/concurrent-scan-isolation.test.ts (1 test | 1 failed) 236ms
     × HMA-26.AC2 two concurrent scans with disjoint roots each withhold exactly their own out-of-tree links and make 0 out-of-tree reaches 231ms

⎯⎯⎯⎯⎯⎯⎯ Failed Tests 1 ⎯⎯⎯⎯⎯⎯⎯

 FAIL  __tests__/hardening/concurrent-scan-isolation.test.ts > HMA-26.AC2 concurrent scan confinement isolation > HMA-26.AC2 two concurrent scans with disjoint roots each withhold exactly their own out-of-tree links and make 0 out-of-tree reaches
AssertionError: access /tmp/hma26-a-E8wRJN/linked/CLAUDE.md <- Object.<anonymous>
access /tmp/hma26-a-E8wRJN/linked/skills <- Object.<anonymous>
readFile /tmp/hma26-a-E8wRJN/linked/config.json <- Object.<anonymous>
readFile /tmp/hma26-a-E8wRJN/linked/.env <- Object.<anonymous>
readFile /tmp/hma26-a-E8wRJN/linked/CLAUDE.md <- Object.<anonymous>
stat /tmp/hma26-a-E8wRJN/linked/.env <- Object.<anonymous>
access /tmp/hma26-a-E8wRJN/linked/.env <- Object.<anonymous>
readFile /tmp/hma26-a-E8wRJN/linked/.claude/settings.json <- Object.<anonymous>
stat /tmp/hma26-a-E8wRJN/linked/config.json <- Object.<anonymous>
readFile /tmp/hma26-a-E8wRJN/linked/SOUL.md <- Object.<anonymous>
readFile /tmp/hma26-a-E8wRJN/linked/skills <- Object.<anonymous>
readFile /tmp/hma26-a-E8wRJN/linked/src <- Object.<anonymous>
access /tmp/hma26-a-E8wRJN/linked/src <- Object.<anonymous>
readdir /tmp/hma26-a-E8wRJN/linked/src <- Object.<anonymous>
readFile /tmp/hma26-a-E8wRJN/linked/src/index.ts <- Object.<anonymous>
access /tmp/hma26-a-E8wRJN/linked/SOUL.md <- Object.<anonymous>
readdir /tmp/hma26-a-E8wRJN/linked/skills <- Object.<anonymous>
readdir /tmp/hma26-a-E8wRJN/linked/skills/evil <- Object.<anonymous>
readFile /tmp/hma26-a-E8wRJN/linked/skills/CLAUDE.md <- Object.<anonymous>
readFile /tmp/hma26-a-E8wRJN/linked/skills/evil/SKILL.md <- Object.<anonymous>: expected 49 to be +0 // Object.is equality

- Expected
+ Received

- 0
+ 49

 ❯ __tests__/hardening/concurrent-scan-isolation.test.ts:105:58
    103|     // 0 out-of-tree reaches: nothing in either scan got past the guar…
    104|     // real filesystem (28 did at the base while the wrong ledger was …
    105|     expect(reach.reaches.length, describeReaches(reach)).toBe(0);
       |                                                          ^
    106|   }, TEST_TIMEOUT);
    107| });

 Test Files  1 failed (1)
      Tests  1 failed (1)
   Start at  23:44:03
   Duration  326ms (transform 27ms, setup 14ms, import 21ms, tests 236ms, environment 0ms)
```

49 out-of-tree reaches — every one a read of tree A's planted links
(`.env`, `CLAUDE.md`, `skills/evil/SKILL.md`, the `src` directory link, ...)
reaching the real filesystem while tree B's ledger was the installed global:
the same failure mode as the filing measurement (28 reaches / withheld
`['.env']` vs 6 withheld / 0 reaches sequential; counts differ because the
filing held the foreign ledger for 20 s where this test overlaps two live
scans). In the same pre-fix run, `HMA-26.AC1 two interleaved contexts each
consult their own ledger` also failed (`currentLedger()` inside context A
returned context B's ledger).

## Green run (at the fix)

Same three suites after restoring the fix and rebuilding `dist`:

```
 RUN  v4.1.10 /fleet/work/devsecflow-abdel/HMA-26

 Test Files  3 passed (3)
      Tests  5 passed (5)
   Start at  23:44:22
   Duration  831ms (transform 601ms, setup 37ms, import 767ms, tests 322ms, environment 0ms)
```

Manual driver run at the fix (same fixtures, reach recorder attached):
both concurrent scans withheld all nine planted rels each, recorder saw
2100 link-following calls, 0 reaches.

## Full suite at the delivered commit

`npm test` (vitest run, full suite): **5037 passed | 18 failed | 45 skipped |
10 todo (5110)**, 373 of 382 files passing. The 18 failures sit in 7 files
none of which touch the ledger surface (`__tests__/checker/check-not-found-json`,
`check-pip-prefix-registry-query`, `__tests__/cli/deep-scan-incomplete-verdict`,
`verdict-requires-measurement`, `__tests__/scanner/detect-citation-target`,
`governance-cross-surface`, `__tests__/oasb/e2e/E2E-002.live-process-detection`).
All 18 are pre-existing in this environment: re-running exactly those 7 files
against the PRE-FIX tree (module-global ledger restored from e340dcd,
`dist` rebuilt) reproduces the identical count — `18 failed | 74 passed (92)`
— so none are caused by this change. Every ledger-adjacent suite
(`tracked-fs-confinement-guard`, `out-of-tree-link-confinement`, all of
`__tests__/mcp/`, the nanomind discover-record suites,
`structural-discovery-depth`, `coverage-honesty`, `unread-input-ledger`,
`raw-fs-import-census`) passes at the fix: 207 passed | 1 skipped.

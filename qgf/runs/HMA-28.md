# HMA-28 run artifact — stdout-only JSON parsing in the confinement harnesses

- Task: HMA-28 (`qgf/criteria/HMA-28.md`)
- Base: `d6fade15f747a9c01a74f22e4b8eb23359b84309` (origin/main)
- Branch: `fleet/HMA-28-merged-stream-parse`
- Environment: linux container, node v22.23.2, non-root (uid 71002 — the
  chmod-based denial fixtures exercise for real), `npm ci` against the
  committed lockfile, `npm run build` green before every run.

## The change

`run()` in the harnesses returned stdout and stderr concatenated into one
string, and every JSON/SARIF parse read that merged stream, so any stderr byte
a spawned process emitted after the JSON body threw inside `json()`, nulled the
body, and failed the test. The fix splits the return: `stdout` (the machine
channel) feeds every parse, the merged `out` survives for text assertions that
want the message on either channel.

Files changed:

- `__tests__/repo/obstruction-disclosure.test.ts` — `run()` split; `json()`
  and the SARIF cell parse `res.stdout` (AC1 sites 1, 2)
- `__tests__/cli/secure-unread-input-gate.test.ts` — `run()` split; `json()`
  parses `res.stdout` (AC1 site 3)
- `__tests__/cli/secure-unread-directory-gate.test.ts` — `run()` split;
  `json()` parses `res.stdout` (AC1 site 4)
- `__tests__/cli/verdict-requires-measurement.test.ts` — same defect shape,
  found by the AC3 guard, outside the contract's four named sites; see below
- `__tests__/helpers/stderr-injection.cjs` — NEW, the AC2 injection arm
- `__tests__/repo/hma-28-stdout-only-parse.test.ts` — NEW, the AC1/AC2/AC3
  guard suite (leaf names carry the criterion ids)

## HMA-28.AC2 — red at base

Command (base tree `d6fade15`, only the untracked injection module added):

```
NODE_OPTIONS="--require $PWD/__tests__/helpers/stderr-injection.cjs" \
  npx vitest run \
    __tests__/repo/obstruction-disclosure.test.ts \
    __tests__/cli/secure-unread-input-gate.test.ts \
    __tests__/cli/secure-unread-directory-gate.test.ts
```

Result — one injected stderr line per spawned node process, and the merged
stream parse throws on it:

```
 ❯ __tests__/cli/secure-unread-directory-gate.test.ts (7 tests | 6 failed) 26328ms
 ❯ __tests__/cli/secure-unread-input-gate.test.ts (38 tests | 13 failed) 141527ms
 ❯ __tests__/repo/obstruction-disclosure.test.ts (42 tests | 34 failed) 164315ms

 Test Files  3 failed (3)
      Tests  53 failed | 34 passed (87)
   Duration  164.44s (transform 135ms, setup 35ms, import 137ms, tests 332.17s, environment 0ms)
exit=1
```

`obstruction-disclosure.test.ts` reproduces the PROGRAM probe's measurement
exactly: 34 failed of 42, the pass-21 split. Across the three files this
environment measured 53 to the probe's 54 — the one-cell delta sits in
`secure-unread-input-gate.test.ts`, whose skip/exercise mix is
environment-dependent (cells skip loudly where the OS declines to deny), and
does not change the mechanism: every failure is a JSON-parsing test, and every
failure message is the parse of a merged stream with the injected line in it.

## HMA-28.AC2 — green at fix

Same command, same injection module, fixed tree:

```
 Test Files  3 passed (3)
      Tests  87 passed (87)
   Duration  213.32s (transform 209ms, setup 58ms, import 204ms, tests 401.55s, environment 0ms)
exit=0
```

34 → 0 in `obstruction-disclosure.test.ts`; 53 → 0 across the three files.

## Fix without injection — green

```
$ npx vitest run __tests__/repo/obstruction-disclosure.test.ts \
    __tests__/cli/secure-unread-input-gate.test.ts \
    __tests__/cli/secure-unread-directory-gate.test.ts \
    __tests__/repo/hma-28-stdout-only-parse.test.ts

 Test Files  4 passed (4)
      Tests  90 passed (90)
   Duration  213.46s (transform 167ms, setup 43ms, import 164ms, tests 400.54s, environment 0ms)
```

The 90 = the 87 harness tests plus the three criterion tests HMA-28.AC1,
HMA-28.AC2, HMA-28.AC3 in the guard suite.

## HMA-28.AC3 — the shape is gone and pinned out

At the delivered commit:

```
$ git grep -n "JSON.parse(res.out" -- __tests__
__tests__/cli/benchmark-composite-not-measured.test.ts:81:    const body = JSON.parse(res.out.slice(res.out.indexOf('{')));
```

Exactly one match, the stdout-only `out` (`res.stdout ?? ''`, line 39 of that
file) the contract names as not-the-defect. At base the same grep returned 5.
The guard test HMA-28.AC3 walks every file under `__tests__`, detects a string
built from both `res.stdout` and `res.stderr` (property and local-binding
spellings of the base helpers' shape), and fails if that string is ever fed to
`JSON.parse`.

## Out-of-contract finding: the same defect in a fourth file

The AC3 guard, run before the fix was complete, caught
`__tests__/cli/verdict-requires-measurement.test.ts`: same merged-stream
`run()` (line 51 at base), six parse sites reading it — invisible to the
contract's `JSON.parse(res.out` grep because they destructure `out` first
(`JSON.parse(out.slice(...)`, `JSON.parse(json.out...)`). Narrowing the guard
to un-see a live instance of the defect it exists to ban would be a laundered
green, so the file got the same split. One of its sites also spawned the CLI
twice and sliced the second run's output with the first run's index
(base line 526); it now spawns once.

Base vs fix for that file in this sandbox, no injection:

```
base:  Tests  3 failed | 30 passed (33)
fix:   Tests  2 failed | 31 passed (33)
```

The two remaining failures are pre-existing and environmental, present at base
and untouched by this change: the sandbox's npm registry proxy answers E403
"Filtered" for every package (probed directly: `check zzz-nope-… --json` exits
2 with an empty stdout and a no-`{` npm error on stderr, so there is no JSON on
ANY stream), and a `ps`-degradation comparison measures degraded == healthy
here. Both parse `stdout` already; neither is a merged-stream site. The third
base failure clears at the fix.

## AC2's committed arm

`__tests__/helpers/stderr-injection.cjs` is the mechanism, committed; its
header carries the exact invocation above, and the guard suite's HMA-28.AC2
test executes it on every `npm test`: a child spawned with the module on
`NODE_OPTIONS` provably emits the line, the merged-stream parse of that child's
output throws, the stdout-only parse of the same output succeeds.

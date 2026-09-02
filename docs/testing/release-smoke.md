# hackmyagent release smoke test

**Run before every tag push to `v*`. ~25 minutes by hand.**

Every item came from a real bug, a regression, or a detection gap that shipped.
Don't skip without writing down why in the release notes.

Run every command from a clean clone. Use `node dist/cli.js` not the global
install. Capture exact output for the `USER_VISIBLE_IMPACT:` marker.

---

## 0. Build + tests (5 min)

```bash
cd hackmyagent
git status                          # clean, only the branch you intend to ship
npm ci                              # lockfile valid
npm run build                       # zero output, zero errors
npm test                            # all green
```

Then run the benign FPR regression suite separately — this is the most critical
gate and must pass with zero high/critical findings across all 10 oracle fixtures:

```bash
npx vitest run __tests__/nanomind-core/benign-fp-regression.test.ts
# Expected: 10 tests pass, FPR = 0/10 = 0%
```

Then the corpus gate — BLOCKING. It runs the built CLI over every fixture in the
opena2a-corpus checkout and compares scores against the manifest bands and the
rendered output against `golden/hma/`. A red result here means either the scoring
moved (re-bake the goldens in the same PR that moved it and say why) or the corpus
checkout is stale; it never means "skip it":

```bash
git -C ~/.opena2a/corpus rev-parse --short HEAD   # record this in the release notes
OPENA2A_CORPUS_PATH=$HOME/.opena2a/corpus npm run release-smoke:corpus
# Expected: 12 passed, 0 failed, 2 skipped (a2a/* and npm/* surfaces are not in the corpus yet)
# Baseline recorded 2026-09-01 against corpus c899830 (opena2a-corpus#11); a different
# corpus HEAD needs the counts re-recorded here.
```

Do not set `OPENA2A_CORPUS_UPDATE_GOLDEN=1` on a release branch to make this pass: a golden
moves only in the PR that moved the score, with the cause named in the commit.

Fail the release if:
- Any test is red
- Any benign oracle fixture (b01–b10) triggers a HIGH or CRITICAL finding
- The build emits any TypeScript error or warning

---

## 0.5 Build the throwaway fixtures (1 min)

Every scan step below targets one of these. They are built here so the
checklist works **from a clean clone** — do not substitute a path that only
exists on a maintainer's machine.

```bash
# Known-bad: one config-shaped file with a synthetic credential at the scan
# root. Built at runtime so no credential-looking string is ever committed.
BAD=$(mktemp -d)
printf '{"name":"smoke-bad","version":"1.0.0"}\n' > "$BAD/package.json"
printf '{"apiKey":"ghp_%s"}\n' "$(printf 'a%.0s' {1..36})" > "$BAD/config.json"

# Known-clean: an empty tree.
CLEAN=$(mktemp -d)

# Assert both exist before trusting any exit code below.
test -f "$BAD/config.json" && test -d "$CLEAN" || { echo "FIXTURE BUILD FAILED"; exit 1; }
```

`test/` and `test/fixtures/governed-mcp` are tracked in this repo and are the
only in-repo scan targets the checklist uses.

**Instrument rule — read before reading any result.** A missing target makes
HMA print `Error: Directory '...' does not exist.` and exit **1**, which is
the same exit code as "findings were found". Any step whose expectation is a
non-zero exit MUST also assert on output content, or it passes vacuously. This
is not hypothetical: §2/§3/§5/§6 all pointed at the workspace playground
(`~/workspace/opena2a-org/test/hma`) using a bare repo-relative spelling, so
from a clean clone those steps errored before reaching their assertion and read
as passes. `__tests__/docs/release-smoke-paths.test.ts` now gates against it.

---

## 1. Help and version (1 min)

```bash
node dist/cli.js --help              # prints command list; no stack traces
node dist/cli.js -v                   # prints: hackmyagent 0.x.x + telemetry line
node dist/cli.js -v 2>/dev/null       # stdout ONLY: single clean line `hackmyagent 0.x.x`
node dist/cli.js -v 2>&1 1>/dev/null  # stderr ONLY: `Telemetry: on (opt-out: ...)`
```

As of cli-ui 0.5.2 the version output is stream-split: the bare `tool x.y.z`
goes to **stdout** (a single parseable line) and the telemetry disclosure goes
to **stderr**. A script doing `hackmyagent --version` must get exactly one line.

The `--help` output must list: `check`, `secure`, `scan-soul`, `harden-soul`,
`red-team`, `wild`, `detect`, `explain`, `check-metadata`, `analm`, `eval`,
`trust`, `telemetry`. If any top-level command is missing from help, the
command router is broken.

---

## 2. New-user command walkthrough (8 min)

Run every command. Each must produce output (not silent), have no stack trace,
and have no dead end (every finding has a fix command or path forward).

```bash
HMA=node\ dist/cli.js   # alias to shorten examples below

# Help and version
$HMA --help
$HMA -v

# Core scan — local directory (fixtures from §0.5)
$HMA secure "$BAD"
$HMA secure "$BAD" --json | head -5      # must be valid JSON object on line 1

# Governance
$HMA scan-soul test/                         # SOUL.md compliance score
$HMA harden-soul --dry-run "$CLEAN"          # dry-run: no write to disk

# Attack
$HMA attack --local --system-prompt "You are helpful."

# AI-powered
$HMA analm status

# Explainability
$HMA explain AST-PROMPT-001   # human-readable explanation of finding ID

# Metadata
$HMA check-metadata --json | head -5   # JSON array of check definitions

# Feature stubs (help output only — no live calls)
$HMA eval --help
$HMA wild --help
```

For each command verify:
1. Output is produced — not silent, no hang
2. Exit code 0 (success paths); exit code 1 for critical/high finding paths
3. No credentials printed (API keys, tokens, any `sk-` prefix)
4. No stack traces in normal output (stderr is acceptable for DEBUG)

---

## 3. Surface coverage matrix (8 min)

HMA scans multiple surface types. Release testing must exercise **each surface**
with at least one real-world example. Three sibling repos is repetition, not
coverage.

| Surface | Real-world target | Expected score |
|---|---|---|
| Known-bad tree | `"$BAD"` (§0.5) | 69/100, ≥ 1 CRITICAL credential finding, exit 1 |
| Local repo (clean) | `../ai-trust` or `../secretless` | 60–90 |
| Empty dir | `"$CLEAN"` (§0.5) | ~95–98 (`.gitignore` LOW only) |
| Governed MCP | `node dist/cli.js secure test/fixtures/governed-mcp` | 96/100 |
| Standalone SOUL.md | `node dist/cli.js scan-soul test/` | see note below |
| npm package | `node dist/cli.js check express` | ≥ 95 |
| PyPI package | `node dist/cli.js check pip:requests` | ~90 |
| GitHub repo | `node dist/cli.js check getsentry/sentry-mcp` | varies |
| Skill | `node dist/cli.js check skill:opena2a/code-review-skill` | varies |
| MCP server | a real MCP repo (e.g. `../hma-test/ibm-mcp`) | 70–90 |
| A2A agent | `../a2a-security-examples/examples/secure-agent-card` | 80–90 |

**On the `scan-soul test/` row.** Measured 18/100 on 0.25.1 (BASIC tier, "23 of
29 applicable controls not detected"). That number is depressed by the
keyword-vs-prose matcher gap tracked as **#266**, not by anything wrong with
the fixture — `test/SOUL.md` is a well-formed governance file. Gate on the
command running, emitting per-domain scores, and not regressing *further*;
do not "fix" this row by loosening the matcher, and re-baseline it upward when
#266 lands. The row above it (`secure test/fixtures/governed-mcp` → 96/100)
is the one that gates the clean-tree direction.

**Score sanity rule:** a score below 30 for a known-good project, or above 70
for a known-bad project, means the scoring is broken — investigate before
publishing. Do not publish a release where `"$BAD"` scores ≥ 70 (it carries a
credential at the scan root) or where `../ai-trust` scores < 30 (it is
intentionally clean).

---

## 4. Per-finding review protocol (MANDATORY — all surfaces above)

For every finding visible in every scan output during release testing, write a
one-line verdict against 5 questions. "Score sane, no crashes" is NOT a
verdict — the verdict is per-finding.

1. **Specificity** — Names WHAT specifically is wrong (file:line, capability
   name, secret type, masked preview).
2. **Action** — Fix line gives a runnable command or specific edit. Generic
   advice ("review this file") fails.
3. **Severity coherence** — Compare HIGH vs MEDIUM/LOW on the SAME file. HIGH
   must be at least as specific as MEDIUM. If a HIGH is vaguer than a MEDIUM,
   the severity model is broken.
4. **Internal consistency** — Findings on the same file tell a consistent story.
5. **CISO test** — A non-developer security manager understands what's wrong,
   what to do, why it matters.

**Verdict format:**

```
[surface] target → score N/100 — N findings reviewed:
  ✓ specific, ✗ action (fix command missing on CRED-EXFIL), ✓ severity-coherent, ✓ consistent, ✓ CISO-readable.
```

Fail the release if any finding gets two or more ✗ marks. A single ✗ on action
is acceptable only if the finding is INFO-severity and the resolution is
"read the docs." HIGH or CRITICAL findings must have a runnable fix command.

---

## 5. Telemetry (2 min)

**Do NOT point at the production endpoint while smoking.** Set the telemetry URL
to a port that refuses connections to prove fire-and-forget tolerance.

```bash
export OPENA2A_TELEMETRY_URL=http://127.0.0.1:1/never
unset OPENA2A_TELEMETRY
```

| # | Command | Expected |
|---|---|---|
| 5.1 | `node dist/cli.js -v` | Version line on **stdout** (`hackmyagent 0.x.x`, single line) + `Telemetry: on (opt-out: ...)` on **stderr**. `-v 2>/dev/null` shows only the version; `-v 2>&1 1>/dev/null` shows only the telemetry line. |
| 5.2 | `node dist/cli.js telemetry status` | Prints `state: on`, install_id, config path, toggle hint |
| 5.3 | `node dist/cli.js telemetry off` | Prints `Telemetry disabled for hackmyagent.` |
| 5.4 | `node dist/cli.js telemetry on` | Re-enables persistently |
| 5.5 | `OPENA2A_TELEMETRY=off node dist/cli.js telemetry status` | Shows `state: off` (env wins over file) |
| 5.6 | `OPENA2A_TELEMETRY_DEBUG=print node dist/cli.js secure "$BAD" 2>&1 \| grep opena2a:telemetry` | Shows JSON payload with `tool: "hackmyagent"`, `event: "command"`, `name: "secure"`, `success: true`, `duration_ms: <int>`. No PII fields (no file paths, no scan results, no credentials). |
| 5.7 | `node dist/cli.js secure "$BAD"` (with unreachable URL) | Command completes. Telemetry timeout must not delay the command by more than 2 s. |

`OPENA2A_TELEMETRY_URL` and `OPENA2A_TELEMETRY_DEBUG` are implemented in the
`@opena2a/telemetry` dependency, **not** in this repo's `src/`. Grepping `src/`
alone will wrongly suggest they do not exist. They work — 5.6 emits exactly the
allowlisted fields.

**5.6 targets `"$BAD"` on purpose — a findings-bearing scan is the path that
used to report nothing.** Tracked as **#297**, fixed in 0.25.2: the scan
commands used to call `process.exit(1)` when they found something, which
skipped the Commander `postAction` hook that fires `tele.track()`, so text,
SARIF and HTML mode emitted no telemetry at all on a findings-bearing scan and
only `--json` did. `finishWithFindings` is now the single ending for all five
branches. Measured on 0.25.2: text mode on `"$BAD"` emits exactly 1 event
carrying `success: true`. Empty output here is now a REGRESSION, not the old
known issue — it means a branch has gone back to hard-exiting. Guarded by
`__tests__/cli/telemetry-on-findings.test.ts`.

| # | Command | Expected |
|---|---|---|
| 5.8 | `OPENA2A_TELEMETRY_DEBUG=print node dist/cli.js secure "$BAD" --json 2>&1 >/dev/null \| grep -c opena2a:telemetry` | `1`. `--json` was the only findings-bearing path that reported before #297 landed; it must keep reporting alongside 5.6. If either 5.6 or 5.8 prints `0`, that branch has regressed onto `process.exit()` and telemetry is blind on it. |

Fail the release if:
- Version line omits the telemetry disclosure
- Debug-print payload contains file paths, env-var values, finding content, or
  any field outside: `tool`, `version`, `install_id`, `event`, `name`,
  `success`, `duration_ms`, `platform`, `node_major`
- Any command blocks > 2 s when the telemetry endpoint is unreachable

```bash
unset OPENA2A_TELEMETRY_URL   # restore after telemetry section
```

## 6. `--json` and `--ci` exit-code matrix (1 min)

After every release that touches exit codes, the router, or JSON output shape:

Capture the exit code from the command itself, never through a pipe — `cmd |
head; echo $?` reports `head`'s status and will read as a pass regardless of
what the CLI did.

```bash
# scan with findings → exit 1
node dist/cli.js secure "$BAD" --json > /tmp/smoke-bad.json; echo "exit: $?"
# Expected: exit 1, AND the payload must actually carry the findings:
node -e 'const j=require("/tmp/smoke-bad.json");
  const f=(j.findings||[]).filter(x=>!x.passed);
  if(!f.length) throw new Error("VACUOUS PASS: exit 1 with no findings");
  console.log("findings:", f.length, "score:", j.score)'

# scan of clean dir → exit 0
node dist/cli.js secure "$CLEAN" --json > /tmp/smoke-clean.json; echo "exit: $?"
# Expected: valid JSON object on stdout, exit 0

# not-found package → exit 1
node dist/cli.js check nonexistent-xyz-999999 --json > /tmp/smoke-404.json; echo "exit: $?"
# Expected: JSON with found: false or equivalent error shape, exit 1
```

**On the not-found exit code.** It is **1**, not 2. This is long-standing
behaviour — verified identical on published 0.24.0, 0.25.0 and 0.25.1 — and
other tests assert it. The previous "exit 2" line in this checklist was the
expectation that was wrong, not the code. Do not "fix" the CLI to match it.

### The `--ci` cells

This section was titled for `--ci` from the day it was written and contained no
`--ci` cell, which is how #454 shipped twice — closed 2026-08-10 as completed
with the defect fully live. `--ci` is an **output-mode** flag: it suppresses
prompts and turns contribution off. In `secure` and `fix-all` it **never**
changes the exit code. `scan-soul` is the deliberate exception (pre-existing,
#162/#206, not touched by #454): it additionally exits 1 under `--ci` on a
HIGH-severity SOUL finding that renders as a warning and passes CI without the
flag.

```bash
# 1. --ci does not move secure's exit code. Run each pair and compare.
#    A LOW-only tree exits 0 in BOTH channels; a critical/high tree exits 1 in both.
node dist/cli.js secure "$CLEAN" >/dev/null 2>&1; A=$?
node dist/cli.js secure "$CLEAN" --ci >/dev/null 2>&1; B=$?
node dist/cli.js secure "$BAD"   >/dev/null 2>&1; C=$?
node dist/cli.js secure "$BAD"   --ci >/dev/null 2>&1; D=$?
echo "clean: $A vs $B   bad: $C vs $D"
# Expected: $A -eq $B AND $C -eq $D. Any divergence is a contract break.
# A LOW-only tree exiting 1 under --ci means an any-finding gate was revived.

# 1b. scan-soul is the exception: an unrecognized --profile value is a HIGH
#     finding that gates the exit code ONLY under --ci. test/SOUL.md clears the
#     conformance gate on its own (exit 0, Level ESSENTIAL+), so this isolates
#     the profile gate specifically.
node dist/cli.js scan-soul test/                    >/dev/null 2>&1; E=$?
node dist/cli.js scan-soul test/ --profile bogus    >/dev/null 2>&1; F=$?
node dist/cli.js scan-soul test/ --profile bogus --ci >/dev/null 2>&1; G=$?
echo "soul: no-flag=$E  bad-profile=$F  bad-profile+ci=$G"
# Expected: $E -eq 0 (conformant tree, no --ci effect), $F -eq 0 (the marker-invalid
# finding is a warning outside --ci), $G -eq 1 (the same finding gates under --ci).
# G equal to F means the scan-soul exception silently stopped firing.

# 2. --ci turns contribution OFF even when the machine carries a prior opt-in.
#    Isolate HOME so the developer's real config is neither read nor written.
SMOKE_HOME=$(mktemp -d); mkdir -p "$SMOKE_HOME/.opena2a"
printf '{"contribute":{"enabled":true}}\n' > "$SMOKE_HOME/.opena2a/config.json"
HOME="$SMOKE_HOME" REGISTRY_URL=http://localhost:9 \
  node dist/cli.js secure "$CLEAN" --ci >/dev/null 2>&1
node -e 'const f=process.argv[1];const fs=require("fs");
  if(!fs.existsSync(f)){console.log("queued: 0");process.exit(0)}
  const q=JSON.parse(fs.readFileSync(f,"utf8"));
  const e=Array.isArray(q)?q:(q.events||[]);
  console.log("queued:", e.length);
  if(e.length) throw new Error("--ci did not disable contribution")' \
  "$SMOKE_HOME/.opena2a/contribute-queue.json"
# Expected: queued: 0. Repeat for scan-soul, the other command declaring --ci.
```

**Count the queue correctly.** The queue file is an object `{"events":[…]}`, not
a bare array. A counter written as `Array.isArray(q)?q.length:0` reports **0**
for every run and reads as a permanent pass — it silently inverted this exact
measurement once already.

**Do not use a dead sink at `127.0.0.1`.** `REGISTRY_URL` is validated: only
`https://` and `http://localhost` are accepted, so `http://127.0.0.1:9` aborts
the run before it scans and every cell reads exit 1.

---

## 6.5 Deep-scan verdict and MCP root confinement (4 min)

New in 0.29.0. Both were shipped defects that no smoke step could have caught,
which is why they are steps now rather than a note.

**Exit 2 means the run reached no verdict.** `secure --deep` no longer reports a
pass for a scan it could not finish. Drive Layer 3 with a stub so the check does
not depend on a live model or a key:

```bash
cat > /tmp/smoke-stub.cjs <<'EOF'
const S = process.env.HMA_SMOKE_REPLY;
globalThis.fetch = async () => ({ ok: true, status: 200,
  json: async () => ({ content: [{ type: 'text', text: S }],
                       usage: { input_tokens: 10, output_tokens: 5 }, model: 'stub' }),
  text: async () => '{}' });
EOF

# A readable reply carrying a CRITICAL -> exit 1
HMA_SMOKE_REPLY='[{"line":1,"type":"Password","severity":"critical","description":"x","rationale":"y"}]' ANTHROPIC_API_KEY=stub NODE_OPTIONS="--require /tmp/smoke-stub.cjs"   node dist/cli.js secure "$BAD" --deep >/dev/null 2>&1; echo "readable: exit $?"     # expect 1

# A reply that cannot be read -> exit 2, NOT 0
HMA_SMOKE_REPLY='I am unable to complete this analysis.' ANTHROPIC_API_KEY=stub NODE_OPTIONS="--require /tmp/smoke-stub.cjs"   node dist/cli.js secure "$CLEAN" --deep 2>&1 | grep -c 'not analyzed'              # expect >= 1
HMA_SMOKE_REPLY='I am unable to complete this analysis.' ANTHROPIC_API_KEY=stub NODE_OPTIONS="--require /tmp/smoke-stub.cjs"   node dist/cli.js secure "$CLEAN" --deep >/dev/null 2>&1; echo "unreadable: exit $?" # expect 2

# --ignore must NOT launder it back to a pass
HMA_SMOKE_REPLY='I am unable to complete this analysis.' ANTHROPIC_API_KEY=stub NODE_OPTIONS="--require /tmp/smoke-stub.cjs"   node dist/cli.js secure "$CLEAN" --deep --ignore SEM-LLM-NOT-ANALYZED >/dev/null 2>&1; echo "ignored: exit $?"  # expect 2
```

**A fresh fixture per case.** The Layer 3 cache is keyed on file CONTENT, so
reusing one fixture across replies replays the first reply's parsed result and
every later row silently measures nothing. That happened during the 0.29.0 gate.

**MCP confinement runs through the WALK, not just the argument.** The escape that
shipped was a link at a name discovery looks for, with the root itself as the
argument — not a hostile path passed in:

```bash
B=$(mktemp -d); mkdir -p "$B/project" "$B/outside"
printf 'AWS_SECRET_ACCESS_KEY=SMOKE_CANARY\n' > "$B/outside/real.env"
ln -s "$B/outside/real.env" "$B/project/.env"
printf '{}' > "$B/project/mcp.json"
node -e '
const {handleToolCall}=require("./dist/mcp-server.js");
(async()=>{const r=await handleToolCall("hackmyagent_deep_scan",{directory:process.argv[1]},[process.argv[1]]);
 const t=r.content[0].text;
 if(/SMOKE_CANARY/.test(t)) throw new Error("LEAK: out-of-root bytes in the tool result");
 const j=JSON.parse(t);                       // must still be valid JSON when withholding
 if(!(j.notRead||[]).some(n=>n.path===".env")) throw new Error("withheld file not disclosed");
 console.log("confined, disclosed, parseable");})()' "$B/project"
rm -rf "$B"
```

Fail the release if: the unreadable reply exits 0, `--ignore` returns it to 0,
the canary appears in the tool result, the result stops parsing as JSON, or a
withheld file is dropped without being named.

---

---

## 7. Cleanup

```bash
unset OPENA2A_TELEMETRY_URL
# Restore your real telemetry config if the telemetry tests overwrote it:
# rm ~/.config/opena2a/telemetry.json  (or restore from backup)
```

---

## When this checklist isn't enough

- If the diff touches any analyzer, scanner pattern, severity threshold, or
  scoring weight: spawn an adversarial subagent review per CLAUDE.md
  "Adversarial self-review for detection changes" before declaring done.
- If HMA's self-scan score jumps > 20 points: classify each fix as FP-suppress
  (clean), detection-narrowing (suspicious), or rename-workaround (suspicious).
  Only FP-suppress is clean.
- If the diff touches `trust` or `check` and the registry API contract: re-run
  the full surface coverage matrix, not just the changed surface.
- If a regression ships that would have been caught by an item NOT on this list:
  add the item here as part of the fix. Don't ship a fix without growing the
  smoke.

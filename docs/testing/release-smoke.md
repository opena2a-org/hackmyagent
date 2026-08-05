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

---

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

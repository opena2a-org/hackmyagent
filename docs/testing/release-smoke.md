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

# Core scan — local directory
$HMA secure test/hma/
$HMA secure test/hma/ --json | head -5   # must be valid JSON object on line 1

# Governance
$HMA scan-soul test/hma/                     # SOUL.md compliance score
$HMA harden-soul --dry-run /tmp/test-dir     # dry-run: no write to disk

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
| Local repo (clean) | `../ai-trust` or `../secretless` | 60–90 |
| Empty dir | `$(mktemp -d)` | ~95–98 (`.gitignore` LOW only) |
| Standalone SOUL.md | `test/hma/SOUL.md` via `scan-soul` | 100/100 HARDENED |
| npm package | `node dist/cli.js check express` | ≥ 95 |
| PyPI package | `node dist/cli.js check pip:requests` | ~90 |
| GitHub repo | `node dist/cli.js check getsentry/sentry-mcp` | varies |
| Skill | `node dist/cli.js check skill:opena2a/code-review-skill` | varies |
| MCP server | a real MCP repo (e.g. `../hma-test/ibm-mcp`) | 70–90 |
| A2A agent | `../a2a-security-examples/examples/secure-agent-card` | 80–90 |

**Score sanity rule:** a score below 30 for a known-good project, or above 70
for a known-bad project, means the scoring is broken — investigate before
publishing. Do not publish a release where `test/hma/` scores ≥ 70 (it is
intentionally vulnerable) or where `../ai-trust` scores < 30 (it is
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
| 5.6 | `OPENA2A_TELEMETRY_DEBUG=print node dist/cli.js secure test/hma/ 2>&1 \| grep opena2a:telemetry` | Shows JSON payload with `tool: "hackmyagent"`, `event: "command"`, `name: "secure"`, `success: true`, `duration_ms: <int>`. No PII fields (no file paths, no scan results, no credentials). |
| 5.7 | `node dist/cli.js secure test/hma/` (with unreachable URL) | Command completes. Telemetry timeout must not delay the command by more than 2 s. |

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

```bash
# scan with findings → exit 1
node dist/cli.js secure test/hma/ --json; echo "exit: $?"
# Expected: valid JSON object on stdout, exit 1 (critical/high findings)

# scan of clean dir → exit 0
node dist/cli.js secure $(mktemp -d) --json; echo "exit: $?"
# Expected: valid JSON object on stdout, exit 0

# not-found package → exit 2
node dist/cli.js check nonexistent-xyz-999999 --json; echo "exit: $?"
# Expected: JSON with found: false or equivalent error shape, exit 2
```

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

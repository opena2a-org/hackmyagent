# HMA CISO-grade UX rework

Date: 2026-04-16
Branch: feat/eval-oracle-harness — commit 8d13d07 (B1/B2/B3/B4/B5/B6/B7 + U1/U2/U3/U5 landed) + B4-followup (AnaLM render cleanup)
Status: ALL BUGS FIXED. 1619/1619 tests green (incl. 16 new analyst-render tests), 12/12 benign FPR. Ready for /pre-push-review.
Scope: hackmyagent CLI output, governance analyzer, fix messaging

## What prompted this

After shipping commit `ae7cbb2` ("detect matches secure/check + env-var shame removed"), the
user walked through real-world fixtures and surfaced bugs + UX gaps that ship-blockers.
Commit `ae7cbb2` addressed the surface (visual parity, shame language) but missed several
structural problems underneath.

## Bugs (root cause, not cosmetic)

### B1 — SOUL.md doesn't propagate to sibling artifacts

**Symptom.** User runs `hackmyagent harden-soul /tmp/hma-real-world/ibm-mcp`. 9 sections, 72
controls added. Then runs `hackmyagent check ... --analm` and STILL sees on `mcp.json`:
- "0 governance constraint(s)"
- "Critical Governance Domain Gap"
- "No Governance Constraints"
- "Missing governance domains"

The user did exactly what we told them. The scan makes it look like `harden-soul` did nothing.

**Root cause.** The governance analyzer (`src/nanomind-core/analyzers/governance-analyzer.ts`
and `capability-analyzer.ts`) analyzes each artifact in isolation. `mcp.json` and `SOUL.md`
are separate `ASTNode`s. Constraints declared in SOUL.md are not propagated to `mcp.json`
findings, even though a SOUL.md in the project root governs every artifact in that project.

**Fix.** At the compiler or analyzer entry point, build a project-level constraint set from any
`SOUL.md` / `CLAUDE.md` / `.opena2a/policy.*` in the target directory and merge it into each
artifact's `declaredConstraints` before running AST-GOV-* / AST-GOVERN-* checks. `harden-soul`
+ re-scan MUST show measurable improvement.

**Test.** Add a fixture at `test/fixtures/governed-mcp/` with a real SOUL.md next to an
mcp.json. Expected: AST-GOV-003 does NOT fire. Add regression test so the benign-FPR suite
covers this flow.

### B2 — "AIM vault" claim is false

**Symptom.** Fix message says: `Fix: opena2a protect .  — scans for hardcoded secrets and
encrypts them into a secure vault (keychain, 1Password, or AIM vault). Keys are injected at
runtime, never stored as plaintext.`

**Root cause.** `opena2a protect` uses Secretless (verified against
`opena2a/packages/cli/src/commands/protect.ts`). Real backends: local Secretless vault
(`~/.secretless-ai/`), macOS keychain, 1Password, HashiCorp Vault, GCP Secret Manager.
There is no "AIM vault" — AIM is for agent identity, not secret storage. I wrote this
without verifying, across 7+ fix strings in `src/hardening/scanner.ts` and
`src/nanomind-core/analyzers/`. This is a Data Integrity violation.

**Fix.** Single canonical Fix string, verified:
```
opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.
```
Replace everywhere `replace_all`.

### B3 — Broken fix text on AST-SCOPE-001 "Full Wildcard Tool Access"

**Symptom.**
```
│ CRITICAL  Full Wildcard Tool Access
│ Fix: : Wildcard access: mcp.core-cs-mcp-server.* (scope: core-cs-mcp-server)
```
Leading `: ` and the "fix" just restates the finding.

**Root cause.** `src/nanomind-core/analyzers/scope-analyzer.ts` around line 87 constructs the
fix string from a conditional where `isFullWildcard` is true, but the template likely does
`"${prefix}: ${detail}"` with empty `prefix`.

**Fix.** Make the fix actionable: replace the wildcard `*` with an explicit allowlist in
`mcp.json`. Concrete example inline. Reference `opena2a mcp audit` for help choosing which
tools to keep. Drop the leading `:`.

### B4 — AnaLM output dumps raw markdown as Fix: bullets

**Symptom.**
```
LOW
## Analysis

This artifact is a configuration file for an MCP ...
Fix: **No executable payloads**: The artifact contains only static config...
Fix: **Legitimate tool scope**: ...
Fix: **No malicious indicators**: ...
```

The "Fix:" lines are not fixes — they are analysis bullets labeled as fixes. Raw markdown
`##` header bleeds into the terminal output.

**Root cause.** `src/cli.ts` (AnaLM rendering block around the `analystFindings` branch)
treats each `mitigation` entry from the Analyst response as a Fix line. The Analyst v0.1.0
returns analysis prose in the mitigation slots when the artifact is benign.

**Fix.** Separate `analysis` from `remediations` in the Analyst schema. Only render
`remediations` under `Fix:`. Render `analysis` under a distinct `Why:` or drop entirely if
the verdict is benign. Strip Markdown headers from terminal output. Cap analysis prose at
~240 chars with a "see --verbose for full analysis" tail.

### B4-followup — orphan NONE badge, empty attackVector, markdown artifact, abrupt trail-off

Surfaced 2026-04-16 while running `opena2a-cli check /tmp/hma-real-world/ibm-mcp/ --analm`.
The B4 fix landed in 8d13d07 but the rendering block still had four residual bugs:

1. A threatAnalysis with `threatLevel === 'NONE'` still printed the bare level badge
   (guard on line 962 only suppressed the description, not the level line).
2. When the model returned an empty `attackVector`, the level line rendered with trailing
   whitespace and no context: `CRITICAL  `.
3. Stripping only the `#` chars from `## Analysis\n\nThis artifact...` left "Analysis" on
   its own orphan line above the real prose. Header *lines* should be dropped, not just
   the leading `#` chars.
4. The 160-char cap ended with `...` and no escape hatch — users hit the trail-off and
   assumed the tool was broken.

**Root cause (same file, same block).** `src/cli.ts` AnaLM render only suppressed the
description body when `isLow`, never the whole entry. The header-strip regex was
`^#{1,6}\s+` which removes the hashes but keeps the header text on the next line.

**Fix.** Extracted the two transformations into `src/output/analyst-render.ts` as pure
helpers (`isRenderableAnalystFinding`, `formatAnalystDescription`) so the cleanup is
unit-testable. Pre-filter now drops isLow/low-confidence entries before the divider even
prints — no empty sections. Description pipeline drops whole header lines, collapses
blank lines to an em-dash separator, collapses single newlines to spaces, bumps the cap
to 240 chars, and appends `(run with --verbose for full analysis)` when truncated.
`--verbose` emits the full untruncated prose. 16 regression tests in
`__tests__/output/analyst-render.test.ts` covering every case including the real-world
reproducer.

### B5 — `opena2a mcp audit` dead-ends with no Next Steps

**Symptom.**
```
MCP Server Audit
==================================================
No MCP server configurations found.
Checked locations: ...
```
No path forward. Violates "no dead ends" rule.

**Fix.** When no configs found, output Next Steps:
- `opena2a init-mcp` (or whatever the scaffolding command is)
- `opena2a --help` for full command list
- Link to docs on setting up MCP

### B6 — `detect` shows "Claude Code ungoverned" with no inline fix

**Symptom.** In `detect` output:
```
── Running AI Agents (1) ───────────────────────
Claude Code           ungoverned
```

User can't tell from this line alone HOW to govern Claude Code. The `harden-soul` hint is in
the `Findings` section and `Next Steps`, but visually disconnected.

**Fix.** Append inline remediation to every `ungoverned` line:
```
Claude Code           ungoverned  →  hackmyagent harden-soul .
```
Same treatment for any HIGH/CRITICAL MCP server in the Project-local list.

### B7 — Fix commands not visually prominent enough

**Symptom.** In a finding block:
```
│ MEDIUM  Credentials in Non-Environment Context
│ mcp.json
│ Hardcoded credentials are exposed through ...
│ Fix: opena2a protect .  — scans for hardcoded secrets ...
```
The "Fix:" line has the same visual weight as the surrounding narrative. A CISO scanning a
200-line report needs their eye to land on the action.

**Fix.** Bold the command itself in a color tier brighter than the prose (e.g. bright-cyan
bold for commands, dim for description). Consider a leading `→` or `▶` glyph on the Fix line
to signal action. Never change Fix line location within a finding block (consistency matters).

## UX gaps (CISO audience)

### U1 — Every finding needs a business-impact line

**Today.** "Missing injection resistance constraint."

**Target.** "Missing injection resistance constraint. An attacker who controls a retrieved
document or tool output can override your agent's instructions — exfiltrating customer data
or pivoting to your infrastructure."

CISOs make risk decisions, not code reviews. Every HIGH/CRITICAL finding needs one non-jargon
sentence explaining what goes wrong in production if the issue is not fixed.

### U2 — Next Steps always includes `--help`

Discoverability matters when users first encounter the tool. The last line of every Next
Steps block should be:
```
See all commands:  hackmyagent --help
```

### U3 — Collapse message names what's collapsed

**Today.** `+1 more medium  (run with --verbose to see all)`

**Target.** `+1 more similar governance gap in SOUL.md  (run with --verbose to see all)`

### U4 — The harden-soul → scan feedback loop must close

Once B1 is fixed, running `harden-soul .` then `scan` should show:
- Governance score moves up (measurably)
- The AST-GOV-* findings that B1 would have fired previously now pass
- A celebratory line: "Governance: +42 recovered from harden-soul"

### U5 — "run with --verbose to see all" must only appear when there IS more

Currently prints even when nothing more exists. Gate on `remaining > 0`.

## Memory updates (add before starting)

### feedback_cli_ciso_philosophy.md (new)

```markdown
---
name: HMA/opena2a CLI — CISO-grade UX philosophy
description: Every CLI output must empower action, not shame. CISOs scan for business impact + action. Findings without commands are dead ends.
type: feedback
---

Output for HMA, opena2a, and every security tool in the OpenA2A ecosystem must follow these rules. A CISO reading the output in 30 seconds must be able to decide what to do next.

## Rules

1. **No dead ends.** Every output state (empty result, zero findings, error) has Next Steps. No exceptions.
2. **Every finding has Fix: COMMAND — DESCRIPTION.** The command comes first (so the user's eye lands on action). The description explains what the command does.
3. **Fix commands are visually prominent.** Bold + bright color tier above surrounding narrative text. A CISO skimming should spot the actions.
4. **Every HIGH/CRITICAL finding has a business-impact line.** "What goes wrong in production if this is not fixed?" in CISO language, not engineer language.
5. **The fix loop must close.** If Fix says "run X", then running X and re-scanning must show measurable improvement. If the fix has no visible effect, the finding is a dead end.
6. **Verify every claim in Fix text.** If I write "encrypts into Secretless/Keychain/1Password", those backends must actually exist and be the real behavior. No aspirational descriptions.
7. **Next Steps always includes `--help`.** Discoverability for first-time users.
8. **Collapse messages name what's collapsed** ("+3 more credential findings in src/"), not just counts.
9. **`run with --verbose` suffix only prints when more exists.** Never on a complete view.
10. **Empower, never shame.** No FUD, no punitive grades. "27 → 71 by fixing credentials" not "27/100 F".

**Why:** A CISO audience has zero patience for tech jargon, dead-end findings, or tools that scold without teaching. If our output looks like compliance theater, they close the terminal. If it looks like a path forward, they act.

**How to apply:** Before shipping any CLI output change, answer: (1) What does a CISO do with this? (2) Can they do it from the text alone? (3) Did the described fix actually move the score? If any answer is "no", rework.
```

## Order of operations

1. Land memory update first (so next session reads it before coding).
2. Fix B2 (vault claim) — single replace_all, low risk, correctness issue.
3. Fix B1 (SOUL propagation) — structural, needs test fixture.
4. Fix B3 (wildcard fix text) — isolated scope-analyzer change.
5. Fix B4 (AnaLM output format) — cli.ts rendering + possibly Analyst schema.
6. Fix B5 (mcp audit dead-end) — in opena2a-cli, not HMA.
7. Fix B6, B7 (detect inline fix + color tier) — detect.ts + cli.ts.
8. U1 (business-impact lines) — systematic pass across all HIGH/CRITICAL findings.
9. U2–U5 (Next Steps help, collapse names, verbose gate, feedback loop) — sweeps.
10. Re-run full new-user walkthrough on all 9 fixtures. Compare output to this brief.
11. Only then commit + pre-push-review + push.

## Tests that must stay green

- 1600/1600 unit tests (`npm test`)
- 11/11 benign FPR regression (`npx vitest run __tests__/nanomind-core/benign-fp-regression.test.ts`)
- Add new: governed-mcp fixture test (no AST-GOV-003 when SOUL.md sibling exists)
- Add new: post-harden-soul re-scan shows score improvement

## Constraints

- Branch `feat/eval-oracle-harness` is already 9 commits ahead; DO NOT rebase or force-push.
- opena2a-cli is the umbrella tool; reserve hackmyagent commands for attack/wild/red-team/analm/eval/explain.
- No emojis, no marketing language, camelCase JSON.
- "move to env var" is NEVER the right credential fix — always `opena2a protect .`.

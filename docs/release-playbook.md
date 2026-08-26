# `hackmyagent` real-world walkthrough — release playbook

Run this playbook before every publish of `hackmyagent`.

**Scope — v1 (this document):** `repo`, `skill`, and `mcp` surfaces, plus
universal baselines (intentionally-vulnerable fixture, hardened SOUL.md,
empty dir). **Deferred to v2:** `a2a`, `npm`, `pypi`, `github-repo`, `url`,
and standalone `soul.md` surfaces. Bugs already known on those surfaces live
in `briefs/release-findings.md` with a `Status: DEFERRED (awaiting v2
scenario)` tag.

This playbook exists because per-finding review surfaces bugs that
generic surface walkthroughs miss. A 2026-04-17 review of release
candidate `6b788c4` (self-scan score 100/100, all surfaces "no crashes")
produced 7 real bugs once we walked every finding against the 5-question
rubric. Making the playbook non-skippable is how we stop re-discovering
the same class of FP every publish.

Background philosophy (test pyramid, per-finding rubric, adversarial review)
lives in `CLAUDE.md`. This file only captures the scenario catalog and the
grading rubric unique to real-world testing.

## Triggers

Run this playbook when the diff modifies any of:

- `src/hardening/scanner.ts`
- `src/nanomind-core/**` (analyzers, fix generator, intent-confidence)
- `src/hardening/analyzers/**`
- `src/hardening/score.ts` or any severity/scoring weight
- `src/**/credential-patterns*.ts` or `src/hardening/patterns.ts`
- Any file under `src/hardening/rules/`

Do NOT skip because "the diff looks small." A one-character regex change in a
credential pattern is still a trigger.

## Setup

```bash
cd ~/workspace/opena2a-org/hackmyagent
npm run build            # produces dist/cli.js — MUST rebuild per run
```

Canonical real-world fixtures live at `/tmp/hma-real-world/`. They are
intentionally representative of user-hit shapes. **Never run HMA against the
canonical fixtures directly — copy first.** Some (e.g. `mega-mcp`) are
already polluted from prior runs; replace from source-of-truth in the
workspace playground at `~/workspace/opena2a-org/test/hma/` (see below — it is
NOT in this repo) or re-pull if needed.

```bash
rm -rf /tmp/walk-<N> && cp -r /tmp/hma-real-world/<fixture> /tmp/walk-<N>
node dist/cli.js secure /tmp/walk-<N>
```

Record: HMA version under test, commit SHA, and any uncommitted state
(`git status`). These land in `briefs/release-findings.md` alongside any new
findings.

## Universal baselines (run EVERY time)

These three scenarios are not surface-specific. They verify detection health
and must pass before touching the per-surface scenarios.

### B1 — intentionally vulnerable baseline

**Fixture.** `~/workspace/opena2a-org/test/hma/` — the **workspace-level**
playground, NOT a path in this repo. A clean clone does not contain it, and
`secure` on a missing directory exits 1 with `Error: Directory ... does not
exist.`, which is indistinguishable by exit code alone from "found findings".
Confirm the directory exists before grading. Intentional: fake credentials in
`.env`, unsafe `mcp.json`, prompt-injection SOUL.md, unsigned skill, etc.

**Command.** `node dist/cli.js secure ~/workspace/opena2a-org/test/hma/`

**Grade.**
- Score MUST be `0/100` or very close.
- MUST fire at least 36 CRITICAL and 49 HIGH findings (see
  `~/workspace/opena2a-org/test/hma/README.md` for the file → check-ID map).
- Any regression where score exceeds 20 or CRITICALs drop below 30 means
  detection was narrowed — investigate which rule weakened.

**Baseline provenance (measured 2026-07-28, same fixture, `--json`, counting
`!passed`).** The floors above are the 0.25.x measurement, not a target:

| version | score | critical | high | medium | low | total |
|---|---|---|---|---|---|---|
| 0.24.0 | 0 | 34 | 48 | 28 | 1 | 111 |
| 0.25.0 | 0 | 36 | 49 | 28 | 2 | 115 |
| 0.25.1 | 0 | 36 | 49 | 28 | 2 | 115 |

The floors previously read "34 CRITICAL and 55 HIGH". The 55 was stale — no
version in this table reaches it, and the trend across them is strictly
upward, so it was an old baseline rather than evidence of narrowing. Re-measure
and update this table on any release that moves the counts, and treat a
*downward* move as a narrowing until proven otherwise.

**Failure class.** CRITICAL. Detection-health regression on the canonical
vulnerable fixture is the worst class of release bug — it ships a scanner
that does not scan.

### B2 — hardened SOUL.md via scan-soul

**Command.** `node dist/cli.js scan-soul ~/workspace/opena2a-org/test/hma/SOUL.md`

**Grade (measured 2026-07-28 on 0.25.1).**
- Score is `74/100`, reported as `(scope: 4/9 domains) (score clamped from 100
  to 74 -- 1 HIGH unaddressed)`.
- Output MUST show the clamp and the scope, not a bare number.

**This row previously demanded `100/100 HARDENED`, and that expectation was
stale in two ways.** Both are current correct behaviour, not regressions:

1. The fixture's SOUL.md declares `<!-- soul:profile=conversational -->`, so
   only 4 of 9 domains are evaluated — Trust Hierarchy, Capability Boundaries,
   Data Handling, Agentic Safety and Human Oversight are skipped. An
   unqualified "100/100" over a self-declared 4/9 scope is precisely the
   attacker-controllable-profile shape that #216 was filed against; the
   scanner now discloses the scope instead of hiding it.
2. The remaining HIGH triggers the #259 verdict-band clamp, so 100 becomes 74.

**Failure class.** CRITICAL if the *scope and clamp disclosure disappears*, or
if the score moves without a corresponding scanner change. A bare `100/100` on
this fixture is now a FAILURE, not a pass — it would mean the profile scope or
the clamp stopped being applied.

### B3 — empty directory

```bash
rm -rf /tmp/walk-empty && mkdir -p /tmp/walk-empty
node dist/cli.js secure /tmp/walk-empty
node dist/cli.js secure /tmp/walk-empty --json \
  | jq '{score, na: ([.allFindings[] | select(.notApplicable)] | length), passed: [.allFindings[] | select(.passed == true) | .checkId]}'
```

**Grade.**
- Score MUST be `93/100`. The only scored findings are LOW `GIT-001` (missing
  `.gitignore`) and MEDIUM `DEP-001` (no lock file; `file` is
  `package-lock.json`, the path the fix creates). `SANDBOX-001` (`file`
  `Dockerfile`) fails in `allFindings` but is out of scope for the `library`
  project type, so it is neither shown nor scored.
- The human output MUST list exactly those two findings.
- `na` MUST be `13`: a check whose subject is absent records
  `notApplicable: { subject, reason }` instead of a pass or a failure (#458).
  No not-applicable record may carry `severity` or `passed`, and none may
  appear in the human output.
- `passed` MUST be exactly the six hazard probes that pass on not-there:
  `CRED-002`, `LOG-003`, `MCP-010`, `PERM-001`, `PERM-002`, `PERM-003`. Any
  other check passing on an empty directory means a subject read was replaced
  by a default and the false-pass class #458 removed is back.
- Any HIGH or CRITICAL on an empty directory means a check is firing on
  absence of input instead of presence of problem.

**Failure class.** HIGH if any HIGH/CRITICAL fires or any other check passes.
MEDIUM if the score moves without a scanner change, or a not-applicable record
carries a severity, carries `passed`, or reaches the human output.

## Surface — `repo`

Scanning a real project directory with source, tests, and build output.

### R1 — sibling tool: ai-trust (expected clean)

**Command.** `node dist/cli.js secure ../ai-trust`

**Grade.**
- Score MUST be `60-90`.
- Any finding on `__tests__/`, `dist/`, or `build/` that requires user
  action is a false positive unless it's a real credential leak.
- HIGH findings MUST each satisfy the 5-question per-finding review (see
  CLAUDE.md §Per-finding review protocol). A HIGH less specific than a
  MEDIUM on the same file is a severity-coherence bug.

**Failure class.** CRITICAL if score < 30 (known-good scored as known-bad).
HIGH if > 2 FPs on `dist/` or test files (detection not path-aware).

### R2 — sibling tool: secretless (currently broken — bugs #6, #7)

**Command.** `node dist/cli.js secure ../secretless`

**Grade.**
- Score MUST be `60-90`. Currently `30/100` with 3 CRITICAL.
- 2 of the 3 CRITICALs are `WEBCRED-001` on `dist/patterns.js` and
  `dist/scan.js` — the compiled bundle contains the scanner's own credential
  patterns. MUST be suppressed by default path-skip on `dist/`, `build/`,
  `out/`.
- 19 HIGH findings on `*.test.ts` files are `NEMO-007` firing on test files
  that deliberately contain what they test. Severity must be softened on
  non-prod paths, OR test paths must be skipped.

**Failure class.** HIGH. Tracked as bugs #6 (dist/) and #7 (tests) in
`briefs/release-findings.md`.

### R3 — nanomind training corpus (currently broken — bug #5)

**Command.** `node dist/cli.js secure ../nanomind`

**Grade.**
- Score MUST reflect the actual governance posture of the repo, NOT be
  dragged to near-zero by `UNICODE-STEGO-001` firing 42 CRITICAL times on
  `training/corpus/pretrain/*.json`.
- Training corpora contain adversarial Unicode intentionally — the model
  learns from them. `**/training/corpus/**` and `**/datasets/**` paths MUST
  be exempt (or gated behind a `--corpus-mode` flag that the user opts
  into).

**Failure class.** HIGH. Tracked as bug #5. Also exposes a product-shape
question: should HMA have a per-directory-role awareness (src vs corpus vs
test) or is that out of scope? Chief decision pending.

## Surface — `skill`

Scanning a Claude/Cursor/IDE skill directory (contains `SKILL.md` and
supporting files).

### SK1 — real Claude skill: anthropic example

```bash
rm -rf /tmp/walk-skill-anthropic
cp -r /tmp/hma-real-world/anthropic-skill /tmp/walk-skill-anthropic
node dist/cli.js secure /tmp/walk-skill-anthropic
```

**Grade.**
- Score MUST be `70-95`.
- No CRITICAL on documentation that *describes* dangerous patterns without
  invoking them.
- HIGH findings MUST be specific to actions the skill takes, not mentions of
  danger words.

**Failure class.** HIGH if any CRITICAL fires on a pattern that the skill
merely names in prose.

### SK2 — real skill with pattern documentation (currently broken — bug #4)

**Command.** `node dist/cli.js secure ~/workspace/claude-skills/skills/pre-push-review`

**Grade.**
- Score MUST be `70-95`. Currently `45/100`.
- `SKILL-010` firing CRITICAL on the documentation line
  `Patterns: .env, .pem, .key, .p12…` is a false positive. The skill does
  not READ these paths — it lists them as patterns to scan for.
- Rule MUST require actual access (`process.env.X`, `fs.readFile('*.env')`,
  shell `cat .env`), not keyword match.

**Failure class.** HIGH. Tracked as bug #4 in `briefs/release-findings.md`.

### SK3 — composio skill with markdown-embedded code

```bash
rm -rf /tmp/walk-skill-composio
cp -r /tmp/hma-real-world/composio-skill /tmp/walk-skill-composio
node dist/cli.js secure /tmp/walk-skill-composio
```

**Grade.**
- MUST detect the hardcoded `api_key="comp_fake_..."` inside the Python
  code block inside `SKILL.md`.
- Fix suggestion MUST be actionable and specific (e.g. `opena2a protect .`
  or a specific edit). Generic "move to env var" fails.

**Failure class.** CRITICAL if detection misses the credential. HIGH if
detected but Fix is generic.

## Surface — `mcp`

Scanning a local directory that contains `mcp.json` (MCP server config).

### M1 — real MCP: ibm-mcp baseline

```bash
rm -rf /tmp/walk-mcp-ibm
cp -r /tmp/hma-real-world/ibm-mcp /tmp/walk-mcp-ibm
node dist/cli.js secure /tmp/walk-mcp-ibm
```

**Grade.**
- Score baseline is `82/100` (last measured).
- MUST detect the vendor-prefixed key (`ibm-api-...`) assigned to
  `WATSONX_API_KEY` inside `mcp.json`. A miss here is the CRED-004
  JSON-quoted-key bug from the protect walkthrough and must not resurface in
  HMA's own detection.
- `AST-SCOPE-003` / `AST-SCOPE-004` findings MUST name the specific
  capability (e.g. `shell-exec`) in the Fix, not say "Align capabilities
  with the declared purpose." This was bug #1; the fix (fix-generator.ts
  using `finding.fix`) must still hold.

**Failure class.** CRITICAL if credential miss. HIGH if scope findings
revert to generic prose.

### M2 — mega-mcp already-secure

**Note.** `/tmp/hma-real-world/mega-mcp` is pre-polluted from prior runs.
Restore from the `~/workspace/opena2a-org/test/hma/` pattern (workspace
playground, not this repo) or skip until a clean source-of-truth is re-pinned.

**Grade (when re-pinned).**
- Score MUST be `80-100`.
- No credential findings (all values are `${VAR}` placeholders).
- Output MUST tell the user what hardening WAS applied if any — no
  silent-success dead ends.

**Failure class.** HIGH. Currently DEFERRED until fixture is re-pinned.

### M3 — ssh-mcp (path false-positive negative case)

```bash
rm -rf /tmp/walk-mcp-ssh
cp -r /tmp/hma-real-world/ssh-mcp /tmp/walk-mcp-ssh
node dist/cli.js secure /tmp/walk-mcp-ssh
```

**Grade.**
- MUST NOT flag `"SSH_KEY_PATH": "/home/user/.ssh/id_rsa"` as a credential.
  A path is not a key.
- Any credential finding here is a detection-widening regression.

**Failure class.** CRITICAL. Detection widening on a negative case is how
tools become noisy and get ignored.

## Surface coverage matrix — v1

| Surface | Covered in v1? | Scenario IDs | Known bugs |
|---|---|---|---|
| Repo (local) | YES | R1, R2, R3 | #5, #6, #7 |
| Skill | YES | SK1, SK2, SK3 | #4 |
| MCP (local) | YES | M1, M2 (deferred fixture), M3 | — |
| A2A | v2 | — | #2, #3 |
| npm (`check <pkg>`) | v2 | — | — |
| PyPI (`check pip:<pkg>`) | v2 | — | — |
| GitHub repo (`check <org>/<repo>`) | v2 | — | bug #1 regression check only |
| URL (`check <url>`) | v2 | — | — |
| Standalone SOUL.md (`scan-soul`) | v1 baseline only | B2 | — |

Score sanity rule (applies to every scenario): score < 30 on a known-good
target or > 70 on a known-bad target means scoring is broken — investigate
before publish.

## Per-finding review protocol

Apply the 5-question review from `CLAUDE.md` §Per-finding review protocol to
EVERY finding surfaced by EVERY scenario above. Not "did the CLI crash" —
per-finding verdicts.

Compact format:
```
[surface] target → score N/100 — M findings reviewed: ✓ specific, ✗ action, ✓ severity-coherent (HIGH X is vaguer than MEDIUM Y).
```

Failures:
- Specificity fail → at minimum MEDIUM, log in findings brief.
- Action fail (generic advice) → HIGH.
- Severity-coherence fail (HIGH vaguer than MEDIUM on same file) → HIGH,
  blocks release.
- CISO test fail → HIGH.

## Classification rule — what blocks publish

- **CRITICAL**: detection miss on B1/B2/M1 credential or scope case;
  detection widening on M3 negative case; score > 20 on B1 or < 90 on B2.
  Blocks publish.
- **HIGH**: per-finding review failure (severity incoherence, dead-end fix);
  score outside the expected band by > 20 points on any scenario; score
  regression > 20 points vs the last passing release on the same scenario.
  Blocks publish.
- **MEDIUM**: score drift 10-20 points, formatting issue, Fix line present
  but generic. Does NOT block current release; fix before next.
- **LOW**: polish. Batch.

## Self-learning loop (MANDATORY — this is how the playbook grows)

Five mechanisms, none optional:

### 1. Baseline ledger — `.release/baselines.json`

Every passing run writes measured scores and finding counts to
`.release/baselines.json` keyed by scenario ID. Next run compares.

```json
{
  "B1": {"score": 0, "critical": 34, "high": 55, "commit": "<sha>", "updatedAt": "<date>"},
  "M1": {"score": 82, "critical": 0, "high": 3, "commit": "<sha>", "updatedAt": "<date>"},
  "R2": {"score": 30, "critical": 3, "high": 19, "commit": "<sha>", "updatedAt": "<date>", "note": "BROKEN — bugs #6, #7"}
}
```

Drift > 10 points on any scenario → append `DRIFT` entry in
`briefs/release-findings.md`, explain before publish. Drift > 20 points
with fewer CRITICALs → §5 score-jump red flag.

Add the file now — initial entries use the values in this playbook's Grade
blocks; subsequent runs update on PASS.

### 2. Findings → regression auto-link

Every `briefs/release-findings.md` entry MUST name the FPR fixture or unit
test that prevents re-shipping. Status transitions:

```
DETECTED → PENDING-REGRESSION → SHIPPED   (must name fixture bNN or test path)
                              → DEFERRED  (must link brief)
                              → WONTFIX   (must state reason)
```

Release blocks on any entry still in `PENDING-REGRESSION` when the playbook
is run. The regression home is `__tests__/nanomind-core/benign-fp-regression.test.ts`
(the `bNN` series) for FPs, and `__tests__/hardening/scanner.test.ts` for
detection changes. Playbook = human eye; regression suite = long-term memory.

### 3. Wild-fixture intake — `/tmp/hma-real-world/` as queue

Every fixture directory in `/tmp/hma-real-world/` that is NOT already
referenced in a scenario above is a **candidate**. The session running this
playbook MUST:

1. List candidates: compare `ls /tmp/hma-real-world/` against scenarios
   R1-R3, SK1-SK3, M1-M3.
2. Run `node dist/cli.js secure` against each candidate.
3. Per-finding-review the output.
4. Promote to a named scenario if stable (one clean run → entry in playbook
   + baselines.json).

As of 2026-04-17 the pool contains: anthropic-skill (SK1), coding-skill
(CANDIDATE), composio-skill (SK3), ibm-mcp (M1), mega-mcp (M2 — deferred),
rad-mcp (CANDIDATE), seedprod-soul (CANDIDATE — scan-soul surface),
ssh-mcp (M3), template-soul (CANDIDATE — scan-soul surface).

Candidates never promoted in 3 releases = prune or flag surface scope.

### 4. Post-release retro — RETRO entries in findings brief

After every publish, the session walks:

- Last 7 days of GitHub issues on `opena2a-org/hackmyagent` and user
  tickets (`gh issue list --repo opena2a-org/hackmyagent --search "updated:>$(date -u -v-7d +%Y-%m-%d)"`).
- Bug entries in `~/.claude/projects/-Users-ecolibria-workspace-opena2a-org/memory/MEMORY.md`
  referencing HMA in the last 7 days.

For each non-trivial bug:

```
## #N — RETRO <date> — <bug one-liner>
**Could the playbook have caught it?** YES / YES-but-trigger / NO
**Action.** <Expand trigger X / Add scenario SY / Process review>
**Scenario added.** <S<ID> in same commit>
```

Three consecutive retros with zero new scenarios = catalog is steady-state
for current behavior. Milestone, not license to stop.

### 5. Score-jump red flag — automatic adversarial review

If any scenario's score moves > 20 points in one release (up OR down), the
release blocks until a `release-findings.md` entry classifies the fix:

- **(a) preserved-detection FP-suppress** — clean; merge.
- **(b) narrowed-detection** — suspicious; spawn adversarial subagent per
  `~/workspace/claude-skills/skills/pre-push-review/SKILL.md` §Phase 4.5.
- **(c) rename workaround** — suspicious; chief decision required.

This matters most when a release claims to fix 7 bugs and the score jumps
from 45 to 100. That jump is a red flag until each fix is classified.

### 6. Steady-state demotion

A scenario passing 10 consecutive releases with zero findings AND zero
related bug reports demotes to quarterly. Recorded in `release-findings.md`
as a `DEMOTE` entry, reversible.

## What to do with findings

Every scenario that degrades produces a one-paragraph entry in
`briefs/release-findings.md` (append-only, monotonic numbering). Entry
template:

```
## #N — <SEVERITY>: <one-line name>
**Reproducer:** <scenario ID>
**Root cause.** <file:line if known>
**Why it matters.** <user/detection impact>
**Fix.** <sketch or PR link>
**Status:** <SHIPPED in PR #N / DEFERRED to <brief> / WONTFIX with reason>
```

Ship-blocker findings MUST have a regression test land in the same PR as
the fix. Benign FPR regression suite is the long-term home — add a fixture
to `__tests__/nanomind-core/benign-fp-regression.test.ts` (the `bNN` series)
matching the failing scenario, then fix.

UX-only findings go into `briefs/hma-ux-roundtwo.md` for the next iteration
— not silently deferred.

## CLAUDE.md snippet (already partially present — cross-reference this path)

The HMA CLAUDE.md already documents surface coverage, per-finding review,
and score-jump red flags. After landing this playbook, add one line near the
top of CLAUDE.md's "Testing Guide" section:

```markdown
### Canonical release playbook
Before every publish: run this playbook (`docs/release-playbook.md`) against real-world fixtures.
New findings append to `briefs/release-findings.md` with numbered entries.
Ship-blocker classification in the playbook is binding.
```

## v2 backlog — what to cover next session

- A2A surface (scenarios for `../a2a-security-examples/examples/secure-agent-card`
  — unblocks bugs #2 AST-CRED on `credentials:null`, #3 AIM-002 on
  bearer-auth example).
- npm surface (`check express` expected 100; `check <known-vuln-pkg>`).
- PyPI surface (`check pip:requests` expected ~93).
- GitHub-repo surface (`check getsentry/sentry-mcp` — regression-proofs
  bug #1 fix).
- URL surface (skipped in session 1 for network risk — pick a stable target).
- Standalone SOUL.md files (expand beyond B2's hardened case to include a
  known-weak SOUL).
- Re-pin the `mega-mcp` canonical fixture so M2 can run.

## Why this playbook exists

On 2026-04-17, commit 6b788c4 shipped with 1627 passing tests and a
self-scan score of 100/100. A surface walkthrough reported "score sane,
no crashes." A subsequent per-finding review against the 5-question
rubric surfaced 7 real bugs (1 fixed, 6 open) and a detection-narrowing
pattern (TOCTOU, DNA-002, DNA-003) that a generic fresh-user subagent
would never have caught — it does not know the difference between
"compiled bundle contains scanner patterns" and "source code leaks
credentials." The lesson: surface coverage and per-finding review are
distinct gates. Both run, neither substitutes for the other.

The playbook is the human eye; the benign FPR regression suite is the
long-term memory; unit tests certify code shape. All three are required.
This playbook is non-skippable.

# Design: NanoMind as the judge for `red-team` adaptive attacks

Status: proposed (2026-06-01)
Owners: CSR (threat research) + CDS (model / training)
Origin: new-user audit 2026-06-01

## Problem

The `red-team` command presents itself as a NanoMind-powered adaptive attack
engine. Its banner and (former) description claimed *"NanoMind generates
target-specific attacks, observes responses, adapts, and maps defenses."* The
implementation does none of that with NanoMind:

- `src/attack-engine/feedback-loop.ts: executeAttack()` constructs a
  `SimulationEngine` and then **ignores it**, calling `evaluateAttackHeuristic()`
  — a regex over the artifact's constraint text. No model, no NanoMind, no agent
  execution.
- The "observed behavior" it reports (`"Skill complied with social_engineering
  attack: ..."`) is **synthetic**. No agent ran; nothing complied. The string is
  a templated description of a heuristic guess presented as an observation.
- Every run **auto-exported** these synthetic, self-labeled strings to
  `~/.opena2a/training-data/labeled-pairs.jsonl` — a path the training pipeline
  docstring calls the SFT source. As of the audit the file held 1,405 pairs,
  1,001 (71%) of them the synthetic `"Skill complied/resisted ..."` form, none
  sanitized, all self-labeled.

This is the "present modeled output as measured" failure mode, applied to a
capability claim and to training data. It violates two binding org rules: *do
not train on data that bypasses the training sanitizer*, and *do not use
self-generated labels as ground truth*.

### Already shipped (audit fix, this PR)

- Corpus export is **opt-in** (`--export-training` / `HMA_EXPORT_TRAINING=1`),
  default off, and the exported pairs are labeled UNSANITIZED in the output.
- The command description and code comments no longer claim NanoMind does the
  evaluation; they point here.

This stops the corpus poisoning and the false claim. It does **not** make the
engine intelligent. That is the work below.

## What already exists to build on

- `src/simulation/llm-executor.ts` defines a real backend chain:
  `NanoMindBackend` (HTTP `POST 127.0.0.1:47200`) → `OllamaBackend` →
  `AnthropicBackend` → heuristic fallback, selected by `detectBestBackend()` /
  `executeProbeLLM()`.
- `src/simulation/index.ts` exposes a `SimulationEngine` with layered probes
  (NanoMind semantic ~8ms → targeted probes → full simulation).
- `red-team` already builds a `SimulationEngine` instance — it just never calls
  it.

The gap is a few function calls, not a new subsystem.

## Proposal

Make NanoMind the **judge** of attack outcomes (phase 1), before making it the
**author** of attack payloads (phase 2).

### Phase 1 — NanoMind judges resistance (highest correctness win)

Route `executeAttack()` through the existing `SimulationEngine` /
`executeProbeLLM()`:

1. Inject the payload as a user/tool message with the artifact as the system
   prompt, run it through the backend chain (NanoMind first).
2. Derive `outcome` (SUCCESS / PARTIAL / FAIL) from the **model's** response via
   the existing success/blocked indicators, not from a regex over constraint
   text.
3. Keep `evaluateAttackHeuristic()` strictly as the **fallback** when no backend
   is reachable, and label results produced by the fallback as `heuristic` so
   they are never mistaken for an observed run.
4. `observedBehavior` must be the **actual model output** (or a faithful summary
   of it), never a templated "Skill complied" sentence.

Acceptance: with the NanoMind daemon up, `red-team <malicious skill>` outcomes
are decided by the model; with it down, the command still runs and clearly says
the result is heuristic.

### Phase 2 — NanoMind co-authors payloads (later)

`generateInitialPayloads` / `generateAdaptedPayload` are template-driven today.
A later phase can have NanoMind propose target-specific payloads from the
artifact's surface. Defer until phase 1 is solid; payload generation has a wider
blast radius and lower marginal value than fixing the judge.

### Transport reconciliation (blocker for phase 1)

`analm status` shows the daemon on a Unix socket `/tmp/nanomind-guard.sock`,
while `NanoMindBackend` posts to HTTP `127.0.0.1:47200`. Reconcile before wiring
(confirm which transport the shipped daemon exposes; the consumer-integration
pattern memo specifies HTTP loopback `47200` `POST /v1/infer`). If the daemon is
socket-only, add an HTTP shim or a socket backend.

### Training export (gated on a sanitizer)

Only after phase 1 may export be considered for default-on, and only with:

- the **real artifact** as `input` (not the observed-behavior string),
- the training **sanitizer** applied (the same one the runbook requires),
- provenance recorded (`source: attack_session`, backend used, model version),
- labels treated as **weak/silver**, never as eval ground truth (Red Team only
  does label-preserving mutations of oracle samples — binding rule).

Until then, export stays behind `--export-training` and is marked UNSANITIZED.

## CHIEF decisions

- **[CHIEF-CSR] DECISION:** `red-team` must not present heuristic output as an
  observed attack result. Phase 1 (NanoMind-as-judge) is the path to an honest
  adaptive engine; the heuristic is a labeled fallback, not the headline.
  RATIONALE: a security tool that fabricates "the agent complied" erodes the
  trust the tool exists to build. ALTERNATIVE REJECTED: keep the heuristic and
  only soften the wording — leaves a dead, mislabeled feature.
- **[CHIEF-CDS] DECISION:** No `red-team` output reaches the training corpus
  without the sanitizer and real-artifact input. The default path writes
  nothing. RATIONALE: the audit found 1,001 synthetic self-labeled rows already
  accumulated; one pipeline that trusts the docstring would have ingested them.
  ALTERNATIVE REJECTED: keep auto-export with a warning — warnings do not
  un-poison a corpus.

## Out of scope / tracked separately

Single-file `secure <file>` under-scan is systemic: each analyzer subsystem has
its own file-discovery path. This change fixed three (semantic AST, SKILL-*,
structural credential/mcp/instruction). Remaining single-file under-scan paths,
all PRE-EXISTING (before this change every single-file scan scored ~98), now
narrower but not closed:

- `secure SOUL.md` governance domains (SoulScanner path).
- Static `HardeningScanner` checks with their own enumerators (e.g. LIFECYCLE-*)
  — a >1 MB malicious mcp.json scanned as a file still scores higher than the
  same file in a directory (98 vs 80 in testing) because those static checks
  and the scanner-bridge 1 MB AST size limit skip the oversized lone file.
- The correct end-state is one normalization at the `secure` entry point ("if
  the target is a file, route every surface analyzer at that file") rather than
  per-helper branches. Until then, single-file scans remain surface-limited;
  `secure <dir>` / `check <file>` are the full-coverage paths.
- Purging the 1,001 pre-existing synthetic rows from any local
  `~/.opena2a/training-data/labeled-pairs.jsonl` (operator action; the file is
  user-local and not shipped).

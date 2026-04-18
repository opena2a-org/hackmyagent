# Ed25519 Signing for HMA Contributions

Date: 2026-04-16
Scope: HMA + @opena2a/contribute + opena2a-registry
Status: Brief — awaiting chief decision

## Context

HMA currently submits contributions through `@opena2a/contribute` → `POST /api/v1/contribute`.
The submission carries only a `contributorToken` (SHA-256 over `hostname | username | salt`) — no
cryptographic proof of origin. Consensus service weights anonymous submissions at **0.3x**.

A separate unified endpoint (`POST /api/v1/trust/publish`) already supports Ed25519-signed
submissions at **0.85x** weight (`PublishTierSigned`). The `contribute` endpoint does not.

Adding Ed25519 signing to HMA contributions moves weight from 0.3x → 0.85x — ~3x more registry
influence per scan, at zero ongoing user cost.

## Current state (verified)

| Component | Has Ed25519 keypair? | Signs submissions? |
|---|---|---|
| `@opena2a/contribute` (`packages/contribute/src/contributor.ts`) | No — SHA-256 hash only | No |
| `@opena2a/contribute` (`packages/contribute/src/client.ts`) | n/a | No signature fields in batch |
| `opena2a-registry` `/api/v1/contribute` handler | n/a | Does not validate or weight by signature |
| `opena2a-registry` `/api/v1/trust/publish` handler | n/a | Yes — Ed25519 verified, canonical message = `name|version|score|maxScore` |

## Decision points

### D1: Which endpoint carries signed scans?

**Option A — extend `/contribute` with signatures.**
- Keep the batch format intact; add `signature` and `publicKey` fields to `ContributionBatch`.
- Registry handler verifies each event (or one signature over the canonical batch payload).
- Pro: single integration point for all contributing tools (HMA, ai-trust, opena2a CLI, ARP, BG).
- Con: duplicates the Ed25519 verify logic already present in `publish_service.go`.

**Option B — route scan_result events through `/trust/publish` when signed, keep other event types on `/contribute`.**
- HMA opts-in to signing, which switches the transport to the unified publish endpoint for scans.
- Non-scan contributions (detect, behavior, adoption) stay on `/contribute`.
- Pro: reuses existing verified path, no Registry change needed for scans.
- Con: two transports. `/publish` is one-scan-per-request; losing batching for scans.

**Recommend A** — keep batching, extend `/contribute` with an optional `batchSignature` over the
canonical batch payload, and upgrade consensus weights when verified. This is a single-repo
Registry handler change and preserves HMA's existing event queue model.

### D2: Key storage

**Option A — local file (`~/.opena2a/contributor-key`, mode 0600).**
- Keypair generated on first contribution, same lifecycle as the existing `contributor-salt`.
- Machine-local. Moving machines = new key = rebuild reputation.
- Pro: simple, zero-config, no extra infra.

**Option B — AIM-backed keypair.**
- Delegates to `aim-core` identity store (already bundled in `opena2a` monorepo).
- Pro: identity survives machine moves, cross-tool.
- Con: AIM-aware bootstrap complicates first-run UX. Not every HMA user has AIM installed.

**Recommend A for default**, leave AIM-backed keys as an opt-in upgrade path when `aim-core`
is detected. Matches the existing pattern where `hackmyagent fix-all --with-aim` opts in.

### D3: Canonical signing payload

`/publish` signs `"{name}|{version}|{score}|{maxScore}"`. That works for single-scan submissions
but not for a batch of heterogeneous events.

Proposed canonical payload for `/contribute`:
```
{contributorToken}|{submittedAt}|sha256(JSON.stringify(events))
```
Events are hashed in submission order. Replay is bounded by `submittedAt` (reject
submissions > 5 min old, same as existing registry replay window).

### D4: Rollout sequence

1. `@opena2a/contribute` v0.2: keypair generation, signature fields on batch, transparent opt-in
   (`OPENA2A_CONTRIBUTE_SIGN=0` disables).
2. `opena2a-registry`: extend `/contribute` handler to validate `batchSignature`, apply
   `PublishTierSigned` weight (0.85) to consensus.
3. Registry deploy goes first (handler tolerates unsigned batches — zero risk).
4. `opena2a-registry` migration: track contributor public keys in a `contributor_public_keys`
   table (first-seen = trust-on-first-use; later rotate via out-of-band flow).
5. HMA bumps `@opena2a/contribute` dependency and ships.

## Non-goals

- Not changing the ContributorToken format. Keypair fingerprint can be added as a secondary
  identity signal without replacing the token.
- Not building a contributor registration/verification flow (TOFU is sufficient for 0.85x tier;
  JWT/publisher tiers already exist for higher weights).
- Not re-keying historical anonymous contributions.

## Open questions

- Does the Registry already enforce a replay window on `/contribute`? (Check before D3.)
- Should `@opena2a/contribute` keypair rotation happen on a fixed cadence or user-triggered?
- What's the impact on consensus quorum thresholds when a machine with a signed keypair scans
  many packages (single signer dominating)? May need per-signer rate limiting.

## Scope + cost

| Repo | Changes | Lines (est) | Tests |
|---|---|---|---|
| `@opena2a/contribute` | Keypair, sign(), batch sig field | ~120 | unit: sign/verify round-trip |
| `opena2a-registry` | Signature validator + migration 2xx for contributor keys | ~180 | integration: signed batch → 0.85 weight |
| `hackmyagent` | Bump contribute dep, version bump | ~5 | existing telemetry tests |

## Ask

Chief decision on D1 + D2 before implementation. Flagging D3 replay window as a Registry
pre-check. No code changes until approved.

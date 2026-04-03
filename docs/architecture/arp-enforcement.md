# ARP Enforcement Hardening: CR-001 and CR-002

## Overview

This document describes two critical changes to the ARP (Agent Runtime Protection) enforcement engine that eliminate classes of bypass vulnerabilities identified in OPENA2A-IB-007.

## CR-001: Parse-to-Deny Semantics

**Principle:** All parse failures produce DENY. Unparseable input is never trusted.

### Problem

Prior to this change, JSON parse failures in the proxy inspection layer returned `false` (no threat detected), allowing malformed requests to pass through uninspected. An attacker could craft intentionally malformed JSON that fails parsing but is still processed by the upstream service, bypassing all ARP inspection.

Similarly, the L2 (LLM) assessment parser defaulted to `recommendation: 'allow'` when the LLM response couldn't be parsed, creating a path from parse failure to implicit allow.

### Changes

**Proxy layer** (`src/arp/proxy/server.ts`):
- All `catch` blocks in protocol inspectors (`inspectOpenAIRequest`, `inspectOpenAIResponse`, `inspectMCPRequest`, `inspectMCPResponse`, `inspectA2AResponse`, `inspectA2ARequest`) now return `true` (threat detected) instead of `false`.
- Each parse failure emits a `POLICY_PARSE_FAILURE` event through the event engine with category `threat` and severity `high`.
- No raw request body is included in telemetry (privacy). Only body length and protocol type are recorded.

**L2 assessment parser** (`src/arp/intelligence/coordinator.ts`):
- Default recommendation changed from `'allow'` to `'alert'`.
- Default `consistent` changed from `true` to `false`.
- If no `ACTION:` line is found in LLM response, recommendation remains `'alert'`.
- Unrecognized action strings default to `'alert'`, not `'allow'`.

**Command complexity analysis** (`src/arp/interceptors/process.ts`):
- New `analyzeCommandComplexity()` function counts shell operators (pipes, semicolons, ampersands, command substitutions) in exec'd commands.
- Commands exceeding `MAX_SUBCOMMANDS` (10) are classified as `threat` with `critical` severity.
- This addresses the adversarial pipeline attack vector where an attacker generates commands with 50+ subcommands to overwhelm enforcement.

### Telemetry

A new GTIN event type `policy_parse_failure` has been added to the telemetry pipeline (`src/arp/telemetry/gtin.ts`). Events with `data.policyParseFailure = true` are mapped to this type and forwarded to the Registry for community threat intelligence.

### tree-sitter-bash Evaluation

`tree-sitter-bash` (v0.25.1) was evaluated for full AST-based command parsing to replace the regex-based approach. Findings:

- **Pro:** Full bash AST with proper handling of quoting, escaping, heredocs, and nested structures.
- **Con:** Requires native compilation (`node-addon-api` + `node-gyp-build`), which adds a build toolchain dependency that conflicts with HMA's zero-dependency philosophy for portability.
- **Decision:** Deferred. The regex-based `analyzeCommandComplexity()` covers the adversarial pipeline attack vector. tree-sitter-bash remains a candidate for future upgrade when native dependency management improves or when more sophisticated command analysis is needed.

## CR-002: No-Ask-Mode (Fail-Closed Enforcement)

**Principle:** Enforcement actions always execute immediately. No interactive fallback. No deferred enforcement.

### Problem

The `requireLlmConfirmation` flag on alert rules caused enforcement to be deferred indefinitely. The event was tagged with `_pendingConfirmation` and enforcement was skipped (`continue`), with the expectation that L2 (LLM assessment) would later confirm and execute the action.

This created multiple bypass paths:
1. If L2 was disabled (no adapter configured), pending events were never enforced.
2. If the LLM budget was exhausted, pending events were never enforced.
3. If the LLM was unavailable (network failure), pending events were never enforced.
4. An attacker who knew about the threshold could generate events that would reliably exhaust the L2 budget, then operate freely.

### Changes

**Event engine** (`src/arp/engine/event-engine.ts`):
- `requireLlmConfirmation` no longer defers enforcement. The matched action executes immediately.
- Events are tagged with `_llmReviewRequested: true` for L2 follow-up assessment.
- L2 can still UPGRADE severity after assessment (e.g., alert -> kill), but the initial action always fires.
- The old `_pendingConfirmation`, `_pendingAction`, `_pendingRule` fields are removed.

### Enforcement Flow (After CR-001 + CR-002)

```
Request arrives
  -> Protocol parser runs
    -> Parse SUCCESS: scan for threats
    -> Parse FAILURE: DENY + emit POLICY_PARSE_FAILURE (CR-001)
  -> Rule evaluation
    -> Rule matches:
      -> requireLlmConfirmation? Tag for L2 review BUT enforce NOW (CR-002)
      -> Execute enforcement action immediately
  -> L2 runs asynchronously (if available and budgeted)
    -> L2 parse failure: default to 'alert' (CR-001)
    -> L2 can upgrade severity (alert -> kill)
    -> L2 cannot downgrade below L0/L1 classification
```

## Testing

Enforcement hardening tests are in `src/arp/enforcement/enforcement-hardening.test.ts`:

- **CR-002 tests:** Verify that `requireLlmConfirmation` rules enforce immediately, that events are tagged but not deferred, and that multiple rules (with and without LLM confirmation) all fire.
- **CR-001 adversarial pipeline tests:** 10 fuzz-style adversarial bash pipelines with 50+ subcommands, each verified to exceed the MAX_SUBCOMMANDS threshold and produce DENY.
- **CR-001 L2 parser tests:** Verify that empty, garbage, and missing-ACTION LLM responses default to 'alert' (not 'allow').
- **POLICY_PARSE_FAILURE telemetry tests:** Verify parse failure events are emitted with correct category and severity.

## OASB Control Mapping

These changes support **OASB-SEC-021** (Policy Enforcement Fail-Closed Semantics):
- **Evidence Tier 1:** This document.
- **Evidence Tier 2:** PEI-001 and PEI-003 HMA check pass (Session 2).
- **Evidence Tier 3:** Clean POLICY_PARSE_FAILURE event log.

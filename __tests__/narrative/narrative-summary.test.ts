import { describe, it, expect } from "vitest";
import {
  generateNarrativeSummary,
  isAcceptedByInputClassifier,
  emptyResult,
} from "../../src/narrative/narrative-summary.js";
import type { SecurityAST } from "../../src/nanomind-core/types.js";

const baseAst = (overrides: Partial<SecurityAST> = {}): SecurityAST => ({
  artifactType: "skill",
  contentHash: "abc",
  artifactSize: 100,
  declaredPurpose: "",
  declaredCapabilities: [],
  declaredConstraints: [],
  declaredDataAccess: [],
  inferredCapabilities: [],
  inferredRiskSurface: [],
  intentClassification: "benign",
  intentConfidence: 0.5,
  dependsOn: [],
  governedBy: [],
  evidenceSpans: [],
  signature: "",
  modelVersion: "heuristic-v1",
  compiledAt: "2026-04-27T00:00:00.000Z",
  ...overrides,
});

describe("isAcceptedByInputClassifier", () => {
  it("accepts skill artifacts", () => {
    expect(isAcceptedByInputClassifier(baseAst({ artifactType: "skill" }))).toBe(true);
  });
  it("accepts mcp_config artifacts", () => {
    expect(isAcceptedByInputClassifier(baseAst({ artifactType: "mcp_config" }))).toBe(true);
  });
  it("rejects soul / system_prompt / source_code / unknown", () => {
    for (const t of ["soul", "system_prompt", "source_code", "unknown"] as const) {
      expect(isAcceptedByInputClassifier(baseAst({ artifactType: t }))).toBe(false);
    }
  });
});

describe("generateNarrativeSummary (v1 stub)", () => {
  it("returns empty triple + generated=false on accepted skill input", async () => {
    const out = await generateNarrativeSummary(baseAst({ artifactType: "skill" }));
    expect(out).toEqual(emptyResult());
  });

  it("returns empty triple + generated=false on accepted mcp_config input", async () => {
    const out = await generateNarrativeSummary(baseAst({ artifactType: "mcp_config" }));
    expect(out).toEqual(emptyResult());
  });

  it("returns empty triple on a rejected artifact type", async () => {
    const out = await generateNarrativeSummary(baseAst({ artifactType: "source_code" }));
    expect(out).toEqual(emptyResult());
  });

  it("never throws — always resolves to a triple", async () => {
    await expect(
      generateNarrativeSummary(baseAst({ artifactType: "skill" })),
    ).resolves.toBeDefined();
  });
});

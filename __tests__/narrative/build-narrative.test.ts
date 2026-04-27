import { describe, expect, it } from "vitest";
import {
  buildPackageNarrative,
  synthesizeSummary,
  type BuildPackageNarrativeInput,
} from "../../src/narrative/build-narrative.js";
import type { SecurityAST } from "../../src/nanomind-core/types.js";

const baseAst = (artifactType: "skill" | "mcp_config"): SecurityAST =>
  ({
    artifactType,
    contentHash: "deadbeef",
    artifactSize: 0,
    declaredPurpose: "",
    declaredCapabilities: [],
    declaredConstraints: [],
    declaredDataAccess: [],
    inferredCapabilities: [],
    inferredRiskSurface: [],
    intentClassification: "unknown",
    intentConfidence: 0,
    dependsOn: [],
    governedBy: [],
    evidenceSpans: [],
    signature: "",
    modelVersion: "test",
    compiledAt: "2026-04-27T00:00:00.000Z",
  }) as unknown as SecurityAST;

const skillInput = (
  overrides: Partial<BuildPackageNarrativeInput> = {},
): BuildPackageNarrativeInput => ({
  ast: baseAst("skill"),
  packageName: "opena2a/code-review-skill",
  packageVersion: "0.3.1",
  findings: [],
  verdict: "LISTED",
  scanStatus: "completed",
  publisher: { verified: false, hasNpmProvenance: false, hasMaintainerHistory: false },
  attestations: {},
  communityScans: 0,
  cleanCommunityScans: 0,
  hasSoulFile: false,
  ...overrides,
});

const mcpInput = (
  overrides: Partial<BuildPackageNarrativeInput> = {},
): BuildPackageNarrativeInput => ({
  ast: baseAst("mcp_config"),
  packageName: "@example/server",
  packageVersion: "1.0.0",
  findings: [],
  verdict: "LISTED",
  scanStatus: "completed",
  publisher: { verified: false, hasNpmProvenance: false, hasMaintainerHistory: false },
  attestations: {},
  communityScans: 0,
  cleanCommunityScans: 0,
  hasSoulFile: false,
  ...overrides,
});

describe("synthesizeSummary", () => {
  it("uses NanoMind summary when present", () => {
    const out = synthesizeSummary(
      "Real comprehension summary.",
      skillInput({ skillFrontmatter: { description: "frontmatter desc" } }),
      "skill",
    );
    expect(out).toBe("Real comprehension summary.");
  });

  it("falls back to SKILL.md frontmatter description for skill artifacts", () => {
    const out = synthesizeSummary(
      "",
      skillInput({ skillFrontmatter: { description: "Reviews diffs and PRs." } }),
      "skill",
    );
    expect(out).toBe("Reviews diffs and PRs.");
  });

  it("falls back to package.json description for mcp artifacts", () => {
    const out = synthesizeSummary(
      "",
      mcpInput({ mcpConfig: { description: "Filesystem MCP server." } }),
      "mcp",
    );
    expect(out).toBe("Filesystem MCP server.");
  });

  it("uses generic deterministic line when neither NanoMind nor author description is present (skill)", () => {
    const out = synthesizeSummary("", skillInput(), "skill");
    expect(out).toBe("Skill: opena2a/code-review-skill");
  });

  it("uses generic deterministic line when neither NanoMind nor author description is present (mcp)", () => {
    const out = synthesizeSummary("", mcpInput(), "mcp");
    expect(out).toBe("MCP: @example/server");
  });

  it("collapses whitespace and trims", () => {
    const out = synthesizeSummary(
      "  multi\n  line   summary  \n",
      skillInput(),
      "skill",
    );
    expect(out).toBe("multi line summary");
  });

  it("caps at 4096 chars (registry narrativeMaxSummaryBytes)", () => {
    const out = synthesizeSummary("x".repeat(5000), skillInput(), "skill");
    expect(out.length).toBe(4096);
  });

  it("ignores non-string author descriptions", () => {
    const out = synthesizeSummary(
      "",
      skillInput({ skillFrontmatter: { description: 42 as unknown as string } }),
      "skill",
    );
    expect(out).toBe("Skill: opena2a/code-review-skill");
  });
});

describe("buildPackageNarrative — wire-publish regression", () => {
  it("produces a non-empty summary when NanoMind is in graceful-degrade (the bug that made `secure --publish` fail with 400 invalid_summary)", async () => {
    const narrative = await buildPackageNarrative(
      skillInput({
        skillFrontmatter: {
          description:
            "Code review skill that reads files and produces structured findings.",
        },
        skillSource: "---\ndescription: x\n---\n# Body",
      }),
    );
    expect(narrative).not.toBeNull();
    expect(narrative!.summary.length).toBeGreaterThan(0);
    expect(narrative!.summary).toBe(
      "Code review skill that reads files and produces structured findings.",
    );
  });

  it("falls back to generic line when no author description is available, still non-empty", async () => {
    const narrative = await buildPackageNarrative(skillInput());
    expect(narrative).not.toBeNull();
    expect(narrative!.summary).toBe("Skill: opena2a/code-review-skill");
  });
});

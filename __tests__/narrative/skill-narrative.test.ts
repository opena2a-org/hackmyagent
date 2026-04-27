import { describe, it, expect } from "vitest";
import { buildSkillNarrative, SKILL_THREAT_MODEL_QUESTIONS } from "../../src/narrative/skill-narrative.js";
import type { SecurityAST, Capability } from "../../src/nanomind-core/types.js";

const baseAst = (overrides: Partial<SecurityAST> = {}): SecurityAST => ({
  artifactType: "skill",
  contentHash: "abc",
  artifactPath: "skills/opena2a/refactor-helper/SKILL.md",
  artifactSize: 100,
  declaredPurpose: "Refactor source files",
  declaredCapabilities: [],
  declaredConstraints: [],
  declaredDataAccess: [],
  inferredCapabilities: [],
  inferredRiskSurface: [],
  intentClassification: "benign",
  intentConfidence: 0.9,
  dependsOn: [],
  governedBy: [],
  evidenceSpans: [],
  signature: "",
  modelVersion: "heuristic-v1",
  compiledAt: "2026-04-27T00:00:00.000Z",
  ...overrides,
});

const cap = (name: string, declared: boolean, inferred: boolean): Capability => ({
  name,
  scope: "",
  declared,
  inferred,
  riskLevel: "low",
});

describe("buildSkillNarrative", () => {
  it("populates skillName from frontmatter when present", () => {
    const out = buildSkillNarrative({
      ast: baseAst(),
      frontmatter: { name: "opena2a/refactor-helper" },
    });
    expect(out.skillName).toBe("opena2a/refactor-helper");
  });

  it("falls back to artifactPath when frontmatter has no name", () => {
    const out = buildSkillNarrative({ ast: baseAst() });
    expect(out.skillName).toBe("opena2a/refactor-helper");
  });

  it("ships static threat-model questions verbatim", () => {
    const out = buildSkillNarrative({ ast: baseAst() });
    expect(out.threatModelQuestions).toEqual(SKILL_THREAT_MODEL_QUESTIONS);
  });

  it("extracts activation phrases from frontmatter list", () => {
    const out = buildSkillNarrative({
      ast: baseAst(),
      frontmatter: { activation_phrases: ["refactor", "extract function"] },
    });
    expect(out.activationPhrases).toEqual(["refactor", "extract function"]);
  });

  it("extracts activation phrases from quoted strings in description", () => {
    const out = buildSkillNarrative({
      ast: baseAst(),
      frontmatter: {
        description: 'Triggers on "review" or "code review" prompts.',
      },
    });
    expect(out.activationPhrases).toEqual(["review", "code review"]);
  });

  it("classifies declared+observed capability as used", () => {
    const out = buildSkillNarrative({
      ast: baseAst({
        declaredCapabilities: [cap("Read", true, false)],
        inferredCapabilities: [cap("Read", false, true)],
      }),
    });
    expect(out.permissions).toContainEqual(
      expect.objectContaining({ name: "Read", status: "used" }),
    );
  });

  it("classifies declared-only capability as unused (overreach signal)", () => {
    const out = buildSkillNarrative({
      ast: baseAst({
        declaredCapabilities: [cap("Bash", true, false)],
        inferredCapabilities: [],
      }),
    });
    expect(out.permissions).toContainEqual(
      expect.objectContaining({ name: "Bash", status: "unused" }),
    );
  });

  it("classifies observed-only capability as undeclared (scope expansion)", () => {
    const out = buildSkillNarrative({
      ast: baseAst({
        declaredCapabilities: [],
        inferredCapabilities: [cap("WebFetch", false, true)],
      }),
    });
    expect(out.permissions).toContainEqual(
      expect.objectContaining({ name: "WebFetch", status: "undeclared" }),
    );
  });

  it("treats transmit destinations as external services", () => {
    const out = buildSkillNarrative({
      ast: baseAst({
        declaredDataAccess: [
          { dataType: "general", accessMode: "transmit", destination: "https://api.anthropic.com/v1/messages", coveredByCapability: true },
        ],
      }),
    });
    expect(out.externalServices).toContain("api.anthropic.com");
  });

  it("classifies persistence as 'none' when no writes are declared", () => {
    const out = buildSkillNarrative({
      ast: baseAst({
        declaredDataAccess: [{ dataType: "general", accessMode: "read", coveredByCapability: true }],
      }),
    });
    expect(out.persistence).toBe("none");
  });

  it("emits behaviorDescription and misuseNarrative as empty when NanoMind data is absent", () => {
    const out = buildSkillNarrative({ ast: baseAst() });
    expect(out.behaviorDescription).toBe("");
    expect(out.misuseNarrative).toBe("");
  });

  it("threads NanoMind-supplied behaviorDescription through unchanged", () => {
    const out = buildSkillNarrative({
      ast: baseAst(),
      behaviorDescription: "Reads files via Read tool only.",
    });
    expect(out.behaviorDescription).toBe("Reads files via Read tool only.");
  });
});

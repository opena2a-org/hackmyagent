import { describe, it, expect } from "vitest";
import { buildRichBlockInput } from "../../src/check/rich-block-adapter.js";
import type { FetchedPackageNarrative } from "../../src/check/narrative-fetch.js";

const skillNarrative: FetchedPackageNarrative = {
  artifactType: "skill",
  packageName: "opena2a/code-review",
  packageVersion: "0.1.2",
  schemaVersion: 1,
  generatedAt: "2026-04-27T00:00:00Z",
  summary: "summary",
  hardcodedSecrets: { detected: [], scanCovered: true },
  skillNarrative: {
    skillName: "opena2a/code-review",
    activationPhrases: ["review", "lint"],
    behaviorDescription: "code review skill",
    permissions: [
      { name: "read_files", declared: true, used: true, status: "used" },
      { name: "execute_shell", declared: false, used: true, status: "undeclared" },
    ],
    externalServices: ["github.com"],
    persistence: "none",
    toolCallsObserved: [{ tool: "git", count: 3 }],
    misuseNarrative: "Could exfiltrate code by reading + posting to webhook.",
  },
  mcpNarrative: null,
  verdictReasoning: [
    { kind: "positive", text: "Permissions match observed behavior" },
    { kind: "gap", text: "No npm provenance" },
  ],
  nextSteps: [
    { weight: "primary", label: "Install confidently", command: "opena2a install ..." },
    { weight: "secondary", label: "Pin to current", command: "..." },
  ],
};

const baseTrust = {
  trustVerdict: "LISTED" as const,
  trustScore: 72,
  scanStatus: "completed",
};

describe("buildRichBlockInput", () => {
  it("returns a valid CheckRichBlockInput for a skill artifact", () => {
    const input = buildRichBlockInput({
      name: "opena2a/code-review",
      artifactType: "skill",
      narrative: skillNarrative,
      trust: baseTrust,
      reportTool: "hackmyagent",
    });
    expect(input).not.toBeNull();
    expect(input?.artifactType).toBe("skill");
    expect(input?.skill?.skillName).toBe("opena2a/code-review");
    expect(input?.skill?.activationPhrases).toEqual(["review", "lint"]);
    expect(input?.skill?.permissions).toHaveLength(2);
    expect(input?.mcp).toBeUndefined();
    expect(input?.hardcodedSecrets.scanCovered).toBe(true);
    expect(input?.hardcodedSecrets.detected).toEqual([]);
    expect(input?.verdictReasoning).toHaveLength(2);
    expect(input?.nextSteps).toHaveLength(2);
    expect(input?.header.findingsCount).toBe(0);
    expect(input?.header.trustScore).toBe(72);
    expect(input?.reportTool).toBe("hackmyagent");
    expect(input?.latestVersion).toBe("0.1.2");
  });

  it("returns null when artifactType disagrees with narrative", () => {
    const input = buildRichBlockInput({
      name: "opena2a/code-review",
      artifactType: "mcp",
      narrative: skillNarrative,
      trust: baseTrust,
      reportTool: "hackmyagent",
    });
    expect(input).toBeNull();
  });

  it("returns null when skillNarrative is missing required field", () => {
    const broken: FetchedPackageNarrative = {
      ...skillNarrative,
      skillNarrative: { activationPhrases: [] },
    };
    const input = buildRichBlockInput({
      name: "x",
      artifactType: "skill",
      narrative: broken,
      trust: baseTrust,
      reportTool: "hackmyagent",
    });
    expect(input).toBeNull();
  });

  it("drops malformed permission entries", () => {
    const broken: FetchedPackageNarrative = {
      ...skillNarrative,
      skillNarrative: {
        skillName: "x",
        activationPhrases: [],
        permissions: [
          { name: "ok", status: "used" },
          { name: "no-status" },
          { status: "used" },
          { name: "bad-status", status: "weird" },
        ],
      },
    };
    const input = buildRichBlockInput({
      name: "x",
      artifactType: "skill",
      narrative: broken,
      trust: baseTrust,
      reportTool: "hackmyagent",
    });
    expect(input?.skill?.permissions).toHaveLength(1);
    expect(input?.skill?.permissions[0].name).toBe("ok");
  });

  it("maps local findings into RichObservationFinding shape", () => {
    const input = buildRichBlockInput({
      name: "opena2a/code-review",
      artifactType: "skill",
      narrative: skillNarrative,
      trust: baseTrust,
      reportTool: "hackmyagent",
      localFindings: [
        {
          severity: "high",
          checkId: "CRED-001",
          name: "Hardcoded API key",
          file: "src/secrets.ts",
          line: 42,
          message: "API key found",
          fix: "Move to env var",
        },
        { severity: "low", checkId: "STYLE-001" },
      ],
    });
    expect(input?.findings).toHaveLength(2);
    expect(input?.findings[0]).toMatchObject({
      severity: "high",
      ruleId: "CRED-001",
      locator: "src/secrets.ts:42",
      description: "API key found",
      fix: "Move to env var",
    });
    expect(input?.findings[1].locator).toBe("");
    expect(input?.header.findingsCount).toBe(2);
  });

  it("parses MCP narrative with tools array", () => {
    const mcpNarr: FetchedPackageNarrative = {
      ...skillNarrative,
      artifactType: "mcp",
      skillNarrative: null,
      mcpNarrative: {
        mcpName: "@scope/server",
        tools: [
          {
            name: "read_file",
            signature: "(path: string)",
            description: "Reads a file",
            destructive: false,
          },
        ],
        pathScope: "/tmp",
        network: "none",
        persistence: "none",
        auth: "none",
        sideEffects: ["reads files"],
      },
    };
    const input = buildRichBlockInput({
      name: "@scope/server",
      artifactType: "mcp",
      narrative: mcpNarr,
      trust: baseTrust,
      reportTool: "hackmyagent",
    });
    expect(input?.mcp?.tools).toHaveLength(1);
    expect(input?.mcp?.pathScope).toBe("/tmp");
    expect(input?.mcp?.sideEffects).toEqual(["reads files"]);
    expect(input?.skill).toBeUndefined();
  });

  it("drops malformed verdictReasoning entries", () => {
    const broken: FetchedPackageNarrative = {
      ...skillNarrative,
      verdictReasoning: [
        { kind: "positive", text: "ok" },
        { kind: "weird", text: "drop" },
        { kind: "gap" },
        "not-an-object",
      ] as unknown[],
    };
    const input = buildRichBlockInput({
      name: "x",
      artifactType: "skill",
      narrative: broken,
      trust: baseTrust,
      reportTool: "hackmyagent",
    });
    expect(input?.verdictReasoning).toHaveLength(1);
    expect(input?.verdictReasoning[0].kind).toBe("positive");
  });

  it("preserves only well-formed nextSteps weights", () => {
    const broken: FetchedPackageNarrative = {
      ...skillNarrative,
      nextSteps: [
        { weight: "primary", label: "ok" },
        { weight: "default", label: "drop" },
        { label: "no-weight" },
      ] as unknown[],
    };
    const input = buildRichBlockInput({
      name: "x",
      artifactType: "skill",
      narrative: broken,
      trust: baseTrust,
      reportTool: "hackmyagent",
    });
    expect(input?.nextSteps).toHaveLength(1);
    expect(input?.nextSteps[0].weight).toBe("primary");
  });

  it("drops malformed hardcodedSecrets entries while keeping scanCovered", () => {
    const broken: FetchedPackageNarrative = {
      ...skillNarrative,
      hardcodedSecrets: {
        scanCovered: true,
        detected: [
          {
            type: "openai",
            typeLabel: "OpenAI key",
            file: ".env",
            maskedValue: "sk-...XXX",
            shownChars: 6,
            totalChars: 51,
            shipsInArtifact: true,
            severity: "critical",
          },
          { severity: "weird" },
          { type: "stripe" },
        ],
      },
    };
    const input = buildRichBlockInput({
      name: "x",
      artifactType: "skill",
      narrative: broken,
      trust: baseTrust,
      reportTool: "hackmyagent",
    });
    expect(input?.hardcodedSecrets.scanCovered).toBe(true);
    expect(input?.hardcodedSecrets.detected).toHaveLength(1);
    expect(input?.hardcodedSecrets.detected[0].type).toBe("openai");
  });
});

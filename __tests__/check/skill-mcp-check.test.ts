import { describe, it, expect, vi, afterEach } from "vitest";
import {
  parseRichTarget,
  deriveTrustVerdict,
  checkSkillOrMcp,
} from "../../src/check/skill-mcp-check.js";

const palette = {
  reset: "",
  dim: (s: string) => s,
  bold: (s: string) => s,
  white: (s: string) => s,
  green: (s: string) => s,
  yellow: (s: string) => s,
  red: (s: string) => s,
  brightRed: (s: string) => s,
  cyan: (s: string) => s,
};

describe("parseRichTarget", () => {
  it("parses skill: prefix", () => {
    expect(parseRichTarget("skill:opena2a/code-review")).toEqual({
      artifactType: "skill",
      name: "opena2a/code-review",
    });
  });

  it("parses mcp: prefix", () => {
    expect(parseRichTarget("mcp:@scope/server")).toEqual({
      artifactType: "mcp",
      name: "@scope/server",
    });
  });

  it("returns null for an empty name after the prefix", () => {
    expect(parseRichTarget("skill:")).toBeNull();
    expect(parseRichTarget("mcp:")).toBeNull();
  });

  it("returns null for non-prefixed targets", () => {
    expect(parseRichTarget("@anthropic/code-review")).toBeNull();
    expect(parseRichTarget("express")).toBeNull();
    expect(parseRichTarget("./local")).toBeNull();
  });
});

describe("deriveTrustVerdict", () => {
  it("returns BLOCKED when verdict is 'blocked'", () => {
    expect(deriveTrustVerdict("blocked", 1, "completed")).toBe("BLOCKED");
  });

  it("returns BLOCKED when trustLevel is 0", () => {
    expect(deriveTrustVerdict("warning", 0, "completed")).toBe("BLOCKED");
  });

  it("returns VERIFIED for trustLevel 4", () => {
    expect(deriveTrustVerdict("verified", 4, "completed")).toBe("VERIFIED");
  });

  it("returns LISTED_UNSCANNED when scanStatus is missing or pending", () => {
    expect(deriveTrustVerdict("listed", 2, undefined)).toBe(
      "LISTED_UNSCANNED",
    );
    expect(deriveTrustVerdict("listed", 2, "pending")).toBe(
      "LISTED_UNSCANNED",
    );
    expect(deriveTrustVerdict("listed", 2, "queued")).toBe("LISTED_UNSCANNED");
  });

  it("returns LISTED for scanned but not verified packages", () => {
    expect(deriveTrustVerdict("listed", 2, "completed")).toBe("LISTED");
    expect(deriveTrustVerdict("scanned", 3, "completed")).toBe("LISTED");
  });
});

describe("checkSkillOrMcp", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("returns rendered=false when trust is null", async () => {
    const result = await checkSkillOrMcp({
      parsed: { artifactType: "skill", name: "x" },
      registryUrl: "https://api.example.com",
      userAgent: "test/0.0.0",
      reportTool: "hackmyagent",
      trust: null,
      palette,
      version: "0.1.0",
    });
    expect(result.rendered).toBe(false);
  });

  it("returns rendered=false when version is omitted (latest sentinel TBD)", async () => {
    const result = await checkSkillOrMcp({
      parsed: { artifactType: "skill", name: "x" },
      registryUrl: "https://api.example.com",
      userAgent: "test/0.0.0",
      reportTool: "hackmyagent",
      trust: {
        found: true,
        name: "x",
        trustScore: 0.7,
        trustLevel: 2,
        verdict: "listed",
        scanStatus: "completed",
      },
      palette,
    });
    expect(result.rendered).toBe(false);
  });

  it("returns rendered=false when narrative fetch returns null", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 404 }),
    );
    const result = await checkSkillOrMcp({
      parsed: { artifactType: "skill", name: "x" },
      registryUrl: "https://api.example.com",
      userAgent: "test/0.0.0",
      reportTool: "hackmyagent",
      trust: {
        found: true,
        name: "x",
        trustScore: 0.7,
        trustLevel: 2,
        verdict: "listed",
        scanStatus: "completed",
      },
      palette,
      version: "0.1.0",
    });
    expect(result.rendered).toBe(false);
  });

  it("renders when trust + narrative are both available", async () => {
    const narrativeBody = {
      artifactType: "skill",
      packageName: "x",
      packageVersion: "0.1.0",
      schemaVersion: 1,
      generatedAt: "2026-04-27T00:00:00Z",
      summary: "summary",
      hardcodedSecrets: { detected: [], scanCovered: true },
      skillNarrative: {
        skillName: "x",
        activationPhrases: ["go"],
        permissions: [],
        externalServices: [],
        persistence: "none",
        toolCallsObserved: [],
        misuseNarrative: "",
      },
      mcpNarrative: null,
      verdictReasoning: [],
      nextSteps: [],
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => narrativeBody,
      }),
    );
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const result = await checkSkillOrMcp({
      parsed: { artifactType: "skill", name: "x" },
      registryUrl: "https://api.example.com",
      userAgent: "test/0.0.0",
      reportTool: "hackmyagent",
      trust: {
        found: true,
        name: "x",
        trustScore: 0.7,
        trustLevel: 2,
        verdict: "listed",
        scanStatus: "completed",
      },
      palette,
      version: "0.1.0",
    });
    logSpy.mockRestore();
    expect(result.rendered).toBe(true);
    expect(result.input?.artifactType).toBe("skill");
    expect(result.input?.name).toBe("x");
  });

  it("suppresses trustScore when scanStatus is not completed", async () => {
    const narrativeBody = {
      artifactType: "skill",
      packageName: "x",
      packageVersion: "0.1.0",
      schemaVersion: 1,
      generatedAt: "2026-04-27T00:00:00Z",
      summary: "",
      hardcodedSecrets: { detected: [], scanCovered: false },
      skillNarrative: {
        skillName: "x",
        activationPhrases: [],
        permissions: [],
        externalServices: [],
        persistence: "",
        toolCallsObserved: [],
        misuseNarrative: "",
      },
      mcpNarrative: null,
      verdictReasoning: [],
      nextSteps: [],
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => narrativeBody,
      }),
    );
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const result = await checkSkillOrMcp({
      parsed: { artifactType: "skill", name: "x" },
      registryUrl: "https://api.example.com",
      userAgent: "test/0.0.0",
      reportTool: "hackmyagent",
      trust: {
        found: true,
        name: "x",
        trustScore: 0.7,
        trustLevel: 2,
        verdict: "listed",
        scanStatus: "error",
      },
      palette,
      version: "0.1.0",
    });
    logSpy.mockRestore();
    expect(result.rendered).toBe(true);
    expect(result.input?.header.trustScore).toBeUndefined();
    expect(result.input?.header.trustVerdict).toBe("LISTED_UNSCANNED");
  });
});

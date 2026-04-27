import { describe, it, expect } from "vitest";
import {
  buildMcpNarrative,
  MCP_THREAT_MODEL_QUESTIONS,
} from "../../src/narrative/mcp-narrative.js";
import type { SecurityAST } from "../../src/nanomind-core/types.js";

const baseAst = (overrides: Partial<SecurityAST> = {}): SecurityAST => ({
  artifactType: "mcp_config",
  contentHash: "abc",
  artifactPath: "mcps/server-filesystem/package.json",
  artifactSize: 100,
  declaredPurpose: "filesystem MCP",
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

describe("buildMcpNarrative", () => {
  it("populates mcpName from config when present", () => {
    const out = buildMcpNarrative({
      ast: baseAst(),
      config: { name: "@modelcontextprotocol/server-filesystem" },
    });
    expect(out.mcpName).toBe("@modelcontextprotocol/server-filesystem");
  });

  it("ships threat-model questions verbatim", () => {
    const out = buildMcpNarrative({ ast: baseAst() });
    expect(out.threatModelQuestions).toEqual(MCP_THREAT_MODEL_QUESTIONS);
  });

  it("classifies write_file as destructive and read_file as non-destructive", () => {
    const out = buildMcpNarrative({
      ast: baseAst(),
      toolRegistrations: [
        { name: "read_file", signature: "read_file(path)" },
        { name: "write_file", signature: "write_file(path, content)" },
      ],
    });
    const write = out.tools.find((t) => t.name === "write_file");
    const read = out.tools.find((t) => t.name === "read_file");
    expect(write?.destructive).toBe(true);
    expect(read?.destructive).toBe(false);
  });

  it("reports config-allowlisted scope when allowedDirectories is set", () => {
    const out = buildMcpNarrative({
      ast: baseAst(),
      config: { allowedDirectories: ["~/agent-workspace", "~/scratch"] },
    });
    expect(out.pathScope).toMatch(/^config-allowlisted/);
  });

  it("reports 'any path agent passes' when there is no allowlist + writes are declared", () => {
    const out = buildMcpNarrative({
      ast: baseAst({
        declaredDataAccess: [{ dataType: "general", accessMode: "write", coveredByCapability: true }],
      }),
    });
    expect(out.pathScope).toBe("any path agent passes");
  });

  it("reports network 'none' for fully-local MCP", () => {
    const out = buildMcpNarrative({ ast: baseAst() });
    expect(out.network).toBe("none");
  });

  it("classifies bearer token auth from config", () => {
    const out = buildMcpNarrative({
      ast: baseAst(),
      config: { name: "x", bearerToken: true },
    });
    expect(out.auth).toBe("bearer token");
  });

  it("flags spawn side-effects from inferred risk surface", () => {
    const out = buildMcpNarrative({
      ast: baseAst({
        inferredRiskSurface: [
          {
            surface: "child process spawn",
            attackClass: "RCE",
            confidence: 0.8,
            evidence: "child_process.spawn(...)",
          },
        ],
      }),
    });
    expect(out.sideEffects).toContain("spawns child processes");
  });

  it("returns empty tools[] when no registrations are passed", () => {
    const out = buildMcpNarrative({ ast: baseAst() });
    expect(out.tools).toEqual([]);
  });
});

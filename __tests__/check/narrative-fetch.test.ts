import { describe, it, expect, vi, afterEach } from "vitest";
import { fetchNarrative } from "../../src/check/narrative-fetch.js";

// Wire shape uses `skill` / `mcp` keys (matches registry handler's
// json:"skill,omitempty" tag). The fetch helper renames them to
// skillNarrative / mcpNarrative on the typed result.
const validBody = {
  artifactType: "skill",
  packageName: "opena2a/code-review",
  packageVersion: "0.1.2",
  schemaVersion: 1,
  generatedAt: "2026-04-27T00:00:00Z",
  summary: "summary",
  hardcodedSecrets: { detected: [], scanCovered: true },
  skill: { skillName: "opena2a/code-review" },
  mcp: null,
  verdictReasoning: [],
  nextSteps: [],
};

describe("fetchNarrative", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("returns parsed narrative on 200 OK", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => validBody,
      }),
    );
    const result = await fetchNarrative({
      registryUrl: "https://api.example.com",
      artifactType: "skill",
      name: "opena2a/code-review",
      version: "0.1.2",
      userAgent: "test/0.0.0",
    });
    expect(result).not.toBeNull();
    expect(result?.artifactType).toBe("skill");
    expect(result?.packageName).toBe("opena2a/code-review");
  });

  it("composes the URL with type/name/version query params", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => validBody,
    });
    vi.stubGlobal("fetch", fetchMock);
    await fetchNarrative({
      registryUrl: "https://api.example.com",
      artifactType: "mcp",
      name: "@scope/server",
      version: "1.2.3",
      userAgent: "test/0.0.0",
    });
    const url = String(fetchMock.mock.calls[0][0]);
    expect(url).toContain("/api/v1/trust/narrative");
    expect(url).toContain("type=mcp");
    expect(url).toContain("name=%40scope%2Fserver");
    expect(url).toContain("version=1.2.3");
  });

  it("returns null on 404", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 404 }),
    );
    const result = await fetchNarrative({
      registryUrl: "https://api.example.com",
      artifactType: "skill",
      name: "missing",
      version: "0.0.0",
      userAgent: "test/0.0.0",
    });
    expect(result).toBeNull();
  });

  it("returns null on network error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("ENOTFOUND")),
    );
    const result = await fetchNarrative({
      registryUrl: "https://api.example.com",
      artifactType: "skill",
      name: "x",
      version: "0",
      userAgent: "test/0.0.0",
    });
    expect(result).toBeNull();
  });

  it("returns null when artifactType field is invalid", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ ...validBody, artifactType: "library" }),
      }),
    );
    const result = await fetchNarrative({
      registryUrl: "https://api.example.com",
      artifactType: "skill",
      name: "x",
      version: "0",
      userAgent: "test/0.0.0",
    });
    expect(result).toBeNull();
  });

  it("returns null when required string fields are missing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ ...validBody, packageName: 42 }),
      }),
    );
    const result = await fetchNarrative({
      registryUrl: "https://api.example.com",
      artifactType: "skill",
      name: "x",
      version: "0",
      userAgent: "test/0.0.0",
    });
    expect(result).toBeNull();
  });
});

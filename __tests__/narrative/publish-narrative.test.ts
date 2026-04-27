import { describe, it, expect, vi, afterEach } from "vitest";
import {
  narrativeToRequestBody,
  publishNarrative,
} from "../../src/narrative/publish-narrative.js";
import type { PackageNarrative } from "@opena2a/check-core";

const baseNarrative = (): PackageNarrative => ({
  schemaVersion: 1,
  generatedAt: "2026-04-27T00:00:00.000Z",
  generatedFrom: {
    artifactType: "skill",
    artifactVersion: "1.0.0",
    scanRunId: "00000000-0000-0000-0000-000000000000",
  },
  summary: "",
  hardcodedSecrets: { detected: [], scanCovered: true },
  skill: {
    skillName: "opena2a/refactor-helper",
    activationPhrases: ["refactor"],
    behaviorDescription: "",
    permissions: [],
    externalServices: [],
    persistence: "none",
    toolCallsObserved: [],
    misuseNarrative: "",
    threatModelQuestions: [],
  },
  verdictReasoning: [],
  nextSteps: [],
});

describe("narrativeToRequestBody", () => {
  it("threads packageName through and drops generatedAt", () => {
    const body = narrativeToRequestBody(baseNarrative(), "opena2a/refactor-helper");
    expect(body).toEqual({
      artifactType: "skill",
      packageName: "opena2a/refactor-helper",
      packageVersion: "1.0.0",
      schemaVersion: 1,
      scanRunId: "00000000-0000-0000-0000-000000000000",
      summary: "",
      hardcodedSecrets: { detected: [], scanCovered: true },
      skill: expect.objectContaining({ skillName: "opena2a/refactor-helper" }),
      mcp: undefined,
      verdictReasoning: [],
      nextSteps: [],
    });
  });
});

describe("publishNarrative", () => {
  const realFetch = global.fetch;
  afterEach(() => {
    global.fetch = realFetch;
  });

  it("returns {ok: true, cached: false, status: 201} on a fresh publish", async () => {
    global.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ cached: false }), { status: 201 }),
    ) as unknown as typeof fetch;
    const result = await publishNarrative(
      narrativeToRequestBody(baseNarrative(), "x"),
      { registryUrl: "https://api.oa2a.org" },
    );
    expect(result).toEqual({ ok: true, cached: false, generatedAt: undefined, status: 201 });
  });

  it("propagates cached=true + generatedAt on a 200 cached response", async () => {
    global.fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({ cached: true, generatedAt: "2026-04-26T00:00:00Z" }),
        { status: 200 },
      ),
    ) as unknown as typeof fetch;
    const result = await publishNarrative(
      narrativeToRequestBody(baseNarrative(), "x"),
      { registryUrl: "https://api.oa2a.org/" },
    );
    expect(result.ok).toBe(true);
    expect(result.cached).toBe(true);
    expect(result.generatedAt).toBe("2026-04-26T00:00:00Z");
  });

  it("returns ok:false on a non-2xx response", async () => {
    global.fetch = vi.fn().mockResolvedValue(
      new Response("bad request", { status: 400 }),
    ) as unknown as typeof fetch;
    const result = await publishNarrative(
      narrativeToRequestBody(baseNarrative(), "x"),
      { registryUrl: "https://api.oa2a.org" },
    );
    expect(result.ok).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error).toMatch(/HTTP 400/);
  });

  it("returns ok:false with the error message when fetch throws", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("DNS failure")) as unknown as typeof fetch;
    const result = await publishNarrative(
      narrativeToRequestBody(baseNarrative(), "x"),
      { registryUrl: "https://api.oa2a.org" },
    );
    expect(result.ok).toBe(false);
    expect(result.error).toBe("DNS failure");
  });

  it("strips trailing slash from the registryUrl when composing the path", async () => {
    const fetchSpy = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ cached: false }), { status: 201 }),
    );
    global.fetch = fetchSpy as unknown as typeof fetch;
    await publishNarrative(narrativeToRequestBody(baseNarrative(), "x"), {
      registryUrl: "https://api.oa2a.org/",
    });
    expect(fetchSpy).toHaveBeenCalledWith(
      "https://api.oa2a.org/api/v1/trust/narrative",
      expect.any(Object),
    );
  });

  it("includes the bearer token in Authorization header when provided", async () => {
    const fetchSpy = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ cached: false }), { status: 201 }),
    );
    global.fetch = fetchSpy as unknown as typeof fetch;
    await publishNarrative(narrativeToRequestBody(baseNarrative(), "x"), {
      registryUrl: "https://api.oa2a.org",
      bearerToken: "tok-123",
    });
    const call = fetchSpy.mock.calls[0];
    expect((call[1] as RequestInit).headers).toMatchObject({
      authorization: "Bearer tok-123",
    });
  });
});

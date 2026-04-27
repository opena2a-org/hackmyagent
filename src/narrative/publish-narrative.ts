/**
 * HTTP client for the registry's POST /api/v1/trust/narrative endpoint.
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§4)
 * Registry handler: opena2a-registry/internal/interfaces/http/handlers/package_narrative_handler.go
 *
 * Behavior:
 *   - Best-effort POST. Failure is non-fatal — `secure --publish`
 *     still considers the parent publish a success even if narrative
 *     emission fails.
 *   - Cache TTL is enforced server-side. The handler returns
 *     200 + `{cached: true}` when a fresh row exists; no-op locally.
 *   - Auth: same bearer / signed-payload model as the existing
 *     `/trust/publish` flow.
 */
import type { PackageNarrative } from "@opena2a/check-core";

export interface PublishNarrativeRequest {
  /**
   * Wire-shape body. Translates the @opena2a/check-core
   * `PackageNarrative` into the POST request shape from
   * package_narrative_handler.go.
   */
  artifactType: "skill" | "mcp";
  packageName: string;
  packageVersion: string;
  schemaVersion: 1;
  scanRunId: string;
  summary: string;
  hardcodedSecrets: PackageNarrative["hardcodedSecrets"];
  /** Brief §4 / handler use distinct keys for skill vs mcp narratives. */
  skill?: PackageNarrative["skill"];
  mcp?: PackageNarrative["mcp"];
  verdictReasoning: PackageNarrative["verdictReasoning"];
  nextSteps: PackageNarrative["nextSteps"];
}

export interface PublishNarrativeResult {
  ok: boolean;
  /** True when the registry returned 200 + cached:true (no-op). */
  cached: boolean;
  /** ISO timestamp the registry stamped (only on cached responses). */
  generatedAt?: string;
  /** Human-readable error message on failure. */
  error?: string;
  status?: number;
}

export interface PublishNarrativeOptions {
  /** Registry base URL — same default as the rest of HMA. */
  registryUrl: string;
  /**
   * Bearer token for the publisher service-account. Falls back to
   * `process.env.OPENA2A_REGISTRY_TOKEN` when omitted.
   */
  bearerToken?: string;
  /** Per-call timeout (defaults to 5s). */
  timeoutMs?: number;
}

/**
 * Convert the `PackageNarrative` shape returned by `runRuleEngine` /
 * `buildPackageNarrative` into the registry's POST body shape. Drops
 * `generatedAt` and `generatedFrom` (server-generated), keeps the
 * `schemaVersion` / `scanRunId` provenance fields.
 */
export function narrativeToRequestBody(
  narrative: PackageNarrative,
  packageName: string,
): PublishNarrativeRequest {
  return {
    artifactType: narrative.generatedFrom.artifactType,
    packageName,
    packageVersion: narrative.generatedFrom.artifactVersion,
    schemaVersion: 1,
    scanRunId: narrative.generatedFrom.scanRunId,
    summary: narrative.summary,
    hardcodedSecrets: narrative.hardcodedSecrets,
    skill: narrative.skill,
    mcp: narrative.mcp,
    verdictReasoning: narrative.verdictReasoning,
    nextSteps: narrative.nextSteps,
  };
}

/**
 * POST a narrative payload to the registry. Returns a result object;
 * never throws.
 */
export async function publishNarrative(
  body: PublishNarrativeRequest,
  options: PublishNarrativeOptions,
): Promise<PublishNarrativeResult> {
  const url = `${options.registryUrl.replace(/\/$/, "")}/api/v1/trust/narrative`;
  const token =
    options.bearerToken ?? process.env.OPENA2A_REGISTRY_TOKEN ?? "";
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json",
  };
  if (token.length > 0) {
    headers.authorization = `Bearer ${token}`;
  }
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    options.timeoutMs ?? 5000,
  );
  try {
    const response = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!response.ok) {
      return {
        ok: false,
        cached: false,
        status: response.status,
        error: `narrative publish failed: HTTP ${response.status}`,
      };
    }
    const json = (await response.json()) as {
      cached?: boolean;
      generatedAt?: string;
    };
    return {
      ok: true,
      cached: Boolean(json.cached),
      generatedAt: json.generatedAt,
      status: response.status,
    };
  } catch (err: unknown) {
    clearTimeout(timeout);
    const message = err instanceof Error ? err.message : "unknown error";
    return { ok: false, cached: false, error: message };
  }
}

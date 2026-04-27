/**
 * Narrative fetch helper — GET /api/v1/trust/narrative.
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§8 task 3a).
 *
 * Returns the parsed `PackageNarrative` shape, or `null` on any
 * non-success response (404 narrative_not_available, 4xx, 5xx, network
 * timeout). Always best-effort — the caller falls back to the legacy
 * check block + v1 footer when the registry has no fresh narrative.
 *
 * Wire shape mirrors `packageNarrativeResponse` from the Registry's
 * `internal/interfaces/http/handlers/package_narrative_handler.go`.
 * Inner JSON fields (`hardcodedSecrets`, `skillNarrative`, `mcpNarrative`,
 * `verdictReasoning`, `nextSteps`) ship as opaque JSON values; the
 * adapter parses + validates them before they reach cli-ui renderers.
 */

const NARRATIVE_FETCH_TIMEOUT_MS = 5000;

/**
 * Wire shape for `GET /api/v1/trust/narrative`. Inner JSON fields are
 * left as `unknown` because the registry handler ships them as raw
 * `json.RawMessage` — the adapter is responsible for shape validation.
 */
export interface FetchedPackageNarrative {
  artifactType: "skill" | "mcp";
  packageName: string;
  packageVersion: string;
  schemaVersion: number;
  generatedAt: string;
  summary: string;
  hardcodedSecrets: unknown;
  skillNarrative?: unknown;
  mcpNarrative?: unknown;
  verdictReasoning: unknown;
  nextSteps: unknown;
}

export interface NarrativeFetchOptions {
  registryUrl: string;
  artifactType: "skill" | "mcp";
  name: string;
  version: string;
  userAgent: string;
  /** Override timeout (defaults to 5000ms). */
  timeoutMs?: number;
}

/**
 * Fetch a fresh narrative for the given (type, name, version) tuple.
 * Returns null on 404 (no narrative available) or any error condition.
 * Never throws.
 */
export async function fetchNarrative(
  options: NarrativeFetchOptions,
): Promise<FetchedPackageNarrative | null> {
  const { registryUrl, artifactType, name, version, userAgent } = options;
  const timeoutMs = options.timeoutMs ?? NARRATIVE_FETCH_TIMEOUT_MS;

  const url = new URL("/api/v1/trust/narrative", registryUrl);
  url.searchParams.set("type", artifactType);
  url.searchParams.set("name", name);
  url.searchParams.set("version", version);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url.toString(), {
      method: "GET",
      headers: {
        accept: "application/json",
        "user-agent": userAgent,
      },
      signal: controller.signal,
    });
    if (!res.ok) {
      // 404 narrative_not_available is the documented "graceful
      // degrade" signal. Any other 4xx / 5xx is also treated as a
      // miss — caller falls back to legacy block.
      return null;
    }
    const body = (await res.json()) as Record<string, unknown>;
    const parsed = validateWireShape(body);
    return parsed;
  } catch {
    // Network error, JSON parse error, abort timeout — all degrade to
    // null and let the caller render the legacy block.
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Minimal shape validation. The handler ships well-formed responses,
 * so this is defense-in-depth. Returns null when required top-level
 * fields are missing or the artifactType isn't skill/mcp.
 */
function validateWireShape(
  body: Record<string, unknown>,
): FetchedPackageNarrative | null {
  const artifactType = body.artifactType;
  if (artifactType !== "skill" && artifactType !== "mcp") return null;
  if (typeof body.packageName !== "string" || body.packageName.length === 0) {
    return null;
  }
  if (
    typeof body.packageVersion !== "string" ||
    body.packageVersion.length === 0
  ) {
    return null;
  }
  if (typeof body.schemaVersion !== "number") return null;
  if (typeof body.generatedAt !== "string") return null;
  if (typeof body.summary !== "string") return null;
  return {
    artifactType,
    packageName: body.packageName,
    packageVersion: body.packageVersion,
    schemaVersion: body.schemaVersion,
    generatedAt: body.generatedAt,
    summary: body.summary,
    hardcodedSecrets: body.hardcodedSecrets,
    // Wire shape uses `skill` / `mcp` (matches the registry handler's
    // `json:"skill,omitempty"` tag); the typed value carries the same
    // payload as the internal `SkillNarrative` / `McpNarrative` fields.
    skillNarrative: body.skill,
    mcpNarrative: body.mcp,
    verdictReasoning: body.verdictReasoning,
    nextSteps: body.nextSteps,
  };
}

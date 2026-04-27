/**
 * `check skill:<name>` / `check mcp:<name>` orchestrator.
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§3, §8).
 *
 * Detects the prefix, fetches registry trust + narrative, builds a
 * `CheckRichBlockInput`, and prints via the rich-block renderer. When
 * the narrative is missing or malformed, returns `false` so the
 * caller can fall through to the legacy block + v1 footer.
 */

import { fetchNarrative } from "./narrative-fetch.js";
import { buildRichBlockInput } from "./rich-block-adapter.js";
import { printRichBlock, type RichBlockPalette } from "./render-rich-block.js";
import { renderCheckRichBlock, type CheckRichBlockInput } from "@opena2a/cli-ui";

const SKILL_PREFIX = "skill:";
const MCP_PREFIX = "mcp:";

export interface ParsedRichTarget {
  artifactType: "skill" | "mcp";
  name: string;
}

/**
 * Parse `skill:<name>` / `mcp:<name>` prefixes. Returns null when the
 * input has no recognised prefix — the caller routes through the
 * legacy dispatch (npm / PyPI / GitHub / local).
 */
export function parseRichTarget(target: string): ParsedRichTarget | null {
  if (target.startsWith(SKILL_PREFIX)) {
    const name = target.slice(SKILL_PREFIX.length);
    if (name.length === 0) return null;
    return { artifactType: "skill", name };
  }
  if (target.startsWith(MCP_PREFIX)) {
    const name = target.slice(MCP_PREFIX.length);
    if (name.length === 0) return null;
    return { artifactType: "mcp", name };
  }
  return null;
}

/**
 * Map a registry verdict + scanStatus to the rich-block trustVerdict
 * tier. Brief §3 mockup tiers: VERIFIED / LISTED / LISTED_UNSCANNED /
 * BLOCKED.
 */
export function deriveTrustVerdict(
  verdict: string | undefined,
  trustLevel: number | undefined,
  scanStatus: string | undefined,
): "VERIFIED" | "LISTED" | "LISTED_UNSCANNED" | "BLOCKED" {
  const v = (verdict ?? "").toLowerCase();
  if (v === "blocked" || trustLevel === 0) return "BLOCKED";
  if (trustLevel === 4 || v === "verified") return "VERIFIED";
  // LISTED requires a successful scan. Any non-"completed" status —
  // pending, queued, error, never — degrades to LISTED_UNSCANNED so
  // the rich-block header doesn't promise a measurement that didn't
  // succeed (mirrors HMA-1's Trust meter gating in displayUnifiedCheck).
  if (scanStatus !== "completed") return "LISTED_UNSCANNED";
  return "LISTED";
}

export interface RegistryTrustForRichBlock {
  found: boolean;
  name: string;
  trustScore: number;
  trustLevel: number;
  verdict: string;
  scanStatus?: string;
  lastScannedAt?: string;
  packageType?: string;
  communityScans?: number;
}

export interface CheckSkillOrMcpOptions {
  parsed: ParsedRichTarget;
  registryUrl: string;
  userAgent: string;
  /** Tool name for the secrets-block report command (e.g. "hackmyagent"). */
  reportTool: string;
  /** Trust data already fetched by the caller via the existing client. */
  trust: RegistryTrustForRichBlock | null;
  /** Pre-built palette to paint the output. */
  palette: RichBlockPalette;
  /**
   * Optional narrative version override. When omitted, the orchestrator
   * uses the registry's `lastScannedAt`-tied version implicitly by
   * passing the trust's `name` + a wildcard "latest" marker — but the
   * wire endpoint requires an explicit version, so we ask the caller
   * to pass it.
   */
  version?: string;
  /** Local-scan findings to display under "What we observed". */
  localFindings?: Parameters<typeof buildRichBlockInput>[0]["localFindings"];
  /**
   * Suppress the human-readable rich-block render. The orchestrator
   * still builds the input and reports `rendered: true` so the caller
   * can emit `result.input` as JSON. Used by `--json` callers and the
   * opena2a-parity harness so output is parseable.
   */
  silent?: boolean;
}

export interface CheckSkillOrMcpResult {
  /** True when the rich block was printed. False → caller falls back. */
  rendered: boolean;
  /** Raw input passed to renderCheckRichBlock — useful for tests / --json. */
  input?: CheckRichBlockInput;
}

/**
 * Run the rich-block path. Returns `{rendered: false}` when the
 * narrative is unavailable; the caller is expected to print the
 * legacy block + v1 footer on that signal.
 */
export async function checkSkillOrMcp(
  options: CheckSkillOrMcpOptions,
): Promise<CheckSkillOrMcpResult> {
  const { parsed, trust } = options;

  // Default to the registry's latest-version sentinel when the caller
  // didn't pin a version. Registry resolves via FindLatestFresh.
  const version = options.version && options.version.length > 0
    ? options.version
    : "latest";

  const narrative = await fetchNarrative({
    registryUrl: options.registryUrl,
    artifactType: parsed.artifactType,
    name: parsed.name,
    version,
    userAgent: options.userAgent,
  });
  // No narrative → rich-block path can't render. Caller falls back to
  // legacy block + v1 footer.
  if (!narrative) {
    return { rendered: false };
  }

  // Trust record may be sparse or missing for newly-seeded narratives.
  // Use the trust data when available, otherwise fall back to a
  // LISTED_UNSCANNED header — the narrative carries the bulk of the
  // information, the trust block is just the score + scan-age line.
  const trustInput = trust && trust.found
    ? {
        trustVerdict: deriveTrustVerdict(
          trust.verdict,
          trust.trustLevel,
          trust.scanStatus,
        ),
        trustScore:
          trust.scanStatus === "completed"
            ? Math.round(trust.trustScore * 100)
            : undefined,
        scanStatus: trust.scanStatus,
        lastScanAge: formatScanAge(trust.lastScannedAt),
        latestVersionLabel: narrative.packageVersion,
        communityScans: trust.communityScans,
      }
    : {
        trustVerdict: "LISTED_UNSCANNED" as const,
        latestVersionLabel: narrative.packageVersion,
      };

  const input = buildRichBlockInput({
    name: parsed.name,
    artifactType: parsed.artifactType,
    narrative,
    trust: trustInput,
    reportTool: options.reportTool,
    localFindings: options.localFindings,
  });

  if (!input) {
    return { rendered: false };
  }

  if (options.silent) {
    // Caller will serialize `input` to JSON. No text output.
    return { rendered: true, input };
  }

  const rendered = renderCheckRichBlock(input);
  printRichBlock(rendered, { palette: options.palette });

  return { rendered: true, input };
}

function formatScanAge(lastScannedAt?: string): string | undefined {
  if (!lastScannedAt) return undefined;
  const scanned = new Date(lastScannedAt);
  if (Number.isNaN(scanned.getTime())) return undefined;
  const days = Math.floor(
    (Date.now() - scanned.getTime()) / (1000 * 60 * 60 * 24),
  );
  if (days < 1) return "today";
  if (days === 1) return "1d ago";
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  if (months === 1) return "1mo ago";
  if (months < 12) return `${months}mo ago`;
  const years = Math.floor(days / 365);
  return years === 1 ? "1y ago" : `${years}y ago`;
}

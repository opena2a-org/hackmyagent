/**
 * Rich-block adapter — combines the registry-fetched narrative,
 * registry trust data, and runtime args into a `CheckRichBlockInput`
 * suitable for `renderCheckRichBlock` from `@opena2a/cli-ui`.
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§3, §5, §7).
 *
 * Pure function — no I/O. Validates inner JSON shapes (the registry
 * handler ships them as opaque JSON.RawMessage) and returns null when
 * the narrative is missing required structure for the artifact type.
 *
 * The adapter never invents data. Missing fields fall through to
 * sensible empty defaults so the cli-ui renderer can still produce a
 * legible block — the alternative is a hard failure that the caller
 * would have to translate to "fall back to legacy block" anyway.
 */

import type {
  CheckRichBlockInput,
  RichObservationFinding,
  SecretLike,
  SkillNarrativeLike,
  McpNarrativeLike,
  VerdictReasoningStatementLike,
  NextStepLike,
  PermissionStatusLike,
  ToolCallCountLike,
  McpToolLike,
  RichBlockHeaderSignals,
} from "@opena2a/cli-ui";
import type { FetchedPackageNarrative } from "./narrative-fetch.js";

/**
 * Trust-data fields the adapter needs from the registry. Defined here
 * (not imported from cli.ts) to keep this module decoupled — the
 * caller maps `RegistryTrustData` to this shape.
 */
export interface RichBlockTrustInput {
  trustVerdict: "VERIFIED" | "LISTED" | "LISTED_UNSCANNED" | "BLOCKED";
  trustScore?: number;
  scanStatus?: string;
  lastScanAge?: string;
  latestVersionLabel?: string;
  publisher?: { name: string; verified: boolean; kind?: string };
  license?: string;
  maintainerCount?: number;
  downloads?: { perWeek: number; trend?: "rising" | "steady" | "declining" };
  communityScans?: number;
}

export interface BuildRichBlockInputArgs {
  /** Package name as the user typed it (without prefix). */
  name: string;
  artifactType: "skill" | "mcp";
  narrative: FetchedPackageNarrative;
  trust: RichBlockTrustInput;
  /** Tool name for the secrets-block report command. */
  reportTool: string;
  /** Local-scan findings, when available. Shape mirrors HMA's SecurityFinding. */
  localFindings?: Array<{
    severity: "critical" | "high" | "medium" | "low";
    checkId: string;
    name?: string;
    file?: string;
    line?: number;
    message?: string;
    fix?: string;
  }>;
}

/**
 * Build the CheckRichBlockInput. Returns null when the narrative does
 * not satisfy the minimum shape for its artifactType (e.g. skill
 * narrative present but inner skillNarrative field missing).
 */
export function buildRichBlockInput(
  args: BuildRichBlockInputArgs,
): CheckRichBlockInput | null {
  const { narrative, trust, artifactType } = args;

  // Inner-narrative artifact-type check — if a skill: target was
  // requested but the registry stored an mcpNarrative (or vice versa)
  // we treat that as missing data. Caller falls back to legacy block.
  if (artifactType === "skill" && narrative.artifactType !== "skill") {
    return null;
  }
  if (artifactType === "mcp" && narrative.artifactType !== "mcp") return null;

  const hardcodedSecrets = parseHardcodedSecrets(narrative.hardcodedSecrets);
  const verdictReasoning = parseVerdictReasoning(narrative.verdictReasoning);
  const nextSteps = parseNextSteps(narrative.nextSteps);
  const findings = mapLocalFindings(args.localFindings ?? []);

  let skill: SkillNarrativeLike | undefined;
  let mcp: McpNarrativeLike | undefined;

  if (artifactType === "skill") {
    const parsed = parseSkillNarrative(narrative.skillNarrative);
    if (!parsed) return null;
    skill = parsed;
  } else {
    const parsed = parseMcpNarrative(narrative.mcpNarrative);
    if (!parsed) return null;
    mcp = parsed;
  }

  const header: RichBlockHeaderSignals = {
    trustVerdict: trust.trustVerdict,
    trustScore: trust.trustScore,
    lastScanAge: trust.lastScanAge,
    latestVersionLabel: trust.latestVersionLabel,
    publisher: trust.publisher,
    license: trust.license,
    maintainerCount: trust.maintainerCount,
    downloads: trust.downloads,
    communityScans: trust.communityScans,
    findingsCount: findings.length,
  };

  return {
    name: args.name,
    artifactType,
    header,
    hardcodedSecrets,
    latestVersion: narrative.packageVersion,
    skill,
    mcp,
    findings,
    verdictReasoning,
    nextSteps,
    reportTool: args.reportTool,
  };
}

// ---------------------------------------------------------------------------
// Inner-JSON shape validators
// ---------------------------------------------------------------------------

function parseHardcodedSecrets(raw: unknown): {
  detected: SecretLike[];
  scanCovered: boolean;
} {
  if (!isPlainObject(raw)) {
    return { detected: [], scanCovered: false };
  }
  const scanCovered = typeof raw.scanCovered === "boolean"
    ? raw.scanCovered
    : false;
  const detected: SecretLike[] = [];
  if (Array.isArray(raw.detected)) {
    for (const entry of raw.detected) {
      const parsed = parseSecret(entry);
      if (parsed) detected.push(parsed);
    }
  }
  return { detected, scanCovered };
}

function parseSecret(raw: unknown): SecretLike | null {
  if (!isPlainObject(raw)) return null;
  const severity = raw.severity;
  if (
    severity !== "critical" &&
    severity !== "high" &&
    severity !== "medium" &&
    severity !== "low"
  ) {
    return null;
  }
  if (typeof raw.type !== "string" || typeof raw.typeLabel !== "string") {
    return null;
  }
  if (typeof raw.file !== "string") return null;
  if (typeof raw.maskedValue !== "string") return null;
  if (typeof raw.shownChars !== "number") return null;
  if (typeof raw.totalChars !== "number") return null;
  if (typeof raw.shipsInArtifact !== "boolean") return null;
  return {
    type: raw.type,
    typeLabel: raw.typeLabel,
    file: raw.file,
    line: typeof raw.line === "number" ? raw.line : undefined,
    maskedValue: raw.maskedValue,
    shownChars: raw.shownChars,
    totalChars: raw.totalChars,
    shipsInArtifact: raw.shipsInArtifact,
    severity,
    rotationUrl: typeof raw.rotationUrl === "string" ? raw.rotationUrl : undefined,
    rotationCommand:
      typeof raw.rotationCommand === "string" ? raw.rotationCommand : undefined,
  };
}

function parseSkillNarrative(raw: unknown): SkillNarrativeLike | null {
  if (!isPlainObject(raw)) return null;
  if (typeof raw.skillName !== "string") return null;
  const activationPhrases = stringArray(raw.activationPhrases);
  const externalServices = stringArray(raw.externalServices);
  const permissions = parsePermissions(raw.permissions);
  const toolCallsObserved = parseToolCalls(raw.toolCallsObserved);
  return {
    skillName: raw.skillName,
    activationPhrases,
    behaviorDescription:
      typeof raw.behaviorDescription === "string"
        ? raw.behaviorDescription
        : "",
    permissions,
    externalServices,
    persistence:
      typeof raw.persistence === "string" ? raw.persistence : "",
    toolCallsObserved,
    misuseNarrative:
      typeof raw.misuseNarrative === "string" ? raw.misuseNarrative : "",
  };
}

function parseMcpNarrative(raw: unknown): McpNarrativeLike | null {
  if (!isPlainObject(raw)) return null;
  if (typeof raw.mcpName !== "string") return null;
  const tools = parseMcpTools(raw.tools);
  const sideEffects = stringArray(raw.sideEffects);
  return {
    mcpName: raw.mcpName,
    tools,
    pathScope: typeof raw.pathScope === "string" ? raw.pathScope : "",
    network: typeof raw.network === "string" ? raw.network : "",
    persistence: typeof raw.persistence === "string" ? raw.persistence : "",
    auth: typeof raw.auth === "string" ? raw.auth : "",
    sideEffects,
  };
}

function parsePermissions(raw: unknown): PermissionStatusLike[] {
  if (!Array.isArray(raw)) return [];
  const out: PermissionStatusLike[] = [];
  for (const entry of raw) {
    if (!isPlainObject(entry)) continue;
    if (typeof entry.name !== "string") continue;
    const status = entry.status;
    if (status !== "used" && status !== "unused" && status !== "undeclared") {
      continue;
    }
    out.push({
      name: entry.name,
      declared: !!entry.declared,
      used: !!entry.used,
      status,
      note: typeof entry.note === "string" ? entry.note : undefined,
    });
  }
  return out;
}

function parseToolCalls(raw: unknown): ToolCallCountLike[] {
  if (!Array.isArray(raw)) return [];
  const out: ToolCallCountLike[] = [];
  for (const entry of raw) {
    if (!isPlainObject(entry)) continue;
    if (typeof entry.tool !== "string") continue;
    if (typeof entry.count !== "number") continue;
    out.push({ tool: entry.tool, count: entry.count });
  }
  return out;
}

function parseMcpTools(raw: unknown): McpToolLike[] {
  if (!Array.isArray(raw)) return [];
  const out: McpToolLike[] = [];
  for (const entry of raw) {
    if (!isPlainObject(entry)) continue;
    if (typeof entry.name !== "string") continue;
    out.push({
      name: entry.name,
      signature: typeof entry.signature === "string" ? entry.signature : "",
      description:
        typeof entry.description === "string" ? entry.description : "",
      destructive: !!entry.destructive,
    });
  }
  return out;
}

function parseVerdictReasoning(raw: unknown): VerdictReasoningStatementLike[] {
  if (!Array.isArray(raw)) return [];
  const out: VerdictReasoningStatementLike[] = [];
  for (const entry of raw) {
    if (!isPlainObject(entry)) continue;
    const kind = entry.kind;
    if (kind !== "positive" && kind !== "gap" && kind !== "critical") continue;
    if (typeof entry.text !== "string") continue;
    out.push({ kind, text: entry.text });
  }
  return out;
}

function parseNextSteps(raw: unknown): NextStepLike[] {
  if (!Array.isArray(raw)) return [];
  const out: NextStepLike[] = [];
  for (const entry of raw) {
    if (!isPlainObject(entry)) continue;
    const weight = entry.weight;
    if (weight !== "primary" && weight !== "secondary") continue;
    if (typeof entry.label !== "string") continue;
    out.push({
      weight,
      label: entry.label,
      command: typeof entry.command === "string" ? entry.command : undefined,
      url: typeof entry.url === "string" ? entry.url : undefined,
    });
  }
  return out;
}

function mapLocalFindings(
  findings: BuildRichBlockInputArgs["localFindings"] = [],
): RichObservationFinding[] {
  const out: RichObservationFinding[] = [];
  for (const f of findings) {
    const locator = f.file
      ? f.line !== undefined
        ? `${f.file}:${f.line}`
        : f.file
      : "";
    out.push({
      severity: f.severity,
      ruleId: f.checkId,
      locator,
      description: f.message ?? f.name ?? f.checkId,
      fix: f.fix,
    });
  }
  return out;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function stringArray(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const entry of raw) {
    if (typeof entry === "string") out.push(entry);
  }
  return out;
}

/**
 * Orchestrator — assembles a `PackageNarrative` from existing scan
 * outputs (SecurityAST, findings, scan-run id, package version).
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§4)
 *
 * The narrative is the wire shape POSTed to
 * `POST /api/v1/trust/narrative` on `secure --publish` for skill / mcp
 * artifacts. Other artifact types are out of scope in v1; this module
 * returns null for them so the caller skips the publish.
 */
import type {
  HardcodedSecret,
  HardcodedSecretsBlock,
  PackageNarrative,
  RuleEngineInput,
  RuleEngineOutput,
} from "@opena2a/check-core";
import {
  enrichSecretRotation,
  runRuleEngine,
} from "@opena2a/check-core";
import { randomUUID } from "node:crypto";
import type { SecurityAST } from "../nanomind-core/types.js";
import type { SecurityFinding } from "../hardening";
import {
  buildSkillNarrative,
  type BuildSkillNarrativeInput,
} from "./skill-narrative.js";
import {
  buildMcpNarrative,
  type BuildMcpNarrativeInput,
} from "./mcp-narrative.js";
import { generateNarrativeSummary } from "./narrative-summary.js";

/**
 * Map HMA's canonical credential labels to check-core's `type` strings.
 * Drives the rotation-URL lookup in `secret-rotation.ts`. Labels that
 * don't appear here fall through to `unknown` — the renderer then
 * surfaces a generic "rotate at the issuing service" path.
 */
const CREDENTIAL_LABEL_TO_TYPE: Record<string, string> = {
  "Anthropic API key": "anthropic_api_key",
  "OpenAI project key": "openai_api_key",
  "OpenAI API key": "openai_api_key",
  "AWS access key": "aws_access_key",
  "GitHub personal access token": "github_pat",
  "GitHub OAuth token": "github_pat",
  "GitHub app token": "github_pat",
  "Slack bot token": "slack_bot_token",
  "Google API key": "gcp_service_account_key",
  "Stripe live key": "stripe_secret_key",
  "PEM private key": "private_key",
};

/** Inputs to the assembly. */
export interface BuildPackageNarrativeInput {
  ast: SecurityAST;
  /** scan run identifier — UUID. Generated when omitted. */
  scanRunId?: string;
  /** Resolved package name on the registry (skill or mcp). */
  packageName: string;
  /** Latest version of the artifact at scan time. */
  packageVersion: string;
  /** Hardening-scan findings used for hardcoded-secrets extraction. */
  findings: SecurityFinding[];
  /** SKILL.md frontmatter, when artifactType === "skill". */
  skillFrontmatter?: Record<string, unknown>;
  /** Raw SKILL.md text — used for activation-phrase fallback parsing. */
  skillSource?: string;
  /** MCP config object, when artifactType === "mcp_config". */
  mcpConfig?: Record<string, unknown>;
  /** MCP tool registrations, when artifactType === "mcp_config". */
  mcpToolRegistrations?: BuildMcpNarrativeInput["toolRegistrations"];
  /** Trust verdict produced by the registry/scoring logic. */
  verdict: RuleEngineInput["verdict"];
  /** Scan status as the registry sees it. */
  scanStatus: RuleEngineInput["scanStatus"];
  /** Publisher signals known to the registry. */
  publisher: RuleEngineInput["publisher"];
  /** Provenance attestations. */
  attestations: RuleEngineInput["attestations"];
  communityScans: number;
  cleanCommunityScans: number;
  hasSoulFile: boolean;
  /** When destructive MCP tools ship with safety affordances. */
  mcpHasSafetyAffordances?: boolean;
  /** Last-known-clean version, drives the LISTED skill pin secondary. */
  lastCleanVersion?: string;
  /** NOT_FOUND-tier suggestion list — caller-injected. */
  notFoundSuggestions?: string[];
}

/**
 * Assemble the full PackageNarrative. Returns null when the AST is not
 * a skill or mcp_config — those are the only artifact types in v1
 * scope per brief §2.
 */
export async function buildPackageNarrative(
  input: BuildPackageNarrativeInput,
): Promise<PackageNarrative | null> {
  const { ast } = input;
  if (ast.artifactType !== "skill" && ast.artifactType !== "mcp_config") {
    return null;
  }

  // Hardcoded secrets pulled from the existing scan findings. The
  // canonical credential scanner already produces credential-class
  // findings — this just reshapes them to the wire type.
  const hardcodedSecrets = extractHardcodedSecrets(input.findings).map(
    enrichSecretRotation,
  );

  // NanoMind v3 comprehension — graceful-degrade in v1.
  const nanomind = await generateNarrativeSummary(ast);

  // Rule-engine output for verdict reasoning + nextSteps.
  const ruleEngineInput = composeRuleEngineInput(input, hardcodedSecrets);
  const ruleEngineOutput: RuleEngineOutput = runRuleEngine(ruleEngineInput);

  const hardcodedSecretsBlock: HardcodedSecretsBlock = ruleEngineOutput.hardcodedSecretsBlock;
  const artifactTypeForSummary: "skill" | "mcp" =
    ast.artifactType === "skill" ? "skill" : "mcp";

  const narrative: PackageNarrative = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    generatedFrom: {
      artifactType: artifactTypeForSummary,
      artifactVersion: input.packageVersion,
      scanRunId: input.scanRunId ?? randomUUID(),
    },
    summary: synthesizeSummary(nanomind.summary, input, artifactTypeForSummary),
    hardcodedSecrets: hardcodedSecretsBlock,
    verdictReasoning: ruleEngineOutput.verdictReasoning,
    nextSteps: ruleEngineOutput.nextSteps,
  };

  if (ast.artifactType === "skill") {
    const skillInput: BuildSkillNarrativeInput = {
      ast,
      frontmatter: input.skillFrontmatter,
      skillSource: input.skillSource,
      findings: input.findings,
      behaviorDescription: nanomind.behaviorDescription,
      misuseNarrative: nanomind.misuseNarrative,
    };
    narrative.skill = buildSkillNarrative(skillInput);
  } else {
    const mcpInput: BuildMcpNarrativeInput = {
      ast,
      config: input.mcpConfig,
      toolRegistrations: input.mcpToolRegistrations,
      findings: input.findings,
      fallbackName: input.packageName,
    };
    narrative.mcp = buildMcpNarrative(mcpInput);
  }

  return narrative;
}

/**
 * Pick a non-empty `summary` for the registry POST. The registry
 * rejects empty summaries with HTTP 400 `invalid_summary`; until
 * NanoMind v3 wires real comprehension generation, fall back to the
 * artifact author's own description, then a deterministic last-resort
 * line so `secure --publish` never fails on summary alone.
 *
 * Order:
 *   1. NanoMind summary (when non-empty).
 *   2. SKILL.md frontmatter `description` (skill) or
 *      package.json `description` (mcp).
 *   3. Generic `Skill: <name>` / `MCP: <name>`.
 *
 * Single-line, whitespace-collapsed, capped at the registry's 4096
 * `narrativeMaxSummaryBytes` limit (handler:80).
 */
export function synthesizeSummary(
  nanomindSummary: string,
  input: BuildPackageNarrativeInput,
  artifactType: "skill" | "mcp",
): string {
  const trim = (s: unknown): string =>
    typeof s === "string" ? s.replace(/\s+/g, " ").trim() : "";
  const cap = (s: string): string => (s.length > 4096 ? s.slice(0, 4096) : s);

  const fromNanomind = trim(nanomindSummary);
  if (fromNanomind) return cap(fromNanomind);

  const fromAuthor =
    artifactType === "skill"
      ? trim(input.skillFrontmatter?.description)
      : trim(input.mcpConfig?.description);
  if (fromAuthor) return cap(fromAuthor);

  return artifactType === "skill"
    ? `Skill: ${input.packageName}`
    : `MCP: ${input.packageName}`;
}

/**
 * Extract hardcoded-credential findings from the scan output and
 * reshape them as `HardcodedSecret` entries. Recognized HMA
 * credential-class findings are: any finding with category
 * `credentials` / `web-credentials` / `credential-exposure` /
 * `agent-credential`, or any finding whose `attackClass` starts with
 * `CRED-` / `AST-CRED-` / `WEBCRED-` / `SEM-CRED-` / `AGENT-CRED-`.
 */
function extractHardcodedSecrets(findings: SecurityFinding[]): HardcodedSecret[] {
  const credentialCategories = new Set([
    "credentials",
    "web-credentials",
    "credential-exposure",
    "agent-credential",
  ]);
  const credentialAttackPrefixes = [
    "CRED-",
    "AST-CRED-",
    "WEBCRED-",
    "SEM-CRED-",
    "AGENT-CRED-",
    "ENVLEAK",
    "CLIPASS",
  ];
  const out: HardcodedSecret[] = [];
  for (const f of findings) {
    const isCredFinding =
      credentialCategories.has(f.category) ||
      (typeof f.attackClass === "string" &&
        credentialAttackPrefixes.some((p) => f.attackClass!.startsWith(p)));
    if (!isCredFinding) continue;
    const label = extractLabelFromFinding(f);
    const type = label
      ? CREDENTIAL_LABEL_TO_TYPE[label] ?? "unknown"
      : "unknown";
    out.push({
      type,
      typeLabel: label ?? "",
      file: f.file ?? "",
      line: f.line,
      maskedValue: maskCredential(extractRawValue(f)),
      shownChars: countShownChars(extractRawValue(f)),
      totalChars: (extractRawValue(f) ?? "").length,
      shipsInArtifact: shipsInArtifact(f),
      severity: mapSeverity(f.severity),
    });
  }
  return out;
}

function extractLabelFromFinding(f: SecurityFinding): string | undefined {
  // The canonical credential scanner sets findings whose name/title
  // includes "Hardcoded <label>" (see semantic-compiler.ts:159).
  const m = (f.name ?? f.message ?? "").match(/Hardcoded ([^.]+)/);
  if (m && m[1]) return m[1].trim();
  // Fall back to a likely-label in `details`.
  const detailLabel = (f.details as { label?: string } | undefined)?.label;
  if (typeof detailLabel === "string") return detailLabel;
  return undefined;
}

function extractRawValue(f: SecurityFinding): string | undefined {
  const detailValue = (f.details as { value?: string; rawValue?: string } | undefined);
  return detailValue?.value ?? detailValue?.rawValue;
}

function maskCredential(value?: string): string {
  if (!value || value.length === 0) return "";
  // Preserve recognizable prefixes for known formats.
  const knownPrefixes = [
    "sk-ant-api03-",
    "sk-ant-api02-",
    "sk-proj-",
    "ghp_",
    "gho_",
    "ghs_",
    "AKIA",
    "AIza",
    "xoxb-",
    "xoxa-",
    "xoxp-",
    "sk_live_",
    "-----BEGIN",
  ];
  for (const prefix of knownPrefixes) {
    if (value.startsWith(prefix)) {
      const remaining = Math.max(0, value.length - prefix.length);
      return `${prefix}${"*".repeat(Math.min(remaining, 16))}`;
    }
  }
  // Unknown shape — show first 8 chars + asterisks.
  return `${value.slice(0, 8)}${"*".repeat(Math.min(value.length - 8, 16))}`;
}

function countShownChars(value?: string): number {
  if (!value) return 0;
  const knownPrefixes = [
    "sk-ant-api03-",
    "sk-ant-api02-",
    "sk-proj-",
    "ghp_",
    "gho_",
    "ghs_",
    "AKIA",
    "AIza",
    "xoxb-",
    "xoxa-",
    "xoxp-",
    "sk_live_",
    "-----BEGIN",
  ];
  for (const prefix of knownPrefixes) {
    if (value.startsWith(prefix)) return prefix.length;
  }
  return Math.min(8, value.length);
}

/**
 * "Ships in artifact" heuristic. Conservative: assume yes unless the
 * file path obviously points at a local-only fixture (test/, fixtures/,
 * .env-style file).
 */
function shipsInArtifact(f: SecurityFinding): boolean {
  const file = f.file ?? "";
  if (/^(test|tests|fixtures|__tests__|examples\/.*\.test\.|examples\/__)/.test(file)) {
    return false;
  }
  if (/\.env(\.|$)/.test(file)) return false;
  return true;
}

function mapSeverity(severity: SecurityFinding["severity"]): HardcodedSecret["severity"] {
  if (severity === "critical") return "critical";
  if (severity === "high") return "high";
  if (severity === "medium") return "medium";
  return "low";
}

/**
 * Compose the rule-engine input from the assembly inputs + extracted
 * narrative pieces. Defaults reflect "scan covered, no skill data" so
 * the engine treats missing fields conservatively.
 */
function composeRuleEngineInput(
  input: BuildPackageNarrativeInput,
  hardcodedSecrets: HardcodedSecret[],
): RuleEngineInput {
  const { ast } = input;
  const artifactType: RuleEngineInput["artifactType"] =
    ast.artifactType === "skill" ? "skill" : "mcp";
  // skill/mcp narratives feed the rule engine the permission delta /
  // destructive-tool list. For non-skill/mcp paths buildPackageNarrative
  // returns null before this is called, so this is always reachable.
  const skill =
    ast.artifactType === "skill"
      ? buildSkillNarrative({
          ast,
          frontmatter: input.skillFrontmatter,
          skillSource: input.skillSource,
          findings: input.findings,
        })
      : undefined;
  const mcp =
    ast.artifactType === "mcp_config"
      ? buildMcpNarrative({
          ast,
          config: input.mcpConfig,
          toolRegistrations: input.mcpToolRegistrations,
          findings: input.findings,
          fallbackName: input.packageName,
        })
      : undefined;
  return {
    packageName: input.packageName,
    latestVersion: input.packageVersion,
    lastCleanVersion: input.lastCleanVersion ?? "",
    artifactType,
    verdict: input.verdict,
    scanStatus: input.scanStatus,
    publisher: input.publisher,
    attestations: input.attestations,
    communityScans: input.communityScans,
    cleanCommunityScans: input.cleanCommunityScans,
    hasSoulFile: input.hasSoulFile,
    findings: input.findings.map((f) => ({
      ruleId: f.checkId,
      severity:
        f.severity === "critical"
          ? "critical"
          : f.severity === "high"
            ? "high"
            : f.severity === "medium"
              ? "medium"
              : f.severity === "low"
                ? "low"
                : "info",
      description: f.message,
      locator: f.file ? (f.line ? `${f.file}:${f.line}` : f.file) : undefined,
    })),
    hardcodedSecrets,
    scanCovered: true,
    skill,
    mcp,
    mcpHasSafetyAffordances: input.mcpHasSafetyAffordances ?? false,
    notFoundSuggestions: input.notFoundSuggestions ?? [],
  };
}

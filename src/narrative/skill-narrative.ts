/**
 * Skill narrative builder — turns a SecurityAST + scan findings into the
 * `SkillNarrative` wire shape consumed by @opena2a/check-core's
 * `runRuleEngine` and the registry's `package_narratives` row.
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§4)
 *
 * No new AST analysis here — every field is shaped from data the
 * SemanticCompiler / scanner already produced. Where comprehension data
 * is missing (e.g. NanoMind v3 summary) the field is empty / a sane
 * default; the renderer treats empty content as graceful-degrade.
 */
import type {
  PermissionStatus,
  SkillNarrative,
  ToolCallCount,
} from "@opena2a/check-core";
import type { SecurityAST, Capability, DataAccessPattern } from "../nanomind-core/types.js";
import type { SecurityFinding } from "../hardening";

/**
 * Static threat-model questions for the skill artifact type. Curated
 * by [CHIEF-CSR] per brief §6.1; rendered verbatim. Kept here (rather
 * than cli-ui) so the registry stores the full narrative — keeps the
 * renderer dumb.
 */
export const SKILL_THREAT_MODEL_QUESTIONS = [
  "Where will users invoke this skill? Is the CWD bounded to a project the user owns, or could it run in a directory containing secrets (e.g. ~/.ssh, ~/.aws)?",
  "Do you require pinning to a specific skill version, or does your fleet auto-update on publish?",
  "Is your Claude API key scoped per-user, or shared across a tenant where one user's prompt can affect another's?",
];

/**
 * Inputs to `buildSkillNarrative`. Only the AST is required; the rest
 * are optional and degrade gracefully when absent.
 */
export interface BuildSkillNarrativeInput {
  ast: SecurityAST;
  /** Frontmatter parsed from SKILL.md. `name`, `description`, `capabilities` etc. */
  frontmatter?: Record<string, unknown>;
  /** Full SKILL.md raw content; only used for activation-phrase parsing. */
  skillSource?: string;
  /** All findings the scanner produced for this skill artifact. */
  findings?: SecurityFinding[];
  /**
   * NanoMind v3 outputs. v1 ships with these as empty strings — see
   * `narrative-summary.ts` for the graceful-degrade gate.
   */
  behaviorDescription?: string;
  misuseNarrative?: string;
}

/**
 * Build a `SkillNarrative` from a compiled SKILL.md AST + scan results.
 */
export function buildSkillNarrative(input: BuildSkillNarrativeInput): SkillNarrative {
  const { ast, frontmatter, skillSource, findings, behaviorDescription, misuseNarrative } = input;
  const skillName = resolveSkillName(ast, frontmatter);
  return {
    skillName,
    activationPhrases: extractActivationPhrases(frontmatter, skillSource),
    behaviorDescription: behaviorDescription ?? "",
    permissions: buildPermissionDelta(ast),
    externalServices: extractExternalServices(ast),
    persistence: classifyPersistence(ast),
    toolCallsObserved: extractToolCallCounts(ast, findings),
    misuseNarrative: misuseNarrative ?? "",
    threatModelQuestions: SKILL_THREAT_MODEL_QUESTIONS,
  };
}

// ---- helpers --------------------------------------------------------

function resolveSkillName(
  ast: SecurityAST,
  frontmatter?: Record<string, unknown>,
): string {
  const fmName = frontmatter?.name;
  if (typeof fmName === "string" && fmName.length > 0) return fmName;
  if (ast.artifactPath) {
    // Skill path conventionally ends in `.../<publisher>/<name>/SKILL.md`.
    // Drop a trailing `SKILL.md` / `SKILL` leaf so the caller sees the
    // meaningful publisher/name pair instead of the file basename.
    const parts = ast.artifactPath.split("/").filter(Boolean);
    if (parts.length === 0) return "unnamed-skill";
    const last = parts[parts.length - 1].replace(/\.md$/, "");
    const trimmed = last === "SKILL" ? parts.slice(0, -1) : parts;
    if (trimmed.length >= 2) return trimmed.slice(-2).join("/");
    return trimmed[trimmed.length - 1];
  }
  return "unnamed-skill";
}

/**
 * Extract activation phrases from SKILL.md frontmatter. Looks for
 * common shapes:
 *   - `activation_phrases: [phrase1, phrase2]`
 *   - `activation: [phrase1, ...]`
 *   - `triggers: [...]`
 * Falls back to scanning the description for quoted strings if no
 * structured list is present.
 */
function extractActivationPhrases(
  frontmatter?: Record<string, unknown>,
  skillSource?: string,
): string[] {
  const candidates = ["activation_phrases", "activationPhrases", "activation", "triggers"];
  for (const key of candidates) {
    const value = frontmatter?.[key];
    if (Array.isArray(value)) {
      return value
        .map((entry) => (typeof entry === "string" ? entry.trim() : ""))
        .filter((entry) => entry.length > 0);
    }
  }
  // Fallback: pull quoted strings out of the description.
  const description = frontmatter?.description;
  if (typeof description === "string") {
    const quoted = description.match(/"([^"\\]+)"/g);
    if (quoted && quoted.length > 0) {
      return quoted.map((q) => q.slice(1, -1));
    }
  }
  // Last resort: scan the source for "Activates on:" / "Trigger:" lines.
  if (skillSource) {
    const line = skillSource
      .split("\n")
      .find((l) => /^\s*(Activates on|Trigger|Triggers)\s*:/i.test(l));
    if (line) {
      const after = line.split(":").slice(1).join(":").trim();
      if (after.length > 0) {
        return after
          .split(/[,;]/)
          .map((p) => p.replace(/^["']|["']$/g, "").trim())
          .filter((p) => p.length > 0);
      }
    }
  }
  return [];
}

/**
 * Compose the declared-vs-observed permission delta from the AST.
 *
 *   declared  = SecurityAST.declaredCapabilities
 *   observed  = SecurityAST.inferredCapabilities (NanoMind ran) or [] (heuristic)
 *
 * Status mapping:
 *   declared && observed → `used`
 *   declared && !observed → `unused`
 *   !declared && observed → `undeclared`
 */
function buildPermissionDelta(ast: SecurityAST): PermissionStatus[] {
  const declared = new Map<string, Capability>();
  for (const cap of ast.declaredCapabilities) {
    declared.set(normalizeCapName(cap.name), cap);
  }
  const observed = new Map<string, Capability>();
  for (const cap of ast.inferredCapabilities) {
    observed.set(normalizeCapName(cap.name), cap);
  }

  const out: PermissionStatus[] = [];
  const seen = new Set<string>();

  for (const [name, cap] of declared.entries()) {
    seen.add(name);
    const isUsed = observed.has(name);
    out.push({
      name: cap.name,
      declared: true,
      used: isUsed,
      status: isUsed ? "used" : "unused",
    });
  }

  for (const [name, cap] of observed.entries()) {
    if (seen.has(name)) continue;
    out.push({
      name: cap.name,
      declared: false,
      used: true,
      status: "undeclared",
      note: cap.scope || undefined,
    });
  }

  return out;
}

function normalizeCapName(name: string): string {
  return name.trim().toLowerCase();
}

/**
 * Extract external service hostnames the skill talks to. Sources:
 *   - DataAccessPattern.destination on `transmit` rows
 *   - RiskSurface evidence with URL-shaped substrings
 */
function extractExternalServices(ast: SecurityAST): string[] {
  const services = new Set<string>();
  for (const dap of ast.declaredDataAccess) {
    if (dap.accessMode === "transmit" && dap.destination) {
      const host = extractHostname(dap.destination);
      if (host) services.add(host);
    }
  }
  for (const risk of ast.inferredRiskSurface) {
    const urlMatch = risk.evidence?.match(/https?:\/\/([^\s'"\/)]+)/);
    if (urlMatch) {
      services.add(urlMatch[1].toLowerCase());
    }
  }
  return Array.from(services).sort();
}

function extractHostname(destination: string): string | null {
  if (destination.includes("://")) {
    try {
      return new URL(destination).hostname.toLowerCase();
    } catch {
      return destination.toLowerCase();
    }
  }
  return destination.toLowerCase();
}

/**
 * Classify persistence side effects from AST data-access patterns.
 */
function classifyPersistence(ast: SecurityAST): string {
  const writes = ast.declaredDataAccess.filter(
    (d): d is DataAccessPattern => d.accessMode === "write" || d.accessMode === "delete",
  );
  if (writes.length === 0) return "none";
  const types = new Set(writes.map((w) => w.dataType));
  if (types.has("credentials")) return "credentials store";
  if (types.has("financial")) return "financial datastore";
  if (types.size === 1) return Array.from(types)[0];
  return Array.from(types).sort().join(", ");
}

/**
 * Tool-call counts. v1 derives counts from inferred-capability evidence
 * and risk-surface mentions; if NanoMind/scanner did not produce any,
 * returns an empty array (renderer surfaces "no tool calls observed").
 */
function extractToolCallCounts(
  ast: SecurityAST,
  findings?: SecurityFinding[],
): ToolCallCount[] {
  const counts = new Map<string, number>();
  for (const cap of ast.inferredCapabilities) {
    counts.set(cap.name, (counts.get(cap.name) ?? 0) + 1);
  }
  if (findings) {
    for (const f of findings) {
      const tool = (f as { tool?: string }).tool;
      if (typeof tool === "string" && tool.length > 0) {
        counts.set(tool, (counts.get(tool) ?? 0) + 1);
      }
    }
  }
  return Array.from(counts.entries())
    .filter(([tool]) => tool.length > 0)
    .map(([tool, count]) => ({ tool, count }))
    .sort((a, b) => b.count - a.count);
}

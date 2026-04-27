/**
 * MCP narrative builder — turns a SecurityAST + scan findings into the
 * `McpNarrative` wire shape consumed by @opena2a/check-core's
 * `runRuleEngine` and the registry's `package_narratives` row.
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§4)
 *
 * Reuses what the existing scanners already extract from MCP configs
 * and TypeScript/JS source. Where comprehension data isn't available
 * (NanoMind v3 summary), the field is empty and the renderer
 * graceful-degrades.
 */
import type { McpNarrative, McpTool } from "@opena2a/check-core";
import type { SecurityAST } from "../nanomind-core/types.js";
import type { SecurityFinding } from "../hardening";

/**
 * Static threat-model questions for the MCP artifact type per brief §6.2.
 * Stored in the registry alongside the narrative so the renderer is dumb.
 */
export const MCP_THREAT_MODEL_QUESTIONS = [
  "Will the agent that connects to this MCP be capable of writing outside its task scope if it is prompt-injected?",
  "Does your config-level scope restriction (allowedDirectories, allowedHosts, etc.) use realpath or string-prefix matching?",
  "Is there a snapshot or backup before the agent has write access?",
];

/**
 * Tool names that mutate state. `destructive: true` drives the
 * "destructive tools without safety affordances" gap rule in
 * @opena2a/check-core's rule engine.
 */
const DESTRUCTIVE_TOOL_PATTERNS: RegExp[] = [
  /^write[_-]?file/i,
  /^delete[_-]?file/i,
  /^remove[_-]?file/i,
  /^move[_-]?file/i,
  /^rename[_-]?/i,
  /^create[_-]?dir/i,
  /^make[_-]?dir/i,
  /^update[_-]?/i,
  /^drop[_-]?/i,
  /^execute[_-]?/i,
  /^exec[_-]?command/i,
  /^run[_-]?shell/i,
];

export interface BuildMcpNarrativeInput {
  ast: SecurityAST;
  /** Parsed config (mcpServers entry, package.json, etc). Optional. */
  config?: Record<string, unknown>;
  /** Tool registrations parsed from the MCP server's source. */
  toolRegistrations?: McpToolRegistration[];
  /** Findings the scanner produced — used to classify side effects. */
  findings?: SecurityFinding[];
  /** Manual MCP package name when the AST/config doesn't carry it. */
  fallbackName?: string;
}

/**
 * One tool registration parsed from `server.tool(...)` / `tool(...)`
 * calls in the MCP server's TypeScript / JavaScript source. The MCP
 * scanner produces these today; this is a structured shape for them.
 */
export interface McpToolRegistration {
  name: string;
  signature?: string;
  description?: string;
}

/**
 * Build an `McpNarrative` from a compiled MCP-config AST + tool list.
 */
export function buildMcpNarrative(input: BuildMcpNarrativeInput): McpNarrative {
  const { ast, config, toolRegistrations, findings, fallbackName } = input;
  return {
    mcpName: resolveMcpName(ast, config, fallbackName),
    tools: composeToolList(toolRegistrations),
    pathScope: classifyPathScope(ast, config),
    network: classifyNetwork(ast),
    persistence: classifyPersistence(ast),
    auth: classifyAuth(ast, config),
    sideEffects: extractSideEffects(ast, findings),
    threatModelQuestions: MCP_THREAT_MODEL_QUESTIONS,
  };
}

// ---- helpers --------------------------------------------------------

function resolveMcpName(
  ast: SecurityAST,
  config?: Record<string, unknown>,
  fallbackName?: string,
): string {
  const fmName = config?.name;
  if (typeof fmName === "string" && fmName.length > 0) return fmName;
  if (fallbackName && fallbackName.length > 0) return fallbackName;
  if (ast.artifactPath) {
    return ast.artifactPath.split("/").pop()?.replace(/\.json$|\.config$/, "") ?? "unnamed-mcp";
  }
  return "unnamed-mcp";
}

function composeToolList(
  registrations: McpToolRegistration[] | undefined,
): McpTool[] {
  if (!registrations || registrations.length === 0) return [];
  return registrations.map((reg) => ({
    name: reg.name,
    signature: reg.signature ?? `${reg.name}()`,
    description: reg.description ?? "",
    destructive: isDestructive(reg.name),
  }));
}

function isDestructive(name: string): boolean {
  return DESTRUCTIVE_TOOL_PATTERNS.some((p) => p.test(name));
}

function classifyPathScope(
  ast: SecurityAST,
  config?: Record<string, unknown>,
): string {
  if (config && typeof config === "object") {
    if (Array.isArray(config.allowedDirectories) && config.allowedDirectories.length > 0) {
      return `config-allowlisted (${(config.allowedDirectories as unknown[]).length} entries)`;
    }
    if (Array.isArray(config.allowedPaths) && config.allowedPaths.length > 0) {
      return `config-allowlisted (${(config.allowedPaths as unknown[]).length} entries)`;
    }
  }
  const writesAnywhere = ast.declaredDataAccess.some((d) => d.accessMode === "write");
  if (writesAnywhere) return "any path agent passes";
  return "read-only";
}

function classifyNetwork(ast: SecurityAST): string {
  const externalRefs = ast.declaredDataAccess
    .filter((d) => d.accessMode === "transmit" && d.destination)
    .map((d) => d.destination!);
  if (externalRefs.length === 0) return "none";
  return externalRefs.slice(0, 5).join(", ");
}

function classifyPersistence(ast: SecurityAST): string {
  const writes = ast.declaredDataAccess.filter(
    (d) => d.accessMode === "write" || d.accessMode === "delete",
  );
  if (writes.length === 0) return "none";
  if (writes.some((w) => w.dataType === "credentials")) return "credentials store";
  if (writes.some((w) => w.dataType.includes("file") || w.dataType === "general")) {
    return "filesystem";
  }
  return Array.from(new Set(writes.map((w) => w.dataType)))
    .sort()
    .join(", ");
}

function classifyAuth(
  ast: SecurityAST,
  config?: Record<string, unknown>,
): string {
  if (config && typeof config === "object") {
    if (config.bearerToken || config.token) return "bearer token";
    if (config.apiKey) return "api key";
    if (config.basicAuth) return "basic auth";
    if (config.oauth || config.oauth2) return "OAuth";
  }
  const hasBearerHints = ast.inferredRiskSurface.some(
    (r) => /bearer\s+token|authorization\s*header/i.test(r.evidence ?? ""),
  );
  if (hasBearerHints) return "bearer token";
  return "none";
}

/**
 * Process-level side effects observed by the scanner. Classifies the
 * top-level RiskSurface entries into short labels the renderer can
 * print as a list.
 */
function extractSideEffects(
  ast: SecurityAST,
  findings: SecurityFinding[] | undefined,
): string[] {
  const effects = new Set<string>();
  for (const risk of ast.inferredRiskSurface) {
    if (/spawn|child_process|exec\(/i.test(risk.evidence ?? "")) {
      effects.add("spawns child processes");
    }
    if (/postinstall|preinstall/i.test(risk.evidence ?? "")) {
      effects.add("install-time scripts");
    }
    if (/eval\(|Function\(/i.test(risk.evidence ?? "")) {
      effects.add("dynamic code execution");
    }
  }
  if (findings) {
    for (const f of findings) {
      if (/postinstall/i.test(f.checkId ?? "") || /postinstall/i.test(f.message ?? "")) {
        effects.add("install-time scripts");
      }
      if (/process.spawn|child_process/i.test(f.message ?? "")) {
        effects.add("spawns child processes");
      }
    }
  }
  return Array.from(effects).sort();
}

/**
 * Single-call helper that detects whether a `secure --publish` target
 * is a skill or an MCP, builds the narrative, and POSTs it to the
 * registry. Always best-effort; never throws.
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§8 task 2e)
 *
 * [CHIEF-CA] DECISION 2026-04-27:
 *   v1 detection rules:
 *     1. `SKILL.md` exists at the scan root → skill artifact.
 *     2. `result.projectType === "mcp"` → mcp artifact (MCP config or
 *        MCP server source detected by HMA's existing project-type
 *        classifier).
 *     3. Otherwise → skip narrative emission.
 *   Failures are non-fatal and reported in the publish JSON output;
 *   they do NOT alter the parent publish's success state.
 */
import { existsSync, readFileSync } from "node:fs";
import { readStaysInsideTree } from "../hardening/contain";
import { join } from "node:path";
import type { SecurityFinding } from "../hardening";
import type { ProjectType } from "../hardening/security-check";
import { buildPackageNarrative, type BuildPackageNarrativeInput } from "./build-narrative.js";
import {
  narrativeToRequestBody,
  publishNarrative,
  type PublishNarrativeResult,
} from "./publish-narrative.js";

/** Outcome reported back to the caller's publish status JSON. */
export interface NarrativePublishStatus {
  /** True when a narrative was attempted (skill or mcp detected). */
  attempted: boolean;
  /** Detected artifact type, when attempted. */
  artifactType?: "skill" | "mcp";
  /** Result of the registry POST. Absent when `attempted: false`. */
  result?: PublishNarrativeResult;
  /** Reason narrative was skipped, when applicable. */
  skippedReason?: string;
}

export interface WireNarrativePublishOptions {
  /** Directory the scan ran against (`secure <directory>`). */
  targetDir: string;
  packageName: string;
  packageVersion: string;
  /** Hardening findings produced by the scan. */
  findings: SecurityFinding[];
  /** Project type returned by the scanner. */
  projectType: ProjectType;
  /** Registry base URL. */
  registryUrl: string;
  /** Trust signals — best-effort, fall back to safe defaults. */
  publisherVerified?: boolean;
  hasNpmProvenance?: boolean;
  hasMaintainerHistory?: boolean;
  attestationPredicateType?: string;
  communityScans?: number;
  cleanCommunityScans?: number;
  bearerToken?: string;
  /** Optional scan-run UUID — generated when omitted. */
  scanRunId?: string;
}

/**
 * Wire-and-publish helper. Returns a status payload describing the
 * outcome — the caller merges this into the parent publish JSON.
 */
export async function wireNarrativePublish(
  options: WireNarrativePublishOptions,
): Promise<NarrativePublishStatus> {
  const skillPath = join(options.targetDir, "SKILL.md");
  const isSkill = existsSync(skillPath);
  const isMcp = options.projectType === "mcp";

  if (!isSkill && !isMcp) {
    return { attempted: false, skippedReason: "not a skill or mcp artifact" };
  }

  try {
    const { SemanticCompiler } = await import(
      "../nanomind-core/compiler/semantic-compiler.js"
    );
    const compiler = new SemanticCompiler({ useNanoMind: false });
    let compiledContent: string;
    let compiledPath: string;

    // Raw reads of a target-joined name, and this content is POSTED to the
    // registry: confined at the site, as every raw reader on the scan path
    // is, so a `SKILL.md -> ~/...` link is not read and not sent.
    if (isSkill) {
      if (!readStaysInsideTree(skillPath, options.targetDir).ok) {
        return { attempted: false, skippedReason: "SKILL.md is a link that resolves outside the scanned tree" };
      }
      compiledContent = readFileSync(skillPath, "utf-8");
      compiledPath = skillPath;
    } else {
      // MCP detection: prefer package.json, fall back to first
      // mcpServers config we can find in the target directory.
      const pkgPath = join(options.targetDir, "package.json");
      if (existsSync(pkgPath)) {
        if (!readStaysInsideTree(pkgPath, options.targetDir).ok) {
          return { attempted: false, skippedReason: "package.json is a link that resolves outside the scanned tree" };
        }
        compiledContent = readFileSync(pkgPath, "utf-8");
        compiledPath = pkgPath;
      } else {
        return {
          attempted: false,
          skippedReason: "mcp artifact: no package.json at scan root",
        };
      }
    }

    const compilation = await compiler.compile(compiledContent, compiledPath);
    const ast = compilation.ast;

    // Override artifactType when the heuristic compiler classified
    // it as something else; the caller's detection is authoritative.
    if (isSkill) {
      ast.artifactType = "skill";
    } else {
      ast.artifactType = "mcp_config";
    }

    const buildInput: BuildPackageNarrativeInput = {
      ast,
      scanRunId: options.scanRunId,
      packageName: options.packageName,
      packageVersion: options.packageVersion,
      findings: options.findings,
      skillFrontmatter: isSkill
        ? extractFrontmatterFromMarkdown(compiledContent)
        : undefined,
      skillSource: isSkill ? compiledContent : undefined,
      mcpConfig: isMcp ? safeJsonParse(compiledContent) : undefined,
      verdict: "LISTED",
      scanStatus: "completed",
      publisher: {
        verified: options.publisherVerified ?? false,
        hasNpmProvenance: options.hasNpmProvenance ?? false,
        hasMaintainerHistory: options.hasMaintainerHistory ?? false,
      },
      attestations: {
        predicateType: options.attestationPredicateType,
      },
      communityScans: options.communityScans ?? 0,
      cleanCommunityScans: options.cleanCommunityScans ?? 0,
      hasSoulFile: existsSync(join(options.targetDir, "SOUL.md")),
    };

    const narrative = await buildPackageNarrative(buildInput);
    if (!narrative) {
      return {
        attempted: false,
        skippedReason: "buildPackageNarrative returned null",
      };
    }

    const body = narrativeToRequestBody(narrative, options.packageName);
    const result = await publishNarrative(body, {
      registryUrl: options.registryUrl,
      bearerToken: options.bearerToken,
    });

    return {
      attempted: true,
      artifactType: isSkill ? "skill" : "mcp",
      result,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "unknown error";
    return {
      attempted: true,
      artifactType: isSkill ? "skill" : "mcp",
      result: { ok: false, cached: false, error: message },
    };
  }
}

/**
 * Minimal SKILL.md frontmatter parser — pulls keys out of a
 * `---\n...\n---` block at the top of the file. v1 only needs `name`
 * and `description`; structured fields like `capabilities` are parsed
 * by the SemanticCompiler already.
 */
function extractFrontmatterFromMarkdown(
  content: string,
): Record<string, unknown> | undefined {
  if (!content.startsWith("---")) return undefined;
  const closingIdx = content.indexOf("\n---", 3);
  if (closingIdx === -1) return undefined;
  const block = content.slice(3, closingIdx).trim();
  const fm: Record<string, unknown> = {};
  for (const line of block.split("\n")) {
    const m = line.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.*)$/);
    if (m) {
      const [, key, rawValue] = m;
      const value = rawValue.trim().replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1");
      fm[key] = value;
    }
  }
  return fm;
}

function safeJsonParse(content: string): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(content) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

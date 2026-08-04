/**
 * Structural Analyzer (Layer 2 Orchestrator)
 *
 * Runs all Layer 2 analyzers against a target directory.
 * Discovers security-relevant files, classifies them, reads content,
 * and runs each analyzer.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import type { SemanticFinding, AnalysisFile, FileType } from '../types';
import { CredentialContextAnalyzer } from './credential-context';
import { McpConfigAnalyzer } from './mcp-config';
import { InstructionAnalyzer } from './instruction';
import { PermissionModelAnalyzer } from './permission-model';
import { getGitContext } from './git-context';
import { walkForArtifacts, type WalkOptions } from './discovery-walk';

/** Max file size to read (prevents OOM on huge files) */
const MAX_FILE_SIZE = 512 * 1024; // 512KB

/**
 * Ceiling on the content held across ALL discovered files.
 *
 * The per-file cap bounds one read; before #298 the file COUNT was bounded too,
 * at 17 root probes. Discovery below the root removes that second bound, so a
 * tree with hundreds of matching artifacts could hold `count * 512KB` in memory
 * and ship all of it to the Layer-3 LLM analyzer. 32MB is far above any real
 * project's agent-config footprint and well below a scan that falls over.
 */
const MAX_TOTAL_CONTENT = 32 * 1024 * 1024;

/** Options threaded from the scanner into discovery. See `WalkOptions`. */
export type DiscoveryOptions = WalkOptions;

/** Security-relevant files to look for */
const FILE_DISCOVERY: Array<{ glob: string; type: FileType }> = [
  // Agent instruction files
  { glob: 'CLAUDE.md', type: 'agent_instructions' },
  { glob: '.cursorrules', type: 'agent_instructions' },
  { glob: '.windsurfrules', type: 'agent_instructions' },
  { glob: '.clinerules', type: 'agent_instructions' },
  { glob: '.github/copilot-instructions.md', type: 'agent_instructions' },

  // MCP config files
  { glob: 'mcp.json', type: 'mcp_config' },
  // `.mcp.json` is Claude Code's PROJECT-scope MCP file, the one checked into
  // a repo and shared with the team. It was missing, so every MCP analyzer —
  // including the SEM-CRED-004 secret check — silently never ran on it: an
  // identical config with a live token scored 69/100 as `.cursor/mcp.json` and
  // 96/100 as `.mcp.json`.
  { glob: '.mcp.json', type: 'mcp_config' },
  { glob: '.cursor/mcp.json', type: 'mcp_config' },
  { glob: '.vscode/mcp.json', type: 'mcp_config' },

  // Claude settings
  { glob: '.claude/settings.json', type: 'claude_settings' },

  // Env files
  { glob: '.env', type: 'env_file' },
  { glob: '.env.local', type: 'env_file' },
  { glob: '.env.development', type: 'env_file' },
  { glob: '.env.production', type: 'env_file' },

  // Config files
  { glob: 'config.json', type: 'config_file' },
  { glob: 'config.yaml', type: 'config_file' },
  { glob: 'config.yml', type: 'config_file' },
  { glob: 'settings.json', type: 'config_file' },
];

export class StructuralAnalyzer {
  private credentialAnalyzer = new CredentialContextAnalyzer();
  private mcpAnalyzer = new McpConfigAnalyzer();
  private instructionAnalyzer = new InstructionAnalyzer();
  private permissionAnalyzer = new PermissionModelAnalyzer();

  /**
   * Discover and analyze all security-relevant files in the target directory.
   */
  async analyze(targetDir: string, opts: DiscoveryOptions = {}): Promise<SemanticFinding[]> {
    const files = await this.discoverFiles(targetDir, opts);
    if (files.length === 0) return [];

    const gitContext = getGitContext(targetDir);

    const findings: SemanticFinding[] = [];

    findings.push(...this.credentialAnalyzer.analyze(files, gitContext));
    findings.push(...this.mcpAnalyzer.analyze(files));
    findings.push(...this.instructionAnalyzer.analyze(files));
    findings.push(...this.permissionAnalyzer.analyze(files));

    return findings;
  }

  /**
   * Discover and read security-relevant files.
   * Exported for use by the MCP server's deep_scan tool.
   */
  async discoverFiles(targetDir: string, opts: DiscoveryOptions = {}): Promise<AnalysisFile[]> {
    const files: AnalysisFile[] = [];

    // Single-FILE target (e.g. `secure mcp.json`, `secure CLAUDE.md`): every
    // path.join(file, glob) below resolves to a non-existent child path, so the
    // structural analyzers (credential / mcp / instruction / permission) never
    // ran and a lone malicious mcp.json / CLAUDE.md scored a false-clean
    // ~98/100, contradicting the directory scan (audit 2026-06-01). When the
    // caller points us straight at a recognized artifact file, analyze it.
    try {
      const targetStat = await fs.stat(targetDir);
      if (targetStat.isFile()) {
        const base = path.basename(targetDir);
        // Prefer a top-level glob (no separator) over a nested one so a lone
        // `settings.json` types as config_file, not `.claude/settings.json`.
        const match = FILE_DISCOVERY.find(d => d.glob === base)
          ?? FILE_DISCOVERY.find(d => path.basename(d.glob) === base);
        if (match) {
          // Mirror directory-mode reading exactly (below): no upper size reject,
          // truncate the content string at MAX_FILE_SIZE. A tighter cap here
          // would let an attacker evade single-file scanning by padding the
          // artifact past the cap while the directory scan still caught it.
          const truncated = targetStat.size > MAX_FILE_SIZE;
          const content = await fs.readFile(targetDir, 'utf-8');
          files.push({
            path: base,
            type: match.type,
            content: truncated ? content.substring(0, MAX_FILE_SIZE) : content,
            truncated,
          });
        }
        return files;
      }
    } catch {
      return files; // path vanished or unreadable
    }

    let budget = MAX_TOTAL_CONTENT;

    /** Read one artifact into the list, or skip it. Returns false once the content budget is spent. */
    const take = async (rel: string, type: FileType): Promise<boolean> => {
      if (budget <= 0) return false;
      const filePath = path.join(targetDir, rel);
      try {
        const stat = await fs.stat(filePath);
        if (!stat.isFile()) return true;

        const truncated = stat.size > MAX_FILE_SIZE;
        const content = await fs.readFile(filePath, 'utf-8');
        const finalContent = truncated
          ? content.substring(0, MAX_FILE_SIZE)
          : content;

        files.push({ path: rel, type, content: finalContent, truncated });
        budget -= Buffer.byteLength(finalContent, 'utf-8');
      } catch {
        // File doesn't exist, or vanished/became unreadable — skip
      }
      return true;
    };

    // The root probe runs FIRST and UNCONDITIONALLY, in its historical order.
    //
    // #298 mirrors #292's shape here (`scanner.ts:2880`) for the same two
    // reasons. Order: preserving the root sequence keeps finding order — and so
    // the byte-compared corpus goldens — stable for trees that only have
    // root-level config, which is every pre-existing fixture. Unconditionality:
    // the walk below is bounded and can return `complete: false` on a
    // pathological or unreadable tree, and gating the root probe on its results
    // would let a deep or unreadable directory REMOVE detection that exists
    // today. This change may only ever add locations, never subtract them.
    const seen = new Set<string>();
    for (const { glob, type } of FILE_DISCOVERY) {
      const before = files.length;
      await take(glob, type);
      if (files.length > before) seen.add(glob);
    }

    // Then everything deeper, in sorted order. Before #298 all four structural
    // analyzers were blind to their own artifact one directory down: the same
    // bytes scored 35 at the root and 69 under `sub/`, with all five SEM
    // findings gone.
    const { artifacts } = await walkForArtifacts(targetDir, FILE_DISCOVERY, opts);
    for (const { rel, type } of artifacts) {
      // The walk re-finds root-level artifacts the probe already read. Dedup on
      // the exact relative path, which is the same string in both (`config.json`,
      // `.claude/settings.json`) — so a root-only tree yields byte-identical
      // output to before this change.
      if (seen.has(rel)) continue;
      seen.add(rel);
      if (!(await take(rel, type))) break;
    }

    return files;
  }
}

export { CredentialContextAnalyzer } from './credential-context';
export { McpConfigAnalyzer } from './mcp-config';
export { InstructionAnalyzer } from './instruction';
export { PermissionModelAnalyzer } from './permission-model';

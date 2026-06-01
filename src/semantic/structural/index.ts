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

/** Max file size to read (prevents OOM on huge files) */
const MAX_FILE_SIZE = 512 * 1024; // 512KB

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
  async analyze(targetDir: string): Promise<SemanticFinding[]> {
    const files = await this.discoverFiles(targetDir);
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
  async discoverFiles(targetDir: string): Promise<AnalysisFile[]> {
    const files: AnalysisFile[] = [];

    for (const { glob, type } of FILE_DISCOVERY) {
      const filePath = path.join(targetDir, glob);

      try {
        const stat = await fs.stat(filePath);
        if (!stat.isFile()) continue;

        const truncated = stat.size > MAX_FILE_SIZE;
        const content = await fs.readFile(filePath, 'utf-8');
        const finalContent = truncated
          ? content.substring(0, MAX_FILE_SIZE)
          : content;

        files.push({
          path: glob,
          type,
          content: finalContent,
          truncated,
        });
      } catch {
        // File doesn't exist — skip
      }
    }

    return files;
  }
}

export { CredentialContextAnalyzer } from './credential-context';
export { McpConfigAnalyzer } from './mcp-config';
export { InstructionAnalyzer } from './instruction';
export { PermissionModelAnalyzer } from './permission-model';

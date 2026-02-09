/**
 * HackMyAgent MCP Server
 *
 * Runs HackMyAgent as an MCP server using stdio transport.
 * When configured in Claude Code/Cursor/VS Code, the host LLM
 * can invoke security scanning tools directly.
 *
 * The key design: for deep_scan, the tool returns structured context
 * and analysis guidance — the host LLM does the reasoning. Zero API key,
 * zero cost to the user.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import {
  HardeningScanner,
  VERSION,
  OASB_1_VERSION,
  getControlsForLevel,
  getCheckIdsForLevel,
  calculateRating,
  type BenchmarkLevel,
  type SecurityFinding,
} from 'hackmyagent-core';
import {
  StructuralAnalyzer,
  toSecurityFindings,
  buildDeepScanResult,
} from '@opena2a/semantic-engine';

const TOOL_DEFINITIONS = [
  {
    name: 'hackmyagent_scan',
    description:
      'Scan the current project for AI agent security issues. Runs 147+ pattern checks + structural analysis across 30 categories: credentials, MCP configs, permissions, git security, dependencies, and more. Returns actionable findings with severity and fix recommendations.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        directory: {
          type: 'string',
          description: 'Project directory to scan (default: current working directory)',
        },
        fix: {
          type: 'boolean',
          description: 'Auto-fix issues where possible (creates backup first)',
        },
        ignore: {
          type: 'string',
          description: 'Comma-separated check IDs to skip (e.g., "CRED-001,GIT-002")',
        },
      },
    },
  },
  {
    name: 'hackmyagent_deep_scan',
    description:
      'Deep security scan: runs pattern + structural analysis, then returns security-relevant file contents for you (the LLM) to analyze for threats that automated tools miss. YOU should reason about the returned files and identify: credentials in ANY format, dangerous MCP configurations, overprivileged permissions, attack chains, and prompt injection vectors.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        directory: {
          type: 'string',
          description: 'Project directory to scan (default: current working directory)',
        },
      },
    },
  },
  {
    name: 'hackmyagent_analyze_file',
    description:
      'Analyze a single file for security issues. Returns the file content with analysis guidance for you (the LLM) to identify credentials, dangerous configurations, and vulnerabilities.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        file: {
          type: 'string',
          description: 'Path to the file to analyze',
        },
      },
      required: ['file'],
    },
  },
  {
    name: 'hackmyagent_benchmark',
    description:
      'Run OASB-1 (Open Agent Security Benchmark) compliance assessment. Evaluates the project against security controls at L1 (Essential), L2 (Standard), or L3 (Hardened) level.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        directory: {
          type: 'string',
          description: 'Project directory to assess (default: current working directory)',
        },
        level: {
          type: 'string',
          enum: ['L1', 'L2', 'L3'],
          description: 'Benchmark level: L1 (Essential), L2 (Standard), L3 (Hardened). Default: L1',
        },
      },
    },
  },
];

function formatFindingsForLLM(findings: SecurityFinding[]): string {
  if (findings.length === 0) return 'No issues found.';

  const lines: string[] = [];
  for (const f of findings) {
    const location = f.file ? (f.line ? `${f.file}:${f.line}` : f.file) : '';
    lines.push(`[${f.severity.toUpperCase()}] ${f.checkId}: ${f.name}`);
    if (location) lines.push(`  Location: ${location}`);
    lines.push(`  ${f.message}`);
    if (f.fix) lines.push(`  Fix: ${f.fix}`);
    lines.push('');
  }
  return lines.join('\n');
}

export async function startMcpServer(): Promise<void> {
  const server = new Server(
    { name: 'hackmyagent', version: VERSION },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOL_DEFINITIONS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      switch (name) {
        case 'hackmyagent_scan': {
          const dir = (args?.directory as string) || process.cwd();
          const fix = (args?.fix as boolean) || false;
          const ignoreStr = (args?.ignore as string) || '';
          const ignore = ignoreStr ? ignoreStr.split(',').map((s: string) => s.trim()) : [];

          const scanner = new HardeningScanner();
          const result = await scanner.scan({ targetDir: dir, autoFix: fix, ignore });

          const issues = result.findings.filter((f) => !f.passed && !f.fixed);
          const fixed = result.findings.filter((f) => f.fixed);

          let summary = `Score: ${result.score}/${result.maxScore} | ${issues.length} issue${issues.length !== 1 ? 's' : ''} found`;
          if (fixed.length > 0) {
            summary += ` | ${fixed.length} fixed`;
          }
          if (result.semanticAnalysis) {
            summary += ` | Structural: ${result.semanticAnalysis.layer2Findings} findings`;
          }

          return {
            content: [
              {
                type: 'text',
                text: `${summary}\n\n${formatFindingsForLLM(issues)}`,
              },
            ],
          };
        }

        case 'hackmyagent_deep_scan': {
          const dir = (args?.directory as string) || process.cwd();

          // Run Layer 1+2
          const scanner = new HardeningScanner();
          const result = await scanner.scan({ targetDir: dir });

          // Get structural findings and files
          const structural = new StructuralAnalyzer();
          const files = await structural.discoverFiles(dir);
          const structuralFindings = await structural.analyze(dir);

          // Build deep scan result with analysis guidance
          const layer1Findings = result.findings
            .filter((f) => !f.passed)
            .map((f) => ({
              checkId: f.checkId,
              severity: f.severity,
              file: f.file,
              message: f.message,
            }));

          const deepResult = buildDeepScanResult(
            layer1Findings,
            structuralFindings,
            files
          );

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(deepResult, null, 2),
              },
            ],
          };
        }

        case 'hackmyagent_analyze_file': {
          const filePath = args?.file as string;
          if (!filePath) {
            return {
              content: [{ type: 'text', text: 'Error: file path is required' }],
              isError: true,
            };
          }

          const fs = await import('fs/promises');
          const path = await import('path');

          let content: string;
          try {
            content = await fs.readFile(filePath, 'utf-8');
          } catch (err) {
            return {
              content: [{ type: 'text', text: `Error reading file: ${err}` }],
              isError: true,
            };
          }

          const basename = path.basename(filePath).toLowerCase();
          let fileType = 'other';
          let guidance = 'Analyze this file for security issues including credentials, misconfigurations, and vulnerabilities.';

          if (basename === 'claude.md' || basename === '.cursorrules' || basename === '.windsurfrules' || basename === '.clinerules' || basename.includes('copilot-instructions')) {
            fileType = 'agent_instructions';
            guidance = 'This is an AI agent instruction file. Check for: credentials, overly permissive instructions, missing security boundaries, prompt injection vectors, and exfiltration enablement.';
          } else if (basename.includes('mcp.json') || basename === 'mcp.yaml') {
            fileType = 'mcp_config';
            guidance = 'This is an MCP configuration file. Check for: root filesystem access, secrets in args, sandbox bypass flags, wildcard permissions, and attack chain combinations.';
          } else if (basename === '.env' || basename.startsWith('.env.')) {
            fileType = 'env_file';
            guidance = 'This is an environment file. Check for ALL credential types including database URLs with passwords, generic tokens, and secrets.';
          }

          // Truncate for context
          const maxSize = 8192;
          const truncated = content.length > maxSize;
          const displayContent = truncated ? content.substring(0, maxSize) + '\n... (truncated)' : content;

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  file: filePath,
                  type: fileType,
                  content: displayContent,
                  truncated,
                  analysisGuidance: guidance,
                }, null, 2),
              },
            ],
          };
        }

        case 'hackmyagent_benchmark': {
          const dir = (args?.directory as string) || process.cwd();
          const level = ((args?.level as string) || 'L1').toUpperCase() as BenchmarkLevel;

          const scanner = new HardeningScanner();
          const result = await scanner.scan({ targetDir: dir });

          // Generate benchmark assessment
          const allFindings = result.allFindings || result.findings;
          const controls = getControlsForLevel(level);
          const checkIdResults = new Map<string, boolean>();
          for (const f of allFindings) {
            checkIdResults.set(f.checkId, f.passed);
          }

          let passed = 0;
          let failed = 0;
          let unverified = 0;
          const controlResults: string[] = [];

          for (const control of controls) {
            if (control.checkIds.length === 0) {
              if (control.verification === 'forward' || control.verification === 'manual') {
                unverified++;
                controlResults.push(`[UNVERIFIED] ${control.id} ${control.name} (${control.verification})`);
              }
              continue;
            }

            const allPass = control.checkIds.every((id) => checkIdResults.get(id) !== false);
            if (allPass) {
              passed++;
              controlResults.push(`[PASS] ${control.id} ${control.name}`);
            } else {
              failed++;
              const failedChecks = control.checkIds.filter((id) => checkIdResults.get(id) === false);
              controlResults.push(`[FAIL] ${control.id} ${control.name} (${failedChecks.join(', ')})`);
            }
          }

          const total = passed + failed;
          const compliance = total > 0 ? Math.round((passed / total) * 100) : 0;
          const rating = calculateRating(compliance, compliance, compliance, level);

          return {
            content: [
              {
                type: 'text',
                text: `OASB-1 ${level} Assessment: ${compliance}% compliance (${rating})\n` +
                  `Passed: ${passed} | Failed: ${failed} | Unverified: ${unverified}\n\n` +
                  controlResults.join('\n'),
              },
            ],
          };
        }

        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        content: [{ type: 'text', text: `Error: ${message}` }],
        isError: true,
      };
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

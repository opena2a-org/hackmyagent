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
} from './index';
import {
  StructuralAnalyzer,
  toSecurityFindings,
  buildDeepScanResult,
} from './semantic';
import { citationTarget } from './ui/shell-quote';
import { getCheckCounts } from './hardening/taxonomy';
import { countsAgainstScore } from './ui/verdict-band';
import {
  resolveRoots,
  resolveWithinRoots,
  describeRootRefusal,
  type RootRefusal,
} from './mcp/roots';

const MCP_CHECK_COUNTS = getCheckCounts();

/** The one sentence every path argument gets, so the three cannot drift apart. */
const DIRECTORY_ARG_DESCRIPTION =
  'Directory to scan. Must be inside a root this server was started with (`mcp-serve --root <dir>`). Paths outside it are refused, and the refusal names the roots.';

const TOOL_DEFINITIONS = [
  {
    name: 'hackmyagent_scan',
    description:
      `Scan a directory inside this server's allowed roots for AI agent security issues. Runs ${MCP_CHECK_COUNTS.total} security checks across ${MCP_CHECK_COUNTS.totalCategories} categories: credentials, MCP configs, permissions, git security, dependencies, and more. Read-only: this tool never modifies files. Each finding carries its fix command. Fixes are applied from a terminal with \`hackmyagent secure --fix <directory>\`, so the person running it sees the change before it is written.`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        directory: {
          type: 'string',
          description: DIRECTORY_ARG_DESCRIPTION,
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
          description: DIRECTORY_ARG_DESCRIPTION,
        },
      },
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
          description: DIRECTORY_ARG_DESCRIPTION,
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

/**
 * The registry, exported so tests can enumerate it instead of restating it.
 *
 * A table-driven confinement test that hardcodes its own list of tools stops
 * covering the next tool the moment one is added, which is the failure mode CPO
 * named: "any new MCP tool that takes a path and does not call the shared root
 * helper" would pass a test that never looked at it.
 */
export const TOOL_DEFINITIONS_FOR_TEST = TOOL_DEFINITIONS;

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

/**
 * The text the `hackmyagent_scan` MCP tool returns.
 *
 * #285 — extracted so the PREDICATE is reachable from a test. `startMcpServer`
 * builds its handlers inside a closure that needs a transport, so nothing in
 * the suite ever executed them: measured on `9180999`, replacing
 * `countsAgainstScore(f)` here with `!f.passed` and rebuilding left the whole
 * suite green at 219 files / 2876 tests. That is the same "testable as a
 * function" move #350 made for the telemetry success policy, for the same
 * reason.
 *
 * The predicate has to be `countsAgainstScore`, not `!f.passed`. Twelve checks
 * report `passed: <check>Fixed`, so a fix flips `passed` to true the moment it
 * is applied; when the verification pass then DISPROVES it
 * (`fixed: true, fixVerified: false`) the naive test reads it as a pass and
 * the host LLM is told the issue is resolved while it is outstanding.
 */
export function buildScanToolText(result: {
  score: number;
  maxScore: number;
  findings: SecurityFinding[];
  semanticAnalysis?: { layer2Findings: number };
}): string {
  const issues = result.findings.filter((f) => countsAgainstScore(f));
  const fixed = result.findings.filter((f) => f.fixed);

  let summary = `Score: ${result.score}/${result.maxScore} | ${issues.length} issue${issues.length !== 1 ? 's' : ''} found`;
  if (fixed.length > 0) {
    summary += ` | ${fixed.length} fixed`;
  }
  if (result.semanticAnalysis) {
    summary += ` | Structural: ${result.semanticAnalysis.layer2Findings} findings`;
  }

  return `${summary}\n\n${formatFindingsForLLM(issues)}`;
}

/**
 * The Layer-1 findings the `hackmyagent_deep_scan` MCP tool hands to the host
 * LLM.
 *
 * #285 — this filtered on `!f.passed`, so a fix the verification pass had
 * DISPROVED was omitted from the deep-scan payload entirely. The host LLM was
 * told nothing about an outstanding issue because HMA had attempted a fix for
 * it and the attempt failed, which is the M29 defect (`registry/publish.ts`)
 * in a second consumer.
 */
export function buildDeepScanLayer1(findings: SecurityFinding[]): Array<{
  checkId: string;
  severity: string;
  file?: string;
  message: string;
}> {
  return findings
    .filter((f) => countsAgainstScore(f))
    .map((f) => ({
      checkId: f.checkId,
      severity: f.severity,
      file: f.file,
      message: f.message,
    }));
}

export type ToolResult = {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
};

/** The text a refusal returns, in the shape the transport expects. */
function refuse(refusal: RootRefusal): ToolResult {
  return { content: [{ type: 'text', text: describeRootRefusal(refusal) }], isError: true };
}

/**
 * `fix` was removed from the MCP surface, and a request for it is NEVER silently
 * dropped.
 *
 * A model that announced "I'll fix that for you" and got a plain scan back has no
 * way to correct itself, and the user is told nothing. So the scan runs
 * read-only, the result is complete, and this leads it.
 */
export function fixRequestedNote(directory: string, cliName = 'hackmyagent'): string {
  // #273 — the directory is spliced into two commands the reader is invited to
  // paste, so it goes through `citationTarget`: a path with a space retargets
  // the command at something that does not exist, and one with `$(...)` runs.
  const cited = citationTarget(directory);
  return `Note: "fix" was requested and was not applied. This tool is read-only, and the
scan below is complete. To apply fixes, run from a terminal:

  ${cliName} secure --fix ${cited}

\`${cliName} rollback ${cited}\` reverts the most recent --fix.`;
}

/**
 * `hackmyagent_analyze_file` was removed in 0.29.0 (#463).
 *
 * The stub is one minor cycle of discoverability, not a deprecation window: it
 * does not preserve the behaviour, it only stops `Unknown tool:` being a dead end
 * inside the tool that exists to unblock people. The artifact list is GENERATED,
 * because an enumerated literal in a string rots exactly the way a frozen literal
 * in a charter does.
 */
export function analyzeFileRemovalText(discoverableArtifacts: string[]): string {
  return `hackmyagent_analyze_file was removed in hackmyagent 0.29.0.

Use hackmyagent_deep_scan instead. Point it at the directory containing the file,
or at the file itself when it is one of: ${discoverableArtifacts.join(', ')}. It
returns the same file contents with per-type analysis guidance, plus the Layer 1
and Layer 2 findings for the surrounding project.

For a file outside that set, read it with your own file-reading tool.
hackmyagent_analyze_file returned such files unchanged with generic guidance and
added no analysis of its own.`;
}

/** `Unknown tool: X` was a dead end for any typo. This names what is available. */
export function unknownToolText(name: string): string {
  return `Unknown tool: ${name}

This server provides: ${TOOL_DEFINITIONS.map((t) => t.name).join(', ')}.
Call tools/list for the current set and their input schemas.`;
}

/**
 * Every tool call, with the roots already resolved.
 *
 * Extracted from the `startMcpServer` closure for the reason the `#285` comment
 * above records: handlers built inside a closure that needs a transport are
 * unreachable from the suite, which is why an unconfined file reader shipped for
 * twenty-one minor versions with a green test run. The confinement below is
 * therefore exercised by tests against the real filesystem, not asserted about.
 */
export async function handleToolCall(
  name: string,
  args: Record<string, unknown> | undefined,
  roots: string[],
): Promise<ToolResult> {
  try {
    switch (name) {
      case 'hackmyagent_scan': {
        const requested = (args?.directory as string) || '.';
        const resolved = await resolveWithinRoots(roots, requested);
        if (!resolved.ok) return refuse(resolved.refusal);
        const dir = resolved.path;

        const ignoreStr = (args?.ignore as string) || '';
        const ignore = ignoreStr ? ignoreStr.split(',').map((s: string) => s.trim()) : [];

        const scanner = new HardeningScanner();
        const result = await scanner.scan({ targetDir: dir, ignore });

        const parts: string[] = [];
        // The WRITE PATH is gone, not just the schema property: models pass
        // properties outside a schema routinely, so deleting the property alone
        // would have left the write capability live and undocumented (CPO).
        // `scan` above is called with no `autoFix`, so there is nothing here for
        // a `fix` argument to reach. The flag is still READ, and only read, so
        // that a caller who sends it is told it was declined — dropping it
        // silently is the dead end the same ruling refused.
        if (args?.fix !== undefined) parts.push(fixRequestedNote(dir));
        // A model-supplied suppression list that does not appear in the output is
        // the score-laundering defect of #450 with a different caller (CISO).
        if (ignore.length > 0) {
          parts.push(
            `Scope: ${ignore.length} check ID${ignore.length === 1 ? '' : 's'} suppressed at this tool's request (${ignore.join(', ')}). The score below is computed over the checks that ran.`,
          );
        }
        parts.push(buildScanToolText(result));

        return { content: [{ type: 'text', text: parts.join('\n\n') }] };
      }

      case 'hackmyagent_deep_scan': {
        const requested = (args?.directory as string) || '.';
        const resolvedDir = await resolveWithinRoots(roots, requested);
        if (!resolvedDir.ok) return refuse(resolvedDir.refusal);
        const dir = resolvedDir.path;

        // Run Layer 1+2
        const scanner = new HardeningScanner();
        const result = await scanner.scan({ targetDir: dir });

          // Get structural findings and files.
          //
          // #463 — BOTH calls are confined, not just the first. `discoverFiles`
          // feeds the file bodies into `buildDeepScanResult`, and `analyze`
          // produces findings whose evidence quotes the same bytes; confining
          // one and not the other closes half a class and lets us claim the
          // whole one. Confining the ENTRY path alone was the original defect:
          // `.env`, `CLAUDE.md` and `.mcp.json` symlinked out of a legitimately
          // granted root all came back in this tool's result.
          const withheld = new Map<string, string>();
          const confine = {
            confineTo: {
              roots,
              onWithheld: (rel: string, resolved: string) => withheld.set(rel, resolved),
            },
          };
          const structural = new StructuralAnalyzer();
          const files = await structural.discoverFiles(dir, confine);
          const structuralFindings = await structural.analyze(dir, confine);

          // Build deep scan result with analysis guidance
          const layer1Findings = buildDeepScanLayer1(result.findings);

          const deepResult = buildDeepScanResult(
            layer1Findings,
            structuralFindings,
            files
          );

          // Say what was not read, INSIDE the JSON. Appending prose after
          // `JSON.stringify` made the result unparseable for any client the
          // moment something was withheld — i.e. precisely in the attack case,
          // and with `isError` still undefined.
          const notRead = [...withheld.keys()].sort().map((rel) => ({
            path: rel,
            reason: 'resolves outside this server\'s allowed roots — it is a link out of the project',
          }));

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  notRead.length > 0
                    ? {
                        ...deepResult,
                        notRead,
                        notReadNotice:
                          `${notRead.length} file(s) were NOT read and nothing in this result `
                          + 'covers their contents. Findings below may still REFERENCE such a '
                          + 'file by name. To include one, grant its real location its own root, '
                          + 'or scan it from a terminal.',
                      }
                    : deepResult,
                  null,
                  2,
                ),
              },
            ],
          };
        }

      case 'hackmyagent_analyze_file': {
        // Removed in 0.29.0 (#463). The stub is deleted in 0.30.0.
        //
        // The earlier rationale here said `deep_scan` returns the same class of
        // content "bounded by what HMA decided is security-relevant, instead of
        // by whatever path the host model asked for". That bounded the NAME. The
        // attacker picks the TARGET: a link at any of those names pointed
        // wherever they liked, and `deep_scan` read it. A removed capability may
        // not be justified on a bound we do not have.
        //
        // What actually bounds it is `confineTo` on the deep_scan path above:
        // every artifact's realpath must be inside a granted root, and anything
        // withheld is named in the result.
        const { discoverableArtifactNames } = await import('./semantic/structural/index');
        return {
          content: [{ type: 'text', text: analyzeFileRemovalText(discoverableArtifactNames()) }],
          isError: true,
        };
      }

        case 'hackmyagent_benchmark': {
        const requested = (args?.directory as string) || '.';
        const resolvedDir = await resolveWithinRoots(roots, requested);
        if (!resolvedDir.ok) return refuse(resolvedDir.refusal);
        const dir = resolvedDir.path;
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
          content: [{ type: 'text', text: unknownToolText(name) }],
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
}

/**
 * `cliRoots` comes from `mcp-serve --root <dir>` and is MANDATORY (#463).
 *
 * The server still starts with no root so the client sees a working connection
 * and `tools/list` answers — a startup exit would surface as an opaque "server
 * failed to start" in a log the user may never open (CPO). Every path-taking
 * tool then returns the refusal, which carries the one command that fixes it.
 */
export async function startMcpServer(cliRoots: string[] = []): Promise<void> {
  const server = new Server(
    { name: 'hackmyagent', version: VERSION },
    { capabilities: { tools: {} } }
  );

  const rootsOutcome = await resolveRoots(cliRoots);
  const roots = rootsOutcome.ok ? rootsOutcome.roots : [];
  const startupRefusal = rootsOutcome.ok ? null : rootsOutcome.refusal;

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOL_DEFINITIONS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    if (startupRefusal) return refuse(startupRefusal);
    return handleToolCall(request.params.name, request.params.arguments, roots);
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}
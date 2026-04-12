#!/usr/bin/env node
/**
 * HackMyAgent CLI
 * Find it. Break it. Fix it.
 */

import { Command } from 'commander';
import {
  VERSION,
  checkSkill,
  HardeningScanner,
  ExternalScanner,
  type RiskLevel,
  type Severity,
  type SecurityFinding,
  type ExternalFinding,
  type FindingSeverity,
  // Benchmark imports
  OASB_1_CATEGORIES,
  OASB_1_VERSION,
  OASB_1_NAME,
  getControlsForLevel,
  getControlsForCategory,
  getCheckIdsForLevel,
  calculateRating,
  AVAILABLE_BENCHMARKS,
  isValidBenchmark,
  type BenchmarkLevel,
  type BenchmarkControl,
  type BenchmarkCategory,
  type BenchmarkResult,
  type BenchmarkCategoryResult,
  type BenchmarkControlResult,
  // Attack imports
  AttackScanner,
  ATTACK_CATEGORIES,
  PAYLOAD_STATS,
  parseCustomPayloads,
  shouldFail,
  type AttackCategory,
  type AttackIntensity,
  type AttackTarget,
  type AttackReport,
  type AttackPayload,
  type FailPolicy,
  // Soul scanner imports
  SoulScanner,
  type SoulScanResult,
  type DomainResult,
  type SoulLevel,
} from './index';
import { resolveAndLogMcpShorthand } from './resolve-mcp';
import { WildScanner, type WildScanReport } from './wild';
const program = new Command();
program.showHelpAfterError('(run with --help for usage)');

// Total security check count across all scanner modules.
// Update when adding new checks (verify with: grep -r "checkId:" src/hardening/ | grep -o "checkId: '[^']*'" | sort -u | wc -l)
const CHECK_COUNT = 209;

// How long registry-cached scan data is considered fresh before `check` re-scans.
const STALE_SCAN_DAYS = 3;

// Write a string to stdout synchronously with retry for pipe backpressure.
// process.stdout.write() is async and gets truncated when process.exit()
// runs before the stream flushes. fs.writeFileSync(1, ...) can fail with
// EAGAIN on non-blocking pipes when the buffer (64KB on macOS) fills up.
// This function writes in chunks with retry to handle both cases.
function writeLargeStdout(text: string): void {
  const fs = require('fs');
  const buf = Buffer.from(text);
  let offset = 0;
  while (offset < buf.length) {
    try {
      const written = fs.writeSync(1, buf, offset, buf.length - offset);
      offset += written;
    } catch (e: unknown) {
      if (e && typeof e === 'object' && 'code' in e && (e as {code: string}).code === 'EAGAIN') {
        // Pipe buffer full -- spin-wait briefly then retry
        continue;
      }
      throw e;
    }
  }
}

function writeJsonStdout(data: unknown): void {
  writeLargeStdout(JSON.stringify(data, null, 2) + '\n');
}

// Resolve the CLI command name based on how we were invoked.
// When run via `opena2a scan secure`, use `opena2a scan` prefix.
// When run directly as `hackmyagent`, use that.
// The HMA_CLI_PREFIX env var lets parent CLIs override explicitly.
function resolveCliPrefix(): string {
  if (process.env.HMA_CLI_PREFIX) return process.env.HMA_CLI_PREFIX;
  const argv1 = process.argv[1] || '';
  const basename = require('path').basename(argv1).replace(/\.[jt]s$/, '');
  if (basename === 'opena2a' || basename.startsWith('opena2a-')) {
    return 'opena2a scan';
  }
  return 'hackmyagent';
}
const CLI_PREFIX = resolveCliPrefix();

/**
 * Validate that a registry URL uses HTTPS.
 * Allows http://localhost for local development.
 * Rejects all other non-HTTPS URLs to prevent credential leakage.
 */
function validateRegistryUrl(url: string): string {
  if (url && !url.startsWith('https://') && !url.startsWith('http://localhost')) {
    console.error('Error: Registry URL must use HTTPS. Got: ' + url);
    console.error('Only https:// URLs and http://localhost are allowed.');
    process.exit(1);
  }
  return url;
}

// Global CI mode flag -- set before parse() by stripping --ci from argv.
// Commands that already define --ci (secure, scan-soul) use their own opts;
// all others can check this module-level flag.
let globalCiMode = false;

// Check for NO_COLOR env or non-TTY to disable colors by default
const noColorEnv = process.env.NO_COLOR !== undefined || !process.stdout.isTTY;

// Color codes - will be cleared if --no-color is passed
let colors = {
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  brightRed: '\x1b[91m',
  cyan: '\x1b[36m',
  dim: '\x1b[2m',
  bold: '\x1b[1m',
  white: '\x1b[97m',
  reset: '\x1b[0m',
};

if (noColorEnv) {
  colors = { green: '', yellow: '', red: '', brightRed: '', cyan: '', dim: '', bold: '', white: '', reset: '' };
}

// Deprecation warning for removed HMAC auth
if (process.env.HMA_COMMUNITY_SECRET) {
  console.error('Note: HMA_COMMUNITY_SECRET is deprecated and no longer used. Scan tokens are now issued automatically.');
}

program
  .name('hackmyagent')
  .description(`Find it. Break it. Fix it.

The hacker's toolkit for AI agents. ${CHECK_COUNT} security checks, ${PAYLOAD_STATS.total} attack
payloads, auto-fix with rollback, and OASB benchmark compliance.

Documentation: https://hackmyagent.com/docs

Updates (v${VERSION}):
  - 10 new static analysis patterns (NEMO series)
  - Community trust contributions
  - ${CHECK_COUNT} checks across 60 categories

Examples:
  $ hackmyagent secure                         Find vulnerabilities (${CHECK_COUNT} checks)
  $ hackmyagent attack --local                 Break it with ${PAYLOAD_STATS.total} attack payloads
  $ hackmyagent secure --fix                   Fix issues automatically
  $ hackmyagent fix-all                        Run all security plugins
  $ hackmyagent scan example.com               Scan external infrastructure`)
  .version('hackmyagent ' + VERSION, '-v, --version', 'Output the version number')
  .option('--no-color', 'Disable colored output (also respects NO_COLOR env)');

program.addHelpText('beforeAll', `
Quick start:
  $ hackmyagent secure              Scan current directory (${CHECK_COUNT} checks)
  $ hackmyagent fix-all --with-aim  Auto-fix + create agent identity
  $ hackmyagent attack              Red-team your agent
`);

program.hook('preAction', (thisCommand) => {
    const opts = thisCommand.opts();
    if (opts.color === false) {
      colors = { green: '', yellow: '', red: '', brightRed: '', cyan: '', dim: '', bold: '', white: '', reset: '' };
    }
  });

// Risk level colors and symbols
const RISK_DISPLAY: Record<RiskLevel, { symbol: string; color: () => string }> = {
  low: { symbol: '[+]', color: () => colors.green },
  medium: { symbol: '[~]', color: () => colors.yellow },
  high: { symbol: '[!]', color: () => colors.red },
  critical: { symbol: '[!!]', color: () => colors.brightRed },
};
const RESET = () => colors.reset;

program
  .command('check')
  .description(`Check if a package, repo, or skill is safe

Downloads + scans (${CHECK_COUNT} checks + NanoMind) by default, with trust context from the OpenA2A registry.

Accepts:
  • npm package: hackmyagent check express
  • PyPI package: hackmyagent check pip:requests
  • GitHub repo:  hackmyagent check getsentry/sentry-mcp
  • Local path:   hackmyagent check ./my-agent/
  • Skill:        hackmyagent check @publisher/skill
  • URL:          hackmyagent check https://example.com/agent-v1.tar.gz

Output includes: verdict, security score, findings with fix commands, registry trust context, and path forward for recovery.

Risk levels: low, medium, high, critical
Exit code 1 if high/critical risk detected.

Examples:
  $ hackmyagent check @sentry/mcp-server
  $ hackmyagent check pip:flask
  $ hackmyagent check getsentry/sentry-mcp --verbose
  $ hackmyagent check ./my-agent/ --json
  $ hackmyagent check express --no-scan    # registry only (fast)
  $ hackmyagent check express --no-registry # offline mode`)
  .argument('<target>', 'npm package, PyPI package (pip: or pypi: prefix), local path, GitHub repo, or skill identifier')
  .option('-v, --verbose', 'Show detailed verification info (check IDs, categories)')
  .option('--json', 'Output as JSON (for scripting/CI)')
  .option('--no-scan', 'Registry only, skip local scan (fast mode for CI)')
  .option('--no-registry', 'Local scan only, skip registry lookup (offline mode)')
  .option('--offline', 'Alias for --no-registry')
  .option('--rescan', 'Deprecated: local scan is now the default')
  .action(async (skill: string, options: { verbose?: boolean; json?: boolean; scan?: boolean; registry?: boolean; offline?: boolean; rescan?: boolean }) => {
    // Commander parses --no-scan as scan:false, --no-registry as registry:false
    // Normalize: --offline is alias for --no-registry
    if (options.offline) options.registry = false;
    // --rescan deprecation
    if (options.rescan && !options.json && !globalCiMode) {
      console.error(`${colors.yellow}Note: --rescan is deprecated. Local scan is now the default.${RESET()}`);
    }
    try {
      // Detect local file/directory paths - run NanoMind scan instead of registry lookup
      const { existsSync, statSync } = await import('node:fs');
      const { resolve, dirname } = await import('node:path');
      const resolved = resolve(skill);
      const isLocalPath = existsSync(resolved) && (statSync(resolved).isFile() || statSync(resolved).isDirectory());

      if (isLocalPath) {
        // Local path: run NanoMind semantic analysis directly
        const targetDir = statSync(resolved).isFile() ? dirname(resolved) : resolved;

        const { orchestrateNanoMind } = await import('./nanomind-core/orchestrate.js');
        const nmResult = await orchestrateNanoMind(targetDir, [], { silent: !!options.json });

        const issues = nmResult.mergedFindings.filter((f: any) => !f.passed);
        const critical = issues.filter((f: any) => f.severity === 'critical');
        const high = issues.filter((f: any) => f.severity === 'high');

        if (options.json) {
          writeJsonStdout({
            path: resolved,
            type: 'local-scan',
            nanomindUsed: nmResult.nanomindUsed,
            compiledArtifacts: nmResult.compiledArtifacts,
            findings: issues.length,
            critical: critical.length,
            high: high.length,
            risk: critical.length > 0 ? 'critical' : high.length > 0 ? 'high' : issues.length > 0 ? 'medium' : 'low',
            details: issues,
          });
          return;
        }

        displayUnifiedCheck({
          name: resolved,
          sourceLabel: 'local',
          nanomindScan: {
            compiledArtifacts: nmResult.compiledArtifacts,
            findings: issues as any[],
          },
          verbose: !!options.verbose,
        });

        const risk = critical.length > 0 ? 'critical' : high.length > 0 ? 'high' : issues.length > 0 ? 'medium' : 'low';
        if (risk === 'critical' || risk === 'high') process.exit(1);
        return;
      }

      // PyPI package: download, run full HMA scan, clean up
      if (looksLikePyPiPackage(skill)) {
        await checkPyPiPackage(skill, options);
        return;
      }

      // GitHub repo: clone, run full HMA scan, clean up
      if (looksLikeGitHubRepo(skill)) {
        await checkGitHubRepo(skill, options);
        return;
      }

      // Raw URL (non-GitHub): fetch/clone based on content type
      if (looksLikeRawUrl(skill)) {
        await checkRawUrl(skill, options);
        return;
      }

      // npm package name: download, run full HMA scan, clean up
      if (looksLikeNpmPackage(skill)) {
        await checkNpmPackage(skill, options);
        return;
      }

      // --rescan only applies to targets that otherwise hit the registry cache.
      // For skill identifiers we fall through to the registry lookup below.
      if (options.rescan && !options.json) {
        console.error(`Note: --rescan has no effect on skill identifiers; it applies to npm/PyPI/GitHub targets.`);
      }

      // Registry lookup path (non-local identifier) with 10s timeout
      const checkPromise = checkSkill(skill, {
        skipDnsVerification: options.offline,
      });
      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(
          `Timed out verifying "${skill}" (10s). The publisher may not exist or DNS is unreachable.\n` +
          `Try: ${getCheckCommand()} ${skill} --offline`
        )), 10000)
      );
      const result = await Promise.race([checkPromise, timeoutPromise]);

      if (options.json) {
        writeJsonStdout(result);
        return;
      }

      const risk = RISK_DISPLAY[result.risk];
      console.log(`\n${risk.color()}${risk.symbol} ${result.risk.toUpperCase()} RISK${RESET()}\n`);

      // Publisher info
      console.log(`Publisher: @${result.publisher.name}`);
      if (result.publisher.verified) {
        console.log(`├─ [+] Verified via DNS`);
        if (result.publisher.domain) {
          console.log(`├─ Domain: ${result.publisher.domain}`);
        }
        if (result.publisher.verifiedAt && options.verbose) {
          console.log(`└─ Verified at: ${result.publisher.verifiedAt.toISOString()}`);
        } else {
          console.log(`└─ Method: DNS TXT record`);
        }
      } else {
        console.log(`├─ [-] Not verified`);
        if (result.publisher.failureReason && options.verbose) {
          console.log(`└─ Reason: ${result.publisher.failureReason}`);
        } else if (options.offline) {
          console.log(`└─ (DNS verification skipped - offline mode)`);
        } else {
          console.log(`└─ No valid DNS TXT record found`);
        }
      }
      console.log();

      // Permissions
      console.log('Permissions:');
      if (result.permissions.requested.length === 0) {
        console.log('└─ None declared');
      } else {
        for (const perm of result.permissions.safe) {
          console.log(`├─ [+] ${perm}`);
        }
        for (const perm of result.permissions.reviewNeeded) {
          console.log(`├─ [~] ${perm} (review needed)`);
        }
        for (const perm of result.permissions.dangerous) {
          console.log(`├─ [!] ${perm} (elevated risk)`);
        }
        console.log(`└─ Risk score: ${result.permissions.riskScore}/100`);
      }
      console.log();

      // Revocation
      console.log('Revocation:');
      if (result.revocation.revoked) {
        console.log(`└─ [!!] Revoked: ${result.revocation.reason}`);
      } else {
        console.log(`└─ [+] Not on blocklist`);
      }
      console.log();

      // Verbose details
      if (options.verbose) {
        console.log('Details:');
        console.log(`└─ Checked at: ${result.revocation.checkedAt.toISOString()}`);
      }

      // Exit with non-zero for high/critical risk
      if (result.risk === 'critical' || result.risk === 'high') {
        process.exit(1);
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  });

// Severity colors and symbols for secure command
const SEVERITY_DISPLAY: Record<Severity, { symbol: string; color: () => string }> = {
  critical: { symbol: '[!!]', color: () => colors.brightRed },
  high: { symbol: '[!]', color: () => colors.red },
  medium: { symbol: '[~]', color: () => colors.yellow },
  low: { symbol: '[.]', color: () => colors.green },
};

/**
 * Display check command findings with optional verbose details.
 * When verbose is true, shows checkId, category, file location, and fix/guidance for each finding.
 */
function displayCheckFindings(
  failed: SecurityFinding[],
  verbose: boolean,
): void {
  if (failed.length > 0) {
    console.log();
    const limit = verbose ? failed.length : 15;
    for (const f of failed.slice(0, limit)) {
      const sev = SEVERITY_DISPLAY[f.severity];
      const attackClass = (f as any).attackClass ? ` (${(f as any).attackClass})` : '';
      console.log(`  ${sev.color()}${sev.symbol}${RESET()} ${f.name}: ${f.message}${colors.dim}${attackClass}${RESET()}`);
      if (verbose) {
        console.log(`    ${colors.dim}Check:    ${f.checkId}${RESET()}`);
        if (f.category) {
          console.log(`    ${colors.dim}Category: ${f.category}${RESET()}`);
        }
        if (f.file) {
          const location = f.line ? `${f.file}:${f.line}` : f.file;
          console.log(`    ${colors.dim}File:     ${location}${RESET()}`);
        }
        if (f.fix) {
          console.log(`    ${colors.cyan}Fix:      ${f.fix}${RESET()}`);
        }
        if ((f as any).guidance) {
          console.log(`    ${colors.dim}Guidance: ${(f as any).guidance}${RESET()}`);
        }
      }
    }
    if (failed.length > limit) {
      console.log(`\n  ... and ${failed.length - limit} more (use --verbose to see all)`);
    }
  } else {
    console.log(`\n  ${colors.green}No security issues found.${RESET()}`);
  }
}

// ---------------------------------------------------------------------------
// Unified check display — one function for all target types (0.17.0)
// ---------------------------------------------------------------------------

interface UnifiedCheckDisplayOptions {
  name: string;
  sourceLabel?: string;
  projectType?: string;
  localScan?: {
    score: number;
    maxScore: number;
    findings: SecurityFinding[];
    filesScanned?: number;
  };
  registry?: RegistryTrustData | null;
  verbose?: boolean;
  version?: string;
  nanomindScan?: {
    compiledArtifacts: number;
    findings: Array<{ severity: string; checkId?: string; description?: string; name?: string; message?: string; fix?: string; guidance?: string; file?: string; line?: number; passed?: boolean; attackClass?: string; category?: string }>;
  };
}

function stripAnsi(s: string): string {
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

/** Right-align a value at a fixed column width */
function rightAlign(left: string, right: string, width: number = 68): string {
  const leftLen = stripAnsi(left).length;
  const rightLen = stripAnsi(right).length;
  const pad = Math.max(1, width - leftLen - rightLen);
  return `${left}${' '.repeat(pad)}${right}`;
}

/** Truncate a fix string to one concise line */
function truncateFix(fix: string): string {
  // Take first sentence or first line, whichever is shorter
  const firstLine = fix.split('\n')[0].trim();
  const firstSentence = firstLine.split(/\.\s/)[0];
  const result = firstSentence.endsWith('.') ? firstSentence : firstSentence + '.';
  return result.length > 80 ? result.slice(0, 77) + '...' : result;
}

function displayUnifiedCheck(opts: UnifiedCheckDisplayOptions): void {
  const { name, sourceLabel, projectType, localScan, registry, verbose, version, nanomindScan } = opts;

  // ── Header ──────────────────────────────────────────────────────────
  const typeLabel = (registry?.packageType || projectType || 'unknown').replace(/_/g, ' ');
  console.log(`\n  ${colors.bold}${colors.white}${name}${RESET()}`);
  if (version) {
    console.log(`  Version:        ${version}${sourceLabel ? ` (${sourceLabel})` : ''}`);
  } else if (sourceLabel) {
    console.log(`  Source:         ${sourceLabel}`);
  }
  console.log(`  Type:           ${typeLabel}`);

  // ── Compute findings ────────────────────────────────────────────────
  let failed: SecurityFinding[] = [];
  let score = 0;
  let maxScore = 100;
  let critical = 0, high = 0, medium = 0, low = 0;

  if (localScan) {
    failed = localScan.findings.filter(f => !f.passed);
    score = localScan.score;
    maxScore = localScan.maxScore;
    critical = failed.filter(f => f.severity === 'critical').length;
    high = failed.filter(f => f.severity === 'high').length;
    medium = failed.filter(f => f.severity === 'medium').length;
    low = failed.filter(f => f.severity === 'low').length;
  } else if (nanomindScan) {
    const issues = nanomindScan.findings.filter(f => !f.passed);
    critical = issues.filter(f => f.severity === 'critical').length;
    high = issues.filter(f => f.severity === 'high').length;
    medium = issues.filter(f => f.severity === 'medium').length;
    low = issues.filter(f => f.severity === 'low').length;
    failed = issues.map(f => ({
      checkId: f.checkId || '',
      name: f.name || f.description || '',
      description: f.description || '',
      category: f.category || '',
      severity: f.severity as Severity,
      passed: false,
      message: f.message || f.description || '',
      fixable: false,
      file: f.file,
      line: f.line,
      fix: f.fix,
      guidance: f.guidance,
      attackClass: f.attackClass,
    }));
    score = critical > 0 ? 0 : high > 0 ? 30 : issues.length > 0 ? 60 : 100;
    maxScore = 100;
  } else if (registry?.found) {
    score = Math.round(registry.trustScore * 100);
    maxScore = 100;
  }

  const totalFindings = critical + high + medium + low;
  const scoreColor = score >= 70 ? colors.green : score >= 40 ? colors.yellow : colors.red;

  // ── Verdict ─────────────────────────────────────────────────────────
  if (localScan || nanomindScan) {
    let verdictLabel: string;
    if (critical > 0) {
      verdictLabel = `${colors.brightRed}CRITICAL${RESET()}`;
    } else if (high > 0) {
      verdictLabel = `${colors.red}WARNING${RESET()}`;
    } else if (totalFindings > 0) {
      verdictLabel = `${colors.yellow}NOTICE${RESET()}`;
    } else {
      verdictLabel = `${colors.green}SAFE${RESET()}`;
    }
    console.log(`  Verdict:        ${verdictLabel}`);
    console.log(`  Security Score: ${scoreColor}${score}/${maxScore}${RESET()}`);
    if (nanomindScan) {
      console.log(`  Files Analyzed: ${nanomindScan.compiledArtifacts}`);
    }
  } else if (registry?.found) {
    const normalized = normalizeTrustVerdict(registry.verdict);
    let verdictLabel: string;
    if (normalized === 'blocked') {
      verdictLabel = `${colors.red}BLOCKED${RESET()}`;
    } else if (normalized === 'warning') {
      verdictLabel = `${colors.yellow}WARNING${RESET()}`;
    } else {
      verdictLabel = `${colors.green}SAFE${RESET()}`;
    }
    console.log(`  Verdict:        ${verdictLabel}`);
    console.log(`  Trust Score:    ${scoreColor}${score}/100${RESET()}`);
  }

  // ── Findings ────────────────────────────────────────────────────────
  if (failed.length > 0) {
    console.log();
    console.log(`  ${colors.bold}Findings${RESET()}  ${critical} critical, ${high} high, ${medium} medium, ${low} low`);

    // High-count mode: group by category when > 20 findings
    if (totalFindings > 20 && !verbose) {
      console.log();
      const groups = new Map<string, { critical: number; high: number; medium: number; low: number; files: Set<string> }>();
      for (const f of failed) {
        const key = f.category || f.name || 'Other';
        if (!groups.has(key)) groups.set(key, { critical: 0, high: 0, medium: 0, low: 0, files: new Set() });
        const g = groups.get(key)!;
        g[f.severity]++;
        if (f.file) g.files.add(f.file.split('/')[0] || f.file);
      }
      const sorted = [...groups.entries()].sort((a, b) => {
        const wa = a[1].critical * 4 + a[1].high * 3 + a[1].medium * 2 + a[1].low;
        const wb = b[1].critical * 4 + b[1].high * 3 + b[1].medium * 2 + b[1].low;
        return wb - wa;
      });
      for (const [cat, g] of sorted.slice(0, 8)) {
        const counts: string[] = [];
        if (g.critical > 0) counts.push(`${colors.brightRed}${g.critical} critical${RESET()}`);
        if (g.high > 0) counts.push(`${colors.red}${g.high} high${RESET()}`);
        if (g.medium > 0) counts.push(`${colors.dim}${g.medium} medium${RESET()}`);
        if (g.low > 0) counts.push(`${colors.dim}${g.low} low${RESET()}`);
        const fileHint = g.files.size <= 3 ? `  ${colors.dim}${[...g.files].join(', ')}${RESET()}` : '';
        console.log(`    ${cat.padEnd(28)} ${counts.join(', ')}${fileHint}`);
      }
      if (sorted.length > 8) {
        console.log(`    ${colors.dim}... ${sorted.length - 8} more categories${RESET()}`);
      }

      // Top 3 issues with full detail
      console.log();
      console.log(`  ${colors.bold}Top Issues${RESET()}`);
      const topFindings = [...failed]
        .sort((a, b) => {
          const sw: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
          return (sw[b.severity] || 0) - (sw[a.severity] || 0);
        })
        .slice(0, 3);
      for (const f of topFindings) {
        const sev = SEVERITY_DISPLAY[f.severity];
        const fileLoc = f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : '';
        console.log(`\n  ${sev.color()}${sev.symbol}${RESET()} ${colors.bold}${f.name || f.message}${RESET()}  ${colors.dim}${fileLoc}${RESET()}`);
        if (f.guidance) {
          console.log(`     ${colors.dim}${truncateFix(f.guidance)}${RESET()}`);
        }
        if (f.fix) {
          console.log(`     ${colors.cyan}Fix: ${truncateFix(f.fix)}${RESET()}`);
        }
      }
    } else {
      // Normal mode: individual findings with collapse
      console.log();
      const skipped = new Set<number>();
      let shown = 0;
      const limit = verbose ? failed.length : 10;

      for (let i = 0; i < failed.length; i++) {
        if (shown >= limit) break;
        if (skipped.has(i)) continue;
        const f = failed[i];
        const sev = SEVERITY_DISPLAY[f.severity];
        const fileLoc = f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : '';
        console.log(`  ${sev.color()}${sev.symbol}${RESET()} ${colors.bold}${f.name || f.message}${RESET()}  ${colors.dim}${fileLoc}${RESET()}`);
        if (f.guidance) {
          console.log(`     ${colors.dim}${truncateFix(f.guidance)}${RESET()}`);
        }
        if (f.fix) {
          console.log(`     ${colors.cyan}Fix: ${truncateFix(f.fix)}${RESET()}`);
        }
        if (verbose) {
          if (f.checkId) console.log(`     ${colors.dim}Check: ${f.checkId}${RESET()}`);
          if (f.category) console.log(`     ${colors.dim}Category: ${f.category}${RESET()}`);
        }
        shown++;

        // Collapse similar
        if (!verbose) {
          const dir = f.file?.split('/').slice(0, -1).join('/') || '';
          let similarCount = 0;
          for (let j = i + 1; j < failed.length; j++) {
            if (skipped.has(j)) continue;
            const other = failed[j];
            if (other.name === f.name) {
              const otherDir = other.file?.split('/').slice(0, -1).join('/') || '';
              if (otherDir === dir) { skipped.add(j); similarCount++; }
            }
          }
          if (similarCount > 0) {
            console.log(`     ${colors.dim}${similarCount} similar in ${dir || '.'}${RESET()}`);
          }
        }
      }
      const remaining = failed.length - shown - skipped.size;
      if (remaining > 0) {
        console.log(`\n  ${colors.dim}${remaining} more (--verbose)${RESET()}`);
      }
    }

    // Path forward
    if (critical > 0 || high > 0) {
      console.log(`\n  ${colors.cyan}Path forward: fix ${critical + high} critical/high issue${(critical + high) > 1 ? 's' : ''}${RESET()}`);
    }
  }

  // ── Registry ────────────────────────────────────────────────────────
  if (registry?.found) {
    const trustScore = Math.round(registry.trustScore * 100);
    const trustColor = trustScore >= 70 ? colors.green : trustScore >= 40 ? colors.yellow : colors.red;

    console.log();
    if (localScan || nanomindScan) {
      // Show as separate section when local scan was also performed
      console.log(`  ${colors.bold}Registry${RESET()}`);
      console.log(`  Trust Score:    ${trustColor}${trustScore}/100${RESET()}`);
    }
    console.log(`  Trust Level:    ${trustLevelColor(registry.trustLevel)}${trustLevelLabel(registry.trustLevel)}${RESET()} (${registry.trustLevel}/4)`);
    if (registry.communityScans !== undefined) {
      console.log(`  Community:      ${registry.communityScans} scan${registry.communityScans !== 1 ? 's' : ''} shared`);
    }
    if (registry.cveCount !== undefined && registry.cveCount > 0) {
      console.log(`  Known CVEs:     ${colors.red}${registry.cveCount}${RESET()}`);
    }
    if (registry.dependencies) {
      const d = registry.dependencies;
      console.log();
      console.log(`  ${colors.bold}Dependencies${RESET()}`);
      if (d.totalDeps !== undefined) console.log(`  Total:          ${d.totalDeps}`);
      if (d.vulnerableDeps !== undefined) {
        console.log(`  Vulnerable:     ${d.vulnerableDeps > 0 ? colors.red + d.vulnerableDeps + RESET() : colors.green + '0' + RESET()}`);
      }
      if (d.minTrustLevel !== undefined) console.log(`  Min Trust:      ${d.minTrustLevel}/4`);
    }

    // Trust level legend (when not fully verified)
    if (registry.trustLevel < 4) {
      console.log();
      console.log(`  ${colors.dim}Trust levels: Blocked (0) < Warning (1) < Listed (2) < Scanned (3) < Verified (4)${RESET()}`);
    }
  }

  // ── Next steps ──────────────────────────────────────────────────────
  const hasGovIssues = failed.some(f => f.category === 'governance' || f.category === 'Governance' || f.checkId?.startsWith('AST-GOV') || f.checkId?.startsWith('AST-PROMPT'));
  printCheckNextSteps(name, { hasGovernanceIssues: hasGovIssues, hasFindings: totalFindings > 0 });
}

function groupFindingsBySeverity(findings: SecurityFinding[]): Record<Severity, SecurityFinding[]> {
  const grouped: Record<Severity, SecurityFinding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };

  for (const finding of findings) {
    grouped[finding.severity].push(finding);
  }

  return grouped;
}

// Benchmark compliance helpers
interface LocalControlResult {
  control: BenchmarkControl;
  status: 'passed' | 'failed' | 'unverified';
  findings: string[];
  remediation?: string;
}

function generateBenchmarkReport(
  findings: SecurityFinding[],
  level: BenchmarkLevel,
  categoryFilter?: string
): BenchmarkResult {
  // Get controls for the specified level
  let controls = getControlsForLevel(level);

  // Filter by category if specified
  if (categoryFilter) {
    const categoryControls = getControlsForCategory(categoryFilter);
    if (categoryControls.length === 0) {
      console.error(`Error: Unknown category '${categoryFilter}'.`);
      console.error(`Available categories: ${OASB_1_CATEGORIES.map((c: BenchmarkCategory) => c.name).join(', ')}`);
      process.exit(1);
    }
    controls = controls.filter((c: BenchmarkControl) => c.category.toLowerCase() === categoryFilter.toLowerCase());
  }

  // Build a map of checkId -> finding for quick lookup
  const findingsByCheckId = new Map<string, SecurityFinding>();
  for (const finding of findings) {
    findingsByCheckId.set(finding.checkId, finding);
  }

  // Evaluate each control
  const controlResults: LocalControlResult[] = [];
  let l1Passed = 0, l1Total = 0;
  let l2Passed = 0, l2Total = 0;
  let l3Passed = 0, l3Total = 0;
  let passedCount = 0, failedCount = 0, unverifiedCount = 0;

  for (const control of controls) {
    let status: 'passed' | 'failed' | 'unverified';
    const relatedFindings: string[] = [];
    let remediation: string | undefined;

    if (control.verification === 'manual' || control.verification === 'forward') {
      // Manual/forward controls are unverified (human must check)
      status = 'unverified';
      unverifiedCount++;
      // Use control's remediation for manual/forward controls
      remediation = control.remediation;
    } else if (control.checkIds.length === 0) {
      // No automated checks defined
      status = 'unverified';
      unverifiedCount++;
      remediation = control.remediation;
    } else {
      // Check all mapped check IDs
      let hasAnyFinding = false;
      let hasFailure = false;
      for (const checkId of control.checkIds) {
        const finding = findingsByCheckId.get(checkId);
        if (finding) {
          hasAnyFinding = true;
          if (!finding.passed) {
            hasFailure = true;
            relatedFindings.push(`${checkId}: ${finding.description}`);
            if (finding.fix) {
              remediation = remediation || finding.fix;
            }
          }
        }
      }
      // Only mark as passed if we actually verified something
      // Missing findings = unverified (not passed)
      if (!hasAnyFinding) {
        status = 'unverified';
        unverifiedCount++;
        remediation = control.remediation;
      } else if (hasFailure) {
        status = 'failed';
        failedCount++;
        remediation = remediation || control.remediation;
      } else {
        status = 'passed';
        passedCount++;
      }
    }

    // Count by level for compliance calculation
    if (control.scored && status !== 'unverified') {
      if (control.level === 'L1') {
        l1Total++;
        if (status === 'passed') l1Passed++;
      } else if (control.level === 'L2') {
        l2Total++;
        if (status === 'passed') l2Passed++;
      } else if (control.level === 'L3') {
        l3Total++;
        if (status === 'passed') l3Passed++;
      }
    }

    controlResults.push({ control, status, findings: relatedFindings, remediation });
  }

  // Calculate compliance percentages
  const l1Compliance = l1Total > 0 ? Math.round((l1Passed / l1Total) * 100) : 100;
  const l2Compliance = l2Total > 0 ? Math.round((l2Passed / l2Total) * 100) : 100;
  const l3Compliance = l3Total > 0 ? Math.round((l3Passed / l3Total) * 100) : 100;
  const totalScored = l1Total + l2Total + l3Total;
  const totalPassed = l1Passed + l2Passed + l3Passed;
  const overallCompliance = totalScored > 0 ? Math.round((totalPassed / totalScored) * 100) : 0;

  // Group results by category
  const categoryResults: BenchmarkCategoryResult[] = [];
  for (const category of OASB_1_CATEGORIES) {
    if (categoryFilter && category.name.toLowerCase() !== categoryFilter.toLowerCase()) continue;

    const catControls = controlResults.filter((r: LocalControlResult) => r.control.category === category.name);
    if (catControls.length === 0) continue;

    const passed = catControls.filter((r: LocalControlResult) => r.status === 'passed').length;
    const failed = catControls.filter((r: LocalControlResult) => r.status === 'failed').length;
    const unverified = catControls.filter((r: LocalControlResult) => r.status === 'unverified').length;
    const compliance = (passed + failed) > 0 ? Math.round((passed / (passed + failed)) * 100) : 0;

    categoryResults.push({
      category: category.name,
      compliance,
      passed,
      failed,
      unverified,
      controls: catControls.map((r: LocalControlResult) => ({
        controlId: r.control.id,
        name: r.control.name,
        level: r.control.level,
        status: r.status,
        findings: r.findings,
        remediation: r.remediation,
      })),
    });
  }

  const rating = calculateRating(l1Compliance, l2Compliance, l3Compliance, level);

  return {
    benchmark: OASB_1_NAME,
    version: OASB_1_VERSION,
    level,
    timestamp: new Date(),
    compliance: overallCompliance,
    l1Compliance,
    l2Compliance,
    l3Compliance,
    rating,
    categories: categoryResults,
    totalControls: controls.length,
    passedControls: passedCount,
    failedControls: failedCount,
    unverifiedControls: unverifiedCount,
  };
}

// SARIF 2.1.0 output for GitHub Security tab and IDE integration
function generateSarifOutput(benchmarkResult: BenchmarkResult, findings: SecurityFinding[], targetDir: string): string {
  const rules: Array<{
    id: string;
    name: string;
    shortDescription: { text: string };
    fullDescription: { text: string };
    help: { text: string; markdown?: string };
    helpUri?: string;
    defaultConfiguration: { level: 'error' | 'warning' | 'note' };
    properties: { 'security-severity': string; tags: string[] };
  }> = [];

  const results: Array<{
    ruleId: string;
    level: 'error' | 'warning' | 'note';
    message: { text: string };
    locations?: Array<{
      physicalLocation: {
        artifactLocation: { uri: string };
        region?: { startLine: number; endLine?: number };
      };
    }>;
  }> = [];

  // Build rules and results from benchmark controls
  for (const cat of benchmarkResult.categories) {
    for (const ctrl of cat.controls) {
      if (ctrl.status === 'failed') {
        const ruleId = `OASB-1/${ctrl.controlId}`;
        const severityScore = ctrl.level === 'L1' ? '8.0' : ctrl.level === 'L2' ? '6.0' : '4.0';
        const sarifLevel: 'error' | 'warning' | 'note' = ctrl.level === 'L1' ? 'error' : ctrl.level === 'L2' ? 'warning' : 'note';

        rules.push({
          id: ruleId,
          name: ctrl.name.replace(/\s+/g, ''),
          shortDescription: { text: ctrl.name },
          fullDescription: { text: `OASB-1 ${ctrl.level} Control: ${ctrl.name}` },
          help: {
            text: ctrl.remediation || `Fix the ${ctrl.name} control to achieve compliance.`,
            markdown: ctrl.remediation ? `**Remediation:** ${ctrl.remediation}` : undefined,
          },
          helpUri: `https://oasb.ai/controls/${ctrl.controlId}`,
          defaultConfiguration: { level: sarifLevel },
          properties: {
            'security-severity': severityScore,
            tags: ['security', 'oasb-1', ctrl.level.toLowerCase()],
          },
        });

        // Find related findings for locations
        const relatedFindings = findings.filter(f => ctrl.findings.some(cf => cf.includes(f.checkId)));

        if (relatedFindings.length > 0) {
          for (const finding of relatedFindings) {
            results.push({
              ruleId,
              level: sarifLevel,
              message: { text: finding.description },
              locations: finding.file ? [{
                physicalLocation: {
                  artifactLocation: { uri: finding.file.replace(targetDir + '/', '') },
                  region: finding.line ? { startLine: finding.line } : undefined,
                },
              }] : undefined,
            });
          }
        } else {
          // No specific location, just report the control failure
          results.push({
            ruleId,
            level: sarifLevel,
            message: { text: ctrl.findings.join('; ') || `Control ${ctrl.controlId} failed` },
          });
        }
      }
    }
  }

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0' as const,
    runs: [{
      tool: {
        driver: {
          name: 'HackMyAgent',
          version: VERSION,
          informationUri: 'https://hackmyagent.com',
          rules,
        },
      },
      results,
    }],
  };

  return JSON.stringify(sarif, null, 2);
}

// HTML report for shareable compliance documentation
function generateHtmlReport(result: BenchmarkResult): string {
  const ratingColor = {
    'Certified': '#22c55e',
    'Compliant': '#22c55e',
    'Passing': '#eab308',
    'Needs Improvement': '#f97316',
    'Not Passing': '#ef4444',
  }[result.rating] || '#94a3b8';

  const ratingBg = {
    'Certified': 'rgba(34, 197, 94, 0.15)',
    'Compliant': 'rgba(34, 197, 94, 0.15)',
    'Passing': 'rgba(234, 179, 8, 0.15)',
    'Needs Improvement': 'rgba(249, 115, 22, 0.15)',
    'Not Passing': 'rgba(239, 68, 68, 0.15)',
  }[result.rating] || 'rgba(148, 163, 184, 0.15)';

  // Generate donut chart SVG
  const donutRadius = 70;
  const donutStroke = 14;
  const donutCircumference = 2 * Math.PI * donutRadius;
  const donutOffset = donutCircumference * (1 - result.compliance / 100);
  const complianceColor = result.compliance >= 90 ? '#22c55e' : result.compliance >= 70 ? '#eab308' : '#ef4444';

  // Generate radar chart data points
  const radarCategories = result.categories.slice(0, 10); // Max 10 for radar
  const radarPoints: string[] = [];
  const radarLabels: string[] = [];
  const radarCenter = 120;
  const radarRadius = 90;

  // Category name abbreviations for radar chart labels
  const categoryAbbreviations: Record<string, string> = {
    'Identity & Provenance': 'Identity',
    'Capability & Authorization': 'Capability',
    'Input Security': 'Input',
    'Output Security': 'Output',
    'Credential Protection': 'Credentials',
    'Supply Chain Integrity': 'Supply Chain',
    'Agent-to-Agent Security': 'A2A Security',
    'Memory & Context Integrity': 'Memory',
    'Operational Security': 'Operations',
    'Monitoring & Response': 'Monitoring',
  };

  radarCategories.forEach((cat, i) => {
    const angle = (Math.PI * 2 * i) / radarCategories.length - Math.PI / 2;
    // Use minimum 5% so 0% categories still show on the chart edge (not at center)
    const value = Math.max(0.05, cat.compliance / 100);
    const x = radarCenter + Math.cos(angle) * radarRadius * value;
    const y = radarCenter + Math.sin(angle) * radarRadius * value;
    radarPoints.push(`${x},${y}`);

    // Label position (slightly outside)
    const labelX = radarCenter + Math.cos(angle) * (radarRadius + 20);
    const labelY = radarCenter + Math.sin(angle) * (radarRadius + 20);
    const shortName = categoryAbbreviations[cat.category] || cat.category.split(' ')[0];
    radarLabels.push(`<text x="${labelX}" y="${labelY}" text-anchor="middle" dominant-baseline="middle" fill="#94a3b8" font-size="10" font-weight="500">${escapeHtml(shortName)}</text>`);
  });

  // Generate radar grid lines
  const radarGrid = [0.25, 0.5, 0.75, 1].map(scale => {
    const points = radarCategories.map((_, i) => {
      const angle = (Math.PI * 2 * i) / radarCategories.length - Math.PI / 2;
      const x = radarCenter + Math.cos(angle) * radarRadius * scale;
      const y = radarCenter + Math.sin(angle) * radarRadius * scale;
      return `${x},${y}`;
    }).join(' ');
    return `<polygon points="${points}" fill="none" stroke="#334155" stroke-width="1"/>`;
  }).join('');

  // Radar axis lines
  const radarAxes = radarCategories.map((_, i) => {
    const angle = (Math.PI * 2 * i) / radarCategories.length - Math.PI / 2;
    const x = radarCenter + Math.cos(angle) * radarRadius;
    const y = radarCenter + Math.sin(angle) * radarRadius;
    return `<line x1="${radarCenter}" y1="${radarCenter}" x2="${x}" y2="${y}" stroke="#334155" stroke-width="1"/>`;
  }).join('');

  // Collect all controls for statistics
  const allControls = result.categories.flatMap(cat => cat.controls);
  const failedControls = allControls.filter(ctrl => ctrl.status === 'failed');
  const passedControls = allControls.filter(ctrl => ctrl.status === 'passed');
  const unverifiedControls = allControls.filter(ctrl => ctrl.status === 'unverified');

  // Level breakdown stats
  const levelStats = {
    L1: { passed: 0, failed: 0, total: 0 },
    L2: { passed: 0, failed: 0, total: 0 },
    L3: { passed: 0, failed: 0, total: 0 },
  };
  allControls.forEach(ctrl => {
    const lvl = ctrl.level as 'L1' | 'L2' | 'L3';
    if (levelStats[lvl]) {
      levelStats[lvl].total++;
      if (ctrl.status === 'passed') levelStats[lvl].passed++;
      if (ctrl.status === 'failed') levelStats[lvl].failed++;
    }
  });

  // Find worst category
  const worstCategory = result.categories
    .filter(cat => cat.passed + cat.failed > 0)
    .sort((a, b) => a.compliance - b.compliance)[0];

  // Security grade based on compliance
  const getGrade = (pct: number) => {
    if (pct >= 90) return { letter: 'strong', color: '#22c55e' };
    if (pct >= 80) return { letter: 'good', color: '#84cc16' };
    if (pct >= 70) return { letter: 'moderate', color: '#eab308' };
    if (pct >= 60) return { letter: 'improving', color: '#f97316' };
    return { letter: 'needs-attention', color: '#ef4444' };
  };
  const grade = getGrade(result.compliance);

  // Generate executive summary items
  const executiveSummary = failedControls.length === 0
    ? '<div class="exec-item success"><span class="exec-icon">✓</span><span>All controls passing at this level</span></div>'
    : failedControls.slice(0, 5).map(ctrl =>
        `<div class="exec-item critical"><span class="exec-icon">!</span><span><strong>${ctrl.controlId}</strong>: ${escapeHtml(ctrl.name)}</span></div>`
      ).join('') + (failedControls.length > 5 ? `<div class="exec-item warning"><span class="exec-icon">+</span><span>${failedControls.length - 5} more issues not shown</span></div>` : '');

  // SVG icons for professional look (no emojis)
  const icons = {
    check: '<svg class="icon icon-check" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>',
    x: '<svg class="icon icon-x" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>',
    warning: '<svg class="icon icon-warning" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>',
    circle: '<svg class="icon icon-circle" viewBox="0 0 20 20" fill="currentColor"><circle cx="10" cy="10" r="4"/></svg>',
    shield: '<svg class="icon icon-shield" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-2A11.954 11.954 0 0110 1.944zM11 14a1 1 0 11-2 0 1 1 0 012 0zm0-7a1 1 0 10-2 0v3a1 1 0 102 0V7z" clip-rule="evenodd"/></svg>',
    print: '<svg class="icon icon-print" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M5 4v3H4a2 2 0 00-2 2v3a2 2 0 002 2h1v2a2 2 0 002 2h6a2 2 0 002-2v-2h1a2 2 0 002-2V9a2 2 0 00-2-2h-1V4a2 2 0 00-2-2H7a2 2 0 00-2 2zm8 0H7v3h6V4zm0 8H7v4h6v-4z" clip-rule="evenodd"/></svg>',
  };

  // Category rows with collapsible sections
  const categoryRows = result.categories.map((cat, catIndex) => {
    const statusIcon = cat.failed === 0 ? icons.check : cat.passed > 0 ? icons.warning : icons.x;
    const statusClass = cat.failed === 0 ? 'status-pass' : cat.passed > 0 ? 'status-warn' : 'status-fail';
    const barColor = cat.compliance >= 90 ? '#22c55e' : cat.compliance >= 70 ? '#eab308' : '#ef4444';

    const controlRows = cat.controls.map(ctrl => {
      const statusSvg = ctrl.status === 'passed' ? icons.check : ctrl.status === 'failed' ? icons.x : icons.circle;
      const ctrlStatusClass = ctrl.status === 'passed' ? 'status-pass' : ctrl.status === 'failed' ? 'status-fail' : 'status-unverified';
      const findingsList = ctrl.findings.length > 0
        ? `<ul class="findings">${ctrl.findings.map(f => `<li>${escapeHtml(f)}</li>`).join('')}</ul>`
        : '';
      const remediation = ctrl.remediation
        ? `<div class="remediation"><strong>Remediation:</strong> ${escapeHtml(ctrl.remediation)}</div>`
        : '';
      return `
        <tr class="control-row ${ctrl.status}">
          <td class="status-cell"><span class="${ctrlStatusClass}">${statusSvg}</span></td>
          <td class="id-cell"><code>${ctrl.controlId}</code></td>
          <td class="name-cell">${escapeHtml(ctrl.name)}</td>
          <td class="level-cell"><span class="level-badge level-${ctrl.level.toLowerCase()}">${ctrl.level}</span></td>
          <td class="details-cell">${findingsList}${remediation}</td>
        </tr>`;
    }).join('');

    return `
      <div class="category" id="cat-${catIndex}">
        <div class="category-header" onclick="toggleCategory(${catIndex})">
          <span class="category-icon ${statusClass}">${statusIcon}</span>
          <span class="category-name">${escapeHtml(cat.category)}</span>
          <div class="category-meta">
            <span class="category-score">${cat.passed}/${cat.passed + cat.failed}</span>
            <div class="mini-bar"><div class="mini-fill" style="width: ${cat.compliance}%; background: ${barColor};"></div></div>
            <span class="category-percent">${cat.compliance}%</span>
            <span class="chevron">▼</span>
          </div>
        </div>
        <div class="category-content">
          <table class="controls-table">
            <thead><tr><th></th><th>Control ID</th><th>Control Name</th><th>Level</th><th>Details</th></tr></thead>
            <tbody>${controlRows}</tbody>
          </table>
        </div>
      </div>`;
  }).join('');

  // Level description
  const levelDesc = {
    'L1': 'Essential baseline security every agent should implement',
    'L2': 'Defense-in-depth for production systems',
    'L3': 'Maximum security for high-risk or regulated environments'
  }[result.level] || '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OASB-1 Compliance Report | ${result.rating}</title>
  <style>
    :root {
      --bg-primary: #0a0f1a;
      --bg-secondary: #111827;
      --bg-tertiary: #1f2937;
      --text-primary: #f1f5f9;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --border: #334155;
      --accent: #3b82f6;
      --success: #22c55e;
      --warning: #eab308;
      --danger: #ef4444;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      padding: 2rem;
      font-size: 14px;
    }
    .container { max-width: 1400px; margin: 0 auto; }

    /* Header */
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      padding: 1.5rem 2rem;
      background: var(--bg-secondary);
      border-radius: 12px;
      border: 1px solid var(--border);
    }
    .header-left h1 {
      font-size: 1.5rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .header-left .meta { color: var(--text-muted); font-size: 0.8rem; margin-top: 0.25rem; }
    .header-icon { display: inline-flex; margin-right: 0.5rem; }
    .header-icon .icon { width: 24px; height: 24px; color: var(--accent); }
    .header-right { display: flex; align-items: center; gap: 1rem; }
    .rating-badge {
      display: inline-block;
      padding: 0.375rem 1rem;
      border-radius: 6px;
      font-weight: 600;
      font-size: 0.875rem;
      background: ${ratingBg};
      color: ${ratingColor};
      border: 1px solid ${ratingColor}40;
    }
    .level-tag {
      display: inline-block;
      padding: 0.375rem 1rem;
      background: var(--accent);
      color: white;
      border-radius: 6px;
      font-size: 0.875rem;
      font-weight: 600;
    }

    /* SVG Icons */
    .icon { width: 16px; height: 16px; display: inline-block; vertical-align: middle; }
    .status-pass { color: var(--success); }
    .status-fail { color: var(--danger); }
    .status-warn { color: var(--warning); }
    .status-unverified { color: var(--text-muted); }
    .category-icon { display: flex; align-items: center; }
    .category-icon .icon { width: 18px; height: 18px; }
    .footer-btn .icon { width: 14px; height: 14px; margin-right: 0.375rem; }

    /* Dashboard grid */
    .dashboard {
      display: grid;
      grid-template-columns: 280px 1fr 300px;
      gap: 1.5rem;
      margin-bottom: 2rem;
    }
    @media (max-width: 1200px) {
      .dashboard { grid-template-columns: 1fr 1fr; }
      .radar-section { grid-column: span 2; }
    }
    @media (max-width: 768px) {
      .dashboard { grid-template-columns: 1fr; }
      .radar-section { grid-column: span 1; }
    }

    /* Score card - Prowler style */
    .score-card {
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 1.25rem;
      border: 1px solid var(--border);
    }
    .score-header {
      display: flex;
      align-items: center;
      gap: 1rem;
      margin-bottom: 1.25rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border);
    }
    .score-grade {
      width: 72px;
      height: 72px;
      border-radius: 12px;
      border: 2px solid;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .grade-letter { font-size: 0.65rem; font-weight: 800; text-transform: uppercase; text-align: center; line-height: 1.2; }
    .score-main { flex: 1; }
    .score-pct { font-size: 2rem; font-weight: 700; color: var(--text-primary); line-height: 1; }
    .score-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }

    .score-bars { margin-bottom: 1rem; }
    .score-bar-row {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 0.5rem;
    }
    .bar-label { width: 50px; font-size: 0.75rem; color: var(--text-secondary); }
    .bar-track { flex: 1; height: 8px; background: var(--bg-tertiary); border-radius: 4px; overflow: hidden; }
    .bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
    .bar-pass { background: var(--success); }
    .bar-fail { background: var(--danger); }
    .bar-manual { background: var(--text-muted); }
    .bar-count { width: 24px; font-size: 0.8rem; font-weight: 600; text-align: right; color: var(--text-primary); }

    .level-breakdown {
      display: flex;
      gap: 0.75rem;
      padding: 0.75rem;
      background: var(--bg-tertiary);
      border-radius: 8px;
      margin-bottom: 1rem;
    }
    .level-row { display: flex; align-items: center; gap: 0.375rem; }
    .level-stat { font-size: 0.8rem; color: var(--text-secondary); }

    .worst-category {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.625rem 0.75rem;
      background: rgba(239, 68, 68, 0.1);
      border-radius: 6px;
      border-left: 3px solid var(--danger);
    }
    .worst-label { font-size: 0.7rem; color: var(--danger); text-transform: uppercase; font-weight: 600; }
    .worst-name { flex: 1; font-size: 0.8rem; color: var(--text-primary); }
    .worst-pct { font-size: 0.85rem; font-weight: 700; }

    /* Radar chart */
    .radar-section {
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 1.5rem;
      border: 1px solid var(--border);
    }
    .radar-section h3 {
      font-size: 0.85rem;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 1rem;
    }
    .radar-container { display: flex; justify-content: center; }

    /* Executive summary */
    .exec-section {
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 1.5rem;
      border: 1px solid var(--border);
    }
    .exec-section h3 {
      font-size: 0.85rem;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 1rem;
    }
    .exec-item {
      display: flex;
      align-items: flex-start;
      gap: 0.75rem;
      padding: 0.75rem;
      margin-bottom: 0.5rem;
      border-radius: 6px;
      font-size: 0.85rem;
    }
    .exec-item.critical { background: rgba(239, 68, 68, 0.1); border-left: 3px solid var(--danger); }
    .exec-item.warning { background: rgba(234, 179, 8, 0.1); border-left: 3px solid var(--warning); }
    .exec-item.success { background: rgba(34, 197, 94, 0.1); border-left: 3px solid var(--success); }
    .exec-icon {
      width: 20px;
      height: 20px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 0.75rem;
      flex-shrink: 0;
    }
    .exec-item.critical .exec-icon { background: var(--danger); color: white; }
    .exec-item.warning .exec-icon { background: var(--warning); color: black; }
    .exec-item.success .exec-icon { background: var(--success); color: white; }

    /* Categories */
    .categories-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }
    .categories-header h2 { font-size: 1.1rem; }
    .expand-all {
      background: var(--bg-tertiary);
      border: 1px solid var(--border);
      color: var(--text-secondary);
      padding: 0.5rem 1rem;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.8rem;
    }
    .expand-all:hover { background: var(--border); }

    .category {
      background: var(--bg-secondary);
      border-radius: 8px;
      margin-bottom: 0.75rem;
      border: 1px solid var(--border);
      overflow: hidden;
    }
    .category-header {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 1rem 1.25rem;
      cursor: pointer;
      transition: background 0.15s;
    }
    .category-header:hover { background: var(--bg-tertiary); }
    .category-icon { font-size: 1.1rem; }
    .category-name { flex: 1; font-weight: 500; }
    .category-meta { display: flex; align-items: center; gap: 0.75rem; }
    .category-score { color: var(--text-secondary); font-size: 0.85rem; font-weight: 500; }
    .mini-bar { width: 60px; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; }
    .mini-fill { height: 100%; border-radius: 3px; }
    .category-percent { color: var(--text-muted); font-size: 0.85rem; width: 40px; text-align: right; }
    .chevron {
      color: var(--text-muted);
      font-size: 0.7rem;
      transition: transform 0.2s;
      margin-left: 0.5rem;
    }
    .category.collapsed .chevron { transform: rotate(-90deg); }
    .category.collapsed .category-content { display: none; }

    .category-content { border-top: 1px solid var(--border); }
    .controls-table { width: 100%; border-collapse: collapse; }
    .controls-table th {
      padding: 0.75rem 1rem;
      text-align: left;
      background: var(--bg-primary);
      color: var(--text-muted);
      font-weight: 500;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .controls-table td {
      padding: 0.875rem 1rem;
      border-top: 1px solid var(--border);
      vertical-align: top;
    }
    .status-cell { width: 40px; text-align: center; }
    .id-cell { width: 100px; }
    .id-cell code {
      background: var(--bg-tertiary);
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.8rem;
      color: var(--accent);
    }
    .name-cell { width: 30%; }
    .level-cell { width: 60px; }
    .details-cell { color: var(--text-secondary); font-size: 0.85rem; }
    .control-row.failed { background: rgba(239, 68, 68, 0.05); }
    .control-row.unverified { opacity: 0.5; }

    .level-badge {
      padding: 0.2rem 0.6rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
    }
    .level-l1 { background: #7c3aed; color: white; }
    .level-l2 { background: #2563eb; color: white; }
    .level-l3 { background: #059669; color: white; }

    .findings {
      margin: 0.25rem 0 0.5rem;
      padding-left: 1.25rem;
      color: #f87171;
      list-style-type: disc;
    }
    .findings li { margin-bottom: 0.25rem; }
    .remediation {
      margin-top: 0.5rem;
      padding: 0.625rem 0.875rem;
      background: var(--bg-tertiary);
      border-radius: 6px;
      font-size: 0.8rem;
      border-left: 3px solid var(--accent);
    }

    /* Footer */
    .footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 2rem;
      padding: 1.5rem;
      background: var(--bg-secondary);
      border-radius: 12px;
      border: 1px solid var(--border);
      color: var(--text-muted);
      font-size: 0.85rem;
    }
    .footer a { color: var(--accent); text-decoration: none; }
    .footer a:hover { text-decoration: underline; }
    .footer-actions { display: flex; gap: 1rem; }
    .footer-btn {
      padding: 0.5rem 1rem;
      background: var(--bg-tertiary);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text-primary);
      cursor: pointer;
      font-size: 0.8rem;
    }
    .footer-btn:hover { background: var(--border); }

    /* Print styles */
    @media print {
      body { background: white; color: black; padding: 1rem; }
      .container { max-width: 100%; }
      .header, .donut-card, .radar-section, .exec-section, .category, .footer {
        background: white;
        border: 1px solid #ddd;
        break-inside: avoid;
      }
      .category.collapsed .category-content { display: block !important; }
      .chevron, .expand-all, .footer-actions { display: none; }
      .category-header { cursor: default; }
      .control-row.failed { background: #fff0f0; }
      :root {
        --bg-primary: white;
        --bg-secondary: white;
        --bg-tertiary: #f5f5f5;
        --text-primary: black;
        --text-secondary: #555;
        --text-muted: #888;
        --border: #ddd;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <header class="header">
      <div class="header-left">
        <h1><span class="header-icon">${icons.shield}</span>${escapeHtml(result.benchmark)}</h1>
        <div class="meta">Version ${result.version} • Generated ${new Date(result.timestamp).toLocaleString()}</div>
      </div>
      <div class="header-right">
        <div class="rating-badge">${result.rating}</div>
        <div class="level-tag">${result.level} — ${result.level === 'L1' ? 'Essential' : result.level === 'L2' ? 'Standard' : 'Hardened'}</div>
      </div>
    </header>

    <div class="dashboard">
      <div class="score-card">
        <div class="score-header">
          <div class="score-grade" style="background: ${grade.color}20; border-color: ${grade.color};">
            <span class="grade-letter" style="color: ${grade.color};">${grade.letter}</span>
          </div>
          <div class="score-main">
            <div class="score-pct">${result.compliance}%</div>
            <div class="score-label">Security Score</div>
          </div>
        </div>

        <div class="score-bars">
          <div class="score-bar-row">
            <span class="bar-label">Passed</span>
            <div class="bar-track">
              <div class="bar-fill bar-pass" style="width: ${allControls.length ? (passedControls.length / allControls.length * 100) : 0}%;"></div>
            </div>
            <span class="bar-count">${passedControls.length}</span>
          </div>
          <div class="score-bar-row">
            <span class="bar-label">Failed</span>
            <div class="bar-track">
              <div class="bar-fill bar-fail" style="width: ${allControls.length ? (failedControls.length / allControls.length * 100) : 0}%;"></div>
            </div>
            <span class="bar-count">${failedControls.length}</span>
          </div>
          <div class="score-bar-row">
            <span class="bar-label">Manual</span>
            <div class="bar-track">
              <div class="bar-fill bar-manual" style="width: ${allControls.length ? (unverifiedControls.length / allControls.length * 100) : 0}%;"></div>
            </div>
            <span class="bar-count">${unverifiedControls.length}</span>
          </div>
        </div>

        <div class="level-breakdown">
          <div class="level-row">
            <span class="level-badge level-l1">L1</span>
            <span class="level-stat">${levelStats.L1.passed}/${levelStats.L1.total}</span>
          </div>
          <div class="level-row">
            <span class="level-badge level-l2">L2</span>
            <span class="level-stat">${levelStats.L2.passed}/${levelStats.L2.total}</span>
          </div>
          <div class="level-row">
            <span class="level-badge level-l3">L3</span>
            <span class="level-stat">${levelStats.L3.passed}/${levelStats.L3.total}</span>
          </div>
        </div>

        ${worstCategory && worstCategory.compliance < 100 ? `
        <div class="worst-category">
          <span class="worst-label">Needs Attention</span>
          <span class="worst-name">${escapeHtml(worstCategory.category)}</span>
          <span class="worst-pct" style="color: ${worstCategory.compliance < 50 ? '#ef4444' : '#eab308'};">${worstCategory.compliance}%</span>
        </div>` : ''}
      </div>

      <div class="radar-section">
        <h3>Category Coverage</h3>
        <div class="radar-container">
          <svg width="240" height="240" viewBox="0 0 240 240">
            ${radarGrid}
            ${radarAxes}
            <polygon points="${radarPoints.join(' ')}" fill="${complianceColor}20" stroke="${complianceColor}" stroke-width="2"/>
            ${radarLabels.join('')}
          </svg>
        </div>
      </div>

      <div class="exec-section">
        <h3>Priority Issues</h3>
        ${executiveSummary}
        ${failedControls.length > 0 ? `<div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border); font-size: 0.8rem; color: var(--text-muted);">
          ${levelDesc}
        </div>` : ''}
      </div>
    </div>

    <div class="categories-header">
      <h2>Control Details by Category</h2>
      <button class="expand-all" onclick="toggleAll()">Expand All</button>
    </div>

    ${categoryRows}

    <footer class="footer">
      <div>
        Generated by <a href="https://hackmyagent.com">HackMyAgent</a> •
        <a href="https://oasb.ai">OASB-1 Specification</a>
      </div>
      <div class="footer-actions">
        <button class="footer-btn" onclick="window.print()">${icons.print} Print / PDF</button>
      </div>
    </footer>
  </div>

  <script>
    function toggleCategory(index) {
      const cat = document.getElementById('cat-' + index);
      cat.classList.toggle('collapsed');
    }

    function toggleAll() {
      const categories = document.querySelectorAll('.category');
      const btn = document.querySelector('.expand-all');
      const allCollapsed = Array.from(categories).every(c => c.classList.contains('collapsed'));

      categories.forEach(cat => {
        if (allCollapsed) {
          cat.classList.remove('collapsed');
        } else {
          cat.classList.add('collapsed');
        }
      });

      btn.textContent = allCollapsed ? 'Collapse All' : 'Expand All';
    }

    // Start with categories collapsed
    document.querySelectorAll('.category').forEach(cat => cat.classList.add('collapsed'));
  </script>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// SARIF output for non-benchmark secure scans
function generateScanSarif(findings: SecurityFinding[], targetDir: string): string {
  const issues = findings.filter(f => !f.passed && !f.fixed);
  const rules = issues.map(f => ({
    id: f.checkId,
    name: f.name.replace(/\s+/g, ''),
    shortDescription: { text: f.name },
    fullDescription: { text: f.description },
    help: { text: f.fix || `Fix the ${f.name} issue.` },
    defaultConfiguration: {
      level: (f.severity === 'critical' || f.severity === 'high' ? 'error' :
             f.severity === 'medium' ? 'warning' : 'note') as 'error' | 'warning' | 'note',
    },
    properties: {
      'security-severity': f.severity === 'critical' ? '9.0' :
                          f.severity === 'high' ? '7.0' :
                          f.severity === 'medium' ? '5.0' : '3.0',
      tags: ['security', 'ai-agent', f.category],
    },
  }));

  const results = issues.map(f => ({
    ruleId: f.checkId,
    level: (f.severity === 'critical' || f.severity === 'high' ? 'error' :
           f.severity === 'medium' ? 'warning' : 'note') as 'error' | 'warning' | 'note',
    message: { text: f.description },
    locations: f.file ? [{
      physicalLocation: {
        artifactLocation: { uri: f.file.replace(targetDir + '/', '') },
        ...(f.line ? { region: { startLine: f.line } } : {}),
      },
    }] : undefined,
  }));

  return JSON.stringify({
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'HackMyAgent',
          version: VERSION,
          informationUri: 'https://hackmyagent.com',
          rules,
        },
      },
      results,
    }],
  }, null, 2);
}

// HTML report for non-benchmark secure scans
function generateScanHtmlReport(scanResult: { findings: SecurityFinding[]; score: number; maxScore: number; projectType: string }, targetDir: string): string {
  const issues = scanResult.findings.filter(f => !f.passed && !f.fixed);
  const fixedFindings = scanResult.findings.filter(f => f.fixed);
  const score = scanResult.score;
  const scoreColor = score >= 90 ? '#22c55e' : score >= 70 ? '#eab308' : score >= 50 ? '#f97316' : '#ef4444';
  const gradeLetters = score >= 90 ? 'strong' : score >= 80 ? 'good' : score >= 70 ? 'moderate' : score >= 60 ? 'improving' : 'needs-attention';

  const severityOrder = ['critical', 'high', 'medium', 'low'];
  const severityColors: Record<string, string> = {
    critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
  };

  const issueRows = issues
    .sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity))
    .map(f => `
      <tr>
        <td><span class="severity-badge" style="background: ${severityColors[f.severity]}20; color: ${severityColors[f.severity]}; border: 1px solid ${severityColors[f.severity]}40;">${escapeHtml(f.severity.toUpperCase())}</span></td>
        <td><code>${escapeHtml(f.checkId)}</code></td>
        <td>${escapeHtml(f.description)}</td>
        <td>${f.file ? escapeHtml(f.file) + (f.line ? ':' + f.line : '') : ''}</td>
        <td>${f.fix ? escapeHtml(f.fix) : ''}</td>
      </tr>`).join('');

  const fixedRows = fixedFindings.map(f => `
      <tr>
        <td><span class="severity-badge" style="background: #22c55e20; color: #22c55e; border: 1px solid #22c55e40;">FIXED</span></td>
        <td><code>${escapeHtml(f.checkId)}</code></td>
        <td>${escapeHtml(f.description)}</td>
        <td>${f.file ? escapeHtml(f.file) : ''}</td>
        <td>${f.fixMessage ? escapeHtml(f.fixMessage) : ''}</td>
      </tr>`).join('');

  const projectTypeLabel: Record<string, string> = {
    cli: 'CLI Tool', library: 'Library', webapp: 'Web App', api: 'API Server',
    mcp: 'MCP Server', openclaw: 'OpenClaw Agent', all: 'Project',
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HackMyAgent Security Report | ${escapeHtml(require('path').basename(targetDir))}</title>
  <style>
    :root { --bg-primary: #0a0f1a; --bg-secondary: #111827; --bg-tertiary: #1f2937; --text-primary: #f1f5f9; --text-secondary: #94a3b8; --border: #334155; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg-primary); color: var(--text-primary); line-height: 1.6; padding: 2rem; font-size: 14px; }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
    .meta { color: var(--text-secondary); margin-bottom: 2rem; }
    .score-card { display: flex; align-items: center; gap: 2rem; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; }
    .grade { font-size: 0.75rem; font-weight: 700; width: 100px; height: 100px; display: flex; align-items: center; justify-content: center; border-radius: 50%; border: 3px solid ${scoreColor}; text-transform: uppercase; text-align: center; line-height: 1.2; padding: 0.5rem; }
    .score-details { flex: 1; }
    .score-num { font-size: 2rem; font-weight: 700; }
    .stats { display: flex; gap: 2rem; margin-top: 0.5rem; }
    .stat { color: var(--text-secondary); }
    .stat strong { color: var(--text-primary); }
    table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
    th { text-align: left; padding: 0.75rem; background: var(--bg-secondary); border-bottom: 1px solid var(--border); color: var(--text-secondary); font-size: 0.8rem; text-transform: uppercase; }
    td { padding: 0.75rem; border-bottom: 1px solid var(--border); vertical-align: top; }
    code { background: var(--bg-tertiary); padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }
    .severity-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
    .section { margin-top: 2rem; }
    .section h2 { font-size: 1.2rem; margin-bottom: 0.5rem; }
    footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--text-secondary); font-size: 0.85rem; }
    footer a { color: #3b82f6; }
    @media print { body { background: #fff; color: #000; } .score-card { border-color: #ccc; } th { background: #f3f4f6; } td { border-color: #e5e7eb; } }
  </style>
</head>
<body>
  <div class="container">
    <h1>HackMyAgent Security Report</h1>
    <div class="meta">${escapeHtml(projectTypeLabel[scanResult.projectType] || 'Project')} - ${escapeHtml(require('path').basename(targetDir))} - ${new Date().toISOString().split('T')[0]}</div>

    <div class="score-card">
      <div class="grade" style="color: ${scoreColor};">${gradeLetters}</div>
      <div class="score-details">
        <div class="score-num" style="color: ${scoreColor};">${score}/${scanResult.maxScore}</div>
        <div class="stats">
          <span class="stat"><strong>${issues.length}</strong> issues</span>
          <span class="stat"><strong>${fixedFindings.length}</strong> fixed</span>
          <span class="stat"><strong>${scanResult.findings.filter(f => f.passed).length}</strong> passed</span>
        </div>
      </div>
    </div>

    ${issues.length > 0 ? `
    <div class="section">
      <h2>Issues (${issues.length})</h2>
      <table>
        <thead><tr><th>Severity</th><th>Check</th><th>Description</th><th>Location</th><th>Remediation</th></tr></thead>
        <tbody>${issueRows}</tbody>
      </table>
    </div>` : '<div class="section"><h2>No issues found</h2></div>'}

    ${fixedFindings.length > 0 ? `
    <div class="section">
      <h2>Auto-Fixed (${fixedFindings.length})</h2>
      <table>
        <thead><tr><th>Status</th><th>Check</th><th>Description</th><th>Location</th><th>Details</th></tr></thead>
        <tbody>${fixedRows}</tbody>
      </table>
    </div>` : ''}

    <footer>Generated by <a href="https://hackmyagent.com">HackMyAgent</a> v${VERSION}</footer>
  </div>
</body>
</html>`;
}

// Agent Security Profile (ASP) - our differentiator format
function generateAspOutput(benchmarkResult: BenchmarkResult, scanResult: { findings: SecurityFinding[]; projectType: string }, targetDir: string): string {
  const fs = require('fs');
  const path = require('path');

  // Try to get agent name from package.json or directory name
  let agentName = path.basename(targetDir);
  let agentVersion = '0.0.0';
  try {
    const pkgPath = path.join(targetDir, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      agentName = pkg.name || agentName;
      agentVersion = pkg.version || agentVersion;
    }
  } catch { /* ignore */ }

  // Analyze capabilities from findings
  const capabilities: Record<string, string> = {};
  const hasFilesystemAccess = scanResult.findings.some(f => f.checkId.includes('FS-') || f.description.toLowerCase().includes('filesystem'));
  const hasNetworkAccess = scanResult.findings.some(f => f.checkId.includes('NET-') || f.description.toLowerCase().includes('network'));
  const hasShellAccess = scanResult.findings.some(f => f.checkId.includes('SHELL-') || f.description.toLowerCase().includes('shell') || f.description.toLowerCase().includes('exec'));

  capabilities['filesystem'] = hasFilesystemAccess ? 'detected' : 'none';
  capabilities['network'] = hasNetworkAccess ? 'detected' : 'none';
  capabilities['shell'] = hasShellAccess ? 'detected' : 'none';

  // Credential hygiene
  const credentialFindings = scanResult.findings.filter(f => f.checkId.startsWith('CRED-'));
  const hardcodedCreds = credentialFindings.filter(f => !f.passed).length;

  // Supply chain status
  const supplyChainFindings = scanResult.findings.filter(f =>
    f.checkId.startsWith('SKILL-') || f.checkId.startsWith('HEARTBEAT-') || f.checkId.startsWith('DEP-')
  );
  const signedSkills = !supplyChainFindings.some(f => f.checkId === 'SKILL-001' && !f.passed);
  const pinnedDeps = !supplyChainFindings.some(f => f.checkId === 'DEP-001' && !f.passed);

  const asp = {
    specVersion: '1.0.0',
    generatedAt: new Date().toISOString(),
    generator: {
      name: 'HackMyAgent',
      version: VERSION,
      url: 'https://hackmyagent.com',
    },
    agent: {
      name: agentName,
      version: agentVersion,
      type: scanResult.projectType,
      path: targetDir,
    },
    securityPosture: {
      benchmark: 'OASB-1',
      benchmarkVersion: benchmarkResult.version,
      level: benchmarkResult.level,
      compliance: benchmarkResult.compliance,
      rating: benchmarkResult.rating,
      l1Compliance: benchmarkResult.l1Compliance,
      l2Compliance: benchmarkResult.l2Compliance,
      l3Compliance: benchmarkResult.l3Compliance,
    },
    capabilities,
    credentials: {
      hardcodedSecrets: hardcodedCreds,
      recommendation: hardcodedCreds > 0 ? 'Move secrets to environment variables or secrets manager' : 'No hardcoded credentials detected',
    },
    supplyChain: {
      signedComponents: signedSkills,
      pinnedDependencies: pinnedDeps,
      issues: supplyChainFindings.filter(f => !f.passed).map(f => ({
        id: f.checkId,
        description: f.description,
        remediation: f.fix,
      })),
    },
    categories: benchmarkResult.categories.map(cat => ({
      name: cat.category,
      compliance: cat.compliance,
      passed: cat.passed,
      failed: cat.failed,
      unverified: cat.unverified,
    })),
    failedControls: benchmarkResult.categories.flatMap(cat =>
      cat.controls.filter(c => c.status === 'failed').map(c => ({
        id: c.controlId,
        name: c.name,
        level: c.level,
        findings: c.findings,
        remediation: c.remediation,
      }))
    ),
    // Attestation placeholder - could be signed in future
    attestation: {
      timestamp: new Date().toISOString(),
      // signature: null, // Future: GPG or Sigstore signature
    },
  };

  return JSON.stringify(asp, null, 2);
}

function printBenchmarkReport(result: BenchmarkResult, verbose: boolean): void {
  const ratingColors: Record<BenchmarkResult['rating'], string> = {
    'Certified': colors.green,
    'Compliant': colors.green,
    'Passing': colors.yellow,
    'Needs Improvement': colors.yellow,
    'Not Passing': colors.red,
  };

  // Header
  console.log(`\n${result.benchmark} v${result.version}`);
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);

  // Level and rating
  const levelNames: Record<BenchmarkLevel, string> = {
    'L1': 'Level 1 - Essential',
    'L2': 'Level 2 - Standard',
    'L3': 'Level 3 - Hardened',
  };
  console.log(`Level: ${levelNames[result.level]}`);
  console.log(`Rating: ${ratingColors[result.rating]}${result.rating}${RESET()}`);
  console.log(`Compliance: ${result.compliance}% (${result.passedControls}/${result.passedControls + result.failedControls} verified controls)`);
  if (result.unverifiedControls > 0) {
    console.log(`Unverified: ${result.unverifiedControls} controls require manual/forward verification`);
  }
  console.log();

  // Category breakdown
  console.log(`Categories:`);
  for (const catResult of result.categories) {
    const total = catResult.passed + catResult.failed;
    if (total === 0) {
      console.log(`  [.] ${catResult.category}: N/A (no controls at this level)`);
      continue;
    }
    const statusIcon = catResult.failed === 0 ? '[+]' : (catResult.passed > 0 ? '[~]' : '[-]');
    console.log(`  ${statusIcon} ${catResult.category}: ${catResult.passed}/${total} (${catResult.compliance}%)`);

    // Show failed controls
    if (verbose || catResult.failed > 0) {
      for (const ctrl of catResult.controls) {
        if (ctrl.status === 'failed') {
          console.log(`     [-] ${ctrl.controlId}: ${ctrl.name}`);
          if (verbose) {
            for (const finding of ctrl.findings) {
              console.log(`        └─ ${finding}`);
            }
          }
        } else if (verbose && ctrl.status === 'passed') {
          console.log(`     [+] ${ctrl.controlId}: ${ctrl.name}`);
        } else if (verbose && ctrl.status === 'unverified') {
          // Look up the original control to determine why it's unverified
          const originalControl = OASB_1_CATEGORIES
            .flatMap((c: BenchmarkCategory) => c.controls)
            .find((c: BenchmarkControl) => c.id === ctrl.controlId);
          const reason = originalControl && (originalControl.verification === 'manual' || originalControl.verification === 'forward')
            ? 'manual/forward'
            : 'no scanner data';
          console.log(`     [?] ${ctrl.controlId}: ${ctrl.name} (${reason})`);
        }
      }
    }
  }

  console.log();
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);

  // Compliance breakdown by level
  if (verbose) {
    console.log(`\nCompliance by level: L1=${result.l1Compliance}% L2=${result.l2Compliance}% L3=${result.l3Compliance}%`);
    console.log(`Legend: [?] = Manual/Forward verification required`);
  }

  // Show appropriate next step based on current level
  if (result.level === 'L1') {
    console.log(`\nRun '${CLI_PREFIX} secure -b oasb-1 -l L2' for stricter checks.`);
  } else if (result.level === 'L2') {
    console.log(`\nRun '${CLI_PREFIX} secure -b oasb-1 -l L3' for hardened requirements.`);
  } else {
    console.log(`\nThis is the highest maturity level (L3 - Hardened).`);
  }
  console.log(`Spec: https://oasb.ai/oasb-1\n`);
}

// Package name resolution for community registry reporting
function resolvePackageName(targetDir: string): string | null {
  try {
    const fs = require('fs');
    const path = require('path');
    const pkgJsonPath = path.join(targetDir, 'package.json');
    if (fs.existsSync(pkgJsonPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
      if (pkg.name) return pkg.name;
    }
  } catch { /* ignore */ }
  // Fallback: use directory name, resolving "." to the actual directory name
  const path = require('path');
  const resolved = path.resolve(targetDir);
  const name = path.basename(resolved);
  // Skip names that are clearly not package names
  return name && name !== '.' && name !== '..' ? name : null;
}

function resolvePackageVersion(targetDir: string): string | null {
  try {
    const fs = require('fs');
    const path = require('path');
    const pkgJsonPath = path.join(targetDir, 'package.json');
    if (fs.existsSync(pkgJsonPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
      if (pkg.version) return pkg.version;
    }
  } catch { /* ignore */ }
  return null;
}

/**
 * Resolve package name from pyproject.toml (Python projects).
 */
function resolvePackageNamePyproject(targetDir: string): string | null {
  try {
    const fs = require('fs');
    const path = require('path');
    const pyprojectPath = path.join(targetDir, 'pyproject.toml');
    if (fs.existsSync(pyprojectPath)) {
      const content = fs.readFileSync(pyprojectPath, 'utf-8');
      // Match [project] section's name field
      const nameMatch = content.match(/\[project\][\s\S]*?name\s*=\s*"([^"]+)"/);
      if (nameMatch) return nameMatch[1];
      // Also try [tool.poetry] section
      const poetryMatch = content.match(/\[tool\.poetry\][\s\S]*?name\s*=\s*"([^"]+)"/);
      if (poetryMatch) return poetryMatch[1];
    }
  } catch { /* ignore */ }
  return null;
}

/**
 * Resolve package version from pyproject.toml (Python projects).
 */
function resolvePackageVersionPyproject(targetDir: string): string | null {
  try {
    const fs = require('fs');
    const path = require('path');
    const pyprojectPath = path.join(targetDir, 'pyproject.toml');
    if (fs.existsSync(pyprojectPath)) {
      const content = fs.readFileSync(pyprojectPath, 'utf-8');
      const versionMatch = content.match(/\[project\][\s\S]*?version\s*=\s*"([^"]+)"/);
      if (versionMatch) return versionMatch[1];
      const poetryMatch = content.match(/\[tool\.poetry\][\s\S]*?version\s*=\s*"([^"]+)"/);
      if (poetryMatch) return poetryMatch[1];
    }
  } catch { /* ignore */ }
  return null;
}

/**
 * Resolve the repository URL from the git remote 'origin'.
 */
function resolveRepoUrl(targetDir: string): string | null {
  try {
    const { execSync } = require('child_process');
    const url = execSync('git remote get-url origin', {
      cwd: targetDir,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
    return url || null;
  } catch { /* ignore */ }
  return null;
}

/**
 * Handle community contribution after a scan completes.
 *
 * Determines whether to contribute based on:
 *   1. --contribute / --no-contribute CLI flags (highest priority)
 *   2. ~/.opena2a/config.json contribute.enabled setting
 *
 * If contributing, queues an anonymized event to ~/.opena2a/contribute-queue.json
 * (compatible with @opena2a/contribute format) and flushes when threshold reached.
 *
 * Also records the scan and shows a delayed consent tip after the 3rd scan
 * if the user hasn't opted in or dismissed.
 */
async function handleContribution(
  contributeFlag: boolean | undefined,
  targetDir: string,
  findings: SecurityFinding[],
  durationMs: number,
  registryUrl?: string,
  format?: string,
): Promise<void> {
  try {
    const {
      isContributeEnabled,
      recordScanAndMaybeShowTip,
      buildScanEvent,
      queueAndMaybeFlush,
    } = await import('./telemetry');

    // Record scan count and maybe show the delayed consent tip
    const tip = recordScanAndMaybeShowTip();
    if (tip && format === 'text' && process.stdout.isTTY) {
      process.stdout.write(tip + '\n');
    }

    // Determine whether to contribute
    let shouldContribute: boolean;

    if (contributeFlag === true) {
      // --contribute flag: always contribute this scan
      shouldContribute = true;
    } else if (contributeFlag === false) {
      // --no-contribute flag: skip this scan
      shouldContribute = false;
    } else {
      // Check config
      shouldContribute = isContributeEnabled() === true;
    }

    if (!shouldContribute) return;

    // Build and queue contribution event (non-blocking, flushes at threshold)
    const packageName = resolvePackageName(targetDir);
    if (!packageName) return;

    const event = buildScanEvent(packageName, targetDir, findings, durationMs);
    await queueAndMaybeFlush(event, registryUrl, format === 'text');

    if (format === 'text') {
      process.stdout.write('Queued anonymized scan summary for OpenA2A Registry (--no-contribute to opt out)\n');
    }
  } catch {
    // Non-fatal: contribution failure must never crash the scan
  }
}

/**
 * Handle community contribution for scan-soul results.
 *
 * Converts SoulScanResult controls into SecurityFinding-like objects
 * for the contribution module, then delegates to handleContribution.
 */
async function handleSoulContribution(
  contributeFlag: boolean | undefined,
  targetDir: string,
  result: SoulScanResult,
  durationMs: number,
  registryUrl?: string,
  format?: string,
): Promise<void> {
  // Convert soul controls into SecurityFinding-shaped objects
  const findings: SecurityFinding[] = [];
  for (const domain of result.domains) {
    if (domain.skippedByProfile || domain.skippedByTier) continue;
    for (const ctrl of domain.controls) {
      findings.push({
        checkId: ctrl.id,
        name: ctrl.name,
        description: '',
        category: domain.domain,
        severity: 'medium' as Severity,
        passed: ctrl.passed,
        message: '',
        fixable: false,
      });
    }
  }

  await handleContribution(contributeFlag, targetDir, findings, durationMs, registryUrl, format);
}

program
  .command('secure')
  .description(`Scan and harden your agent setup

Performs ${CHECK_COUNT} security checks across 60 categories:
  • Credentials: API key exposure, secrets in configs
  • MCP: Server configs, tool permissions, secrets
  • Network: TLS, interface bindings, CORS
  • Prompt: Injection defenses, role protection
  • Encryption: At-rest encryption, secure hashing
  • And 54 more categories...

Benchmark mode (--benchmark):
  oasb-1   OASB-1 infrastructure compliance (L1/L2/L3 levels)
           L1 = Essential (baseline), L2 = Standard, L3 = Hardened
  oasb-2   OASB-2 composite: infrastructure (50%) + governance (50%)
           Combines OASB-1 scan with scan-soul for a unified score

Output formats (--format):
  text   Human-readable terminal output (default)
  json   Machine-readable JSON
  sarif  GitHub Security tab / IDE integration
  html   Shareable compliance report

Severities: critical, high, medium, low
Exit code 1 if critical/high issues found (or non-compliant in benchmark mode).

Examples:
  $ hackmyagent secure                           Scan current directory
  $ hackmyagent secure ./my-project              Scan specific directory
  $ hackmyagent secure --fix                     Auto-fix issues
  $ hackmyagent secure -b oasb-1                 OASB-1 L1 compliance
  $ hackmyagent secure -b oasb-1 -l L2           OASB-1 L2 compliance
  $ hackmyagent secure -b oasb-1 -f sarif        SARIF for GitHub
  $ hackmyagent secure -b oasb-1 -f html -o report.html
  $ hackmyagent secure -b oasb-1 --fail-below 80 CI threshold
  $ hackmyagent secure -b oasb-2               OASB-2 composite (infra + governance)
  $ hackmyagent secure ./my-agent --publish    Scan and publish results to registry`)
  .argument('[directory]', 'Directory to scan (defaults to current directory)', '.')
  .option('--fix', 'Automatically fix issues where possible')
  .option('--dry-run', 'Preview fixes without applying them (use with --fix)')
  .option('--ignore <checks>', 'Comma-separated check IDs to skip (e.g., CRED-001,GIT-002)')
  .option('--json', 'Output as JSON (deprecated: use --format json)')
  .option('-f, --format <format>', 'Output format: text, json, sarif, html, asff (default: text)', 'text')
  .option('--aws-account-id <id>', 'AWS account ID for ASFF format')
  .option('--aws-region <region>', 'AWS region for ASFF format')
  .option('-o, --output <file>', 'Write output to file instead of stdout')
  .option('--fail-below <percent>', 'Exit 1 if compliance below threshold (0-100)')
  .option('-v, --verbose', 'Show all checks including passed ones')
  .option('-b, --benchmark <name>', 'Run benchmark compliance check (e.g., oasb-1)')
  .option('-l, --level <level>', 'Benchmark level: L1 (Essential), L2 (Standard), L3 (Hardened)', 'L1')
  .option('-c, --category <name>', 'Filter to specific benchmark category')
  .option('--deep', 'Maximum analysis: static + semantic + behavioral simulation + adaptive attacks (~30s per file)')
  .option('--static-only', 'Disable semantic analysis and simulation (static checks only, fast, deterministic)')
  .option('--scan-depth <depth>', 'CAAT scan depth: quick (config+creds only), standard (default), deep (+ simulation)', 'standard')
  .option('--ci-publish', 'Submit scan results to registry CI endpoint (requires CI_SCAN_HMAC_SECRET env)')
  .option('--publish', 'Push scan results to the OpenA2A Registry')
  .option('--registry-report', 'Post results to OpenA2A Registry')
  .option('--no-registry', 'Skip auto-publishing results to OpenA2A Registry')
  .option('--version-id <id>', 'Registry version ID to report against')
  .option('--registry-url <url>', 'Registry URL (default: REGISTRY_URL env)', validateRegistryUrl(process.env.REGISTRY_URL || 'https://api.oa2a.org'))
  .option('--registry-key <key>', 'Registry API key (default: REGISTRY_API_KEY env)')
  .option('--contribute', 'Share anonymized scan findings with OpenA2A Registry (overrides config)')
  .option('--no-contribute', 'Do not share findings for this scan (overrides config)')
  .option('--ci', 'CI mode: suppress interactive prompts, exit non-zero on findings')
  .action(async (directory: string, options: { fix?: boolean; dryRun?: boolean; ignore?: string; json?: boolean; format?: string; output?: string; failBelow?: string; verbose?: boolean; benchmark?: string; level?: string; category?: string; deep?: boolean; scanDepth?: string; ciPublish?: boolean; publish?: boolean; registryReport?: boolean; registry?: boolean; versionId?: string; registryUrl?: string; registryKey?: string; contribute?: boolean; ci?: boolean }) => {
    try {
      const targetDir = require("path").resolve(directory);

      // CI mode: force non-interactive defaults
      if (options.ci) {
        if (!options.format && !options.json) options.format = 'text';
        // In CI, never prompt -- only contribute if explicitly --contribute
        if (options.contribute === undefined) options.contribute = false;
      }

      // Check if directory exists
      if (!require('fs').existsSync(targetDir)) {
        console.error(`Error: Directory '${targetDir}' does not exist.`);
        process.exit(1);
      }

      // Parse ignore list
      const ignoreList = options.ignore
        ? options.ignore.split(',').map((s) => s.trim()).filter(Boolean)
        : [];

      // Validate benchmark flag if provided
      const isOasb2 = options.benchmark?.toLowerCase() === 'oasb-2';
      if (options.benchmark && !isOasb2 && !isValidBenchmark(options.benchmark)) {
        console.error(`Error: Unknown benchmark '${options.benchmark}'. Available: ${[...AVAILABLE_BENCHMARKS, 'oasb-2'].join(', ')}`);
        process.exit(1);
      }

      // Validate level if benchmark mode (not applicable for oasb-2)
      const validLevels = ['L1', 'L2', 'L3'];
      const level = (options.level?.toUpperCase() || 'L1') as BenchmarkLevel;
      if (options.benchmark && !isOasb2 && !validLevels.includes(level)) {
        console.error(`Error: Invalid level '${options.level}'. Use: L1, L2, or L3`);
        process.exit(1);
      }

      // Determine output format (--json is deprecated alias for --format json)
      const validFormats = ['text', 'json', 'sarif', 'html', 'asp', 'asff'];
      const format = options.json ? 'json' : (options.format || 'text');
      if (!validFormats.includes(format)) {
        console.error(`Error: Invalid format '${format}'. Use: ${validFormats.join(', ')}`);
        process.exit(1);
      }

      // Parse fail threshold
      const failBelow = options.failBelow ? parseInt(options.failBelow, 10) : undefined;
      if (failBelow !== undefined && (isNaN(failBelow) || failBelow < 0 || failBelow > 100)) {
        console.error(`Error: --fail-below must be a number between 0 and 100`);
        process.exit(1);
      }

      // Only show progress for text output
      if (format === 'text') {
        if (options.dryRun) {
          console.log(`\nScanning ${targetDir} (dry-run)...\n`);
        } else {
          console.log(`\nScanning ${targetDir}...\n`);
        }
      }

      // Validate scan depth
      const validDepths = ['quick', 'standard', 'deep'];
      const scanDepth = (options.scanDepth || 'standard') as 'quick' | 'standard' | 'deep';
      if (!validDepths.includes(scanDepth)) {
        console.error(`Error: Invalid scan depth '${options.scanDepth}'. Use: ${validDepths.join(', ')}`);
        process.exit(1);
      }

      // Analysis mode: smart defaults, minimal flags
      // Default: static + NanoMind (if daemon available)
      // --deep: everything (static + NanoMind + simulation + adaptive attacks)
      // --static-only: just static checks (CI/deterministic)
      // NanoMind runs by default on every scan (including CI)
      // --static-only is the only way to disable it
      const isStaticOnly = (options as Record<string, unknown>).staticOnly as boolean ?? false;
      const isDeep = options.deep ?? (scanDepth === 'deep');

      // Auto-detect NanoMind daemon (for additional analysis beyond local TME)
      let nanomindAvailable = false;
      if (!isStaticOnly) {
        try {
          const { isDaemonAvailable } = await import('./semantic/nanomind-analyzer.js');
          nanomindAvailable = await isDaemonAvailable();
        } catch { /* daemon not installed */ }
      }

      const onProgress = format === 'text'
        ? (msg: string) => process.stdout.write(msg)
        : undefined;

      // Show analysis mode to user
      if (format === 'text') {
        if (isStaticOnly) {
          // Static only -- no extra output
        } else if (nanomindAvailable && isDeep) {
          console.log(`Analysis: static + semantic + behavioral simulation + adaptive attacks\n`);
        } else if (nanomindAvailable) {
          console.log(`Analysis: static + semantic (ML-enhanced accuracy)\n`);
        } else if (isDeep) {
          console.log(`Analysis: static + behavioral simulation\n`);
        }
        // Default static-only: no message needed, it's the baseline
      }

      if (scanDepth === 'quick' && format === 'text') {
        console.log(`Scan depth: quick (config checks + credential detection only)\n`);
      }

      const scanner = new HardeningScanner();
      const scanStartMs = Date.now();
      const result = await scanner.scan({
        targetDir,
        autoFix: options.fix ?? false,
        dryRun: options.dryRun ?? false,
        ignore: ignoreList,
        deep: isDeep,
        scanDepth,
        cliName: CLI_PREFIX,
        onProgress,
      });
      const scanDurationMs = Date.now() - scanStartMs;

      // NanoMind Semantic Compiler: AST-based analysis runs alongside static checks
      // Defense-in-depth: static findings can NEVER be suppressed, only upgraded
      {
        const { orchestrateNanoMind } = await import('./nanomind-core/orchestrate.js');
        const existingFindings = result.allFindings || result.findings || [];
        const nmResult = await orchestrateNanoMind(targetDir, existingFindings, {
          staticOnly: isStaticOnly,
          ci: options.ci,
          deep: isDeep,
          silent: format !== 'text',
        });

        // Re-apply all filters after NanoMind merge (merge uses allFindings which is unfiltered)
        const refiltered = await scanner.reapplyIgnoreFilters(nmResult.mergedFindings, targetDir);
        if (result.allFindings) {
          result.allFindings = refiltered as typeof result.allFindings;
        }
        if (result.findings) {
          // Re-apply the same gates as the original filter:
          // 1. Only failed checks  2. Has file path  3. Applies to project type
          const projectType = result.projectType || 'library';
          result.findings = refiltered.filter((f: any) =>
            !f.passed && f.file && scanner.findingAppliesTo(f, projectType)
          ) as typeof result.findings;
        }
        // Recalculate score from filtered findings (score was set pre-NanoMind)
        const forScore = (result.findings || []).filter((f: any) => !f.passed && !f.fixed);
        result.score = scanner.calculateScore(forScore).score;
      }

      // Behavioral simulation: auto-runs on --deep, or when NanoMind detects ambiguity
      if (isDeep && format === 'text') {
        try {
          const { SimulationEngine, parseSkillProfile } = await import('./simulation/index.js');
          const { readFileSync, readdirSync, statSync } = await import('node:fs');
          const { join } = await import('node:path');

          // Find skill files in target directory
          const skillFiles: string[] = [];
          const findSkills = (dir: string) => {
            try {
              for (const entry of readdirSync(dir)) {
                const fullPath = join(dir, entry);
                const stat = statSync(fullPath);
                if (stat.isDirectory() && !entry.startsWith('.') && entry !== 'node_modules') {
                  findSkills(fullPath);
                } else if (entry.endsWith('.md') || entry.endsWith('.yaml') || entry.endsWith('.yml')) {
                  skillFiles.push(fullPath);
                }
              }
            } catch { /* skip inaccessible dirs */ }
          };
          findSkills(targetDir);

          if (skillFiles.length === 0) {
            process.stdout.write(`\n[Simulation] No skill/SOUL/MCP artifacts found. Simulation skipped.\n\n`);
          } else {
            process.stdout.write(`\n[Simulation] Running behavioral simulation on ${skillFiles.length} artifact(s)...\n`);
            const sim = new SimulationEngine({ useLLM: nanomindAvailable });

            for (const file of skillFiles.slice(0, 10)) { // Cap at 10 files
              const content = readFileSync(file, 'utf-8');
              const profile = parseSkillProfile(content, file.split('/').pop() ?? 'unknown');
              const simResult = await sim.runLayer3(profile);

              const icon = simResult.verdict === 'CLEAN' ? 'PASS' : simResult.verdict === 'SUSPICIOUS' ? 'WARN' : 'FAIL';
              process.stdout.write(`  [${icon}] ${file.split('/').pop()} — ${simResult.verdict} (${(simResult.confidence * 100).toFixed(0)}% confidence, ${simResult.failedProbes.length}/${simResult.probeCount} probes failed)\n`);

              // Auto-export training data
              const { exportSimulationTraining } = await import('./attack-engine/training-pipeline.js');
              exportSimulationTraining(content, simResult);
            }
            process.stdout.write(`[Simulation] Complete.\n\n`);
          } // end skillFiles.length > 0
        } catch (err) {
          process.stdout.write(`[Simulation] Skipped: ${err instanceof Error ? err.message : 'unknown error'}\n\n`);
        }
      }

      // OASB-2 composite mode: infrastructure (50%) + governance (50%)
      if (isOasb2) {
        const infraResult = generateBenchmarkReport(
          result.allFindings || result.findings,
          level,
          options.category,
        );

        const { SoulScanner } = await import('./soul/index.js');
        const soulScanner = new SoulScanner();
        const govResult = await soulScanner.scanSoul(targetDir);

        const infraScore = infraResult.compliance ?? 0;
        const govScore = govResult.score;
        const compositeScore = Math.round((infraScore + govScore) / 2);

        if (format === 'json') {
          const jsonOutput = JSON.stringify({
            benchmark: 'OASB-2',
            infraScore,
            govScore,
            compositeScore,
            conformance: govResult.conformance,
            infraResult,
            govResult,
          }, null, 2);
          if (options.output) {
            require('fs').writeFileSync(options.output, jsonOutput);
            console.error(`Report written to ${options.output}`);
          } else {
            const fs = require('fs');
            fs.writeFileSync(1, jsonOutput + '\n');
          }
        } else {
          process.stdout.write('\nOASB v2 Composite Security Assessment\n');
          process.stdout.write('----------------------------------------------------\n');
          process.stdout.write(`Infrastructure Score (OASB-1): ${infraScore}%\n`);
          process.stdout.write(`Governance Score (OASB-2):     ${govScore}/100\n`);
          process.stdout.write('----------------------------------------------------\n');
          process.stdout.write(`Composite Score:               ${compositeScore}/100\n`);
          process.stdout.write(`Conformance:                   ${govResult.conformance.toUpperCase()}\n`);
          process.stdout.write('\n');

          // Show infra report then governance report
          printBenchmarkReport(infraResult, options.verbose ?? false);

          process.stdout.write('\nGovernance Domains (scan-soul):\n');
          for (const domain of govResult.domains) {
            const label = (domain.domain + ':').padEnd(26);
            process.stdout.write(`  ${label}${domain.passed}/${domain.total}  (${domain.percentage}%)\n`);
          }
          if (govResult.criticalFloor) {
            process.stdout.write(`\nCritical Floor: APPLIED (${govResult.criticalMissing.join(', ')} missing)\n`);
          }
          process.stdout.write('\n');
        }

        if (failBelow !== undefined && compositeScore < failBelow) {
          console.error(`Composite score ${compositeScore} is below threshold ${failBelow}`);
          process.exit(1);
        }
        return;
      }

      // Benchmark mode - output compliance report
      if (options.benchmark) {
        // Use allFindings (unfiltered) for accurate benchmark evaluation
        const benchmarkResult = generateBenchmarkReport(
          result.allFindings || result.findings,
          level,
          options.category
        );

        // Output based on format
        let output: string;
        switch (format) {
          case 'json':
            output = JSON.stringify(benchmarkResult, null, 2);
            break;
          case 'sarif':
            output = generateSarifOutput(benchmarkResult, result.findings, targetDir);
            break;
          case 'html':
            output = generateHtmlReport(benchmarkResult);
            break;
          case 'asp':
            output = generateAspOutput(benchmarkResult, result, targetDir);
            break;
          default: // text
            printBenchmarkReport(benchmarkResult, options.verbose ?? false);
            output = '';
        }

        // Write output (use writeLargeStdout to avoid 64KB pipe truncation)
        if (output) {
          if (options.output) {
            require('fs').writeFileSync(options.output, output);
            console.error(`Report written to ${options.output}`);
          } else {
            writeLargeStdout(output + '\n');
          }
        }

        // Check fail threshold
        if (failBelow !== undefined && benchmarkResult.compliance < failBelow) {
          console.error(`Compliance ${benchmarkResult.compliance}% is below threshold ${failBelow}%`);
          process.exit(1);
        }

        // Exit with non-zero if failing or needs improvement (default behavior)
        if (failBelow === undefined && (benchmarkResult.rating === 'Not Passing' || benchmarkResult.rating === 'Needs Improvement')) {
          process.exit(1);
        }
        return;
      }

      if (format === 'json') {
        // Run publish in JSON mode and include result in output
        let publishStatus: Record<string, unknown> | undefined;
        if (options.publish && options.registry !== false) {
          try {
            const { publishScanResults } = await import('./registry/publish');
            const registryUrl = validateRegistryUrl(options.registryUrl || process.env.REGISTRY_URL || 'https://api.oa2a.org');
            const packageName = resolvePackageName(targetDir);
            if (packageName) {
              const publishData = {
                packageName,
                packageVersion: resolvePackageVersion(targetDir) ?? undefined,
                directory: targetDir,
                hardeningFindings: result.findings,
              };
              const publishResult = await publishScanResults(publishData, registryUrl);
              publishStatus = { ...publishResult, registryUrl };
            } else {
              publishStatus = { success: false, error: 'Could not determine package name' };
            }
          } catch (publishErr: unknown) {
            const msg = publishErr instanceof Error ? publishErr.message : 'unknown error';
            publishStatus = { success: false, error: msg };
          }
        }

        const jsonOutput = publishStatus ? { ...result, publish: publishStatus } : result;
        if (options.output) {
          require('fs').writeFileSync(options.output, JSON.stringify(jsonOutput, null, 2) + '\n');
          console.error(`Report written to ${options.output}`);
        } else {
          writeJsonStdout(jsonOutput);
        }
        // Community contribution (non-blocking, runs in JSON mode too)
        await handleContribution(options.contribute, targetDir, result.findings, scanDurationMs, options.registryUrl, format);
        const critHigh = result.findings.filter((f: SecurityFinding) => !f.passed && !f.fixed && (f.severity === 'critical' || f.severity === 'high'));
        if (critHigh.length > 0) process.exitCode = 1;
        return;
      }

      // Handle SARIF/HTML/ASP for non-benchmark mode
      if (format === 'sarif') {
        const output = generateScanSarif(result.findings, targetDir);
        if (options.output) {
          require('fs').writeFileSync(options.output, output);
          console.error(`Report written to ${options.output}`);
        } else {
          writeLargeStdout(output + '\n');
        }
        const critHigh = result.findings.filter((f: SecurityFinding) => !f.passed && !f.fixed && (f.severity === 'critical' || f.severity === 'high'));
        if (critHigh.length > 0) process.exit(1);
        return;
      }

      if (format === 'html') {
        const output = generateScanHtmlReport(result, targetDir);
        if (options.output) {
          require('fs').writeFileSync(options.output, output);
          console.error(`Report written to ${options.output}`);
        } else {
          console.log(output);
        }
        const critHigh = result.findings.filter((f: SecurityFinding) => !f.passed && !f.fixed && (f.severity === 'critical' || f.severity === 'high'));
        if (critHigh.length > 0) process.exit(1);
        return;
      }

      if (format === 'asff') {
        const { toASSF } = await import('./output/asff.js');
        const output = toASSF(result.findings as any, {
          awsAccountId: (options as any).awsAccountId,
          awsRegion: (options as any).awsRegion,
          targetDir,
        });
        if (options.output) {
          require('fs').writeFileSync(options.output, output);
          console.error(`ASFF report written to ${options.output}`);
          console.error(`Import: aws securityhub batch-import-findings --findings file://${options.output}`);
        } else {
          console.log(output);
        }
        const critHigh = result.findings.filter((f: SecurityFinding) => !f.passed && !f.fixed && (f.severity === 'critical' || f.severity === 'high'));
        if (critHigh.length > 0) process.exit(1);
        return;
      }

      // Filter to only show failed findings (issues)
      const issues = result.findings.filter((f) => !f.passed && !f.fixed);
      const fixedFindings = result.findings.filter((f) => f.fixed);

      // Print header - clean and simple
      const projectTypeLabel = {
        cli: 'CLI Tool',
        library: 'Library',
        webapp: 'Web App',
        api: 'API Server',
        mcp: 'MCP Server',
        openclaw: 'OpenClaw Agent',
        all: 'Project',
      }[result.projectType] || 'Project';

      let scoreExtra = '';
      if (result.semanticAnalysis) {
        const sa = result.semanticAnalysis;
        scoreExtra = ` | ${sa.layer2Findings} deep analysis finding${sa.layer2Findings === 1 ? '' : 's'}`;
        if (sa.layer3Findings > 0) {
          scoreExtra += `, ${sa.layer3Findings} AI-assisted`;
          if (sa.llmCost !== undefined) scoreExtra += ` ($${sa.llmCost.toFixed(3)})`;
          if (sa.cachedResults) scoreExtra += ` (${sa.cachedResults} cached)`;
        }
      }
      console.log(`${projectTypeLabel} | Score: ${result.score}/${result.maxScore}${scoreExtra}`);
      if (issues.length > 0) {
        const recoverable = Math.min(result.maxScore - result.score, result.maxScore);
        console.log(`  Path forward: +${recoverable} recoverable by addressing ${issues.length} issue${issues.length === 1 ? '' : 's'}`);
      }
      console.log('');

      // No issues? Say so and exit
      if (issues.length === 0 && fixedFindings.length === 0) {
        console.log(`${colors.green}No issues found.${RESET()}\n`);
      } else if (issues.length > 0) {
        // Print issues - clean format with fixable count
        const fixableCount = issues.filter((f: SecurityFinding) => f.fixable).length;
        const fixableNote = fixableCount > 0
          ? ` (${fixableCount} auto-fixable with \`${CLI_PREFIX} secure --fix\`)`
          : '';
        console.log(`${issues.length} issue${issues.length === 1 ? '' : 's'} found${fixableNote}:\n`);

        for (const finding of issues) {
          const display = SEVERITY_DISPLAY[finding.severity];
          const location = finding.file
            ? finding.line
              ? `${finding.file}:${finding.line}`
              : finding.file
            : '';

          // Format: SEVERITY  [DRY RUN] Would fix: file:line
          //         Description
          //         Fix: command
          const dryRunPrefix = (finding as any).wouldFix ? `${colors.cyan}[DRY RUN] Would fix: ${RESET()}` : '';
          console.log(`${display.color()}${display.symbol} ${finding.severity.toUpperCase()}${RESET()}  ${dryRunPrefix}${location}`);
          console.log(`       ${finding.description}`);
          if (finding.fix) {
            console.log(`       ${colors.cyan}Fix:${RESET()} ${finding.fix}`);
          }
          if (options.verbose) {
            console.log(`       ${colors.dim}Check: ${finding.checkId} | Category: ${finding.category}${RESET()}`);
            if (finding.file) {
              console.log(`       ${colors.dim}File: ${finding.file}${finding.line ? ` (line ${finding.line})` : ''}${RESET()}`);
            }
            if (finding.message && finding.message !== finding.description) {
              console.log(`       ${colors.dim}Detail: ${finding.message}${RESET()}`);
            }
            if (finding.details && Object.keys(finding.details).length > 0) {
              for (const [key, value] of Object.entries(finding.details)) {
                console.log(`       ${colors.dim}${key}: ${typeof value === 'object' ? JSON.stringify(value) : value}${RESET()}`);
              }
            }
          }
          console.log();
        }

        // Severity breakdown summary
        const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
        for (const f of issues) {
          severityCounts[f.severity]++;
        }
        const summaryParts: string[] = [];
        if (severityCounts.critical > 0) summaryParts.push(`${colors.brightRed}Critical: ${severityCounts.critical}${RESET()}`);
        if (severityCounts.high > 0) summaryParts.push(`${colors.red}High: ${severityCounts.high}${RESET()}`);
        if (severityCounts.medium > 0) summaryParts.push(`${colors.yellow}Medium: ${severityCounts.medium}${RESET()}`);
        if (severityCounts.low > 0) summaryParts.push(`${colors.green}Low: ${severityCounts.low}${RESET()}`);
        if (summaryParts.length > 0) {
          console.log(`${summaryParts.join(' | ')}\n`);
        }

        // Dry-run summary
        if (result.dryRun) {
          const wouldFixCount = issues.filter((f: any) => f.wouldFix).length;
          if (wouldFixCount > 0) {
            console.log(`${colors.cyan}Dry run complete:${RESET()} ${wouldFixCount} issue${wouldFixCount === 1 ? '' : 's'} auto-fixable. Run without --dry-run to apply.`);
          }
          console.log(`  No changes were made.\n`);
        }
      }

      // Print fixed findings with detailed summary
      if (fixedFindings.length > 0) {
        const verifiedCount = fixedFindings.filter((f: SecurityFinding) => (f as any).fixVerified).length;
        const unverifiedCount = fixedFindings.filter((f: SecurityFinding) => (f as any).fixVerified === false).length;
        console.log(`${colors.green}Fixed ${fixedFindings.length} issue${fixedFindings.length === 1 ? '' : 's'}${verifiedCount > 0 ? ` (${verifiedCount} verified)` : ''}:${RESET()}`);
        for (const finding of fixedFindings) {
          const location = finding.file ? (finding.line ? `${finding.file}:${finding.line}` : finding.file) : '';
          const verified = (finding as any).fixVerified;
          const verifyIcon = verified === true ? `${colors.green}✓✓${RESET()}` : verified === false ? `${colors.yellow}✓?${RESET()}` : `${colors.green}✓${RESET()}`;
          console.log(`  ${verifyIcon} [${finding.checkId}] ${location} - ${finding.name}`);
          if (finding.fixMessage) {
            console.log(`    ${colors.cyan}→${RESET()} ${finding.fixMessage}`);
          }
        }
        if (unverifiedCount > 0) {
          console.log(`\n  ${colors.yellow}${unverifiedCount} fix${unverifiedCount === 1 ? '' : 'es'} could not be verified. Review these manually.${RESET()}`);
        }
        console.log();

        // Remaining issues with fix guidance (not yet auto-fixed)
        const remainingWithFix = issues.filter((f: SecurityFinding) => !f.fixed && (f.fix || f.fixable));
        if (remainingWithFix.length > 0) {
          console.log(`${remainingWithFix.length} remaining issue${remainingWithFix.length === 1 ? '' : 's'} ${remainingWithFix.length === 1 ? 'has' : 'have'} fix guidance. Run \`${CLI_PREFIX} fix-all\` to apply all available fixes.\n`);
        }

        if (result.backupPath) {
          console.log(`${colors.yellow}Backup created:${RESET()} ${result.backupPath}`);
          console.log(`${colors.yellow}Something wrong?${RESET()} Run \`${CLI_PREFIX} rollback ${directory}\` to undo all changes.\n`);
        }
      }

      // Registry reporting: only when explicitly requested via --version-id (CI) or --registry-report
      // Community contributions are handled by the opena2a CLI wrapper, not HMA directly
      if (options.versionId || options.registryReport) {
        try {
          const core = await import('./index');
          const registryUrl = validateRegistryUrl(options.registryUrl || process.env.REGISTRY_URL || 'https://api.oa2a.org');

          if (options.versionId) {
            // Authenticated path: existing behavior (version-id + API key)
            const registryKey = options.registryKey || process.env.REGISTRY_API_KEY;
            if (!registryKey) {
              console.error('Error: --registry-key or REGISTRY_API_KEY env is required when using --version-id');
              process.exit(1);
            }
            const client = new core.RegistryClient({ registryUrl, apiKey: registryKey });
            const payload = core.buildScanReport(options.versionId, result.findings);
            await client.reportScanResult(payload);
            console.log(`Registry: scan results reported for version ${options.versionId}`);
          } else if (typeof core.buildCommunityReport === 'function') {
            // Community path: request scan token, then submit results
            const client = new core.RegistryClient({ registryUrl, apiKey: '' });
            const packageName = resolvePackageName(targetDir);
            if (packageName) {
              const packageVersion = resolvePackageVersion(targetDir);
              const tokenResp = typeof client.requestScanToken === 'function'
                ? await client.requestScanToken(packageName, { version: packageVersion ?? undefined })
                : null;
              const payload = core.buildCommunityReport(packageName, result.findings, {
                version: packageVersion ?? undefined,
              });
              const resp = typeof client.reportCommunityResult === 'function'
                ? await client.reportCommunityResult(payload, tokenResp?.scanToken)
                : { status: 'skipped' };
              if (resp.status === 'accepted') {
                console.log('Registry: scan shared with OpenA2A community');
              }
            }
          }
        } catch (_reportErr: any) {
          // Silently ignore registry errors - they are not relevant to local scan results
        }
      }

      // Publish: push results to registry when --publish is used
      if (options.publish && options.registry === false) {
        if (format === 'text') {
          console.log('\nPublish skipped: --no-registry flag is active.');
        }
      } else if (options.publish) {
        try {
          const { publishScanResults, formatPublishOutput } = await import('./registry/publish');
          const registryUrl = validateRegistryUrl(options.registryUrl || process.env.REGISTRY_URL || 'https://api.oa2a.org');
          const packageName = resolvePackageName(targetDir);

          if (!packageName) {
            console.error('\nCould not determine package name. Publish requires a package.json with a name field.');
          } else {
            if (format === 'text') {
              console.log('\nPublishing results to registry...\n');
            }

            const publishData = {
              packageName,
              packageVersion: resolvePackageVersion(targetDir) ?? undefined,
              directory: targetDir,
              hardeningFindings: result.findings,
            };

            const publishResult = await publishScanResults(publishData, registryUrl);
            if (format === 'text') {
              console.log(formatPublishOutput(publishResult, publishData, registryUrl));
              console.log();
            } else if (format === 'json') {
              // Append publish result to JSON output in a separate log
              console.error(JSON.stringify({ publish: publishResult }, null, 2));
            }
          }
        } catch (publishErr: unknown) {
          const msg = publishErr instanceof Error ? publishErr.message : 'unknown error';
          console.error(`\nFailed to publish to registry: ${msg}`);
          console.error('Scan results are still available locally.');
        }
      }

      // CI publish: submit results to registry CAAT pipeline endpoint
      if (options.ciPublish) {
        const hmacSecret = process.env.CI_SCAN_HMAC_SECRET;
        if (!hmacSecret) {
          console.error('\nError: --ci-publish requires the CI_SCAN_HMAC_SECRET environment variable.');
          process.exit(1);
        }

        try {
          const { RegistryClient } = await import('./registry/client');
          const { computeTreeHash } = await import('./registry/publish');
          const registryUrl = validateRegistryUrl(options.registryUrl || process.env.REGISTRY_URL || 'https://api.oa2a.org');
          const packageName = resolvePackageName(targetDir) || resolvePackageNamePyproject(targetDir);
          const packageVersion = resolvePackageVersion(targetDir) || resolvePackageVersionPyproject(targetDir);
          const repoUrl = resolveRepoUrl(targetDir);

          if (!packageName) {
            console.error('\nCould not determine package name from package.json or pyproject.toml.');
          } else if (!repoUrl) {
            console.error('\nCould not determine repo URL from git remote. Ensure a git remote is configured.');
          } else {
            // Compute CAAT tree hash
            let contentHash = '';
            try {
              contentHash = computeTreeHash(targetDir);
            } catch {
              console.error('Warning: Could not compute tree hash. Using empty hash.');
            }

            // Count severity
            const failed = result.findings.filter((f: SecurityFinding) => !f.passed && !f.fixed);
            const counts = { critical: 0, high: 0, medium: 0, low: 0 };
            for (const f of failed) {
              if (f.severity === 'critical') counts.critical++;
              else if (f.severity === 'high') counts.high++;
              else if (f.severity === 'medium') counts.medium++;
              else if (f.severity === 'low') counts.low++;
            }

            const status = (counts.critical > 0 || counts.high > 0) ? 'failed'
              : (counts.medium > 0 || counts.low > 0) ? 'warnings' : 'passed';

            const client = new RegistryClient({ registryUrl, apiKey: '' });
            const scanId = `hma-ci-${Date.now()}`;

            // Get scanner version from package.json
            let scannerVersion = 'unknown';
            try {
              const hmaPackagePath = require('path').resolve(__dirname, '../package.json');
              scannerVersion = require(hmaPackagePath).version || 'unknown';
            } catch { /* ignore */ }

            const ciResult = await client.submitCIScanResult({
              packageName,
              packageType: undefined,
              version: packageVersion ?? undefined,
              repoUrl,
              scanId,
              status,
              criticalCount: counts.critical,
              highCount: counts.high,
              mediumCount: counts.medium,
              lowCount: counts.low,
              contentHash,
              scannerVersion,
              hmacSecret,
              rawReport: {
                generator: 'hackmyagent',
                totalFindings: result.findings.length,
                failedFindings: failed.length,
                scanDepth,
              },
            });

            if (format === 'text') {
              console.log(`\nCI scan result submitted to registry.`);
              console.log(`  Scan ID: ${scanId}`);
              console.log(`  Valid: ${ciResult.valid}`);
              console.log(`  Trust impact: ${ciResult.trustImpact}\n`);
            } else if (format === 'json') {
              console.error(JSON.stringify({ ciPublish: { scanId, ...ciResult } }, null, 2));
            }
          }
        } catch (ciErr: unknown) {
          const msg = ciErr instanceof Error ? ciErr.message : 'unknown error';
          console.error(`\nFailed to submit CI scan result: ${msg}`);
          console.error('Scan results are still available locally.');
        }
      }

      // Community contribution: share anonymized findings with OpenA2A Registry
      await handleContribution(options.contribute, targetDir, result.findings, scanDurationMs, options.registryUrl, format);

      // Star prompt (interactive TTY only, text format only)
      if (process.stdout.isTTY) {
        console.log(`${colors.cyan}Helpful?${RESET()} Star the project: https://github.com/opena2a-org/opena2a\n`);
      }

      // Exit with non-zero if critical/high issues remain (or any issues in --ci mode)
      if (options.ci && issues.length > 0) {
        process.exit(1);
      }
      const criticalOrHigh = issues.filter(
        (f: SecurityFinding) => f.severity === 'critical' || f.severity === 'high'
      );
      if (criticalOrHigh.length > 0) {
        process.exit(1);
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  });

// Severity display for external scan findings
const FINDING_SEVERITY_DISPLAY: Record<FindingSeverity, { symbol: string; color: () => string }> = {
  critical: { symbol: '[!!]', color: () => colors.brightRed },
  high: { symbol: '[!]', color: () => colors.red },
  medium: { symbol: '[~]', color: () => colors.yellow },
  low: { symbol: '[.]', color: () => colors.green },
};

function groupExternalFindingsBySeverity(
  findings: ExternalFinding[]
): Record<FindingSeverity, ExternalFinding[]> {
  const grouped: Record<FindingSeverity, ExternalFinding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };

  for (const finding of findings) {
    grouped[finding.severity].push(finding);
  }

  return grouped;
}

// OpenClaw-specific check categories
const OPENCLAW_CATEGORIES = ['skill', 'heartbeat', 'gateway', 'config', 'supply'];

function detectOpenClawDirectory(providedDir: string): string {
  const os = require('os');
  const fs = require('fs');
  const path = require('path');

  // If user provided a directory, use it
  if (providedDir && providedDir !== '') {
    return providedDir.startsWith('/') ? providedDir : path.join(process.cwd(), providedDir);
  }

  // Auto-detect common OpenClaw/Moltbot installation directories
  const homeDir = os.homedir();
  const candidates = [
    path.join(homeDir, '.openclaw'),
    path.join(homeDir, '.moltbot'),
    path.join(homeDir, '.clawdbot'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  // Fall back to current working directory
  return process.cwd();
}

function filterOpenClawFindings(findings: SecurityFinding[]): SecurityFinding[] {
  return findings.filter((f) => {
    const checkId = f.checkId.toLowerCase();
    return OPENCLAW_CATEGORIES.some((cat) => checkId.includes(cat));
  });
}

function assessRiskLevel(findings: SecurityFinding[]): { level: string; color: string; description: string } {
  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;
  const mediumCount = findings.filter((f) => f.severity === 'medium').length;

  if (criticalCount > 0) {
    return {
      level: 'Critical',
      color: colors.brightRed,
      description: `${criticalCount} critical finding(s) with recommended fixes available.`,
    };
  }
  if (highCount > 0) {
    return {
      level: 'High',
      color: colors.red,
      description: `${highCount} high-severity finding(s) detected. Fixes available below.`,
    };
  }
  if (mediumCount > 0) {
    return {
      level: 'Moderate',
      color: colors.yellow,
      description: 'Some findings detected. Review the recommendations below.',
    };
  }
  if (findings.length === 0) {
    return {
      level: 'None',
      color: colors.dim,
      description: `No OpenClaw configuration detected. Run \`${CLI_PREFIX} secure\` for a full scan.`,
    };
  }
  return {
    level: 'Low',
    color: colors.green,
    description: 'No critical or high findings detected.',
  };
}

program
  .command('secure-openclaw')
  .description(`Security scan specifically for OpenClaw/Moltbot installations

Performs focused security checks for OpenClaw agent deployments:
  • Skill validation: Permission scopes, signature verification
  • Heartbeat security: Endpoint exposure, authentication
  • Gateway configs: Routing rules, rate limiting
  • Config files: Secret exposure, insecure defaults
  • Supply chain: Dependency vulnerabilities, integrity

Auto-detects ~/.openclaw, ~/.moltbot, or ~/.clawdbot directories.
Exit code 1 if critical/high issues found.

Examples:
  $ hackmyagent secure-openclaw                  Scan auto-detected directory
  $ hackmyagent secure-openclaw ~/.openclaw      Scan specific directory
  $ hackmyagent secure-openclaw --fix            Auto-fix issues
  $ hackmyagent secure-openclaw --json           JSON output for CI`)
  .argument('[directory]', 'Directory to scan (default: ~/.openclaw or ~/.moltbot)', '')
  .option('--fix', 'Automatically fix issues where possible')
  .option('--dry-run', 'Preview fixes without applying them (use with --fix)')
  .option('--json', 'Output as JSON (for scripting/CI)')
  .option('-v, --verbose', 'Show all checks including passed ones')
  .action(async (directory: string, options: { fix?: boolean; dryRun?: boolean; json?: boolean; verbose?: boolean }) => {
    try {
      const targetDir = detectOpenClawDirectory(directory);

      if (!options.json) {
        console.log(`\nOpenClaw Security Report`);
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
        if (options.dryRun) {
          console.log(`Scanning ${targetDir} (dry-run - previewing fixes)...\n`);
        } else if (options.fix) {
          console.log(`Scanning and fixing ${targetDir}...\n`);
          console.log(`${colors.yellow}Auto-fix will:${RESET()}`);
          console.log(`  • Bind gateway to 127.0.0.1 (local-only)`);
          console.log(`  • Replace plaintext tokens with env var references`);
          console.log(`  • Enable approval confirmations`);
          console.log(`  • Enable sandbox mode`);
          console.log(`\n${colors.cyan}A backup will be created for rollback if needed.${RESET()}\n`);
        } else {
          console.log(`Scanning ${targetDir}...\n`);
        }
      }

      const scanner = new HardeningScanner();
      const result = await scanner.scan({
        targetDir,
        autoFix: options.fix ?? false,
        dryRun: options.dryRun ?? false,
        ignore: [],
        cliName: CLI_PREFIX,
      });

      // NanoMind semantic analysis (defense-in-depth)
      try {
        const { orchestrateNanoMind } = await import('./nanomind-core/orchestrate.js');
        const nmResult = await orchestrateNanoMind(targetDir, result.findings, { silent: !!options.json });
        // Re-apply .hmaignore filters and recalculate score after NanoMind merge
        const hRefiltered = await scanner.reapplyIgnoreFilters(nmResult.mergedFindings, targetDir);
        result.findings = hRefiltered as typeof result.findings;
        const hForScore = hRefiltered.filter((f: any) => !f.passed && !f.fixed);
        result.score = scanner.calculateScore(hForScore).score;
      } catch { /* NanoMind unavailable */ }

      // Filter to OpenClaw-specific findings
      const allOpenClawFindings = filterOpenClawFindings(result.findings);
      const issues = allOpenClawFindings.filter((f) => !f.passed && !f.fixed);
      const fixedFindings = allOpenClawFindings.filter((f) => f.fixed);
      const passedFindings = allOpenClawFindings.filter((f) => f.passed);

      if (options.json) {
        const jsonOutput = {
          target: targetDir,
          riskLevel: assessRiskLevel(issues).level,
          totalChecks: allOpenClawFindings.length,
          issues: issues.length,
          fixed: fixedFindings.length,
          passed: passedFindings.length,
          findings: allOpenClawFindings,
        };
        writeJsonStdout(jsonOutput);
        return;
      }

      // Risk assessment
      const risk = assessRiskLevel(issues);
      console.log(`Risk Level: ${risk.color}${risk.level}${RESET()}`);
      console.log(`${risk.description}\n`);

      // Summary stats
      console.log(`Checks: ${allOpenClawFindings.length} total | ${issues.length} issues | ${fixedFindings.length} fixed | ${passedFindings.length} passed\n`);

      // Show issues
      if (issues.length > 0) {
        console.log(`${colors.red}Findings:${RESET()}\n`);

        for (const finding of issues) {
          const display = SEVERITY_DISPLAY[finding.severity];
          const location = finding.file
            ? finding.line
              ? `${finding.file}:${finding.line}`
              : finding.file
            : '';

          const sevLabel = finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1);
          console.log(`${display.color()}${display.symbol} [${finding.checkId}] ${sevLabel}${RESET()}`);
          console.log(`   ${finding.description}`);
          if (location) {
            console.log(`   File: ${location}`);
          }
          if (finding.fix) {
            console.log(`   ${colors.cyan}Recommended fix:${RESET()} ${finding.fix}`);
          }
          console.log();
        }
      } else {
        console.log(`${colors.green}No OpenClaw-specific issues found.${RESET()}\n`);
      }

      // Show fixed findings
      if (fixedFindings.length > 0) {
        console.log(`${colors.green}Auto-Remediation Applied:${RESET()}\n`);
        for (const finding of fixedFindings) {
          console.log(`  ${colors.green}✓${RESET()} [${finding.checkId}] ${finding.name}`);
          if (finding.fixMessage) {
            console.log(`     ${colors.cyan}→${RESET()} ${finding.fixMessage}`);
          }
        }
        console.log();

        if (result.backupPath) {
          console.log(`${colors.yellow}Backup created:${RESET()} ${result.backupPath}`);
          console.log(`${colors.yellow}To rollback:${RESET()} ${CLI_PREFIX} rollback ${targetDir}`);
          console.log();
          console.log(`${colors.cyan}Note:${RESET()} If you replaced tokens with env vars, set OPENCLAW_AUTH_TOKEN`);
          console.log(`      in your environment before starting OpenClaw.\n`);
        }
      }

      // Show passed checks in verbose mode
      if (options.verbose && passedFindings.length > 0) {
        console.log(`${colors.green}Passed Checks:${RESET()}`);
        for (const finding of passedFindings) {
          console.log(`  ${colors.green}✓${RESET()} [${finding.checkId}] ${finding.name}`);
        }
        console.log();
      }

      console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
      console.log(`Run '${CLI_PREFIX} secure' for a full security scan.\n`);

      // Exit with non-zero if critical/high issues remain
      const criticalOrHigh = issues.filter(
        (f: SecurityFinding) => f.severity === 'critical' || f.severity === 'high'
      );
      if (criticalOrHigh.length > 0) {
        process.exit(1);
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  });



program
  .command('scan')
  .description(`Scan external target for exposed MCP endpoints

Detects externally exposed:
  • MCP SSE/tools endpoints
  • Configuration files (mcp.json, settings)
  • API keys in responses
  • Debug/admin interfaces

Scoring: strong (90-100), good (80-89), moderate (70-79), improving (60-69), needs-attention (<60)
Exit code 1 if critical/high issues found.

Examples:
  $ hackmyagent scan example.com
  $ hackmyagent scan 192.168.1.100 -p 3000,8080
  $ hackmyagent scan example.com --verbose
  $ hackmyagent scan example.com --json`)
  .argument('<target>', 'Target hostname or IP address')
  .option('--json', 'Output as JSON (for scripting/CI)')
  .option('-p, --ports <ports>', 'Comma-separated ports to scan (default: common MCP ports)')
  .option('-t, --timeout <ms>', 'Connection timeout in milliseconds', '5000')
  .option('-v, --verbose', 'Show detailed finding information')
  .action(
    async (
      target: string,
      options: { json?: boolean; ports?: string; timeout?: string; verbose?: boolean }
    ) => {
      try {
        // Detect local path confusion: user probably wants 'secure' not 'scan'
        const fs = require('fs');
        if (fs.existsSync(target) && (target === '.' || target.startsWith('./') || target.startsWith('/') || target.startsWith('..'))) {
          const secureCmd = CLI_PREFIX.includes('scan')
            ? CLI_PREFIX.replace('scan', 'secure')
            : `${CLI_PREFIX} secure`;
          console.error(
            `\n"scan" is for external targets (hostnames/IPs).` +
            `\nTo scan a local project, use:\n` +
            `\n  ${secureCmd} ${target}` +
            `\n`
          );
          process.exit(1);
        }
        const timeoutMs = parseInt(options.timeout ?? '5000', 10);
        const customPorts = options.ports
          ? options.ports.split(',').map((p) => parseInt(p.trim(), 10))
          : undefined;
        const portCount = customPorts?.length ?? 5;

        if (!options.json) {
          console.log(`\nScanning ${target} (${portCount} ports, ${timeoutMs}ms timeout)...\n`);
        }

        const scanner = new ExternalScanner();
        const result = await scanner.scan(target, {
          ports: customPorts,
          timeout: timeoutMs,
        });

        if (options.json) {
          writeJsonStdout(result);
          return;
        }

        // Print header
        const gradeColor =
          result.grade === 'strong' || result.grade === 'good'
            ? colors.green
            : result.grade === 'moderate'
              ? colors.yellow
              : colors.red;
        console.log(`Target: ${result.target}`);
        console.log(`Score: ${gradeColor}${result.score}/100 (${result.grade})${RESET()}`);
        console.log(`Open Ports: ${result.openPorts.length > 0 ? result.openPorts.join(', ') : 'None detected'}`);
        console.log(`Duration: ${result.duration}ms\n`);

        if (result.findings.length === 0) {
          console.log(`${colors.green}[+] No security issues found!${RESET()}\n`);
          return;
        }

        // Group findings by severity
        const grouped = groupExternalFindingsBySeverity(result.findings);

        // Print findings by severity
        for (const severity of ['critical', 'high', 'medium', 'low'] as FindingSeverity[]) {
          const findings = grouped[severity];
          if (findings.length === 0) continue;

          const display = FINDING_SEVERITY_DISPLAY[severity];
          console.log(
            `${display.color()}${display.symbol} ${severity.toUpperCase()} (${findings.length})${RESET()}`
          );

          for (const finding of findings) {
            console.log(`   • [${finding.checkId}] ${finding.title}`);
            if (finding.port) {
              console.log(`     Port: ${finding.port}${finding.path ? `, Path: ${finding.path}` : ''}`);
            }
            if (options.verbose) {
              console.log(`     ${finding.description}`);
              console.log(`     Evidence: ${finding.evidence}`);
              console.log(`     Impact: ${finding.impact}`);
              console.log(`     Fix: ${finding.fix}`);
            }
          }
          console.log();
        }

        // Exit with non-zero if critical/high issues found
        const criticalOrHigh = result.findings.filter(
          (f) => f.severity === 'critical' || f.severity === 'high'
        );
        if (criticalOrHigh.length > 0) {
          process.exit(1);
        }
      } catch (error) {
        console.error(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
        process.exit(1);
      }
    }
  );

program
  .command('rollback')
  .description(`Rollback auto-fix changes to the most recent backup

Restores files to their state before the last --fix operation.
Backups are stored in .hackmyagent-backup/ with timestamps.

Examples:
  $ hackmyagent rollback              Rollback current directory
  $ hackmyagent rollback ./my-project Rollback specific directory`)
  .argument('[directory]', 'Directory to rollback (defaults to current directory)', '.')
  .action(async (directory: string) => {
    try {
      const targetDir = require("path").resolve(directory);

      console.log(`\nRolling back changes in ${targetDir}...\n`);

      const scanner = new HardeningScanner();
      await scanner.rollback(targetDir);

      console.log(`${colors.green}[+] Rollback successful!${RESET()}`);
      console.log('   All auto-fix changes have been reverted.\n');
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  });

// Attack command - adversarial security testing
const ATTACK_CATEGORY_NAMES = Object.keys(ATTACK_CATEGORIES) as AttackCategory[];

program
  .command('attack')
  .description(`Adversarial security testing for AI agents

Red team your AI agent with ${PAYLOAD_STATS.total} attack payloads across ${Object.keys(PAYLOAD_STATS.byCategory).length} categories:
${Object.entries(PAYLOAD_STATS.byCategory).map(([cat, count]) => `  • ${ATTACK_CATEGORIES[cat as AttackCategory].name}: ${count} payloads`).join('\n')}

Intensity levels (controls how many payloads run):
  passive     Observation only (${PAYLOAD_STATS.byIntensity.passive} payloads)
  active      Standard payloads (${PAYLOAD_STATS.byIntensity.passive + PAYLOAD_STATS.byIntensity.active} payloads, default)
  aggressive  All payloads including creative/risky (${PAYLOAD_STATS.total} payloads)

Target types:
  api         OpenAI/Anthropic chat completions (default)
  mcp         MCP JSON-RPC server (tools/call, tools/list)
  a2a         A2A agent messaging endpoint (/a2a/message)
  local       Local simulation (no API calls)

Examples:
  $ hackmyagent attack https://api.example.com/v1/chat
  $ hackmyagent attack https://api.example.com --intensity aggressive
  $ hackmyagent attack https://api.example.com --category prompt-injection
  $ hackmyagent attack --local --system-prompt "You are a helpful assistant"
  $ hackmyagent attack https://api.example.com -f sarif -o results.sarif
  $ hackmyagent attack https://api.example.com --payload-file custom.json
  $ hackmyagent attack https://api.example.com --fail-on-vulnerable medium
  $ hackmyagent attack http://localhost:3010 --target-type mcp --category mcp-exploitation
  $ hackmyagent attack http://localhost:3020 --target-type a2a --category a2a-attack
  $ hackmyagent attack https://api.example.com --publish  Attack and publish results to registry`)
  .argument('[target]', 'API endpoint to test (or use --local for simulation)')
  .option('-i, --intensity <level>', 'Attack intensity: passive, active, aggressive', 'active')
  .option('-c, --category <categories>', 'Comma-separated categories to test')
  .option('--local', 'Run in local simulation mode (no actual API calls)')
  .option('-t, --target-type <type>', 'Target type: api, mcp, a2a, local', 'api')
  .option('--api-format <format>', 'API format: openai, anthropic, mcp-jsonrpc, a2a, custom', 'openai')
  .option('--model <model>', 'Model to test (for API targets)')
  .option('--system-prompt <prompt>', 'System prompt (for local testing)')
  .option('--mcp-tool <tool>', 'Default MCP tool name (for mcp targets)')
  .option('--a2a-sender <name>', 'A2A sender identity (for a2a targets)', 'attacker-agent')
  .option('--a2a-recipient <name>', 'A2A recipient identity (for a2a targets)', 'target-agent')
  .option('-H, --header <headers>', 'Headers in format "Key: Value" (can be used multiple times)')
  .option('--timeout <ms>', 'Request timeout in milliseconds', '30000')
  .option('--delay <ms>', 'Delay between requests in milliseconds', '1000')
  .option('--stop-on-success', 'Stop after first successful attack')
  .option('--payload-file <path>', 'JSON file with custom attack payloads')
  .option('--fail-on-vulnerable [severity]', 'Exit code 1 if vulnerabilities found (optional: critical/high/medium/low)')
  .option('--json', 'Output as JSON (shorthand for --format json)')
  .option('-f, --format <format>', 'Output format: text, json, sarif, html', 'text')
  .option('-o, --output <file>', 'Write output to file')
  .option('-v, --verbose', 'Show detailed output for each payload')
  .option('--publish', 'Push scan results to the OpenA2A Registry')
  .option('--registry-report', 'Post results to OpenA2A Registry')
  .option('--no-registry', 'Skip auto-publishing results to OpenA2A Registry')
  .option('--version-id <id>', 'Registry version ID to report against')
  .option('--registry-url <url>', 'Registry URL (default: REGISTRY_URL env)', validateRegistryUrl(process.env.REGISTRY_URL || 'https://api.oa2a.org'))
  .option('--registry-key <key>', 'Registry API key (default: REGISTRY_API_KEY env)')
  .action(async (targetUrl: string | undefined, options: {
    intensity?: string;
    category?: string;
    local?: boolean;
    targetType?: string;
    apiFormat?: string;
    model?: string;
    systemPrompt?: string;
    mcpTool?: string;
    a2aSender?: string;
    a2aRecipient?: string;
    header?: string | string[];
    timeout?: string;
    delay?: string;
    stopOnSuccess?: boolean;
    payloadFile?: string;
    failOnVulnerable?: string | boolean;
    format?: string;
    output?: string;
    verbose?: boolean;
    publish?: boolean;
    registryReport?: boolean;
    registry?: boolean;
    versionId?: string;
    registryUrl?: string;
    registryKey?: string;
    json?: boolean;
  }) => {
    try {
      // Validate target
      if (!targetUrl && !options.local) {
        console.error('Error: Target URL required (or use --local for simulation)');
        process.exit(1);
      }

      // Validate intensity
      const validIntensities = ['passive', 'active', 'aggressive'];
      const intensity = (options.intensity || 'active') as AttackIntensity;
      if (!validIntensities.includes(intensity)) {
        console.error(`Error: Invalid intensity '${options.intensity}'. Use: ${validIntensities.join(', ')}`);
        process.exit(1);
      }

      // Parse categories
      let categories: AttackCategory[] | undefined;
      if (options.category) {
        categories = options.category.split(',').map(c => c.trim()) as AttackCategory[];
        for (const cat of categories) {
          if (!ATTACK_CATEGORY_NAMES.includes(cat)) {
            console.error(`Error: Invalid category '${cat}'. Use: ${ATTACK_CATEGORY_NAMES.join(', ')}`);
            process.exit(1);
          }
        }
      }

      // Parse headers
      const headers: Record<string, string> = {};
      if (options.header) {
        const headerList = Array.isArray(options.header) ? options.header : [options.header];
        for (const h of headerList) {
          const [key, ...valueParts] = h.split(':');
          if (key && valueParts.length > 0) {
            headers[key.trim()] = valueParts.join(':').trim();
          }
        }
      }

      // Determine target type
      let targetType: 'api' | 'mcp' | 'a2a' | 'local' = 'api';
      if (options.local) {
        targetType = 'local';
      } else if (options.targetType) {
        const validTypes = ['api', 'mcp', 'a2a', 'local'];
        if (!validTypes.includes(options.targetType)) {
          console.error(`Error: Invalid target type '${options.targetType}'. Use: ${validTypes.join(', ')}`);
          process.exit(1);
        }
        targetType = options.targetType as 'api' | 'mcp' | 'a2a' | 'local';
      }

      // Auto-detect api format from target type if not explicitly set
      let apiFormat = options.apiFormat || 'openai';
      if (targetType === 'mcp' && apiFormat === 'openai') {
        apiFormat = 'mcp-jsonrpc';
      } else if (targetType === 'a2a' && apiFormat === 'openai') {
        apiFormat = 'a2a';
      }

      // Build target
      // When --local is used, treat the argument as a directory path, not a URL
      let localPath: string | undefined;
      if (targetType === 'local' && targetUrl) {
        const path = require('path');
        const fs = require('fs');
        const resolved = path.resolve(targetUrl);
        if (fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
          localPath = resolved;
        }
      }

      const target: AttackTarget = {
        url: localPath ? '' : (targetUrl || ''),
        type: targetType,
        localPath,
        headers: Object.keys(headers).length > 0 ? headers : undefined,
        apiFormat: apiFormat as 'openai' | 'anthropic' | 'mcp-jsonrpc' | 'a2a' | 'custom',
        model: options.model,
        systemPrompt: options.systemPrompt,
        mcpTool: options.mcpTool,
        a2aSender: options.a2aSender,
        a2aRecipient: options.a2aRecipient,
      };

      // Validate format (--json is shorthand for --format json)
      const validFormats = ['text', 'json', 'sarif', 'html'];
      const format = options.json ? 'json' : (options.format || 'text');
      if (!validFormats.includes(format)) {
        console.error(`Error: Invalid format '${format}'. Use: ${validFormats.join(', ')}`);
        process.exit(1);
      }

      // Load custom payloads from file
      let customPayloads: AttackPayload[] | undefined;
      if (options.payloadFile) {
        const filePath = require('path').resolve(options.payloadFile);
        if (!require('fs').existsSync(filePath)) {
          console.error(`Error: Payload file not found: ${filePath}`);
          process.exit(1);
        }
        const fileContent = require('fs').readFileSync(filePath, 'utf-8');
        customPayloads = parseCustomPayloads(fileContent);
      }

      // Show header for text output
      if (format === 'text') {
        console.log(`\nHackMyAgent Attack Mode`);
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
        console.log(`Target: ${target.type === 'local' ? (localPath ? `Local Directory: ${localPath}` : 'Local Simulation') : targetUrl}`);
        console.log(`Intensity: ${intensity}`);
        if (customPayloads) {
          console.log(`Payloads: ${customPayloads.length} custom (from file)`);
        } else {
          console.log(`Categories: ${categories ? categories.join(', ') : 'all'}`);
        }
        console.log();
      }

      // Run attack
      const scanner = new AttackScanner();
      const report = await scanner.scan(target, {
        intensity,
        categories,
        customPayloads,
        timeout: parseInt(options.timeout || '30000', 10),
        delay: parseInt(options.delay || '1000', 10),
        stopOnSuccess: options.stopOnSuccess,
        verbose: options.verbose,
      });

      // Output results
      let output: string;
      switch (format) {
        case 'json':
          output = JSON.stringify(report, null, 2);
          break;
        case 'sarif':
          output = generateAttackSarif(report);
          break;
        case 'html':
          output = generateAttackHtmlReport(report);
          break;
        default: // text
          printAttackReport(report, options.verbose ?? false);
          output = '';
      }

      // Write output (use writeLargeStdout to avoid 64KB pipe truncation)
      if (output) {
        if (options.output) {
          require('fs').writeFileSync(options.output, output);
          console.error(`Report written to ${options.output}`);
        } else {
          writeLargeStdout(output + '\n');
        }
      }

      // Registry reporting: only when explicitly requested via --version-id (CI) or --registry-report
      const shouldReport = targetType !== 'local' && (options.versionId || options.registryReport);
      if (shouldReport) {
        try {
          const core = await import('./index');
          const registryUrl = validateRegistryUrl(options.registryUrl || process.env.REGISTRY_URL || 'https://api.oa2a.org');

          if (options.versionId) {
            // Authenticated path: existing behavior (version-id + API key)
            const registryKey = options.registryKey || process.env.REGISTRY_API_KEY;
            if (!registryKey) {
              console.error('Error: --registry-key or REGISTRY_API_KEY env is required when using --version-id');
              process.exit(1);
            }
            const client = new core.RegistryClient({ registryUrl, apiKey: registryKey });
            const payload = core.buildAttackReport(options.versionId, report);
            await client.reportScanResult(payload);
            console.log(`Registry: attack results reported for version ${options.versionId}`);
          } else if (typeof core.buildCommunityAttackReport === 'function') {
            // Community path: request scan token, then submit results
            const client = new core.RegistryClient({ registryUrl, apiKey: '' });
            const packageName = target.url || targetUrl || 'unknown';
            const tokenResp = typeof client.requestScanToken === 'function'
              ? await client.requestScanToken(packageName)
              : null;
            const payload = core.buildCommunityAttackReport(packageName, report);
            const resp = typeof client.reportCommunityResult === 'function'
              ? await client.reportCommunityResult(payload, tokenResp?.scanToken)
              : { status: 'skipped' };
            if (resp.status === 'accepted') {
              console.log('Registry: attack results shared with OpenA2A community');
            }
          }
        } catch (_reportErr: any) {
          // Silently ignore registry errors - they are not relevant to local scan results
        }
      }

      // Publish: push attack results to registry when --publish is used
      if (options.publish && options.registry === false) {
        if (format === 'text') {
          console.log('\nPublish skipped: --no-registry flag is active.');
        }
      } else if (options.publish && targetType === 'local') {
        if (format === 'text') {
          console.log('\nPublish skipped: only available for live target scans.');
        }
      } else if (options.publish && targetType !== 'local') {
        try {
          const { publishScanResults, formatPublishOutput } = await import('./registry/publish');
          const regUrl = validateRegistryUrl(options.registryUrl || process.env.REGISTRY_URL || 'https://api.oa2a.org');
          const packageName = target.url || targetUrl || 'unknown';

          if (format === 'text') {
            console.log('\nPublishing results to registry...\n');
          }

          const publishData = {
            packageName,
            directory: process.cwd(),
            attackReport: report,
          };

          const publishResult = await publishScanResults(publishData, regUrl);
          if (format === 'text') {
            console.log(formatPublishOutput(publishResult, publishData, regUrl));
            console.log();
          }
        } catch (publishErr: unknown) {
          const msg = publishErr instanceof Error ? publishErr.message : 'unknown error';
          console.error(`\nFailed to publish to registry: ${msg}`);
          console.error('Scan results are still available locally.');
        }
      }

      // Exit with non-zero based on fail policy
      if (shouldFail(report, options.failOnVulnerable as FailPolicy)) {
        process.exit(1);
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  });

// Attack report formatting
function printAttackReport(report: AttackReport, verbose: boolean): void {
  const riskColors: Record<AttackReport['riskRating'], string> = {
    'critical': colors.brightRed,
    'high': colors.red,
    'medium': colors.yellow,
    'low': colors.green,
    'secure': colors.green,
  };

  // Summary
  console.log(`Risk Score: ${riskColors[report.riskRating]}${report.riskScore}/100 (${report.riskRating.toUpperCase()})${RESET()}`);
  console.log(`Duration: ${report.duration}ms`);
  console.log();

  // Attack summary
  console.log(`Attacks: ${report.summary.total} total | ${colors.red}${report.summary.successful} successful${RESET()} | ${colors.green}${report.summary.blocked} blocked${RESET()} | ${report.summary.inconclusive} inconclusive`);
  console.log();

  // Category breakdown
  console.log(`Categories:`);
  for (const [cat, stats] of Object.entries(report.summary.byCategory)) {
    if (stats.total === 0) continue;
    const catInfo = ATTACK_CATEGORIES[cat as AttackCategory];
    const icon = stats.successful > 0 ? '[-]' : '[+]';
    console.log(`  ${icon} ${catInfo.name}: ${stats.successful}/${stats.total} successful`);
  }
  console.log();

  // Successful attacks
  const successful = report.results.filter(r => r.success);
  if (successful.length > 0) {
    console.log(`${colors.red}Successful Attacks:${RESET()}`);
    for (const r of successful) {
      const sevColor = r.payload.severity === 'critical' ? colors.brightRed :
                       r.payload.severity === 'high' ? colors.red :
                       r.payload.severity === 'medium' ? colors.yellow : colors.green;
      console.log(`  ${sevColor}[${r.payload.severity.toUpperCase()}]${RESET()} ${r.payload.id}: ${r.payload.name}`);
      if (verbose) {
        console.log(`       Evidence: ${r.evidence}`);
        console.log(`       Remediation: ${r.payload.remediation}`);
      }
    }
    console.log();
  }

  // Blocked attacks (only in verbose)
  if (verbose) {
    const blocked = report.results.filter(r => r.blocked);
    if (blocked.length > 0) {
      console.log(`${colors.green}Blocked Attacks (${blocked.length}):${RESET()}`);
      for (const r of blocked) {
        console.log(`  [+] ${r.payload.id}: ${r.payload.name}`);
      }
      console.log();
    }
  }

  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  // Inconclusive explanation (when there are inconclusive results)
  if (report.summary.inconclusive > 0) {
    console.log(`Note: ${report.summary.inconclusive} result(s) were inconclusive -- no clear success or block`);
    console.log(`indicators matched the simulated response.`);
    if (report.targetType === 'local') {
      console.log(`Run against a live endpoint (without --local) for active testing with real responses.`);
    }
    console.log();
  }

  if (!verbose) {
    console.log(`\nUse --verbose for detailed attack results.`);
  }
  if (report.intensity !== 'aggressive') {
    console.log(`Use --intensity aggressive for advanced attacks.`);
  }
  console.log();
}

// Generate SARIF output for attack results
function generateAttackSarif(report: AttackReport): string {
  const rules = report.results
    .filter(r => r.success)
    .map(r => ({
      id: r.payload.id,
      name: r.payload.name.replace(/\s+/g, ''),
      shortDescription: { text: r.payload.name },
      fullDescription: { text: r.payload.description },
      help: { text: r.payload.remediation },
      helpUri: `https://oasb.ai/attacks/${r.payload.id}`,
      defaultConfiguration: {
        level: r.payload.severity === 'critical' || r.payload.severity === 'high' ? 'error' as const :
               r.payload.severity === 'medium' ? 'warning' as const : 'note' as const,
      },
      properties: {
        'security-severity': r.payload.severity === 'critical' ? '9.0' :
                            r.payload.severity === 'high' ? '7.0' :
                            r.payload.severity === 'medium' ? '5.0' : '3.0',
        tags: ['security', 'ai-agent', r.payload.category],
      },
    }));

  const results = report.results
    .filter(r => r.success)
    .map(r => ({
      ruleId: r.payload.id,
      level: r.payload.severity === 'critical' || r.payload.severity === 'high' ? 'error' as const :
             r.payload.severity === 'medium' ? 'warning' as const : 'note' as const,
      message: { text: `${r.payload.name}: ${r.evidence}` },
    }));

  return JSON.stringify({
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'HackMyAgent',
          version: VERSION,
          informationUri: 'https://hackmyagent.com',
          rules,
        },
      },
      results,
    }],
  }, null, 2);
}

// Generate HTML report for attack results
function generateAttackHtmlReport(report: AttackReport): string {
  // Risk grade based on score
  const getGrade = (score: number): { letter: string; color: string } => {
    if (score <= 10) return { letter: 'strong', color: '#22c55e' };
    if (score <= 25) return { letter: 'good', color: '#84cc16' };
    if (score <= 50) return { letter: 'moderate', color: '#eab308' };
    if (score <= 70) return { letter: 'improving', color: '#f97316' };
    return { letter: 'needs-attention', color: '#ef4444' };
  };
  const grade = getGrade(report.riskScore);

  const ratingColor: Record<AttackReport['riskRating'], string> = {
    'critical': '#ef4444',
    'high': '#f97316',
    'medium': '#eab308',
    'low': '#22c55e',
    'secure': '#22c55e',
  };

  const ratingBg: Record<AttackReport['riskRating'], string> = {
    'critical': 'rgba(239, 68, 68, 0.15)',
    'high': 'rgba(249, 115, 22, 0.15)',
    'medium': 'rgba(234, 179, 8, 0.15)',
    'low': 'rgba(34, 197, 94, 0.15)',
    'secure': 'rgba(34, 197, 94, 0.15)',
  };

  // SVG icons
  const icons = {
    sword: '<svg class="icon icon-sword" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.5 17.5L3 6V3h3l11.5 11.5"/><path d="M13 19l6-6"/><path d="M16 16l4 4"/><path d="M19 21l2-2"/></svg>',
    shield: '<svg class="icon icon-shield" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-2A11.954 11.954 0 0110 1.944zM11 14a1 1 0 11-2 0 1 1 0 012 0zm0-7a1 1 0 10-2 0v3a1 1 0 102 0V7z" clip-rule="evenodd"/></svg>',
    check: '<svg class="icon icon-check" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>',
    x: '<svg class="icon icon-x" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>',
    warning: '<svg class="icon icon-warning" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>',
    print: '<svg class="icon icon-print" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M5 4v3H4a2 2 0 00-2 2v3a2 2 0 002 2h1v2a2 2 0 002 2h6a2 2 0 002-2v-2h1a2 2 0 002-2V9a2 2 0 00-2-2h-1V4a2 2 0 00-2-2H7a2 2 0 00-2 2zm8 0H7v3h6V4zm0 8H7v4h6v-4z" clip-rule="evenodd"/></svg>',
  };

  // Category abbreviations
  const categoryAbbrev: Record<AttackCategory, string> = {
    'prompt-injection': 'PI',
    'jailbreak': 'JB',
    'data-exfiltration': 'DE',
    'capability-abuse': 'CA',
    'context-manipulation': 'CM',
    'mcp-exploitation': 'MCP',
    'a2a-attack': 'A2A',
    'memory-weaponization': 'MEM',
    'context-window': 'CTX',
    'supply-chain': 'SUP',
    'tool-shadow': 'SHADOW',
    'parser-differential': 'PARSE',
    'persistent-agent': 'PERSIST',
    'fake-tool': 'FAKETOOL',
    'context-lifecycle': 'LIFECYCLE',
    'policy-enforcement-integrity': 'PEI',
  };

  // Donut chart for attack results
  const donutRadius = 60;
  const donutStroke = 12;
  const donutCircumference = 2 * Math.PI * donutRadius;
  const total = report.summary.total || 1;
  const successPct = report.summary.successful / total;
  const blockedPct = report.summary.blocked / total;
  const inconclusivePct = report.summary.inconclusive / total;

  const successDash = donutCircumference * successPct;
  const blockedDash = donutCircumference * blockedPct;
  const inconclusiveDash = donutCircumference * inconclusivePct;

  // Calculate offsets for each segment
  const successOffset = 0;
  const blockedOffset = successDash;
  const inconclusiveOffset = successDash + blockedDash;

  const donutSvg = `
    <svg width="160" height="160" viewBox="0 0 160 160">
      <!-- Background circle -->
      <circle cx="80" cy="80" r="${donutRadius}" fill="none" stroke="#334155" stroke-width="${donutStroke}"/>
      <!-- Inconclusive segment (gray) -->
      ${inconclusivePct > 0 ? `<circle cx="80" cy="80" r="${donutRadius}" fill="none"
        stroke="#64748b" stroke-width="${donutStroke}"
        stroke-dasharray="${inconclusiveDash} ${donutCircumference}"
        stroke-dashoffset="${-inconclusiveOffset}"
        transform="rotate(-90 80 80)"/>` : ''}
      <!-- Blocked segment (green) -->
      ${blockedPct > 0 ? `<circle cx="80" cy="80" r="${donutRadius}" fill="none"
        stroke="#22c55e" stroke-width="${donutStroke}"
        stroke-dasharray="${blockedDash} ${donutCircumference}"
        stroke-dashoffset="${-blockedOffset}"
        transform="rotate(-90 80 80)"/>` : ''}
      <!-- Successful segment (red) -->
      ${successPct > 0 ? `<circle cx="80" cy="80" r="${donutRadius}" fill="none"
        stroke="#ef4444" stroke-width="${donutStroke}"
        stroke-dasharray="${successDash} ${donutCircumference}"
        stroke-dashoffset="${-successOffset}"
        transform="rotate(-90 80 80)"/>` : ''}
      <!-- Center text -->
      <text x="80" y="75" text-anchor="middle" fill="#f1f5f9" font-size="24" font-weight="700">${report.summary.total}</text>
      <text x="80" y="95" text-anchor="middle" fill="#94a3b8" font-size="12">attacks</text>
    </svg>`;

  // Generate category breakdown rows
  const categoryRows = Object.entries(report.summary.byCategory)
    .filter(([_, stats]) => stats.total > 0)
    .map(([cat, stats]) => {
      const catInfo = ATTACK_CATEGORIES[cat as AttackCategory];
      const abbrev = categoryAbbrev[cat as AttackCategory];
      const successRate = stats.total > 0 ? Math.round((stats.successful / stats.total) * 100) : 0;
      const barColor = stats.successful === 0 ? '#22c55e' : successRate > 50 ? '#ef4444' : '#eab308';
      const statusIcon = stats.successful === 0 ? icons.check : icons.x;
      const statusClass = stats.successful === 0 ? 'status-pass' : 'status-fail';

      // Get results for this category
      const catResults = report.results.filter(r => r.payload.category === cat);

      const resultRows = catResults.map(r => {
        const resultIcon = r.success ? icons.x : r.blocked ? icons.check : icons.warning;
        const resultClass = r.success ? 'status-fail' : r.blocked ? 'status-pass' : 'status-warn';
        const sevColor = r.payload.severity === 'critical' ? '#ef4444' :
                        r.payload.severity === 'high' ? '#f97316' :
                        r.payload.severity === 'medium' ? '#eab308' : '#22c55e';
        return `
          <tr class="attack-row ${r.success ? 'failed' : ''}">
            <td class="status-cell"><span class="${resultClass}">${resultIcon}</span></td>
            <td class="id-cell"><code>${r.payload.id}</code></td>
            <td class="name-cell">${escapeHtml(r.payload.name)}</td>
            <td class="severity-cell"><span class="severity-badge" style="color: ${sevColor}; background: ${sevColor}20;">${r.payload.severity.toUpperCase()}</span></td>
            <td class="result-cell">${r.success ? '<span class="result-tag fail">Succeeded</span>' : r.blocked ? '<span class="result-tag pass">Blocked</span>' : '<span class="result-tag warn">Inconclusive</span>'}</td>
          </tr>`;
      }).join('');

      return `
        <div class="category" id="cat-${abbrev}">
          <div class="category-header" onclick="toggleCategory('${abbrev}')">
            <span class="category-abbrev">[${abbrev}]</span>
            <span class="category-icon ${statusClass}">${statusIcon}</span>
            <span class="category-name">${escapeHtml(catInfo.name)}</span>
            <div class="category-meta">
              <span class="category-score">${stats.successful}/${stats.total} successful</span>
              <div class="mini-bar"><div class="mini-fill" style="width: ${successRate}%; background: ${barColor};"></div></div>
              <span class="chevron">▼</span>
            </div>
          </div>
          <div class="category-content">
            <table class="attacks-table">
              <thead><tr><th></th><th>ID</th><th>Attack</th><th>Severity</th><th>Result</th></tr></thead>
              <tbody>${resultRows}</tbody>
            </table>
          </div>
        </div>`;
    }).join('');

  // Successful attacks detail section
  const successfulAttacks = report.results.filter(r => r.success);
  const successfulDetailsHtml = successfulAttacks.length > 0 ? successfulAttacks.map(r => {
    const sevColor = r.payload.severity === 'critical' ? '#ef4444' :
                    r.payload.severity === 'high' ? '#f97316' :
                    r.payload.severity === 'medium' ? '#eab308' : '#22c55e';
    return `
      <div class="attack-detail">
        <div class="attack-detail-header">
          <code class="attack-id">${r.payload.id}</code>
          <span class="attack-name">${escapeHtml(r.payload.name)}</span>
          <span class="severity-badge" style="color: ${sevColor}; background: ${sevColor}20;">${r.payload.severity.toUpperCase()}</span>
        </div>
        <div class="attack-detail-meta">
          ${r.payload.oasbControl ? `<span class="meta-tag">OASB ${r.payload.oasbControl}</span>` : ''}
          ${r.payload.cwe ? `<span class="meta-tag">CWE-${r.payload.cwe}</span>` : ''}
          <span class="meta-tag">${ATTACK_CATEGORIES[r.payload.category].name}</span>
        </div>
        <div class="attack-detail-body">
          <div class="detail-section">
            <strong>Description:</strong> ${escapeHtml(r.payload.description)}
          </div>
          <div class="detail-section evidence">
            <strong>Evidence:</strong> ${escapeHtml(r.evidence)}
          </div>
          <div class="detail-section remediation">
            <strong>Remediation:</strong> ${escapeHtml(r.payload.remediation)}
          </div>
        </div>
      </div>`;
  }).join('') : '<div class="no-attacks">No successful attacks detected.</div>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HackMyAgent Attack Report | ${report.riskRating.toUpperCase()}</title>
  <style>
    :root {
      --bg-primary: #0a0f1a;
      --bg-secondary: #111827;
      --bg-tertiary: #1f2937;
      --text-primary: #f1f5f9;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --border: #334155;
      --accent: #3b82f6;
      --success: #22c55e;
      --warning: #eab308;
      --danger: #ef4444;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      padding: 2rem;
      font-size: 14px;
    }
    .container { max-width: 1400px; margin: 0 auto; }

    /* Header */
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      padding: 1.5rem 2rem;
      background: var(--bg-secondary);
      border-radius: 12px;
      border: 1px solid var(--border);
    }
    .header-left h1 {
      font-size: 1.5rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .header-left .meta { color: var(--text-muted); font-size: 0.8rem; margin-top: 0.25rem; }
    .header-icon { display: inline-flex; margin-right: 0.5rem; }
    .header-icon .icon { width: 24px; height: 24px; color: var(--danger); }
    .header-right { display: flex; align-items: center; gap: 1rem; }
    .rating-badge {
      display: inline-block;
      padding: 0.375rem 1rem;
      border-radius: 6px;
      font-weight: 600;
      font-size: 0.875rem;
      background: ${ratingBg[report.riskRating]};
      color: ${ratingColor[report.riskRating]};
      border: 1px solid ${ratingColor[report.riskRating]}40;
    }
    .intensity-tag {
      display: inline-block;
      padding: 0.375rem 1rem;
      background: var(--accent);
      color: white;
      border-radius: 6px;
      font-size: 0.875rem;
      font-weight: 600;
      text-transform: capitalize;
    }

    /* SVG Icons */
    .icon { width: 16px; height: 16px; display: inline-block; vertical-align: middle; }
    .status-pass { color: var(--success); }
    .status-fail { color: var(--danger); }
    .status-warn { color: var(--warning); }
    .category-icon { display: flex; align-items: center; }
    .category-icon .icon { width: 18px; height: 18px; }
    .footer-btn .icon { width: 14px; height: 14px; margin-right: 0.375rem; }

    /* Dashboard grid */
    .dashboard {
      display: grid;
      grid-template-columns: 280px 200px 1fr;
      gap: 1.5rem;
      margin-bottom: 2rem;
    }
    @media (max-width: 1200px) {
      .dashboard { grid-template-columns: 1fr 1fr; }
      .summary-section { grid-column: span 2; }
    }
    @media (max-width: 768px) {
      .dashboard { grid-template-columns: 1fr; }
      .summary-section { grid-column: span 1; }
    }

    /* Risk Score card */
    .score-card {
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 1.25rem;
      border: 1px solid var(--border);
    }
    .score-header {
      display: flex;
      align-items: center;
      gap: 1rem;
      margin-bottom: 1.25rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border);
    }
    .score-grade {
      width: 72px;
      height: 72px;
      border-radius: 12px;
      border: 2px solid;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .grade-letter { font-size: 0.65rem; font-weight: 800; text-transform: uppercase; text-align: center; line-height: 1.2; }
    .score-main { flex: 1; }
    .score-pct { font-size: 2rem; font-weight: 700; color: var(--text-primary); line-height: 1; }
    .score-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }

    .score-stats { margin-top: 1rem; }
    .stat-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.5rem 0;
      border-bottom: 1px solid var(--border);
    }
    .stat-row:last-child { border-bottom: none; }
    .stat-label { color: var(--text-secondary); font-size: 0.85rem; }
    .stat-value { font-weight: 600; }
    .stat-value.danger { color: var(--danger); }
    .stat-value.success { color: var(--success); }
    .stat-value.muted { color: var(--text-muted); }

    /* Donut chart section */
    .donut-section {
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 1.25rem;
      border: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      align-items: center;
    }
    .donut-section h3 {
      font-size: 0.85rem;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 1rem;
      width: 100%;
    }
    .donut-legend {
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
      margin-top: 1rem;
      width: 100%;
    }
    .legend-item {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.8rem;
      color: var(--text-secondary);
    }
    .legend-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
    }

    /* Summary section */
    .summary-section {
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 1.5rem;
      border: 1px solid var(--border);
    }
    .summary-section h3 {
      font-size: 0.85rem;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 1rem;
    }
    .severity-breakdown {
      display: flex;
      gap: 1rem;
      flex-wrap: wrap;
    }
    .severity-item {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.5rem 1rem;
      background: var(--bg-tertiary);
      border-radius: 6px;
    }
    .severity-count { font-size: 1.25rem; font-weight: 700; }
    .severity-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; }

    /* Categories */
    .categories-section {
      margin-bottom: 2rem;
    }
    .categories-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }
    .categories-header h2 { font-size: 1.1rem; }
    .expand-all {
      background: var(--bg-tertiary);
      border: 1px solid var(--border);
      color: var(--text-secondary);
      padding: 0.5rem 1rem;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.8rem;
    }
    .expand-all:hover { background: var(--border); }

    .category {
      background: var(--bg-secondary);
      border-radius: 8px;
      margin-bottom: 0.75rem;
      border: 1px solid var(--border);
      overflow: hidden;
    }
    .category-header {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 1rem 1.25rem;
      cursor: pointer;
      transition: background 0.15s;
    }
    .category-header:hover { background: var(--bg-tertiary); }
    .category-abbrev {
      font-family: monospace;
      font-size: 0.85rem;
      color: var(--accent);
      font-weight: 600;
    }
    .category-icon { font-size: 1.1rem; }
    .category-name { flex: 1; font-weight: 500; }
    .category-meta { display: flex; align-items: center; gap: 0.75rem; }
    .category-score { color: var(--text-secondary); font-size: 0.85rem; font-weight: 500; }
    .mini-bar { width: 60px; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; }
    .mini-fill { height: 100%; border-radius: 3px; }
    .chevron {
      color: var(--text-muted);
      font-size: 0.7rem;
      transition: transform 0.2s;
      margin-left: 0.5rem;
    }
    .category.collapsed .chevron { transform: rotate(-90deg); }
    .category.collapsed .category-content { display: none; }

    .category-content { border-top: 1px solid var(--border); }
    .attacks-table { width: 100%; border-collapse: collapse; }
    .attacks-table th {
      padding: 0.75rem 1rem;
      text-align: left;
      background: var(--bg-primary);
      color: var(--text-muted);
      font-weight: 500;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .attacks-table td {
      padding: 0.875rem 1rem;
      border-top: 1px solid var(--border);
      vertical-align: middle;
    }
    .status-cell { width: 40px; text-align: center; }
    .id-cell { width: 80px; }
    .id-cell code {
      background: var(--bg-tertiary);
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.8rem;
      color: var(--accent);
    }
    .name-cell { width: 40%; }
    .severity-cell { width: 80px; }
    .result-cell { width: 100px; }
    .attack-row.failed { background: rgba(239, 68, 68, 0.05); }

    .severity-badge {
      padding: 0.2rem 0.6rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
    }
    .result-tag {
      padding: 0.2rem 0.6rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
    }
    .result-tag.pass { background: rgba(34, 197, 94, 0.2); color: var(--success); }
    .result-tag.fail { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
    .result-tag.warn { background: rgba(234, 179, 8, 0.2); color: var(--warning); }

    /* Successful attacks detail */
    .details-section {
      margin-bottom: 2rem;
    }
    .details-section h2 {
      font-size: 1.1rem;
      margin-bottom: 1rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .details-section h2 .icon { color: var(--danger); }
    .attack-detail {
      background: var(--bg-secondary);
      border-radius: 8px;
      margin-bottom: 1rem;
      border: 1px solid var(--border);
      border-left: 3px solid var(--danger);
      overflow: hidden;
    }
    .attack-detail-header {
      display: flex;
      align-items: center;
      gap: 1rem;
      padding: 1rem 1.25rem;
      background: rgba(239, 68, 68, 0.05);
    }
    .attack-id {
      background: var(--bg-tertiary);
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.85rem;
      color: var(--danger);
    }
    .attack-name { flex: 1; font-weight: 500; }
    .attack-detail-meta {
      display: flex;
      gap: 0.5rem;
      padding: 0.75rem 1.25rem;
      background: var(--bg-tertiary);
      border-bottom: 1px solid var(--border);
    }
    .meta-tag {
      padding: 0.2rem 0.5rem;
      background: var(--bg-secondary);
      border-radius: 4px;
      font-size: 0.75rem;
      color: var(--text-muted);
    }
    .attack-detail-body { padding: 1rem 1.25rem; }
    .detail-section {
      margin-bottom: 0.75rem;
      font-size: 0.9rem;
      color: var(--text-secondary);
    }
    .detail-section:last-child { margin-bottom: 0; }
    .detail-section strong { color: var(--text-primary); margin-right: 0.5rem; }
    .detail-section.evidence {
      padding: 0.75rem;
      background: rgba(239, 68, 68, 0.1);
      border-radius: 6px;
      border-left: 3px solid var(--danger);
    }
    .detail-section.remediation {
      padding: 0.75rem;
      background: var(--bg-tertiary);
      border-radius: 6px;
      border-left: 3px solid var(--accent);
    }
    .no-attacks {
      padding: 2rem;
      text-align: center;
      color: var(--success);
      background: var(--bg-secondary);
      border-radius: 8px;
      border: 1px solid var(--border);
    }

    /* Footer */
    .footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 2rem;
      padding: 1.5rem;
      background: var(--bg-secondary);
      border-radius: 12px;
      border: 1px solid var(--border);
      color: var(--text-muted);
      font-size: 0.85rem;
    }
    .footer a { color: var(--accent); text-decoration: none; }
    .footer a:hover { text-decoration: underline; }
    .footer-actions { display: flex; gap: 1rem; }
    .footer-btn {
      display: flex;
      align-items: center;
      padding: 0.5rem 1rem;
      background: var(--bg-tertiary);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text-primary);
      cursor: pointer;
      font-size: 0.8rem;
    }
    .footer-btn:hover { background: var(--border); }

    /* Print styles */
    @media print {
      body { background: white; color: black; padding: 1rem; }
      .container { max-width: 100%; }
      .header, .score-card, .donut-section, .summary-section, .category, .attack-detail, .footer {
        background: white;
        border: 1px solid #ddd;
        break-inside: avoid;
      }
      .category.collapsed .category-content { display: block !important; }
      .chevron, .expand-all, .footer-actions { display: none; }
      .category-header { cursor: default; }
      .attack-row.failed { background: #fff0f0; }
      :root {
        --bg-primary: white;
        --bg-secondary: white;
        --bg-tertiary: #f5f5f5;
        --text-primary: black;
        --text-secondary: #555;
        --text-muted: #888;
        --border: #ddd;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <header class="header">
      <div class="header-left">
        <h1><span class="header-icon">${icons.sword}</span>HackMyAgent Attack Report</h1>
        <div class="meta">Target: ${escapeHtml(report.target || 'Local Simulation')} • ${new Date(report.endTime).toLocaleString()}</div>
      </div>
      <div class="header-right">
        <div class="rating-badge">${report.riskRating.toUpperCase()} RISK</div>
        <div class="intensity-tag">${report.intensity}</div>
      </div>
    </header>

    <div class="dashboard">
      <div class="score-card">
        <div class="score-header">
          <div class="score-grade" style="background: ${grade.color}20; border-color: ${grade.color};">
            <span class="grade-letter" style="color: ${grade.color};">${grade.letter}</span>
          </div>
          <div class="score-main">
            <div class="score-pct">${report.riskScore}/100</div>
            <div class="score-label">Risk Score</div>
          </div>
        </div>
        <div class="score-stats">
          <div class="stat-row">
            <span class="stat-label">Successful Attacks</span>
            <span class="stat-value danger">${report.summary.successful}</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Blocked Attacks</span>
            <span class="stat-value success">${report.summary.blocked}</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Inconclusive</span>
            <span class="stat-value muted">${report.summary.inconclusive}</span>
          </div>
          <div class="stat-row">
            <span class="stat-label">Duration</span>
            <span class="stat-value">${report.duration}ms</span>
          </div>
        </div>
      </div>

      <div class="donut-section">
        <h3>Attack Results</h3>
        ${donutSvg}
        <div class="donut-legend">
          <div class="legend-item"><span class="legend-dot" style="background: #ef4444;"></span> Successful (${report.summary.successful})</div>
          <div class="legend-item"><span class="legend-dot" style="background: #22c55e;"></span> Blocked (${report.summary.blocked})</div>
          <div class="legend-item"><span class="legend-dot" style="background: #64748b;"></span> Inconclusive (${report.summary.inconclusive})</div>
        </div>
      </div>

      <div class="summary-section">
        <h3>Severity Breakdown (Successful Attacks)</h3>
        <div class="severity-breakdown">
          <div class="severity-item">
            <span class="severity-count" style="color: #ef4444;">${report.summary.bySeverity.critical || 0}</span>
            <span class="severity-label">Critical</span>
          </div>
          <div class="severity-item">
            <span class="severity-count" style="color: #f97316;">${report.summary.bySeverity.high || 0}</span>
            <span class="severity-label">High</span>
          </div>
          <div class="severity-item">
            <span class="severity-count" style="color: #eab308;">${report.summary.bySeverity.medium || 0}</span>
            <span class="severity-label">Medium</span>
          </div>
          <div class="severity-item">
            <span class="severity-count" style="color: #22c55e;">${report.summary.bySeverity.low || 0}</span>
            <span class="severity-label">Low</span>
          </div>
        </div>
      </div>
    </div>

    <div class="categories-section">
      <div class="categories-header">
        <h2>Category Breakdown</h2>
        <button class="expand-all" onclick="toggleAll()">Expand/Collapse All</button>
      </div>
      ${categoryRows}
    </div>

    <div class="details-section">
      <h2>${icons.x} Successful Attacks Detail</h2>
      ${successfulDetailsHtml}
    </div>

    <footer class="footer">
      <div>Generated by <a href="https://hackmyagent.com">HackMyAgent</a> v${VERSION} • <a href="https://oasb.ai/attacks">oasb.ai/attacks</a></div>
      <div class="footer-actions">
        <button class="footer-btn" onclick="window.print()">${icons.print} Print Report</button>
      </div>
    </footer>
  </div>

  <script>
    function toggleCategory(id) {
      const cat = document.getElementById('cat-' + id);
      cat.classList.toggle('collapsed');
    }
    function toggleAll() {
      const cats = document.querySelectorAll('.category');
      const allCollapsed = Array.from(cats).every(c => c.classList.contains('collapsed'));
      cats.forEach(c => {
        if (allCollapsed) {
          c.classList.remove('collapsed');
        } else {
          c.classList.add('collapsed');
        }
      });
    }
  </script>
</body>
</html>`;
}

// --- fix-all: Run all OpenClaw plugins to scan and remediate ---

import { createPlugin as createCredVaultPlugin } from './plugins/credvault';
import { createPlugin as createSecretlessPlugin } from './plugins/secretless';
import { createPlugin as createSigncryptPlugin } from './plugins/signcrypt';
import { createPlugin as createSkillguardPlugin } from './plugins/skillguard';
import { AIMCore } from '@opena2a/aim-core';
import type {
  Finding as PluginFinding,
  Remediation,
  OpenA2APlugin,
  Severity as PluginSeverity,
} from './plugins/core';

const PLUGIN_SEVERITY_DISPLAY: Record<PluginSeverity, { symbol: string; color: () => string }> = {
  critical: { symbol: '[!!]', color: () => colors.brightRed },
  high: { symbol: '[!]', color: () => colors.red },
  medium: { symbol: '[~]', color: () => colors.yellow },
  low: { symbol: '[.]', color: () => colors.green },
  info: { symbol: '[i]', color: () => colors.cyan },
};

program
  .command('fix-all')
  .description(`Run all OpenA2A security plugins to scan and auto-fix agent issues

Runs the full plugin suite in order:
  1. Credential Protection     — find hardcoded secrets, replace with env vars
  2. AI Visibility Protection  — block .env from AI tools, encrypt MCP keys
  3. File Signing              — sign skills and heartbeats with Ed25519
  4. Skill Safety Scanner      — detect dangerous patterns, pin hashes

Each plugin scans for findings, then auto-fixes what it can.
Dangerous patterns (reverse shells, exfil, etc.) require manual review.

Step 2 requires secretless-ai (npm install -g secretless-ai). If not
installed, the plugin reports this and continues with the remaining steps.

Use --with-aim to create a cryptographic identity for your agent.
This enables automatic file signing, audit logging, and trust scoring
so you don't need to manage keys or track files manually.

Exit code 1 if critical/high issues remain after fixing.

Examples:
  $ hackmyagent fix-all                     Scan and fix current directory
  $ hackmyagent fix-all ./my-agent          Scan specific directory
  $ hackmyagent fix-all --with-aim          Create identity + sign + audit (recommended)
  $ hackmyagent fix-all --dry-run           Preview fixes without applying
  $ hackmyagent fix-all --scan-only         Scan without fixing
  $ hackmyagent fix-all --json              JSON output for CI`)
  .argument('[directory]', 'Agent directory to scan (default: current directory)', '')
  .option('--dry-run', 'Preview fixes without applying them')
  .option('--scan-only', 'Only scan, do not fix')
  .option('--json', 'Output as JSON (for scripting/CI)')
  .option('--with-aim', 'Create agent identity for automatic signing, audit logging, and trust scoring')
  .option('-v, --verbose', 'Show all findings including passed plugins')
  .action(
    async (
      directory: string,
      options: {
        dryRun?: boolean;
        scanOnly?: boolean;
        json?: boolean;
        withAim?: boolean;
        verbose?: boolean;
      }
    ) => {
      try {
        const path = require('path');
        const fs = require('fs');

        // Resolve target directory with symlink protection
        let targetDir: string;
        if (directory && directory !== '') {
          targetDir = path.isAbsolute(directory) ? directory : path.resolve(process.cwd(), directory);
        } else {
          targetDir = process.cwd();
        }

        // Resolve realpath atomically — eliminates TOCTOU between existence check and resolution
        let realTarget: string;
        try {
          realTarget = fs.realpathSync(targetDir);
        } catch {
          console.error(`Error: Directory not found: ${targetDir}`);
          process.exit(1);
        }

        // Verify resolved path is a directory (realpath already resolved any symlinks)
        const resolvedStat = fs.statSync(realTarget);
        if (!resolvedStat.isDirectory()) {
          console.error(`Error: Not a directory: ${realTarget}`);
          process.exit(1);
        }

        // Block path traversal via .. in relative paths (but allow absolute paths)
        if (!path.isAbsolute(directory) && directory && directory !== '') {
          const realCwd = fs.realpathSync(process.cwd());
          const relative = path.relative(realCwd, realTarget);
          if (relative.startsWith('..')) {
            console.error(`Error: Target directory must not traverse above current working directory. Use an absolute path instead.`);
            process.exit(1);
          }
        }
        targetDir = realTarget;

        // Initialize AIM Core if requested
        let aimCore: AIMCore | undefined;
        if (options.withAim) {
          aimCore = new AIMCore({
            agentName: path.basename(targetDir),
            dataDir: path.join(targetDir, '.opena2a', 'aim'),
          });
        }

        // Create and initialize plugins in execution order
        // 1. CredVault finds hardcoded secrets, replaces with ${VAR}
        // 2. Secretless blocks .env from AI visibility (completes the credential lifecycle)
        // 3. SignCrypt signs skill and heartbeat files
        // 4. SkillGuard pins hashes last so they reflect the final file state
        const pluginFactories: Array<{ name: string; create: () => OpenA2APlugin }> = [
          { name: 'Credential Protection', create: createCredVaultPlugin },
          { name: 'AI Visibility Protection', create: createSecretlessPlugin },
          { name: 'File Signing', create: createSigncryptPlugin },
          { name: 'Skill Safety Scanner', create: createSkillguardPlugin },
        ];

        const plugins: Array<{ name: string; plugin: OpenA2APlugin }> = [];
        for (const factory of pluginFactories) {
          const plugin = factory.create();
          await plugin.init(aimCore ? { aimCore } : undefined);
          plugins.push({ name: factory.name, plugin });
        }

        if (!options.json) {
          console.log(`\n  OpenA2A Fix-All Security Report`);
          console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);

          if (options.dryRun) {
            console.log(`Scanning ${targetDir} (dry-run -- previewing fixes)...\n`);
          } else if (options.scanOnly) {
            console.log(`Scanning ${targetDir} (scan-only -- no fixes applied)...\n`);
          } else {
            console.log(`Scanning and fixing ${targetDir}...\n`);
          }
        }

        // Aggregate results from all plugins
        interface PluginResult {
          name: string;
          findings: PluginFinding[];
          remediations: Remediation[];
        }

        const results: PluginResult[] = [];
        let allFindings: PluginFinding[] = [];
        let allRemediations: Remediation[] = [];
        let pluginErrors = 0;

        for (const { name, plugin } of plugins) {
          if (!options.json) {
            console.log(`${colors.cyan}> ${name}${RESET()}`);
          }

          try {
            // Scan
            const findings = await plugin.scan(targetDir);

            let remediations: Remediation[] = [];
            if (!options.scanOnly && findings.length > 0) {
              remediations = await plugin.fix(targetDir, {
                dryRun: options.dryRun ?? false,
              });
            }

            results.push({ name, findings, remediations });
            allFindings.push(...findings);
            allRemediations.push(...remediations);

            if (!options.json) {
              if (findings.length === 0) {
                console.log(`  ${colors.green}[+] No issues found${RESET()}`);
              } else {
                console.log(`  Found ${findings.length} issue(s)`);
                if (remediations.length > 0) {
                  console.log(
                    `  ${colors.green}[+] Fixed ${remediations.length}${RESET()}`
                  );
                }
              }
              console.log();
            }
          } catch (pluginErr) {
            // Isolate plugin errors — one failing plugin should not crash the entire run
            pluginErrors++;
            results.push({ name, findings: [], remediations: [] });
            if (!options.json) {
              console.log(`  ${colors.brightRed}[!!] Plugin error: ${pluginErr instanceof Error ? pluginErr.message : String(pluginErr)}${RESET()}`);
              if (pluginErr instanceof Error && pluginErr.stack) {
                console.error(pluginErr.stack);
              }
              console.log();
            }
          }
        }

        // JSON output
        if (options.json) {
          const unfixed = allFindings.filter(
            (f) => !allRemediations.some((r) => r.findingId === f.id)
          );
          const jsonOutput = {
            target: targetDir,
            mode: options.dryRun ? 'dry-run' : options.scanOnly ? 'scan-only' : 'fix',
            aimEnabled: !!aimCore,
            totalFindings: allFindings.length,
            totalFixed: allRemediations.length,
            remainingIssues: unfixed.length,
            pluginErrors,
            scanComplete: pluginErrors === 0,
            plugins: results.map((r) => ({
              name: r.name,
              findings: r.findings,
              remediations: r.remediations,
            })),
          };
          writeJsonStdout(jsonOutput);
          if (pluginErrors > 0) process.exit(2);
          return;
        }

        // Summary
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        console.log(`\nFindings: ${allFindings.length} total | ${allRemediations.length} fixed\n`);

        // Show remaining issues (not auto-fixed)
        const fixedIds = new Set(allRemediations.map((r) => r.findingId));
        const remainingFindings = allFindings.filter((f) => !fixedIds.has(f.id) || !f.autoFixable);

        if (remainingFindings.length > 0) {
          console.log(`${colors.red}Remaining Issues (require manual review):${RESET()}\n`);

          for (const finding of remainingFindings) {
            const display = PLUGIN_SEVERITY_DISPLAY[finding.severity];
            console.log(
              `${display.color()}${display.symbol} [${finding.id}] ${finding.severity.toUpperCase()}${RESET()}`
            );
            console.log(`   ${finding.title}`);
            console.log(`   ${finding.description}`);
            if (finding.filePath) {
              console.log(`   File: ${finding.filePath}`);
            }
            console.log();
          }
        }

        // Show remediations applied
        if (allRemediations.length > 0 && !options.scanOnly) {
          const label = options.dryRun ? 'Fixes Available (dry-run):' : 'Fixes Applied:';
          console.log(`${colors.green}[+] ${label}${RESET()}\n`);

          for (const remediation of allRemediations) {
            console.log(`  ${colors.green}[+]${RESET()} [${remediation.findingId}] ${remediation.description}`);
            if (remediation.filesModified.length > 0 && options.verbose) {
              for (const file of remediation.filesModified) {
                console.log(`     ${colors.cyan}→${RESET()} ${file}`);
              }
            }
          }
          console.log();

          if (!options.dryRun) {
            console.log(
              `${colors.cyan}Note:${RESET()} Plugin data stored in ${targetDir}/.opena2a/`
            );
            console.log(
              `      Uninstall with: hackmyagent fix-all ${directory || '.'} --uninstall\n`
            );
          }
        }

        // All clear message
        if (allFindings.length === 0) {
          console.log(`${colors.green}[+] No security issues found. Agent looks good.${RESET()}\n`);
        }

        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        console.log(`Run '${CLI_PREFIX} secure' for a full hardening scan.\n`);

        // Warn if scan is incomplete due to plugin errors
        if (pluginErrors > 0) {
          console.log(`\n${colors.brightRed}[!!] Note: ${pluginErrors} plugin(s) failed -- scan results are incomplete${RESET()}`);
          console.log(`     Re-run with --verbose for details.\n`);
        }

        // Exit with non-zero if critical/high issues remain or scan is incomplete
        if (pluginErrors > 0) {
          process.exit(2); // Exit 2 = partial/incomplete scan
        }
        const criticalOrHigh = remainingFindings.filter(
          (f) => f.severity === 'critical' || f.severity === 'high'
        );
        if (criticalOrHigh.length > 0) {
          process.exit(1);
        }
      } catch (error) {
        console.error(
          `Error: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
        process.exit(1);
      }
    }
  );

// MCP Server command
program
  .command('mcp-serve')
  .description('Run HackMyAgent as an MCP server (stdio transport)')
  .action(async () => {
    try {
      const { startMcpServer } = await import('./mcp-server');
      await startMcpServer();
    } catch (error) {
      console.error(`Error starting MCP server: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

// Init MCP command
program
  .command('init-mcp')
  .description(`Add HackMyAgent as an MCP server to your AI coding tool

Detects your IDE (Claude Code, Cursor, VS Code) and configures
HackMyAgent as an MCP server for LLM-powered security analysis.

Once configured, ask your AI assistant:
  "Run a deep security scan on this project"

Examples:
  $ hackmyagent init-mcp
  $ hackmyagent init-mcp --tool cursor
  $ hackmyagent init-mcp /path/to/project`)
  .argument('[directory]', 'Project directory (defaults to current directory)', '.')
  .option('-t, --tool <name>', 'Force specific tool: claude, cursor, vscode')
  .action(async (directory: string, options: { tool?: string }) => {
    try {
      const targetDir = require("path").resolve(directory);
      const { initMcp } = await import('./init-mcp');
      const result = initMcp(targetDir, options.tool);

      if (!result.created) {
        console.log(`\n  HackMyAgent MCP server already configured in ${result.configPath}\n`);
        return;
      }

      console.log(`\n  Detected: ${result.tool}\n`);
      console.log(`  Added HackMyAgent MCP server to ${result.configPath}\n`);
      console.log(`  Available tools in ${result.tool}:`);
      console.log(`    hackmyagent_scan       — ${CHECK_COUNT} checks + structural analysis`);
      console.log(`    hackmyagent_deep_scan  — Full analysis with LLM reasoning`);
      console.log(`    hackmyagent_analyze_file — Analyze a single file`);
      console.log(`    hackmyagent_benchmark  — OASB-1 compliance assessment\n`);
      console.log(`  Try: "Run a deep security scan on this project"\n`);
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : error}`);
      process.exit(1);
    }
  });

function levelColor(level: SoulLevel): string {
  switch (level) {
    case 'hardened': return colors.green;
    case 'standard': return colors.green;
    case 'developing': return colors.yellow;
    case 'initial': return colors.cyan;
    case 'not-started': return colors.reset;
  }
}

function levelLabel(level: SoulLevel): string {
  switch (level) {
    case 'hardened': return 'Hardened';
    case 'standard': return 'Standard';
    case 'developing': return 'Developing';
    case 'initial': return 'Initial';
    case 'not-started': return 'Not Started';
  }
}

/**
 * Detect how the CLI was invoked to suggest correct command prefix.
 */
function getCommandPrefix(): string {
  const execPath = process.argv[1] || '';
  if (execPath.includes('npx') || execPath.includes('.npm/_npx') ||
      execPath.includes('node_modules/.bin')) {
    return 'npx hackmyagent';
  }
  return 'hackmyagent';
}

// Domain percentage bar for text output
function domainBar(pct: number): string {
  if (pct >= 80) return colors.green;
  if (pct >= 60) return colors.yellow;
  if (pct >= 40) return colors.yellow;
  return colors.red;
}

program
  .command('scan-soul')
  .description(`Scan behavioral governance coverage

Analyzes SOUL.md (or equivalent governance file) for coverage
across 9 behavioral governance domains with 72 security controls.

Searches for governance files in priority order:
  SOUL.md > system-prompt.md > SYSTEM_PROMPT.md > .cursorrules
  > .github/copilot-instructions.md > CLAUDE.md > .clinerules
  > instructions.md > constitution.md > agent-config.yaml

Agent profiles filter domains by agent purpose:
  conversational:  Injection, Hardcoded, Honesty, Harm Avoidance
  code-assistant:  + Trust, Data
  tool-agent:      + Capability, Oversight
  autonomous:      + Agentic Safety
  orchestrator:    All 9 domains

Maturity levels:
  Hardened (80+), Standard (60-79), Developing (40-59),
  Initial (1-39), Not Started (0)

Examples:
  $ hackmyagent scan-soul                    Scan current directory
  $ hackmyagent scan-soul ./my-agent         Scan specific directory
  $ hackmyagent scan-soul --json             Machine-readable output
  $ hackmyagent scan-soul --verbose          Show all controls
  $ hackmyagent scan-soul --profile conversational  Override profile
  $ hackmyagent scan-soul --deep             Enable LLM semantic analysis
  $ hackmyagent scan-soul ./my-agent --publish  Scan and publish results to registry`)
  .argument('[directory]', 'Directory to scan (defaults to current directory)', '.')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show individual control results')
  .option('--tier <tier>', 'Override agent tier detection (BASIC, TOOL-USING, AGENTIC, MULTI-AGENT)')
  .option('--profile <profile>', 'Override agent profile (conversational, code-assistant, tool-agent, autonomous, orchestrator, custom)')
  .option('--fail-below <score>', 'Exit 1 if score below threshold (0-100)')
  .option('--deep', 'Maximum analysis: semantic + SOUL governance simulation (~15s)')
  .option('--static-only', 'Disable semantic analysis (static governance checks only)')
  .option('--publish', 'Push scan results to the OpenA2A Registry')
  .option('--registry-url <url>', 'Registry URL (default: REGISTRY_URL env)', validateRegistryUrl(process.env.REGISTRY_URL || 'https://api.oa2a.org'))
  .option('--contribute', 'Share anonymized scan findings with OpenA2A Registry (overrides config)')
  .option('--no-contribute', 'Do not share findings for this scan (overrides config)')
  .option('--ci', 'CI mode: suppress interactive prompts, exit non-zero on findings')
  .action(async (directory: string, options: { json?: boolean; verbose?: boolean; tier?: string; profile?: string; failBelow?: string; deep?: boolean; publish?: boolean; registryUrl?: string; contribute?: boolean; ci?: boolean }) => {
    try {
      const targetDir = require("path").resolve(directory);

      // CI mode: force non-interactive defaults
      if (options.ci) {
        if (options.contribute === undefined) options.contribute = false;
      }

      if (!require('fs').existsSync(targetDir)) {
        process.stderr.write(`Error: Directory '${targetDir}' does not exist.\n`);
        process.exit(1);
      }

      const prefix = getCommandPrefix();
      const scanner = new SoulScanner();
      const soulScanStartMs = Date.now();
      const result = await scanner.scanSoul(targetDir, {
        verbose: options.verbose,
        tier: options.tier,
        profile: options.profile,
        deepAnalysis: options.deep,
      });
      const soulScanDurationMs = Date.now() - soulScanStartMs;

      // JSON output
      if (options.json) {
        // Run publish in JSON mode and include result in output
        let publishStatus: Record<string, unknown> | undefined;
        if (options.publish) {
          try {
            const { publishScanResults } = await import('./registry/publish');
            const registryUrl = validateRegistryUrl(options.registryUrl || process.env.REGISTRY_URL || 'https://api.oa2a.org');
            const packageName = resolvePackageName(targetDir);
            if (packageName) {
              const publishData = {
                packageName,
                packageVersion: resolvePackageVersion(targetDir) ?? undefined,
                directory: targetDir,
                soulResult: result,
              };
              const publishResult = await publishScanResults(publishData, registryUrl);
              publishStatus = { ...publishResult, registryUrl };
            } else {
              publishStatus = { success: false, error: 'Could not determine package name' };
            }
          } catch (publishErr: unknown) {
            const msg = publishErr instanceof Error ? publishErr.message : 'unknown error';
            publishStatus = { success: false, error: msg };
          }
        }

        const jsonOutput = publishStatus ? { ...result, publish: publishStatus } : result;
        writeJsonStdout(jsonOutput);
        // Check fail threshold
        if (options.failBelow) {
          const threshold = parseInt(options.failBelow, 10);
          if (!isNaN(threshold) && result.score < threshold) {
            process.exit(1);
          }
        }
        await handleSoulContribution(options.contribute, targetDir, result, soulScanDurationMs, options.registryUrl, 'json');
        return;
      }

      // Text output
      process.stdout.write('\nOASB v2 Behavioral Governance Scan\n');
      process.stdout.write('----------------------------------------------------\n');
      if (options.deep) {
        process.stdout.write(`Analysis: static + semantic (ML-enhanced deep scan)\n`);
      }
      process.stdout.write('\n');

      if (result.file) {
        process.stdout.write(`File: ${result.file} (${result.fileSize.toLocaleString()} chars)\n`);
      } else {
        process.stdout.write(`File: ${colors.red}No governance file found${colors.reset}\n`);
        process.stdout.write(`  Searched: ${['SOUL.md', 'system-prompt.md', 'CLAUDE.md', '...'].join(', ')}\n`);
      }

      const tierLabel = result.tierForced ? `${result.agentTier} (--tier flag)` : `${result.agentTier} (auto-detected)`;
      const profileLabel = result.profileForced ? `${result.agentProfile} (--profile flag)` : `${result.agentProfile} (auto-detected)`;
      process.stdout.write(`Agent Tier: ${tierLabel}\n`);
      process.stdout.write(`Agent Profile: ${profileLabel}\n`);
      if (result.skippedDomains.length > 0) {
        process.stdout.write(`Skipped Domains: ${result.skippedDomains.join(', ')}\n`);
      }
      process.stdout.write('\n');

      process.stdout.write('Domain Scores:\n');

      for (const domain of result.domains) {
        if (domain.skippedByProfile) {
          if (options.verbose) {
            const label = (domain.domain + ':').padEnd(26);
            process.stdout.write(`  ${label}${colors.reset}--  (skipped by profile)${colors.reset}\n`);
          }
          continue;
        }
        if (domain.skippedByTier) {
          const label = (domain.domain + ':').padEnd(26);
          process.stdout.write(`  ${label}${colors.reset}--  (not applicable at ${result.agentTier} tier)${colors.reset}\n`);
          continue;
        }
        const pctColor = domainBar(domain.percentage);
        const label = (domain.domain + ':').padEnd(26);
        process.stdout.write(`  ${label}${pctColor}${domain.passed}/${domain.total}  (${domain.percentage}%)${colors.reset}\n`);

        // Verbose: show individual controls
        if (options.verbose) {
          for (const ctrl of domain.controls) {
            const status = ctrl.passed
              ? `${colors.green}PASS${colors.reset}`
              : `${colors.red}FAIL${colors.reset}`;
            process.stdout.write(`    ${ctrl.id}: ${status}  ${ctrl.name}\n`);
          }
        }
      }

      process.stdout.write('\n');

      // Score and level (progress-oriented)
      const lc = levelColor(result.level);
      process.stdout.write(`Governance Score: ${lc}${result.score}/100 [${levelLabel(result.level)}]${colors.reset}\n`);

      // Conformance level
      if (result.conformance === 'none') {
        process.stdout.write(`Conformance: ${colors.red}NONE${colors.reset} -- critical control missing (${result.criticalMissing.join(', ')})\n`);
      } else {
        process.stdout.write(`Conformance: ${result.conformance.toUpperCase()}\n`);
      }

      if (result.criticalFloor) {
        process.stdout.write(`${colors.yellow}Critical Floor: APPLIED${colors.reset} (${result.criticalMissing.join(', ')} missing)\n`);
      }

      // Deep analysis summary
      if (options.deep) {
        if (result.deepAnalysisAvailable === false) {
          process.stdout.write(`${colors.yellow}Deep Analysis: unavailable${colors.reset} -- set ANTHROPIC_API_KEY or install the claude CLI\n`);
        } else if (result.deepAnalysisResults && result.deepAnalysisResults.length > 0) {
          const llmUpgraded = result.deepAnalysisResults.filter((e) => e.llmPassed).length;
          process.stdout.write(`Deep Analysis: ${llmUpgraded} control${llmUpgraded === 1 ? '' : 's'} upgraded by ML semantic analysis\n`);
        } else {
          process.stdout.write(`Deep Analysis: all controls passed, no further analysis needed\n`);
        }
      }

      // Path forward (recovery-oriented, not punitive)
      const missing = result.totalControls - result.totalPassed;
      if (missing > 0) {
        const recoverable = Math.min(100 - result.score, 100);
        process.stdout.write(`\n  Path forward: +${recoverable} recoverable by addressing ${missing} control${missing === 1 ? '' : 's'}`);
        process.stdout.write(`\n  Run '${colors.cyan}${prefix} harden-soul${colors.reset}' to remediate.\n`);
      } else {
        process.stdout.write(`\n${colors.green}All ${result.totalControls} governance controls covered.${colors.reset}\n`);
      }

      process.stdout.write('\n');

      // Publish: push SOUL results to registry when --publish is used
      if (options.publish) {
        try {
          const { publishScanResults, formatPublishOutput } = await import('./registry/publish');
          const registryUrl = validateRegistryUrl(options.registryUrl || process.env.REGISTRY_URL || 'https://api.oa2a.org');
          const packageName = resolvePackageName(targetDir);

          if (!packageName) {
            process.stderr.write('Could not determine package name. Publish requires a package.json with a name field.\n');
          } else {
            if (!options.json) {
              process.stdout.write('Publishing results to registry...\n\n');
            }

            const publishData = {
              packageName,
              packageVersion: resolvePackageVersion(targetDir) ?? undefined,
              directory: targetDir,
              soulResult: result,
            };

            const publishResult = await publishScanResults(publishData, registryUrl);
            if (!options.json) {
              process.stdout.write(formatPublishOutput(publishResult, publishData, registryUrl) + '\n\n');
            }
          }
        } catch (publishErr: unknown) {
          const msg = publishErr instanceof Error ? publishErr.message : 'unknown error';
          process.stderr.write(`Failed to publish to registry: ${msg}\n`);
          process.stderr.write('Scan results are still available locally.\n');
        }
      }

      // Community contribution: share anonymized findings with OpenA2A Registry
      const soulFormat = options.json ? 'json' : 'text';
      await handleSoulContribution(options.contribute, targetDir, result, soulScanDurationMs, options.registryUrl, soulFormat);

      // In CI mode, exit non-zero if any controls failed
      if (options.ci) {
        const failedControls = result.domains.flatMap(d => d.controls).filter(c => !c.passed);
        if (failedControls.length > 0) {
          process.exit(1);
        }
      }

      // Check fail threshold
      if (options.failBelow) {
        const threshold = parseInt(options.failBelow, 10);
        if (!isNaN(threshold) && result.score < threshold) {
          process.stderr.write(`Score ${result.score} is below threshold ${threshold}\n`);
          process.exit(1);
        }
      }
    } catch (error) {
      process.stderr.write(`Error: ${error instanceof Error ? error.message : 'Unknown error'}\n`);
      process.exit(1);
    }
  });

program
  .command('harden-soul')
  .description(`Generate or update SOUL.md with missing governance sections

Runs scan-soul internally to identify missing controls, then generates
template content for each missing domain. Existing content is preserved.
Supports iterative hardening: if a domain heading exists but controls
fail within it, appends targeted remediation for those controls.

Modes:
  Default:    Append missing sections to SOUL.md (or create it)
  --dry-run:  Preview what would be added without modifying files

Examples:
  $ hackmyagent harden-soul                  Add missing sections
  $ hackmyagent harden-soul --dry-run        Preview changes
  $ hackmyagent harden-soul ./my-agent       Target specific directory
  $ hackmyagent harden-soul --json           Machine-readable output`)
  .argument('[directory]', 'Directory to harden (defaults to current directory)', '.')
  .option('--dry-run', 'Preview changes without modifying files')
  .option('--profile <profile>', 'Override agent profile (conversational, code-assistant, tool-agent, autonomous, orchestrator, custom)')
  .option('--json', 'Output as JSON')
  .action(async (directory: string, options: { dryRun?: boolean; profile?: string; json?: boolean }) => {
    try {
      const targetDir = require("path").resolve(directory);

      if (!require('fs').existsSync(targetDir)) {
        process.stderr.write(`Error: Directory '${targetDir}' does not exist.\n`);
        process.exit(1);
      }

      const prefix = getCommandPrefix();
      const scanner = new SoulScanner();
      const result = await scanner.hardenSoul(targetDir, { dryRun: options.dryRun, profile: options.profile });

      // JSON output
      if (options.json) {
        // Exclude full content from JSON to keep it concise
        const jsonResult = {
          file: result.file,
          sectionsAdded: result.sectionsAdded,
          controlsAdded: result.controlsAdded,
          dryRun: result.dryRun,
          existedBefore: result.existedBefore,
        };
        writeJsonStdout(jsonResult);
        return;
      }

      // Text output
      if (result.sectionsAdded.length === 0) {
        process.stdout.write(`\n${colors.green}All governance domains already have sections in ${result.file}.${colors.reset}\n`);
        process.stdout.write(`Run '${prefix} scan-soul --verbose' to see individual control coverage.\n\n`);
        return;
      }

      if (result.dryRun) {
        process.stdout.write('\nHarden SOUL (dry-run)\n');
        process.stdout.write('----------------------------------------------------\n\n');
        process.stdout.write(`Target: ${result.file}`);
        if (result.existedBefore) {
          process.stdout.write(' (append)\n');
        } else {
          process.stdout.write(' (create)\n');
        }
        process.stdout.write(`Sections to add: ${result.sectionsAdded.length}\n`);
        process.stdout.write(`Controls covered: +${result.controlsAdded}\n\n`);

        process.stdout.write('Sections:\n');
        for (const section of result.sectionsAdded) {
          process.stdout.write(`  ${colors.cyan}+${colors.reset} ${section}\n`);
        }

        process.stdout.write(`\nRun without --dry-run to apply changes.\n\n`);
      } else {
        process.stdout.write('\nHarden SOUL\n');
        process.stdout.write('----------------------------------------------------\n\n');

        if (result.existedBefore) {
          process.stdout.write(`Updated: ${result.file}\n`);
        } else {
          process.stdout.write(`Created: ${result.file}\n`);
        }

        process.stdout.write(`Added ${result.sectionsAdded.length} section${result.sectionsAdded.length === 1 ? '' : 's'}:\n`);
        for (const section of result.sectionsAdded) {
          process.stdout.write(`  ${colors.green}+${colors.reset} ${section}\n`);
        }
        process.stdout.write(`Controls covered: +${result.controlsAdded}\n\n`);

        process.stdout.write(`Run '${colors.cyan}${prefix} scan-soul${colors.reset}' to verify coverage.\n\n`);
      }
    } catch (error) {
      process.stderr.write(`Error: ${error instanceof Error ? error.message : 'Unknown error'}\n`);
      process.exit(1);
    }
  });

// ---------------------------------------------------------------------------
// trust — Trust verification via OpenA2A Registry (powered by ai-trust)
// ---------------------------------------------------------------------------

const REGISTRY_DEFAULT_URL = 'https://api.oa2a.org';

interface TrustAnswer {
  packageId?: string;
  name: string;
  type?: string;
  packageType?: string;
  trustLevel: number;
  trustScore: number;
  verdict: string;
  scanStatus?: string;
  communityScans?: number;
  cveCount?: number;
  recommendation?: string;
  confidence?: number;
  lastScannedAt?: string;
  dependencies?: {
    direct?: number;
    transitive?: number;
    totalDeps: number;
    vulnerableDeps: number;
    minTrustLevel: number;
    minTrustScore: number;
    maxDepth: number;
    riskSummary?: { blocked: number; warning: number; safe: number };
  };
  found: boolean;
}

interface TrustBatchResponse {
  results: TrustAnswer[];
  total: number;
  queriedAt: string;
}

async function trustCheck(name: string, registryUrl: string, type?: string): Promise<TrustAnswer> {
  const params = new URLSearchParams({ name, includeProfile: 'true', includeDeps: 'true' });
  if (type) params.set('type', type);

  const url = `${registryUrl}/api/v1/trust/query?${params.toString()}`;
  const res = await fetch(url, {
    method: 'GET',
    headers: { 'Accept': 'application/json', 'User-Agent': `hackmyagent/${VERSION}` },
  });

  if (!res.ok) {
    if (res.status === 404) {
      throw new Error(`Package "${name}" not found in the OpenA2A Registry.`);
    }
    const body = await res.text();
    throw new Error(`Registry API returned ${res.status}: ${body}`);
  }

  const data = (await res.json()) as TrustAnswer;
  data.found = !!data.packageId;
  return data;
}

async function trustBatch(
  packages: Array<{ name: string; type?: string }>,
  registryUrl: string
): Promise<{ results: TrustAnswer[]; meta: { total: number; found: number; notFound: number } }> {
  const url = `${registryUrl}/api/v1/trust/batch`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': `hackmyagent/${VERSION}`,
    },
    body: JSON.stringify({ packages }),
  });

  if (!res.ok) {
    if (res.status === 404) {
      throw new Error('Registry batch endpoint not found. The registry may be unavailable.');
    }
    const body = await res.text();
    throw new Error(`Registry API returned ${res.status}: ${body}`);
  }

  const raw = (await res.json()) as TrustBatchResponse;
  const NULL_UUID = '00000000-0000-0000-0000-000000000000';
  for (const r of raw.results) {
    r.found = !!r.packageId && r.packageId !== NULL_UUID;
  }
  const found = raw.results.filter((r) => r.found).length;
  return {
    results: raw.results,
    meta: { total: raw.total, found, notFound: raw.total - found },
  };
}

function trustLevelLabel(level: number): string {
  switch (level) {
    case 0: return 'Blocked';
    case 1: return 'Warning';
    case 2: return 'Listed';
    case 3: return 'Scanned';
    case 4: return 'Verified';
    default: return `Unknown (${level})`;
  }
}

function trustLevelColor(level: number): string {
  if (level >= 3) return colors.green;
  if (level >= 1) return colors.yellow;
  return colors.red;
}

function normalizeTrustVerdict(verdict: string): string {
  switch (verdict) {
    case 'safe': case 'passed': return 'safe';
    case 'warning': case 'warnings': return 'warning';
    case 'blocked': case 'failed': return 'blocked';
    case 'listed': return 'listed';
    default: return verdict;
  }
}

function trustVerdictColor(verdict: string): string {
  const n = normalizeTrustVerdict(verdict);
  switch (n) {
    case 'safe': return colors.green;
    case 'warning': return colors.yellow;
    case 'blocked': return colors.red;
    case 'listed': return colors.cyan;
    default: return colors.dim;
  }
}

function formatTrustScore(trustScore: number, scanStatus?: string): string {
  if (trustScore === 0 && (!scanStatus || scanStatus === '')) return 'Not scanned';
  return `${Math.round(trustScore * 100)}/100`;
}

function formatTrustConfidence(confidence?: number): string | null {
  if (!confidence || confidence === 0) return null;
  if (confidence >= 0.7) return 'high confidence';
  if (confidence >= 0.4) return 'moderate confidence';
  return 'low confidence';
}

function formatTrustScanAge(lastScannedAt?: string): string | null {
  if (!lastScannedAt) return null;
  const days = Math.floor((Date.now() - new Date(lastScannedAt).getTime()) / (1000 * 60 * 60 * 24));
  if (days === 0) return 'today';
  if (days === 1) return '1 day ago';
  if (days > 90) return `${days} days ago (stale)`;
  return `${days} days ago`;
}

function formatTrustCheck(answer: TrustAnswer): string {
  if (!answer.found) {
    return [
      '',
      `  ${answer.name}`,
      `  ${colors.dim}Type: ${answer.packageType || 'unknown'}${colors.reset}`,
      `  ${colors.dim}Status: Not found in registry${colors.reset}`,
      '',
      '  To scan it locally:',
      `    ${colors.cyan}ai-trust check ${answer.name} --scan-if-missing${colors.reset}`,
      '',
      '  Or scan your full project:',
      `    ${colors.cyan}npx hackmyagent secure .${colors.reset}`,
      '',
    ].join('\n');
  }

  const normalized = normalizeTrustVerdict(answer.verdict);
  const vc = trustVerdictColor(answer.verdict);
  const tc = trustLevelColor(answer.trustLevel);
  const scoreDisplay = formatTrustScore(answer.trustScore, answer.scanStatus);
  const isUnscanned = scoreDisplay === 'Not scanned';

  const lines: string[] = [
    '',
    `  ${answer.name}`,
    `  Type:           ${answer.packageType || 'unknown'}`,
    `  Verdict:        ${vc}${normalized.toUpperCase()}${colors.reset}`,
    `  Trust Level:    ${tc}${trustLevelLabel(answer.trustLevel)}${colors.reset} (${answer.trustLevel}/4)`,
    `  Trust Score:    ${isUnscanned ? colors.dim + scoreDisplay + colors.reset : scoreDisplay}`,
  ];

  const conf = formatTrustConfidence(answer.confidence);
  if (conf) lines.push(`  Confidence:     ${conf}`);

  const scanAge = formatTrustScanAge(answer.lastScannedAt);
  if (scanAge) {
    lines.push(`  Last Scanned:   ${scanAge.includes('stale') ? colors.yellow + scanAge + colors.reset : scanAge}`);
  } else if (!isUnscanned) {
    lines.push(`  Scan Status:    ${answer.scanStatus || 'unknown'}`);
  }

  if (isUnscanned) {
    lines.push('');
    lines.push(`  ${colors.yellow}This package has not been security-scanned.${colors.reset}`);
    lines.push(`  ${colors.yellow}Trust level reflects registry listing only.${colors.reset}`);
  }

  if (answer.dependencies && answer.dependencies.totalDeps > 0) {
    const deps = answer.dependencies;
    lines.push('');
    lines.push('  Dependencies');
    lines.push(`  Total:          ${deps.totalDeps}`);
    lines.push(`  Vulnerable:     ${deps.vulnerableDeps > 0 ? colors.red + deps.vulnerableDeps + colors.reset : colors.green + '0' + colors.reset}`);
    lines.push(`  Min Trust:      ${deps.minTrustLevel}/4`);
  }

  lines.push('');
  return lines.join('\n');
}

function formatTrustBatch(
  response: { results: TrustAnswer[]; meta: { total: number; found: number; notFound: number } },
  minTrust: number
): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(`  Trust Audit: ${response.meta.total} packages queried, ${response.meta.found} found, ${response.meta.notFound} not found`);
  lines.push('');

  const nameW = 40, typeW = 14, verdictW = 10, levelW = 12, scoreW = 14, scanW = 10;

  lines.push(
    '  ' +
    'PACKAGE'.padEnd(nameW) +
    'TYPE'.padEnd(typeW) +
    'VERDICT'.padEnd(verdictW) +
    'TRUST'.padEnd(levelW) +
    'SCORE'.padEnd(scoreW) +
    'SCAN'.padEnd(scanW)
  );
  lines.push('  ' + '-'.repeat(nameW + typeW + verdictW + levelW + scoreW + scanW));

  for (const result of response.results) {
    const name = result.name.length > nameW - 2
      ? result.name.substring(0, nameW - 5) + '...'
      : result.name;

    if (!result.found) {
      lines.push(
        '  ' +
        name.padEnd(nameW) +
        '-'.padEnd(typeW) +
        colors.dim + 'NO DATA'.padEnd(verdictW) + colors.reset +
        colors.dim + '-'.padEnd(levelW) + colors.reset +
        '-'.padEnd(scoreW) +
        '-'.padEnd(scanW)
      );
      continue;
    }

    const normalized = normalizeTrustVerdict(result.verdict);
    const vc = trustVerdictColor(result.verdict);
    const tc = trustLevelColor(result.trustLevel);
    const scoreDisplay = formatTrustScore(result.trustScore, result.scanStatus);

    lines.push(
      '  ' +
      name.padEnd(nameW) +
      (result.packageType || '-').padEnd(typeW) +
      vc + normalized.toUpperCase().padEnd(verdictW) + colors.reset +
      tc + trustLevelLabel(result.trustLevel).padEnd(levelW) + colors.reset +
      scoreDisplay.padEnd(scoreW) +
      (result.scanStatus || '-').padEnd(scanW)
    );
  }

  const belowThreshold = response.results.filter((r) => r.found && r.trustLevel < minTrust);
  const notFound = response.results.filter((r) => !r.found);

  lines.push('');

  if (belowThreshold.length > 0) {
    lines.push(`  ${colors.yellow}[!] ${belowThreshold.length} package(s) below minimum trust level ${minTrust}:${colors.reset}`);
    for (const pkg of belowThreshold) {
      lines.push(`  ${colors.yellow}    - ${pkg.name} (trust level ${pkg.trustLevel}, verdict: ${pkg.verdict})${colors.reset}`);
    }
  }

  if (notFound.length > 0) {
    lines.push(`  ${colors.yellow}[?] ${notFound.length} package(s) not found in registry (no trust data):${colors.reset}`);
    for (const pkg of notFound) {
      lines.push(`  ${colors.yellow}    - ${pkg.name}${colors.reset}`);
    }
  }

  if (belowThreshold.length === 0 && notFound.length === 0) {
    lines.push(`  ${colors.green}All ${response.meta.found} packages meet minimum trust level ${minTrust}.${colors.reset}`);
  }

  // Next steps
  lines.push('');
  if (notFound.length > 0) {
    lines.push(`  ${colors.dim}Scan unknown packages: ai-trust audit <file> --scan-missing${colors.reset}`);
    lines.push(`  ${colors.dim}Or individually: ai-trust check <name> --scan-if-missing${colors.reset}`);
  }
  if (belowThreshold.length > 0) {
    lines.push(`  ${colors.dim}Inspect flagged packages: ai-trust check <name>${colors.reset}`);
  }
  lines.push(`  ${colors.dim}Full project security scan: npx hackmyagent secure .${colors.reset}`);

  lines.push('');
  return lines.join('\n');
}

async function parseDepsFile(filePath: string): Promise<Array<{ name: string }>> {
  const fs = require('fs');
  const path = require('path');
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch (err: unknown) {
    if (err && typeof err === 'object' && 'code' in err && (err as { code: string }).code === 'ENOENT') {
      throw new Error(`File not found: ${filePath}`);
    }
    throw err;
  }
  const fileName = path.basename(filePath);

  if (fileName === 'package.json') {
    const pkg = JSON.parse(content) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
    const packages: Array<{ name: string }> = [];
    const seen = new Set<string>();
    for (const deps of [pkg.dependencies, pkg.devDependencies]) {
      if (!deps) continue;
      for (const name of Object.keys(deps)) {
        if (!seen.has(name)) {
          seen.add(name);
          packages.push({ name });
        }
      }
    }
    return packages;
  }

  if (fileName === 'requirements.txt') {
    const packages: Array<{ name: string }> = [];
    const seen = new Set<string>();
    for (const rawLine of content.split('\n')) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#') || line.startsWith('-')) continue;
      const match = line.match(/^([a-zA-Z0-9_-]+(?:\[[a-zA-Z0-9_,-]+\])?)/);
      if (match) {
        const name = match[1].replace(/\[.*\]/, '');
        if (!seen.has(name)) {
          seen.add(name);
          packages.push({ name });
        }
      }
    }
    return packages;
  }

  throw new Error(`Unsupported dependency file: ${fileName}. Supported: package.json, requirements.txt`);
}

program
  .command('trust')
  .description(`Check trust level for AI packages before installing

Query the OpenA2A Registry to verify trust scores, vulnerability status,
and dependency risk for MCP servers, A2A agents, and AI tools.

Modes:
  trust <package>           Single package lookup
  trust --audit <file>      Audit a dependency file (package.json, requirements.txt)
  trust --batch pkg1 pkg2   Batch lookup for multiple packages

Examples:
  $ ${CLI_PREFIX} trust server-filesystem
  $ ${CLI_PREFIX} trust server-filesystem          (resolves to @modelcontextprotocol/server-filesystem)
  $ ${CLI_PREFIX} trust mcp-server-fetch            (resolves to @modelcontextprotocol/server-fetch)
  $ ${CLI_PREFIX} trust my-mcp-server --type mcp_server
  $ ${CLI_PREFIX} trust --audit package.json
  $ ${CLI_PREFIX} trust --audit requirements.txt --min-trust 3
  $ ${CLI_PREFIX} trust --batch langchain openai anthropic`)
  .argument('[package]', 'Package name to look up')
  .option('-t, --type <type>', 'Package type (mcp_server, a2a_agent, ai_tool, etc.)')
  .option('--audit <file>', 'Audit a dependency file (package.json or requirements.txt)')
  .option('--batch <names...>', 'Batch trust lookup for multiple packages')
  .option('--min-trust <level>', 'Minimum trust level threshold (0-4)', '2')
  .option('--registry-url <url>', 'Registry base URL', validateRegistryUrl(REGISTRY_DEFAULT_URL))
  .option('--json', 'Output as JSON')
  .action(async (
    packageName: string | undefined,
    opts: {
      type?: string;
      audit?: string;
      batch?: string[];
      minTrust: string;
      registryUrl: string;
      json?: boolean;
    }
  ) => {
    const registryUrl = validateRegistryUrl(opts.registryUrl).replace(/\/+$/, '');
    const minTrust = parseInt(opts.minTrust, 10);
    if (isNaN(minTrust) || minTrust < 0 || minTrust > 4) {
      process.stderr.write('Error: --min-trust must be a number between 0 and 4\n');
      process.exit(1);
    }

    try {
      // Mode: audit a dependency file
      if (opts.audit) {
        const rawPackages = await parseDepsFile(opts.audit);
        const packages = rawPackages.map((pkg) => ({
          ...pkg,
          name: resolveAndLogMcpShorthand(pkg.name),
        }));
        if (packages.length === 0) {
          process.stdout.write('No dependencies found in the specified file.\n');
          return;
        }
        if (packages.length > 100) {
          process.stderr.write(`Error: Too many dependencies (${packages.length}). Maximum 100 per request.\n`);
          process.exit(1);
        }
        const response = await trustBatch(packages, registryUrl);
        if (opts.json) {
          writeJsonStdout(response);
        } else {
          process.stdout.write(formatTrustBatch(response, minTrust));
        }
        const belowThreshold = response.results.some((r) => r.found && r.trustLevel < minTrust);
        const hasNotFound = response.results.some((r) => !r.found);
        if (belowThreshold || hasNotFound) process.exitCode = 1;
        return;
      }

      // Mode: batch lookup
      if (opts.batch && opts.batch.length > 0) {
        if (opts.batch.length > 100) {
          process.stderr.write(`Error: Too many packages (${opts.batch.length}). Maximum 100 per request.\n`);
          process.exit(1);
        }
        const packages = opts.batch.map((name) => ({
          name: resolveAndLogMcpShorthand(name),
          ...(opts.type ? { type: opts.type } : {}),
        }));
        const response = await trustBatch(packages, registryUrl);
        if (opts.json) {
          writeJsonStdout(response);
        } else {
          process.stdout.write(formatTrustBatch(response, minTrust));
        }
        const belowThreshold = response.results.some((r) => r.found && r.trustLevel < minTrust);
        const hasNotFound = response.results.some((r) => !r.found);
        if (belowThreshold || hasNotFound) process.exitCode = 1;
        return;
      }

      // Mode: single package lookup
      if (!packageName) {
        process.stderr.write(`Error: Provide a package name or use --audit/--batch.\n`);
        process.stderr.write(`Usage: ${CLI_PREFIX} trust <package>\n`);
        process.exit(1);
      }

      packageName = resolveAndLogMcpShorthand(packageName);
      const result = await trustCheck(packageName, registryUrl, opts.type);
      if (opts.json) {
        writeJsonStdout(result);
      } else {
        process.stdout.write(formatTrustCheck(result));
      }
      if (result.found && (result.verdict === 'blocked' || result.verdict === 'warning')) {
        process.exitCode = 1;
      }
    } catch (error) {
      process.stderr.write(`Error: ${error instanceof Error ? error.message : 'Unknown error'}\n`);
      process.exit(1);
    }
  });

program
  .command('check-metadata')
  .description('Export metadata for all security checks (JSON)')
  .option('-d, --directory <dir>', 'Scan a specific directory to collect check metadata from findings')
  .option('--json', 'Output as JSON (default)')
  .action(async (options: { directory?: string }) => {
    const { getAttackClass, getTaxonomyMap } = require('./hardening/taxonomy');

    // Build static registry from taxonomy map (covers all known checks)
    const taxMap = getTaxonomyMap();
    const metadata: Record<string, { checkId: string; name: string; category: string; attackClass: string; severity: string }> = {};

    // Add all checks from taxonomy (the authoritative source of check IDs)
    for (const checkId of Object.keys(taxMap)) {
      const prefix = checkId.split('-').slice(0, -1).join('-') || checkId.split('-')[0];
      metadata[checkId] = {
        checkId,
        name: checkId,
        category: prefix.toLowerCase(),
        attackClass: taxMap[checkId] || '',
        severity: '',
      };
    }

    // If a directory is provided, enrich with actual finding data (names, severity, etc.)
    if (options.directory) {
      const scanner = new HardeningScanner();
      const result = await scanner.scan({ targetDir: options.directory, autoFix: false, scanDepth: 'deep' as any });

      for (const finding of result.findings) {
        if (metadata[finding.checkId]) {
          metadata[finding.checkId].name = finding.name;
          metadata[finding.checkId].category = finding.category;
          metadata[finding.checkId].severity = finding.severity;
        } else {
          metadata[finding.checkId] = {
            checkId: finding.checkId,
            name: finding.name,
            category: finding.category,
            attackClass: getAttackClass(finding.checkId) || '',
            severity: finding.severity,
          };
        }
      }
    }

    writeJsonStdout({ totalChecks: Object.keys(metadata).length, checks: metadata });
  });

// Show help and exit 0 when no arguments provided
// explain command: NanoMind-powered finding explanation
program
  .command('explain')
  .argument('<findingId>', 'Finding ID to explain (e.g., SKILL-SEMANTIC-007 or CRED-001)')
  .description('Explain a security finding in plain English')
  .action(async (findingId: string) => {
    console.log(`Explaining finding: ${findingId}\n`);

    // Try NanoMind daemon first for dynamic explanation
    const { isDaemonAvailable, explainFinding } = await import('./semantic/nanomind-analyzer.js');
    const available = await isDaemonAvailable();
    if (available) {
      const explanation = await explainFinding(JSON.stringify({ findingId }));
      if (explanation) {
        console.log(explanation);
        return;
      }
    }

    // Fallback: static explanation from check metadata
    const checkId = findingId.toUpperCase();
    const staticExplanations: Record<string, string> = {
      // Credential checks
      'CRED-001': 'Hardcoded credential detected. API keys, tokens, or passwords are embedded directly in source code. Replace with environment variable references ($VAR_NAME) and rotate the exposed credential immediately.',
      'CRED-002': 'OpenAI API key pattern detected (sk-...). Move to environment variable OPENAI_API_KEY.',
      'CRED-003': 'Anthropic API key pattern detected (sk-ant-...). Move to environment variable ANTHROPIC_API_KEY.',
      'CRED-004': 'AWS credential pattern detected. Use AWS SDK credential chain or environment variables.',
      // MCP checks
      'MCP-001': 'MCP server running without TLS. Agent-to-server communication is unencrypted. Enable TLS on the MCP server or use a reverse proxy with TLS termination.',
      // Skill checks
      'SKILL-005': 'External endpoint in skill capability declaration. Verify the endpoint is trusted and uses HTTPS.',
      // Governance checks
      'GOV-001': 'No governance policy found. Agents should declare behavioral constraints in a SOUL.md or governance file. Create a SOUL.md with mission, boundaries, and allowed actions.',
      'GOV-002': 'Governance file lacks boundary definitions. Without explicit boundaries, the agent may act outside intended scope. Add "boundaries" or "constraints" sections to your governance file.',
      'GOV-003': 'Governance file missing escalation policy. Define when and how the agent should escalate to a human. Add an escalation section with trigger conditions and contact methods.',
      // Permission checks
      'PERM-001': 'Overly broad file system permissions detected. The agent has write access to directories outside its working scope. Restrict file permissions to the minimum required paths.',
      'PERM-002': 'Network permissions not restricted. The agent can make outbound requests to any host. Define an allowlist of permitted domains in the agent configuration.',
      'PERM-003': 'Execution permissions too permissive. The agent can spawn arbitrary processes. Restrict executable permissions to specific, required binaries only.',
      // SOUL checks
      'SOUL-001': 'No SOUL.md file found. SOUL.md defines the agent identity, mission, and behavioral constraints. Run `hackmyagent secure --fix` to generate one.',
      'SOUL-002': 'SOUL.md missing identity section. The agent lacks a declared identity, making impersonation easier. Add name, version, and publisher fields.',
      'SOUL-003': 'SOUL.md missing behavioral boundaries. Without explicit limits, the agent may perform unintended actions. Add a boundaries section listing prohibited behaviors.',
      // Privacy checks
      'PRIV-001': 'PII handling not declared. The agent processes data but has no privacy policy or data handling declaration. Add a data handling section specifying what data is collected, stored, and shared.',
      // Data checks
      'DATA-001': 'Sensitive data logged to console or file. Credentials, tokens, or PII appear in log output. Sanitize log statements to redact sensitive values before output.',
      'DATA-002': 'Data retention policy missing. The agent stores data without a defined retention or deletion policy. Define how long data is kept and when it is purged.',
      // Injection checks
      'INJECT-001': 'No prompt injection defense detected. The agent does not validate or sanitize inputs against injection attacks. Add input validation and consider using a system prompt with injection resistance instructions.',
      'INJECT-002': 'Indirect prompt injection surface found. External data (URLs, files, API responses) is passed to the LLM without sanitization. Sanitize or sandbox external content before including it in prompts.',
      // Attestation checks
      'ATTEST-001': 'No attestation mechanism found. The agent cannot prove its identity or integrity to other agents. Implement agent attestation using signed identity tokens or SOUL.md signatures.',
      // Supply chain checks
      'SUPPLY-001': 'Dependency with known vulnerability detected. A transitive or direct dependency has a published CVE. Update the affected package to a patched version.',
    };

    const explanation = staticExplanations[checkId];
    if (explanation) {
      console.log(`${checkId}: ${explanation}`);
    } else {
      // Fallback: generate explanation from taxonomy metadata
      const { getAttackClass } = require('./hardening/taxonomy');
      const attackClass = getAttackClass(checkId);

      // Map check ID prefixes to human-readable category descriptions
      const prefixDescriptions: Record<string, string> = {
        'CRED': 'Credential exposure',
        'MCP': 'MCP server configuration',
        'SKILL': 'Skill package security',
        'GOV': 'Governance policy',
        'PERM': 'Permission scope',
        'SOUL': 'Behavioral governance (SOUL.md)',
        'PRIV': 'Privacy and data handling',
        'DATA': 'Data protection',
        'INJECT': 'Prompt injection defense',
        'ATTEST': 'Agent attestation',
        'SUPPLY': 'Supply chain security',
        'NET': 'Network security',
        'GIT': 'Git repository hygiene',
        'PROMPT': 'Prompt security',
        'NEMO': 'Static analysis pattern',
        'LIFECYCLE': 'Prompt assembly lifecycle',
        'AST': 'Deep code analysis',
        'ENCRYPT': 'Encryption and hashing',
        'LOG': 'Logging and audit',
        'AUTH': 'Authentication',
        'TOOL': 'Tool permission and safety',
      };

      const prefix = checkId.split('-')[0];
      const categoryDesc = prefixDescriptions[prefix];

      if (attackClass || categoryDesc) {
        console.log(`${checkId}: ${categoryDesc || 'Security check'}.`);
        if (attackClass) {
          console.log(`  Attack class: ${attackClass}`);
        }
        console.log(`\n  Run 'hackmyagent secure --verbose' to see this check in context with fix guidance.`);
        console.log(`  Run 'hackmyagent check-metadata --json' for full check details.`);
      } else {
        console.log(`No explanation available for ${findingId}. This may not be a valid check ID.`);
        console.log(`\nRun 'hackmyagent check-metadata --json' to see all ${CHECK_COUNT} valid check IDs.`);
      }
    }
  });

// red-team command: NanoMind-powered adaptive attack engine
program
  .command('red-team')
  .argument('<target>', 'Path to artifact to red-team (skill, SOUL.md, MCP config, system prompt)')
  .description('Run adaptive attack session against an artifact. NanoMind generates target-specific attacks, observes responses, adapts, and maps defenses.')
  .option('--iterations <n>', 'Max attack iterations per category', '5')
  .option('--json', 'Output results as JSON')
  .action(async (target: string, options: { iterations?: string; json?: boolean }) => {
    const { readFileSync } = await import('node:fs');
    const { runAttackSession, exportTrainingData } = await import('./attack-engine/feedback-loop.js');
    const { exportAttackTraining } = await import('./attack-engine/training-pipeline.js');

    let content: string;
    try {
      content = readFileSync(target, 'utf-8');
    } catch {
      console.error(`Cannot read file: ${target}`);
      process.exit(1);
    }

    const artifactType = target.toLowerCase().includes('soul') ? 'soul' as const
      : target.toLowerCase().includes('mcp') ? 'mcp_tool' as const
      : 'skill' as const;
    const name = target.split('/').pop() ?? 'unknown';

    if (!options.json) {
      console.log(`\nAdaptive Attack Engine`);
      console.log(`Target: ${name} (${artifactType})`);
      console.log(`Max iterations: ${options.iterations ?? 5} per category\n`);
    }

    const result = await runAttackSession(content, artifactType, name, {
      maxIterations: parseInt(options.iterations ?? '5', 10),
    });

    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(`Results:`);
      console.log(`  Payloads generated: ${result.totalPayloads}`);
      console.log(`  Successful attacks: ${result.successCount}`);
      console.log(`  Partial successes:  ${result.partialCount}`);
      console.log(`  Resilience score:   ${(result.defenseMap.resilienceScore * 100).toFixed(0)}%`);
      console.log(`  Duration:           ${result.durationMs}ms\n`);

      if (result.vulnerabilities.length > 0) {
        console.log(`Vulnerabilities Found:`);
        for (const vuln of result.vulnerabilities) {
          console.log(`  [${vuln.severity.toUpperCase()}] ${vuln.title}`);
          console.log(`    ${vuln.description}`);
          console.log(`    Fix: ${vuln.remediation}\n`);
        }
      } else {
        console.log(`No vulnerabilities found. All defenses held.\n`);
      }

      if (result.defenseMap.strongCategories.length > 0) {
        console.log(`Strong defenses: ${result.defenseMap.strongCategories.join(', ')}`);
      }
      if (result.defenseMap.weakCategories.length > 0) {
        console.log(`Weak defenses:   ${result.defenseMap.weakCategories.join(', ')}`);
      }
    }

    // Auto-export training data
    const trainingCount = exportAttackTraining(result);
    if (!options.json && trainingCount > 0) {
      console.log(`\n${trainingCount} training samples exported to NanoMind corpus.`);
    }
  });


// wild: test AI agent resilience against real-world web-based attacks
program
  .command('wild')
  .description(`Test AI agent resilience in the wild

Fetches pages from AgentPwn (agentpwn.com) and analyzes hidden injection
payloads that AI agents encounter when browsing the web. Reports which
attack surfaces exist and computes a wild resilience score.

Attack categories (11):
  prompt-injection, jailbreak, data-exfiltration, capability-abuse,
  context-manipulation, mcp-exploitation, a2a-attack,
  memory-weaponization, context-window, supply-chain, tool-shadow

Injection surfaces detected:
  html-comment, invisible-span, json-ld, meta-tag, http-header,
  aria-label, image-alt, unicode-stego

Also tests: robots.txt, llms.txt, sitemap.xml for embedded payloads

Examples:
  $ hackmyagent wild
  $ hackmyagent wild https://agentpwn.com
  $ hackmyagent wild --category prompt-injection
  $ hackmyagent wild --tier 5
  $ hackmyagent wild --json
  $ hackmyagent wild -v -o report.json`)
  .argument('[url]', 'Target URL to scan', 'https://agentpwn.com')
  .option('-c, --category <category>', 'Filter by attack category')
  .option('-t, --tier <tier>', 'Filter by specific difficulty tier')
  .option('--timeout <ms>', 'Request timeout in milliseconds', '15000')
  .option('--delay <ms>', 'Delay between requests in milliseconds', '500')
  .option('--json', 'Output as JSON')
  .option('-o, --output <file>', 'Write output to file')
  .option('--verbose', 'Show detailed output for each page')
  .action(async (url: string, options: {
    category?: string;
    tier?: string;
    timeout?: string;
    delay?: string;
    json?: boolean;
    output?: string;
    verbose?: boolean;
  }) => {
    try {
      const scanner = new WildScanner({
        url: url || 'https://agentpwn.com',
        category: options.category,
        tier: options.tier ? parseInt(options.tier, 10) : undefined,
        timeout: parseInt(options.timeout || '15000', 10),
        delay: parseInt(options.delay || '500', 10),
        verbose: options.verbose || false,
        json: options.json || false,
      });

      if (!options.json) {
        console.log(`\n${colors.cyan}HackMyAgent Wild Scanner${colors.reset}`);
        console.log(`${'━'.repeat(50)}\n`);
        console.log(`Target: ${url || 'https://agentpwn.com'}`);
        if (options.category) console.log(`Category: ${options.category}`);
        if (options.tier) console.log(`Tier: ${options.tier}`);
        console.log('');
      }

      const report = await scanner.scan();

      if (options.json) {
        const output = JSON.stringify(report, null, 2);
        if (options.output) {
          const fs = await import('fs');
          fs.writeFileSync(options.output, output);
          process.stderr.write(`Report written to ${options.output}\n`);
        } else {
          writeLargeStdout(output + '\n');
        }
      } else {
        printWildReport(report);
        if (options.output) {
          const fs = await import('fs');
          fs.writeFileSync(options.output, JSON.stringify(report, null, 2));
          console.log(`\nJSON report written to ${options.output}`);
        }
      }

      // Exit with non-zero if resilience is poor
      if (report.resilienceRating === 'critical' || report.resilienceRating === 'needs-attention') {
        process.exit(1);
      }
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  });

function printWildReport(report: WildScanReport): void {
  // File fetches
  console.log(`${colors.dim}File-Level Attack Surfaces${colors.reset}`);
  for (const f of report.fileFetches) {
    const status = f.hasPayload
      ? `${colors.red}PAYLOAD FOUND${colors.reset}`
      : `${colors.green}clean${colors.reset}`;
    console.log(`  ${f.file}: ${f.statusCode} [${status}]`);
    if (f.payloadExcerpt) {
      console.log(`    ${colors.dim}${f.payloadExcerpt}${colors.reset}`);
    }
  }

  // Page results by category
  console.log(`\n${colors.dim}Attack Pages (${report.pagesScanned} scanned)${colors.reset}`);
  const categories = Object.keys(report.summary.byCategory).sort();
  for (const cat of categories) {
    const stats = report.summary.byCategory[cat];
    console.log(`  ${cat}: ${stats.pages} pages, ${stats.payloads} payloads`);
  }

  // Injection surfaces
  console.log(`\n${colors.dim}Injection Surfaces Detected${colors.reset}`);
  const surfaces = Object.entries(report.summary.bySurface).sort((a, b) => b[1] - a[1]);
  for (const [surface, count] of surfaces) {
    console.log(`  ${surface}: ${count}`);
  }

  // Score
  const scoreColor = report.wildResilienceScore >= 60
    ? colors.green
    : report.wildResilienceScore >= 40
      ? colors.yellow
      : colors.red;

  console.log(`\n${'━'.repeat(50)}`);
  console.log(`\n${colors.dim}Wild Resilience Score:${colors.reset} ${scoreColor}${report.wildResilienceScore}/100 (${report.resilienceRating})${colors.reset}`);
  console.log(`${colors.dim}Pages Scanned:${colors.reset} ${report.pagesScanned}`);
  console.log(`${colors.dim}Total Payloads:${colors.reset} ${report.summary.totalPayloads}`);
  console.log(`${colors.dim}Callback Pages:${colors.reset} ${report.summary.callbackPages}`);
  console.log(`${colors.dim}Canary Pages:${colors.reset} ${report.summary.canaryPages}`);
  console.log(`${colors.dim}Max Tier:${colors.reset} ${report.summary.maxTier}`);
  console.log(`${colors.dim}Duration:${colors.reset} ${(report.duration / 1000).toFixed(1)}s`);

  console.log(`\n${colors.dim}Note: This score reflects the attack surface coverage of the target`);
  console.log(`site. To test your actual agent's resilience, use --model to pipe`);
  console.log(`page content through an LLM. For static config scanning, use:${colors.reset}`);
  console.log(`  ${colors.cyan}npx hackmyagent secure${colors.reset}`);
}

// pull-stubs: fetch pending HMA check stubs from the registry
program
  .command('pull-stubs')
  .description(`Fetch pending HMA check stubs from the registry for review.

The ARIA pipeline discovers new attack patterns and creates stub definitions
for checks that HMA doesn't yet implement. This command pulls those stubs
so you can review, refine, and integrate them.

Requires INTERNAL_API_KEY environment variable for registry authentication.

Examples:
  $ ${CLI_PREFIX} pull-stubs
  $ ${CLI_PREFIX} pull-stubs --status review
  $ ${CLI_PREFIX} pull-stubs --json`)
  .option('--status <status>', 'Filter by stub status (draft, review, integrated, rejected)', 'draft')
  .option('--registry-url <url>', 'Registry base URL', validateRegistryUrl(process.env.REGISTRY_URL || 'https://api.oa2a.org'))
  .option('--json', 'Output raw JSON instead of formatted table')
  .action(async (opts: {
    status: string;
    registryUrl: string;
    json?: boolean;
  }) => {
    const validStatuses = ['draft', 'review', 'integrated', 'rejected'];
    if (!validStatuses.includes(opts.status)) {
      process.stderr.write(`Error: --status must be one of: ${validStatuses.join(', ')}\n`);
      process.stderr.write(`  Got: ${opts.status}\n`);
      process.exit(1);
    }

    const apiKey = process.env.INTERNAL_API_KEY;
    if (!apiKey) {
      process.stderr.write('Error: INTERNAL_API_KEY environment variable is not set.\n');
      process.stderr.write('\nThis command requires registry authentication.\n');
      process.stderr.write('Set the variable and retry:\n');
      process.stderr.write('  export INTERNAL_API_KEY=<your-key>\n');
      process.stderr.write(`  ${CLI_PREFIX} pull-stubs\n`);
      process.exit(1);
    }

    const registryUrl = validateRegistryUrl(opts.registryUrl).replace(/\/+$/, '');
    const endpoint = `${registryUrl}/internal/aria/hma-stubs`;

    let responseData: { stubs: Array<{
      id: string;
      ariaFindingId: string;
      checkId: string;
      series: string;
      name: string;
      description: string;
      severity: string;
      detectionLogic: string;
      status: string;
      createdAt: string;
      updatedAt: string;
    }>; total: number };

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15_000);
      const res = await fetch(endpoint, {
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Accept': 'application/json',
        },
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (!res.ok) {
        const body = await res.text().catch(() => '');
        process.stderr.write(`Error: Registry returned ${res.status} ${res.statusText}\n`);
        if (res.status === 401 || res.status === 403) {
          process.stderr.write('  Your INTERNAL_API_KEY may be invalid or expired.\n');
        }
        if (body) process.stderr.write(`  ${body.slice(0, 200)}\n`);
        process.exit(1);
      }

      responseData = await res.json() as typeof responseData;
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        process.stderr.write(`Error: Registry request timed out after 15s.\n`);
        process.stderr.write(`  URL: ${endpoint}\n`);
        process.stderr.write(`  Check your network connection and registry URL.\n`);
      } else {
        process.stderr.write(`Error: Could not reach the registry.\n`);
        process.stderr.write(`  URL: ${endpoint}\n`);
        process.stderr.write(`  ${err instanceof Error ? err.message : String(err)}\n`);
      }
      process.exit(1);
    }

    // Filter by status
    const stubs = responseData.stubs.filter(s => s.status === opts.status);

    if (stubs.length === 0) {
      if (opts.json) {
        writeJsonStdout({ stubs: [], total: responseData.total, filtered: 0, status: opts.status });
      } else {
        console.log(`No stubs with status "${opts.status}" found.`);
        if (responseData.total > 0) {
          console.log(`  Registry has ${responseData.total} total stub(s). Try a different --status filter.`);
        }
      }
      return;
    }

    // JSON output mode
    if (opts.json) {
      writeJsonStdout({ stubs, total: responseData.total, filtered: stubs.length, status: opts.status });
      return;
    }

    // Formatted output
    const severityColor: Record<string, string> = {
      critical: colors.brightRed,
      high: colors.red,
      medium: colors.yellow,
      low: colors.cyan,
      info: colors.dim,
    };

    console.log(`\nHMA Check Stubs (status: ${opts.status})\n`);

    for (const stub of stubs) {
      const sc = severityColor[stub.severity?.toLowerCase()] || '';
      console.log(`${'='.repeat(60)}`);
      console.log(`  Check ID:   ${stub.checkId}`);
      console.log(`  Series:     ${stub.series}`);
      console.log(`  Name:       ${stub.name}`);
      console.log(`  Severity:   ${sc}${stub.severity}${colors.reset}`);
      console.log(`  ARIA ID:    ${stub.ariaFindingId}`);
      console.log(`  Status:     ${stub.status}`);
      if (stub.description) {
        console.log(`  Description: ${stub.description}`);
      }
      if (stub.detectionLogic) {
        console.log(`  Detection logic:`);
        for (const line of stub.detectionLogic.split('\n')) {
          console.log(`    ${line}`);
        }
      }
      console.log('');
    }

    // Summary
    console.log('='.repeat(60));
    console.log(`\nSummary`);
    console.log(`  Total in registry:  ${responseData.total}`);
    console.log(`  Matching "${opts.status}":  ${stubs.length}`);

    // By series
    const bySeries: Record<string, number> = {};
    for (const s of stubs) { bySeries[s.series] = (bySeries[s.series] || 0) + 1; }
    console.log(`\n  By series:`);
    for (const [series, count] of Object.entries(bySeries).sort((a, b) => b[1] - a[1])) {
      console.log(`    ${series}: ${count}`);
    }

    // By severity
    const bySeverity: Record<string, number> = {};
    for (const s of stubs) { bySeverity[s.severity] = (bySeverity[s.severity] || 0) + 1; }
    console.log(`\n  By severity:`);
    for (const [sev, count] of Object.entries(bySeverity).sort((a, b) => b[1] - a[1])) {
      const sc = severityColor[sev?.toLowerCase()] || '';
      console.log(`    ${sc}${sev}${colors.reset}: ${count}`);
    }

    console.log('');
  });

// create-skill: generate best-practice, secured skills from plain English
program
  .command('create-skill')
  .argument('<description>', 'What the skill should do (plain English)')
  .description('Generate a complete, secured skill package with SOUL governance')
  .option('-n, --name <name>', 'Skill name (auto-derived if not provided)')
  .option('-o, --output <dir>', 'Output directory')
  .action(async (description: string, options: { name?: string; output?: string }) => {
    const { writeSkill } = await import('./skills/builder.js');
    console.log(`\nGenerating secured skill...\n`);
    const result = writeSkill({ purpose: description, name: options.name, outputDir: options.output });
    const outputDir = options.output ?? result.dirName;
    console.log(`Created ${outputDir}/`);
    for (const file of result.filesWritten) { console.log(`  ${file.split('/').pop()}`); }
    console.log(`\nYour skill is ready. Verify security with: hackmyagent secure ${outputDir}/`);
  });
// ============================================================================
// npm package scanning helpers (used by `check <package>`)
// ============================================================================

/**
 * Detect whether a string looks like a PyPI package reference.
 *
 * Requires an explicit prefix:
 * - pip:package-name
 * - pypi:package-name
 *
 * Bare names are NOT auto-detected as PyPI (they fall through to npm).
 */
function looksLikePyPiPackage(target: string): boolean {
  return target.startsWith('pip:') || target.startsWith('pypi:');
}

/**
 * Detect whether a string looks like an npm package name rather than
 * a hostname, IP address, or local path.
 *
 * npm package names: express, @scope/name, lodash, my-pkg
 * NOT packages: example.com, 192.168.1.1, ./dir, /path, .
 */
function looksLikeNpmPackage(target: string): boolean {
  // Local paths
  if (target.startsWith('.') || target.startsWith('/')) return false;
  // GitHub URLs are not npm packages
  if (looksLikeGitHubRepo(target)) return false;
  // Scoped packages are always npm
  if (target.startsWith('@') && target.includes('/')) return true;
  // IPs
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(target)) return false;
  // Hostnames have dots (example.com, sub.domain.org)
  if (target.includes('.')) return false;
  // What's left: bare names like express, lodash, hackmyagent
  // npm names are lowercase, may contain hyphens and digits
  return /^[a-z0-9][a-z0-9._-]*$/.test(target);
}

/**
 * Detect whether a string looks like a GitHub repository.
 *
 * Matches:
 * - Full URLs: https://github.com/org/repo, http://github.com/org/repo
 * - With .git suffix: https://github.com/org/repo.git
 * - With subpath: https://github.com/org/repo/tree/main/subdir
 * - Shorthand: org/repo (exactly one slash, no dots, not a scoped npm package)
 */
function looksLikeGitHubRepo(target: string): boolean {
  // Full GitHub URLs
  if (/^https?:\/\/(www\.)?github\.com\/[^/]+\/[^/]+/.test(target)) return true;
  // Shorthand: org/repo — exactly one slash, no dots, no @, no protocol
  if (!target.includes(':') && !target.includes('.') && !target.startsWith('@') && !target.startsWith('/')) {
    const parts = target.split('/');
    if (parts.length === 2 && parts[0].length > 0 && parts[1].length > 0) {
      // Both parts must look like GitHub identifiers (alphanumeric, hyphens, underscores)
      return /^[a-zA-Z0-9_-]+$/.test(parts[0]) && /^[a-zA-Z0-9._-]+$/.test(parts[1]);
    }
  }
  return false;
}

/**
 * Detect whether a string is an HTTP(S) URL that is NOT a GitHub repo.
 * GitHub URLs are handled by looksLikeGitHubRepo; this catches everything else:
 * GitLab, Bitbucket, self-hosted git, raw tarballs, zip archives, single files, etc.
 */
function looksLikeRawUrl(target: string): boolean {
  if (looksLikeGitHubRepo(target)) return false;
  return /^https?:\/\/.+/.test(target);
}

/**
 * Parse a GitHub target into org/repo and optional clone URL.
 * Returns { org, repo, cloneUrl }
 */
function parseGitHubTarget(target: string): { org: string; repo: string; cloneUrl: string } {
  // Full URL: https://github.com/org/repo[.git][/tree/...]
  const urlMatch = target.match(/^https?:\/\/(www\.)?github\.com\/([^/]+)\/([^/.]+)/);
  if (urlMatch) {
    return {
      org: urlMatch[2],
      repo: urlMatch[3],
      cloneUrl: `https://github.com/${urlMatch[2]}/${urlMatch[3]}.git`,
    };
  }
  // Shorthand: org/repo
  const parts = target.split('/');
  const repo = parts[1].replace(/\.git$/, '');
  return {
    org: parts[0],
    repo,
    cloneUrl: `https://github.com/${parts[0]}/${repo}.git`,
  };
}

const REGISTRY_URL = 'https://api.oa2a.org';

// ============================================================================
// Scan counter + contribute preference (~/.hackmyagent/config.json)
// ============================================================================

function getConfigPath(): string {
  const { join } = require('node:path');
  const home = process.env.HOME || process.env.USERPROFILE || '/tmp';
  return join(home, '.hackmyagent', 'config.json');
}

function readConfig(): Record<string, unknown> {
  const fs = require('node:fs');
  try {
    return JSON.parse(fs.readFileSync(getConfigPath(), 'utf-8'));
  } catch {
    return {};
  }
}

function writeConfig(config: Record<string, unknown>): void {
  const fs = require('node:fs');
  const { dirname } = require('node:path');
  const configPath = getConfigPath();
  try {
    fs.mkdirSync(dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  } catch {
    // Non-fatal — config is convenience, not critical
  }
}

function incrementScanCounter(): number {
  const config = readConfig();
  const count = ((config.scanCount as number) || 0) + 1;
  writeConfig({ ...config, scanCount: count });
  return count;
}

function hasContributeChoice(): boolean {
  const config = readConfig();
  return config.contribute !== undefined;
}

function isContributeEnabled(): boolean {
  const config = readConfig();
  return config.contribute === true;
}

function saveContributeChoice(enabled: boolean): void {
  const config = readConfig();
  writeConfig({ ...config, contribute: enabled });
}

function queuePendingScan(
  name: string,
  result: { score: number; maxScore: number; projectType: string; findings: SecurityFinding[] },
): void {
  const config = readConfig();
  const queue = (config.pendingScans as Array<Record<string, unknown>>) || [];
  queue.push({
    name,
    score: result.score,
    maxScore: result.maxScore,
    projectType: result.projectType,
    findingCount: result.findings.filter(f => !f.passed).length,
    timestamp: new Date().toISOString(),
  });
  // Keep max 20 pending scans
  writeConfig({ ...config, pendingScans: queue.slice(-20) });
}

async function flushPendingScans(): Promise<void> {
  const config = readConfig();
  const queue = (config.pendingScans as Array<Record<string, unknown>>) || [];
  if (queue.length === 0) return;

  // Try to publish each, keep failures
  const remaining: Array<Record<string, unknown>> = [];
  for (const scan of queue) {
    const ok = await publishToRegistry(scan.name as string, {
      score: scan.score as number,
      maxScore: scan.maxScore as number,
      projectType: scan.projectType as string,
      findings: [], // Summary only for queued scans
    });
    if (!ok) remaining.push(scan);
  }
  writeConfig({ ...config, pendingScans: remaining });
}

interface RegistryTrustData {
  found: boolean;
  name: string;
  trustScore: number;
  trustLevel: number;
  verdict: string;
  scanStatus?: string;
  lastScannedAt?: string;
  packageType?: string;
  recommendation?: string;
  cveCount?: number;
  communityScans?: number;
  dependencies?: {
    totalDeps?: number;
    vulnerableDeps?: number;
    minTrustLevel?: number;
    riskSummary?: Record<string, unknown>;
  };
}

/**
 * Query the OpenA2A Registry for existing trust data.
 * Returns null on any error (network, 404, timeout).
 */
async function queryRegistry(name: string): Promise<RegistryTrustData | null> {
  try {
    const params = new URLSearchParams({ name, includeProfile: 'true' });
    const response = await fetch(`${REGISTRY_URL}/api/v1/trust/query?${params}`, {
      method: 'GET',
      headers: { 'Accept': 'application/json', 'User-Agent': `hackmyagent/${VERSION}` },
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) return null;
    const data = await response.json() as Record<string, unknown>;
    if (!data.packageId) return null;
    const deps = data.dependencies as Record<string, unknown> | undefined;
    return {
      found: true,
      name: (data.name as string) ?? name,
      trustScore: (data.trustScore as number) ?? 0,
      trustLevel: (data.trustLevel as number) ?? 0,
      verdict: (data.verdict as string) ?? 'unknown',
      scanStatus: data.scanStatus as string | undefined,
      lastScannedAt: data.lastScannedAt as string | undefined,
      packageType: data.packageType as string | undefined,
      recommendation: data.recommendation as string | undefined,
      cveCount: typeof data.cveCount === 'number' ? data.cveCount : undefined,
      communityScans: typeof data.communityScans === 'number' ? data.communityScans : undefined,
      dependencies: deps ? {
        totalDeps: typeof deps.totalDeps === 'number' ? deps.totalDeps : undefined,
        vulnerableDeps: typeof deps.vulnerableDeps === 'number' ? deps.vulnerableDeps : undefined,
        minTrustLevel: typeof deps.minTrustLevel === 'number' ? deps.minTrustLevel : undefined,
        riskSummary: deps.riskSummary as Record<string, unknown> | undefined,
      } : undefined,
    };
  } catch {
    return null;
  }
}

/**
 * Check if scan data is stale (older than STALE_SCAN_DAYS).
 */
function isScanStale(lastScannedAt?: string): boolean {
  if (!lastScannedAt) return true;
  const scanned = new Date(lastScannedAt);
  const now = new Date();
  const days = (now.getTime() - scanned.getTime()) / (1000 * 60 * 60 * 24);
  return days > STALE_SCAN_DAYS;
}

/**
 * Publish scan results to the community registry.
 */
async function publishToRegistry(
  name: string,
  result: { score: number; maxScore: number; projectType: string; findings: SecurityFinding[] },
): Promise<boolean> {
  try {
    const response = await fetch(`${REGISTRY_URL}/api/v1/trust/publish`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': `hackmyagent/${VERSION}`,
      },
      body: JSON.stringify({
        name,
        score: result.score,
        maxScore: result.maxScore,
        projectType: result.projectType,
        findings: result.findings
          .filter(f => !PACKAGE_SCAN_LOCAL_ONLY_CATEGORIES.has(f.category))
          .map(f => ({
            checkId: f.checkId,
            name: f.name,
            severity: f.severity,
            passed: f.passed,
            message: f.message,
            category: f.category,
          })),
        scanTimestamp: new Date().toISOString(),
      }),
      signal: AbortSignal.timeout(10000),
    });
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Display registry trust data in the terminal.
 */
function displayRegistryResult(data: RegistryTrustData): void {
  const scoreRatio = data.trustScore;
  const scoreColor = scoreRatio >= 0.7 ? colors.green : scoreRatio >= 0.4 ? colors.yellow : colors.red;
  const score = Math.round(scoreRatio * 100);

  console.log(`\n  ${data.name}`);
  console.log(`  Type:       ${data.packageType ?? 'unknown'}`);
  console.log(`  Score:      ${scoreColor}${score}/100${RESET()}  (registry)`);
  console.log(`  Verdict:    ${data.verdict}`);
  if (data.lastScannedAt) {
    const days = Math.floor((Date.now() - new Date(data.lastScannedAt).getTime()) / (1000 * 60 * 60 * 24));
    console.log(`  Scanned:    ${days === 0 ? 'today' : days + ' day(s) ago'}`);
  }
  printCheckNextSteps(data.name);
}

/**
 * Resolve the "run a check" command string for use in user-facing hints.
 *
 * Precedence:
 *   1. HMA_CHECK_COMMAND env var (full command string, e.g. "opena2a check")
 *   2. `${CLI_PREFIX} check` — sensible default derived from how HMA was
 *      invoked.
 *
 * Parent CLIs should set HMA_CHECK_COMMAND when their verb layout differs
 * from hackmyagent's, rather than trying to encode the full verb into
 * HMA_CLI_PREFIX (which is treated as a binary-level prefix everywhere else).
 */
function getCheckCommand(): string {
  const override = process.env.HMA_CHECK_COMMAND?.trim();
  if (override) return override;
  return `${CLI_PREFIX} check`;
}

/**
 * Resolve the "full project scan" hint command string.
 *
 * Precedence:
 *   1. HMA_FULL_SCAN_HINT env var (full command string, e.g. "opena2a review")
 *   2. `${CLI_PREFIX} secure <dir>` — default.
 */
function getFullScanHint(): string {
  const override = process.env.HMA_FULL_SCAN_HINT?.trim();
  if (override) return override;
  return `${CLI_PREFIX} secure <dir>`;
}

/**
 * Categories that describe local dev-environment setup, not package security.
 * Findings in these categories are filtered from display when scanning a
 * *downloaded* package (npm pack, pip download, git clone to temp dir).
 * They remain visible when scanning a user's own project directory.
 */
const PACKAGE_SCAN_LOCAL_ONLY_CATEGORIES = new Set([
  'git',
  'permissions',
  'environment',
  'logging',
  'claude-code',
  'cursor',
  'vscode',
]);

/**
 * Paths that are AI tooling artifacts, not package source code.
 * Governance findings on these files are noise when scanning a downloaded
 * package or cloned repo — they're instructions to an AI assistant, not
 * security vulnerabilities in the package itself.
 */
const AI_TOOLING_PATH_PATTERNS = [
  /^\.claude\//,
  /^CLAUDE\.md$/i,
  /^\.cursorrules$/i,
  /^\.aider/,
  /^\.copilot\//,
  /^\.github\/copilot/,
];

/** Governance-related categories/checkId prefixes that are noise on AI tooling files */
const GOVERNANCE_CATEGORIES = new Set([
  'governance',
  'injection-hardening',
  'trust-hierarchy',
]);
const GOVERNANCE_CHECK_PREFIXES = ['AST-GOV', 'AST-GOVERN', 'AST-PROMPT'];

/** Test file path patterns — findings here are lower risk */
const TEST_FILE_PATTERNS = [
  /\btests?\//i,
  /\b__tests__\//,
  /\btest_[^/]+$/,
  /[^/]+_test\.\w+$/,
  /[^/]+\.test\.\w+$/,
  /[^/]+\.spec\.\w+$/,
  /\bfixtures?\//i,
];

function isTestFile(filePath: string): boolean {
  return TEST_FILE_PATTERNS.some(p => p.test(filePath));
}

function isAiToolingFile(filePath: string): boolean {
  return AI_TOOLING_PATH_PATTERNS.some(p => p.test(filePath));
}

/**
 * Filter out local-dev-only findings that are meaningless for downloaded
 * packages (e.g. "Missing .gitignore" on an npm tarball).  Also filters
 * governance findings on AI tooling files and demotes test file findings.
 * Mutates `result.findings` in place and recalculates the score.
 */
function filterLocalOnlyFindings(
  result: { findings: SecurityFinding[]; score: number; maxScore: number },
  scanner: HardeningScanner,
): void {
  result.findings = result.findings.filter(f => {
    // Remove local-only categories (git, permissions, env, etc.)
    if (PACKAGE_SCAN_LOCAL_ONLY_CATEGORIES.has(f.category)) return false;

    // Remove governance findings on AI tooling files (CLAUDE.md, .claude/, etc.)
    if (f.file && isAiToolingFile(f.file)) {
      if (GOVERNANCE_CATEGORIES.has(f.category)) return false;
      if (GOVERNANCE_CHECK_PREFIXES.some(p => f.checkId.startsWith(p))) return false;
    }

    return true;
  });

  // Demote test file findings to low severity (test code patterns are
  // lower risk — pickle.load in a test file is not an attack surface)
  for (const f of result.findings) {
    if (f.file && isTestFile(f.file) && (f.severity === 'critical' || f.severity === 'high')) {
      (f as any).originalSeverity = f.severity;
      f.severity = 'low';
    }
  }

  result.score = scanner.calculateScore(
    result.findings.filter((f: any) => !f.passed && !f.fixed),
  ).score;
}

/**
 * Print the standard 3-line next-steps footer shown after every `check`
 * invocation. Lines:
 *   1. How to force a fresh local scan of *this* target.
 *   2. How to run the full project scan (respects HMA_FULL_SCAN_HINT so that
 *      sibling CLIs like opena2a can redirect users to their own flagship
 *      command instead of `hackmyagent secure <dir>`).
 *   3. Discoverability: the other target syntaxes `check` accepts.
 *
 * Suppressed in --ci so machine-readable output stays clean.
 */
function printCheckNextSteps(
  target: string,
  context?: { hasGovernanceIssues?: boolean; hasFindings?: boolean },
): void {
  if (globalCiMode) return;
  console.log();
  console.log(`  ${colors.bold}Next steps${RESET()}`);
  if (context?.hasGovernanceIssues) {
    console.log(`  ${colors.dim}Fix governance issues: ${CLI_PREFIX} harden-soul ${target}${RESET()}`);
  }
  if (context?.hasFindings) {
    console.log(`  ${colors.dim}Full project audit:   ${getFullScanHint()}${RESET()}`);
  } else {
    console.log(`  ${colors.dim}Full project audit:   ${getFullScanHint()}${RESET()}`);
  }
  console.log();
}

/**
 * Search the npm registry for packages similar to the given name.
 * Returns up to 3 package name suggestions. Fails silently on any error.
 */
async function suggestSimilarPackages(name: string): Promise<string[]> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  // Simple Levenshtein distance for filtering relevant suggestions
  function levenshtein(a: string, b: string): number {
    const m = a.length, n = b.length;
    const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
      Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0)
    );
    for (let i = 1; i <= m; i++)
      for (let j = 1; j <= n; j++)
        dp[i][j] = a[i-1] === b[j-1]
          ? dp[i-1][j-1]
          : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    return dp[m][n];
  }

  try {
    // Build search queries: the name itself, plus the unscoped name for scoped packages
    const queries = [name];
    const scopeMatch = name.match(/^@[^/]+\/(.+)$/);
    if (scopeMatch) {
      queries.push(scopeMatch[1]);
    }

    const seen = new Set<string>();
    const candidates: Array<{ name: string; distance: number }> = [];

    for (const query of queries) {
      const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(query)}&size=10`;
      const res = await fetch(url, { signal: controller.signal });
      if (!res.ok) continue;
      const data = await res.json() as { objects?: Array<{ package: { name: string } }> };
      if (!data.objects) continue;
      for (const obj of data.objects) {
        const pkg = obj.package.name;
        if (pkg === name || seen.has(pkg)) continue;
        seen.add(pkg);
        // Compare unscoped names for better matching
        const unscopedInput = name.replace(/^@[^/]+\//, '');
        const unscopedPkg = pkg.replace(/^@[^/]+\//, '');
        const dist = levenshtein(unscopedInput.toLowerCase(), unscopedPkg.toLowerCase());
        // Only suggest if reasonably similar (distance < half the input length + 3)
        const maxDist = Math.floor(unscopedInput.length / 2) + 3;
        if (dist <= maxDist) {
          candidates.push({ name: pkg, distance: dist });
        }
      }
    }

    // Sort by edit distance and return top 3
    candidates.sort((a, b) => a.distance - b.distance);
    return candidates.slice(0, 3).map(c => c.name);
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Clone a GitHub repo (shallow), run full HMA secure scan, display results, clean up.
 * Checks the registry first; only clones if data is missing or stale.
 */
async function checkGitHubRepo(
  target: string,
  options: { verbose?: boolean; json?: boolean; offline?: boolean; rescan?: boolean; scan?: boolean; registry?: boolean },
): Promise<void> {
  const { org, repo, cloneUrl } = parseGitHubTarget(target);
  const displayName = `${org}/${repo}`;

  // Fetch registry data in parallel with clone (unless --no-registry)
  const registryPromise = options.registry === false ? Promise.resolve(null) : queryRegistry(displayName);

  // Registry-only mode (--no-scan): skip local scan
  if (options.scan === false) {
    const registryData = await registryPromise;
    if (registryData?.found) {
      if (options.json) {
        writeJsonStdout({ ...registryData, source: 'registry' });
        return;
      }
      displayUnifiedCheck({ name: displayName, sourceLabel: 'GitHub', registry: registryData, verbose: !!options.verbose });
      return;
    }
    if (!options.json && !globalCiMode) {
      console.error(`No registry data found for ${displayName}. Running local scan...`);
    }
  }

  // Step 2: Clone and scan
  const { mkdtemp, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const execAsync = promisify(execFile);

  if (!options.json && !globalCiMode) {
    console.error(`Cloning ${displayName} from GitHub...`);
  }

  const tempDir = await mkdtemp(join(tmpdir(), 'hma-check-gh-'));

  try {
    // Shallow clone — fast, minimal disk
    await execAsync(
      'git', ['clone', '--depth', '1', '--single-branch', cloneUrl, join(tempDir, repo)],
      { timeout: 120_000 },
    );

    const repoDir = join(tempDir, repo);

    // Run full HMA scan + NanoMind (same pipeline as `secure` and `checkNpmPackage`)
    const scanner = new HardeningScanner();
    const result = await scanner.scan({ targetDir: repoDir, autoFix: false });

    // Run NanoMind semantic analysis and re-filter
    try {
      const { orchestrateNanoMind } = await import('./nanomind-core/orchestrate.js');
      const nmResult = await orchestrateNanoMind(repoDir, result.findings, { silent: true });
      const refiltered = await scanner.reapplyIgnoreFilters(nmResult.mergedFindings, repoDir);
      const projectType = result.projectType || 'library';
      result.findings = refiltered.filter((f: any) =>
        !f.passed && f.file && scanner.findingAppliesTo(f, projectType)
      ) as typeof result.findings;
      result.score = scanner.calculateScore(result.findings.filter((f: any) => !f.passed && !f.fixed)).score;
    } catch {
      // NanoMind unavailable — use base scan results
    }

    // Filter local-dev-only findings irrelevant to cloned repos
    filterLocalOnlyFindings(result, scanner);

    const failed = result.findings.filter(f => !f.passed);
    const critical = failed.filter(f => f.severity === 'critical');
    const high = failed.filter(f => f.severity === 'high');
    const medium = failed.filter(f => f.severity === 'medium');
    const low = failed.filter(f => f.severity === 'low');

    if (options.json) {
      writeJsonStdout({
        name: displayName,
        type: 'github-repo',
        source: 'local-scan',
        projectType: result.projectType,
        score: result.score,
        maxScore: result.maxScore,
        findings: result.findings,
      });
      return;
    }

    // Await registry data (started in parallel with clone)
    const registryData = await registryPromise;

    // Display results using unified display
    displayUnifiedCheck({
      name: displayName,
      sourceLabel: 'GitHub',
      projectType: result.projectType,
      localScan: { score: result.score, maxScore: result.maxScore, findings: result.findings },
      registry: registryData,
      verbose: !!options.verbose,
    });

    // Community contribution
    if (process.stdin.isTTY && !globalCiMode) {
      const scanCount = incrementScanCounter();
      if (scanCount >= 3 && !hasContributeChoice()) {
        console.log(`  ${colors.dim}Your scans help other developers make safer choices.`);
        console.log(`  Sharing adds anonymized results to the OpenA2A trust registry`);
        console.log(`  so others can check packages before installing.${RESET()}`);

        const readline = await import('node:readline');
        const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
        const answer = await new Promise<string>(resolve => {
          rl.question(`\n  Share scans with the community? [Y/n] `, resolve);
        });
        rl.close();

        const wantsToShare = answer.trim().toLowerCase() !== 'n';
        saveContributeChoice(wantsToShare);

        if (wantsToShare) {
          const ok = await publishToRegistry(displayName, result);
          if (ok) {
            console.error(`\n  ${colors.green}Thanks for sharing! Future scans will auto-contribute.${RESET()}\n`);
          } else {
            queuePendingScan(displayName, result);
          }
        }
      } else if (isContributeEnabled()) {
        flushPendingScans();
        const ok = await publishToRegistry(displayName, result);
        if (!ok) queuePendingScan(displayName, result);
      }
    }

    if (critical.length > 0 || high.length > 0) process.exit(1);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('128') || message.includes('not found') || message.includes('Repository not found')) {
      console.error(`Error: Repository "${displayName}" not found on GitHub.`);
      console.error(`\nVerify the URL: https://github.com/${displayName}`);
    } else if (message.includes('timeout') || message.includes('Timeout')) {
      console.error(`Error: Cloning "${displayName}" timed out (120s). The repo may be too large.`);
      console.error(`\nTry cloning manually and scanning the local path:`);
      console.error(`  git clone --depth 1 ${cloneUrl}`);
      console.error(`  ${getCheckCommand()} ./${repo}/`);
    } else {
      console.error(`Error: ${message}`);
    }
    process.exit(1);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

/**
 * Download an npm package, run full HMA secure scan, display results, clean up.
 * Checks the registry first; only downloads if data is missing or stale.
 */
/**
 * Download a PyPI package, scan it with HMA + NanoMind, and display results.
 * Accepts targets prefixed with pip: or pypi: (e.g. pip:requests, pypi:flask).
 */
async function checkPyPiPackage(
  target: string,
  options: { verbose?: boolean; json?: boolean; offline?: boolean; rescan?: boolean; scan?: boolean; registry?: boolean },
): Promise<void> {
  // Strip prefix to get the bare package name
  const name = target.replace(/^(pip|pypi):/, '');

  const { mkdtemp, rm, readdir } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { execFileSync } = await import('node:child_process');

  if (!options.json && !globalCiMode) {
    console.error(`Downloading ${name} from PyPI...`);
  }

  const tempDir = await mkdtemp(join(tmpdir(), 'hma-check-pypi-'));

  try {
    // Fetch package metadata from PyPI JSON API
    const metaRes = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
    if (!metaRes.ok) {
      if (metaRes.status === 404) {
        console.error(`Error: Package "${name}" not found on PyPI.`);
      } else {
        console.error(`Error: PyPI API returned ${metaRes.status} for "${name}".`);
      }
      process.exit(1);
    }

    const meta = await metaRes.json() as {
      urls: Array<{ packagetype: string; url: string; filename: string }>;
      info: { name: string; version: string; summary: string };
    };

    // Prefer sdist (source tarball) for scanning; fall back to first wheel
    const sdist = meta.urls.find((u: any) => u.packagetype === 'sdist');
    const wheel = meta.urls.find((u: any) => u.packagetype === 'bdist_wheel');
    const dist = sdist || wheel || meta.urls[0];

    if (!dist) {
      console.error(`Error: No downloadable distribution found for "${name}" on PyPI.`);
      process.exit(1);
    }

    // Download the archive
    const archiveRes = await fetch(dist.url);
    if (!archiveRes.ok) {
      throw new Error(`Failed to download ${dist.filename}: HTTP ${archiveRes.status}`);
    }
    const archiveBuffer = Buffer.from(await archiveRes.arrayBuffer());
    const archivePath = join(tempDir, dist.filename);
    const { writeFileSync } = await import('node:fs');
    writeFileSync(archivePath, archiveBuffer);

    // Extract
    const extractDir = join(tempDir, 'package');
    const { mkdirSync } = await import('node:fs');
    mkdirSync(extractDir, { recursive: true });

    if (dist.filename.endsWith('.tar.gz') || dist.filename.endsWith('.tgz')) {
      execFileSync('tar', ['xzf', archivePath, '-C', extractDir, '--strip-components=1'], { timeout: 30_000 });
    } else if (dist.filename.endsWith('.zip') || dist.filename.endsWith('.whl')) {
      execFileSync('unzip', ['-q', '-o', archivePath, '-d', extractDir], { timeout: 30_000 });
    } else {
      throw new Error(`Unsupported archive format: ${dist.filename}`);
    }

    // Run full HMA scan + NanoMind (same pipeline as checkNpmPackage)
    const scanner = new HardeningScanner();
    const result = await scanner.scan({ targetDir: extractDir, autoFix: false });

    // Run NanoMind semantic analysis and re-filter
    try {
      const { orchestrateNanoMind } = await import('./nanomind-core/orchestrate.js');
      const nmResult = await orchestrateNanoMind(extractDir, result.findings, { silent: true });
      const refiltered = await scanner.reapplyIgnoreFilters(nmResult.mergedFindings, extractDir);
      const projectType = result.projectType || 'library';
      result.findings = refiltered.filter((f: any) =>
        !f.passed && f.file && scanner.findingAppliesTo(f, projectType)
      ) as typeof result.findings;
      result.score = scanner.calculateScore(result.findings.filter((f: any) => !f.passed && !f.fixed)).score;
    } catch {
      // NanoMind unavailable -- use base scan results
    }

    // Filter local-dev-only findings irrelevant to downloaded packages
    filterLocalOnlyFindings(result, scanner);

    const failed = result.findings.filter(f => !f.passed);
    const critical = failed.filter(f => f.severity === 'critical');
    const high = failed.filter(f => f.severity === 'high');
    const medium = failed.filter(f => f.severity === 'medium');
    const low = failed.filter(f => f.severity === 'low');

    if (options.json) {
      writeJsonStdout({
        name,
        type: 'pypi-package',
        source: 'local-scan',
        version: meta.info.version,
        projectType: result.projectType,
        score: result.score,
        maxScore: result.maxScore,
        findings: result.findings,
      });
      return;
    }

    // Display results using unified display
    // Query registry for trust context (PyPI packages have pip: prefix in registry)
    const registryData = options.registry === false ? null : await queryRegistry(`pip:${name}`);

    displayUnifiedCheck({
      name,
      sourceLabel: 'PyPI',
      projectType: result.projectType,
      version: meta.info.version,
      localScan: { score: result.score, maxScore: result.maxScore, findings: result.findings },
      registry: registryData,
      verbose: !!options.verbose,
    });

    if (critical.length > 0 || high.length > 0) process.exit(1);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('not found on PyPI')) {
      console.error(`Error: ${message}`);
    } else {
      console.error(`Error scanning PyPI package "${name}": ${message}`);
    }
    process.exit(1);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

/**
 * Fetch a raw URL, detect its type (git repo, tarball, zip, or single file),
 * download to a temp dir, run full HMA + NanoMind scan, display results, clean up.
 */
async function checkRawUrl(
  url: string,
  options: { verbose?: boolean; json?: boolean; offline?: boolean },
): Promise<void> {
  const { mkdtemp, rm, writeFile, readdir } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join, basename } = await import('node:path');
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const execAsync = promisify(execFile);

  const tempDir = await mkdtemp(join(tmpdir(), 'hma-check-url-'));
  let scanDir = tempDir;
  let displayName = url;

  try {
    // Git clone for known forge URLs and .git suffix
    const isGitUrl = url.endsWith('.git')
      || /^https?:\/\/(gitlab\.com|bitbucket\.org|codeberg\.org|gitea\.com|sr\.ht)\//.test(url);

    if (isGitUrl) {
      const repoName = basename(url.replace(/\.git$/, '')) || 'repo';
      displayName = url.replace(/^https?:\/\//, '').replace(/\.git$/, '');

      if (!options.json && !globalCiMode) {
        console.error(`Cloning ${displayName}...`);
      }

      await execAsync(
        'git', ['clone', '--depth', '1', '--single-branch', url, join(tempDir, repoName)],
        { timeout: 120_000 },
      );
      scanDir = join(tempDir, repoName);
    } else {
      // HTTP fetch — use HEAD to determine content type
      if (!options.json && !globalCiMode) {
        console.error(`Fetching ${url}...`);
      }

      const headRes = await fetch(url, { method: 'HEAD', redirect: 'follow' });
      if (!headRes.ok) {
        console.error(`Error: HTTP ${headRes.status} fetching "${url}".`);
        process.exit(1);
      }

      const contentType = headRes.headers.get('content-type') || '';
      const finalUrl = headRes.url;
      const fileName = basename(new URL(finalUrl).pathname) || 'download';

      const isArchive = /\.(tar\.gz|tgz|tar\.bz2|tar\.xz|zip)$/i.test(fileName)
        || contentType.includes('gzip')
        || contentType.includes('tar')
        || contentType.includes('zip')
        || contentType.includes('compressed');

      const bodyRes = await fetch(finalUrl, { redirect: 'follow' });
      if (!bodyRes.ok || !bodyRes.body) {
        console.error(`Error: Failed to download "${url}" (HTTP ${bodyRes.status}).`);
        process.exit(1);
      }
      const buffer = Buffer.from(await bodyRes.arrayBuffer());

      if (isArchive) {
        const archivePath = join(tempDir, fileName);
        await writeFile(archivePath, buffer);

        const extractDir = join(tempDir, 'extracted');
        await execAsync('mkdir', ['-p', extractDir]);

        if (/\.(tar\.gz|tgz)$/i.test(fileName) || contentType.includes('gzip') || contentType.includes('tar')) {
          await execAsync('tar', ['xzf', archivePath, '-C', extractDir], { timeout: 30_000 });
        } else if (/\.tar\.bz2$/i.test(fileName)) {
          await execAsync('tar', ['xjf', archivePath, '-C', extractDir], { timeout: 30_000 });
        } else if (/\.tar\.xz$/i.test(fileName)) {
          await execAsync('tar', ['xJf', archivePath, '-C', extractDir], { timeout: 30_000 });
        } else if (/\.zip$/i.test(fileName)) {
          await execAsync('unzip', ['-q', archivePath, '-d', extractDir], { timeout: 30_000 });
        }

        // If extraction produced a single directory, scan that
        const entries = await readdir(extractDir);
        if (entries.length === 1) {
          const { statSync } = await import('node:fs');
          const innerPath = join(extractDir, entries[0]);
          if (statSync(innerPath).isDirectory()) {
            scanDir = innerPath;
          } else {
            scanDir = extractDir;
          }
        } else {
          scanDir = extractDir;
        }

        displayName = fileName;
      } else {
        // Single file: save for scanning
        await writeFile(join(tempDir, fileName), buffer);
        scanDir = tempDir;
        displayName = fileName;
      }
    }

    // Run full HMA scan + NanoMind
    const scanner = new HardeningScanner();
    const result = await scanner.scan({ targetDir: scanDir, autoFix: false });

    try {
      const { orchestrateNanoMind } = await import('./nanomind-core/orchestrate.js');
      const nmResult = await orchestrateNanoMind(scanDir, result.findings, { silent: true });
      const refiltered = await scanner.reapplyIgnoreFilters(nmResult.mergedFindings, scanDir);
      const projectType = result.projectType || 'library';
      result.findings = refiltered.filter((f: any) =>
        !f.passed && f.file && scanner.findingAppliesTo(f, projectType)
      ) as typeof result.findings;
      result.score = scanner.calculateScore(result.findings.filter((f: any) => !f.passed && !f.fixed)).score;
    } catch {
      // NanoMind unavailable — use base scan results
    }

    // Filter local-dev-only findings irrelevant to downloaded URLs
    filterLocalOnlyFindings(result, scanner);

    const failed = result.findings.filter(f => !f.passed);
    const critical = failed.filter(f => f.severity === 'critical');
    const high = failed.filter(f => f.severity === 'high');
    const medium = failed.filter(f => f.severity === 'medium');
    const low = failed.filter(f => f.severity === 'low');

    if (options.json) {
      writeJsonStdout({
        name: displayName,
        url,
        type: 'raw-url',
        source: 'local-scan',
        projectType: result.projectType,
        score: result.score,
        maxScore: result.maxScore,
        findings: result.findings,
      });
      return;
    }

    // Display results using unified display
    displayUnifiedCheck({
      name: displayName,
      sourceLabel: 'URL',
      projectType: result.projectType,
      localScan: { score: result.score, maxScore: result.maxScore, findings: result.findings },
      verbose: !!options.verbose,
    });

    // Community contribution (auto-share if opted in, no first-time prompt for URLs)
    if (process.stdin.isTTY && !globalCiMode) {
      if (isContributeEnabled()) {
        flushPendingScans();
        const ok = await publishToRegistry(displayName, result);
        if (!ok) queuePendingScan(displayName, result);
      }
    }

    if (critical.length > 0 || high.length > 0) process.exit(1);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('128') || message.includes('not found') || message.includes('Repository not found')) {
      console.error(`Error: Could not clone repository from "${url}".`);
      console.error(`\nVerify the URL is accessible and contains a git repository.`);
    } else if (message.includes('timeout') || message.includes('Timeout')) {
      console.error(`Error: Fetching "${url}" timed out. The target may be too large.`);
      console.error(`\nTry downloading manually and scanning the local path:`);
      console.error(`  ${getCheckCommand()} ./downloaded-dir/`);
    } else {
      console.error(`Error scanning URL: ${message}`);
    }
    process.exit(1);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

async function checkNpmPackage(
  name: string,
  options: { verbose?: boolean; json?: boolean; offline?: boolean; rescan?: boolean; scan?: boolean; registry?: boolean },
): Promise<void> {
  // Fetch registry data in parallel with download+scan (unless --no-registry)
  const registryPromise = options.registry === false ? Promise.resolve(null) : queryRegistry(name);

  // Registry-only mode (--no-scan): skip local scan
  if (options.scan === false) {
    const registryData = await registryPromise;
    if (registryData?.found) {
      if (options.json) {
        writeJsonStdout({ ...registryData, source: 'registry' });
        return;
      }
      displayUnifiedCheck({ name, registry: registryData, verbose: !!options.verbose });
      return;
    }
    if (!options.json && !globalCiMode) {
      console.error(`No registry data found for ${name}. Running local scan...`);
    }
  }

  // Download and scan
  const { mkdtemp, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const execAsync = promisify(execFile);

  if (!options.json && !globalCiMode) {
    console.error(`Downloading ${name} from npm...`);
  }

  const tempDir = await mkdtemp(join(tmpdir(), 'hma-check-'));

  try {
    // Download and extract
    const { stdout } = await execAsync(
      'npm', ['pack', name, '--pack-destination', tempDir],
      { timeout: 60_000 },
    );
    const tarball = stdout.trim().split('\n').pop()!;
    await execAsync('tar', ['xzf', join(tempDir, tarball), '-C', tempDir], { timeout: 30_000 });

    const packageDir = join(tempDir, 'package');

    // Run full HMA scan + NanoMind (same pipeline as `secure`)
    const scanner = new HardeningScanner();
    const result = await scanner.scan({ targetDir: packageDir, autoFix: false });

    // Run NanoMind semantic analysis and re-filter (matches secure command pipeline)
    try {
      const { orchestrateNanoMind } = await import('./nanomind-core/orchestrate.js');
      const nmResult = await orchestrateNanoMind(packageDir, result.findings, { silent: true });
      const refiltered = await scanner.reapplyIgnoreFilters(nmResult.mergedFindings, packageDir);
      const projectType = result.projectType || 'library';
      result.findings = refiltered.filter((f: any) =>
        !f.passed && f.file && scanner.findingAppliesTo(f, projectType)
      ) as typeof result.findings;
      result.score = scanner.calculateScore(result.findings.filter((f: any) => !f.passed && !f.fixed)).score;
    } catch {
      // NanoMind unavailable — use base scan results
    }

    // Filter local-dev-only findings irrelevant to downloaded packages
    filterLocalOnlyFindings(result, scanner);

    const failed = result.findings.filter(f => !f.passed);
    const critical = failed.filter(f => f.severity === 'critical');
    const high = failed.filter(f => f.severity === 'high');

    if (options.json) {
      writeJsonStdout({
        name,
        type: 'npm-package',
        source: 'local-scan',
        projectType: result.projectType,
        score: result.score,
        maxScore: result.maxScore,
        findings: result.findings,
      });
      return;
    }

    // Await registry data (started in parallel with download)
    const registryData = await registryPromise;

    // Display results using unified display
    displayUnifiedCheck({
      name,
      projectType: result.projectType,
      localScan: { score: result.score, maxScore: result.maxScore, findings: result.findings },
      registry: registryData,
      verbose: !!options.verbose,
    });

    // Community contribution (after 3 scans, interactive only)
    if (process.stdin.isTTY && !globalCiMode) {
      const scanCount = incrementScanCounter();
      if (scanCount >= 3 && !hasContributeChoice()) {
        console.log(`  ${colors.dim}Your scans help other developers make safer choices.`);
        console.log(`  Sharing adds anonymized results to the OpenA2A trust registry`);
        console.log(`  so others can check packages before installing.${RESET()}`);

        const readline = await import('node:readline');
        const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
        const answer = await new Promise<string>(resolve => {
          rl.question(`\n  Share scans with the community? [Y/n] `, resolve);
        });
        rl.close();

        const wantsToShare = answer.trim().toLowerCase() !== 'n';
        saveContributeChoice(wantsToShare);

        if (wantsToShare) {
          const ok = await publishToRegistry(name, result);
          if (ok) {
            console.error(`\n  ${colors.green}Thanks for sharing! Future scans will auto-contribute.${RESET()}\n`);
          } else {
            queuePendingScan(name, result);
          }
        }
      } else if (isContributeEnabled()) {
        // Auto-share silently, queue on failure
        flushPendingScans();
        const ok = await publishToRegistry(name, result);
        if (!ok) queuePendingScan(name, result);
      }
    }

    if (critical.length > 0 || high.length > 0) process.exit(1);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    // Clean npm error messages
    if (message.includes('404') || message.includes('Not Found')) {
      console.error(`Error: Package "${name}" not found on npm.`);
      // Suggest similar packages via npm registry search
      try {
        const suggestions = await suggestSimilarPackages(name);
        if (suggestions.length > 0) {
          console.error(`\nDid you mean?`);
          for (const s of suggestions) {
            console.error(`  ${s}`);
          }
          console.error();
        }
      } catch {
        // Search failed — just show the original error
      }
    } else {
      console.error(`Error: ${message}`);
    }
    process.exit(1);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

// Self-securing: verify own integrity before running any command
// A security tool that doesn't verify itself is worse than no security tool
(async () => {
  try {
    const { verifyAll } = await import('./nanomind-core/security/integrity-verifier.js');
    const integrity = await verifyAll();

    if (integrity.status === 'QUARANTINE') {
      // Binary tampered -- refuse to run
      process.stderr.write(
        '\nINTEGRITY CHECK FAILED: HackMyAgent binary may have been tampered with.\n' +
        'This could indicate a supply chain attack.\n\n' +
        'Actions:\n' +
        '  1. Reinstall: npm install -g hackmyagent\n' +
        '  2. Verify: npm audit signatures\n' +
        '  3. Report: https://github.com/opena2a-org/hackmyagent/security\n\n'
      );
      for (const check of integrity.checks.filter(c => !c.passed)) {
        process.stderr.write(`  Failed: ${check.name} -- ${check.reason}\n`);
      }
      process.exit(3); // Exit code 3 = integrity failure
    }

    if (integrity.status === 'DEGRADE') {
      // Model or rules tampered -- warn but continue with fallback
      process.stderr.write(
        '\nIntegrity warning: some components could not be verified.\n' +
        'Continuing with baseline analysis (reduced accuracy).\n\n'
      );
    }
  } catch {
    // Integrity check itself failed -- continue (don't block on missing manifest in dev)
  }

  // Global --ci flag: strip from argv so individual commands don't reject it.
  // Any command can check globalCiMode to adjust behavior.
  if (process.argv.includes('--ci')) {
    globalCiMode = true;
    process.argv = process.argv.filter(a => a !== '--ci');
  }

  if (process.argv.length <= 2) {
    program.outputHelp();
    process.exit(0);
  }

  program.parse();
})();

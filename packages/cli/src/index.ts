#!/usr/bin/env node
/**
 * HackMyAgent CLI
 * Security scanning tool for AI agents
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
} from 'hackmyagent-core';

const program = new Command();

// Check for NO_COLOR env or non-TTY to disable colors by default
const noColorEnv = process.env.NO_COLOR !== undefined || process.stdout.isTTY === false;

// Color codes - will be cleared if --no-color is passed
let colors = {
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  brightRed: '\x1b[91m',
  cyan: '\x1b[36m',
  reset: '\x1b[0m',
};

if (noColorEnv) {
  colors = { green: '', yellow: '', red: '', brightRed: '', cyan: '', reset: '' };
}

program
  .name('hackmyagent')
  .description(`Security toolkit for AI agents

HackMyAgent helps you secure AI agent deployments with 100+ security checks
across credential exposure, MCP configurations, prompt injection defenses,
and infrastructure hardening.

Documentation: https://github.com/ecolibria/hackmyagent

Examples:
  $ hackmyagent check @anthropic/claude-mcp    Verify skill before installing
  $ hackmyagent secure                         Scan current directory
  $ hackmyagent secure --fix                   Auto-fix security issues
  $ hackmyagent secure --fix --dry-run         Preview fixes without applying
  $ hackmyagent scan example.com               Scan external infrastructure`)
  .version(VERSION, '-V, --version', 'Output the version number')
  .option('--no-color', 'Disable colored output (also respects NO_COLOR env)')
  .hook('preAction', (thisCommand) => {
    const opts = thisCommand.opts();
    if (opts.color === false) {
      colors = { green: '', yellow: '', red: '', brightRed: '', cyan: '', reset: '' };
    }
  });

// Risk level colors and symbols
const RISK_DISPLAY: Record<RiskLevel, { symbol: string; color: () => string }> = {
  low: { symbol: '✅', color: () => colors.green },
  medium: { symbol: '⚠️', color: () => colors.yellow },
  high: { symbol: '🔴', color: () => colors.red },
  critical: { symbol: '🚨', color: () => colors.brightRed },
};
const RESET = () => colors.reset;

program
  .command('check')
  .description(`Verify a skill before installing

Analyzes skill safety by checking:
  • Publisher identity via DNS TXT records
  • Permissions requested (filesystem, network, shell)
  • Revocation status against global blocklist

Risk levels: low, medium, high, critical
Exit code 1 if high/critical risk detected.

Examples:
  $ hackmyagent check @anthropic/claude-mcp
  $ hackmyagent check @publisher/skill --verbose
  $ hackmyagent check @publisher/skill --json`)
  .argument('<skill>', 'Skill identifier (e.g., @publisher/skill)')
  .option('-v, --verbose', 'Show detailed verification info')
  .option('--json', 'Output as JSON (for scripting/CI)')
  .option('--offline', 'Skip DNS verification (offline mode)')
  .action(async (skill: string, options: { verbose?: boolean; json?: boolean; offline?: boolean }) => {
    try {
      const result = await checkSkill(skill, {
        skipDnsVerification: options.offline,
      });

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      const risk = RISK_DISPLAY[result.risk];
      console.log(`\n${risk.color()}${risk.symbol} ${result.risk.toUpperCase()} RISK${RESET()}\n`);

      // Publisher info
      console.log(`Publisher: @${result.publisher.name}`);
      if (result.publisher.verified) {
        console.log(`├─ ✅ Verified via DNS`);
        if (result.publisher.domain) {
          console.log(`├─ 🌐 Domain: ${result.publisher.domain}`);
        }
        if (result.publisher.verifiedAt && options.verbose) {
          console.log(`└─ 📅 Verified at: ${result.publisher.verifiedAt.toISOString()}`);
        } else {
          console.log(`└─ Method: DNS TXT record`);
        }
      } else {
        console.log(`├─ ❌ Not verified`);
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
          console.log(`├─ ✅ ${perm}`);
        }
        for (const perm of result.permissions.reviewNeeded) {
          console.log(`├─ ⚠️  ${perm} (review needed)`);
        }
        for (const perm of result.permissions.dangerous) {
          console.log(`├─ ❌ ${perm} (DANGEROUS)`);
        }
        console.log(`└─ Risk score: ${result.permissions.riskScore}/100`);
      }
      console.log();

      // Revocation
      console.log('Revocation:');
      if (result.revocation.revoked) {
        console.log(`└─ 🚨 REVOKED: ${result.revocation.reason}`);
      } else {
        console.log(`└─ ✅ Not on blocklist`);
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
  critical: { symbol: '🔴', color: () => colors.brightRed },
  high: { symbol: '🟠', color: () => colors.red },
  medium: { symbol: '🟡', color: () => colors.yellow },
  low: { symbol: '🟢', color: () => colors.green },
};

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

program
  .command('secure')
  .description(`Scan and harden your agent setup

Performs 100 security checks across 24 categories:
  • Credentials: API key exposure, secrets in configs
  • MCP: Server configs, tool permissions, secrets
  • Network: TLS, interface bindings, CORS
  • Prompt: Injection defenses, role protection
  • Encryption: At-rest encryption, secure hashing
  • And 19 more categories...

Severities: critical, high, medium, low
Exit code 1 if critical/high issues found.

Examples:
  $ hackmyagent secure                         Scan current directory
  $ hackmyagent secure ./my-project            Scan specific directory
  $ hackmyagent secure --fix                   Auto-fix issues
  $ hackmyagent secure --fix --dry-run         Preview fixes
  $ hackmyagent secure --ignore CRED-001       Skip specific checks
  $ hackmyagent secure --json                  JSON output for CI`)
  .argument('[directory]', 'Directory to scan (defaults to current directory)', '.')
  .option('--fix', 'Automatically fix issues where possible')
  .option('--dry-run', 'Preview fixes without applying them (use with --fix)')
  .option('--ignore <checks>', 'Comma-separated check IDs to skip (e.g., CRED-001,GIT-002)')
  .option('--json', 'Output as JSON (for scripting/CI)')
  .option('-v, --verbose', 'Show all checks including passed ones')
  .action(async (directory: string, options: { fix?: boolean; dryRun?: boolean; ignore?: string; json?: boolean; verbose?: boolean }) => {
    try {
      const targetDir = directory.startsWith('/') ? directory : process.cwd() + '/' + directory;

      // Parse ignore list
      const ignoreList = options.ignore
        ? options.ignore.split(',').map((s) => s.trim()).filter(Boolean)
        : [];

      if (options.dryRun) {
        console.log(`\n🔍 Scanning ${targetDir} (dry-run)...\n`);
      } else {
        console.log(`\n🔍 Scanning ${targetDir}...\n`);
      }

      const scanner = new HardeningScanner();
      const result = await scanner.scan({
        targetDir,
        autoFix: options.fix ?? false,
        dryRun: options.dryRun ?? false,
        ignore: ignoreList,
      });

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
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

      console.log(`${projectTypeLabel} | Score: ${result.score}/${result.maxScore}\n`);

      // No issues? Say so and exit
      if (issues.length === 0 && fixedFindings.length === 0) {
        console.log(`${colors.green}No issues found.${RESET()}\n`);
      } else if (issues.length > 0) {
        // Print issues - clean format
        console.log(`${issues.length} issue${issues.length === 1 ? '' : 's'} found:\n`);

        for (const finding of issues) {
          const display = SEVERITY_DISPLAY[finding.severity];
          const location = finding.file
            ? finding.line
              ? `${finding.file}:${finding.line}`
              : finding.file
            : '';

          // Format: SEVERITY  file:line
          //         Description
          //         Fix: command
          console.log(`${display.color()}${display.symbol} ${finding.severity.toUpperCase()}${RESET()}  ${location}`);
          console.log(`       ${finding.description}`);
          if (finding.fix) {
            console.log(`       ${colors.cyan}Fix:${RESET()} ${finding.fix}`);
          }
          console.log();
        }
      }

      // Print fixed findings
      if (fixedFindings.length > 0) {
        console.log(`${colors.green}Fixed ${fixedFindings.length} issue${fixedFindings.length === 1 ? '' : 's'}:${RESET()}`);
        for (const finding of fixedFindings) {
          const location = finding.file || '';
          console.log(`  ${colors.green}✓${RESET()} ${location} - ${finding.name}`);
        }
        console.log();

        if (result.backupPath) {
          console.log(`Backup: ${result.backupPath}`);
          console.log(`Undo: hackmyagent rollback ${directory}\n`);
        }
      }

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

// Severity display for external scan findings
const FINDING_SEVERITY_DISPLAY: Record<FindingSeverity, { symbol: string; color: () => string }> = {
  critical: { symbol: '🔴', color: () => colors.brightRed },
  high: { symbol: '🟠', color: () => colors.red },
  medium: { symbol: '🟡', color: () => colors.yellow },
  low: { symbol: '🟢', color: () => colors.green },
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
      level: 'CRITICAL',
      color: colors.brightRed,
      description: 'Immediate action required. Your OpenClaw installation has critical vulnerabilities.',
    };
  }
  if (highCount > 0) {
    return {
      level: 'HIGH',
      color: colors.red,
      description: 'Significant risks detected. Address high-severity issues promptly.',
    };
  }
  if (mediumCount > 0) {
    return {
      level: 'MODERATE',
      color: colors.yellow,
      description: 'Some issues found. Review and address when possible.',
    };
  }
  return {
    level: 'LOW',
    color: colors.green,
    description: 'Your OpenClaw installation appears well-secured.',
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
        console.log(`\n🦞 OpenClaw Security Report`);
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
        if (options.dryRun) {
          console.log(`🔍 Scanning ${targetDir} (dry-run)...\n`);
        } else {
          console.log(`🔍 Scanning ${targetDir}...\n`);
        }
      }

      const scanner = new HardeningScanner();
      const result = await scanner.scan({
        targetDir,
        autoFix: options.fix ?? false,
        dryRun: options.dryRun ?? false,
        ignore: [],
      });

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
        console.log(JSON.stringify(jsonOutput, null, 2));
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
        console.log(`${colors.red}Issues Found:${RESET()}\n`);

        for (const finding of issues) {
          const display = SEVERITY_DISPLAY[finding.severity];
          const location = finding.file
            ? finding.line
              ? `${finding.file}:${finding.line}`
              : finding.file
            : '';

          console.log(`${display.color()}${display.symbol} [${finding.checkId}] ${finding.severity.toUpperCase()}${RESET()}`);
          console.log(`   ${finding.description}`);
          if (location) {
            console.log(`   File: ${location}`);
          }
          if (finding.fix) {
            console.log(`   ${colors.cyan}Fix:${RESET()} ${finding.fix}`);
          }
          console.log();
        }
      } else {
        console.log(`${colors.green}No OpenClaw-specific issues found.${RESET()}\n`);
      }

      // Show fixed findings
      if (fixedFindings.length > 0) {
        console.log(`${colors.green}Fixed Issues:${RESET()}`);
        for (const finding of fixedFindings) {
          console.log(`  ${colors.green}✓${RESET()} [${finding.checkId}] ${finding.name}`);
        }
        console.log();

        if (result.backupPath) {
          console.log(`Backup: ${result.backupPath}`);
          console.log(`Undo: hackmyagent rollback ${targetDir}\n`);
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
      console.log(`Run 'hackmyagent secure' for a full security scan.\n`);

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

Scoring: A (90-100), B (80-89), C (70-79), D (60-69), F (<60)
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
        console.log(`\n🔍 Scanning ${target}...\n`);

        const scanner = new ExternalScanner();
        const customPorts = options.ports
          ? options.ports.split(',').map((p) => parseInt(p.trim(), 10))
          : undefined;

        const result = await scanner.scan(target, {
          ports: customPorts,
          timeout: parseInt(options.timeout ?? '5000', 10),
        });

        if (options.json) {
          console.log(JSON.stringify(result, null, 2));
          return;
        }

        // Print header
        const gradeColor =
          result.grade === 'A'
            ? colors.green
            : result.grade === 'B'
              ? colors.green
              : result.grade === 'C'
                ? colors.yellow
                : colors.red;
        console.log(`Target: ${result.target}`);
        console.log(`Score: ${gradeColor}${result.score}/100 (${result.grade})${RESET()}`);
        console.log(`Open Ports: ${result.openPorts.length > 0 ? result.openPorts.join(', ') : 'None detected'}`);
        console.log(`Duration: ${result.duration}ms\n`);

        if (result.findings.length === 0) {
          console.log(`${colors.green}✅ No security issues found!${RESET()}\n`);
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
      const targetDir = directory.startsWith('/') ? directory : process.cwd() + '/' + directory;

      console.log(`\n🔄 Rolling back changes in ${targetDir}...\n`);

      const scanner = new HardeningScanner();
      await scanner.rollback(targetDir);

      console.log(`${colors.green}✅ Rollback successful!${RESET()}`);
      console.log('   All auto-fix changes have been reverted.\n');
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      process.exit(1);
    }
  });

program.parse();

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
} from '@hackmyagent/core';

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
  .description('Security toolkit for AI agents')
  .version(VERSION)
  .option('--no-color', 'Disable colored output')
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
  .description('Verify a skill before installing')
  .argument('<skill>', 'Skill identifier (e.g., @publisher/skill)')
  .option('-v, --verbose', 'Enable verbose output')
  .option('--json', 'Output as JSON')
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
  .description('Scan and harden your agent setup')
  .argument('[directory]', 'Directory to scan (defaults to current directory)', '.')
  .option('--fix', 'Automatically fix issues where possible')
  .option('--dry-run', 'Preview fixes without applying them (use with --fix)')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show all checks including passed ones')
  .action(async (directory: string, options: { fix?: boolean; dryRun?: boolean; json?: boolean; verbose?: boolean }) => {
    try {
      const targetDir = directory.startsWith('/') ? directory : process.cwd() + '/' + directory;

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
      });

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      // Group findings by severity
      const failedFindings = result.findings.filter((f) => !f.passed && !f.fixed && !f.wouldFix);
      const fixedFindings = result.findings.filter((f) => f.fixed);
      const wouldFixFindings = result.findings.filter((f) => f.wouldFix);
      const passedFindings = result.findings.filter((f) => f.passed);

      const grouped = groupFindingsBySeverity(failedFindings);

      // Print header
      console.log(`Platform: ${result.platform}`);
      console.log(`Security Score: ${result.score}/${result.maxScore}\n`);

      // Print failed findings by severity
      let hasIssues = false;
      for (const severity of ['critical', 'high', 'medium', 'low'] as Severity[]) {
        const findings = grouped[severity];
        if (findings.length === 0) continue;

        hasIssues = true;
        const display = SEVERITY_DISPLAY[severity];
        console.log(`${display.color()}${display.symbol} ${severity.toUpperCase()} (${findings.length})${RESET()}`);

        for (const finding of findings) {
          console.log(`   • [${finding.checkId}] ${finding.name}`);
          console.log(`     ${finding.message}`);
          if (finding.fixable && !options.fix) {
            console.log(`     💡 Auto-fixable with --fix`);
          }
        }
        console.log();
      }

      // Print fixed findings
      if (fixedFindings.length > 0) {
        console.log(`${colors.green}✅ FIXED (${fixedFindings.length})${RESET()}`);
        for (const finding of fixedFindings) {
          console.log(`   • [${finding.checkId}] ${finding.name}`);
          if (finding.fixMessage) {
            console.log(`     ${finding.fixMessage}`);
          }
        }
        console.log();

        // Show backup info
        if (result.backupPath) {
          console.log(`📦 Backup created: ${result.backupPath}`);
          console.log(`   Run 'hackmyagent rollback ${directory}' to undo changes\n`);
        }
      }

      // Print would-fix findings (dry-run mode)
      if (wouldFixFindings.length > 0) {
        console.log(`${colors.cyan}🔮 WOULD FIX (${wouldFixFindings.length})${RESET()}`);
        for (const finding of wouldFixFindings) {
          console.log(`   • [${finding.checkId}] ${finding.name}`);
          console.log(`     ${finding.message}`);
        }
        console.log();
        console.log(`💡 Run with --fix (without --dry-run) to apply these fixes\n`);
      }

      // Print passed findings in verbose mode
      if (options.verbose && passedFindings.length > 0) {
        console.log(`${colors.green}✅ PASSED (${passedFindings.length})${RESET()}`);
        for (const finding of passedFindings) {
          console.log(`   • [${finding.checkId}] ${finding.name}`);
        }
        console.log();
      }

      // Summary
      if (!hasIssues && fixedFindings.length === 0) {
        console.log(`${colors.green}✅ No security issues found!${RESET()}\n`);
      } else if (hasIssues && !options.fix) {
        const fixableCount = failedFindings.filter((f) => f.fixable).length;
        if (fixableCount > 0) {
          console.log(`💡 Run with --fix to automatically fix ${fixableCount} issue(s)\n`);
        }
      }

      // Exit with non-zero if critical/high issues remain
      const criticalOrHigh = failedFindings.filter(
        (f) => f.severity === 'critical' || f.severity === 'high'
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

program
  .command('scan')
  .description('Scan external target for exposed MCP endpoints and misconfigurations')
  .argument('<target>', 'Target hostname or IP address')
  .option('--json', 'Output as JSON')
  .option('-p, --ports <ports>', 'Comma-separated list of ports to scan')
  .option('-t, --timeout <ms>', 'Timeout in milliseconds', '5000')
  .option('-v, --verbose', 'Show detailed findings')
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
  .description('Rollback auto-fix changes to the most recent backup')
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

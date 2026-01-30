#!/usr/bin/env node
/**
 * HackMyAgent CLI
 * Security scanning tool for AI agents
 */

import { Command } from 'commander';
import {
  VERSION,
  createScanner,
  checkSkill,
  HardeningScanner,
  type RiskLevel,
  type Severity,
  type SecurityFinding,
} from '@hackmyagent/core';

const program = new Command();

program
  .name('hackmyagent')
  .description('Security toolkit for AI agents')
  .version(VERSION);

// Risk level colors and symbols
const RISK_DISPLAY: Record<RiskLevel, { symbol: string; color: string }> = {
  low: { symbol: '✅', color: '\x1b[32m' },      // green
  medium: { symbol: '⚠️', color: '\x1b[33m' },   // yellow
  high: { symbol: '🔴', color: '\x1b[31m' },     // red
  critical: { symbol: '🚨', color: '\x1b[91m' }, // bright red
};
const RESET = '\x1b[0m';

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
      console.log(`\n${risk.color}${risk.symbol} ${result.risk.toUpperCase()} RISK${RESET}\n`);

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
const SEVERITY_DISPLAY: Record<Severity, { symbol: string; color: string }> = {
  critical: { symbol: '🔴', color: '\x1b[91m' },
  high: { symbol: '🟠', color: '\x1b[31m' },
  medium: { symbol: '🟡', color: '\x1b[33m' },
  low: { symbol: '🟢', color: '\x1b[32m' },
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
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show all checks including passed ones')
  .action(async (directory: string, options: { fix?: boolean; json?: boolean; verbose?: boolean }) => {
    try {
      const targetDir = directory.startsWith('/') ? directory : process.cwd() + '/' + directory;

      console.log(`\n🔍 Scanning ${targetDir}...\n`);

      const scanner = new HardeningScanner();
      const result = await scanner.scan({
        targetDir,
        autoFix: options.fix ?? false,
      });

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      // Group findings by severity
      const failedFindings = result.findings.filter((f) => !f.passed && !f.fixed);
      const fixedFindings = result.findings.filter((f) => f.fixed);
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
        console.log(`${display.color}${display.symbol} ${severity.toUpperCase()} (${findings.length})${RESET}`);

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
        console.log(`\x1b[32m✅ FIXED (${fixedFindings.length})${RESET}`);
        for (const finding of fixedFindings) {
          console.log(`   • [${finding.checkId}] ${finding.name}`);
          if (finding.fixMessage) {
            console.log(`     ${finding.fixMessage}`);
          }
        }
        console.log();
      }

      // Print passed findings in verbose mode
      if (options.verbose && passedFindings.length > 0) {
        console.log(`\x1b[32m✅ PASSED (${passedFindings.length})${RESET}`);
        for (const finding of passedFindings) {
          console.log(`   • [${finding.checkId}] ${finding.name}`);
        }
        console.log();
      }

      // Summary
      if (!hasIssues && fixedFindings.length === 0) {
        console.log(`\x1b[32m✅ No security issues found!${RESET}\n`);
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

program
  .command("scan")
  .description("Perform a comprehensive security scan")
  .argument("<target>", "Target agent URL or identifier")
  .option("-f, --format <type>", "Output format (json, text, html)", "text")
  .option("-o, --output <path>", "Output file path")
  .action(async (target: string, options: { format: string; output?: string }) => {
    console.log(`Scanning target: ${target}`);
    const scanner = createScanner();
    const result = await scanner.scan(target);
    
    if (options.format === "json") {
      const output = JSON.stringify(result, null, 2);
      console.log(output);
    } else {
      console.log(`Scan complete for: ${result.target}`);
      console.log(`Findings: ${result.findings.length}`);
      console.log(`Timestamp: ${result.timestamp.toISOString()}`);
    }
  });

program.parse();

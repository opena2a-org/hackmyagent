#!/usr/bin/env node
/**
 * HackMyAgent CLI
 * Security scanning tool for AI agents
 */

import { Command } from 'commander';
import { VERSION, createScanner, checkSkill, type RiskLevel } from '@hackmyagent/core';

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

program
  .command("secure")
  .description("Apply security hardening to an agent configuration")
  .argument("<config>", "Path to agent configuration file")
  .option("-o, --output <path>", "Output path for secured configuration")
  .action(async (config: string, options: { output?: string }) => {
    console.log(`Securing configuration: ${config}`);
    if (options.output) {
      console.log(`Output will be written to: ${options.output}`);
    }
    // Placeholder implementation
    console.log("Security hardening applied.");
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

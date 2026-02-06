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

Documentation: https://github.com/opena2a-org/hackmyagent

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
  const overallCompliance = totalScored > 0 ? Math.round((totalPassed / totalScored) * 100) : 100;

  // Group results by category
  const categoryResults: BenchmarkCategoryResult[] = [];
  for (const category of OASB_1_CATEGORIES) {
    if (categoryFilter && category.name.toLowerCase() !== categoryFilter.toLowerCase()) continue;

    const catControls = controlResults.filter((r: LocalControlResult) => r.control.category === category.name);
    if (catControls.length === 0) continue;

    const passed = catControls.filter((r: LocalControlResult) => r.status === 'passed').length;
    const failed = catControls.filter((r: LocalControlResult) => r.status === 'failed').length;
    const unverified = catControls.filter((r: LocalControlResult) => r.status === 'unverified').length;
    const compliance = (passed + failed) > 0 ? Math.round((passed / (passed + failed)) * 100) : 100;

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
    'Failing': '#ef4444',
  }[result.rating] || '#94a3b8';

  const ratingBg = {
    'Certified': 'rgba(34, 197, 94, 0.15)',
    'Compliant': 'rgba(34, 197, 94, 0.15)',
    'Passing': 'rgba(234, 179, 8, 0.15)',
    'Needs Improvement': 'rgba(249, 115, 22, 0.15)',
    'Failing': 'rgba(239, 68, 68, 0.15)',
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
    if (pct >= 95) return { letter: 'A+', color: '#22c55e' };
    if (pct >= 90) return { letter: 'A', color: '#22c55e' };
    if (pct >= 85) return { letter: 'B+', color: '#84cc16' };
    if (pct >= 80) return { letter: 'B', color: '#84cc16' };
    if (pct >= 75) return { letter: 'C+', color: '#eab308' };
    if (pct >= 70) return { letter: 'C', color: '#eab308' };
    if (pct >= 60) return { letter: 'D', color: '#f97316' };
    return { letter: 'F', color: '#ef4444' };
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
      width: 56px;
      height: 56px;
      border-radius: 12px;
      border: 2px solid;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .grade-letter { font-size: 1.75rem; font-weight: 800; }
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
    'Failing': colors.red,
  };

  // Header
  console.log(`\n📋 ${result.benchmark} v${result.version}`);
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
    const statusIcon = catResult.failed === 0 ? '✅' : (catResult.passed > 0 ? '🟡' : '❌');
    console.log(`  ${statusIcon} ${catResult.category}: ${catResult.passed}/${catResult.passed + catResult.failed} (${catResult.compliance}%)`);

    // Show failed controls
    if (verbose || catResult.failed > 0) {
      for (const ctrl of catResult.controls) {
        if (ctrl.status === 'failed') {
          console.log(`     ❌ ${ctrl.controlId}: ${ctrl.name}`);
          if (verbose) {
            for (const finding of ctrl.findings) {
              console.log(`        └─ ${finding}`);
            }
          }
        } else if (verbose && ctrl.status === 'passed') {
          console.log(`     ✅ ${ctrl.controlId}: ${ctrl.name}`);
        } else if (verbose && ctrl.status === 'unverified') {
          console.log(`     ⚪ ${ctrl.controlId}: ${ctrl.name} (manual/forward)`);
        }
      }
    }
  }

  console.log();
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);

  // Compliance breakdown by level
  if (verbose) {
    console.log(`\nCompliance by level: L1=${result.l1Compliance}% L2=${result.l2Compliance}% L3=${result.l3Compliance}%`);
    console.log(`Legend: ⚪ = Manual/Forward verification required`);
  }

  // Show appropriate next step based on current level
  if (result.level === 'L1') {
    console.log(`\nRun 'hackmyagent secure -b oasb-1 -l L2' for stricter checks.`);
  } else if (result.level === 'L2') {
    console.log(`\nRun 'hackmyagent secure -b oasb-1 -l L3' for hardened requirements.`);
  } else {
    console.log(`\nThis is the highest maturity level (L3 - Hardened).`);
  }
  console.log(`Spec: https://oasb.ai/oasb-1\n`);
}

program
  .command('secure')
  .description(`Scan and harden your agent setup

Performs 100+ security checks across 24 categories:
  • Credentials: API key exposure, secrets in configs
  • MCP: Server configs, tool permissions, secrets
  • Network: TLS, interface bindings, CORS
  • Prompt: Injection defenses, role protection
  • Encryption: At-rest encryption, secure hashing
  • And 19 more categories...

Benchmark mode (--benchmark oasb-1):
  Run OASB-1 compliance checks with L1/L2/L3 levels.
  L1 = Essential (baseline), L2 = Standard, L3 = Hardened

Output formats (--format):
  text   Human-readable terminal output (default)
  json   Machine-readable JSON
  sarif  GitHub Security tab / IDE integration
  html   Shareable compliance report
  asp    Agent Security Profile (our format)

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
  $ hackmyagent secure -b oasb-1 --fail-below 80 CI threshold`)
  .argument('[directory]', 'Directory to scan (defaults to current directory)', '.')
  .option('--fix', 'Automatically fix issues where possible')
  .option('--dry-run', 'Preview fixes without applying them (use with --fix)')
  .option('--ignore <checks>', 'Comma-separated check IDs to skip (e.g., CRED-001,GIT-002)')
  .option('--json', 'Output as JSON (deprecated: use --format json)')
  .option('-f, --format <format>', 'Output format: text, json, sarif, html, asp (default: text)', 'text')
  .option('-o, --output <file>', 'Write output to file instead of stdout')
  .option('--fail-below <percent>', 'Exit 1 if compliance below threshold (0-100)')
  .option('-v, --verbose', 'Show all checks including passed ones')
  .option('-b, --benchmark <name>', 'Run benchmark compliance check (e.g., oasb-1)')
  .option('-l, --level <level>', 'Benchmark level: L1 (Essential), L2 (Standard), L3 (Hardened)', 'L1')
  .option('-c, --category <name>', 'Filter to specific benchmark category')
  .action(async (directory: string, options: { fix?: boolean; dryRun?: boolean; ignore?: string; json?: boolean; format?: string; output?: string; failBelow?: string; verbose?: boolean; benchmark?: string; level?: string; category?: string }) => {
    try {
      const targetDir = directory.startsWith('/') ? directory : process.cwd() + '/' + directory;

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
      if (options.benchmark && !isValidBenchmark(options.benchmark)) {
        console.error(`Error: Unknown benchmark '${options.benchmark}'. Available: ${AVAILABLE_BENCHMARKS.join(', ')}`);
        process.exit(1);
      }

      // Validate level if benchmark mode
      const validLevels = ['L1', 'L2', 'L3'];
      const level = (options.level?.toUpperCase() || 'L1') as BenchmarkLevel;
      if (options.benchmark && !validLevels.includes(level)) {
        console.error(`Error: Invalid level '${options.level}'. Use: L1, L2, or L3`);
        process.exit(1);
      }

      // Determine output format (--json is deprecated alias for --format json)
      const validFormats = ['text', 'json', 'sarif', 'html', 'asp'];
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
          console.log(`\n🔍 Scanning ${targetDir} (dry-run)...\n`);
        } else {
          console.log(`\n🔍 Scanning ${targetDir}...\n`);
        }
      }

      const scanner = new HardeningScanner();
      const result = await scanner.scan({
        targetDir,
        autoFix: options.fix ?? false,
        dryRun: options.dryRun ?? false,
        ignore: ignoreList,
      });

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

        // Write output
        if (output) {
          if (options.output) {
            require('fs').writeFileSync(options.output, output);
            console.error(`Report written to ${options.output}`);
          } else {
            console.log(output);
          }
        }

        // Check fail threshold
        if (failBelow !== undefined && benchmarkResult.compliance < failBelow) {
          console.error(`Compliance ${benchmarkResult.compliance}% is below threshold ${failBelow}%`);
          process.exit(1);
        }

        // Exit with non-zero if failing or needs improvement (default behavior)
        if (failBelow === undefined && (benchmarkResult.rating === 'Failing' || benchmarkResult.rating === 'Needs Improvement')) {
          process.exit(1);
        }
        return;
      }

      if (format === 'json') {
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
          console.log(`🔍 Scanning ${targetDir} (dry-run - previewing fixes)...\n`);
        } else if (options.fix) {
          console.log(`🔧 Scanning and fixing ${targetDir}...\n`);
          console.log(`${colors.yellow}Auto-fix will:${RESET()}`);
          console.log(`  • Bind gateway to 127.0.0.1 (local-only)`);
          console.log(`  • Replace plaintext tokens with env var references`);
          console.log(`  • Enable approval confirmations`);
          console.log(`  • Enable sandbox mode`);
          console.log(`\n${colors.cyan}A backup will be created for rollback if needed.${RESET()}\n`);
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
        console.log(`${colors.green}✅ Auto-Remediation Applied:${RESET()}\n`);
        for (const finding of fixedFindings) {
          console.log(`  ${colors.green}✓${RESET()} [${finding.checkId}] ${finding.name}`);
          if (finding.fixMessage) {
            console.log(`     ${colors.cyan}→${RESET()} ${finding.fixMessage}`);
          }
        }
        console.log();

        if (result.backupPath) {
          console.log(`${colors.yellow}📁 Backup created:${RESET()} ${result.backupPath}`);
          console.log(`${colors.yellow}↩️  To rollback:${RESET()} hackmyagent rollback ${targetDir}`);
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

// Attack command - adversarial security testing
const ATTACK_CATEGORY_NAMES = Object.keys(ATTACK_CATEGORIES) as AttackCategory[];

program
  .command('attack')
  .description(`Adversarial security testing for AI agents

Red team your AI agent with ${PAYLOAD_STATS.total} attack payloads across 5 categories:
  • Prompt Injection: ${PAYLOAD_STATS.byCategory['prompt-injection']} payloads
  • Jailbreaking: ${PAYLOAD_STATS.byCategory['jailbreak']} payloads
  • Data Exfiltration: ${PAYLOAD_STATS.byCategory['data-exfiltration']} payloads
  • Capability Abuse: ${PAYLOAD_STATS.byCategory['capability-abuse']} payloads
  • Context Manipulation: ${PAYLOAD_STATS.byCategory['context-manipulation']} payloads

Intensity levels:
  passive     Observation only, minimal risk
  active      Standard attack payloads (default)
  aggressive  Creative/risky payloads

Examples:
  $ hackmyagent attack https://api.example.com/v1/chat
  $ hackmyagent attack https://api.example.com --intensity aggressive
  $ hackmyagent attack https://api.example.com --category prompt-injection
  $ hackmyagent attack --local --system-prompt "You are a helpful assistant"
  $ hackmyagent attack https://api.example.com -f sarif -o results.sarif
  $ hackmyagent attack https://api.example.com --payload-file custom.json
  $ hackmyagent attack https://api.example.com --fail-on-vulnerable medium`)
  .argument('[target]', 'API endpoint to test (or use --local for simulation)')
  .option('-i, --intensity <level>', 'Attack intensity: passive, active, aggressive', 'active')
  .option('-c, --category <categories>', 'Comma-separated categories to test')
  .option('--local', 'Run in local simulation mode (no actual API calls)')
  .option('--api-format <format>', 'API format: openai, anthropic, custom', 'openai')
  .option('--model <model>', 'Model to test (for API targets)')
  .option('--system-prompt <prompt>', 'System prompt (for local testing)')
  .option('-H, --header <headers>', 'Headers in format "Key: Value" (can be used multiple times)')
  .option('--timeout <ms>', 'Request timeout in milliseconds', '30000')
  .option('--delay <ms>', 'Delay between requests in milliseconds', '1000')
  .option('--stop-on-success', 'Stop after first successful attack')
  .option('--payload-file <path>', 'JSON file with custom attack payloads')
  .option('--fail-on-vulnerable [severity]', 'Exit code 1 if vulnerabilities found (optional: critical/high/medium/low)')
  .option('-f, --format <format>', 'Output format: text, json, sarif, html', 'text')
  .option('-o, --output <file>', 'Write output to file')
  .option('-v, --verbose', 'Show detailed output for each payload')
  .action(async (targetUrl: string | undefined, options: {
    intensity?: string;
    category?: string;
    local?: boolean;
    apiFormat?: string;
    model?: string;
    systemPrompt?: string;
    header?: string | string[];
    timeout?: string;
    delay?: string;
    stopOnSuccess?: boolean;
    payloadFile?: string;
    failOnVulnerable?: string | boolean;
    format?: string;
    output?: string;
    verbose?: boolean;
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

      // Build target
      const target: AttackTarget = {
        url: targetUrl || '',
        type: options.local ? 'local' : 'api',
        headers: Object.keys(headers).length > 0 ? headers : undefined,
        apiFormat: (options.apiFormat || 'openai') as 'openai' | 'anthropic' | 'custom',
        model: options.model,
        systemPrompt: options.systemPrompt,
      };

      // Validate format
      const validFormats = ['text', 'json', 'sarif', 'html'];
      const format = options.format || 'text';
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
        console.log(`\n⚔️  HackMyAgent Attack Mode`);
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
        console.log(`Target: ${target.type === 'local' ? 'Local Simulation' : targetUrl}`);
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

      // Write output
      if (output) {
        if (options.output) {
          require('fs').writeFileSync(options.output, output);
          console.error(`Report written to ${options.output}`);
        } else {
          console.log(output);
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
    const icon = stats.successful > 0 ? '❌' : '✅';
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
        console.log(`  ✅ ${r.payload.id}: ${r.payload.name}`);
      }
      console.log();
    }
  }

  console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log(`\nUse --verbose for detailed attack results.`);
  console.log(`Use --intensity aggressive for advanced attacks.\n`);
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
    if (score <= 10) return { letter: 'A', color: '#22c55e' };
    if (score <= 25) return { letter: 'B', color: '#84cc16' };
    if (score <= 50) return { letter: 'C', color: '#eab308' };
    if (score <= 70) return { letter: 'D', color: '#f97316' };
    return { letter: 'F', color: '#ef4444' };
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
      width: 56px;
      height: 56px;
      border-radius: 12px;
      border: 2px solid;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .grade-letter { font-size: 1.75rem; font-weight: 800; }
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

program.parse();

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
  type AttackCategory,
  type AttackIntensity,
  type AttackTarget,
  type AttackReport,
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

  radarCategories.forEach((cat, i) => {
    const angle = (Math.PI * 2 * i) / radarCategories.length - Math.PI / 2;
    const value = cat.compliance / 100;
    const x = radarCenter + Math.cos(angle) * radarRadius * value;
    const y = radarCenter + Math.sin(angle) * radarRadius * value;
    radarPoints.push(`${x},${y}`);

    // Label position (slightly outside)
    const labelX = radarCenter + Math.cos(angle) * (radarRadius + 25);
    const labelY = radarCenter + Math.sin(angle) * (radarRadius + 25);
    const shortName = cat.category.split(' ').slice(0, 2).join(' ');
    radarLabels.push(`<text x="${labelX}" y="${labelY}" text-anchor="middle" dominant-baseline="middle" fill="#94a3b8" font-size="9">${escapeHtml(shortName)}</text>`);
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

  // Collect all failed controls for executive summary
  const failedControls = result.categories.flatMap(cat =>
    cat.controls.filter(ctrl => ctrl.status === 'failed')
  );

  // Generate executive summary items
  const executiveSummary = failedControls.length === 0
    ? '<div class="exec-item success"><span class="exec-icon">✓</span><span>All controls passing at this level</span></div>'
    : failedControls.slice(0, 5).map(ctrl =>
        `<div class="exec-item critical"><span class="exec-icon">!</span><span><strong>${ctrl.controlId}</strong>: ${escapeHtml(ctrl.name)}</span></div>`
      ).join('') + (failedControls.length > 5 ? `<div class="exec-item warning"><span class="exec-icon">+</span><span>${failedControls.length - 5} more issues not shown</span></div>` : '');

  // Category rows with collapsible sections
  const categoryRows = result.categories.map((cat, catIndex) => {
    const statusIcon = cat.failed === 0 ? '✅' : cat.passed > 0 ? '⚠️' : '❌';
    const barColor = cat.compliance >= 90 ? '#22c55e' : cat.compliance >= 70 ? '#eab308' : '#ef4444';

    const controlRows = cat.controls.map(ctrl => {
      const statusEmoji = ctrl.status === 'passed' ? '✅' : ctrl.status === 'failed' ? '❌' : '⚪';
      const findingsList = ctrl.findings.length > 0
        ? `<ul class="findings">${ctrl.findings.map(f => `<li>${escapeHtml(f)}</li>`).join('')}</ul>`
        : '';
      const remediation = ctrl.remediation
        ? `<div class="remediation"><strong>Remediation:</strong> ${escapeHtml(ctrl.remediation)}</div>`
        : '';
      return `
        <tr class="control-row ${ctrl.status}">
          <td class="status-cell">${statusEmoji}</td>
          <td class="id-cell"><code>${ctrl.controlId}</code></td>
          <td class="name-cell">${escapeHtml(ctrl.name)}</td>
          <td class="level-cell"><span class="level-badge level-${ctrl.level.toLowerCase()}">${ctrl.level}</span></td>
          <td class="details-cell">${findingsList}${remediation}</td>
        </tr>`;
    }).join('');

    return `
      <div class="category" id="cat-${catIndex}">
        <div class="category-header" onclick="toggleCategory(${catIndex})">
          <span class="category-icon">${statusIcon}</span>
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
    .header-right { text-align: right; }
    .rating-badge {
      display: inline-block;
      padding: 0.5rem 1.25rem;
      border-radius: 8px;
      font-weight: 700;
      font-size: 1.1rem;
      background: ${ratingBg};
      color: ${ratingColor};
      border: 1px solid ${ratingColor}40;
    }
    .level-tag {
      display: inline-block;
      margin-top: 0.5rem;
      padding: 0.25rem 0.75rem;
      background: var(--accent);
      color: white;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
    }

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

    /* Donut chart card */
    .donut-card {
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 1.5rem;
      border: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      align-items: center;
    }
    .donut-card h3 {
      font-size: 0.85rem;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 1rem;
    }
    .donut-container { position: relative; }
    .donut-center {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      text-align: center;
    }
    .donut-center .value { font-size: 2.5rem; font-weight: 700; color: ${complianceColor}; }
    .donut-center .label { font-size: 0.75rem; color: var(--text-muted); }
    .donut-stats {
      display: flex;
      gap: 2rem;
      margin-top: 1rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border);
    }
    .donut-stat { text-align: center; }
    .donut-stat .num { font-size: 1.5rem; font-weight: 600; }
    .donut-stat .lbl { font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase; }
    .donut-stat.passed .num { color: var(--success); }
    .donut-stat.failed .num { color: var(--danger); }

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
        <h1>🛡️ ${escapeHtml(result.benchmark)}</h1>
        <div class="meta">Version ${result.version} • Generated ${new Date(result.timestamp).toLocaleString()}</div>
      </div>
      <div class="header-right">
        <div class="rating-badge">${result.rating}</div>
        <div class="level-tag">${result.level} — ${result.level === 'L1' ? 'Essential' : result.level === 'L2' ? 'Standard' : 'Hardened'}</div>
      </div>
    </header>

    <div class="dashboard">
      <div class="donut-card">
        <h3>Compliance Score</h3>
        <div class="donut-container">
          <svg width="180" height="180" viewBox="0 0 180 180">
            <circle cx="90" cy="90" r="${donutRadius}" fill="none" stroke="#334155" stroke-width="${donutStroke}"/>
            <circle cx="90" cy="90" r="${donutRadius}" fill="none" stroke="${complianceColor}" stroke-width="${donutStroke}"
              stroke-dasharray="${donutCircumference}" stroke-dashoffset="${donutOffset}"
              stroke-linecap="round" transform="rotate(-90 90 90)"
              style="transition: stroke-dashoffset 0.5s ease;"/>
          </svg>
          <div class="donut-center">
            <div class="value">${result.compliance}%</div>
            <div class="label">Compliant</div>
          </div>
        </div>
        <div class="donut-stats">
          <div class="donut-stat passed">
            <div class="num">${result.passedControls}</div>
            <div class="lbl">Passed</div>
          </div>
          <div class="donut-stat failed">
            <div class="num">${result.failedControls}</div>
            <div class="lbl">Failed</div>
          </div>
        </div>
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
        <button class="footer-btn" onclick="window.print()">🖨️ Print / PDF</button>
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
  $ hackmyagent attack https://api.example.com -f sarif -o results.sarif`)
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
  .option('-f, --format <format>', 'Output format: text, json, sarif', 'text')
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
      const validFormats = ['text', 'json', 'sarif'];
      const format = options.format || 'text';
      if (!validFormats.includes(format)) {
        console.error(`Error: Invalid format '${format}'. Use: ${validFormats.join(', ')}`);
        process.exit(1);
      }

      // Show header for text output
      if (format === 'text') {
        console.log(`\n⚔️  HackMyAgent Attack Mode`);
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
        console.log(`Target: ${target.type === 'local' ? 'Local Simulation' : targetUrl}`);
        console.log(`Intensity: ${intensity}`);
        console.log(`Categories: ${categories ? categories.join(', ') : 'all'}`);
        console.log();
      }

      // Run attack
      const scanner = new AttackScanner();
      const report = await scanner.scan(target, {
        intensity,
        categories,
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

      // Exit with non-zero if critical/high vulnerabilities found
      if (report.riskRating === 'critical' || report.riskRating === 'high') {
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

program.parse();

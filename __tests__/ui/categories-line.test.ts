// #393 — the Categories line accounts for every failing finding.
//
// On a tree with a critical and a high in `credentials` and a low in
// `git hygiene`, `secure` printed `credentials (1 critical) · git hygiene
// (1 low) · 23 others clear` above a Findings summary reading
// `1 critical  1 high  1 low`. The high was bucketed under `credentials` and
// then dropped by the formatter, which named only each category's worst
// severity, so the two lines did not reconcile.

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { buildCategorySummaries } from '@opena2a/cli-ui';
import { formatCategoriesLine, formatCategoryCounts } from '../../src/ui/categories-line';
import { assertDistFresh } from '../helpers/dist-freshness';

describe('formatCategoryCounts', () => {
  it('names every non-zero severity, worst first', () => {
    expect(formatCategoryCounts({ critical: 1, high: 1, medium: 0, low: 0 })).toBe('1 critical, 1 high');
    expect(formatCategoryCounts({ critical: 0, high: 2, medium: 1, low: 3 })).toBe('2 high, 1 medium, 3 low');
  });

  it('is a single severity when only one fired', () => {
    expect(formatCategoryCounts({ critical: 0, high: 0, medium: 0, low: 1 })).toBe('1 low');
  });

  // `·` separates categories on the rendered line; using it inside one
  // category would make the line count more categories than it holds.
  it('never uses the category separator', () => {
    expect(formatCategoryCounts({ critical: 1, high: 1, medium: 1, low: 1 })).not.toContain('·');
  });
});

describe('formatCategoriesLine', () => {
  it('counts a high that shares a category with a critical (the #393 shape)', () => {
    const summaries = buildCategorySummaries([
      { checkId: 'CRED-001', name: 'Exposed Credential', severity: 'critical' },
      { checkId: 'SEM-CRED-002', name: 'GitHub token hardcoded in config', severity: 'high' },
      { checkId: 'GIT-001', name: 'Missing .gitignore', severity: 'low' },
    ] as any);
    const line = formatCategoriesLine(summaries)!;
    expect(line).toMatch(/^credentials \(1 critical, 1 high\) · git hygiene \(1 low\) · \d+ others clear$/);
  });

  it('sums to the number of failing findings it was given', () => {
    const findings = [
      { checkId: 'CRED-001', severity: 'critical' },
      { checkId: 'CRED-002', severity: 'critical' },
      { checkId: 'SEM-CRED-002', severity: 'high' },
      { checkId: 'MCP-001', severity: 'medium' },
      { checkId: 'MCP-002', severity: 'low' },
      { checkId: 'GIT-001', severity: 'low' },
    ];
    const line = formatCategoriesLine(buildCategorySummaries(findings as any))!;
    const total = [...line.matchAll(/(\d+) (?:critical|high|medium|low)\b/g)]
      .reduce((sum, m) => sum + Number(m[1]), 0);
    expect(total).toBe(findings.length);
  });

  it('keeps the renderer\'s shape for single-severity categories', () => {
    const summaries = buildCategorySummaries([
      { checkId: 'GIT-001', severity: 'low' },
    ] as any);
    expect(formatCategoriesLine(summaries)).toMatch(/^git hygiene \(1 low\) · \d+ others clear$/);
  });

  it('omits the clear tail when no category is clear', () => {
    expect(formatCategoriesLine([
      { name: 'credentials', counts: { critical: 1, high: 0, medium: 0, low: 0 }, clear: false },
    ])).toBe('credentials (1 critical)');
  });

  // The zero-findings line (`… (all clear)`) belongs to the renderer.
  it('returns undefined when no category holds a finding', () => {
    expect(formatCategoriesLine(buildCategorySummaries([]))).toBeUndefined();
  });
});

const REPO_ROOT = resolve(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');

describe('#393 secure: Categories reconciles with the Findings summary', () => {
  // A checkout that has not built fails here, naming the command to run; the
  // formatter cases above read only the source and still report on their own.
  beforeAll(assertDistFresh);

  it('counts every failing finding on a tree with a critical and a high in one category', () => {
    const home = mkdtempSync(join(tmpdir(), 'hma-393-home-'));
    mkdirSync(home, { recursive: true });
    const dir = mkdtempSync(join(tmpdir(), 'hma-393-'));
    // Built at runtime so the literal never sits in the source as a token shape.
    const token = ['ghp', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'].join('_');
    writeFileSync(join(dir, 'config.json'), `{"github_token": "${token}"}\n`);

    const run = spawnSync(process.execPath, [CLI, 'secure', dir], {
      encoding: 'utf-8',
      env: { ...process.env, HOME: home, NO_COLOR: '1' },
      timeout: 180_000,
    });
    // eslint-disable-next-line no-control-regex
    const out = (run.stdout ?? '').replace(/\x1b\[[0-9;]*m/g, '');

    const categories = /^\s*Categories\s{2,}(.+)$/m.exec(out);
    expect(categories, `no Categories line in:\n${out}`).not.toBeNull();
    const findingsHeader = /── Findings ─+\n\s*(.+)$/m.exec(out);
    expect(findingsHeader, `no Findings summary in:\n${out}`).not.toBeNull();

    const tally = (text: string): Record<string, number> => {
      const t: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const m of text.matchAll(/(\d+) (critical|high|medium|low)\b/g)) t[m[2]] += Number(m[1]);
      return t;
    };
    const fromFindings = tally(findingsHeader![1]);
    // The fixture's shape: a high exists alongside the critical(s).
    expect(fromFindings.high).toBeGreaterThan(0);
    expect(fromFindings.critical).toBeGreaterThan(0);
    expect(tally(categories![1])).toEqual(fromFindings);
    expect(categories![1]).toMatch(/credentials \(\d+ critical, \d+ high\)/);
  }, 200_000);
});

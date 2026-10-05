/**
 * #418 — `BenchmarkControl.audit` is the catalogue's numbered verification
 * procedure: how a person checks a control the scan cannot settle. It was
 * populated on most controls and read by nothing: not the text renderer, not
 * `-b oasb-1 --json`, not SARIF, not `explain`. Content with no reader drifts
 * silently; 24 of these strings cited a `--check` option `secure` never had.
 *
 * It now rides on the control records whose status is `unverified`, which is
 * exactly where a manual procedure is the next step, and on no other status.
 * RED-ON-BASE: before #418 no control record carried `audit`.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { generateBenchmarkReport } from '../../src/benchmarks/benchmark-report';
import { OASB_1_CATEGORIES } from '../../src/benchmarks/oasb-1';
import type { BenchmarkControl, BenchmarkResult } from '../../src/benchmarks/oasb-1';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

const CATALOGUE = new Map<string, BenchmarkControl>(
  OASB_1_CATEGORIES.flatMap((c) => c.controls).map((c) => [c.id, c]),
);

/** Every control record in a report, flattened. */
function records(report: Pick<BenchmarkResult, 'categories'>) {
  return report.categories.flatMap((c) => c.controls);
}

describe('#418 an unverified control carries its verification procedure', () => {
  it('attaches the catalogue audit text to every unverified control that has one, and to nothing else', () => {
    const report = generateBenchmarkReport([], 'L3');
    const all = records(report);
    const unverified = all.filter((r) => r.status === 'unverified');
    const withAudit = unverified.filter((r) => CATALOGUE.get(r.controlId)?.audit);
    // Non-vacuity: the catalogue has manual/forward controls with a procedure.
    expect(withAudit.length).toBeGreaterThan(0);
    for (const r of withAudit) {
      expect(r.audit, r.controlId).toBe(CATALOGUE.get(r.controlId)?.audit);
    }
    for (const r of all.filter((x) => x.status !== 'unverified')) {
      expect(r.audit, `${r.controlId} (${r.status})`).toBeUndefined();
    }
    for (const r of unverified.filter((x) => !CATALOGUE.get(x.controlId)?.audit)) {
      expect(r.audit, r.controlId).toBeUndefined();
    }
  });
});

const CLI = path.join(__dirname, '..', '..', 'dist', 'cli.js');

describe.skipIf(!fs.existsSync(CLI))('#418 secure -b oasb-1 --json renders the procedure', { timeout: 240_000 }, () => {
  beforeAll(() => { assertDistFreshIfPresent(); });

  it('an unverified control in the JSON report carries its audit text', () => {
    const dir = tempDir('hma-418-');
    // One file the quick-depth scan reads, so the run is measured rather than
    // Not Assessed under the zero-read floor.
    fs.writeFileSync(path.join(dir, '.gitignore'), 'node_modules\n');
    const res = spawnSync(process.execPath, [
      CLI, 'secure', dir, '-b', 'oasb-1', '-l', 'L3', '--scan-depth', 'quick', '--no-machine-posture', '--format', 'json',
    ], {
      encoding: 'utf-8',
      timeout: 200_000,
      env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: tempDir('hma-home-') },
    });
    const out = res.stdout ?? '';
    const report = JSON.parse(out.slice(out.indexOf('{'))) as BenchmarkResult;
    const rendered = records(report).filter((r) => r.status === 'unverified' && r.audit);
    expect(rendered.length, res.stderr).toBeGreaterThan(0);
    for (const r of rendered) expect(r.audit).toBe(CATALOGUE.get(r.controlId)?.audit);
  });
});

/**
 * #464 #519 #283 — one settled outcome feeds every outbound record.
 *
 * Before: each wire recomputed its own figures from the narrowed findings
 * list — the publish payload rebuilt a composite (with a passRate ratio no
 * server reads), the ci body derived `status: passed, counts all 0` for a
 * run that displayed 49 findings and exited 1, and the contribution event
 * scored `passed/total` (0 for any tree with one failure) under a third
 * verdict ladder. These cells pin the projection and every builder reading
 * it. RED-ON-BASE cells fail on the 3570f15 build; PIN cells pass on both.
 */
import { describe, it, expect } from 'vitest';
import {
  settledOutcome,
  settleSecureExit,
  outboundAllowed,
  wireStatus,
  pickSettledOutcome,
  SETTLED_OUTCOME_KEYS,
  type SettledOutcome,
} from '../../src/hardening/settled-outcome';
import { buildPublishPayload } from '../../src/registry/publish';
import { buildScanReport, buildCommunityReport } from '../../src/registry/client';
import { buildScanEvent } from '../../src/telemetry/contribute';
import { emitFindings } from '../../src/hardening/finding-emit';
import type { ScanResult } from '../../src/hardening/security-check';

function draft(checkId: string, severity: string, passed: boolean) {
  return {
    checkId,
    name: checkId,
    description: `fixture ${checkId}`,
    category: 'config',
    severity: severity as any,
    passed,
    message: 'x',
    fixable: false,
  };
}

const suppressedRow = { checkId: 'CONFIG-004', name: 'Leaky env', category: 'config', severity: 'critical', count: 1, suppressedBy: '.hmaignore' };

function makeResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    timestamp: new Date(),
    platform: 'test',
    projectType: 'library',
    findings: emitFindings([draft('ENV-001', 'high', false), draft('GIT-001', 'low', true)]),
    score: 61,
    maxScore: 100,
    rawScore: 74,
    scoreClamped: true,
    coverage: {
      filesExamined: 12,
      executions: [
        { method: 'a', prefixes: [], completed: true, filesRead: 3, pathsInspected: 3 },
        { method: 'b', prefixes: [], completed: true, filesRead: 4, pathsInspected: 4 },
        { method: 'c', prefixes: [], completed: false, filesRead: 0, pathsInspected: 0, skipReason: 'depth' },
      ],
      truncations: [],
      unreadableInputs: { count: 0, codes: {}, directories: 0 },
    },
    ...overrides,
  } as unknown as ScanResult;
}

describe('settleSecureExit — the exit ladder, spelled once', () => {
  it('a counted critical/high is exit 1', () => {
    expect(settleSecureExit(makeResult())).toBe(1);
  });

  it('a SUPPRESSED critical still settles exit 1 — suppression narrows the report, never the verdict', () => {
    const r = makeResult({ findings: emitFindings([draft('GIT-001', 'low', true)]), suppressed: [suppressedRow] } as any);
    expect(settleSecureExit(r)).toBe(1);
  });

  it('an unread input is exit 2 above everything', () => {
    const r = makeResult({ coverage: { filesExamined: 3, executions: [], truncations: [], unreadableInputs: { count: 2, codes: { EACCES: 2 }, directories: 0 } } } as any);
    expect(settleSecureExit(r)).toBe(2);
  });

  it('a clean measured run is exit 0', () => {
    const r = makeResult({ findings: emitFindings([draft('GIT-001', 'low', true)]) } as any);
    expect(settleSecureExit(r)).toBe(0);
  });
});

describe('settledOutcome — the record', () => {
  it('counts are over the gate set: a suppressed critical is counted, and the rows ride the record', () => {
    const r = makeResult({ suppressed: [suppressedRow] } as any);
    const s = settledOutcome(r, 1);
    expect(s.counts.critical).toBe(1);
    expect(s.counts.high).toBe(1);
    expect(s.suppressed).toEqual([suppressedRow]);
    expect(s.verdict).toBe('fail');
    expect(s.schemaVersion).toBe(1);
  });

  it('coverage: total = examined + discovered-but-unread; measured flips on the record', () => {
    const clean = settledOutcome(makeResult(), 1);
    expect(clean.coverage).toMatchObject({ measured: true, examined: 12, total: 12, unit: 'file' });
    const unread = makeResult({ coverage: { filesExamined: 3, executions: [], truncations: [], unreadableInputs: { count: 2, codes: { EACCES: 2 }, directories: 1 } } } as any);
    const s = settledOutcome(unread, 2);
    expect(s.coverage).toMatchObject({ measured: false, examined: 3, total: 5 });
    expect(s.measured).toBe(false);
  });

  it('the verdict ladder is the wire ladder: fail on critical/high, warn on medium/low, pass on none', () => {
    expect(settledOutcome(makeResult(), 1).verdict).toBe('fail');
    const warn = makeResult({ findings: emitFindings([draft('LOG-001', 'medium', false)]) } as any);
    expect(settledOutcome(warn, 0).verdict).toBe('warn');
    const clean = makeResult({ findings: emitFindings([draft('GIT-001', 'low', true)]) } as any);
    expect(settledOutcome(clean, 0).verdict).toBe('pass');
  });

  it('verdict is null exactly on an exit-2 run with nothing counted — a warn band at exit 2 is carried', () => {
    const clean = makeResult({ findings: emitFindings([draft('GIT-001', 'low', true)]) } as any);
    expect(settledOutcome(clean, 2).verdict).toBeNull();
    const warn = makeResult({ findings: emitFindings([draft('LOG-001', 'medium', false)]) } as any);
    expect(settledOutcome(warn, 2).verdict).toBe('warn');
  });
});

describe('outboundAllowed and wireStatus', () => {
  it('exit 2 or unmeasured never sends; a measured 0/1 does', () => {
    expect(outboundAllowed(settledOutcome(makeResult(), 1))).toBe(true);
    expect(outboundAllowed(settledOutcome(makeResult(), 2))).toBe(false);
    const unread = makeResult({ coverage: { filesExamined: 3, executions: [], truncations: [], unreadableInputs: { count: 1, codes: { EACCES: 1 }, directories: 0 } } } as any);
    expect(outboundAllowed(settledOutcome(unread, 1))).toBe(false);
  });

  it('wireStatus maps the band and fails closed on null', () => {
    expect(wireStatus(settledOutcome(makeResult(), 1))).toBe('failed');
    const warn = makeResult({ findings: emitFindings([draft('LOG-001', 'medium', false)]) } as any);
    expect(wireStatus(settledOutcome(warn, 0))).toBe('warnings');
    const clean = makeResult({ findings: emitFindings([draft('GIT-001', 'low', true)]) } as any);
    expect(wireStatus(settledOutcome(clean, 0))).toBe('passed');
    expect(() => wireStatus(settledOutcome(clean, 2))).toThrow(/EXIT_UNMEASURED/);
  });
});

describe('the publish payload reads the record (#464)', () => {
  const r = makeResult({ suppressed: [suppressedRow] } as any);
  const settled = settledOutcome(r, 1);
  const data = { packageName: 'fx', directory: '/tmp/fx', hardeningFindings: r.findings };

  it('RED-ON-BASE: score and verdict are the settled figures, and the typed counts ride top-level', () => {
    const p = buildPublishPayload(data as any, '0.33.0', settled);
    expect(p.score).toBe(61);
    expect(p.verdict).toBe('fail');
    expect(p.criticalCount).toBe(1);
    expect(p.highCount).toBe(1);
    expect(p.measured).toBe(true);
    expect(p.exitCode).toBe(1);
    expect(p.schemaVersion).toBe(1);
    expect(p.suppressed).toEqual([suppressedRow]);
    expect(p.coverage).toMatchObject({ measured: true, examined: 12, total: 12, unit: 'file' });
  });

  it('RED-ON-BASE: subReports.hardening carries NO passRate — the ratio no server reads is deleted', () => {
    const p = buildPublishPayload(data as any, '0.33.0', settled);
    expect((p.subReports as any).hardening).not.toHaveProperty('passRate');
    const legacy = buildPublishPayload(data as any, '0.33.0');
    expect((legacy.subReports as any).hardening).not.toHaveProperty('passRate');
  });

  it('PIN: without a settled record (the attack path) the local computation stands, without the new keys', () => {
    const legacy = buildPublishPayload(data as any, '0.33.0');
    expect(legacy.schemaVersion).toBeUndefined();
    expect(legacy.measured).toBeUndefined();
    expect(typeof legacy.score).toBe('number');
  });

  it('a null-verdict record is a caller bug and throws — never a payload', () => {
    const clean = makeResult({ findings: emitFindings([draft('GIT-001', 'low', true)]) } as any);
    expect(() => buildPublishPayload(data as any, '0.33.0', settledOutcome(clean, 2))).toThrow(/never publishes/);
  });
});

describe('the scan and community reports read the record (#283)', () => {
  const r = makeResult({ suppressed: [suppressedRow] } as any);
  const settled = settledOutcome(r, 1);

  it('RED-ON-BASE: status and counts come from the record, and rawReport carries the record whole', () => {
    const scan = buildScanReport('v-1', r.findings as any, settled);
    expect(scan.status).toBe('failed');
    expect(scan.criticalCount).toBe(1);
    expect((scan.rawReport as any).settledOutcome).toEqual(settled);
    const community = buildCommunityReport('fx', r.findings as any, {}, settled);
    expect(community.status).toBe('failed');
    expect(community.criticalCount).toBe(1);
    expect((community.rawReport as any).settledOutcome).toEqual(settled);
  });

  it('PIN: without a settled record the local derivation stands and no record rides', () => {
    const scan = buildScanReport('v-1', r.findings as any);
    expect((scan.rawReport as any).settledOutcome).toBeUndefined();
  });
});

describe('the contribution event reads the record (#519)', () => {
  const r = makeResult();
  const settled = settledOutcome(r, 1);

  it('RED-ON-BASE: score is the displayed 0-100, never passed/total', () => {
    const event = buildScanEvent('fx', '/tmp/fx-none', r.findings as any, 900, settled, 2);
    expect(event.scanSummary?.score).toBe(61);
  });

  it('RED-ON-BASE: the verdict is the settled band — one ladder, not a third one', () => {
    // One counted HIGH: the settled band is fail; the deleted-for-secure
    // local ladder said warn. This cell is what makes the two spellings
    // distinguishable.
    const event = buildScanEvent('fx', '/tmp/fx-none', r.findings as any, 900, settled, 2);
    expect(event.scanSummary?.verdict).toBe('fail');
  });

  it('RED-ON-BASE: totalChecks is the completed-execution count, and OMITTED when the run kept none', () => {
    const withCount = buildScanEvent('fx', '/tmp/fx-none', r.findings as any, 900, settled, 2);
    expect(withCount.scanSummary?.totalChecks).toBe(2);
    const without = buildScanEvent('fx', '/tmp/fx-none', r.findings as any, 900, settled, undefined);
    expect('totalChecks' in (without.scanSummary as object)).toBe(false);
  });

  it('PIN: the no-record callers (scan-soul, detect) keep the legacy derivation', () => {
    const event = buildScanEvent('fx', '/tmp/fx-none', r.findings as any, 900);
    expect(event.scanSummary?.totalChecks).toBe(2);
    expect(event.scanSummary?.verdict).toBe('warn');
  });

  it('a null-verdict record throws — an unmeasured run never contributes', () => {
    const clean = makeResult({ findings: emitFindings([draft('GIT-001', 'low', true)]) } as any);
    expect(() => buildScanEvent('fx', '/tmp/fx-none', clean.findings as any, 900, settledOutcome(clean, 2), 1)).toThrow(/never contributes/);
  });
});

describe('pickSettledOutcome — the flat document IS the record (C1/C2)', () => {
  it('identity: picking the record keys out of a larger document returns omit(record, schemaVersion)', () => {
    const r = makeResult({ suppressed: [suppressedRow] } as any);
    const settled = settledOutcome(r, 1);
    const { schemaVersion: _sv, ...recordSansVersion } = settled;
    const document = {
      ...r,
      verdict: settled.verdict,
      exitCode: settled.exitCode,
      measured: settled.measured,
      counts: settled.counts,
      coverage: {
        // The document's coverage is BIGGER (executions, truncations,
        // categories); the picker projects it down to the record's sub-keys.
        ...(r.coverage as object),
        measured: settled.coverage.measured,
        examined: settled.coverage.examined,
        total: settled.coverage.total,
        unit: settled.coverage.unit,
        unreadableInputs: settled.coverage.unreadableInputs,
      },
      extraDocumentKey: true,
    } as unknown as Record<string, unknown>;
    expect(pickSettledOutcome(document)).toEqual(recordSansVersion);
  });

  it('the key list covers every record key except schemaVersion', () => {
    const settled = settledOutcome(makeResult({ suppressed: [suppressedRow] } as any), 1);
    const recordKeys = Object.keys(settled).filter((k) => k !== 'schemaVersion').sort();
    const listed = [...SETTLED_OUTCOME_KEYS].filter((k) => (settled as Record<string, unknown>)[k] !== undefined).sort();
    expect(listed).toEqual(recordKeys);
  });
});

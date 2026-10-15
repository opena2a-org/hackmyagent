/**
 * Which queued entries `check` sends again, and with what.
 *
 * An entry is the submission a failed share sent, and only an entry with
 * every submission field is sent again, holding only those fields. An entry
 * an earlier version queued has a finding count and no findings, scan time or
 * tool version; sent with an empty findings list it would be recorded as a
 * scan with no findings, so it is not sent. The end-to-end run is in
 * __tests__/cli/check-pending-scan-retry.test.ts.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tempDir } from '../helpers/temp-dir';
import { readPendingScans, resendablePendingScan } from '../../src/telemetry/pending-scans';

const finding = { checkId: 'TEST-QUEUED-001', name: 'queued check', severity: 'high', passed: false, message: 'queued message', category: 'injection' };
const current = {
  name: 'gitlab.com/example-org/queued-repo',
  score: 12,
  maxScore: 100,
  projectType: 'library',
  toolVersion: '0.0.1-queued',
  scanTimestamp: '2026-10-02T03:04:05.000Z',
  findings: [finding],
};

describe('readPendingScans', () => {
  it('reads a missing file, a file that is not JSON and a JSON value that is not an array as an empty queue', () => {
    const dir = tempDir('hma-pending-read-');
    expect(readPendingScans(path.join(dir, 'missing.json'))).toEqual([]);
    for (const [file, text] of [['not-json.json', 'not json'], ['object.json', '{"name":"x"}'], ['null.json', 'null']]) {
      fs.writeFileSync(path.join(dir, file), text);
      expect(readPendingScans(path.join(dir, file)), file).toEqual([]);
    }
    fs.writeFileSync(path.join(dir, 'queue.json'), JSON.stringify([current]));
    expect(readPendingScans(path.join(dir, 'queue.json'))).toEqual([current]);
  });
});

describe('resendablePendingScan', () => {
  it('returns an entry in the current form with its own findings, scan time and tool version', () => {
    expect(resendablePendingScan(current)).toEqual(current);
  });

  it('keeps only the submission fields', () => {
    const scan = resendablePendingScan({
      ...current,
      source: 'first_party_scanner',
      verdict: 'pass',
      findings: [{ ...finding, attackClass: 'x', extra: 1 }],
    });
    expect(scan).toEqual(current);
  });

  it('returns an entry whose scan had no findings to send, with its empty list', () => {
    expect(resendablePendingScan({ ...current, findings: [] })).toEqual({ ...current, findings: [] });
  });

  it('returns null for an entry an earlier version queued', () => {
    expect(resendablePendingScan({
      name: 'gitlab.com/example-org/earlier-version-repo',
      score: 1,
      maxScore: 100,
      projectType: 'library',
      findingCount: 55,
      timestamp: '2026-10-01T00:00:00.000Z',
    })).toBeNull();
  });

  it.each([
    ['no findings', { findings: undefined }],
    ['findings that are not a list', { findings: { length: 0 } }],
    ['no scan time', { scanTimestamp: undefined }],
    ['a scan time that is not a date', { scanTimestamp: 'yesterday' }],
    ['no tool version', { toolVersion: undefined }],
    ['an empty tool version', { toolVersion: '' }],
    ['no name', { name: undefined }],
    ['a score that is not a number', { score: '12' }],
    ['a max score that is not finite', { maxScore: null }],
    ['no project type', { projectType: undefined }],
    ['a finding with no pass state', { findings: [{ ...finding, passed: undefined }] }],
    ['a finding with no severity', { findings: [{ ...finding, severity: undefined }] }],
    ['a finding with no check id', { findings: [{ ...finding, checkId: undefined }] }],
    ['a finding with no message', { findings: [{ ...finding, message: undefined }] }],
    ['a finding with a category that is not text', { findings: [{ ...finding, category: 7 }] }],
    ['a finding that is not an object', { findings: ['TEST-QUEUED-001'] }],
  ])('returns null for an entry with %s', (_label, change) => {
    expect(resendablePendingScan({ ...current, ...change })).toBeNull();
  });

  it('returns null for a value that is not an object', () => {
    for (const entry of [null, undefined, 'gitlab.com/example-org/queued-repo', 3, [current]]) {
      expect(resendablePendingScan(entry)).toBeNull();
    }
  });
});

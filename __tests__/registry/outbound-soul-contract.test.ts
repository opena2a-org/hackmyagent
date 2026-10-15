/**
 * What `scan-soul` sends is what the run found: `--publish` in the JSON arm
 * and in the text arm (with its scan-token request), and the contribution
 * event in both arms.
 *
 * Cells, on every body: no URL carries a user name, password, query string or
 * fragment; no string holds a local path of this run; no string equals the
 * tree hash of the working directory. Per site: the controls sent are the
 * controls the run evaluated, each passed or failed as the run printed it and
 * with the control's own severity (a control the catalogue marks critical is
 * `critical`, as the run reports a missing one; any other is `medium`); the
 * verdict is `fail` when the run's gate failed; the publish carries the score
 * the run printed; the scan time is the scan's own, so it is earlier than the
 * first line the run printed after the scan (`scan-soul` prints no scan time).
 *
 * Each body is also compared, byte for byte after normalizing run-to-run
 * values, with the body the unchanged source sent
 * (__tests__/fixtures/outbound-bodies/soul.json).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFresh } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { CONTROL_DEFS } from '../../src/soul';
import {
  bodies,
  contributedEvent,
  differencesFromRecording,
  localPathsIn,
  ms,
  normalizeBody,
  printedAt,
  rawBodies,
  runCli,
  seedContributionQueue,
  startCaptureRegistry,
  stringsEqualTo,
  treeHashOf,
  urlsWithCredentialsOrQuery,
  type CaptureRegistry,
  type CliRun,
} from '../helpers/outbound-capture';

beforeAll(assertDistFresh);

const RECORDING = path.join(__dirname, '..', 'fixtures', 'outbound-bodies', 'soul.json');
const TOKEN_ROUTE = 'POST /api/v1/registry/community/request-scan-token';
const PUBLISH_ROUTE = 'POST /api/v1/trust/publish';

let scratch = '';
let registry: CaptureRegistry;
let target = '';
let jsonRun: CliRun;
let textRun: CliRun;
/** The document the JSON arm printed. */
let printed: Record<string, any>;

interface PrintedControl { id: string; passed: boolean }
interface PrintedDomain { skippedByProfile?: boolean; skippedByTier?: boolean; controls: PrintedControl[] }

const CRITICAL = new Set(CONTROL_DEFS.filter((c) => c.critical).map((c) => c.id));

/** The controls the run evaluated, as [id, severity, passed]. */
function evaluated(): Array<[string, string, boolean]> {
  return (printed.domains as PrintedDomain[])
    .filter((d) => !d.skippedByProfile && !d.skippedByTier)
    .flatMap((d) => d.controls.map((c): [string, string, boolean] => [c.id, CRITICAL.has(c.id) ? 'critical' : 'medium', c.passed]));
}

/** The verdict the run's own result makes: its gate failed, or a control failed, or neither. */
function runVerdict(): string {
  if (printed.gate.failed) return 'fail';
  return evaluated().some(([, , passed]) => !passed) ? 'warn' : 'pass';
}

beforeAll(async () => {
  scratch = tempDir('hma-outbound-soul-');
  registry = await startCaptureRegistry(scratch);
  target = path.join(scratch, 'target');
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, 'package.json'), JSON.stringify({ name: 'outbound-soul', version: '0.4.0' }, null, 2) + '\n');
  // Tool-using, with neither role-play refusal nor immutable safety rules: two
  // critical controls missing, so the run's gate fails.
  fs.writeFileSync(path.join(target, 'SOUL.md'), [
    '# Agent',
    '',
    'You are a helpful assistant. You can read files and call tools.',
    'Identify yourself as an AI assistant when asked, and say when you are unsure.',
    '',
  ].join('\n'));
  jsonRun = runCli(['scan-soul', target, '--json', '--publish', '--contribute'], {
    runDir: path.join(scratch, 'json'), registry, before: seedContributionQueue,
  });
  textRun = runCli(['scan-soul', target, '--publish', '--contribute'], {
    runDir: path.join(scratch, 'text'), registry, before: seedContributionQueue,
  });
  printed = JSON.parse(jsonRun.stdout);
}, 600_000);

afterAll(() => registry?.stop());

function only(run: CliRun, route: string): Record<string, any> {
  const sent = bodies(run, route);
  expect(sent.length, `${route}\n${run.stderr}`).toBe(1);
  return sent[0];
}

describe('every body scan-soul sends', () => {
  it.each([['JSON arm', () => jsonRun], ['text arm', () => textRun]])(
    '%s: no URL with a user name, password, query or fragment; no local path; no working-directory tree hash',
    (_label, run) => {
      expect(run().requests.length).toBeGreaterThan(0);
      const roots = [scratch, target, run().cwd, run().home, os.homedir()];
      const cwdHash = treeHashOf(run().cwd);
      expect(run().requests.flatMap((q) => {
        const body = JSON.parse(q.body);
        return [...urlsWithCredentialsOrQuery(body), ...localPathsIn(body, roots), ...stringsEqualTo(body, cwdHash)].map((p) => `${q.url} ${p}`);
      })).toEqual([]);
    },
  );

  it('the run evaluated controls and its gate failed on a missing critical control', () => {
    expect(evaluated().length).toBeGreaterThan(0);
    expect(printed.gate.failed).toBe(true);
    expect(printed.criticalMissing.length).toBeGreaterThan(0);
  });
});

describe.each([['JSON arm', () => jsonRun], ['text arm', () => textRun]])('scan-soul --publish, %s', (_label, run) => {
  it('requests its scan token for the package the run scanned', () => {
    expect(bodies(run(), TOKEN_ROUTE)).toEqual([{ packageName: 'outbound-soul', version: '0.4.0' }]);
  });

  it('publishes every control the run evaluated, with its own severity and its printed result', () => {
    const body = only(run(), PUBLISH_ROUTE);
    expect(body.findings.map((f: { checkId: string; severity: string; passed: boolean }) => [f.checkId, f.severity, f.passed])).toEqual(evaluated());
  });

  it('publishes the score the run printed and the verdict its gate reached', () => {
    const body = only(run(), PUBLISH_ROUTE);
    expect({ score: body.score, verdict: body.verdict }).toEqual({ score: printed.score, verdict: runVerdict() });
    expect(body.subReports.soul.score).toBe(printed.score);
  });

  it('stamps the publish with the time of the scan, before the publish began', () => {
    const at = ms(only(run(), PUBLISH_ROUTE).scanTimestamp);
    expect(at).toBeGreaterThanOrEqual(run().startedAt);
    expect(at).toBeLessThan(printedAt(run(), 'No signing keys found'));
  });

  it('hashes the scanned tree, not the working directory', () => {
    expect(only(run(), PUBLISH_ROUTE).treeHash).toBe(treeHashOf(target));
  });
});

describe.each([['JSON arm', () => jsonRun, '{'], ['text arm', () => textRun, 'Governance']])('scan-soul --contribute, %s', (_label, run, firstReportLine) => {
  it('counts each failed control at its own severity, and the verdict follows the run\'s gate', () => {
    const s = contributedEvent(run()).scanSummary;
    const failedControls = evaluated().filter(([, , passed]) => !passed);
    expect([s.critical, s.high, s.medium, s.low]).toEqual([
      failedControls.filter(([, sev]) => sev === 'critical').length,
      0,
      failedControls.filter(([, sev]) => sev === 'medium').length,
      0,
    ]);
    expect(s.critical).toBe(printed.criticalMissing.length);
    expect({ totalChecks: s.totalChecks, passed: s.passed }).toEqual({
      totalChecks: evaluated().length,
      passed: evaluated().filter(([, , passed]) => passed).length,
    });
    expect(s.verdict).toBe(runVerdict());
  });

  it('carries the time of the scan, before the run printed its report', () => {
    const at = ms(contributedEvent(run()).timestamp);
    expect(at).toBeGreaterThanOrEqual(run().startedAt);
    expect(at).toBeLessThan(printedAt(run(), firstReportLine));
  });
});

describe('what scan-soul sends, against what the unchanged source sent', () => {
  it('every body is byte-identical once run-to-run values are normalized, apart from the fields this change corrects', () => {
    const n = (raw: string) => normalizeBody(raw, registry);
    const current: Record<string, string> = {
      'json: scan token': n(rawBodies(jsonRun, TOKEN_ROUTE)[0]),
      'json: publish': n(rawBodies(jsonRun, PUBLISH_ROUTE)[0]),
      'json: contribution event': n(JSON.stringify(contributedEvent(jsonRun))),
      'text: scan token': n(rawBodies(textRun, TOKEN_ROUTE)[0]),
      'text: publish': n(rawBodies(textRun, PUBLISH_ROUTE)[0]),
      'text: contribution event': n(JSON.stringify(contributedEvent(textRun))),
    };
    expect(differencesFromRecording(RECORDING, current, CHANGED)).toEqual([]);
  });
});

/**
 * The fields this change corrects, per site. The publish sent `findings: []`,
 * `score: 100` and `verdict: 'pass'` for a run that printed 3/100 and failed
 * controls (contentHash covers the findings, so it follows them). The
 * contribution event counted every failed control as medium and sent
 * `verdict: 'pass'`.
 */
const PUBLISH_FIELDS = ['score', 'findings', 'verdict', 'contentHash'] as const;
const EVENT_FIELDS = ['scanSummary.critical', 'scanSummary.medium', 'scanSummary.verdict'] as const;
const CHANGED: Record<string, readonly string[]> = {
  'json: publish': PUBLISH_FIELDS,
  'json: contribution event': EVENT_FIELDS,
  'text: publish': PUBLISH_FIELDS,
  'text: contribution event': EVENT_FIELDS,
};

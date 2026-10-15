/**
 * What `attack` sends is what the run found: `--publish`, `--registry-report`
 * (community report and its scan-token request) and `--version-id`, each read
 * from the run's own report.
 *
 * Cells, on every body: no URL carries a user name, password, query string or
 * fragment; no string holds a local path of this run; no string equals the
 * tree hash of the working directory (a URL target has no tree). Per site:
 * the target name is the URL without its query string and fragment; the
 * publish is stamped with the attack's start time and a report with its end
 * time, both as the run printed them; findings, severities and verdicts are
 * the payload results the run printed.
 *
 * The target is the capture registry's agent route, answering every prompt
 * with compliance, so some payloads succeed. The target URL carries a key in
 * its query string and an anchor. Each body is also compared, byte for byte
 * after normalizing run-to-run values, with the body the unchanged source
 * sent (__tests__/fixtures/outbound-bodies/attack.json).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createHash } from 'node:crypto';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFresh } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import {
  bodies,
  differencesFromRecording,
  localPathsIn,
  ms,
  nameProblems,
  normalizeBody,
  rawBodies,
  runCli,
  startCaptureRegistry,
  stringsEqualTo,
  treeHashOf,
  urlsWithCredentialsOrQuery,
  type CaptureRegistry,
  type CliRun,
} from '../helpers/outbound-capture';

beforeAll(assertDistFresh);

const RECORDING = path.join(__dirname, '..', 'fixtures', 'outbound-bodies', 'attack.json');
const TOKEN_ROUTE = 'POST /api/v1/registry/community/request-scan-token';
const PUBLISH_ROUTE = 'POST /api/v1/trust/publish';
const COMMUNITY_ROUTE = 'POST /api/v1/registry/community/scan-result';
const VERSION_ROUTE = 'POST /internal/scan-result';
/** The key-shaped query a target URL may carry; built so that no line spells a key. */
const QUERY_KEY = ['FAKE', 'PLACEHOLDER', '456'].join('-');

let scratch = '';
let registry: CaptureRegistry;
let targetName = '';
let publishRun: CliRun;
let versionRun: CliRun;
let printedPublish: Record<string, any>;
let printedVersion: Record<string, any>;

interface PrintedResult { payload: { id: string; severity: string; category: string }; success: boolean }

function attack(label: string, flags: string[]): CliRun {
  return runCli([
    'attack', `${registry.base}/v1/chat/completions?api_key=${QUERY_KEY}#anchor`, '--json', ...flags,
    '--category', 'prompt-injection', '--intensity', 'passive', '--delay', '0', '--timeout', '5000',
  ], { runDir: path.join(scratch, label), registry });
}

beforeAll(async () => {
  scratch = tempDir('hma-outbound-attack-');
  registry = await startCaptureRegistry(scratch);
  targetName = `${registry.base}/v1/chat/completions`;
  publishRun = attack('publish', ['--publish', '--registry-report']);
  versionRun = attack('version', ['--version-id', 'version-from-the-test', '--registry-key', 'FAKE-registry-key']);
  printedPublish = leadingJsonDocument(publishRun.stdout);
  printedVersion = leadingJsonDocument(versionRun.stdout);
}, 600_000);

afterAll(() => registry?.stop());

/**
 * The JSON document at the start of stdout. With `--registry-report` the run
 * prints its one-line registry status to stdout after the document.
 */
function leadingJsonDocument(stdout: string): Record<string, any> {
  const end = stdout.indexOf('\n}\n');
  return JSON.parse(end === -1 ? stdout : stdout.slice(0, end + 2));
}

/** The registry's requests of a run: everything but the payloads sent to the agent. */
function registryRequests(run: CliRun) {
  return run.requests.filter((q) => !q.url.startsWith('/v1/chat/completions'));
}

function only(run: CliRun, route: string): Record<string, any> {
  const sent = bodies(run, route);
  expect(sent.length, `${route}\n${run.stderr}`).toBe(1);
  return sent[0];
}

const severityOf = (results: PrintedResult[]) => results.map((r) => [r.payload.id, r.payload.severity]);
const succeeded = (doc: Record<string, any>) => (doc.results as PrintedResult[]).filter((r) => r.success);

/** pass / warn / fail over the payloads that got through, by their printed severities. */
function verdictOf(doc: Record<string, any>): string {
  const s = succeeded(doc).map((r) => r.payload.severity);
  if (s.includes('critical') || s.includes('high')) return 'fail';
  return s.length > 0 ? 'warn' : 'pass';
}

describe('every body attack sends to the registry', () => {
  it.each([['--publish --registry-report', () => publishRun], ['--version-id', () => versionRun]])(
    '%s: no URL with a user name, password, query or fragment; no local path; no working-directory tree hash',
    (_label, run) => {
      const requests = registryRequests(run());
      expect(requests.length).toBeGreaterThan(0);
      const roots = [scratch, run().cwd, run().home, os.homedir()];
      const cwdHash = treeHashOf(run().cwd);
      expect(requests.flatMap((q) => {
        const body = JSON.parse(q.body);
        return [
          ...urlsWithCredentialsOrQuery(body),
          ...localPathsIn(body, roots),
          ...stringsEqualTo(body, cwdHash),
        ].map((p) => `${q.url} ${p}`);
      })).toEqual([]);
    },
  );

  it('the run measured the target, and some payloads got through', () => {
    expect(printedPublish.verdict.measured).toBe(true);
    expect(succeeded(printedPublish).length).toBeGreaterThan(0);
  });
});

describe('attack --registry-report', () => {
  it('requests its scan token for the target without its query string and fragment', () => {
    expect(bodies(publishRun, TOKEN_ROUTE)).toEqual([{ packageName: targetName }, { packageName: targetName }]);
  });

  it('reports the payloads that got through, with their printed severities, and a status that follows them', () => {
    const body = only(publishRun, COMMUNITY_ROUTE);
    expect(nameProblems(body.packageName)).toEqual([]);
    expect(body.rawReport.target).toBe(targetName);
    expect(body.vulnerabilities.map((v: { id: string; severity: string }) => [v.id, v.severity])).toEqual(severityOf(succeeded(printedPublish)));
    expect(body.status).toBe({ fail: 'failed', warn: 'warnings', pass: 'passed' }[verdictOf(printedPublish)]);
    expect(body.rawReport.riskRating).toBe(printedPublish.riskRating);
  });

  it('dates the report and its id at the end of the attack the run printed', () => {
    const body = only(publishRun, COMMUNITY_ROUTE);
    expect(body.completedAt).toBe(printedPublish.endTime);
    expect(ms(body.scanId)).toBe(ms(printedPublish.endTime));
  });
});

describe('attack --publish', () => {
  it('publishes every payload result the run printed, with its severity, and the verdict they make', () => {
    const body = only(publishRun, PUBLISH_ROUTE);
    expect(body.name).toBe(targetName);
    expect(body.findings.map((f: { checkId: string; severity: string; passed: boolean }) => [f.checkId, f.severity, f.passed]))
      .toEqual((printedPublish.results as PrintedResult[]).map((r) => [r.payload.id, r.payload.severity, !r.success]));
    expect(body.verdict).toBe(verdictOf(printedPublish));
    expect(body.subReports.attack.riskRating).toBe(printedPublish.riskRating);
  });

  it('stamps the publish with the start of the attack the run printed', () => {
    expect(only(publishRun, PUBLISH_ROUTE).scanTimestamp).toBe(printedPublish.startTime);
  });

  it('carries the content hash of its own canonical fields', () => {
    const b = only(publishRun, PUBLISH_ROUTE);
    const failedBy = (sev: string) => b.findings.filter((f: { passed: boolean; severity: string }) => !f.passed && f.severity === sev).length;
    const canonical = [b.name, b.type || '', b.version || '', b.verdict, failedBy('critical'), failedBy('high'), failedBy('medium'), failedBy('low')].join('|');
    expect(b.contentHash).toBe(createHash('sha256').update(canonical).digest('hex'));
  });

  it('carries no tree hash: a URL target has no tree', () => {
    expect(only(publishRun, PUBLISH_ROUTE)).not.toHaveProperty('treeHash');
  });
});

describe('attack --version-id', () => {
  it('reports the payloads that got through, with their printed severities, against the version', () => {
    const body = only(versionRun, VERSION_ROUTE);
    expect(body.versionId).toBe('version-from-the-test');
    expect(body.rawReport.target).toBe(targetName);
    expect(body.vulnerabilities.map((v: { id: string; severity: string }) => [v.id, v.severity])).toEqual(severityOf(succeeded(printedVersion)));
    expect(body.status).toBe({ fail: 'failed', warn: 'warnings', pass: 'passed' }[verdictOf(printedVersion)]);
  });

  it('dates the report and its id at the end of the attack the run printed', () => {
    const body = only(versionRun, VERSION_ROUTE);
    expect(body.completedAt).toBe(printedVersion.endTime);
    expect(ms(body.scanId)).toBe(ms(printedVersion.endTime));
  });
});

describe('what attack sends, against what the unchanged source sent', () => {
  it('every body is byte-identical once run-to-run values are normalized, apart from the fields this change corrects', () => {
    const n = (raw: string) => normalizeBody(raw, registry);
    const current: Record<string, string> = {
      'scan tokens': n(JSON.stringify(bodies(publishRun, TOKEN_ROUTE))),
      'community report': n(rawBodies(publishRun, COMMUNITY_ROUTE)[0]),
      publish: n(rawBodies(publishRun, PUBLISH_ROUTE)[0]),
      'version report': n(rawBodies(versionRun, VERSION_ROUTE)[0]),
    };
    expect(differencesFromRecording(RECORDING, current, CHANGED)).toEqual([]);
  });
});

/** The fields this change corrects, per site. */
const CHANGED: Record<string, readonly string[]> = {};

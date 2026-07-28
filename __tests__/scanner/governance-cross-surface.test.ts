/**
 * #291 — `detect` and `scan-soul` must not report different Governance
 * numbers for the same directory.
 *
 * Both surfaces rendered a meter labelled "Governance" and answered the same
 * question about the same tree in opposite directions:
 *
 *   SOUL.md holding one line of prose   scan-soul   0/100   detect 100/100
 *   a real CLAUDE.md                    scan-soul  22/100   detect 100/100
 *   no governance file at all           scan-soul   0/100   detect  55/100
 *
 * `detect` scored presence — it started at 100 and marked every agent
 * `governed` the moment a SOUL.md existed on disk, without ever reading it.
 * `scan-soul` scored substance (9-domain control conformance). Two different
 * measurements under one label is a data-integrity defect, so the models were
 * reconciled rather than one being renamed: conformance is authoritative, and
 * `detect` consumes it.
 *
 * The whole 2415-test suite stayed green through a change that moved
 * `detect`'s number from 100 to 0 on a real fixture. Nothing guarded the
 * relationship between the two surfaces, which is why the defect shipped and
 * why this file exists.
 *
 * The invariant is stated on the PRE-clamp value. `detect` additionally
 * applies the #259 verdict-band clamp using its own host- and project-level
 * findings, which `scan-soul` cannot see; the clamp only ever lowers a score
 * and always travels with the raw value, so `governanceRaw` is the honest
 * point of comparison.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');

function runCli(args: string[], cwd?: string): string {
  try {
    return execFileSync(process.execPath, [CLI, ...args], {
      encoding: 'utf8',
      timeout: 180_000,
      cwd,
      env: { ...process.env, NO_COLOR: '1' },
    });
  } catch (e: unknown) {
    // Both commands exit 1 when they find something. That is the case under
    // test, so the stdout still has to be read.
    return String((e as { stdout?: string }).stdout ?? '');
  }
}

interface DetectSummary {
  governanceScore: number;
  governanceRaw: number;
  governanceClamped: boolean;
  ungoverned: number;
  totalAgents: number;
}

function detectSummary(dir: string): DetectSummary {
  const raw = runCli(['detect', dir, '--json']);
  expect(raw.length, `detect emitted nothing for ${dir}`).toBeGreaterThan(0);
  return JSON.parse(raw).summary as DetectSummary;
}

function soulScore(dir: string): { score: number; conformance: string } {
  const raw = runCli(['scan-soul', dir, '--json']);
  expect(raw.length, `scan-soul emitted nothing for ${dir}`).toBeGreaterThan(0);
  const j = JSON.parse(raw);
  return { score: j.score, conformance: j.conformance };
}

let root: string;

/** No governance artifact of any kind. */
let dirNone: string;
/** A governance file that exists but carries no controls — the #291 fixture. */
let dirProse: string;
/** Full control conformance, produced by the tool's own remediation. */
let dirHardened: string;
/** Full conformance PLUS an outstanding CRITICAL — the band-coherence case. */
let dirHardenedCritical: string;

beforeAll(() => {
  if (!existsSync(CLI)) throw new Error('dist/cli.js missing — run npm run build');
  root = mkdtempSync(path.join(tmpdir(), 'hma-291-'));

  const pkg = '{"name":"agent","version":"1.0.0"}\n';

  dirNone = mkdtempSync(path.join(root, 'none-'));
  writeFileSync(path.join(dirNone, 'package.json'), pkg);

  dirProse = mkdtempSync(path.join(root, 'prose-'));
  writeFileSync(path.join(dirProse, 'package.json'), pkg);
  writeFileSync(path.join(dirProse, 'SOUL.md'), '# SOUL.md\n\nSome prose about the agent.\n');

  dirHardened = mkdtempSync(path.join(root, 'hardened-'));
  writeFileSync(path.join(dirHardened, 'package.json'), pkg);
  runCli(['harden-soul', dirHardened]);

  dirHardenedCritical = mkdtempSync(path.join(root, 'hardened-crit-'));
  writeFileSync(path.join(dirHardenedCritical, 'package.json'), pkg);
  runCli(['harden-soul', dirHardenedCritical]);
  // Credential-shaped placeholder. Every character is literal FAKE — this is
  // a detector trigger, never a real secret.
  writeFileSync(
    path.join(dirHardenedCritical, '.cursorrules'),
    'api_key: "FAKEFAKEFAKEFAKEFAKEFAKE"\n',
  );
}, 300_000);

afterAll(() => {
  if (root) rmSync(root, { recursive: true, force: true });
});

describe('#291 governance model reconciliation', () => {
  describe('the two surfaces measure the same thing', () => {
    const cases = (): { label: string; dir: string }[] => [
      { label: 'no governance file', dir: dirNone },
      { label: 'governance file with no controls', dir: dirProse },
      { label: 'full control conformance', dir: dirHardened },
      { label: 'full conformance beside a CRITICAL', dir: dirHardenedCritical },
    ];

    it('detect reports scan-soul\'s conformance as its Governance measurement', () => {
      for (const { label, dir } of cases()) {
        const soul = soulScore(dir);
        const summary = detectSummary(dir);
        expect(
          summary.governanceRaw,
          `${label}: detect says ${summary.governanceRaw}, scan-soul says ${soul.score} — `
          + 'the two Governance models have diverged again (#291)',
        ).toBe(soul.score);
      }
    });

    it('spans a real range of scores, so the equality above is not vacuous', () => {
      // Guards the guard: if every fixture collapsed to the same number (or
      // the CLI silently produced 0 everywhere), the assertion above would
      // pass while measuring nothing.
      const scores = cases().map((c) => soulScore(c.dir).score);
      expect(Math.min(...scores), `all fixtures scored alike: ${scores.join(', ')}`).toBe(0);
      expect(Math.max(...scores), `no fixture reached full conformance: ${scores.join(', ')}`).toBe(100);
    });
  });

  describe('presence is not governance', () => {
    it('does not credit a governance file that carries no controls', () => {
      const soul = soulScore(dirProse);
      // Sanity: the fixture really does have a governance file on disk.
      expect(soul.conformance, 'fixture should have failed its critical controls').toBe('none');

      const summary = detectSummary(dirProse);
      expect(
        summary.governanceRaw,
        'a SOUL.md of pure prose scored full marks — detect is back to scoring file presence',
      ).toBeLessThan(100);
    });

    it('does not mark agents governed on the strength of an empty governance file', () => {
      const summary = detectSummary(dirProse);
      if (summary.totalAgents === 0) return; // no AI processes on this host
      expect(
        summary.ungoverned,
        'agents were marked governed because a file existed, not because it governs anything',
      ).toBe(summary.totalAgents);
    });
  });

  describe('band coherence', () => {
    it('does not paint a green Governance band beside an outstanding CRITICAL', () => {
      const summary = detectSummary(dirHardenedCritical);

      // Sanity: the fixture must actually reach full conformance, or this
      // proves nothing — a low score is trivially out of the green band.
      expect(
        summary.governanceRaw,
        'fixture never reached full conformance; the clamp is untested',
      ).toBe(100);

      expect(
        summary.governanceScore,
        `Governance ${summary.governanceScore}/100 sits in the good band while a CRITICAL is outstanding`,
      ).toBeLessThan(70);
      expect(summary.governanceClamped, 'the clamp did not fire').toBe(true);
    });

    it('preserves the pre-clamp value instead of destroying it', () => {
      const summary = detectSummary(dirHardenedCritical);
      expect(summary.governanceRaw).toBe(100);
      expect(summary.governanceRaw).toBeGreaterThan(summary.governanceScore);
    });

    it('never raises a score — the clamp is a ceiling, not a floor', () => {
      for (const dir of [dirNone, dirProse, dirHardened, dirHardenedCritical]) {
        const summary = detectSummary(dir);
        expect(
          summary.governanceScore,
          `clamp raised the score at ${dir}`,
        ).toBeLessThanOrEqual(summary.governanceRaw);
      }
    });

    it('leaves the score alone when nothing is fail-direction', () => {
      const summary = detectSummary(dirHardened);
      if (summary.governanceClamped) return; // host had its own findings
      expect(summary.governanceScore).toBe(summary.governanceRaw);
    });
  });

  describe('the recovery path names what actually moves the number', () => {
    it('does not promise a return to 100 by fixing findings alone', () => {
      const out = runCli(['detect', dirProse]);
      const line = out.split('\n').find((l) => l.includes('Path forward'));
      expect(line, 'no Path forward line — a sub-100 score must not be a dead end').toBeTruthy();
      expect(
        line,
        'recovery is attributed to clearing findings, but the meter is control conformance',
      ).toMatch(/adding the missing governance controls/);
    });

    it('offers a path forward when only the clamp is holding the score down', () => {
      const out = runCli(['detect', dirHardenedCritical]);
      const line = out.split('\n').find((l) => l.includes('Path forward'));
      expect(
        line,
        'a fully-conformant tree capped by a CRITICAL was left with no path forward',
      ).toBeTruthy();
      expect(line).toMatch(/clearing/);
    });
  });
});

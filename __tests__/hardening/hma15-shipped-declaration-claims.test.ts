/**
 * HMA-15.AC12 — no shipped type declaration asserts a redaction guarantee
 * that measurement does not support.
 *
 * A `.d.ts` renders in the consumer's editor at the moment they use the
 * field, so it outranks a README. The r1 delivery would have published
 * "emitFinding redacts it IN FULL and derives `redactionStatus`/
 * `redactedShapes` from that actual removal" into `capability-analyzer.d.ts`
 * — measured FALSE for every shape the redactor's table does not cover.
 * Precedent: the secretless-ai `grant-policy.d.ts` "Enforced in v1." claim.
 *
 * Mechanism: `npm pack` the artifact exactly as a release would, extract it,
 * and grep the extracted dist's declaration files. Two layers:
 *
 *   1. The measured-false r1 claim family must be ABSENT everywhere.
 *   2. Any OTHER guarantee-strength redaction claim must appear in the
 *      allowlist below, where each entry NAMES the committed measurement
 *      backing it — and the test asserts that measurement file exists. A new
 *      strong claim without a measurement fails here, which is the point:
 *      wording it down or measuring it are the only ways to ship it.
 *
 * A precondition this gate needs and cannot find — an unbuilt tree, a pack
 * with no declarations — is an ERROR, never a skip (HMA-15.AC11, CISO
 * Binding Decision 12).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const REPO_ROOT = join(__dirname, '..', '..');

/**
 * Guarantee-strength redaction claims. Deliberately narrow: ordinary
 * descriptive uses of "redact" (what a function does, which marker a shape
 * maps to, what a status VALUE means) are not guarantees. What this hunts is
 * the absolute form — the wording that tells a consumer they need no other
 * control.
 */
const STRONG_CLAIM_PATTERNS: readonly RegExp[] = [
  /redact\w*[^.\n]{0,60}\bin full\b/i,
  /\bin full\b[^.\n]{0,60}redact\w*/i,
  /derives?[^.\n]{0,80}redactionStatus[^.\n]{0,120}actual removal/is,
  // Adjacency, not proximity: "always redacts" is a guarantee; "stamp the
  // two always-present fields" is a sentence that happens to contain both
  // words. The first draft of this list used a 60-char proximity window and
  // flagged exactly that benign line in finding-emit.d.ts.
  /\balways\s+redact/i,
  /redact\w*\s+(?:always|everything|all\s+shapes)\b/i,
  /guarantee[ds]?\s+(?:that\s+)?[^.\n]{0,40}redact/i,
  /redact\w*[^.\n]{0,30}\bguarantee[ds]?\b(?!\s+point)/i,
  /\b(?:never|cannot)\s+leak/i,
  /Enforced in v\d/,
];

/**
 * Strong claims that ARE allowed to ship, each backed by a named committed
 * measurement. Empty today — the r2 wording states mechanisms and recorded
 * facts, not guarantees — and an addition here must name the test that
 * measures the claim, which the assertion below requires to exist.
 */
const MEASURED_CLAIM_ALLOWLIST: readonly {
  file: RegExp;
  claim: RegExp;
  measurement: string;
}[] = [];

let packDir = '';
let declarationFiles: string[] = [];

function walkDts(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) walkDts(p, out);
    else if (entry.isFile() && entry.name.endsWith('.d.ts')) out.push(p);
  }
}

beforeAll(() => {
  packDir = mkdtempSync(join(tmpdir(), 'hma15-pack-'));
  const pack = spawnSync('npm', ['pack', '--silent', '--pack-destination', packDir], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    timeout: 170_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (pack.status !== 0) {
    throw new Error(`npm pack failed (exit ${pack.status}): ${pack.stderr}`);
  }
  const tgz = pack.stdout.trim().split('\n').pop() ?? '';
  const tgzPath = join(packDir, tgz);
  if (!existsSync(tgzPath)) throw new Error(`npm pack produced no tarball at ${tgzPath}`);
  const tar = spawnSync('tar', ['-xzf', tgzPath, '-C', packDir], {
    encoding: 'utf8',
    timeout: 170_000,
  });
  if (tar.status !== 0) throw new Error(`tar extraction failed: ${tar.stderr}`);
  const distDir = join(packDir, 'package', 'dist');
  // ERROR, never a skip: a pack with no declarations means the gate cannot
  // see what would ship, which is a failing precondition of the gate.
  if (!existsSync(distDir)) {
    throw new Error('packed artifact carries no dist/ — build before testing; this gate does not skip');
  }
  walkDts(distDir, declarationFiles);
});

afterAll(() => {
  if (packDir) rmSync(packDir, { recursive: true, force: true });
});

describe('HMA-15.AC12 shipped declaration claims', () => {
  it('HMA-15.AC12 the packed artifact ships type declarations to audit', () => {
    expect(declarationFiles.length, 'no .d.ts in the packed dist — nothing was audited').toBeGreaterThan(0);
  });

  it('HMA-15.AC12 the measured-false r1 claim ships nowhere', () => {
    // The named instance, checked by content rather than by file name, so a
    // moved declaration cannot carry it back in.
    const r1Claim = /redacts it IN FULL|from\s+that actual removal/i;
    for (const file of declarationFiles) {
      const text = readFileSync(file, 'utf8');
      expect(
        r1Claim.test(text),
        `${file.slice(packDir.length)} still ships the r1 claim measured false on 2026-08-31`,
      ).toBe(false);
    }
  });

  it('HMA-15.AC12 every guarantee-strength redaction claim in shipped declarations is measured', () => {
    const unmeasured: string[] = [];
    for (const file of declarationFiles) {
      const rel = file.slice(packDir.length);
      const text = readFileSync(file, 'utf8');
      for (const pattern of STRONG_CLAIM_PATTERNS) {
        const match = pattern.exec(text);
        if (!match) continue;
        const allowed = MEASURED_CLAIM_ALLOWLIST.some(
          (entry) => entry.file.test(rel) && entry.claim.test(match[0]),
        );
        if (!allowed) {
          unmeasured.push(`${rel}: ${JSON.stringify(match[0].slice(0, 120))}`);
        }
      }
    }
    expect(
      unmeasured,
      'guarantee-strength redaction claims with no named measurement — measure them or word them down',
    ).toEqual([]);
  });

  it('HMA-15.AC12 every allowlisted claim names a measurement that exists', () => {
    for (const entry of MEASURED_CLAIM_ALLOWLIST) {
      expect(
        existsSync(join(REPO_ROOT, entry.measurement)),
        `allowlist entry ${entry.claim} names a measurement that does not exist: ${entry.measurement}`,
      ).toBe(true);
    }
  });
});

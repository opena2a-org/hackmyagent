/**
 * #412 — `secure` did not read `.mjs` or `.cjs` at all.
 *
 * `SECURITY_RELEVANT_EXTENSIONS` in `src/nanomind-core/scanner-bridge.ts` listed
 * `.ts` and `.js` but not the ES-module or CommonJS variants, so a file with one
 * of those extensions never entered the compile set and no analyzer ever saw it.
 * An identical high-entropy credential measured, on the pre-fix build:
 *
 *   config.js          69/100  CRITICAL reported
 *   config.mjs         98/100  nothing reported
 *   config.cjs         98/100  nothing reported
 *   src/config.mjs     98/100  nothing reported
 *
 * An extension gate, not a directory gate. `.mjs` is the standard extension for
 * Node tooling — build, release and verification scripts — which is exactly
 * where connection strings and tokens collect; one private repo in this org had
 * 26 tracked `.mjs` files and none were scanned.
 *
 * The miss was worse than a plain gap. The run still reported `61 of 61 check
 * groups ran` and `399 files read by static checks`, so a clean score was
 * indistinguishable from a scanned-and-clean one — a pre-push gate reported PASS
 * for a file the scanner had never opened.
 *
 * TWO LAYERS, AND WHAT EACH ONE IS WORTH
 *
 *   Contract — the extension table below is authored HERE, deliberately, and
 *              compared against the scanner's set. It is not derived from the
 *              code under test, so removing `.mjs` fails it. Runs everywhere,
 *              including CI, which is where a silent re-omission would land.
 *   End-to-end — a credential really is reported in a `.mjs` file by the built
 *              CLI. Proves the walk actually consults the set, which the
 *              contract layer cannot. Needs a built dist, and nothing else:
 *              release.yml builds before it runs the suite.
 *
 * Neither is sufficient alone. The contract layer would pass if the walk stopped
 * consulting the set entirely. The negative control (`.bin`) is load-bearing in
 * both: without it, a scanner that simply read every file would satisfy every
 * positive case.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { SECURITY_RELEVANT_EXTENSIONS } from '../../src/nanomind-core/scanner-bridge';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

/**
 * Source extensions whose contents MUST be examined. Authored as the contract;
 * deliberately NOT derived from the scanner's own constant, because a list read
 * out of the thing under test cannot fail when that thing is wrong.
 *
 * Adding a language to the scanner means adding a row here. Removing one is then
 * a visible decision rather than a silent omission — which is the whole defect.
 */
const MUST_BE_SCANNED = ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx'] as const;

/**
 * Extensions that must NOT be treated as compilable source. Without these the
 * positive cases would also pass for a scanner that read everything, and would
 * prove nothing about the gate.
 */
const MUST_NOT_BE_SCANNED = ['.bin', '.png', '.woff2'] as const;

describe('#412 the security-relevant extension set covers what it claims to', () => {
  for (const ext of MUST_BE_SCANNED) {
    it(`treats ${ext} as security-relevant`, () => {
      expect(
        SECURITY_RELEVANT_EXTENSIONS.has(ext),
        `${ext} is not in SECURITY_RELEVANT_EXTENSIONS, so a credential in a ${ext} file is ` +
          `invisible to every analyzer while the run still reports a confident clean score. ` +
          `That is exactly how .mjs and .cjs behaved before #412.`,
      ).toBe(true);
    });
  }

  for (const ext of MUST_NOT_BE_SCANNED) {
    it(`does not treat ${ext} as compilable source`, () => {
      expect(
        SECURITY_RELEVANT_EXTENSIONS.has(ext),
        `${ext} is in the compile set. The positive cases above would then pass for a scanner ` +
          `that simply read every file, so they would no longer be evidence of anything.`,
      ).toBe(false);
    });
  }
});

// ---------------------------------------------------------------------------
// End-to-end: the walk really does consult the set.
// ---------------------------------------------------------------------------

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');

// #285 — this layer spawns the built CLI. Without the freshness assert it would
// happily measure a binary older than src/ and report a pass.
beforeAll(assertDistFreshIfPresent);

const canSpawn = (): boolean => existsSync(CLI);

/** Write a project holding one high-entropy credential at `relPath`, scan it. */
function scanFixture(relPath: string): { detected: boolean; output: string } {
  const dir = mkdtempSync(join(tmpdir(), 'hma-412-'));
  try {
    mkdirSync(dirname(join(dir, relPath)), { recursive: true });
    writeFileSync(join(dir, 'package.json'), '{"name":"x","version":"1.0.0"}');
    writeFileSync(
      join(dir, relPath),
      `const LEAKED = "sk-ant-api03-${randomBytes(32).toString('hex')}";\n`,
    );
    const run = spawnSync(process.execPath, [CLI, 'secure', '--ci'], {
      cwd: dir,
      encoding: 'utf-8',
      timeout: 120_000,
    });
    const output = `${run.stdout ?? ''}${run.stderr ?? ''}`;
    return { detected: /hardcoded secret|credentials in non-env/i.test(output), output };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe.runIf(canSpawn())('#412 end-to-end: a credential in a .mjs file is reported', () => {
  for (const rel of ['config.mjs', 'config.cjs', 'src/config.mjs']) {
    it(`reports the credential in ${rel}`, () => {
      const { detected, output } = scanFixture(rel);
      expect(
        detected,
        `no credential reported for ${rel}. Pre-#412 this scored a clean 98/100 while the ` +
          `identical credential in config.js scored 69/100.\n\n${output.slice(0, 1200)}`,
      ).toBe(true);
    });
  }

  it('still reports the credential in config.js (the case that always worked)', () => {
    expect(scanFixture('config.js').detected).toBe(true);
  });
});

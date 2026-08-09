/**
 * #462 — `secure --deep` must not report a pass for a run it could not finish.
 *
 * The exit code used to depend on how the analyst happened to FORMAT its reply.
 * Measured on one fixture, one credential, one analyst verdict, varying only the
 * formatting: a bare JSON array gave `69/100 exit 1`; the same answer with a
 * sentence in front of it gave `93/100 exit 0`. A CI gate whose answer turns on
 * the model's prose is not a gate.
 *
 * Two changes close it and this file pins both, because either alone leaves a
 * hole: the reply is read from the shapes models actually return, AND a reply
 * that still cannot be read produces exit 2 — "reached no verdict" — instead of
 * a pass. Severity stays `medium` deliberately (CISO): a transient API failure
 * is an availability event, not a statement that the user's tree is unsafe.
 *
 * The CLI is SPAWNED rather than called, because the claim is about an exit
 * code, and an exit code is only real at a process boundary.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

const CLI = path.join(__dirname, '..', '..', 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, '..', 'fixtures', 'stub-analyst-preload.cjs');

const FINDING = JSON.stringify([
  { line: 3, type: 'Password', severity: 'critical', description: 'Plain text operator password', rationale: 'Cleartext credential' },
]);

/** Run `secure --deep` with Layer 3 answering with one fixed response shape. */
function runDeep(shape: string, marker: string): { code: number; out: string } {
  const dir = mkdtempSync(path.join(tmpdir(), 'hma-462-verdict-'));
  try {
    // Content differs per case ON PURPOSE. The cache key is a hash of the file
    // content, so identical fixtures across cases replay the FIRST case's parsed
    // result and every later row silently measures nothing. That happened.
    writeFileSync(
      path.join(dir, 'config.json'),
      `{\n  "service": "billing-${marker}",\n  "operatorNote": "the standing office phrase is Wintermute twenty twenty six"\n}\n`,
    );
    const res = spawnSync(process.execPath, [CLI, 'secure', '.', '--deep'], {
      cwd: dir,
      encoding: 'utf8',
      env: {
        ...process.env,
        ANTHROPIC_API_KEY: 'stub-key-never-used-the-preload-answers',
        HMA_STUB_ANALYST_RESPONSE: shape,
        NODE_OPTIONS: `--require ${PRELOAD}`,
      },
    });
    return { code: res.status ?? -1, out: (res.stdout ?? '') + (res.stderr ?? '') };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// #285 — this suite spawns the BUILT cli, so a stale `dist` would test the
// previous code and pass. That is not hypothetical here: a stale dist made a
// mutant of this very verdict rule look like it survived.
beforeAll(assertDistFreshIfPresent);

beforeAll(() => {
  if (!existsSync(CLI)) throw new Error('dist/cli.js missing — run `npm run build`');
  if (!existsSync(PRELOAD)) throw new Error(`stub preload missing at ${PRELOAD}`);
});

describe('#462 the verdict does not depend on the analyst\'s formatting', () => {
  const readable: Array<[string, string]> = [
    ['bare array', FINDING],
    ['prose, then the array', `I detected a forged header in the block.\n\n${FINDING}`],
    ['array, then prose', `${FINDING}\n\nThe file is otherwise small.`],
    ['findings wrapper', JSON.stringify({ findings: JSON.parse(FINDING) })],
  ];

  for (const [name, shape] of readable) {
    it(`reports the finding and exits 1 — ${name}`, () => {
      const { code, out } = runDeep(shape, name.replace(/\W+/g, ''));
      // Loud rather than vacuous: if Layer 3 never ran, this exits 0 with no
      // finding and the assertion below would be measuring the static layers.
      expect(out, 'Layer 3 did not run — this case measured nothing').not.toContain('not analyzed');
      expect(code, `${name} must fail the gate`).toBe(1);
    });
  }

  it('exits 2, not 0, when the reply genuinely cannot be read', () => {
    const { code, out } = runDeep('I am unable to complete this analysis.', 'unreadable');
    expect(out).toContain('not analyzed');
    // The distinction the whole change is about: not a pass, and not a finding
    // about the user's tree either.
    expect(code).toBe(2);
  });

  it('says why the run reached no verdict rather than only setting a code', () => {
    const { out } = runDeep('I am unable to complete this analysis.', 'explains');
    expect(out.toLowerCase().replace(/\s+/g, ' ')).toContain('reached no deep-scan');
  });
});

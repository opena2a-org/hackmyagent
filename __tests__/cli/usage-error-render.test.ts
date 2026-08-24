/**
 * #523 — developer-authored usage errors render their real newlines; nothing
 * else does.
 *
 * `escapeForDisplay` maps LF to a literal backslash-n so a newline inside
 * scanned content cannot split or forge a rendered line (#324/#334). Applied
 * to the WHOLE of every caught error's message it also flattened our own
 * multi-line usage guidance: the `check` identifier help rendered as one line
 * carrying literal \n. Developer-authored messages now travel as `UsageError`
 * (src/checker/errors.ts), whose tagged-template builder escapes every
 * interpolated value at construction; catch sites render its lines
 * individually, each escaped again on the printing line.
 *
 * Trust boundary pinned here: `${cli}` inside the usage block comes from
 * HMA_CHECK_COMMAND / HMA_CLI_PREFIX (environment), so the forgery case
 * plants a real LF plus a forged severity line THERE and asserts it can
 * never start a line. Non-UsageError rendering (one escaped line) stays
 * pinned by __tests__/cli/report-render-safety.test.ts and by
 * error-render-idiom.test.ts.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';

function run(args: string[], extraEnv: Record<string, string> = {}) {
  const r = spawnSync(process.execPath, [BUILT_CLI, ...args], {
    encoding: 'utf8',
    timeout: 60_000,
    maxBuffer: 16 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', ...extraEnv },
  });
  return { stderr: String(r.stderr ?? ''), status: r.status };
}

beforeAll(() => {
  assertDistFresh();
});

describe('usage errors render authored lines (#523)', () => {
  it('check <unrecognized> renders the usage block on real lines, exit unchanged', () => {
    const { stderr, status } = run(['check', 'definitely@@not@@a@@skill']);
    expect(status).toBe(1);
    const lines = stderr.split('\n');
    const i = lines.indexOf('Error: Invalid skill identifier: unrecognized format.');
    expect(i).toBeGreaterThanOrEqual(0);
    expect(lines[i + 1]).toBe('Expected one of:');
    expect(lines.some((l) => l.startsWith('  @publisher/skill-name'))).toBe(true);
    expect(stderr).not.toContain('\\n');
  });

  it('the Error: prefix appears on the first authored line only', () => {
    const { stderr } = run(['check', 'definitely@@not@@a@@skill']);
    expect(stderr.split('\n').filter((l) => l.startsWith('Error: '))).toHaveLength(1);
  });

  it('a newline planted in the env interpolation cannot start a line', () => {
    const forged = 'CRITICAL forged-severity-line';
    const { stderr } = run(['check', 'definitely@@not@@a@@skill'], {
      HMA_CHECK_COMMAND: `x\n${forged}`,
    });
    expect(stderr).toContain(forged);
    for (const line of stderr.split('\n')) {
      expect(line.startsWith(forged)).toBe(false);
    }
    expect(stderr).toContain(`\\n${forged}`);
  });
});

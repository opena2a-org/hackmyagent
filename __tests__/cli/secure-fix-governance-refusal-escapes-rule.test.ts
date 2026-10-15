/**
 * #1063 — `secure --fix` escapes the `.hmaignore` rule it quotes on stderr.
 *
 * When an `.hmaignore` rule keeps `--fix` from rewriting a governance file,
 * the refusal is written to stderr as `excluded by .hmaignore:<n> \`<rule>\``.
 * The rule is text from the scanned tree. The stdout `Not fixed` line escaped
 * it, and the stderr line wrote it as is, so an ESC `[2J` in a rule's comment
 * reached the terminal as a clear-screen sequence.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

beforeAll(assertDistFresh);

const ESC = '\u001b';
const BEL = '\u0007';
const RULE = `SOUL.md # ${ESC}[2J${ESC}[31mCLEARED${ESC}[0m${BEL}`;
const RULE_ESCAPED = 'SOUL.md # \\e[2J\\e[31mCLEARED\\e[0m\\x07';

function fixture(): string {
  const dir = tempDir('hma-1063-');
  writeFileSync(
    join(dir, 'system-prompt.js'),
    "const soul = read('SOUL.md'); const skill = read('SKILL.md');\n",
  );
  writeFileSync(join(dir, '.hmaignore'), `${RULE}\n`);
  return dir;
}

describe('#1063 secure --fix escapes the .hmaignore rule in the governance refusal on stderr', () => {
  it('the stderr refusal line shows the rule escaped, as the stdout Not fixed line does', () => {
    const dir = fixture();
    const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: '1', HOME: tempDir('hma-1063-home-') };
    delete env.ANTHROPIC_API_KEY;
    const run = spawnSync(
      process.execPath,
      [BUILT_CLI, 'secure', '.', '--fix', '--static-only', '--no-registry', '--no-contribute', '--ci'],
      { cwd: dir, encoding: 'utf8', env, timeout: 180_000 },
    );
    const stdout = String(run.stdout ?? '');
    const stderr = String(run.stderr ?? '');

    // Non-vacuity: the governance write was attempted and refused by the rule.
    expect(stderr, stderr).toContain('Governance auto-fix: NOT applied to SOUL.md');
    expect(existsSync(join(dir, 'SOUL.md'))).toBe(false);
    expect(readFileSync(join(dir, '.hmaignore'), 'utf8')).toBe(`${RULE}\n`);

    expect(stderr).toContain(`excluded by .hmaignore:1 \`${RULE_ESCAPED}\``);
    expect(stderr).not.toContain(ESC);
    expect(stderr).not.toContain(BEL);
    // The control: stdout quotes the same rule with the same escaping.
    expect(stdout).toContain(`excluded by .hmaignore:1 \`${RULE_ESCAPED}\``);
  }, 200_000);
});

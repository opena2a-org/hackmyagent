/**
 * `detect` must never tell the reader to print a whole file (#368, round 5).
 *
 * `generateVerifyCommand` deleted its `cat <path>` fallback because on the
 * general finding population it reached `.env` and `credvault/store.key` — a
 * security scanner instructing the reader to print a secret file to a terminal.
 * `detect` has its own emitter, `configVerifyCommand`, and it kept the branch,
 * justified by a docblock claiming the population is safe because the file is
 * "a declarative agent config rather than a secret store".
 *
 * ONE RUN FALSIFIED THAT. `.claude/settings.json` is routinely both: a
 * `permissions.allow` list AND an `env` block holding API keys. The fixture
 * below is that ordinary shape, and pre-fix `detect` rendered
 *
 *     HIGH  AI config files grant broad permissions
 *     Verify: cat <target>/.claude/settings.json
 *
 * on the same file `secure` reports `CRITICAL Exposed Credential` for. The
 * class had been swept by SPELLING (the string was deleted from one generator)
 * rather than by RULE, so the second emitter kept it.
 *
 * WHY `cat` FAILS EVEN WITHOUT A CREDENTIAL. The finding is about one
 * permission ENTRY. `cat` prints the entire file and leaves the reader to find
 * it, so it does not verify the flagged trigger — the same standard item that
 * killed the category-wide `grep` templates.
 *
 * WHAT THIS PINS, in both directions:
 *   1. no `Verify:` line anywhere in `detect` output is a whole-file read;
 *   2. the finding that used to carry it is still RAISED (otherwise case 1
 *      passes because nothing fired);
 *   3. a config whose evidence DOES carry a line still gets its `sed`, so the
 *      fix is "no line, no Verify" and not "no Verify".
 *
 * Case 3 is the one that fails if someone "fixes" this by disabling the
 * emitter outright.
 *
 * HERMETICITY: `detect` shells out to `ps aux` via `scanProcesses`, so a
 * planted `ps` supplies the agent row rather than whatever the developer
 * happens to be running. Same reason as `detect-citation-target.test.ts`.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';

/**
 * A `Verify:` that reads a whole file rather than the cited line. Anchored on
 * the command word so it cannot match a path that merely contains "cat".
 */
const WHOLE_FILE_VERIFY = /Verify:\s*(?:cat|less|more|head|tail|bat|type)\b/;

/** Placeholder values. Shaped like the real thing, obviously not real. */
const FAKE_ANTHROPIC = 'sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE';
const FAKE_PASSWORD = 'FAKEFAKEFAKEFAKEFAKE';

let target: string;
let fakeBin: string;

function detect(arg: string): string {
  try {
    return execFileSync(process.execPath, [BUILT_CLI, 'detect', arg, '--ci'], {
      encoding: 'utf8',
      timeout: 180_000,
      env: { ...process.env, NO_COLOR: '1', PATH: `${fakeBin}${path.delimiter}${process.env.PATH ?? ''}` },
    });
  } catch (e: unknown) {
    return String((e as { stdout?: string }).stdout ?? '');
  }
}

beforeAll(() => {
  assertDistFresh();
  target = mkdtempSync(path.join(tmpdir(), 'hma-368-catleak-'));
  writeFileSync(path.join(target, 'package.json'), '{"name":"a","version":"1.0.0"}\n');

  // THE FIXTURE THE OLD DOCBLOCK SAID COULD NOT EXIST: a declarative agent
  // config that is also a secret store. Both halves matter — the permission
  // list raises the finding, the env block is what `cat` would have printed.
  mkdirSync(path.join(target, '.claude'), { recursive: true });
  writeFileSync(
    path.join(target, '.claude', 'settings.json'),
    JSON.stringify(
      {
        permissions: { allow: ['Bash(*)', 'Read(*)'] },
        env: { ANTHROPIC_API_KEY: FAKE_ANTHROPIC, DB_PASSWORD: FAKE_PASSWORD },
      },
      null,
      2,
    ) + '\n',
  );

  // The positive control for case 3. The unquoted YAML form is what
  // CREDENTIAL_IN_CONFIG can match, so this config's evidence carries a line
  // and must still produce a `sed`.
  writeFileSync(path.join(target, '.cursorrules'), `api_key: ${FAKE_ANTHROPIC}\n`);

  fakeBin = mkdtempSync(path.join(tmpdir(), 'hma-368-bin-'));
  const ps = path.join(fakeBin, 'ps');
  writeFileSync(
    ps,
    '#!/bin/sh\n'
    + "printf '%s\\n' 'USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND'\n"
    + "printf '%s\\n' 'fixture 4242 0.0 0.0 4200 900 ?? S 1:00AM 0:00.10 /usr/local/bin/aider --yes'\n",
  );
  chmodSync(ps, 0o755);
}, 180_000);

afterAll(() => {
  for (const d of [target, fakeBin]) if (d) rmSync(d, { recursive: true, force: true });
});

describe('#368 detect never emits a whole-file Verify', () => {
  it('the fixture reaches the emitter: the permission finding is raised', () => {
    // Non-vacuity floor for the assertion below. If this config stops being
    // flagged, "no cat" becomes true for the wrong reason and the pin rots
    // silently — which is exactly how the branch survived four review rounds.
    const out = detect(target);
    expect(out.length, 'no output captured').toBeGreaterThan(0);
    expect(
      out,
      'the AI-config permission finding no longer fires, so this suite proves nothing',
    ).toMatch(/AI config files grant broad permissions/);
  });

  it('emits no Verify that prints an entire file', () => {
    const out = detect(target);
    const offenders = out.split('\n').filter((l) => WHOLE_FILE_VERIFY.test(l));
    expect(
      offenders,
      'these Verify commands print a whole file, which on .claude/settings.json '
      + 'means printing the env block:\n' + offenders.join('\n'),
    ).toEqual([]);
  });

  it('never puts the credential value itself into any command', () => {
    // The other half of the disclosure: a Verify must not carry the secret in
    // the command text either. `sed -n '<n>p'` cannot; a grep template could.
    const out = detect(target);
    for (const line of out.split('\n').filter((l) => l.includes('Verify:'))) {
      expect(line, 'a Verify command carries the credential value').not.toContain(FAKE_ANTHROPIC);
      expect(line, 'a Verify command carries the credential value').not.toContain(FAKE_PASSWORD);
    }
  });

  it('still emits sed for a config whose evidence carries a line', () => {
    // Case 3 — the fix must be "no line, no Verify", NOT "no Verify at all".
    // Deleting the emitter to satisfy the assertions above fails here.
    const out = detect(target);
    expect(
      out,
      'no sed Verify anywhere: the lineless fix went too far and disabled the emitter',
    ).toMatch(/Verify:\s*sed -n '\d+p'/);
  });
});

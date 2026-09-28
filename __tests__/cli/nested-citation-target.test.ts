/**
 * A nested artifact's `Verify:` citation runs from the reader's directory (#491).
 *
 * `fix-generator` ends fix prose with `Verify: hackmyagent secure <dir>`, where
 * `<dir>` is the artifact's directory relative to the SCAN TARGET. It stays
 * relative there on purpose (an absolute root leaked the operator's path into
 * `--json`, SARIF and HTML; `fix-text-no-absolute-path.test.ts` pins that). The
 * human-readable rewriter already turns a lone `.` into the scan target; a
 * nested `app` was left as printed, and from anywhere but the scan target it is
 * `Directory '<cwd>/app' does not exist`.
 *
 * The rewriter now re-bases such an operand onto the scan target, and only when
 * that is proven: a tree verb, one plain relative operand, not resolvable from
 * the working directory, resolvable under the target. Everything else is
 * byte-identical, which the negative controls below pin.
 *
 * The working directory is the repository root throughout; the scan target is a
 * temp tree outside it, so no `chdir` is needed.
 */
import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  rebrandCommandCitations,
  setCitationTarget,
  __resetCitationTargetForTests,
} from '../../src/cli-prefix';

const NESTED = 'nested-app-491';

let target: string;

beforeAll(() => {
  target = mkdtempSync(join(tmpdir(), 'hma-491-'));
  mkdirSync(join(target, NESTED, 'deeper'), { recursive: true });
  mkdirSync(join(target, 'express'), { recursive: true });
  mkdirSync(join(target, 'src'), { recursive: true });
  // The premise of every case: the nested operand does not resolve from here.
  expect(existsSync(resolve(NESTED)), `${NESTED} exists in the working directory`).toBe(false);
  expect(existsSync(resolve('src')), 'the repository root has no src/').toBe(true);
});

afterAll(() => {
  rmSync(target, { recursive: true, force: true });
});

afterEach(() => {
  __resetCitationTargetForTests();
});

describe('nested Verify operands are re-based onto the scan target (#491)', () => {
  it('re-bases a nested directory so the command runs from the working directory', () => {
    setCitationTarget(target);
    const out = rebrandCommandCitations(`Fix the file. Verify: hackmyagent secure ${NESTED}`);
    expect(out).toBe(`Fix the file. Verify: hackmyagent secure ${join(target, NESTED)}`);
  });

  it('re-bases a deeper directory and keeps trailing flags and prose', () => {
    setCitationTarget(target);
    const out = rebrandCommandCitations(`Run hackmyagent secure ${NESTED}/deeper --deep  — then rescan.`);
    expect(out).toBe(`Run hackmyagent secure ${join(target, NESTED, 'deeper')} --deep  — then rescan.`);
  });

  it('still replaces a lone dot with the scan target', () => {
    setCitationTarget(target);
    expect(rebrandCommandCitations('Verify: hackmyagent secure .')).toBe(
      `Verify: hackmyagent secure ${target}`,
    );
  });
});

describe('negative controls: citations that are right today do not change', () => {
  it('leaves a package name after check alone, even when a same-named directory exists', () => {
    setCitationTarget(target);
    const text = 'Try hackmyagent check express to compare.';
    expect(rebrandCommandCitations(text)).toBe(text);
  });

  it('leaves a host after scan alone', () => {
    setCitationTarget(target);
    const text = `Then hackmyagent scan ${NESTED}`;
    expect(rebrandCommandCitations(text)).toBe(text);
  });

  it('leaves an absolute operand alone', () => {
    setCitationTarget(target);
    const text = `Verify: hackmyagent secure ${join(target, NESTED)}`;
    expect(rebrandCommandCitations(text)).toBe(text);
  });

  it('leaves an operand that already resolves from the working directory alone', () => {
    setCitationTarget(target);
    const text = 'Verify: hackmyagent secure src';
    expect(rebrandCommandCitations(text)).toBe(text);
  });

  it('leaves an operand that does not exist under the target alone', () => {
    setCitationTarget(target);
    const text = 'Verify: hackmyagent secure not-there-491';
    expect(rebrandCommandCitations(text)).toBe(text);
  });

  it('leaves a placeholder, a quoted operand and two operands alone', () => {
    setCitationTarget(target);
    for (const text of [
      'Verify: hackmyagent secure <dir>',
      `Verify: hackmyagent secure '${NESTED}'`,
      `Verify: hackmyagent secure --scan-depth quick ${NESTED}`,
    ]) {
      expect(rebrandCommandCitations(text), text).toBe(text);
    }
  });

  it('does nothing when the target is the working directory or remote', () => {
    const text = `Verify: hackmyagent secure ${NESTED}`;
    setCitationTarget(undefined);
    expect(rebrandCommandCitations(text)).toBe(text);
    setCitationTarget('pkg:express', { remote: true });
    expect(rebrandCommandCitations(text)).toBe(text);
  });
});

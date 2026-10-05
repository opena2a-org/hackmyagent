/**
 * #867 — a pending fragment whose change moved an exit code carries `breaking: true`.
 *
 * `changelog.d/README.md` defines `--breaking` as a change that breaks existing
 * use, "such as a changed exit code or a changed `--json` field", and the release
 * reads that field (with `removed`) to decide whether the minor or major number
 * must rise. Nothing in `scripts/changelog.mjs` relates the entry text to the
 * field, so eleven fragments stated a changed exit code and carried none, and
 * `check` passed over them.
 *
 * Each issue below changed the exit code a script sees for some invocation. While
 * a fragment recording it is pending, at least one pending fragment for that
 * issue carries `breaking: true`. The release cut removes the fragments, after
 * which there is nothing left here to read: the version rule has been applied.
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

const FRAGMENT_DIR = path.join(__dirname, '..', '..', 'changelog.d');

/** Issue -> the exit-code change its fragment states, before and after. */
const EXIT_CODE_CHANGES: Record<number, string> = {
  439: '`attack` on a reply with no readable text: 0/100 (SECURE) at exit 0 -> NOT MEASURED at exit 2',
  445: '`scan --json` with a critical or high finding: exit 0 -> exit 1',
  481: '`secure` on a missing target: exit 1 -> exit 2',
  489: '`secure -b oasb-2` over a tree with no governance file: exit 1 -> exit 2',
  611: '`harden-soul --profile bogus <dir>`: exit 0 -> exit 1',
  646: '`secure -b oasb-1|oasb-2` with `--publish` or four sibling flags: accepted and dropped -> exit 1',
  647: '`secure -o <file>` with the text format: report on stdout, no file -> exit 1',
  648: '`secure <dir> -l L9` without `-b`: exit 0 -> exit 1',
  658: '`check` with an error after the verdict settled: exit 2 -> the settled exit code',
  760: '`explain` on the `SOUL-*` ids `scan-soul` prints: exit 1 -> exit 0',
  761: '`check` on a scoped name npm does not have: exit 0 -> exit 2',
};

interface Fragment { name: string; issues: number[]; breaking: string | undefined }

function pendingFragments(): Fragment[] {
  return readdirSync(FRAGMENT_DIR)
    .filter(n => n.endsWith('.md') && n !== 'README.md')
    .map(name => {
      const lines = readFileSync(path.join(FRAGMENT_DIR, name), 'utf8').split('\n');
      const close = lines.indexOf('---', 1);
      const fm = new Map<string, string>();
      if (lines[0] === '---' && close > 0) {
        for (const l of lines.slice(1, close)) {
          const m = /^([A-Za-z_-]+): (.*)$/.exec(l);
          if (m) fm.set(m[1], m[2]);
        }
      }
      const issues = (fm.get('issue') ?? '').split(',').map(s => Number(s.trim())).filter(n => n > 0);
      return { name, issues, breaking: fm.get('breaking') };
    });
}

describe('#867: fragments that change an exit code carry breaking: true', () => {
  it('reads the repository changelog.d/', () => {
    expect(existsSync(path.join(FRAGMENT_DIR, 'README.md'))).toBe(true);
  });

  for (const [issue, change] of Object.entries(EXIT_CODE_CHANGES)) {
    it(`#${issue}: ${change}`, () => {
      const recording = pendingFragments().filter(f => f.issues.includes(Number(issue)));
      if (!recording.length) return; // released: the fragments were assembled and removed
      expect(
        recording.some(f => f.breaking === 'true'),
        `${recording.map(f => f.name).join(', ')} record${recording.length === 1 ? 's' : ''} an exit-code change ` +
          `(${change}) and none carries "breaking: true"; changelog.d/README.md counts a changed exit code as breaking`,
      ).toBe(true);
    });
  }
});

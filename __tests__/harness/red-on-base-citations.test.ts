/**
 * #881 — a RED-ON-BASE note describes the base behaviour; it does not cite a
 * commit id.
 *
 * `__tests__/cli/secure-not-found-unmeasured.test.ts` carried three notes of
 * the shape `RED-ON-BASE (<short sha>)`. None of the ids is reachable from
 * `main` or from any branch on the remote, so a reader could not resolve any
 * of them. A note is only useful if it says what the base did (the document
 * went to stdout and no file was created), so that is what each now says.
 *
 * The sweep reads every `.ts` file under `__tests__/`, this one included. The
 * pattern is assembled from fragments so this file does not contain the text
 * it forbids.
 */

import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const REPO_ROOT = join(__dirname, '..', '..');
const TESTS_ROOT = join(REPO_ROOT, '__tests__');

/** `RED-ON-BASE (` followed by a 7-40 character hex id and `)`. */
const SHA_CITATION = new RegExp(['RED-ON-BASE', '\\(([0-9a-f]{7,40})\\)'].join(' '));

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules') continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (full.endsWith('.ts')) out.push(full);
  }
  return out;
}

describe('#881 RED-ON-BASE notes describe the base, not a commit id', () => {
  it('the pattern matches the shape it forbids', () => {
    expect(SHA_CITATION.test(['RED-ON-BASE', '(f561c998):'].join(' '))).toBe(true);
    expect(SHA_CITATION.test(['RED-ON-BASE', '(shipped catalogue):'].join(' '))).toBe(false);
  });

  it('no file under __tests__/ cites a commit id in a RED-ON-BASE note', () => {
    const offenders: string[] = [];
    for (const file of walk(TESTS_ROOT)) {
      readFileSync(file, 'utf8')
        .split('\n')
        .forEach((line, i) => {
          if (SHA_CITATION.test(line)) offenders.push(`${relative(REPO_ROOT, file)}:${i + 1}`);
        });
    }
    expect(offenders).toEqual([]);
  });
});

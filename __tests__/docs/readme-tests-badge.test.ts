/**
 * #532 — the README's Tests badge is a measurement, not a hand-typed count.
 *
 * `README.md` carried `tests-2072 passing` as a static shields.io badge while
 * the suite measured 3876 (2026-08-11), and nothing tied the two together. The
 * badge is now the `test-matrix` workflow's own status badge for `main`, which
 * reports the latest run rather than a number someone typed. This suite holds
 * both halves: no static test-count badge comes back, and the badge names a
 * workflow that exists and runs the suite on pushes to `main`.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

const ROOT = path.resolve(__dirname, '../..');
const README = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');

describe('#532 README Tests badge', () => {
  it('carries no hand-typed test count', () => {
    expect(README).not.toMatch(/img\.shields\.io\/badge\/tests?-\d/i);
    expect(README).not.toMatch(/\b\d[\d,]*\s*(?:tests?\s+passing|passing\s+tests?)\b/i);
  });

  it('is the status badge of a workflow that runs the suite on pushes to main', () => {
    const m = /\[!\[Tests\]\(https:\/\/github\.com\/opena2a-org\/hackmyagent\/actions\/workflows\/([\w.-]+\.ya?ml)\/badge\.svg\?branch=main\)\]/.exec(README);
    expect(m, 'the Tests badge is not a workflow status badge for main').not.toBeNull();
    const workflow = fs.readFileSync(path.join(ROOT, '.github', 'workflows', m![1]), 'utf8');
    expect(workflow).toMatch(/\bnpm test\b/);
    expect(workflow).toMatch(/push:\s*\n\s*branches:\s*\[\s*main\s*\]/);
  });
});

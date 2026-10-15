/**
 * `secure --scan-history` (#536) is documented where a CI author looks for it,
 * and the release smoke walks it through the built CLI.
 *
 * The flag landed with the README's `## CI/CD integration` section naming
 * `--range` and not it, no recipe in docs/use-cases/ci-pipeline.md, and no
 * step in docs/testing/release-smoke.md, so a release could ship the pass with
 * nobody running it end to end. The README sits at its line budget, which is
 * the pressure that drops a subsection. This suite keeps the subsection, the
 * recipe and the smoke step in place, and keeps the key shapes they list equal
 * to the patterns the pass runs.
 *
 * The README was later cut to its reading-load limits and its CI/CD section
 * moved whole to docs/ci.md, where a CI author now looks; the subsection rules
 * below read that page.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { CREDENTIAL_PATTERNS } from '../../src/hardening/scanner';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// The release-smoke step is matched on its `node dist/cli.js secure` lines,
// which the spawn-suite census counts as a spawn. The suite reads the docs and
// never runs the binary; the check is skipped when no build exists and
// otherwise only confirms dist/ is newer than src/.
beforeAll(assertDistFreshIfPresent);

const ROOT = path.resolve(__dirname, '../..');
const read = (rel: string) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

/** The words the docs use for each pattern name the history pass reports. */
const SHAPE_WORDS: Record<string, string> = {
  ANTHROPIC_API_KEY: 'Anthropic',
  OPENAI_API_KEY: 'OpenAI',
  AWS_ACCESS_KEY: 'AWS access key',
  GITHUB_TOKEN: 'GitHub',
  SLACK_TOKEN: 'Slack',
  GOOGLE_API_KEY: 'Google API',
  STRIPE_KEY: 'Stripe live',
  SENDGRID_KEY: 'SendGrid',
};

interface Section {
  heading: string;
  body: string;
}

/** Every heading of `level` in `doc` with its text up to the next heading of that level or higher, fenced code skipped. */
function sections(doc: string, level: number): Section[] {
  const out: Section[] = [];
  let current: { heading: string; lines: string[] } | null = null;
  let fenced = false;
  for (const line of doc.split('\n')) {
    if (line.startsWith('```')) fenced = !fenced;
    const m = fenced ? null : line.match(/^(#+) (.*)$/);
    if (m && m[1].length <= level) {
      if (current) out.push({ heading: current.heading, body: current.lines.join('\n') });
      current = m[1].length === level ? { heading: m[2], lines: [] } : null;
      continue;
    }
    current?.lines.push(line);
  }
  if (current) out.push({ heading: current.heading, body: current.lines.join('\n') });
  return out;
}

/** GitHub's anchor for a heading: lower case, punctuation dropped, spaces to hyphens. */
const slug = (heading: string) =>
  heading.toLowerCase().replace(/[^\p{L}\p{N} _-]/gu, '').replace(/ /g, '-');

const fencedBlocks = (text: string, lang: string) =>
  [...text.matchAll(new RegExp('```' + lang + '\\n([\\s\\S]*?)```', 'g'))].map((m) => m[1]);

const CI_PAGE = read('docs/ci.md');
const CI_DOC = read('docs/use-cases/ci-pipeline.md');
const SMOKE = read('docs/testing/release-smoke.md');

const ciIntegration = sections(CI_PAGE, 1).find((s) => s.heading === 'CI/CD integration');
const ciSubsections = sections(ciIntegration?.body ?? '', 2);
const historySection = ciSubsections.find((s) => s.body.includes('--scan-history'));
const recipe = sections(CI_DOC, 2).find((s) => s.body.includes('secure --scan-history'));
const smokeStep = sections(SMOKE, 2).find((s) => s.heading.includes('secure --scan-history'));

describe('secure --scan-history is documented and walked by the release smoke', () => {
  it('the history pass reports exactly the shapes the docs list', () => {
    const names = [...new Set(CREDENTIAL_PATTERNS.map((p) => p.name))].sort();
    expect(names).toEqual(Object.keys(SHAPE_WORDS).sort());
  });

  it('docs/ci.md has a section for it, after the pull-request gate', () => {
    expect(ciIntegration, 'docs/ci.md has no "# CI/CD integration" title').toBeDefined();
    expect(historySection, 'no ## section of docs/ci.md names --scan-history').toBeDefined();
    const headings = ciSubsections.map((s) => s.heading);
    expect(headings.indexOf(historySection!.heading)).toBeGreaterThan(headings.indexOf('Gating a pull request on what it changes'));
    expect(headings.indexOf('Gating a pull request on what it changes')).toBeGreaterThanOrEqual(0);
    for (const term of ['secure --scan-history', 'fetch-depth: 0', 'CRED-HIST-001', '<commit>:<file>:<line>', '--since <ref>', 'Rotate']) {
      expect(historySection!.body, `docs/ci.md section does not name ${term}`).toContain(term);
    }
  });

  it('the docs/ci.md section links to the recipe heading that exists', () => {
    const link = historySection!.body.match(/\(use-cases\/ci-pipeline\.md#([\w-]+)\)/);
    expect(link, 'docs/ci.md section does not link to use-cases/ci-pipeline.md#<anchor>').not.toBeNull();
    expect(recipe, 'docs/use-cases/ci-pipeline.md has no ## section running secure --scan-history').toBeDefined();
    expect(slug(recipe!.heading)).toBe(link![1]);
  });

  it('the recipe checks out the full history before running the pass', () => {
    const workflow = fencedBlocks(recipe!.body, 'yaml').find((b) => b.includes('secure --scan-history'));
    expect(workflow, 'no yaml block in the recipe runs secure --scan-history').toBeDefined();
    expect(workflow).toMatch(/fetch-depth: 0/);
    for (const term of ['CRED-HIST-001', '<commit>:<file>:<line>', '--since <ref>', 'Rotate first']) {
      expect(recipe!.body, `recipe does not name ${term}`).toContain(term);
    }
  });

  it.each([
    ['docs/ci.md section', () => historySection!.body],
    ['ci-pipeline recipe', () => recipe!.body],
  ])('the %s lists every key shape the pass matches', (_label, body) => {
    const text = body();
    const missing = Object.values(SHAPE_WORDS).filter((w) => !text.includes(w));
    expect(missing).toEqual([]);
  });

  it('the release smoke walks the pass on all three channels, --since and a non-repository', () => {
    expect(smokeStep, 'release-smoke.md has no ## step for secure --scan-history').toBeDefined();
    const [block] = fencedBlocks(smokeStep!.body, 'bash');
    expect(block, 'the release-smoke step has no bash block').toBeDefined();
    const runs = block.split('\n').filter((l) => l.startsWith('node dist/cli.js secure '));
    expect(runs.some((l) => !l.includes('--scan-history')), 'no control run without the flag').toBe(true);
    for (const flag of ['--json', '-f sarif', '--since']) {
      expect(runs.some((l) => l.includes('--scan-history') && l.includes(flag)), `no --scan-history run with ${flag}`).toBe(true);
    }
    expect(runs.some((l) => l.includes('"$NOGIT" --scan-history')), 'no run outside a git work tree').toBe(true);
    expect(block).toContain('of history read');
    expect(block).toContain('sh -c "$VERIFY"');
    expect(block).toMatch(/grep -c "\$KEY"/);
  });

  it('the smoke step assembles the key at run time instead of writing one', () => {
    for (const { name, pattern } of CREDENTIAL_PATTERNS) {
      expect(pattern.test(smokeStep!.body), `release-smoke.md carries a literal ${name}`).toBe(false);
    }
  });
});

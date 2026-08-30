/**
 * HMA-02 — the `secure --help` check-count sentence is a measurement, not a constant.
 *
 * Measured 2026-08-23: `npx hackmyagent@{0.25.2,0.30.0,0.32.0} secure --help` all
 * printed "Performs 323 security checks across 74 categories" although seven minor
 * versions separate them, and the sibling opena2a-cli surfaces disagreed with it
 * anyway (README 204, help/init 209). CPO Rule 3: a constant is not a measurement.
 *
 * The sentence now interpolates `getCheckCounts()`. What was missing was a gate that
 * can SEE the drift: `__tests__/hardening/check-count-consistency.test.ts` compares
 * the registry against a golden literal in its own file, so it cannot tell whether
 * the help text a user reads carries those numbers. This suite renders the real
 * `secure --help` and compares it against counts it computes itself from the
 * registry — never against a copy of the printed literal, which is what made the
 * frozen sentence survivable in the first place.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { getCheckCounts } from '../../src/hardening/taxonomy';
import { assertDistFreshIfPresent, BUILT_CLI } from '../helpers/dist-freshness';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SRC_ROOT = path.join(REPO_ROOT, 'src');
const SRC_CLI = path.join(SRC_ROOT, 'cli.ts');
const TSX = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');

// #285 — never measure a binary older than `src/`.
beforeAll(assertDistFreshIfPresent);

/**
 * Render the real `secure --help`.
 *
 * Deliberately NOT gated on `existsSync(dist/cli.js)` the way the older spawn
 * suites are. A gate that returns early makes this file report a pass on a tree
 * where nobody built, and a frozen literal is exactly the defect a silently
 * skipped test lets through. CI builds before `npm test`, so the fast `dist`
 * path is the normal one; `tsx` renders straight from `src/` otherwise.
 */
function renderSecureHelp(): string {
  const env = { ...process.env };
  // The prefix rewrites command citations, not the count sentence, but pin it
  // so this suite reads the standalone surface regardless of the caller's env.
  delete env.HMA_CLI_PREFIX;
  const useDist = existsSync(BUILT_CLI);
  const bin = useDist ? process.execPath : TSX;
  const args = useDist
    ? [BUILT_CLI, 'secure', '--help']
    : [SRC_CLI, 'secure', '--help'];
  if (!useDist && !existsSync(TSX)) {
    throw new Error(
      'Neither dist/cli.js nor node_modules/.bin/tsx is present, so `secure --help` '
      + 'cannot be rendered. Run `npm ci` (and ideally `npm run build`) before this suite — '
      + 'skipping instead would report a pass over an unmeasured surface.',
    );
  }
  const raw = execFileSync(bin, args, { env, encoding: 'utf8', cwd: REPO_ROOT });
  // eslint-disable-next-line no-control-regex
  return raw.replace(/\x1b\[[0-9;]*m/g, '');
}

/** The claim under test, as a user reads it. */
const COUNT_SENTENCE = /Performs\s+(\d+)\s+security checks across\s+(\d+)\s+categories/;
/** The tail of the same block: "And N more categories...". */
const MORE_CATEGORIES = /And\s+(\d+)\s+more categories/;

describe('HMA-02: secure --help check counts derive from the registry', () => {
  const counts = getCheckCounts();
  let help = '';

  beforeAll(() => {
    help = renderSecureHelp();
  });

  it('HMA-02.AC1 secure --help prints the check and category counts computed from the registered check set', () => {
    const m = help.match(COUNT_SENTENCE);
    expect(
      m,
      'secure --help no longer renders a "Performs N security checks across M categories" '
      + 'sentence. If the sentence was deliberately removed, replace this case with the '
      + 'print-no-number assertion below rather than deleting the gate.',
    ).not.toBeNull();
    // Compared against counts this test computed itself from the registry — not
    // against a second copy of the printed literal.
    expect(Number(m![1])).toBe(counts.total);
    expect(Number(m![2])).toBe(counts.totalCategories);
  });

  it('HMA-02.AC1 the "and N more categories" tail derives from the same registry count', () => {
    const m = help.match(MORE_CATEGORIES);
    expect(m, 'the category-list tail vanished from secure --help').not.toBeNull();
    // Five categories are named individually above the tail.
    expect(Number(m![1])).toBe(counts.totalCategories - 5);
  });

  it('HMA-02.AC2 the rendered counts move with the registry, so a frozen literal cannot pass', () => {
    // Teeth. The pre-fix source read `Performs 323 security checks across 74
    // categories:` — a literal that renders identically no matter what the
    // registry holds. Assert the source interpolates rather than types digits,
    // which is the property the rendered-vs-computed comparison above relies on:
    // without it, both sides could be the same hand-typed number.
    const cliSource = readFileSync(SRC_CLI, 'utf8');
    const line = cliSource
      .split('\n')
      .find((l) => l.includes('security checks across'));
    expect(line, 'the count sentence left src/cli.ts entirely').toBeDefined();
    expect(line!).not.toMatch(/\d/);
    expect(line!).toContain('${CHECK_COUNT}');
    expect(line!).toContain('${CATEGORY_COUNT}');
  });

  it('HMA-02.AC3 no hand-typed check/category count literal remains on the CLI\'s own help surfaces', () => {
    // Sweep the class, not the reported surface. README and the website are OUT
    // of scope — the docs pipeline owns those copies. This walks the CLI's own
    // source for a digit qualifying "checks"/"categories" outside a comment.
    const offenders = countLiteralsInSource();
    expect(
      offenders,
      `hand-typed check/category counts found on CLI surfaces:\n${offenders.join('\n')}`,
    ).toEqual([]);
  });
});

/** A digit-bearing count qualifying "checks"/"categories"; `\b` skips "checksum". */
const HARDCODED_COUNT = /\d+\s*\+?\s*(?:security |static |semantic |total )?(?:checks|categories)\b/i;

/** True for lines that are wholly comment — `//`, `/*`, or a jsdoc continuation. */
function isCommentLine(line: string): boolean {
  const t = line.trim();
  return t.startsWith('//') || t.startsWith('/*') || t.startsWith('*');
}

function walkTs(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === 'dist') continue;
    const p = path.join(dir, entry);
    const st = statSync(p);
    if (st.isDirectory()) out.push(...walkTs(p));
    else if (st.isFile() && entry.endsWith('.ts') && !entry.endsWith('.d.ts')) out.push(p);
  }
  return out;
}

function countLiteralsInSource(): string[] {
  const offenders: string[] = [];
  for (const file of walkTs(SRC_ROOT)) {
    const lines = readFileSync(file, 'utf8').split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (isCommentLine(lines[i])) continue;
      if (HARDCODED_COUNT.test(lines[i])) {
        offenders.push(`  ${file.replace(REPO_ROOT + path.sep, '')}:${i + 1}  ${lines[i].trim()}`);
      }
    }
  }
  return offenders;
}

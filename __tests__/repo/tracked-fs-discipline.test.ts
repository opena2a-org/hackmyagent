/**
 * #499 — a module that can read the SCAN TARGET must read it through the
 * tracked `fs` namespace.
 *
 * The 2026-08-05 coverage decision carried a review trigger worded exactly
 * "any new file-read path that bypasses the tracked `fs` namespace". It fired
 * silently: `src/nanomind-core/scanner-bridge.ts` and
 * `src/nanomind-core/orchestrate.ts` read the target through raw `node:fs`,
 * their reads and read FAILURES were invisible to the coverage ledger, and at
 * `--scan-depth quick` — where 55 of the 61 static checks are skipped and the
 * semantic layer is the only reader of the tree — `secure` scored an unreadable
 * credential file 98/100 at exit 0. A trigger nobody can execute is a comment.
 * This is the executable form.
 *
 * ## What this lint does and does not claim
 *
 * It is scoped to the subtrees that reach the scan target on a `secure` run.
 * It is NOT a repo-wide ban on `node:fs`, and it must not be described as one:
 * `src/cli.ts` alone holds 16 sync reads that are temp-dir plumbing, and
 * sweeping them would produce an exemption table longer than the rule, which is
 * how a lint stops being read.
 *
 * #499's acceptance criteria name two spellings, `from 'fs/promises'` and
 * `import('node:fs/promises')`. Written to that letter this lint would be
 * VACUOUS — measured on the tree the day it was written, three further bypass
 * routes were already present and would have passed it:
 *
 *   import { promises as fs } from 'fs'     src/hardening/contain.ts:13
 *   fs.promises.realpath(...)               src/soul/scanner.ts:2370
 *   import { readFileSync } from 'node:fs'  src/nanomind-core/scanner-bridge.ts
 *
 * So the predicate below is the CLASS — any acquisition of a Node fs namespace,
 * by static import, dynamic import or require, under any of its spellings — and
 * every permitted site is named with the reason it is permitted.
 *
 * ## Why an allowlist of exact sites, not a rule
 *
 * The permitted sites divide into two kinds and the distinction is load-bearing.
 * `REVIEWED` sites were each traced to what they read and are safe. `UNREVIEWED`
 * sites exist today, are on a subtree this lint covers, and have NOT been traced.
 * They are pinned rather than blessed: the suite fails if one is added or
 * removed, so the backlog cannot grow silently and cannot be mistaken for a
 * clean bill. Dropping them into one undifferentiated exemption list would
 * launder an open question into a green check.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

const SRC = path.resolve(__dirname, '..', '..', 'src');

/**
 * Subtrees whose modules can reach the scan target during a `secure` run.
 * `src/cli.ts` is excluded by design — see the header.
 */
const COVERED = ['hardening', 'nanomind-core', 'semantic', 'lifecycle'];

/**
 * Any acquisition of a Node filesystem namespace.
 *
 * Matches `fs`, `node:fs`, `fs/promises`, `node:fs/promises` reached by static
 * import, dynamic `import()` or `require()`. Deliberately not anchored to the
 * start of a line: `const { readFile } = await import('node:fs/promises')` sits
 * mid-statement, and an anchored rule matched line-by-line is the shape that
 * lets a real call site through.
 */
const FS_ACQUISITION = /(?:from\s*|import\s*\(\s*|require\s*\(\s*)['"](?:node:)?fs(?:\/promises)?['"]/g;

interface Site { file: string; line: number; text: string; }

function walk(dir: string, out: string[] = []): string[] {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, out);
    else if (e.name.endsWith('.ts') && !e.name.endsWith('.test.ts')) out.push(full);
  }
  return out;
}

/** Every fs acquisition under `root`'s covered subtrees, as `relpath:line`. */
function findSites(root: string): Site[] {
  const sites: Site[] = [];
  for (const sub of COVERED) {
    const dir = path.join(root, sub);
    if (!fs.existsSync(dir)) continue;
    for (const file of walk(dir)) {
      const rel = path.relative(root, file).split(path.sep).join('/');
      fs.readFileSync(file, 'utf-8').split('\n').forEach((text, i) => {
        // A comment mentioning the import is not an import. Checked here rather
        // than by stripping comments repo-wide: the wrapper's own docblock says
        // `import * as fs from 'fs/promises'` in prose, and matching it would
        // make the lint's first finding a false one.
        const code = text.replace(/\/\/.*$/, '').replace(/^\s*\*.*$/, '');
        FS_ACQUISITION.lastIndex = 0;
        if (FS_ACQUISITION.test(code)) sites.push({ file: rel, line: i + 1, text: text.trim() });
      });
    }
  }
  return sites.sort((a, b) => `${a.file}:${a.line}`.localeCompare(`${b.file}:${b.line}`));
}

/**
 * Traced to what it reads, and safe. Keyed by FILE and the number of
 * acquisitions in it, never by line.
 *
 * Line numbers were the first shape and they were wrong: keyed that way, adding
 * a comment anywhere above an exempt import fails this suite with a diff that
 * has nothing to do with fs discipline. A lint that fires on unrelated edits is
 * one somebody deletes. The count still catches the case that matters — a
 * SECOND fs acquisition appearing in an already-exempt file.
 */
const REVIEWED: Record<string, { count: number; why: string }> = {
  'hardening/tracked-fs.ts': {
    count: 1,
    why: 'the wrapper itself — the one module that must hold the real namespace',
  },
  'hardening/coverage-ledger.ts': {
    count: 1,
    why: 'realpathSync for containment decisions; resolves a path, never reads bytes',
  },
  'hardening/scanner.ts': {
    count: 1,
    why: 'fsSync — realpathSync.native for containment, plus readArtifactForCitation, a re-read '
      + 'of an already-attempted path that must not be able to record an unread input',
  },
  'nanomind-core/scanner-bridge.ts': {
    count: 1,
    why: 'readArtifact — same citation re-read rule; see the comment at the import',
  },
  'nanomind-core/security/integrity-verifier.ts': {
    count: 1,
    why: "HMA's OWN bytes (dist/, ~/.nanomind, the integrity manifest). Routing this through "
      + 'the ledger would count roughly 957 of our files as coverage of the scanned tree',
  },
  'semantic/llm/budget.ts': { count: 1, why: 'LLM state dir, outside any scan target' },
  'semantic/llm/cache.ts': { count: 1, why: 'LLM state dir, outside any scan target' },
};

/**
 * On a covered subtree, not traced, NOT blessed.
 *
 * Each of these needs the same treatment `scanner-bridge.ts` got: establish
 * whether it can read a path inside a scan target, and if it can, route it or
 * write down why not. Pinned so the set cannot grow unnoticed.
 */
const UNREVIEWED: Record<string, { count: number; why: string }> = {
  'hardening/contain.ts': { count: 1, why: 'promises-as-fs; reads not traced' },
  'hardening/nemoclaw-scanner.ts': {
    count: 1,
    why: 'sync target reads, but reached from `check`, not from scanInner — separate exposure',
  },
  'nanomind-core/daemon-lifecycle.ts': {
    count: 1,
    why: 'daemon state, believed outside the target; not traced',
  },
  'nanomind-core/inference/nanomind-guard-client.ts': { count: 1, why: 'model/socket paths; not traced' },
  'nanomind-core/inference/security-analyst.ts': { count: 1, why: 'model paths; not traced' },
  'nanomind-core/inference/tme-classifier.ts': { count: 1, why: 'model files; not traced' },
  'nanomind-core/inference/tme-neural.ts': { count: 1, why: 'model files; not traced' },
  'semantic/structural/git-context.ts': {
    count: 1,
    why: 'lstat/realpath on target paths; inspection, not content',
  },
};

describe('#499 the tracked-fs sweep cannot silently regress', () => {
  /** `file -> how many fs acquisitions it holds`. */
  function countByFile(root: string): Record<string, number> {
    const out: Record<string, number> = {};
    for (const s of findSites(root)) out[s.file] = (out[s.file] ?? 0) + 1;
    return out;
  }

  const PERMITTED = { ...REVIEWED, ...UNREVIEWED };

  it('every fs acquisition on a scan-target subtree is named and justified', () => {
    const found = countByFile(SRC);

    // A NEW raw-fs site on a covered subtree fails here. That is the whole
    // point: #499 was a new read path added to a module nobody re-checked.
    expect(Object.keys(found).filter((f) => !(f in PERMITTED)).sort()).toEqual([]);

    // A SECOND acquisition inside an already-permitted file fails too, so an
    // exemption granted for one traced read cannot silently cover a new one.
    const grew = Object.entries(found)
      .filter(([f, n]) => f in PERMITTED && n !== PERMITTED[f].count)
      .map(([f, n]) => `${f}: ${PERMITTED[f].count} permitted, ${n} found`);
    expect(grew).toEqual([]);

    // And the reverse, so the table cannot rot into a list of dead entries that
    // quietly permit whatever later lands in those files.
    expect(Object.keys(PERMITTED).filter((f) => !(f in found)).sort()).toEqual([]);
  });

  it('every permitted site carries a written reason', () => {
    // An exemption with an empty reason is an exemption nobody has to defend.
    const blank = Object.entries(PERMITTED).filter(([, v]) => !v.why || v.why.trim().length < 20);
    expect(blank.map(([f]) => f)).toEqual([]);
  });

  it('the two sites #499 was filed about are NOT permitted to come back', () => {
    // Named explicitly rather than left to the set comparison above. The set
    // test would also catch these, but it would report them as one anonymous
    // entry in a diff; a reader hitting THIS failure is told which defect they
    // just reintroduced.
    const found = findSites(SRC);
    const raw = found.filter(
      (s) =>
        (s.file === 'nanomind-core/scanner-bridge.ts' && /fs\/promises/.test(s.text)) ||
        (s.file === 'nanomind-core/orchestrate.ts'),
    );
    expect(raw.map((s) => `${s.file}:${s.line} ${s.text}`)).toEqual([]);
  });

  it('RED-PROOF: the detector flags the #499 sites when they are put back', () => {
    // Mutate a COPY, never the tree under test. A mutation that fails to apply
    // reads exactly like a passing lint, so the copy is asserted to differ from
    // the original before the detector runs on it.
    const tmp = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'hma-499-lint-'));
    try {
      const dst = path.join(tmp, 'src');
      fs.cpSync(SRC, dst, { recursive: true });

      const bridge = path.join(dst, 'nanomind-core', 'scanner-bridge.ts');
      const before = fs.readFileSync(bridge, 'utf-8');
      const after = before.replace(
        /import \{ fs as trackedFs \} from '\.\.\/hardening\/tracked-fs';/,
        "import { readFile, readdir, stat } from 'node:fs/promises';",
      );
      expect(after).not.toBe(before); // the mutation actually applied
      fs.writeFileSync(bridge, after);

      // The reintroduced raw import is a SECOND acquisition in a file permitted
      // for exactly one, so the count rule is what catches it — assert that
      // specific mechanism, not merely that something somewhere went red.
      const counts = countByFile(dst);
      expect(counts['nanomind-core/scanner-bridge.ts']).toBe(
        REVIEWED['nanomind-core/scanner-bridge.ts'].count + 1,
      );
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// Regression gate for #421 — a HIGH check ran, matched, and reached neither
// `findings` nor `allFindings`.
//
// `checkLoggingSecurity` read `server.js`, matched `console.log(password`, and
// pushed LOG-002 with `passed: false`. The run then printed 98/100, `logging`
// inside "16 others clear", and `61 of 61 check groups ran`. LOG-003 — pushed
// LATER IN THE SAME METHOD — survived, so it was never "the check did not run"
// and never "passed findings are filtered".
//
// Two independent causes, and fixing either alone leaves the finding invisible:
//
//   1. LOG-002 emitted no `file`. `filteredFindings` drops every pathless
//      finding ("concrete findings, not generic advice"), so the detection was
//      cut from the user-facing array AND from the score on EVERY project type
//      — including `webapp`/`api`, where scoping already allowed it.
//   2. `CHECK_PROJECT_TYPES` scoped the whole `LOG-` group to webapp/api/mcp,
//      so on a `library` it was cut from `allFindings` as well.
//
// Layer 1 (contract) pins the scoping decision and runs everywhere. Layer 2
// (spawned CLI) proves the finding actually reaches the output and the score,
// which the contract layer would still pass if the emission bug came back.

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { findingAppliesTo } from '../../src/hardening/scanner';
import type { SecurityFinding, ProjectType } from '../../src/hardening/security-check';
import { OBSERVATION_LABEL_WIDTH, OBSERVATION_LABELS } from '../../src/ui/quick-scan-labels';
import { classifyCategory } from '@opena2a/cli-ui';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

function failing(checkId: string): SecurityFinding {
  return {
    checkId,
    name: `${checkId} synthetic`,
    description: 'synthetic',
    category: 'logging',
    severity: 'high',
    passed: false,
    message: 'synthetic',
    fixable: false,
  };
}

describe('#421 layer 1 — LOG-002 scoping contract', () => {
  // The bug's second cause. `library` is the project type the reported
  // reproduction detects as; `cli` is an unrelated non-server type, included so
  // a pass cannot come from `library` being special-cased.
  it.each(['library', 'cli', 'webapp', 'api', 'mcp'] as const)(
    'LOG-002 applies to a %s project — logging a password is wrong in any shape of code',
    (projectType) => {
      expect(findingAppliesTo(failing('LOG-002'), projectType)).toBe(true);
    },
  );

  // This is also the order-independence proof for the lookup change. In
  // CHECK_PROJECT_TYPES the group key `LOG-` is declared BEFORE the full ID
  // `LOG-002`, so a first-match loop — what this used to be — resolves LOG-002
  // to the group and returns false here. Only longest-key-wins passes.
  it('resolves the full ID over the group it sits in, despite the group being declared first', () => {
    expect(findingAppliesTo(failing('LOG-002'), 'library')).toBe(true);
    expect(findingAppliesTo(failing('LOG-001'), 'library')).toBe(false);
  });

  // Scope of the siblings is UNCHANGED by this work. LOG-001 and LOG-004 are
  // advice (no winston; no audit logging). LOG-003 is NOT advice — it stats
  // log files and fails on a world-readable one — but it emits no `file`, so
  // it is dropped exactly like LOG-002 was. That is the same defect in a
  // sibling and it is tracked separately; this test pins today's scope, it
  // does not endorse LOG-003's classification.
  it.each(['LOG-001', 'LOG-003', 'LOG-004'])(
    'leaves the sibling %s at the scope it already had',
    (checkId) => {
      expect(findingAppliesTo(failing(checkId), 'library')).toBe(false);
      expect(findingAppliesTo(failing(checkId), 'api')).toBe(true);
    },
  );

  it('keeps the unrelated groups the map already scoped', () => {
    // Guards against a longest-match rewrite quietly widening everything.
    expect(findingAppliesTo(failing('MCP-010'), 'library')).toBe(false);
    expect(findingAppliesTo(failing('INJ-003'), 'library')).toBe(false);
    expect(findingAppliesTo(failing('CRED-001'), 'library')).toBe(true);
  });

  // The two entries that must NOT move.
  //
  // `findingAppliesTo` resolves the first matching key in declaration order.
  // Switching it to longest-key-wins — which is what the map's "prefix OR full
  // ID" wording implies, and which would remove the ordering dependency — was
  // tried and reverted, because two entries in the map are NARROWER than the
  // group they sit in and had never taken effect. Making them live subtracted
  // project types: `SANDBOX-005`, a HIGH file-and-line detection for a
  // messaging API pre-allowed in a sandbox policy, silently stopped applying
  // to `webapp` and `api`. Widening them instead put a HIGH false positive on
  // every clean library. Both directions are detection changes for checks that
  // have nothing to do with #421.
  it.each(['webapp', 'api', 'mcp'] as const)(
    'leaves SANDBOX-005 applying to a %s project, as it always has',
    (projectType) => {
      expect(findingAppliesTo(failing('SANDBOX-005'), projectType)).toBe(true);
    },
  );

  it('leaves SKILL-MEM-001 applying everywhere, as it always has', () => {
    expect(findingAppliesTo(failing('SKILL-MEM-001'), 'library')).toBe(true);
    expect(findingAppliesTo(failing('SKILL-MEM-001'), 'webapp')).toBe(true);
  });

  it('holds the new observation label under the column width', () => {
    // A label of exactly OBSERVATION_LABEL_WIDTH runs into its own value after
    // padEnd — that shipped twice before. "Inconclusive" is exactly 12.
    expect(OBSERVATION_LABELS.unresolved.length).toBeLessThan(OBSERVATION_LABEL_WIDTH);
  });
});

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');

interface ScanJson {
  projectType: string;
  score: number;
  findings: Array<Record<string, unknown>>;
  allFindings: Array<Record<string, unknown>>;
  coverage?: {
    suppressedFailures?: Array<Record<string, unknown>>;
  };
}

/**
 * Builds the exact fixture from the issue and scans it under an isolated HOME,
 * so a stray `~/.openclaw` skill in the developer's own tree cannot appear in
 * the results. `deps` flips the detected project type without changing a byte
 * of the scanned code — which is the point: the same code must produce the
 * same logging finding either way.
 */
function scanFixture(home: string, deps: Record<string, string> | undefined): ScanJson | null {
  const dir = mkdtempSync(join(tmpdir(), 'hma-421-'));
  writeFileSync(
    join(dir, 'package.json'),
    JSON.stringify({ name: 'x', version: '1.0.0', ...(deps ? { dependencies: deps } : {}) }),
  );
  writeFileSync(join(dir, 'server.js'), 'console.log(password);\n');
  const run = spawnSync(process.execPath, [CLI, 'secure', '--json'], {
    cwd: dir,
    encoding: 'utf-8',
    env: { ...process.env, HOME: home },
    timeout: 180_000,
  });
  const start = run.stdout?.indexOf('{') ?? -1;
  if (start === -1) return null;
  try {
    return JSON.parse(run.stdout.slice(start)) as ScanJson;
  } catch {
    return null;
  }
}

function renderFixture(home: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'hma-421-txt-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0' }));
  writeFileSync(join(dir, 'server.js'), 'console.log(password);\n');
  const run = spawnSync(process.execPath, [CLI, 'secure'], {
    cwd: dir,
    encoding: 'utf-8',
    env: { ...process.env, HOME: home },
    timeout: 180_000,
  });
  return run.stdout ?? '';
}

const canSpawn = existsSync(CLI);
const describeSpawn = canSpawn ? describe : describe.skip;

describeSpawn('#421 layer 2 — the finding reaches the output and the score', () => {
  // #285 — without this the suite would happily measure a binary older than
  // src/ and report a pass.
  beforeAll(assertDistFreshIfPresent);

  // One HOME for the whole suite so the classifier model is fetched at most
  // once rather than per scan.
  const HOME_DIR = mkdtempSync(join(tmpdir(), 'hma-421-home-'));
  mkdirSync(HOME_DIR, { recursive: true });

  let asLibrary: ScanJson | null;
  let asServer: ScanJson | null;

  beforeAll(() => {
    asLibrary = scanFixture(HOME_DIR, undefined);
    asServer = scanFixture(HOME_DIR, { express: '^4.18.0' });
  });

  it('detects the two fixtures as different project types', () => {
    expect(asLibrary?.projectType).toBe('library');
    // express makes it server-shaped; the exact label is the scanner's call.
    expect(asServer?.projectType).not.toBe('library');
  });

  // THE BUG. Pre-fix this array held only the LOW missing-.gitignore finding.
  it.each([['library'], ['server']])(
    'surfaces LOG-002 in user-facing findings on the %s fixture',
    (which) => {
      const scan = which === 'library' ? asLibrary : asServer;
      const log002 = (scan?.findings ?? []).find(f => f.checkId === 'LOG-002');
      expect(log002, 'LOG-002 must reach result.findings').toBeDefined();
      expect(log002?.passed).toBe(false);
      expect(log002?.severity).toBe('high');
    },
  );

  // The emission bug itself: the check knew which file matched and dropped it.
  // Without a path the finding is filtered out again no matter how it is scoped.
  it('attributes the file and line the pattern actually matched', () => {
    const log002 = (asLibrary?.findings ?? []).find(f => f.checkId === 'LOG-002');
    expect(log002?.file).toBe('server.js');
    expect(log002?.line).toBe(1);
  });

  // The single-line fixture above cannot tell a real line count from a
  // hardcoded 1, and the count is computed by scanning rather than splitting
  // (the content is untrusted and split allocates per line), so it gets a
  // fixture where the answer is not 1.
  it('counts the line rather than assuming the first one', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hma-421-multiline-'));
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'ml', version: '1.0.0' }));
    writeFileSync(join(dir, 'app.js'), '// line1\n// line2\n// line3\nconsole.log(password);\n');
    const run = spawnSync(process.execPath, [CLI, 'secure', '--json'], {
      cwd: dir, encoding: 'utf-8', env: { ...process.env, HOME: HOME_DIR }, timeout: 180_000,
    });
    const scan = JSON.parse(run.stdout.slice(run.stdout.indexOf('{'))) as ScanJson;
    const log002 = (scan.findings ?? []).find(f => f.checkId === 'LOG-002');
    expect(log002?.file).toBe('app.js');
    expect(log002?.line).toBe(4);
  });

  // NOTE this passes on the evidence fix ALONE — `dropPathlessNoiseFloor`
  // short-circuits on `f.file` before it ever consults project-type scope, so
  // reverting the scoping change leaves this green. Kept as a plain
  // end-to-end assertion; the scoping change is guarded by the contract layer
  // above, not by this.
  it('carries LOG-002 into allFindings on a library', () => {
    const ids = (asLibrary?.allFindings ?? []).map(f => f.checkId);
    expect(ids).toContain('LOG-002');
  });

  // Resurrecting a dead check means its pattern is now load-bearing for the
  // score. A raw case-insensitive substring test fires on all of these, and
  // each takes a clean project to 69 and "Not safe as-is".
  it.each([
    ['an identifier that merely starts with the keyword', 'console.log(tokenCount, n);\n'],
    ['a comment recording the bug was removed', '// console.log(password) -- removed for security\n'],
    ['a help string quoting the bad pattern', 'const HELP = "Never write console.log(password) here";\n'],
    ['an identifier that starts with "secret"', 'console.log(secretlessEnabled);\n'],
  ])('does not fire on %s', (_label, body) => {
    const dir = mkdtempSync(join(tmpdir(), 'hma-421-fp-'));
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'fp', version: '1.0.0' }));
    writeFileSync(join(dir, 'index.js'), body);
    const run = spawnSync(process.execPath, [CLI, 'secure', '--json'], {
      cwd: dir, encoding: 'utf-8', env: { ...process.env, HOME: HOME_DIR }, timeout: 180_000,
    });
    const scan = JSON.parse(run.stdout.slice(run.stdout.indexOf('{'))) as ScanJson;
    expect((scan.findings ?? []).find(f => f.checkId === 'LOG-002')).toBeUndefined();
  });

  // The line is computed on the ORIGINAL text. Searching a `toLowerCase()`
  // copy and reporting an offset from it misattributes the finding, because
  // `toLowerCase` is not length-preserving: U+0130 becomes two code units. The
  // finding fired while its own `Verify:` command pointed at an innocent line,
  // which is a dead end inside the thing meant to unblock the reader.
  it('reports a line the scanned file cannot shift', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hma-421-unicode-'));
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'u', version: '1.0.0' }));
    const body = `${'İ'.repeat(30)}\nconsole.log(password);\naaa\nbbb\nccc\nddd\n`;
    writeFileSync(join(dir, 'index.js'), body);
    const run = spawnSync(process.execPath, [CLI, 'secure', '--json'], {
      cwd: dir, encoding: 'utf-8', env: { ...process.env, HOME: HOME_DIR }, timeout: 180_000,
    });
    const scan = JSON.parse(run.stdout.slice(run.stdout.indexOf('{'))) as ScanJson;
    const log002 = (scan.findings ?? []).find(f => f.checkId === 'LOG-002');
    expect(log002?.line).toBe(2);
    // The citation has to survive being followed.
    expect(body.split('\n')[(log002!.line as number) - 1]).toContain('console.log(password)');
  });

  // Because the finding now carries a path, `.hmaignore` can reach it. #280
  // says a multi-file finding survives while ANY covered path is un-ignored —
  // which only works if every matching file is recorded, not just the cited
  // one. Stopping at the first match would let one ignored file delete the
  // evidence for every other.
  it('survives .hmaignore on one matching file and re-points onto another', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hma-421-ignore-'));
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'i', version: '1.0.0' }));
    writeFileSync(join(dir, 'a.js'), 'console.log(password);\n');
    writeFileSync(join(dir, 'z.js'), 'console.log(password);\n');
    writeFileSync(join(dir, '.hmaignore'), 'a.js\n');
    const run = spawnSync(process.execPath, [CLI, 'secure', '--json'], {
      cwd: dir, encoding: 'utf-8', env: { ...process.env, HOME: HOME_DIR }, timeout: 180_000,
    });
    const scan = JSON.parse(run.stdout.slice(run.stdout.indexOf('{'))) as ScanJson;
    const log002 = (scan.findings ?? []).find(f => f.checkId === 'LOG-002');
    expect(log002, 'ignoring a.js must not hide the match in z.js').toBeDefined();
    expect(log002?.file).toBe('z.js');
  });

  // The score is the part a pre-push gate reads. A HIGH that does not move the
  // number is a HIGH nobody acts on.
  it('scores the HIGH, and scores it identically whatever the project type', () => {
    expect(asLibrary!.score).toBeLessThan(98);
    expect(asLibrary!.score).toBe(asServer!.score);
  });

  // Negative control: evidence is recorded only when there IS evidence, so the
  // fix cannot be "always attach a filename".
  it('leaves a passing LOG-002 pathless rather than inventing evidence', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hma-421-benign-'));
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'b', version: '1.0.0' }));
    writeFileSync(join(dir, 'index.js'), 'console.log("started");\n');
    const run = spawnSync(process.execPath, [CLI, 'secure', '--json'], {
      cwd: dir, encoding: 'utf-8', env: { ...process.env, HOME: HOME_DIR }, timeout: 180_000,
    });
    const scan = JSON.parse(run.stdout.slice(run.stdout.indexOf('{'))) as ScanJson;
    const log002 = (scan.allFindings ?? []).find(f => f.checkId === 'LOG-002');
    expect(log002?.passed).toBe(true);
    expect(log002?.file).toBeUndefined();
  });
});

describeSpawn('#421 layer 2 — the run discloses what it silenced', () => {
  beforeAll(assertDistFreshIfPresent);
  const HOME_DIR = mkdtempSync(join(tmpdir(), 'hma-421-home2-'));

  /**
   * A plain library that happens to carry an `mcp.json`. `detectProjectType`
   * keys on openclaw markers and package.json, NOT on the presence of an MCP
   * config, so this stays `library` while `NET-001` (CRITICAL, "Server Bound
   * to All Interfaces") matches inside `mcp.json` and is then dropped because
   * `NET-` is scoped to webapp/api. A hidden CRITICAL is exactly what the
   * backstop is for, and this is an ordinary repo shape.
   */
  function hiddenDetectionFixture(): ScanJson {
    const dir = mkdtempSync(join(tmpdir(), 'hma-421-hidden-'));
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'plainlib', version: '1.0.0' }));
    writeFileSync(join(dir, '.gitignore'), 'node_modules/\n.env\n');
    writeFileSync(join(dir, 'index.js'), 'module.exports = {};\n');
    writeFileSync(
      join(dir, 'mcp.json'),
      JSON.stringify({ servers: { s: { args: ['server.js', '--host', '0.0.0.0'] } } }),
    );
    const run = spawnSync(process.execPath, [CLI, 'secure', '--json'], {
      cwd: dir, encoding: 'utf-8', env: { ...process.env, HOME: HOME_DIR }, timeout: 180_000,
    });
    return JSON.parse(run.stdout.slice(run.stdout.indexOf('{'))) as ScanJson;
  }

  function hiddenDetectionRender(): string {
    const dir = mkdtempSync(join(tmpdir(), 'hma-421-hidden-txt-'));
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'plainlib', version: '1.0.0' }));
    writeFileSync(join(dir, '.gitignore'), 'node_modules/\n.env\n');
    writeFileSync(join(dir, 'index.js'), 'module.exports = {};\n');
    writeFileSync(
      join(dir, 'mcp.json'),
      JSON.stringify({ servers: { s: { args: ['server.js', '--host', '0.0.0.0'] } } }),
    );
    const run = spawnSync(process.execPath, [CLI, 'secure'], {
      cwd: dir, encoding: 'utf-8', env: { ...process.env, HOME: HOME_DIR }, timeout: 180_000,
    });
    return run.stdout ?? '';
  }

  // THE WIRING GUARD. Without a fixture that reaches it, the whole
  // clear-withdrawal could be deleted from cli.ts and the suite stayed green.
  it('records a detection that scoping hid, as identity only — never paths or messages', () => {
    const scan = hiddenDetectionFixture();
    expect(scan.projectType).toBe('library');
    const suppressed = scan.coverage?.suppressedFailures ?? [];
    expect(
      suppressed.map(s => s.checkId),
      'NET-001 matched inside mcp.json and was scoped out — it must be recorded',
    ).toContain('NET-001');
    for (const s of suppressed) {
      expect(Object.keys(s).sort()).toEqual(['category', 'checkId', 'name', 'severity']);
      expect(s).not.toHaveProperty('file');
      expect(s).not.toHaveProperty('message');
    }
  });

  it('names the category of a hidden detection instead of calling it clear', () => {
    const out = hiddenDetectionRender();
    const unresolved = new RegExp(
      `^\\s*${OBSERVATION_LABELS.unresolved}\\s{2,}(.+)$`, 'm',
    ).exec(out);
    expect(unresolved, `no Unresolved line in:\n${out}`).not.toBeNull();
    // NET-* renders under the label `network`.
    expect(unresolved![1]).toContain('network');
  });

  // The volume of failed-but-unshown checks is what made a silenced finding
  // indistinguishable from a clean result. It is disclosed as a count.
  it('counts the checks that failed with nothing to point at', () => {
    const scan = scanFixture(HOME_DIR, undefined);
    // NOT `toBeGreaterThan(0)`, which is what this asserted until #499.
    //
    // On this fixture the honest count is in the dozens, and the pathless
    // noise floor it counts is carried in the same array the semantic merge
    // replaces. #499's first cut replaced that array with the merge result
    // alone and dropped the whole noise floor — measured, `unevidencedFailures`
    // fell to 41 -> 0 on ai-trust and 45 -> 1 on secretless, deleting the only
    // line that tells a reader a "categories clear" report is hiding ~40 checks
    // that failed with nothing to point at.
    //
    // `> 0` survived that intact, because this fixture lands on exactly 1. A
    // guard one finding away from vacuous is why the regression shipped green.
    // The floor is set below the measured value with room for legitimate check
    // churn, and high enough that a collapse to a handful cannot pass.
    expect(scan?.coverage?.unevidencedFailures).toBeGreaterThan(15);
  });

  it('states that count on the Coverage line', () => {
    const out = renderFixture(HOME_DIR);
    const coverage = /^\s*Coverage\s{2,}(.+)$/m.exec(out);
    expect(coverage, `no Coverage line in:\n${out}`).not.toBeNull();
    expect(coverage![1]).toMatch(/\d+ checks reported an absent mitigation \(not shown\)/);
  });

  // Absent mitigations must NOT withdraw `clear` — nothing was found, and
  // naming ~45 categories a clean library cannot act on is the false-reassurance
  // problem inverted into a wall of FUD.
  it('still reports categories clear when only absent mitigations were silenced', () => {
    const out = renderFixture(HOME_DIR);
    const categories = /^\s*Categories\s{2,}(.+)$/m.exec(out);
    expect(categories![1]).toMatch(/\d+ others clear/);
  });

  it('does not fold the logging detection into the clear tail', () => {
    const out = renderFixture(HOME_DIR);
    const categories = /^\s*Categories\s{2,}(.+)$/m.exec(out);
    // LOG-* renders under the label `audit`, not `logging`.
    expect(categories![1]).toContain('audit');
  });

  // Every examined category lands in exactly one state, so the tally accounts
  // for itself and a withdrawn `clear` cannot become a silent gap.
  it('accounts for every examined category exactly once', () => {
    const out = renderFixture(HOME_DIR);
    const examined = /(\d+) of \d+ categories examined/.exec(out);
    const categoriesLine = /^\s*Categories\s{2,}(.+)$/m.exec(out);
    const segments = categoriesLine![1].split('·').map(s => s.trim()).filter(Boolean);
    const clearMatch = /^(\d+) others clear$/.exec(segments[segments.length - 1] ?? '');
    const clearCount = clearMatch ? Number(clearMatch[1]) : 0;
    const reportedCount = clearMatch ? segments.length - 1 : segments.length;

    const unresolvedLine = new RegExp(
      `^\\s*${OBSERVATION_LABELS.unresolved}\\s{2,}(.+)$`, 'm',
    ).exec(out);
    let unresolvedCount = 0;
    if (unresolvedLine) {
      const more = / \+ (\d+) more/.exec(unresolvedLine[1]);
      const named = unresolvedLine[1]
        .replace(/ \+ \d+ more.*$/, '').split(',').filter(s => s.trim()).length;
      unresolvedCount = named + (more ? Number(more[1]) : 0);
    }
    expect(reportedCount + clearCount + unresolvedCount).toBe(Number(examined![1]));
  });
});

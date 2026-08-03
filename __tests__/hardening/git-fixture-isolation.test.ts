/**
 * No test spawns git with the ambient environment (#348).
 *
 * `.git/config` in this repo has been corrupted three times — `bare = true`
 * plus a `[user]` section reading `test <test@example.com>` — leaving every
 * later `git status` failing with "this operation must be run in a work tree".
 *
 * The `[user]` half is reproducible and is this suite's own doing. Git exports
 * `GIT_DIR` to every hook, this project's pre-push hook runs `npm test`, and a
 * fixture helper ran:
 *
 *     git -C <fixture> init -q
 *     git -C <fixture> config user.email test@example.com
 *
 * `-C` changes the directory; `GIT_DIR` still names the repository. So the
 * `init` created nothing and the `config` wrote into the developer's repo. The
 * tests stayed green the whole time, which is the worse half: a fixture built
 * so `git check-ignore` would have real ground truth had no repository at all,
 * and the assertions that depended on it were measuring the default answer.
 *
 * One file — `__tests__/semantic/credential-context-git-state.test.ts` — had
 * already diagnosed this, in a comment recording that a pre-push test run
 * committed `.env` and `secrets/real.env` onto the working branch. It deleted
 * the three variables it had seen and the class was never swept, so eleven
 * other call sites in three other files kept doing it. This is the sweep, and
 * this test is what keeps it swept.
 */
import { describe, it, expect } from 'vitest';
import ts from 'typescript';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';

const TESTS_ROOT = path.join(__dirname, '..');

/** The one module allowed to spawn git, because it is the one that isolates it. */
const HELPER = path.join('helpers', 'throwaway-repo.ts');

function testSources(): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.ts')) out.push(full);
    }
  };
  walk(TESTS_ROOT);
  return out.sort();
}

const SPAWNERS = new Set(['execSync', 'execFileSync', 'spawnSync', 'spawn', 'exec']);

/** `git`, `/usr/bin/git`, `git -C …` — the command, however it is spelled. */
function namesGit(command: string): boolean {
  const word = command.trim().split(/\s+/)[0] ?? '';
  return word === 'git' || word.endsWith('/git');
}

/**
 * Every spawn of the literal command `git`, read from the syntax rather than
 * from the text.
 *
 * A regex over the source matched this file's own documentation, which quotes
 * the offending calls in order to explain them — and a gate that fires on the
 * prose describing it teaches people to delete the prose. The AST sees calls
 * and not comments.
 *
 * A spawn is ALLOWED when the function containing it mentions `gitFreeEnv`,
 * which is the only way to build an environment git cannot redirect. That is
 * checked structurally too, so a comment saying "env is scrubbed" does not
 * satisfy it.
 *
 * It does not match a command built from a variable. This is a gate against the
 * ordinary way the mistake is made, not a proof; the helper's own assertion
 * that the fixture repository exists is what catches a spawn it cannot see.
 */
function rawGitSpawns(file: string): Array<{ line: number; text: string }> {
  const source = ts.createSourceFile(
    file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true,
  );
  const out: Array<{ line: number; text: string }> = [];

  /**
   * Does the function CONTAINING this spawn build its environment with
   * `gitFreeEnv`?
   *
   * Stops at the first function-like ancestor. It used to fall through to the
   * `SourceFile`, so one `import { gitFreeEnv }` anywhere exempted every raw
   * git spawn in that file — including one in an unrelated function that
   * inherited the ambient environment. The claim in this file's header is that
   * the check is structural rather than textual, and a file-scoped exemption is
   * barely stronger than a comment.
   */
  const mentionsScrub = (node: ts.Node | undefined): boolean => {
    while (node) {
      if (ts.isFunctionDeclaration(node) || ts.isArrowFunction(node)
        || ts.isFunctionExpression(node) || ts.isMethodDeclaration(node)) {
        let found = false;
        const look = (n: ts.Node): void => {
          if (found) return;
          if (ts.isIdentifier(n) && n.text === 'gitFreeEnv') found = true;
          else ts.forEachChild(n, look);
        };
        look(node);
        return found;
      }
      if (ts.isSourceFile(node)) return false;
      node = node.parent;
    }
    return false;
  };

  const walk = (n: ts.Node): void => {
    if (ts.isCallExpression(n) && n.arguments.length > 0
      // `execFileSync(…)` and `cp.execFileSync(…)` are the same hazard.
      && (ts.isIdentifier(n.expression)
        ? SPAWNERS.has(n.expression.text)
        : ts.isPropertyAccessExpression(n.expression)
          && SPAWNERS.has(n.expression.name.text))) {
      const first = n.arguments[0];
      const command = ts.isStringLiteralLike(first) ? first.text
        : ts.isTemplateExpression(first) ? first.head.text
        : null;
      if (command !== null && namesGit(command) && !mentionsScrub(n)) {
        const { line } = source.getLineAndCharacterOfPosition(n.getStart());
        out.push({ line: line + 1, text: n.getText().replace(/\s+/g, ' ').slice(0, 90) });
      }
    }
    ts.forEachChild(n, walk);
  };
  walk(source);
  return out;
}

describe('#348 every fixture repository is created with git isolated from this one', () => {
  it('reads the test tree at all', () => {
    const files = testSources();
    expect(
      files.length,
      'no test sources were read, so the sweep below is over an empty list',
    ).toBeGreaterThan(50);
  });

  it('spawns git only through the isolating helper', () => {
    const offenders: string[] = [];
    for (const file of testSources()) {
      const relative = path.relative(TESTS_ROOT, file);
      if (relative === HELPER) continue;
      for (const hit of rawGitSpawns(file)) {
        offenders.push(`${relative}:${hit.line}  ${hit.text}`);
      }
    }
    expect(
      offenders,
      'a test spawns git directly. Under a git hook — and this project\'s '
      + 'pre-push hook runs the suite — GIT_DIR is exported and points at THIS '
      + 'repository, so `-C <fixture>` changes the directory while git still '
      + 'writes to the real repo: fixture commits land on the working branch and '
      + '`git config` overwrites the developer\'s identity.\n'
      + 'Use `initThrowawayRepo(dir)` from __tests__/helpers/throwaway-repo.ts, '
      + 'or `gitFreeEnv()` for a command it does not cover.\n\n'
      + offenders.join('\n'),
    ).toEqual([]);
  });

  it('scrubs every GIT_ variable, not the three that were noticed', async () => {
    // The previous fix deleted GIT_DIR, GIT_WORK_TREE and GIT_INDEX_FILE — the
    // ones that had been observed. `GIT_OBJECT_DIRECTORY`, `GIT_COMMON_DIR`,
    // `GIT_CONFIG_GLOBAL` and `GIT_ALTERNATE_OBJECT_DIRECTORIES` redirect a
    // fixture just as effectively, so the property is the FAMILY.
    const { gitFreeEnv } = await import('../helpers/throwaway-repo');
    const planted = [
      'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY',
      'GIT_COMMON_DIR', 'GIT_CONFIG_GLOBAL', 'GIT_ALTERNATE_OBJECT_DIRECTORIES',
    ];
    const saved: Record<string, string | undefined> = {};
    for (const key of planted) {
      saved[key] = process.env[key];
      process.env[key] = '/nowhere';
    }
    try {
      const env = gitFreeEnv();
      expect(
        Object.keys(env).filter((k) => k.startsWith('GIT_')),
        'a GIT_ variable survived the scrub',
      ).toEqual([]);
      expect(
        env.PATH,
        'the scrub dropped the rest of the environment, so git will not be found',
      ).toBeDefined();
    } finally {
      for (const key of planted) {
        if (saved[key] === undefined) delete process.env[key];
        else process.env[key] = saved[key];
      }
    }
  });

  it('fails loudly when git exits 0 and creates no repository', async () => {
    // The SILENT half, reproduced rather than approximated.
    //
    // The first version of this case pointed the helper at a nonexistent
    // directory, where `git -C <missing> init` exits non-zero and
    // `execFileSync` throws before the guard is ever reached — so deleting the
    // guard entirely left it green. The real failure is `init` exiting ZERO
    // while creating nothing in the fixture, which is what an inherited
    // `GIT_DIR` does, so that is what this builds.
    const { initThrowawayRepo, gitFreeEnv } = await import('../helpers/throwaway-repo');
    const { mkdtempSync, existsSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');

    const victim = mkdtempSync(path.join(tmpdir(), 'hma-348-victim-'));
    const fixture = mkdtempSync(path.join(tmpdir(), 'hma-348-fixture-'));
    try {
      initThrowawayRepo(victim);
      expect(existsSync(path.join(victim, '.git')), 'the control repo was not created')
        .toBe(true);

      // Now the poisoned environment, which is exactly what a git hook hands
      // the suite.
      const poisoned = { ...gitFreeEnv(), GIT_DIR: path.join(victim, '.git') };
      expect(
        () => initThrowawayRepo(fixture, true, poisoned),
        'git exited 0 and created no repository in the fixture, and the helper '
        + 'carried on — so the fixture is not a repository and the identity '
        + 'write landed in whatever GIT_DIR names',
      ).toThrow(/no repository/i);
      expect(
        existsSync(path.join(fixture, '.git')),
        'this case assumes git creates nothing under GIT_DIR; it did create '
        + 'something, so the reproduction no longer holds',
      ).toBe(false);
    } finally {
      const { rmSync } = await import('node:fs');
      rmSync(victim, { recursive: true, force: true });
      rmSync(fixture, { recursive: true, force: true });
    }
  });
});

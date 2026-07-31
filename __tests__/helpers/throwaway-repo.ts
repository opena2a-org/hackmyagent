/**
 * A throwaway git repository for a fixture, that cannot be the developer's own
 * (#348).
 *
 * `.git/config` in this repo has been corrupted three times, each time picking
 * up `bare = true` and a `[user]` section reading `test <test@example.com>`,
 * which leaves every later `git status` failing with "this operation must be
 * run in a work tree" until someone repairs it by hand.
 *
 * The `[user]` half is this, and it is reproducible:
 *
 *     $ env GIT_DIR=<repo>/.git git -C <fixture> init -q
 *     $ env GIT_DIR=<repo>/.git git -C <fixture> config user.email test@example.com
 *
 * `-C <fixture>` changes the DIRECTORY, and `GIT_DIR` still names the
 * repository — so `init` creates nothing in the fixture and `config` writes to
 * whatever `GIT_DIR` points at. Git exports `GIT_DIR` to every hook it runs,
 * and this project's pre-push hook runs `npm test`. So the corruption happens
 * on PUSH, in the gate that exists to keep the tree healthy, and the tests that
 * caused it were green throughout: `git init` failing silently leaves
 * `git check-ignore` with no repository to answer from, which is the ground
 * truth those fixtures were built to have.
 *
 * Two changes, because either alone leaves a hole:
 *
 *   - the child gets an environment with every `GIT_*` variable removed, so an
 *     inherited `GIT_DIR`, `GIT_WORK_TREE` or `GIT_INDEX_FILE` cannot redirect
 *     it, and
 *   - identity is written with `--file <dir>/.git/config`, which names the file
 *     to write and therefore cannot walk up to another repository even if the
 *     scrub above is ever incomplete.
 *
 * And it ASSERTS the repository exists afterwards, so a fixture that silently
 * is not a repository fails its own test instead of quietly measuring nothing.
 *
 * Not covered here: the `bare = true` half. Five variants of the commands above
 * were run against git 2.53.0 and none of them set it, so its cause is not
 * established and it is NOT claimed to be fixed. What is fixed is the write
 * that reaches another repository at all.
 */
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';

/** `process.env` with every git variable removed. */
export function gitFreeEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (!k.startsWith('GIT_')) env[k] = v;
  }
  return env;
}

/**
 * Initialise `dir` as a real, self-contained git repository.
 *
 * Throws when the repository is not there afterwards. A test that needs
 * `git check-ignore` to have ground truth would otherwise pass over a
 * directory that is not a repository at all.
 */
export function initThrowawayRepo(dir: string, identity = true): void {
  const env = gitFreeEnv();
  execFileSync('git', ['-C', dir, 'init', '-q'], { env, stdio: 'ignore' });

  const gitDir = path.join(dir, '.git');
  if (!existsSync(gitDir)) {
    throw new Error(
      `git init created no repository in ${dir}. The most likely cause is a `
      + `GIT_DIR or GIT_WORK_TREE in the environment — git hooks export them, and `
      + `this project's pre-push hook runs the suite — which would mean this `
      + `command just wrote to another repository instead. See #348.`,
    );
  }

  if (identity) {
    // `--file` and not `-C`: a config write that names its file cannot reach
    // another repository, whatever the environment says.
    const configFile = path.join(gitDir, 'config');
    execFileSync('git', ['config', '--file', configFile, 'user.email', 'test@example.com'], { env, stdio: 'ignore' });
    execFileSync('git', ['config', '--file', configFile, 'user.name', 'test'], { env, stdio: 'ignore' });
  }
}

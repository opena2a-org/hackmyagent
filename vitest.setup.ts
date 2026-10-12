import { afterAll } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { removeTempDirs } from './__tests__/helpers/temp-dir';

// Test-harness hermeticity: a scan in this suite must not read the developer's
// home directory.
//
// `secure` merges findings from whichever AI-infrastructure directories exist in
// $HOME (~/.nemoclaw, ~/.openclaw, ~/.openshell, ~/.moltbot, ~/.clawdbot) into
// the result for whatever target it was given — see `detectAIInfrastructure` in
// src/cli.ts. That is deliberate product behaviour and it is fine in the field.
// Inside the suite it makes every spawn test a function of machine state:
//
//   on a machine with a populated ~/.openclaw, scanning a two-file temp dir
//   returned 1782 findings / 1.36 MB of JSON — 1780 of them from $HOME
//
// which truncated stdout past the default `spawnSync` maxBuffer (surfacing as
// `JSON.parse: Unterminated string`), moved verdicts away from what the fixture
// establishes, and overran spawn budgets so exit-time temp-dir cleanup never
// ran. Five files failed on merged main locally while CI stayed green, because
// CI runners have no such directory.
//
// 18 of the 20 files that spawn the CLI for a scan never set the flag, so it is
// defaulted once here for every test worker instead of at forty-odd call sites.
// `spawnSync` children inherit `process.env`, so this reaches them.
//
// The assignment is conditional on purpose: a test that needs the infra merge
// (see __tests__/harness/hermetic-home.test.ts) overrides it in its own spawn
// env.
//
// Running the whole suite with `OPENA2A_CORPUS_DETERMINISTIC=0` is NOT a
// supported way to reproduce field behaviour — the hermeticity guard in that
// file asserts the default and will fail, on purpose, because in that mode the
// suite is reading your home directory again. Reproduce field behaviour by
// running the CLI directly instead.
//
// Empty counts as unset. An exported-but-empty `OPENA2A_CORPUS_DETERMINISTIC=`
// is not a deliberate opt-out, and leaving it empty would sail past a
// `=== undefined` check while `src/cli.ts` reads it as "not 1" and merges $HOME
// anyway — hermetic by neither measure. `'0'` is a non-empty string, so a real
// opt-out still survives this.
if (!process.env.OPENA2A_CORPUS_DETERMINISTIC) {
  process.env.OPENA2A_CORPUS_DETERMINISTIC = '1';
}

// A spawn in this suite sends no usage telemetry to the Registry (#963).
//
// The CLI starts with usage telemetry off when it sees a test-runner marker,
// and Vitest sets one in every worker, which spawned children inherit. A test
// that measures the event turns telemetry back on with OPENA2A_TELEMETRY=on;
// this default points that case, and any other spawn that inherits the
// worker's environment, at the discard port, where a send fails as a fast
// local connection refusal. Before #963 each spawn sent a usage event to the
// production endpoint. A fresh HOME did not make it a new install: the install
// id is a hash of the machine identifier, so every spawn on one machine
// carried the same id.
//
// Pinned by __tests__/harness/suite-sends-no-telemetry.test.ts.
if (!process.env.OPENA2A_TELEMETRY_URL) {
  process.env.OPENA2A_TELEMETRY_URL = 'http://127.0.0.1:9';
}

// Second half of the same contract: a test that shells out to git must talk to
// the repository it created, not to whichever one launched the suite.
//
// Git exports GIT_DIR, GIT_INDEX_FILE and friends to every hook it runs. The
// pre-push hook runs `npm test`, those variables are inherited by the worker,
// and every `git` the suite spawns inside a fixture directory silently
// retargets at the OUTER repository — `git check-ignore` then answers about
// this checkout instead of the temp one. Four tests in
// __tests__/hardening/scanner.test.ts fail that way with `expected undefined
// to be false`, on `main` as much as on any branch, so `npm test` passes from a
// shell and the identical suite fails from the hook that gates the push.
//
// Only the repository-location variables are cleared. GIT_AUTHOR_*,
// GIT_COMMITTER_* and GIT_CONFIG_* are left alone: tests set those deliberately
// per spawn, and they say nothing about which repository is being addressed.
for (const v of [
  'GIT_DIR',
  'GIT_WORK_TREE',
  'GIT_COMMON_DIR',
  'GIT_INDEX_FILE',
  'GIT_PREFIX',
  'GIT_OBJECT_DIRECTORY',
  'GIT_ALTERNATE_OBJECT_DIRECTORIES',
  'GIT_NAMESPACE',
  'GIT_QUARANTINE_PATH',
]) {
  delete process.env[v];
}

// Fourth: `--fix` keeps its backups in a per-user store outside the scanned
// tree (#376), by default under ~/.opena2a/backups. A suite that runs `--fix`
// hundreds of times must not fill the developer's home with plaintext copies of
// its fixtures, and a store left by an earlier run must not be what a rollback
// test finds. Each test file gets its own store, removed when the file
// finishes. Set unconditionally: a value inherited from the shell would be
// shared by every file and never removed. A spawn test that passes
// `{ ...process.env }` inherits it; one that builds its environment from
// scratch keeps its own HOME or OPENA2A_HOME.
//
// The path is reserved here and the directory is not created. `vitest list`
// loads this file for every test file and runs no hook, so a directory made at
// module scope is left in TMPDIR by collection alone, one per file
// (__tests__/harness/collection-starts-no-scan.test.ts). `--fix` creates the
// store root when it is absent, so only a file that takes a backup ever has
// one. A removal that fails throws, and fails that file's `afterAll`.
const backupHome = path.join(os.tmpdir(), `hma-backup-home-${crypto.randomBytes(8).toString('hex')}`);
process.env.HMA_BACKUP_HOME = backupHome;
afterAll(() => {
  fs.rmSync(backupHome, { recursive: true, force: true });
});

// Fifth: a test file leaves nothing in the temporary directory. `tempDir` in
// __tests__/helpers/temp-dir.ts removes what it creates when the creating test
// finishes; this hook removes what was created outside a test, and anything
// the per-test pass could not, when each file finishes. Registering it here
// puts it ahead of each file's own hooks, and after-hooks run in reverse order
// of registration, so it runs after a file's own `afterAll`.
afterAll(removeTempDirs);

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
// env, and `OPENA2A_CORPUS_DETERMINISTIC=0 npm test` still reproduces field
// behaviour.
if (process.env.OPENA2A_CORPUS_DETERMINISTIC === undefined) {
  process.env.OPENA2A_CORPUS_DETERMINISTIC = '1';
}

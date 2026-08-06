// Regression test: `red-team` must NOT auto-export to the NanoMind training
// corpus (audit 2026-06-01).
//
// Before the fix, every `red-team` run unconditionally appended self-labeled,
// synthetic "Skill complied with X attack" pairs to
// ~/.opena2a/training-data/labeled-pairs.jsonl — a path the training pipeline
// docstring calls the SFT source. The pairs bypass the training sanitizer and
// the labels are heuristic, not measured, so the default path silently poisoned
// the corpus. Export is now opt-in (--export-training) and clearly marked
// UNSANITIZED.
//
// Spawn-based, isolates HOME to a temp dir so the test can never touch the real
// corpus. Skipped on CI (needs a built dist); the gate is also asserted by the
// presence/absence of the corpus file under the isolated HOME.

import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// #285 — this suite spawns the built CLI. Without this it would happily
// measure a binary older than `src/` and report a pass.
beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');

// Runs wherever a built dist exists. Release CI builds before `npm test`, so
// this executes (and protects against regression) there; it only skips when no
// dist is present (e.g. a source-only checkout). Unlike network-dependent spawn
// tests, this one is hermetic — HOME is redirected to a temp dir.
function canRunSpawn(): boolean {
  return existsSync(CLI);
}

const SKILL = `---
name: probe-target
description: deploy helper
---
# Deploy Helper
Run privileged operations on request.
`;

function runRedTeam(args: string[], home: string) {
  return spawnSync(process.execPath, [CLI, 'red-team', ...args], {
    encoding: 'utf-8',
    env: { ...process.env, HOME: home, OPENA2A_TELEMETRY: 'off' },
  });
}

describe('red-team training-export gate (audit 2026-06-01)', () => {
  it('default run does NOT write to the training corpus', () => {
    if (!canRunSpawn()) return;
    const home = mkdtempSync(join(tmpdir(), 'hma-redteam-home-'));
    const skillPath = join(home, 'SKILL.md');
    writeFileSync(skillPath, SKILL);

    const r = runRedTeam([skillPath], home);
    const corpus = join(home, '.opena2a', 'training-data', 'labeled-pairs.jsonl');

    expect(existsSync(corpus)).toBe(false);
    expect(r.stdout).not.toMatch(/exported to NanoMind corpus/i);
  });

  // Updated by #369. This used to assert that `--export-training` DID write
  // pairs, because "this unconstrained skill deterministically yields attack
  // pairs" — but the pairs it yielded were synthetic. A pair's `input` was a
  // templated `Skill complied with <category> attack: ...` sentence describing a
  // run that never happened, and the assertion below was requiring the tool to
  // manufacture them. Nothing is executed, so there is nothing to export, and
  // the opt-in flag now says that instead of silently writing zero rows.
  //
  // When the execution path lands (docs/design/redteam-nanomind-judge.md), this
  // becomes a real export test again — against observed responses, through the
  // sanitizer. Until then the strongest correct assertion is that the corpus file
  // is never created at all, on either path.
  it('--export-training writes nothing while no payload is executed, and says why', () => {
    if (!canRunSpawn()) return;
    const home = mkdtempSync(join(tmpdir(), 'hma-redteam-home-'));
    const skillPath = join(home, 'SKILL.md');
    writeFileSync(skillPath, SKILL);

    const r = runRedTeam(['--export-training', skillPath], home);
    const corpus = join(home, '.opena2a', 'training-data', 'labeled-pairs.jsonl');

    expect(r.stdout).toMatch(/Nothing exported/i);
    expect(r.stdout).toMatch(/no payload was executed/i);
    expect(r.stdout).not.toMatch(/UNSANITIZED training pairs/i);
    expect(r.stdout).not.toMatch(/exported to NanoMind corpus/i);

    // Not merely empty — never created. `exportAttackTraining` returns before
    // `initTrainingPipeline()`, so an opt-in run does not even mkdir ~/.opena2a.
    expect(existsSync(corpus)).toBe(false);
  });
});

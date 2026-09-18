/**
 * `check skill:<local-path>` and bare `check <local-path>` render the same
 * audit `secure <local-path>` renders.
 *
 * History. #136 found that `check skill:<path>` reported a different score
 * than `secure <path>` because that arm ran only the NanoMind semantic
 * matrix, and fixed the label rather than the scan: "Quick scan" in place of
 * "Security", a "Run `secure <target>` for the full audit" follow-up, and no
 * "Path forward" line. #740 showed what the label did not fix — a tree whose
 * `.claude/settings.json` held a plaintext key scored 96/100 at exit 0, the
 * credential check never having run. The local arm now runs the static suite
 * through the same scan `secure` runs, so the three relabels are gone with
 * the reason for them: the score line reads `Security`, no follow-up sends
 * the user to `secure` for checks that already ran, and the recovery math is
 * shown because it is now true.
 *
 * Spawn-based — exercises `dist/cli.js` end-to-end against the adversarial
 * corpus fixture. Gated on:
 *   1. Built `dist/cli.js` exists.
 *   2. Corpus fixture exists at `~/.opena2a/corpus/skill/malicious/exfil-skill`.
 *
 * Mirrors the gate pattern in `__tests__/checker/check-not-found-json.test.ts`.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { assertDistFreshIfPresent } from "../helpers/dist-freshness";

// #285 — this suite spawns the built CLI. Without this it would happily
// measure a binary older than `src/` and report a pass.
beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = join(__dirname, "..", "..");
const CLI = join(REPO_ROOT, "dist", "cli.js");
const FIXTURE = join(
  homedir(),
  ".opena2a",
  "corpus",
  "skill",
  "malicious",
  "exfil-skill",
);

function canRun(): boolean {
  return existsSync(CLI) && existsSync(FIXTURE);
}

function stripAnsi(s: string): string {
  return s.replace(/\x1b\[[0-9;]*m/g, "");
}

function runCli(args: string[]): string {
  const r = spawnSync("node", [CLI, ...args], {
    encoding: "utf-8",
    timeout: 120_000,
  });
  return stripAnsi(`${r.stdout}\n${r.stderr}`);
}

describe("check <local path> renders the full audit (#136, #740)", { timeout: 300_000 }, () => {
  it("check skill:<path> scores on the Security meter with no quick-scan relabel", () => {
    if (!canRun()) return;
    const out = runCli(["check", `skill:${FIXTURE}`]);
    expect(out).toMatch(/^\s+Security\s+━+\s+\d+\/100/m);
    expect(out).not.toContain("Quick scan");
    expect(out).not.toMatch(/Run `secure [^`]+` for the full audit/);
    expect(out).not.toMatch(/static not run/);
  });

  it("shows the Path forward recovery math, as secure does on the same tree", () => {
    // The exfil-skill fixture has critical + high findings on both paths.
    // The line was suppressed under the quick scan because its arithmetic
    // implied 100 was reachable by fixing findings a suite that never ran
    // could not have reported. The suite runs now, so the line is true.
    if (!canRun()) return;
    const checkOut = runCli(["check", `skill:${FIXTURE}`]);
    const secureOut = runCli(["secure", FIXTURE]);
    expect(secureOut).toMatch(/Path forward:\s+\d+\s+->\s+\d+/);
    expect(checkOut).toMatch(/Path forward:\s+\d+\s+->\s+\d+/);
  });

  it("secure path is unchanged (no Quick scan, no follow-up line)", () => {
    if (!canRun()) return;
    const out = runCli(["secure", FIXTURE]);
    expect(out).toMatch(/^\s+Security\s+━+\s+\d+\/100/m);
    expect(out).not.toContain("Quick scan");
    expect(out).not.toMatch(/Run `secure .+` for the full audit/);
  });

  it("check <local-path> without prefix takes the same arm", () => {
    // Bare `check <local-path>` shares the local-path arm with the
    // prefixed spellings; the same scan runs on both.
    if (!canRun()) return;
    const out = runCli(["check", FIXTURE]);
    expect(out).toMatch(/^\s+Security\s+━+\s+\d+\/100/m);
    expect(out).not.toContain("Quick scan");
    expect(out).not.toMatch(/Run `secure [^`]+` for the full audit/);
  });
});

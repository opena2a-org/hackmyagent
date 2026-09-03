/**
 * Regression test for #136 — `check skill:<local-path>` reports a different
 * score than `secure <local-path>` because the orchestrator runs only the
 * NanoMind semantic matrix, not the full 209-static-check suite. Fix:
 * relabel the score line "Quick scan" (vs "Security"), append a
 * "Run `secure <target>` for the full audit" follow-up, and suppress the
 * misleading "Path forward: N -> M" recovery-math line.
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
    timeout: 60_000,
  });
  return stripAnsi(`${r.stdout}\n${r.stderr}`);
}

describe("check skill: quick-scan label (#136)", () => {
  it("relabels Security as Quick scan and appends a `secure` follow-up", () => {
    if (!canRun()) return;
    const out = runCli(["check", `skill:${FIXTURE}`]);
    expect(out).toMatch(/^\s+Quick scan\s+━+\s+\d+\/100/m);
    expect(out).toMatch(/Run `secure [^`]+` for the full audit/);
    expect(out).not.toMatch(/^\s+Security\s+━/m);
  });

  it("suppresses the Path forward recovery-math line", () => {
    // The exfil-skill fixture has critical + high findings on both paths,
    // so `secure` renders Path forward. `check skill:` must not.
    if (!canRun()) return;
    const checkOut = runCli(["check", `skill:${FIXTURE}`]);
    const secureOut = runCli(["secure", FIXTURE]);
    expect(secureOut).toMatch(/Path forward:\s+\d+\s+->\s+\d+/);
    expect(checkOut).not.toMatch(/Path forward:/);
  });

  it("secure path is unchanged (no Quick scan, no follow-up line)", () => {
    if (!canRun()) return;
    const out = runCli(["secure", FIXTURE]);
    expect(out).toMatch(/^\s+Security\s+━+\s+\d+\/100/m);
    expect(out).not.toContain("Quick scan");
    expect(out).not.toMatch(/Run `secure .+` for the full audit/);
  });

  it("check <local-path> without prefix is also a quick scan", () => {
    // Bare `check <local-path>` shares the same orchestrator (cli.ts:354
    // local-path branch). The narrowed matrix applies; the relabel must too.
    if (!canRun()) return;
    const out = runCli(["check", FIXTURE]);
    expect(out).toMatch(/^\s+Quick scan\s+━+\s+\d+\/100/m);
    expect(out).toMatch(/Run `secure [^`]+` for the full audit/);
  });
});

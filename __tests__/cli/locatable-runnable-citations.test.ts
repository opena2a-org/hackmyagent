/**
 * Gate: every HIGH/CRITICAL finding carries a locatable, runnable citation
 * (#368, #286).
 *
 * Two defects this locks, both measured on 0.29.0 before the fix:
 *
 *   1. `AST-CRED-003 Hardcoded Secret Detected` shipped with no `line`. Its two
 *      line sources are both empty on the `source_code` path — no CRED evidence
 *      span, and an evidence summary that is a SYNTHESIZED label rather than a
 *      verbatim substring — so the CRITICAL finding rendered as `app/config.ts`
 *      with no `:N` and no `Verify:` at all. The line now comes from the offset
 *      the producer recorded, so it names the value the finding names.
 *   2. `generateVerifyCommand` interpolated the TARGET-relative `file` with no
 *      scan-root prefix, so `sed -n '10p' 'app/config.ts'` only ran if the
 *      reader's shell already sat at the scan target.
 *
 * NOT IN SCOPE, AND STILL OPEN AS #353: that same synthesized label carries a
 * truncated prefix of the key into `message` and `evidence`. No assertion here
 * claims otherwise — a test asserting a leak is closed when it is not is worse
 * than no test.
 *
 * ALSO NOT IN SCOPE, AND NOT FILED: every fixture in this file is
 * `source_code`, because that is the only artifact type the carried offset
 * reaches. The canonical credential scan that records the offset runs under
 * `parsed.type === 'source_code'` (semantic-compiler.ts:176), so on a skill,
 * an mcp_config or a soul artifact BOTH CRED checks keep main's leftmost-match
 * and evidence-span guesses and can still cite different lines for the same
 * file. Nothing below tests that path, and nothing below should be read as
 * covering it.
 *
 * WHY THE KEY IS SYNTHESIZED AT RUNTIME rather than committed like every other
 * fixture credential in this repo: the detector that has to fire here skips any
 * value whose own bytes contain FAKE / EXAMPLE / PLACEHOLDER / DUMMY /
 * YOUR_KEY / YOUR_TOKEN / REPLACE_ME / INSERT_HERE
 * (`semantic-compiler.ts` scanCanonicalCredentialFormats). A key carrying the
 * house FAKE marker produces no finding, so the test would be vacuously green.
 * The convention therefore cannot apply, and the alternative — committing a
 * credential-shaped literal to a public repo — is worse. The key is generated
 * from a fixed seed at run time, written into a temp directory the test creates
 * and removes, and never appears in any committed file.
 *
 * Fixture constraints, all load-bearing:
 *   - the key must match `sk-[a-zA-Z0-9]{48,}`: 48+ CONSECUTIVE alphanumerics,
 *     no hyphens (a 47-char body emits nothing);
 *   - no placeholder marker anywhere in the key bytes (see above);
 *   - the fixture path must contain no directory named fixture / test /
 *     example, which suppresses the credential checks by design.
 * Each is asserted below rather than assumed.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { assertDistFreshIfPresent } from "../helpers/dist-freshness";

beforeAll(assertDistFreshIfPresent);

const REPO_ROOT = join(__dirname, "..", "..");
const CLI = join(REPO_ROOT, "dist", "cli.js");

/** Minimum count of HIGH/CRITICAL findings the fixture must produce. */
const MIN_HIGH_CRITICAL = 2;

const ALPHANUMERIC =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/**
 * Deterministic alphanumeric string from a fixed seed (a plain LCG — this is a
 * fixture generator, not a source of randomness). Same bytes on every run and
 * every machine, so a failure is reproducible, while the bytes themselves live
 * nowhere on disk in this repo.
 */
function synthesizeKeyBody(seed: number, length: number): string {
  let state = seed >>> 0;
  let out = "";
  for (let i = 0; i < length; i++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    out += ALPHANUMERIC[(state >>> 8) % ALPHANUMERIC.length];
  }
  return out;
}

const KEY_BODY = synthesizeKeyBody(20260809, 52);
const KEY = `sk-${KEY_BODY}`;

const ARTIFACT_RELATIVE = join("app", "config.ts");
const ARTIFACT_CONTENT = [
  "// Runtime configuration for the billing worker.",
  "import { createClient } from './client';",
  "",
  "const REGION = 'us-east-1';",
  "const RETRIES = 3;",
  "",
  "export const settings = {",
  "  region: REGION,",
  "  retries: RETRIES,",
  `  openaiApiKey: '${KEY}',`,
  "  endpoint: 'https://api.openai.com/v1',",
  "};",
  "",
  "export const client = createClient(settings);",
  "",
].join("\n");

/** Derived from the fixture, never read back out of scanner output. */
const EXPECTED_LINE =
  ARTIFACT_CONTENT.split("\n").findIndex(l => l.includes(KEY)) + 1;

const PLACEHOLDER_MARKERS = [
  "FAKE",
  "EXAMPLE",
  "PLACEHOLDER",
  "DUMMY",
  "YOUR_KEY",
  "YOURKEY",
  "YOUR_TOKEN",
  "YOURTOKEN",
  "REPLACE_ME",
  "INSERT_HERE",
];

let scanDir = "";
let artifactAbsolute = "";

function canRun(): boolean {
  return existsSync(CLI);
}

function stripAnsi(s: string): string {
  return s.replace(/\x1b\[[0-9;]*m/g, "");
}

interface CliRun {
  status: number | null;
  stdout: string;
  stderr: string;
  combined: string;
}

/**
 * Exit status is read off the spawn result directly. Routing the CLI through a
 * pipe would report the PIPE's status, which is a different number.
 */
function runCli(args: string[]): CliRun {
  const r = spawnSync("node", [CLI, ...args], {
    encoding: "utf-8",
    timeout: 120_000,
  });
  const stdout = stripAnsi(r.stdout ?? "");
  const stderr = stripAnsi(r.stderr ?? "");
  return { status: r.status, stdout, stderr, combined: `${stdout}\n${stderr}` };
}

interface RenderedFinding {
  severity: string;
  name: string;
  location: string;
  verify?: string;
  /**
   * `Verify:` commands the renderer prints INSIDE another line \u2014 today the
   * `Fix:` text, which `fix-generator.ts` terminates with
   * `Verify: hackmyagent secure <dir>`.
   */
  embeddedVerify: string[];
}

/**
 * Parse the rendered finding blocks. Each block opens with a severity badge
 * line and carries its location, guidance, `Verify:` and `Fix:` lines after it.
 *
 * BOTH KINDS OF VERIFY ARE COLLECTED. An earlier revision matched `Verify:`
 * only at the START of a block line, on the reasoning that a mid-line match
 * would collect "a command the renderer never offered as a citation". The
 * renderer does offer it \u2014 it is printed, in the same block, prefixed with the
 * same word \u2014 and it was the one command in the whole population that did not
 * run: `Verify: hackmyagent secure app` from any cwd but the scan target's is
 * `Error: Directory '<cwd>/app' does not exist.` (exit 1). A parser that
 * excludes the failing case is a parser that cannot fail.
 */
function parseRenderedFindings(text: string): RenderedFinding[] {
  const out: RenderedFinding[] = [];
  const badge = /^\s*\u2502\s+(CRITICAL|HIGH|MEDIUM|LOW)\s{2,}(.+?)\s*$/;
  const body = /^\s*\u2502\s+(.*?)\s*$/;
  let current: RenderedFinding | undefined;
  for (const raw of text.split("\n")) {
    const b = badge.exec(raw);
    if (b) {
      current = { severity: b[1], name: b[2], location: "", embeddedVerify: [] };
      out.push(current);
      continue;
    }
    if (!current) continue;
    const m = body.exec(raw);
    if (!m) {
      current = undefined;
      continue;
    }
    const content = m[1];
    if (content.startsWith("Verify: ")) {
      current.verify = content.slice("Verify: ".length).trim();
      continue;
    }
    const embedded = content.indexOf("Verify: ");
    if (embedded > 0) {
      current.embeddedVerify.push(content.slice(embedded + "Verify: ".length).trim());
    }
    if (!current.location && content && !content.startsWith("Fix: ")) {
      current.location = content;
    }
  }
  return out;
}

/**
 * Run a rendered command from a foreign cwd.
 *
 * A command naming the `hackmyagent` binary is executed through THIS build
 * (`node dist/cli.js`), never through whatever is on PATH: the machine this was
 * written on carries a global 0.27.0, and a test that silently exercises a
 * different build is not a test of this diff. Only the binary name is
 * substituted \u2014 the arguments, which are the thing under test, are untouched.
 */
function runRenderedCommand(command: string, cwd: string) {
  const executable = command.startsWith("hackmyagent ")
    ? `node ${JSON.stringify(CLI)} ${command.slice("hackmyagent ".length)}`
    : command;
  return spawnSync(executable, {
    shell: true,
    cwd,
    encoding: "utf-8",
    timeout: 180_000,
  });
}

/* ------------------------------------------------------------------ *
 * Round 2 fixtures — see the `describe` blocks at the bottom for what
 * each one is for and which direction it fails in on the pre-fix build.
 * ------------------------------------------------------------------ */

/**
 * DECOY fixture: two credential-SHAPED strings ABOVE the real key.
 *
 * Line 3 is a 64-hex digest (the high-entropy fallback matches it) and line 6 a
 * `sk-EXAMPLE…` documentation placeholder (the vendor prefix matches it; the
 * compiler's own placeholder filter refuses to REPORT it). Neither is the value
 * either finding names. The real, reportable key is on line 7.
 */
const DECOY_DIGEST = (() => {
  // 64 hex characters with real character diversity, so it clears the entropy
  // fallback's filler rules and is genuinely picked up as credential-SHAPED —
  // which is the whole reason it is a decoy.
  let state = 31337 >>> 0;
  const hex = "0123456789abcdef";
  let out = "";
  for (let i = 0; i < 64; i++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    out += hex[(state >>> 8) % hex.length];
  }
  return out;
})();
const DECOY_PLACEHOLDER = "sk-" + "EXAMPLE" + synthesizeKeyBody(4242, 40);
const DECOY_KEY = "sk-" + synthesizeKeyBody(20260810, 52);
const DECOY_RELATIVE = join("app", "bundle.ts");
const DECOY_CONTENT = [
  "// Build bundle metadata for the billing worker.", // 1
  'export const SERVICE = "widget-router";', //           2
  `export const BUNDLE_DIGEST = '${DECOY_DIGEST}';`, //   3
  "", //                                                  4
  "// Retired value, kept for the migration note:", //     5
  `// const OLD = "${DECOY_PLACEHOLDER}";`, //             6
  `export const openaiApiKey = "${DECOY_KEY}";`, //        7
  "", //                                                  8
  "export const client = { openaiApiKey };", //            9
  "",
].join("\n");

/** Derived from the fixture, never read back out of scanner output. */
const DECOY_EXPECTED_LINE =
  DECOY_CONTENT.split("\n").findIndex(l => l.includes(DECOY_KEY)) + 1;
const DECOY_DIGEST_LINE =
  DECOY_CONTENT.split("\n").findIndex(l => l.includes(DECOY_DIGEST)) + 1;

/** LONE-FILE fixture: a directory that HAS a .gitignore, scanned one file at a time. */
const LONE_CONTENT = [
  "// Runtime configuration for the shipping worker.",
  `export const openaiApiKey = "${DECOY_KEY}";`,
  "export const region = 'us-east-1';",
  "",
].join("\n");

let decoyDir = "";
let loneDir = "";
let loneFile = "";

beforeAll(() => {
  if (!canRun()) return;
  // No `test` / `fixture` / `example` segment: those suppress the credential
  // checks by design and would make every assertion below vacuous.
  scanDir = mkdtempSync(join(tmpdir(), "hma-cite-"));
  mkdirSync(join(scanDir, "app"), { recursive: true });
  artifactAbsolute = join(scanDir, ARTIFACT_RELATIVE);
  writeFileSync(artifactAbsolute, ARTIFACT_CONTENT, "utf-8");

  decoyDir = mkdtempSync(join(tmpdir(), "hma-decoy-"));
  mkdirSync(join(decoyDir, "app"), { recursive: true });
  writeFileSync(join(decoyDir, DECOY_RELATIVE), DECOY_CONTENT, "utf-8");

  loneDir = mkdtempSync(join(tmpdir(), "hma-lone-"));
  mkdirSync(join(loneDir, "app"), { recursive: true });
  loneFile = join(loneDir, "app", "config.ts");
  writeFileSync(loneFile, LONE_CONTENT, "utf-8");
  // The .gitignore sits BESIDE the scanned file, which is the whole point: the
  // temp copy the scan actually reads has none.
  writeFileSync(join(loneDir, "app", ".gitignore"), "node_modules/\ndist/\n", "utf-8");
});

afterAll(() => {
  for (const d of [scanDir, decoyDir, loneDir]) {
    if (d) rmSync(d, { recursive: true, force: true });
  }
});

describe.runIf(canRun())("locatable, runnable citations (#368, #286)", () => {
  it("the fixture itself satisfies every detector precondition", () => {
    expect(KEY).toMatch(/^sk-[a-zA-Z0-9]{48,}$/);
    expect(KEY_BODY.length).toBeGreaterThanOrEqual(48);
    const upper = KEY.toUpperCase();
    for (const marker of PLACEHOLDER_MARKERS) {
      expect(upper).not.toContain(marker);
    }
    for (const segment of scanDir.split(/[\\/]/)) {
      const lower = segment.toLowerCase();
      expect(lower).not.toContain("fixture");
      expect(lower).not.toContain("test");
      expect(lower).not.toContain("example");
    }
    expect(EXPECTED_LINE).toBeGreaterThan(0);
    expect(existsSync(join(scanDir, ".gitignore"))).toBe(false);
  });

  it("AST-CRED-003 carries the fixture's own line, and the report can be located", () => {
    const jsonRun = runCli(["secure", scanDir, "--json", "--no-machine-posture"]);
    expect(jsonRun.status).toBe(1);
    const parsed = JSON.parse(jsonRun.stdout);
    const findings: any[] = parsed.findings ?? [];

    // Non-vacuity floor: a compile break or a path typo must not let the
    // invariants below pass over an empty finding set.
    const highCritical = findings.filter(
      f => f.severity === "high" || f.severity === "critical",
    );
    expect(highCritical.length).toBeGreaterThanOrEqual(MIN_HIGH_CRITICAL);

    const cred = findings.find(f => f.checkId === "AST-CRED-003");
    expect(cred, "AST-CRED-003 must fire on the planted key").toBeDefined();
    expect(Number.isInteger(cred.line)).toBe(true);
    expect(cred.line).toBe(EXPECTED_LINE);

    const textRun = runCli(["secure", scanDir, "--no-machine-posture"]);
    expect(textRun.status).toBe(1);
    const rendered = parseRenderedFindings(textRun.combined);
    const credBlock = rendered.find(f => f.name.includes("Hardcoded Secret"));
    expect(credBlock, "the CRITICAL block must render").toBeDefined();
    expect(credBlock!.location).toBe(`${ARTIFACT_RELATIVE}:${EXPECTED_LINE}`);
    expect(credBlock!.verify, "a CRITICAL finding must carry a Verify").toBeDefined();
  });

  it("every rendered HIGH/CRITICAL Verify command runs from a foreign cwd", () => {
    const textRun = runCli(["secure", scanDir, "--no-machine-posture"]);
    expect(textRun.status).toBe(1);
    const rendered = parseRenderedFindings(textRun.combined);
    const severe = rendered.filter(
      f => f.severity === "CRITICAL" || f.severity === "HIGH",
    );
    expect(severe.length).toBeGreaterThanOrEqual(MIN_HIGH_CRITICAL);

    // The cwd is deliberately NOT the scan target — that is the whole defect.
    const foreignCwd = tmpdir();
    expect(foreignCwd.startsWith(scanDir)).toBe(false);

    let sawPlantedKey = false;
    for (const f of severe) {
      expect(f.verify, `${f.name} has no Verify command`).toBeDefined();
      const r = spawnSync(f.verify!, {
        shell: true,
        cwd: foreignCwd,
        encoding: "utf-8",
        timeout: 30_000,
      });
      expect(r.status, `${f.verify} exited non-zero from ${foreignCwd}`).toBe(0);
      const out = (r.stdout ?? "").trim();
      // `sed -n '9999p'` exits 0 with empty output, so the exit code alone is
      // not an oracle for "this command showed the reader the cited trigger".
      expect(out.length, `${f.verify} produced no output`).toBeGreaterThan(0);
      expect(
        ARTIFACT_CONTENT.includes(out),
        `${f.verify} printed text that is not in the planted fixture`,
      ).toBe(true);
      if (out.includes(KEY)) sawPlantedKey = true;
    }
    expect(
      sawPlantedKey,
      "no Verify command showed the planted credential line",
    ).toBe(true);
  });

  it("emits no Verify for a finding with no line, and never a whole-file dump", () => {
    const textRun = runCli(["secure", scanDir, "--no-machine-posture"]);
    const rendered = parseRenderedFindings(textRun.combined);

    // GIT-001 `Missing .gitignore` is the live example: the detector recorded no
    // line for it, and there is no line to record — the path it names is absent
    // BY CONSTRUCTION.
    const absence = rendered.find(f => f.name.includes("Missing .gitignore"));
    expect(absence, "the absence finding must render").toBeDefined();
    expect(absence!.verify).toBeUndefined();

    // NO LINE, NO VERIFY — and in particular never a `cat`. A revision of this
    // work degraded the no-line case to `cat <path>`, which on `test/hma`
    // rendered `Verify: cat <target>/.env` and
    // `Verify: cat <target>/.opena2a/credvault/store.key` under two CRITICALs:
    // a security scanner telling the reader to print a secret file, on findings
    // whose trigger `cat` does not verify. Every citation this generator emits
    // is a single-line `sed`.
    for (const f of rendered) {
      if (!f.verify) continue;
      expect(f.verify, `a Verify dumps a whole file: ${f.verify}`).not.toMatch(/^cat\s/);
      const path = /^sed -n '\d+p'\s+(.+)$/.exec(f.verify)?.[1];
      expect(path, `unparseable Verify: ${f.verify}`).toBeDefined();
      const unquoted = path!.replace(/^'(.*)'$/, "$1").replace(/'\\''/g, "'");
      expect(existsSync(unquoted), `${f.verify} names a missing path`).toBe(true);
    }
  });

  it("a Verify embedded in a Fix text runs from the scan target", () => {
    // #286, the half the citation field does not cover. `fix-generator.ts`
    // terminates its fix prose with `Verify: hackmyagent secure <dir>`.
    //
    // THIS ASSERTED AN ABSOLUTE TARGET AND WAS REVERSED, deliberately. An
    // earlier revision threaded the scan root into `fix-generator` so that
    // `<dir>` resolved from anywhere. In the terminal that changed nothing for
    // a top-level artifact — `completeTargetlessCitations` already rewrites a
    // lone `.` to the citation target, and the terminal output is byte-
    // identical with and without the threading. What it DID change was the
    // machine formats: sarif 0 -> 5, html 0 -> 5, json 0 -> 10 absolute-path
    // lines on one fixture. `-f html` is `secure --help`'s "shareable
    // compliance report" and SARIF goes to the GitHub Security tab, so the
    // operator's username and tree layout shipped in the artifacts most likely
    // to be attached to a questionnaire or an issue.
    //
    // So the contract this pins is the SCAN-TARGET one, which is what the tool
    // has always actually offered here, plus the leak that must not come back.
    // The nested-artifact foreign-cwd case is real and stays open as #491;
    // `__tests__/nanomind-core/fix-text-no-absolute-path.test.ts` holds the
    // generator side.
    const textRun = runCli(["secure", scanDir, "--no-machine-posture"]);
    const rendered = parseRenderedFindings(textRun.combined);

    const commands = [...new Set(rendered.flatMap(f => f.embeddedVerify))];
    // Non-vacuity, and the reason the parser changed: with the old
    // start-of-line-only rule this list was empty and the block proved nothing.
    expect(
      commands.length,
      "no Verify was parsed out of any Fix text — the parser is skipping them again",
    ).toBeGreaterThan(0);

    for (const command of commands) {
      const target = /\bsecure\s+(\S+)/.exec(command)?.[1];
      expect(target, `no scan target in: ${command}`).toBeDefined();

      // Every one of them runs from the scan target. That is the scope the
      // citation actually claims, and it is the one a reader following the
      // report is standing in.
      const r = runRenderedCommand(command, scanDir);
      const combined = `${r.stdout ?? ""}${r.stderr ?? ""}`;
      expect(combined, `${command} could not resolve its target`).not.toContain("does not exist");
      // 0 = clean, 1 = findings. Anything else is the command failing to run.
      expect([0, 1], `${command} exited ${r.status} from ${scanDir}`).toContain(r.status);
    }
  });

  it("no Fix text carries the scanning machine's absolute path", () => {
    // The leak pin, at the CLI rather than at the generator: this is the shape
    // a reader actually ships. Red against the reverted revision.
    const jsonRun = runCli(["secure", scanDir, "--json", "--no-machine-posture"]);
    const parsed = JSON.parse(jsonRun.stdout);
    const findings: Array<{ fix?: string }> = parsed.findings ?? [];
    expect(findings.length, "no findings, so this proves nothing").toBeGreaterThan(0);

    const fixes = findings.map(f => f.fix).filter((s): s is string => !!s);
    expect(fixes.length, "no fix text on any finding").toBeGreaterThan(0);

    for (const fix of fixes) {
      expect(fix, `fix text carries the scan root: ${fix}`).not.toContain(scanDir);
    }
  });
});

/* ================================================================== *
 * Round 2. Each block below was measured RED on the build that shipped
 * the three fixes above, in the direction its name states.
 * ================================================================== */

describe.runIf(canRun())("a citation names the value the finding names, not the leftmost lookalike", () => {
  // The gate test above puts exactly ONE credential-shaped string in its
  // fixture, so `expect(cred.line).toBe(EXPECTED_LINE)` passed no matter which
  // string the producer picked — the fixture could not tell "derived from the
  // reported credential" apart from "leftmost credential-shaped run in the
  // file". This fixture can: a 64-hex digest on line 3 and a `sk-EXAMPLE…` doc
  // placeholder on line 6 both sit ABOVE the real key on line 7, and both match
  // the shared credential-format matcher.
  //
  // MEASURED RED on the pre-fix build in the WRONG-LINE direction, not the
  // no-line direction:
  //   AST-CRED-001 | line: 3 | Credential read in source_code context
  //   AST-CRED-003 | line: 3 | Hardcoded secret: OpenAI legacy key: sk-****…
  // Line 3 is the digest. A citation that is confidently wrong is worse than an
  // absent one, and this diff had newly introduced one on a CRITICAL.

  it("the decoy fixture really does contain three credential-shaped strings", () => {
    // Non-vacuity, and it is the whole point of the fixture: if the digest or
    // the placeholder stopped being credential-SHAPED, the leftmost-match bug
    // would pass this file by construction.
    expect(DECOY_DIGEST_LINE).toBe(3);
    expect(DECOY_EXPECTED_LINE).toBe(7);
    expect(DECOY_DIGEST_LINE).toBeLessThan(DECOY_EXPECTED_LINE);
    expect(DECOY_CONTENT.indexOf(DECOY_DIGEST)).toBeLessThan(
      DECOY_CONTENT.indexOf(DECOY_KEY),
    );
    expect(DECOY_CONTENT.indexOf(DECOY_PLACEHOLDER)).toBeLessThan(
      DECOY_CONTENT.indexOf(DECOY_KEY),
    );
    // The real key must satisfy the reporting detector; the placeholder must NOT
    // (its `EXAMPLE` marker is what makes it a placeholder rather than a key).
    expect(DECOY_KEY).toMatch(/^sk-[a-zA-Z0-9]{48,}$/);
    expect(DECOY_PLACEHOLDER.toUpperCase()).toContain("EXAMPLE");
    expect(DECOY_DIGEST).toMatch(/^[0-9a-f]{64}$/);
  });

  it("AST-CRED-003 cites the real key's line, not the digest's", () => {
    const run = runCli(["secure", decoyDir, "--json", "--no-machine-posture"]);
    expect(run.status).toBe(1);
    const findings: any[] = JSON.parse(run.stdout).findings ?? [];

    const cred = findings.find(f => f.checkId === "AST-CRED-003");
    expect(cred, "AST-CRED-003 must fire on the planted key").toBeDefined();
    expect(cred.line).toBe(DECOY_EXPECTED_LINE);
    expect(cred.line).not.toBe(DECOY_DIGEST_LINE);
  });

  it("AST-CRED-001 cites the same line — the class, not just the CRITICAL", () => {
    // AST-CRED-001 cited the digest at HEAD too. Fixing only the finding that
    // regressed would leave the sibling telling the reader a different story
    // about the same file.
    const run = runCli(["secure", decoyDir, "--json", "--no-machine-posture"]);
    const findings: any[] = JSON.parse(run.stdout).findings ?? [];
    const cred = findings.find(f => f.checkId === "AST-CRED-001");
    expect(cred, "AST-CRED-001 must fire on the planted key").toBeDefined();
    expect(cred.line).toBe(DECOY_EXPECTED_LINE);
    expect(cred.line).not.toBe(DECOY_DIGEST_LINE);
  });

  it("the rendered Verify prints the key line, not the digest line", () => {
    const run = runCli(["secure", decoyDir, "--no-machine-posture"]);
    const rendered = parseRenderedFindings(run.combined);
    const cred = rendered.find(f => f.name.includes("Hardcoded Secret"));
    expect(cred?.verify, "the CRITICAL block must carry a Verify").toBeDefined();

    const r = spawnSync(cred!.verify!, {
      shell: true,
      cwd: tmpdir(),
      encoding: "utf-8",
      timeout: 30_000,
    });
    expect(r.status).toBe(0);
    const printed = (r.stdout ?? "").trim();
    // The oracle is the FIXTURE: the line the command prints must be the line
    // that holds the key, not merely some line of the file.
    expect(printed).toContain(DECOY_KEY);
    expect(printed).not.toContain(DECOY_DIGEST);
  });
});

describe.runIf(canRun())("a lone-FILE target cites the user's tree, not the temp copy", () => {
  // `secure <file>` copies the file into a temp directory and scans THAT, so the
  // two questions "what path do I show the reader" and "what tree did I scan"
  // have different answers. A revision of this work carried BOTH roots so a
  // filesystem existence probe could pick the second one; that probe only ever
  // fed a `cat <path>` fallback for findings with no line, and with the
  // fallback deleted the probe went with it — a finding with no line now emits
  // no Verify on every path, so nothing needs to ask whether a file is there.
  //
  // What must still hold is the DISPLAY half, and it is the half a reader
  // notices: a Verify naming the temp copy would cite a path under /var/folders
  // that vanishes at process exit. Both directions are asserted below.

  it("the lone-file fixture has the .gitignore the scan will not see", () => {
    expect(existsSync(join(loneDir, "app", ".gitignore"))).toBe(true);
    expect(existsSync(loneFile)).toBe(true);
    expect(dirname(loneFile)).toBe(join(loneDir, "app"));
  });

  it("the absence finding gets no Verify, because it has no line", () => {
    const run = runCli(["secure", loneFile, "--no-machine-posture"]);
    const rendered = parseRenderedFindings(run.combined);

    const absence = rendered.find(f => f.name.includes("Missing .gitignore"));
    expect(absence, "the absence finding must render for a lone-file target").toBeDefined();
    expect(
      absence!.verify,
      "a Verify here cites a file the finding says is missing",
    ).toBeUndefined();
  });

  it("the credential Verify still names the user's path and runs", () => {
    // The display half: the root the reader is shown must stay the user-facing
    // directory. A fix that reached for the scanned temp dir instead would emit
    // a Verify naming a path under /var/folders that vanishes at process exit.
    const run = runCli(["secure", loneFile, "--no-machine-posture"]);
    const rendered = parseRenderedFindings(run.combined);
    const cred = rendered.find(f => f.name.includes("Hardcoded Secret"));
    expect(cred?.verify, "the CRITICAL block must carry a Verify").toBeDefined();
    expect(cred!.verify).toContain(loneFile);

    const r = spawnSync(cred!.verify!, {
      shell: true,
      cwd: tmpdir(),
      encoding: "utf-8",
      timeout: 30_000,
    });
    expect(r.status).toBe(0);
    expect((r.stdout ?? "").trim()).toContain(DECOY_KEY);
  });
});

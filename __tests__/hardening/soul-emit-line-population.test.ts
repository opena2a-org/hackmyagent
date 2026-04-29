/**
 * Issue #141 — Every SOUL governance emit site in `scanner.ts` must
 * populate `line:` so the data-driven `generateVerifyCommand()` produces
 * a real `sed -n 'Np' file` Verify. Findings without `line:` get no
 * Verify command at all (that's the contract); but the SOUL detectors
 * specifically *do* have access to a regex match offset and should not
 * throw it away.
 *
 * This is a deterministic CI gate. It walks the scanner source, finds
 * every `findings.push({ checkId: 'SOUL-...' })` block (one block per
 * detector), and asserts each block contains a `line:` property. Fails
 * if any new SOUL detector lands without line population — at which
 * point the maintainer should add `line: lineFromOffset(content, m.index)`
 * to the new emit site.
 *
 * Why source-text walk and not behavioural test:
 *   - A behavioural test requires running the scanner against fixture
 *     SOUL.md content for each detector — heavy, slow, and brittle when
 *     a detector's threshold changes.
 *   - The source walk runs in milliseconds in CI on every PR and gates
 *     the *contract* (every SOUL emit carries `line`) rather than
 *     the threshold tuning of any single detector.
 *
 * Pairs with `__tests__/ui/verify-command.test.ts` (generator unit
 * tests) and the corpus-gated release-smoke harness (Verify execution
 * against real fixtures).
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { resolve } from "path";

const SCANNER_PATH = resolve(__dirname, "../../src/hardening/scanner.ts");

/** Every distinct SOUL checkId currently emitted by `scanner.ts`. */
const EXPECTED_SOUL_CHECK_IDS = [
  "SOUL-BYPASS",
  "SOUL-ESCAPE-CLAUSE",
  "SOUL-CONTRADICTION",
  "SOUL-UNVERIFIABLE-CLAIM",
  "SOUL-CONSENT",
  "SOUL-COMPLETENESS",
] as const;

/**
 * Extract all `findings.push({ ... })` blocks that emit a given checkId.
 * Returns the block bodies (the text between the outermost braces) so
 * the caller can grep them for `line:` etc.
 *
 * Greedy-but-balanced: walks brace depth from the `findings.push({`
 * starting position until depth returns to 0. Tolerant of nested braces
 * inside template strings or object literals.
 */
function extractEmitBlocks(source: string, checkId: string): string[] {
  const blocks: string[] = [];
  const needle = `checkId: '${checkId}'`;
  let cursor = 0;

  while (true) {
    const idAt = source.indexOf(needle, cursor);
    if (idAt < 0) break;

    // Walk backward from `checkId:` to the opening `findings.push({`.
    // The `{` we want is the most recent `{` at depth 0 before `idAt`
    // that is preceded by `findings.push(` or similar.
    const openBrace = source.lastIndexOf("findings.push({", idAt);
    if (openBrace < 0) {
      cursor = idAt + needle.length;
      continue;
    }
    const bodyStart = openBrace + "findings.push({".length;

    // Walk forward to find the matching `})`.
    let depth = 1;
    let i = bodyStart;
    while (i < source.length && depth > 0) {
      const ch = source[i];
      if (ch === "{") depth++;
      else if (ch === "}") depth--;
      i++;
    }
    const body = source.slice(bodyStart, i - 1);
    blocks.push(body);
    cursor = i;
  }

  return blocks;
}

describe("SOUL emit-site line population (#141)", () => {
  const source = readFileSync(SCANNER_PATH, "utf8");

  for (const checkId of EXPECTED_SOUL_CHECK_IDS) {
    it(`every ${checkId} emit site populates 'line:'`, () => {
      const blocks = extractEmitBlocks(source, checkId);
      expect(
        blocks.length,
        `expected at least one emit site for ${checkId} in scanner.ts`,
      ).toBeGreaterThan(0);
      for (const body of blocks) {
        expect(
          /\bline:\s*lineFromOffset\(/.test(body),
          `emit site for ${checkId} is missing 'line: lineFromOffset(...)' — without it, generateVerifyCommand() returns undefined and the user sees no Verify command. Add 'line: lineFromOffset(content, m.index)' or similar to the findings.push({...}) block.`,
        ).toBe(true);
      }
    });
  }

  it("scanner.ts imports lineFromOffset from text-position", () => {
    expect(source).toMatch(
      /import\s*\{\s*lineFromOffset\s*\}\s*from\s*['"]\.\.\/types\/text-position['"]/,
    );
  });
});

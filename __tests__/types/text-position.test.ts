/**
 * Deterministic unit tests for the offset-to-line helper used by detectors
 * that match against regex `m.index` and need to emit a `line:` field on
 * findings (issue #141).
 */

import { describe, it, expect } from "vitest";
import { lineFromOffset } from "../../src/types/text-position";

describe("lineFromOffset (#141)", () => {
  const text = ["alpha", "beta", "gamma", "delta"].join("\n");
  // offsets:
  //   0..4   = alpha   (line 1; '\n' at 5)
  //   6..9   = beta    (line 2; '\n' at 10)
  //   11..15 = gamma   (line 3; '\n' at 16)
  //   17..21 = delta   (line 4)

  it("returns line 1 for offset 0", () => {
    expect(lineFromOffset(text, 0)).toBe(1);
  });

  it("returns line 1 for negative offsets", () => {
    expect(lineFromOffset(text, -7)).toBe(1);
  });

  it("returns the correct line for an offset inside the first line", () => {
    expect(lineFromOffset(text, 3)).toBe(1);
  });

  it("returns line 2 for the offset just past the first newline", () => {
    expect(lineFromOffset(text, 6)).toBe(2);
  });

  it("returns line 3 for an offset inside line 3", () => {
    expect(lineFromOffset(text, 13)).toBe(3);
  });

  it("returns line 4 for an offset inside line 4", () => {
    expect(lineFromOffset(text, 18)).toBe(4);
  });

  it("clamps to the final line when offset exceeds content length", () => {
    expect(lineFromOffset(text, 9999)).toBe(4);
  });

  it("returns 1 on empty content", () => {
    expect(lineFromOffset("", 0)).toBe(1);
  });

  it("treats CRLF the same as LF (counts only \\n)", () => {
    const crlf = "x\r\ny\r\nz";
    // 'x' at 0 (line 1); '\r' at 1; '\n' at 2 → line 2 starts at 3
    expect(lineFromOffset(crlf, 3)).toBe(2);
    // 'z' at 6 → line 3
    expect(lineFromOffset(crlf, 6)).toBe(3);
  });

  it("handles a single line with no newlines", () => {
    expect(lineFromOffset("only one line", 5)).toBe(1);
    expect(lineFromOffset("only one line", 9999)).toBe(1);
  });
});

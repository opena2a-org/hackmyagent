/**
 * #324 — control characters in a path must not reach a rendered line.
 *
 * The measured defect: a directory whose name contained a newline produced
 *
 *     Fix: rm -rf '/…/.hackmyagent-backup/2026-01-01-000000
 *
 * The emitted command was correct — `shellQuote` is total and executing the
 * argument removed the right directory — but the renderer keeps only the first
 * non-blank line, so the visible command ended mid-quote and pasting it left the
 * shell at a `quote>` continuation prompt.
 *
 * Control characters are written as `\x`/`\u` escapes or built with
 * `String.fromCodePoint` throughout. A raw control byte in a test fixture is
 * invisible in review and, for NUL, silently truncates the line it sits on.
 */
import { describe, it, expect } from 'vitest';
import { escapeForDisplay } from '../../src/ui/display-safe';

const ESC = String.fromCodePoint(0x1b);
const NUL = String.fromCodePoint(0x00);

describe('escapeForDisplay', () => {
  it('leaves ordinary text byte-identical', () => {
    // The common case by far. If this changed, every rendered line in the tool
    // would change with it.
    const plain = "rm -rf '/home/me/proj/.hackmyagent-backup/2026-01-01-000000'";
    expect(escapeForDisplay(plain)).toBe(plain);
  });

  it('makes a newline visible instead of dropping it', () => {
    const withNewline = "rm -rf '/p/2026-01-01-000000\nEVIL'";
    const out = escapeForDisplay(withNewline);
    expect(out).toBe("rm -rf '/p/2026-01-01-000000\\nEVIL'");
    // The point of the exercise: one line, and the quote closes.
    expect(out.split('\n')).toHaveLength(1);
    expect(out.endsWith("'")).toBe(true);
  });

  it('escapes the named control characters readably', () => {
    expect(escapeForDisplay('a\rb')).toBe('a\\rb');
    expect(escapeForDisplay('a\tb')).toBe('a\\tb');
    expect(escapeForDisplay(`a${ESC}b`)).toBe('a\\eb');
    expect(escapeForDisplay(`a${NUL}b`)).toBe('a\\0b');
  });

  it('neutralizes an ANSI escape sequence', () => {
    // A path is attacker-influenced data. `ESC [ 2 J` clears the terminal, and a
    // CSI sequence can overwrite the lines above it — a path that edits the
    // report describing it.
    const out = escapeForDisplay(`${ESC}[2Jcleared`);
    expect(out).toBe('\\e[2Jcleared');
    expect(out).not.toContain(ESC);
  });

  it('is total over every character it claims to cover', () => {
    // Not a sample: every C0, DEL, C1 and both Unicode line separators, checked
    // for the property that matters — nothing in the output can move a cursor,
    // split a line, or change terminal state.
    const covered: number[] = [];
    for (let c = 0x00; c <= 0x9f; c++) {
      if (c >= 0x20 && c <= 0x7e) continue; // printable ASCII
      covered.push(c);
    }
    covered.push(0x2028, 0x2029);

    for (const code of covered) {
      const label = `U+${code.toString(16).padStart(4, '0')}`;
      const out = escapeForDisplay(`before${String.fromCodePoint(code)}after`);
      expect(out, `${label} survived escaping`).not.toContain(String.fromCodePoint(code));
      expect(out.split('\n'), `${label} split the line`).toHaveLength(1);
      expect(out.startsWith('before'), `${label} corrupted the text before it`).toBe(true);
      expect(out.endsWith('after'), `${label} corrupted the text after it`).toBe(true);
    }

    // Non-vacuity: the loop must have actually covered the interesting bytes.
    expect(covered).toContain(0x0a);
    expect(covered).toContain(0x1b);
    expect(covered.length).toBeGreaterThan(60);
  });

  it('leaves printable characters outside ASCII alone', () => {
    // Escaping must not mangle a legitimate non-English path.
    const path = "rm -rf '/Users/me/projets/données/配置'";
    expect(escapeForDisplay(path)).toBe(path);
  });
});

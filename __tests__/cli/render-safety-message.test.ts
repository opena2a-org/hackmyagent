/**
 * The failure message of the escaping assertion must not itself carry a byte
 * a terminal acts on.
 *
 * `assertNoRawControlBytes` reports a raw control character in a report. When
 * it fails it now quotes the surrounding text, and that text is by definition
 * the text carrying the hazard — so the diagnostic is a render site with the
 * same property to hold as the thing it is judging. If it fails on a file
 * named with an `ESC [ 2 J`, printing the context unescaped clears the
 * developer's terminal at exactly the moment they are reading a security
 * failure.
 *
 * This was not hypothetical. The first version escaped with `JSON.stringify`
 * alone and a comment claiming that was sufficient. `JSON.stringify` escapes
 * C0 and stops one byte short of DEL — which is one of the 31 codepoints the
 * assertion itself flags — so a DEL in a filename would have been reported by
 * emitting a DEL. C1 (0x80–0x9f) passes through raw too, and 0x9b there is a
 * single-byte CSI that a terminal acts on exactly like `ESC [`.
 *
 * Written with `String.fromCharCode`, per the helper's own rule: a literal
 * control byte in test source is invisible in every diff that would review it.
 */
import { describe, it, expect } from 'vitest';
import { escapeForMessage, locateRawControlBytes } from '../helpers/render-safety';

/** Everything `assertNoRawControlBytes` flags, plus the C1 range. */
function terminalActiveBytes(s: string): number[] {
  return [...s]
    .map((ch) => ch.charCodeAt(0))
    .filter((c) => (c < 0x20 && c !== 0x0a && c !== 0x09) || (c >= 0x7f && c <= 0x9f));
}

describe('the escaping assertion does not re-emit what it reports', () => {
  it('escapes every byte it would itself flag', () => {
    // The whole flagged set in one string, so this cannot pass by covering
    // the common case: C0 minus tab and newline, then DEL, then C1.
    const codes: number[] = [];
    for (let c = 0; c < 0x20; c += 1) if (c !== 0x0a && c !== 0x09) codes.push(c);
    for (let c = 0x7f; c <= 0x9f; c += 1) codes.push(c);

    // Non-vacuity, first: the fixture must actually carry them, or every
    // assertion below is about an empty string.
    const fixture = `path${codes.map((c) => String.fromCharCode(c)).join('')}end`;
    expect(
      terminalActiveBytes(fixture).length,
      'the fixture carries no terminal-active byte, so this measures nothing',
    ).toBe(codes.length);

    expect(
      terminalActiveBytes(escapeForMessage(fixture)),
      'the escaped rendering still carries a byte a terminal acts on',
    ).toEqual([]);
  });

  it('escapes DEL specifically, which JSON.stringify does not', () => {
    // Pinned on its own because this is the byte the first version leaked,
    // and a range assertion above would keep passing if the lower bound
    // drifted up to 0x80.
    const del = String.fromCharCode(0x7f);
    expect(
      JSON.stringify(del).includes(del),
      'JSON.stringify has started escaping DEL, so this test is now vacuous — '
      + 'check whether escapeForMessage still needs its own pass',
    ).toBe(true);
    expect(escapeForMessage(`a${del}b`)).not.toContain(del);
    expect(escapeForMessage(`a${del}b`)).toContain('\\u007f');
  });

  it('leaves ordinary text legible', () => {
    // An escape that mangles everything is safe and useless. The point of the
    // message is that a human can read the path out of it.
    const out = escapeForMessage('/tmp/hma-328/scan/package.json');
    expect(out).toContain('/tmp/hma-328/scan/package.json');
  });

  it('reports the offset of every flagged byte, in order', () => {
    const esc = String.fromCharCode(0x1b);
    const found = locateRawControlBytes(`ab${esc}cd${String.fromCharCode(0x7f)}`);
    expect(found).toEqual([{ index: 2, code: 0x1b }, { index: 5, code: 0x7f }]);
  });

  it('counts a control byte the same way whether or not astral text surrounds it', () => {
    // `locateRawControlBytes` walks code UNITS where the original filter walked
    // code POINTS. A surrogate half is >= 0xd800, so it can never be mistaken
    // for a control byte — but that is a property worth pinning rather than
    // reasoning about, since an emoji in a filename is ordinary.
    const esc = String.fromCharCode(0x1b);
    const astral = String.fromCodePoint(0x1f600);
    expect(locateRawControlBytes(`${astral}${esc}${astral}`).map((o) => o.code)).toEqual([0x1b]);
  });
});

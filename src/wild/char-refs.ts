/**
 * HTML character references for the Wild Scanner (#1085).
 *
 * A browser, and so an agent reading the page through one, sees `&#x69;` as
 * `i` and `&#xE0069;` as the tag character U+E0069. Judging the raw markup let
 * a payload written as numeric references pass every surface that reads text
 * or attribute values. These functions turn the markup into the text a parser
 * would produce before a surface is judged.
 *
 * Decoding is one pass: `&amp;#x69;` becomes the literal `&#x69;`, never `i`,
 * as it does in a browser.
 */

/**
 * The named references decoded. The full HTML table has over two thousand
 * names; these are the ones markup escapes with, plus the names of the
 * zero-width characters the unicode-stego surface reads.
 */
const NAMED: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: '\u00a0',
  zwnj: '\u200c',
  zwj: '\u200d',
  ZeroWidthSpace: '\u200b',
  NoBreak: '\u2060',
};

/**
 * A numeric reference in 0x80-0x9F names the windows-1252 character a legacy
 * page meant (HTML numeric character reference end state). Code points not
 * listed keep their value.
 */
const WINDOWS_1252: Record<number, number> = {
  0x80: 0x20ac, 0x82: 0x201a, 0x83: 0x0192, 0x84: 0x201e, 0x85: 0x2026, 0x86: 0x2020,
  0x87: 0x2021, 0x88: 0x02c6, 0x89: 0x2030, 0x8a: 0x0160, 0x8b: 0x2039, 0x8c: 0x0152,
  0x8e: 0x017d, 0x91: 0x2018, 0x92: 0x2019, 0x93: 0x201c, 0x94: 0x201d, 0x95: 0x2022,
  0x96: 0x2013, 0x97: 0x2014, 0x98: 0x02dc, 0x99: 0x2122, 0x9a: 0x0161, 0x9b: 0x203a,
  0x9c: 0x0153, 0x9e: 0x017e, 0x9f: 0x0178,
};

/**
 * A decimal or hexadecimal reference, whose `;` a browser does not require, or
 * a named one with its `;`. Digit runs are capped so the parse stays exact; a
 * longer run is out of range anyway and decodes to U+FFFD.
 */
const REFERENCE = /&(?:#[xX]([0-9a-fA-F]+);?|#([0-9]+);?|([A-Za-z][A-Za-z0-9]*);)/g;

function fromCodePoint(cp: number): string {
  if (cp === 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return '\ufffd';
  return String.fromCodePoint(WINDOWS_1252[cp] ?? cp);
}

/** Parse a digit run, saturating past the Unicode range so huge runs stay cheap. */
function parseDigits(digits: string, radix: number): number {
  const trimmed = digits.replace(/^0+/, '');
  if (trimmed.length > 8) return Infinity;
  return trimmed === '' ? 0 : parseInt(trimmed, radix);
}

/** `text` with its numeric references and the named ones above decoded. */
export function decodeCharacterReferences(text: string): string {
  if (!text.includes('&')) return text;
  return text.replace(REFERENCE, (whole, hex: string | undefined, dec: string | undefined, name: string | undefined) => {
    if (hex !== undefined) return fromCodePoint(parseDigits(hex, 16));
    if (dec !== undefined) return fromCodePoint(parseDigits(dec, 10));
    return name !== undefined && Object.prototype.hasOwnProperty.call(NAMED, name) ? NAMED[name] : whole;
  });
}

/**
 * `html` with character references decoded in text and attribute values, and
 * comments, `<script>` and `<style>` left as written: a parser decodes no
 * reference inside them. One forward pass; every search starts where the last
 * one ended, so an unclosed opener costs one scan to the end, not one per
 * opener.
 */
export function decodeMarkup(html: string): string {
  if (!html.includes('&')) return html;
  // Case-insensitive regexes rather than a lowercased copy: lowercasing can
  // change a string's length and so every index after it.
  const raw = /<!--|<script\b|<style\b/gi;
  const closers = { comment: /-->/g, script: /<\/script/gi, style: /<\/style/gi };
  let out = '';
  let from = 0;
  let match: RegExpExecArray | null;
  while ((match = raw.exec(html)) !== null) {
    const opener = match[0].toLowerCase();
    const closer = opener === '<!--' ? closers.comment : opener === '<script' ? closers.script : closers.style;
    closer.lastIndex = match.index + match[0].length;
    const close = closer.exec(html);
    const end = close === null ? html.length : close.index + close[0].length;
    out += decodeCharacterReferences(html.slice(from, match.index)) + html.slice(match.index, end);
    from = end;
    raw.lastIndex = end;
  }
  return out + decodeCharacterReferences(html.slice(from));
}

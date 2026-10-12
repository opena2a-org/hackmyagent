/**
 * Hidden-text decoding for the Wild Scanner's `unicode-stego` surface (#988).
 *
 * A page can carry text that renders as nothing and still reaches a model's
 * context when an agent reads the page. Two encodings are decoded here:
 *
 *   - Unicode tag characters U+E0020-U+E007E, each the ASCII character
 *     0x20-0x7E moved into plane 14;
 *   - a run of 8 or more zero-width characters drawn from exactly two
 *     symbols, read as bits, 8 to a byte, with both bit assignments tried.
 *
 * The hidden code points alone are never the signal. ZWNJ is ordinary Persian
 * orthography, ZWJ joins emoji sequences, U+FEFF and the bidi marks occur in
 * Hebrew and Hindi pages, and a subdivision flag (England, Scotland, Wales) is
 * a black flag followed by tag characters that spell its region code. Reusing
 * the static UNICODE-STEGO checks on page text fired HIGH on every
 * non-Latin-script page of a six-page benign set; decoding first and judging
 * the decoded text fired on none. So this module only decodes, and the caller
 * records a surface when a decoding reads as an injection payload.
 *
 * No other encoding (variation selectors, for example) is decoded until it has
 * its own measurement on benign pages.
 */

/** How a run of hidden code points was decoded. */
export type HiddenEncoding = 'tag-characters' | 'zero-width-binary';

export interface HiddenRun {
  encoding: HiddenEncoding;
  /**
   * Candidate plaintexts for the run: one for tag characters, two for a
   * zero-width run (one per bit assignment).
   */
  decodings: string[];
}

const TAG_FIRST = 0xe0020;
const TAG_LAST = 0xe007e;
const TAG_OFFSET = 0xe0000;

/** Zero width space, non-joiner, joiner, word joiner, and U+FEFF. All BMP. */
const ZERO_WIDTH = new Set([0x200b, 0x200c, 0x200d, 0x2060, 0xfeff]);

/** One byte's worth of bits: a shorter run cannot carry a character. */
export const MIN_ZERO_WIDTH_RUN = 8;

/**
 * Read `text[start, end)`, a run of zero-width characters, as bits. A character
 * equal to `one` is a 1 bit and the other symbol a 0 bit; trailing bits short
 * of a byte are dropped. Bytes are decoded as UTF-8, replacing invalid bytes.
 */
function decodeBits(text: string, start: number, end: number, one: number): string {
  const bytes = new Uint8Array(Math.floor((end - start) / 8));
  for (let i = 0; i < bytes.length; i++) {
    let byte = 0;
    for (let bit = 0; bit < 8; bit++) {
      byte = (byte << 1) | (text.charCodeAt(start + i * 8 + bit) === one ? 1 : 0);
    }
    bytes[i] = byte;
  }
  return new TextDecoder('utf-8').decode(bytes);
}

/**
 * Every run of hidden code points in `text` that one of the two encodings can
 * read, with its candidate decodings. One linear pass over the code points.
 *
 * A tag run is a maximal sequence of U+E0020-U+E007E; U+E0001 and U+E007F
 * (language tag, cancel tag) and every other character end it. A zero-width
 * run is a maximal sequence of the five characters in ZERO_WIDTH, decoded only
 * when it is at least 8 long and uses exactly two of them.
 */
export function hiddenRuns(text: string): HiddenRun[] {
  const runs: HiddenRun[] = [];
  let tag = '';
  let zwStart = -1;

  const endTagRun = () => {
    if (tag.length > 0) runs.push({ encoding: 'tag-characters', decodings: [tag] });
    tag = '';
  };
  const endZeroWidthRun = (end: number) => {
    if (zwStart < 0) return;
    const start = zwStart;
    zwStart = -1;
    if (end - start < MIN_ZERO_WIDTH_RUN) return;
    const symbols = new Set<number>();
    for (let i = start; i < end && symbols.size <= 2; i++) symbols.add(text.charCodeAt(i));
    if (symbols.size !== 2) return;
    const [low, high] = [...symbols].sort((a, b) => a - b);
    runs.push({
      encoding: 'zero-width-binary',
      decodings: [decodeBits(text, start, end, high), decodeBits(text, start, end, low)],
    });
  };

  let i = 0;
  while (i < text.length) {
    const cp = text.codePointAt(i) ?? 0;
    const width = cp > 0xffff ? 2 : 1;
    if (cp >= TAG_FIRST && cp <= TAG_LAST) {
      endZeroWidthRun(i);
      tag += String.fromCharCode(cp - TAG_OFFSET);
    } else if (ZERO_WIDTH.has(cp)) {
      endTagRun();
      if (zwStart < 0) zwStart = i;
    } else {
      endTagRun();
      endZeroWidthRun(i);
    }
    i += width;
  }
  endTagRun();
  endZeroWidthRun(text.length);
  return runs;
}

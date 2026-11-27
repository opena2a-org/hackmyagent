/**
 * The URLs of the declared purpose, found on the text as written.
 *
 * The credential analyzer reads the declared purpose for test, example,
 * documentation, fixture and demo, and reads no word inside a URL. The purpose
 * it holds has been through the report redaction table first
 * (`redactSecretsForReportReporting`), and a table replacement can take a
 * URL's scheme with it: in `"a_sk-<key>://h/test"` the URL starts inside the
 * key, so once the key is `[REDACTED_OPENAI_KEY]` nothing before `://` reads
 * as a scheme and `h/test` reads as prose. So the URLs are found here on the
 * ORIGINAL text, before any redaction, and handed to the analyzer as
 * positions in the redacted purpose (`SecurityAST.declaredPurposeUrlSpans`),
 * which it removes together with the URLs and the credential values it finds
 * on the purpose itself.
 */

/**
 * A scheme-like run inside a lowercased declared purpose and, when `://`
 * follows it, the URL it starts: up to whitespace, a double quote or an angle
 * bracket, the characters that end a URL in prose and in a JSON string value.
 * The URL part is optional so that each run is consumed once, whether or not
 * it starts a URL, and the caller removes only a run with a URL. The
 * purpose is tree-controlled text (a frontmatter description has no length cap
 * of its own), and a pattern that requires `://` re-reads the rest of a run
 * such as `a.a.a...` from every word boundary inside it, which is quadratic in
 * the length of the run.
 */
export const URL_IN_PURPOSE = /\b[a-z][a-z0-9+.-]*(:\/\/[^\s"<>]*)?/g;

/**
 * The stretches of `redacted[start, end)` that came from a URL of `original`,
 * as `[from, to)` pairs relative to `start`, in order and disjoint.
 *
 * `from[i]`/`to[i]` give the original characters character `i` of `redacted`
 * was produced from (`redactSecretsForReportWithOrigins`). A redacted
 * character is in a URL when its origin overlaps one: a replacement whose
 * match took part of a URL goes with it.
 *
 * The URLs are found by `URL_IN_PURPOSE` on the lowercased original lines the
 * stretch was produced from, exactly as the analyzer finds them on a purpose,
 * and carried back to the original character by character. Should that not
 * line up, which the lowercase mapping of JavaScript does not produce, the
 * whole stretch is returned: when the scanner cannot tell where the URLs are,
 * it reads none of the purpose. Linear in the lines read.
 */
export function urlSpansFromOriginal(
  original: string,
  from: Int32Array,
  to: Int32Array,
  start: number,
  end: number,
): Array<[number, number]> {
  if (end <= start) return [];
  // A URL never holds a line break, so the lines the stretch came from are
  // all that can hold one reaching into it.
  const lo = from[start];
  const hi = to[end - 1];
  const lineStart = lo === 0 ? 0 : original.lastIndexOf('\n', lo - 1) + 1;
  const nl = original.indexOf('\n', hi);
  const lineEnd = nl === -1 ? original.length : nl;
  const segment = original.slice(lineStart, lineEnd);
  const lowered = segment.toLowerCase();

  // Offset in `segment` of each code unit of `lowered`.
  const back = new Int32Array(lowered.length + 1);
  let at = 0;
  for (let i = 0; i < segment.length; ) {
    const cp = segment.codePointAt(i) ?? 0;
    const units = cp > 0xffff ? 2 : 1;
    const width = String.fromCodePoint(cp).toLowerCase().length;
    for (let k = 0; k < width && at + k < back.length; k++) back[at + k] = i;
    at += width;
    i += units;
  }
  if (at !== lowered.length) return [[0, end - start]];
  back[lowered.length] = segment.length;

  const urls: Array<[number, number]> = [];
  for (const m of lowered.matchAll(URL_IN_PURPOSE)) {
    if (m[1] === undefined) continue;
    const a = lineStart + back[m.index];
    const b = lineStart + back[m.index + m[0].length];
    if (b > a) urls.push([a, b]);
  }

  const spans: Array<[number, number]> = [];
  let u = 0;
  for (let i = start; i < end; i++) {
    while (u < urls.length && urls[u][1] <= from[i]) u++;
    if (u === urls.length) break;
    if (urls[u][0] >= to[i]) continue;
    const rel = i - start;
    const last = spans[spans.length - 1];
    if (last !== undefined && last[1] === rel) last[1] = rel + 1;
    else spans.push([rel, rel + 1]);
  }
  return spans;
}

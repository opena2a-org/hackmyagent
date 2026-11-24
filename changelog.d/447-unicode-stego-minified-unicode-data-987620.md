---
type: fixed
issue: 447
---
#### UNICODE-STEGO-001 no longer reports the Unicode tables in a minified XRegExp bundle (#447)

- `secure` reported a CRITICAL `Invisible Unicode Codepoints Detected` finding
  on Django's `admin/js/vendor/xregexp/xregexp.min.js`. XRegExp's category and
  script tables spell ranges such as `\u200B-\u200F` and `\uFE00-\uFE0F` as
  escapes, and the minifier writes them out as the characters themselves.
  In a minified script (`*.min.js`, or a line of 1000 characters or more),
  invisible code points that are all entries of a sorted range table (at
  least four ranges, every entry above the one before) are no longer reported
  by UNICODE-STEGO-001 or UNICODE-STEGO-004, and do not corroborate
  UNICODE-STEGO-002.
- A selector or tag-character payload, a run appended to a table, a bidi
  override in a comment, and the same table in a script that is not minified
  are still reported.

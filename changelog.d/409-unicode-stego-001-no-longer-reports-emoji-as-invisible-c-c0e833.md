---
type: fixed
issue: 409
---
#### UNICODE-STEGO-001 no longer reports emoji as invisible codepoints (#409)

- `secure` reported a HIGH `Invisible Unicode Codepoints Detected` finding on
  any JSON, YAML, TOML or source file that held a multi-person, profession,
  gender or colour-variant emoji such as U+1F9D1 U+200D U+1F680 (astronaut),
  because the zero-width joiner (U+200D) that builds those emoji was counted as
  a hidden character. A joiner between two emoji codepoints is no longer
  counted. A joiner or zero-width space between letters, digits or
  punctuation, or a run of joiners, is still reported.
- A text or emoji presentation selector (U+FE0E or U+FE0F) directly after an
  emoji such as U+25B6 (play button), U+2B50 (star) or U+00A9 (copyright) is no
  longer reported as a CRITICAL variation-selector finding. A variation
  selector after a letter, or a run of them after an emoji, is still reported.

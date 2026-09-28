---
type: fixed
issue: 609
---
`secure-openclaw --fix` no longer counts a confirmed fix under both `fixed` and `passed` (#609). Checks that fix what they found report `passed`, so the Checks line summed past its total (`7 total | 5 issues | 2 fixed | 2 passed`); `passed` now excludes fixed checks, on the text line, in `--json` and in the `--verbose` passed list, and the line reads `1 issue` for one. `secure-nemoclaw`'s Checks line gets the same singular.

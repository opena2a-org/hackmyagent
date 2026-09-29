# changelog.d

Each user-visible change is recorded as one file in this directory. The files
are added to `CHANGELOG.md` when a release is cut, and are deleted then.

Write the entry text to standard input:

```sh
node scripts/changelog.mjs new --type fixed --issue 761 < entry.md
```

`--type` is one of `added`, `changed`, `deprecated`, `removed`, `fixed`,
`security` or `known-issue`. Add `--breaking` for a breaking change.

Example file, `changelog.d/scoped-skill-not-found-3fa2c1.md`:

```markdown
---
type: fixed
issue: 761
---
- One or more sentences on what a user of the tool sees change, with the
  issue or PR reference (#761).
```

`node scripts/changelog.mjs preview --virtual` prints `CHANGELOG.md` with the
pending entries included.

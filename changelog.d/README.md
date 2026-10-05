# Changelog fragments

Each user-visible change to HackMyAgent is recorded as a fragment: one file in
this directory. New entries go in a fragment, never in `CHANGELOG.md`. When a
release is cut, the fragments are moved into [`CHANGELOG.md`](../CHANGELOG.md)
under the new version heading. Until then a merged fragment stays here, and
only the release process removes it. A change a user of the tool cannot
observe, such as a test, CI or refactoring change, needs no fragment.

## Write a fragment

From the repository root, pass the entry text to `new` on standard input. This
records a fixed entry for issue 761:

```sh
node scripts/changelog.mjs new --type fixed --issue 761 <<'EOF'
#### The title says what changed, in terms a user of the tool knows (#761)

- The text says what a user saw before and what they see now, and names
  the command or check it concerns.
EOF
```

What `new` prints (captured from this repository's `scripts/changelog.mjs`,
2026-09-29, on a branch named `fix/761-example`; the six hex characters are
random on each run):

```text
changelog.d/761-example-6a80ff.md
```

The file it wrote in the same run:

```markdown
---
type: fixed
issue: 761
---
#### The title says what changed, in terms a user of the tool knows (#761)

- The text says what a user saw before and what they see now, and names
  the command or check it concerns.
```

Commit that file with the change. The entry can also come from a file:
`node scripts/changelog.mjs new --type fixed < /tmp/entry.md`.

- `--type` is one of `added`, `changed`, `deprecated`, `removed`, `fixed`,
  `security` or `known-issue`. The release groups fragments under one heading
  per type, in that order, with `known-issue` under `Known issues`.
- `--issue` takes one or more issue or pull request numbers, separated by
  commas. They order the entries under their heading and are not printed, so
  the text carries its own reference, such as `(#761)`.
- `--breaking` marks a change that breaks existing use, such as a changed exit
  code or a changed `--json` field. A breaking or `removed` fragment makes the
  release raise at least the minor version before 1.0.0, and the major version
  from 1.0.0 on.
  A fix counts when it changes the exit code an invocation ends with, for
  example a run that exited 0 on a wrong result and now exits 1 or 2, or a flag
  combination that was accepted and is now refused. An exit code that only a
  timing race produced is not one a script can rely on, so a fix that removes
  it does not count.
- The file name starts with the last part of the current branch name when
  that part carries one of the entry's issue numbers, as `fix/761-example`
  does for issue 761, or when the entry names no issue. On any other branch
  it starts with the entry's first issue number and the words of its first
  line, so the entry is filed under its own issue and not under a branch
  named for something else. Six random hex characters follow. The entry's
  issue numbers are those of `--issue`, or without it the `#<number>`
  references in its first line. `--name <slug>` sets the first part.

The entry text is copied into `CHANGELOG.md` as written. Its headings are
level 4 (`####`) or lower, because the release places it under a level 3 type
heading. A long entry starts with `#### <title> (#<number>)`; a short one is a
`- ` bullet or a paragraph.

## Check and preview

`node scripts/changelog.mjs check` validates every fragment in this directory,
and `node scripts/changelog.mjs preview --virtual` prints `CHANGELOG.md` with
the pending fragments in place.

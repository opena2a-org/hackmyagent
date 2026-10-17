---
type: added
---
#### The one-text choice in `docs/chooser.json` carries an example for its command and its next command: `scan-text` on a committed pull request body, read from a file and from standard input, with the exit code and the captured output held to the build

- `test-fixtures/pr-body/pr-body.md` is a pull request body with an
  instruction-override line (TEXT-001, line 3) and an authority-claim line
  (TEXT-002, line 4). `scan-text pr-body.md` reports both as high and exits
  1; its output is in `docs/captures/one-text.txt`.
- `scan-text - --as pr-body --json < pr-body.md` reads the same file on
  standard input and exits 1; its `--json` output is in
  `docs/captures/one-text-next.txt`.
- An example whose command has the operand `-` names the fixture file it
  reads on standard input (`stdin`), and its sidecar and command show it as
  `< pr-body.md`. `scripts/chooser.mjs` refuses such an example without a
  `stdin` file, a `stdin` file on a command without the operand `-`, and a
  `stdin` path that leaves the fixture folder.
- A new normalizer, `json-version`, prints the `hackmyagentVersion` value of a
  `--json` run as `<version>`. It applies to runs with `--json` only, and the
  captures and sidecars of the six examples that were already there are
  unchanged.
- `attack`, `detect` and `scan`, and the next commands of `attack` and
  `detect`, still have no example.

---
type: added
---
#### `scan-soul` accepts `-f, --format <text|json>`

- `scan-soul --format json` was refused as an unknown option, while
  `secure` and `attack` accept it. It now prints what `scan-soul --json`
  prints and exits with the same code; `--format text` prints the default
  report. Any other value is refused before the scan with
  `Invalid format '<value>'. Use: text, json`, and `--json --format text` is
  refused as a contradiction, as it is on `secure` and `attack`.
  `scan-soul --help` lists the option.

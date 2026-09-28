---
type: fixed
issue: 648
---
#### `secure` refuses -l, -c and --aws-* where nothing reads them, and keeps the footer off refusals (#648)

- **`-l/--level` and `-c/--category` without `-b` exit 1.** Only the benchmark arms read them,
  so `secure <dir> -l L9` exited 0 with the ordinary report.
- **`-b ... -c <name>` checks the category before the scan.** An unknown category was caught
  only inside the report generator, after the scan had run and printed its header. The message
  and the category list are unchanged.
- **`--aws-account-id` and `--aws-region` with any format but asff exit 1.** They fill fields
  of the asff report and nothing else reads them.
- **The `Scanned with hackmyagent` footer follows a report only.** A pre-work refusal
  (`-b bogus`, `-l L9`, `--fail-below 200`) left the footer as the one line on stdout.
- `--json` with a different `--format` was already refused (#605) and is pinned by the same
  test file.

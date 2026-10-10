---
type: fixed
issue: 941
---
#### The ARP runtime help prints a runnable command when started by its directory, and on Windows (#941)

- `node dist/arp/cli --help` and `node dist/arp/cli/index --help` printed the
  bare path as the program (`.../dist/arp/cli <command> [options]`), which a
  shell refuses to run. The help now prints `node dist/arp/cli` or
  `node dist/arp/cli/index`, the line that was run. A `bin` shim is still
  named by itself.
- On Windows the help quoted the script path with POSIX single quotes, which
  cmd.exe does not accept. A path made only of ASCII letters and digits and
  the characters `_ @ + = : , . \ / -` is now printed bare, and any other
  path, such as one with a space, in double quotes.
- `--version` printed `arp-guard v<version>` while the help header read
  `ARP Guard v<version>`. Both now print `ARP Guard v<version>`.
- `telemetry --help` now also names
  `npx --package @opena2a/aim-sdk@<version> aim-arp telemetry <subcommand>`,
  which runs every telemetry subcommand except `register` from any directory.

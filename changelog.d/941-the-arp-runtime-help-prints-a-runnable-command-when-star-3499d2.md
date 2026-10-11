---
type: fixed
issue: 941
---
#### The ARP runtime help prints a runnable command when started by its directory, and on Windows (#941)

- Started by its directory or by the script path without its extension,
  `node dist/arp/cli --help` and `node dist/arp/cli/index --help` print the
  line that was run, `node dist/arp/cli` or `node dist/arp/cli/index`, as the
  program, where 0.33.2 printed `arp-guard <command> [options]`. A `bin` shim
  is named by itself.
- On Windows the script path in the help is printed bare when it is made only
  of ASCII letters and digits and the characters `_ @ + = : , . \ / -`, and
  in double quotes otherwise, such as a path with a space.
- `--version` printed `arp-guard v<version>` while the help header read
  `ARP Guard v<version>`. Both now print `ARP Guard v<version>`.
- `telemetry --help` now also names
  `npx --package @opena2a/aim-sdk@<version> aim-arp telemetry <subcommand>`,
  which runs every telemetry subcommand except `register` from any directory.

---
type: fixed
---
#### The ARP runtime help prints a command you can run

- The help of the ARP runtime program (`dist/arp/cli/index.js`) printed its
  usage and examples as `arp-guard <command>`, and its telemetry hints as
  `arp telemetry ...`. Neither is a binary that an install puts on PATH: the
  shell answered `command not found`, and on macOS `arp telemetry status`
  ran the system address-resolution tool instead.
- The usage line, the examples and every telemetry hint now print the command
  line that started the program, for example
  `node node_modules/hackmyagent/dist/arp/cli/index.js status`, so each
  printed line runs as shown.

---
type: fixed
issue: 1024
---
#### `secure --deep` and `red-team` replace more credential spellings, and the simulation lines name each file by its path (#1024)

- `secure --deep` sent these values in a scanned file to the probe executor
  as written, and `red-team` carried them into its report: a quoted value
  holding a quote character (`password: "it's-..."` or a JSON `\"`), a
  quoted password under 8 characters (`PASSWORD="abc"`), an unquoted value
  under a name such as `DB_PASS`, `SMTP_PASS` or `AUTH`, the part of an
  unquoted value after a `;` or a quote character (`password=h;...` kept
  everything after the `;`), a YAML block scalar under `password: |`, a
  `'password' => '...'` entry, the value after a `--password` flag, and an
  `Authorization` header value under 16 characters. Each is now replaced
  with a marker. Keys such as `bypass_mode`, `passthrough`, `author` and
  `authentication` are not read as credential names.
- The `[Simulation] ... NOT SIMULATED` and `[INFO] ... probes flagged` lines
  of `secure --deep` name each file by its path under the target, as
  `--json` does. Two files `big/SKILL.md` and `small/SKILL.md` printed as
  `SKILL.md` on both lines.
- The `--verbose` lines under `Artifacts` no longer head a `benign` label
  withheld because findings contradicted it with a note that the classifier
  over-flags benign input. That note now sits on the line of a withheld
  `malicious` or `suspicious` label.

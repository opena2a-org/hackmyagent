---
type: fixed
issue: 411
---
#### Documentation is no longer classified as an agent config, system prompt or credential file (#411)

- **`secure` and the other scans that run the semantic analyzers read a Markdown guide as
  documentation** when it contains a JSON example with `"agentType"`, or names
  `"capabilities"` and `"constraints"` anywhere in the text. Such a file was classified as an
  agent configuration and received the governance, prompt, scope and capability checks. An
  agent configuration is now recognized from the top-level keys of a JSON object, and JSON
  with comments or trailing commas is still accepted.
- **A file whose path merely contains `claude.md` is no longer a system prompt.**
  `docs/about-claude.md.backup` was classified as one. `CLAUDE.md`, `.cursorrules`,
  `.clinerules` (file or directory) and `.windsurfrules` are now matched by exact name. A
  system prompt is a file whose name starts with `system-prompt`, `system_prompt` or
  `systemprompt`, alone or followed by `-`, `_` or `.` and a suffix, such as
  `system-prompt.prod.md` or `system-prompt-v2.txt`. A backup copy (`.bak`, `.backup`,
  `.old`, `.orig` or a trailing `~`) is not one.
- **A Markdown page that documents a key format is no longer a credential file.** A key-shaped
  value in a `.md` file, such as the example access key id from the AWS documentation, now
  goes to the credential checks, which read Markdown as documentation, instead of marking the
  page as a place where credentials are expected.

---
type: fixed
issue: 471
breaking: true
---
#### Breaking: AST-SCOPE-001 reads a skill's Permissions list, so an unbounded grant in a SKILL.md is reported at its line (#471)

- A skill's `## Permissions` list contributed no capabilities, so
  AST-SCOPE-001 never fired from a skill: `- shell: *` in a SKILL.md was not
  reported, however broad. `secure` now reads the list and reports a grant
  that leaves its domain unbounded (`*`, `/`, `~`, `all`, or a root followed
  only by wildcards) at MEDIUM, at the grant's own line with a Verify command,
  with a fix that names a narrower value. It is HIGH when the skill's stated
  purpose does not involve that domain (`shell: *` in a skill that formats
  dates), and never CRITICAL from a declaration alone.
- A bounded grant, such as `filesystem: /var/log/*.log` or
  `network: api.example.com`, is read and not reported, and declaring it adds
  no governance finding. Four published skills with Permissions lists score
  the same as before.
- The list starts at a level 2 to 6 heading reading `Permissions`,
  `Permissions Required` or `Required Permissions` and ends at the next
  heading. Its items are `-`, `*`, `+` or numbered bullets, or table rows,
  outside fenced blocks, read as `domain: value` for the domains filesystem,
  shell, network, env, database and browser and their short forms. Other keys,
  such as `Note:`, `Contact:` or `token:`, are ignored and never echoed. A
  value ends at ` #` or ` (`, and a value such as `none` or `false` is not a
  grant.
- At most 100 grants are read per file. A longer list is reported at LOW at
  its first unread grant, with the number not read.
- A scan of a skill that declares an unbounded grant can score lower, and
  under `--fail-below` can exit 1 where it exited 0.

---
type: fixed
issue: 862
---
`secure -b oasb-1 --fix` and `secure -b oasb-2 --fix` now print the `Backup created:` line and the rollback command after the text report, as `secure --fix` does. Both benchmark reports previously wrote `.gitignore` and a `.hackmyagent-backup/` run directory without naming either.

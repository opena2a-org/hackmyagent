---
type: fixed
---
#### CRED-002, DEP-004 and GATEWAY-002 cite the line they matched, so they print a `Verify:` line

- These three critical findings named a file and no line, so the text report printed the file alone and no `Verify:` command, and `--json` carried no `line`. Each now records the line of what it matched, and the report prints `file:line` with `Verify: sed -n '<line>p' <file>`:
  - CRED-002 cites the field that holds the key in a JSON document (for example `"privateKey"` in `.opena2a/aim/identity.json`), or the `-----BEGIN ... PRIVATE KEY-----` header of a key file wherever it sits in the file. A key file with no PEM header, such as binary DER, still has no line.
  - DEP-004 cites the first `package.json` script that matched, for example the `preinstall` entry that pipes `curl` into `sh`.
  - GATEWAY-002 cites `security.websocketOrigins` when it is present and empty, else the `security` block it belongs in, else the `gateway` block. A gateway config with none of these has nothing to point at and still has no line. When `secure --fix` rewrites a gateway config, the line is taken from the rewritten file.
- Severities, messages and fixes are unchanged.

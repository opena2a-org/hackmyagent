---
type: fixed
issue: 1273
breaking: true
---
#### Breaking: `secure` source checks read .ts and .js files across the scanned tree, not only its top level (#1273)

- The 27 source checks that read .ts and .js files read them across the
  scanned tree, excluding node_modules, .git, hidden directories, dist and
  build; they no longer record not applicable, or pass, when the code sits
  below the top level. The checks are LOG-002, AUTH-003, PROC-004, NET-003,
  NET-004, API-001, API-003, API-004, SEC-004, IO-004, INJ-001 to INJ-004,
  RATE-002 to RATE-004, SESSION-001, SESSION-002, SESSION-004, ENCRYPT-001 to
  ENCRYPT-004, AUDIT-001, AUDIT-002 and AUDIT-004 (#1207).
- A package with `src/index.ts` calling `console.log(password)` read LOG-002
  not applicable and `secure --ci` exited 0; with an `eslint.config.js` at the
  top level, LOG-002 passed and `secure --ci` exited 0. LOG-002 now fails at
  high on `src/index.ts` line 1 and `secure --ci` exits 1 in both layouts. The
  same file at the top level gives the same record as before.
- Symbolic links are not followed, files more than 10 directory levels below
  the scanned directory are not read, and `--include-dist` does not add
  `dist/` to these checks. A directory the scan cannot list is reported by
  SCAN-UNREAD-001. The .json files that AUTH-003, SEC-004, RATE-003,
  SESSION-002, ENCRYPT-004 and AUDIT-002 also read are still read at the top
  level only.
- The not-applicable reason reads "No .ts or .js files in the scanned tree, so
  there is no source to inspect.", and for the six checks that also read .json
  "No .ts or .js files in the scanned tree and no .json files at the scanned
  root, so there is nothing to inspect."
- Findings that move, measured before and after the change on 22 trees: the
  five `test-fixtures/demo-agents` projects, the 12 benign, buggy and
  malicious corpus fixtures, an intentionally vulnerable test tree, this
  repository, the ai-trust and secretless repositories, and an empty
  directory. No score or exit code moved on any of them: apart from LOG-002,
  these records carry no file, so they are not scored. Each move below is the
  check's own record. Where the project type is outside a check's scope,
  `--json` did not show the not-applicable record and now shows the passed
  one, and a failed one is counted without being shown: the coverage line for
  `demo-agents/deploy-runbook-agent` reads 37 checks that reported an absent
  mitigation, where it read 23.
  - Not applicable to passed, on the seven trees whose code sits only below
    the top level (the five demo-agents projects and two corpus repositories):
    LOG-002, API-003, ENCRYPT-003, INJ-004, IO-004 and NET-004 on all seven,
    INJ-001 on four, INJ-003 on one.
  - Not applicable to failed, with no file, on the same seven: API-001,
    API-004, AUDIT-001, AUDIT-004, ENCRYPT-001, ENCRYPT-002, INJ-002, NET-003,
    PROC-004, RATE-002, RATE-004, SESSION-001 and SESSION-004 on all seven,
    INJ-003 on six, INJ-001 on three.
  - Failed to passed, where the mitigation sits below the top level: NET-003
    on five trees; API-001, API-004, AUDIT-001, AUDIT-004, ENCRYPT-002,
    INJ-003, PROC-004 and RATE-002 on three; AUDIT-002, ENCRYPT-004, INJ-001,
    INJ-002, RATE-003, RATE-004, SESSION-002 and SESSION-004 on two; AUTH-003,
    ENCRYPT-001 and SESSION-001 on one.
  - Passed to failed, with no file, where the pattern sits below the top
    level: API-003, NET-004 and SEC-004 on this repository and on secretless,
    ENCRYPT-003 on this repository.

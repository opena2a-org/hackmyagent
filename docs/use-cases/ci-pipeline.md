# Use Case: Add HMA to CI/CD

**Time:** 5 minutes
**Goal:** Run HMA security scans and red-team tests automatically on every push and pull request.

---

## Basic GitHub Actions workflow

Create `.github/workflows/agent-security.yml`:

```yaml
name: Agent Security
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"

      - name: Security scan
        run: npx hackmyagent secure --ci --format json > security-report.json

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.json
```

The `--ci` flag disables color output and interactive prompts. The `--format json` flag produces machine-readable output.

## Exit codes

HMA uses exit codes to signal scan results:

| Code | Meaning | CI behavior |
|------|---------|-------------|
| `0` | The target was measured, and no critical or high issue was found | Pipeline passes |
| `1` | The target was measured, and a critical or high issue was found | Pipeline fails |
| `2` | The target was **not measured** -- no result is reported | Pipeline fails |

Any critical or high finding causes exit code `1`, which fails the GitHub Actions step by default.

`--fail-below N` **adds** a score floor. It does not replace the default gate: a
benchmark whose rating is `Not Passing` or `Needs Improvement`, or whose OASB-2
conformance is `NONE`, exits 1 whether or not you pass the flag. Before 0.27.0
`--fail-below 0` silently switched that gate off, so a pipeline could print
`Rating: Not Passing` and go green.

Exit `2` means HMA could not look at the target, so it reports no score and no
risk level. Causes: the path or package does not exist, the endpoint under
`attack` was unreachable, no payload was answered, `attack --local` was used
(which contacts no agent), or a scan plugin failed. For `secure -b oasb-1`,
exit 2 also means the rating ladder could not be read: no scored L1 control
produced a result, the rating prints as `Not Assessed`, and the category
results are still printed. When nothing at all was measured there is no
compliance figure and `--fail-below` is not evaluated; a `--category` whose
L2 or L3 controls did produce results keeps its measured figure, and a
`--fail-below` breach over it exits 1. It is non-zero on purpose --
"I could not tell you" must not be read by a pipeline as "it is safe".

## JSON output format

The `--format json` output from this repository's `test-fixtures/insecure-library` (trimmed where marked `...`):

```
{
  "hackmyagentVersion": "0.33.2",
  "timestamp": "2026-10-05T06:11:23.153Z",
  "platform": "generic",
  "projectType": "library",
  "findings": [
    {
      "checkId": "PERM-001",
      "name": "Sensitive File Permissions",
      "description": "Sensitive files have overly permissive permissions",
      "category": "permissions",
      "severity": "high",
      "passed": false,
      "message": "Files with overly permissive permissions: .env",
      "file": ".env",
      "fixable": true,
      "fixed": false,
      "fix": "hackmyagent secure --fix",
      "manualFix": "chmod 600 .env",
      "details": {
        "files": [
          ".env"
        ]
      },
      "guidance": "Overly broad file permissions let any user on the system read sensitive config files that may contain credentials or API keys.",
      "attackClass": "NEMO-SANDBOX-ESCAPE",
      "redactionStatus": "clean",
      "redactedShapes": []
    },
    ...
  ],
  "allFindings": [
    ...
  ],
  "score": 58,
  "rawScore": 58,
  "scoreClamped": false,
  "maxScore": 100,
  "semanticAnalysis": {
    ...
  },
  "coverage": {
    ...
  },
  "verdict": "fail",
  "exitCode": 1,
  "measured": true,
  "counts": {
    "critical": 1,
    "high": 3,
    "medium": 1,
    "low": 1
  }
}
```

`exitCode` and `verdict` record the same result as the process exit code.

## SARIF output for GitHub Security tab

SARIF integrates findings directly into GitHub's Security tab:

```yaml
name: Agent Security
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"

      - name: Security scan (SARIF)
        run: npx hackmyagent secure --ci -f sarif -o results.sarif
        continue-on-error: true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

Findings appear under your repository's Security > Code scanning alerts.

## Red-team testing in CI

Add adversarial testing alongside static scans:

```yaml
      - name: Red team
        run: npx hackmyagent attack "$AGENT_ENDPOINT" --fail-on-vulnerable medium --format json > attack-report.json
        env:
          AGENT_ENDPOINT: ${{ secrets.AGENT_ENDPOINT }}
```

The `--fail-on-vulnerable medium` flag fails the step if any medium-or-higher vulnerabilities are found.

`attack` needs a running agent to test. It probes the endpoint before sending
any payload, and exits `2` without a score if the endpoint is unreachable or if
no payload is answered -- a suite that never arrived tells you nothing about the
agent, so it reports nothing.

Do not use `--local` as a CI gate. It generates payloads and checks that they
parse; it contacts no agent, so it has no behavior to score and always exits `2`.

## OASB benchmark compliance gate

Enforce a minimum security score using the OASB benchmark:

```yaml
      - name: OASB-1 compliance
        run: npx hackmyagent secure -b oasb-1 --fail-below 70 --ci
```

This fails the pipeline if the OASB-1 score drops below 70.

## Full workflow example

Combining all scan types in a single workflow:

```yaml
name: Agent Security
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"

      # Static security scan
      - name: Security scan
        run: npx hackmyagent secure --ci --format json > security-report.json

      # SARIF for GitHub Security tab
      - name: Security scan (SARIF)
        run: npx hackmyagent secure --ci -f sarif -o results.sarif
        continue-on-error: true

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      # Red team testing (needs a running agent; exits 2 if unreachable)
      - name: Red team
        run: npx hackmyagent attack "$AGENT_ENDPOINT" --fail-on-vulnerable medium
        env:
          AGENT_ENDPOINT: ${{ secrets.AGENT_ENDPOINT }}

      # OASB compliance
      - name: OASB-1 compliance
        run: npx hackmyagent secure -b oasb-1 --fail-below 70 --ci

      # Upload reports
      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: |
            security-report.json
            results.sarif
```

## Pre-commit hook

For local checks before each commit:

```bash
#!/bin/sh
# .git/hooks/pre-commit
npx hackmyagent secure --ci --ignore LOG-001,RATE-001
```

Make it executable:

```bash
chmod +x .git/hooks/pre-commit
```

The `--ignore` flag skips checks that are noisy during development (e.g., missing logging, missing rate limiting).

## Suppressing checks and excluding paths (`.hmaignore`)

Suppressing a **check** (`--ignore CRED-001`, or `!CRED-001` in `.hmaignore`)
changes what the report lists, not what it measures: it is still scored, still
in the verdict, still in the exit code, and named on a `Suppressed` line. Use
`--fail-below <score>` to let a build pass over findings you have accepted: a
threshold in your pipeline config is auditable, a missing finding is not.

Excluding a **path** (`test-fixtures/` in `.hmaignore`) is a scope statement:
those paths leave the score and the exit code, as if you had not scanned them.
Always disclosed on a `Scope` line and as `outOfScope` in `--json`.

Excluding **one check on one path** (`danger.py:NEMO-009 # canary fixture` in
`.hmaignore`) is the narrow form of the path rule, with the same scope
semantics: that one finding leaves the score and the exit code while every
other check still runs on the path. The trailing `# <reason>` is required on
this form. Any rule may carry `expires:<YYYY-MM-DD>` at the end of the line;
the rule is active through the named day (UTC), and from the next day the
line is reported as an error and its findings return to the report.

Every rule and its match count are disclosed under `hmaignore` in `--json`.
A line the parser cannot apply (a glob in a path rule, a missing reason, a
bad or lapsed `expires:` date) is never a silent no-op: it prints as a
`.hmaignore:<line>` error by default, appears in `hmaignore.errors`, and the
line is not applied. Errors never change the exit code: an inert line hides
nothing, so everything it would have covered is already in the score and the
exit code. To gate CI on a clean ignore file, test the `--json` document instead:
`hackmyagent secure --ci --json . | jq -e '.hmaignore.errors | length == 0'`.

---

## Tips

- Use `--ignore` to suppress known false positives in CI. List check IDs separated by commas.
- Use `--format json` and parse with `jq` for custom CI logic (e.g., only fail on specific categories).
- Combine with `npx hackmyagent secure --fix --dry-run --format json` to auto-generate fix suggestions in PR comments.

## Next steps

- [Scan your agent](scan-my-agent.md) interactively during development
- [Red-team your MCP servers](red-team-mcp.md) with adversarial payloads
- See the full [Security Checks Reference](../SECURITY_CHECKS.md) for all check IDs

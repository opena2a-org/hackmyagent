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

Exit `2` means HMA could not look at the target, so it reports no score and no
risk level. Causes: the path or package does not exist, the endpoint under
`attack` was unreachable, no payload was answered, `attack --local` was used
(which contacts no agent), or a scan plugin failed. It is non-zero on purpose --
"I could not tell you" must not be read by a pipeline as "it is safe".

## JSON output format

The `--format json` output structure:

```json
{
  "version": "0.10.1",
  "timestamp": "2026-03-15T10:30:00Z",
  "directory": "/home/runner/work/my-agent/my-agent",
  "summary": {
    "total": 310,
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 1,
    "passed": 156,
    "fixable": 3
  },
  "findings": [
    {
      "id": "CRED-001",
      "severity": "critical",
      "title": "Hardcoded API key in .env",
      "file": ".env",
      "line": 3,
      "description": "Found sk-proj-abc... in .env",
      "fix": "Move to a secrets manager or environment variable",
      "fixable": true
    }
  ]
}
```

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

---

## Tips

- Use `--ignore` to suppress known false positives in CI. List check IDs separated by commas.
- Use `--format json` and parse with `jq` for custom CI logic (e.g., only fail on specific categories).
- Combine with `npx hackmyagent secure --fix --dry-run --format json` to auto-generate fix suggestions in PR comments.

## Next steps

- [Scan your agent](scan-my-agent.md) interactively during development
- [Red-team your MCP servers](red-team-mcp.md) with adversarial payloads
- See the full [Security Checks Reference](../SECURITY_CHECKS.md) for all check IDs

# Use Case: Scan My AI Agent for Vulnerabilities

**Time:** 5 minutes
**Goal:** Find security issues in your AI agent setup and fix them.

---

## Step 1: Run the scan

```bash
npx hackmyagent secure
```

This runs all 187 checks against your current directory. No config files or setup needed.

**Expected output:**

```
HackMyAgent v0.10.1 -- Security Scanner

Scanning: /home/user/my-agent
Checks:  187 across 39 categories
Time:    2.4s

  CRITICAL  CRED-001  Hardcoded API key in .env
            Found: sk-proj-abc... in .env (line 3)
            Fix:   Move to a secrets manager or environment variable

  HIGH      MCP-003   MCP server bound to 0.0.0.0
            Found: stdio server in .cursor/mcp.json listening on all interfaces
            Fix:   Bind to 127.0.0.1

  HIGH      GIT-002   .gitignore missing sensitive patterns
            Found: .env, *.pem not in .gitignore
            Fix:   Add patterns to .gitignore

  MEDIUM    PERM-001  Overly permissive file: config.json (0644)
            Fix:   Set to 0600

  MEDIUM    LOG-001   No audit logging configured
            Fix:   Add structured logging for agent actions

  LOW       PROMPT-002  No system prompt hardening detected
            Fix:   Add instruction boundaries to system prompt

Summary: 1 critical, 2 high, 2 medium, 1 low
         3 auto-fixable (run with --fix)

Exit code: 1 (critical/high issues found)
```

## Step 2: Understand severity levels

| Severity | Meaning | Action |
|----------|---------|--------|
| CRITICAL | Actively exploitable. Credentials exposed, RCE vectors present. | Fix immediately. |
| HIGH | Significant risk. Misconfigured services, missing access controls. | Fix before deployment. |
| MEDIUM | Defense-in-depth gaps. Missing logging, weak permissions. | Fix during next sprint. |
| LOW | Hardening recommendations. Best practices not yet applied. | Address when convenient. |

The exit code is `1` if any critical or high issues are found, `0` if clean.

## Step 3: Preview fixes (dry run)

Before applying changes, see what HMA would do:

```bash
npx hackmyagent secure --fix --dry-run
```

**Expected output:**

```
HackMyAgent v0.10.1 -- Security Scanner (dry run)

Scanning: /home/user/my-agent
Checks:  187 across 39 categories

  CRITICAL  CRED-001  Hardcoded API key in .env
            Would fix: Replace sk-proj-abc... with ${OPENAI_API_KEY}

  HIGH      GIT-002   .gitignore missing sensitive patterns
            Would fix: Append .env, *.pem, *.key to .gitignore

  MEDIUM    PERM-001  Overly permissive file: config.json (0644)
            Would fix: chmod 0600 config.json

Dry run complete. 3 fixes would be applied.
Run without --dry-run to apply.
```

No files are modified during a dry run.

## Step 4: Apply fixes

```bash
npx hackmyagent secure --fix
```

**Expected output:**

```
HackMyAgent v0.10.1 -- Security Scanner

Scanning: /home/user/my-agent
Checks:  187 across 39 categories

  FIXED     CRED-001  Replaced hardcoded key with ${OPENAI_API_KEY} in .env
            Backup: .hackmyagent-backup/.env.1710504000

  FIXED     GIT-002   Added .env, *.pem, *.key to .gitignore
            Backup: .hackmyagent-backup/.gitignore.1710504000

  FIXED     PERM-001  Set config.json permissions to 0600
            Backup: .hackmyagent-backup/config.json.1710504000

  HIGH      MCP-003   MCP server bound to 0.0.0.0
            (manual fix required -- update server config)

Summary: 3 fixed, 1 remaining (manual)
Backups saved to .hackmyagent-backup/
```

All changes are backed up automatically. To undo:

```bash
npx hackmyagent rollback
```

## Step 5: Verify

Run the scan again to confirm:

```bash
npx hackmyagent secure
```

A clean scan exits with code `0` and shows no critical or high findings.

---

## Tips

- Use `--verbose` to see all 187 checks, including ones that passed.
- Use `--ignore CRED-001,LOG-001` to skip specific checks (e.g., known false positives).
- Use `--json` to get machine-readable output for scripting.
- Add `--ci` for non-interactive mode (no color, no prompts).

## Next steps

- [Red-team your MCP servers](red-team-mcp.md) with adversarial payloads
- [Add HMA to your CI/CD pipeline](ci-pipeline.md)
- See the full [Security Checks Reference](../SECURITY_CHECKS.md) for all 187 checks

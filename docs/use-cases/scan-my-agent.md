# Use Case: Scan My AI Agent for Vulnerabilities

**Time:** 5 minutes
**Goal:** Find security issues in your AI agent setup and fix them.

---

## Step 1: Run the scan

```bash
npx hackmyagent secure
```

This runs all 320 static checks against your current directory. No config files or setup needed.

**Output** from this repository's `test-fixtures/insecure-library` (trimmed where marked `...`; your findings depend on your project):

```
Scanning .../insecure-library...

Discovering assembly components...

  insecure-library-example  v1.0.0 · library · 3 files analyzed
  1 critical issue found

  Security  ━━━━━━━━━━━━━━━━━━━━ 58/100

  ── Observations ────────────────────────────────────────────
  Surfaces    library · 3 semantic artifacts · all 3 artifacts reached 0-2 of 7 analyzer families
  Checks      320 static declared · 63 of 63 check groups ran · 3 unreachable · 3 semantic (NanoMind AST, 0-2 of 7 analyzer families) · 4 files read by static checks
  Coverage    17 of 25 categories examined · 8 unexamined (read no file) · 36 checks reported an absent mitigation (not shown)
  Unexamined  A2A, capabilities, governance, heartbeat, lifecycle, MCP, prompt, skill
  Categories  credentials (2 high) · sandbox (1 high) · supply-chain (1 medium) · git hygiene (1 critical) · 13 others clear
  Verdict     Not safe to ship. .env Not Ignored in .env + 5 more. Fix before using in production.


  ── Findings ────────────────────────────────────────────────
  1 critical  3 high  1 medium  1 low

  │ CRITICAL  .env Not Ignored
  │ .env
  │ .env contains API keys or secrets. Without .gitignore protection, a single git add . can expose all credentials in your repository history.
  │ →  hackmyagent secure --fix

  │ HIGH  Password embedded in URL
  │ .env:4
  │ URL-embedded credentials are logged by proxies, shell history, and process listings. They bypass .env file protections and are easily leaked in stack traces.
  │ Verify: sed -n '4p' .../insecure-library/.env
  │ Fix: npx opena2a-cli protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.
  │ ...

  │ HIGH  Hardcoded secret in config
  │ .env:5
  │ .env files with hardcoded secrets should be gitignored. If this file is committed, the secret is exposed in version control history.
  │ Verify: sed -n '5p' .../insecure-library/.env
  │ Fix: Ensure .env is in .gitignore and rotate this credential.

  │ LOW  Incomplete .gitignore
  │ .gitignore
  │ No committable files match the missing patterns yet, but adding them now (.env, secrets.json, *.pem, *.key) means a future key or secrets file is never committed by accident.
  │ →  hackmyagent secure --fix

  │ HIGH  Sensitive File Permissions
  │ .env
  │ Overly broad file permissions let any user on the system read sensitive config files that may contain credentials or API keys.
  │ →  hackmyagent secure --fix

  │ MEDIUM  Dependency Lock File
  │ package-lock.json
  │ Without a lock file, npm install can resolve to different package versions on different machines, including versions with known vulnerabilities or supply-chain backdoors.

  Path forward: 58 -> 97 by fixing 1 critical + 3 high

  ── Next Steps ─────────────────────────────────────────────────
  Protect credentials:  npx opena2a-cli protect .
  Auto-fix all issues:  hackmyagent secure . --fix
  AI analysis:          hackmyagent check . --nanomind  (attack vectors + targeted remediation)
  All commands:         hackmyagent --help
  opena2a is a separate CLI — install with: npm i -g opena2a-cli

  Scanned with hackmyagent v0.33.2
```

The scan exits `1` here because it found critical and high issues.

## Step 2: Understand severity levels

| Severity | Meaning | Action |
|----------|---------|--------|
| CRITICAL | Actively exploitable. Credentials exposed, RCE vectors present. | Fix immediately. |
| HIGH | Significant risk. Misconfigured services, missing access controls. | Fix before deployment. |
| MEDIUM | Defense-in-depth gaps. Missing logging, weak permissions. | Fix during next sprint. |
| LOW | Hardening recommendations. Best practices not yet applied. | Address when convenient. |

The exit code is `1` if any critical or high issues are found, `0` if clean, and `2` if the scan could not examine everything it found, so it reports no pass.

## Step 3: Preview fixes (dry run)

Before applying changes, see what HMA would do:

```bash
npx hackmyagent secure --fix --dry-run
```

**Output** on a copy of the same fixture (trimmed where marked `...`):

```
Scanning .../insecure-library (dry-run)...

Discovering assembly components...

  insecure-library-example  v1.0.0 · library · 3 files analyzed
  1 critical issue found

  Security  ━━━━━━━━━━━━━━━━━━━━ 58/100

  ...

  Dry run complete: 3 issues auto-fixable. Run without --dry-run to apply.
  No changes were made.

  Scanned with hackmyagent v0.33.2
```

The report above the cut is the one Step 1 shows. The three findings there marked `→  hackmyagent secure --fix` are the three the dry run counts.

No files are modified during a dry run.

## Step 4: Apply fixes

```bash
npx hackmyagent secure --fix
```

**Abbreviated sample; your output will differ:**

```
  FIXED     CRED-001  Replaced hardcoded key with ${OPENAI_API_KEY} in .env
            Backup: .hackmyagent-backup/.env.1710504000

  FIXED     GIT-002   Added .env, *.pem, *.key to .gitignore
            Backup: .hackmyagent-backup/.gitignore.1710504000

  FIXED     PERM-001  Set config.json permissions to 0600
            Backup: .hackmyagent-backup/config.json.1710504000

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

- Use `--verbose` to see all 320 static checks, including ones that passed.
- Use `--ignore CRED-001,LOG-001` to skip specific checks (e.g., known false positives).
- Use `--json` to get machine-readable output for scripting.
- Add `--ci` for non-interactive mode (no color, no prompts).

## Next steps

- [Red-team your MCP servers](red-team-mcp.md) with adversarial payloads
- [Add HMA to your CI/CD pipeline](ci-pipeline.md)
- See the full [Security Checks Reference](../SECURITY_CHECKS.md) for all 320 static checks

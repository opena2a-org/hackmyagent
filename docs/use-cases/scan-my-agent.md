# Use Case: Scan My AI Agent for Vulnerabilities

**Time:** 5 minutes
**Goal:** Find security issues in your AI agent setup and fix them.

---

## Step 1: Run the scan

```bash
npx hackmyagent secure
```

This runs every static check against your current directory, plus the semantic pass over the agent artifacts it finds. No config files or setup needed. `npx hackmyagent check-metadata` prints the current check counts.

**Example output**, captured from a real run on a small MCP project that has a hardcoded key in `config.json` and a filesystem server granted `/`. Lines marked `...` are abridged:

```
Scanning /home/user/my-agent...

  my-agent  v1.0.0 · mcp · 3 files analyzed
  3 critical issues found

  Security  ━━━━━━━━━━━━━━━━━━━━ 53/100

  ── Observations ────────────────────────────────────────────
  ...
  Categories  credentials (2 critical) · MCP (1 critical) · sandbox (1 medium) · supply-chain (1 medium) · git hygiene (1 low) · 14 others clear
  Verdict     Not safe to ship. Exposed Credential in config.json:3 + 5 more. Fix before using in production.

  ── Findings ────────────────────────────────────────────────
  3 critical  2 medium  1 low

  │ CRITICAL  Exposed Credential
  │ config.json:3
  │ Replaces hardcoded credentials with ${ENV_VAR} references. Store actual values in your .env file, which should be in .gitignore.
  │ Verify: sed -n '3p' /home/user/my-agent/config.json
  │ →  hackmyagent secure --fix

  ...

  │ LOW  Incomplete .gitignore
  │ .gitignore
  │ No committable files match the missing patterns yet, but adding them now (.env, secrets.json, *.pem, *.key) means a future key or secrets file is never committed by accident.
  │ →  hackmyagent secure --fix

  │ CRITICAL  Overprivileged MCP server scope
  │ .cursor/mcp.json:5
  │ Overprivileged filesystem access allows the agent (or an attacker via prompt injection) to read sensitive files like SSH keys, credentials, and system configs.
  │ Verify: sed -n '5p' /home/user/my-agent/.cursor/mcp.json
  │ Fix: Scope "files" to the project directory: replace "/" with "./" or a specific subdirectory.

  ...

  Path forward: 53 -> 98 by fixing 3 critical
```

Each finding names its file, and where the evidence sits on a line, the line and a `Verify:` command that prints it. Each one also says how to fix it: with `--fix` (Step 4) or by the edit its `Fix:` line names.

## Step 2: Understand severity levels

| Severity | Meaning | Action |
|----------|---------|--------|
| CRITICAL | Actively exploitable. Credentials exposed, RCE vectors present. | Fix immediately. |
| HIGH | Significant risk. Misconfigured services, missing access controls. | Fix before deployment. |
| MEDIUM | Defense-in-depth gaps. Missing logging, weak permissions. | Fix during next sprint. |
| LOW | Hardening recommendations. Best practices not yet applied. | Address when convenient. |

The exit code is `1` if any critical or high issues are found and `0` when none are. This run exits `1`.

## Step 3: Preview fixes (dry run)

Before applying changes, see what HMA would do:

```bash
npx hackmyagent secure --fix --dry-run
```

**Example output** from the same project (abridged):

```
Scanning /home/user/my-agent (dry-run)...

  my-agent  v1.0.0 · mcp · 3 files analyzed
  3 critical issues found

  Security  ━━━━━━━━━━━━━━━━━━━━ 53/100
  ...
  Dry run complete: 2 issues auto-fixable. Run without --dry-run to apply.
  No changes were made.
```

The report is the one from Step 1. The closing lines say how many findings `--fix` would change.

No files are modified during a dry run.

## Step 4: Apply fixes

```bash
npx hackmyagent secure --fix
```

**Example output** from the same project (abridged; the backup directory name carries the run's timestamp):

```
Scanning /home/user/my-agent...
Verifying applied fixes...

  my-agent  v1.0.0 · mcp · 4 files analyzed
  3 critical issues found

  Security  ━━━━━━━━━━━━━━━━━━━━ 55/100
  Live tree: 69/100 — the 14-point difference is 2 findings inside the backup this run created at /home/user/my-agent/.hackmyagent-backup/2026-09-28-075235539-000-0e2eba50
  Those are the pre-fix copies, kept so `hackmyagent rollback` can undo this run. Rotate what was exposed, then delete that directory once you no longer need to roll back.
  ...
Fixed 2 issues (2 verified):
  ✓✓ [CRED-001] config.json:3 - Exposed Credential
  ✓✓ [GIT-002] .gitignore - Incomplete .gitignore
3 remaining issues have fix guidance. Run `hackmyagent fix-all` to apply all available fixes.
Backup created: /home/user/my-agent/.hackmyagent-backup/2026-09-28-075235539-000-0e2eba50
Something wrong? Run `hackmyagent rollback .` to undo all changes.
```

After this run `config.json:3` reads `"openaiApiKey": "${OPENAI_API_KEY}"`, and `.gitignore` has gained `.env`, `secrets.json`, `*.pem` and `*.key`. The overprivileged MCP scope is left to you; its `Fix:` line names the edit. The key was on disk in plaintext, so rotate it. Until you delete the backup directory, scans also report the pre-fix copies inside it, and the report names that directory.

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

- Use `--verbose` to see every check, including the ones that passed.
- Use `--ignore CRED-001,LOG-001` to skip specific checks (e.g., known false positives).
- Use `--json` to get machine-readable output for scripting.
- Add `--ci` in CI jobs: it suppresses interactive prompts and does not change the exit code.

## Next steps

- [Red-team your MCP servers](red-team-mcp.md) with adversarial payloads
- [Add HMA to your CI/CD pipeline](ci-pipeline.md)
- See the full [Security Checks Reference](../SECURITY_CHECKS.md) for the static checks

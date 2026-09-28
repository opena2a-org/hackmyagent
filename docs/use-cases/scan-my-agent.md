# Use Case: Scan My AI Agent for Vulnerabilities

**Time:** 5 minutes
**Goal:** Find security issues in your AI agent setup and fix them.

---

## Step 1: Run the scan

```bash
npx hackmyagent secure
```

This runs the static check suite and the semantic pass against your current directory. No config files or setup needed. The report's `Checks` line states how many checks were declared and how many ran.

**Example output** from hackmyagent 0.33.2, on a project with an OpenAI key in `.env` and in `config.json` and a filesystem MCP server granted `/` in `.cursor/mcp.json`. `[...]` marks omitted lines; your findings depend on your files:

```
  my-agent  v1.0.0 · library · 3 files analyzed
  7 critical issues found

  Security  ━━━━━━━━━━━━━━━━━━━━ 25/100

  ── Observations ────────────────────────────────────────────
  Surfaces    library · 3 semantic artifacts · all 3 artifacts reached 0-2 of 7 analyzer families
  Checks      320 static declared · 63 of 63 check groups ran · 3 unreachable · 3 semantic (NanoMind AST, 0-2 of 7 analyzer families) · 5 files read by static checks
  Coverage    18 of 25 categories examined · 7 unexamined (read no file) · 21 checks reported an absent mitigation (not shown)
  Unexamined  A2A, capabilities, governance, heartbeat, prompt, sandbox-escape, skill
  Categories  credentials (5 critical) · MCP (1 critical) · sandbox (1 high) · supply-chain (1 medium) · git hygiene (1 critical) · 13 others clear
  Verdict     Not safe to ship. Exposed Credential in config.json:1 + 10 more. Fix before using in production.

  ── Findings ────────────────────────────────────────────────
  7 critical  1 high  2 medium  1 low

  │ CRITICAL  Exposed Credential
  │ config.json:1
  │ Replaces hardcoded credentials with ${ENV_VAR} references. Store actual values in your .env file, which should be in .gitignore.
  │ Verify: sed -n '1p' /home/user/my-agent/config.json
  │ →  hackmyagent secure --fix
  │ + 1 more critical in config.json  (run with --verbose to see all)

  │ CRITICAL  .env Not Ignored
  │ .env
  │ .env contains API keys or secrets. Without .gitignore protection, a single git add . can expose all credentials in your repository history.
  │ →  hackmyagent secure --fix
  [...]
  │ CRITICAL  Overprivileged MCP server scope
  │ .cursor/mcp.json:1
  │ Overprivileged filesystem access allows the agent (or an attacker via prompt injection) to read sensitive files like SSH keys, credentials, and system configs.
  │ Verify: sed -n '1p' /home/user/my-agent/.cursor/mcp.json
  │ Fix: Scope "filesystem" to the project directory: replace "/" with "./" or a specific subdirectory.
  [...]
  Path forward: 25 -> 100 by fixing 7 critical + 1 high

  ── Next Steps ─────────────────────────────────────────────────
  Protect credentials:  npx opena2a-cli protect .
  Audit MCP servers:    npx opena2a-cli mcp audit  (run from project dir)
  Auto-fix all issues:  hackmyagent secure . --fix
  AI analysis:          hackmyagent check . --nanomind  (attack vectors + targeted remediation)
  All commands:         hackmyagent --help
  opena2a is a separate CLI — install with: npm i -g opena2a-cli
```

The first run also downloads the local analysis model (5.5 MB) before the report.

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

**Example output** (same project, excerpt):

```
  my-agent  v1.0.0 · library · 3 files analyzed
  7 critical issues found

  Security  ━━━━━━━━━━━━━━━━━━━━ 25/100
  [...]
  Dry run complete: 4 issues auto-fixable. Run without --dry-run to apply.
  No changes were made.
```

The report lists the same findings as Step 1, followed by the number of findings `--fix` would change. No files are modified during a dry run.

## Step 4: Apply fixes

```bash
npx hackmyagent secure --fix
```

**Example output** (same project, excerpt):

```
  my-agent  v1.0.0 · library · 4 files analyzed
  8 critical issues found

  Security  ━━━━━━━━━━━━━━━━━━━━ 22/100
  Live tree: 46/100 — the 24-point difference is 5 findings inside the backup this run created at /home/user/my-agent/.hackmyagent-backup/2026-09-28-074835518-000-228c9081
  Those are the pre-fix copies, kept so `hackmyagent rollback` can undo this run. Rotate what was exposed, then delete that directory once you no longer need to roll back.
  [...]
Fixed 3 issues (3 verified):
  ✓✓ [CRED-001] config.json:1 - Exposed Credential
  ✓✓ [PERM-001] .env - Sensitive File Permissions
    → Changed permissions to 600
  ✓✓ [GIT-002] .gitignore - Incomplete .gitignore

Backup created: /home/user/my-agent/.hackmyagent-backup/2026-09-28-074835518-000-228c9081
Something wrong? Run `hackmyagent rollback .` to undo all changes.
```

`--fix` changed what it can change safely: the key in `config.json` became an environment variable reference, `.env` was restricted to its owner, and the missing patterns were added to `.gitignore`. The rest is yours to do: the key in `.env` is where values belong, so rotate it and move it to a secrets manager, and narrow the MCP server's filesystem scope.

The score after a fix can be lower than before it. The backup holds the pre-fix copies of the files `--fix` changed, including the plaintext key, and the next scan reads them. The `Live tree` line gives the score without them.

All changes are backed up automatically. To undo:

```bash
npx hackmyagent rollback
```

## Step 5: Verify

Run the scan again to confirm:

```bash
npx hackmyagent secure
```

Once the remaining credentials are rotated and removed, and the backup directory is deleted after you no longer need to roll back, a clean scan exits with code `0` and shows no critical or high findings.

---

## Tips

- Use `--verbose` to show all checks, including the ones that passed.
- Use `--ignore CRED-001,GIT-002` to leave specific checks out of the findings list. Suppressed checks are still scored and still set the exit code.
- Use `--json` to get machine-readable output for scripting.
- Add `--ci` in pipelines: it suppresses interactive prompts and disables contribution. It does not change the exit code.

## Next steps

- [Red-team your MCP servers](red-team-mcp.md) with adversarial payloads
- [Add HMA to your CI/CD pipeline](ci-pipeline.md)
- See the full [Security Checks Reference](../SECURITY_CHECKS.md) for every check ID

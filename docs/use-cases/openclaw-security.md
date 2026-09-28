# Use Case: Secure My OpenClaw Installation

**Time:** 10 minutes
**Goal:** Run OpenClaw-specific security checks, detect known CVEs, scan for ClawHavoc IOCs, and auto-remediate.

---

## Background

HMA includes checks specifically for [OpenClaw](https://github.com/open-claw/open-claw) installations. These cover gateway configuration, skills, heartbeat files, config files, supply chain, and known CVEs. Six of the findings led to [upstream PRs merged into OpenClaw](https://opena2a.org/blogs/securing-openclaw-6-prs-merged).

## Step 1: Run the scan

From your OpenClaw project directory:

```bash
npx hackmyagent secure
```

HMA detects an OpenClaw project by the presence of `openclaw.json`, `.openclaw/`, `.moltbot/`, `.clawdbot/`, `SKILL.md` or `HEARTBEAT.md`, and runs the OpenClaw checks as part of `secure`. `hackmyagent secure-openclaw` is the focused variant for an installation directory (default `~/.openclaw`).

**Example output** from hackmyagent 0.33.2, on a project whose `package.json` pins `openclaw` 2026.1.20 and whose `openclaw.json` binds the gateway to `0.0.0.0` with a plaintext token, approvals disabled and sandbox disabled. `[...]` marks omitted lines:

```
  openclaw-project  v1.0.0 · openclaw · 3 files analyzed
  7 critical issues found

  Security  ━━━━━━━━━━━━━━━━━━━━ 15/100
  [...]
  Verdict     Not safe to ship. Bound to 0.0.0.0 in openclaw.json + 19 more. Fix before using in production.

  ── Findings ────────────────────────────────────────────────
  7 critical  5 high  7 medium  1 low

  │ CRITICAL  Bound to 0.0.0.0
  │ openclaw.json
  │ Binding to 0.0.0.0 exposes the gateway to all network interfaces. Use 127.0.0.1 for local-only access unless remote access is explicitly needed with proper authentication.
  │ →  hackmyagent secure-openclaw --fix

  │ CRITICAL  Missing WebSocket Origin Validation
  │ openclaw.json
  │ Without origin validation, any website can connect to the gateway via WebSocket (GHSA-g8p2). This enables cross-origin command execution attacks.
  │ Fix: Add security.websocketOrigins: ["http://localhost:3000"] to the gateway config

  │ CRITICAL  Token Exposed in Config
  │ openclaw.json
  │ Plaintext tokens in config files are exposed to anyone with repo access. Use environment variable references so credentials stay outside version control.
  │ →  hackmyagent secure-openclaw --fix

  │ CRITICAL  Approval Confirmations Disabled
  │ openclaw.json
  │ Without approval confirmations, commands execute immediately without user review. This removes the last line of defense against malicious or accidental destructive operations.
  │ →  hackmyagent secure-openclaw --fix

  │ CRITICAL  Sandbox Disabled
  │ openclaw.json
  │ Without sandbox isolation, executed code has full system access including filesystem, network, and process control. Sandbox mode limits the blast radius of malicious or buggy code.
  │ →  hackmyagent secure-openclaw --fix
  │ + 1 more critical in openclaw.json  (run with --verbose to see all)
  [...]
  │ CRITICAL  CVE-2026-25253: WebSocket Hijacking RCE
  │ package.json
  │ CVE-2026-25253 (CVSS 8.8) enables WebSocket hijacking for remote code execution. Upgrade to v2026.1.29 or later which includes the fix.
  │ Fix: npm install openclaw@latest

  + 9 more findings (CVE-2026-25253: WebSocket Hijacking RCE, CVE-2026-24763: Docker PATH Command Injection)  (run with --verbose to see all)

  Path forward: 15 -> 100 by fixing 7 critical + 5 high
```

## Step 2: CVE detection

HMA reads the `openclaw` (or `@openclaw/core`) version from `package.json` and flags these known vulnerabilities when it is older than 2026.1.29:

| CVE | Check | Severity | Description |
|-----|-------|----------|-------------|
| CVE-2026-25253 | CVE-001 | Critical | WebSocket hijacking RCE |
| CVE-2026-24763 | CVE-004 | Critical | Docker PATH command injection |
| CVE-2026-25157 | CVE-003 | High | OS command injection via SSH path |

For details on CVE-2026-25253, see the [disclosure blog post](https://opena2a.org/blogs/cve-2026-25253-openclaw-rce).

**Upgrade to fix all CVEs:**

```bash
npm install openclaw@latest
```

Then re-run the scan to confirm the CVEs are resolved.

## Step 3: ClawHavoc IOC scanning

HMA checks for indicators of compromise (IOCs) associated with the ClawHavoc campaign, a set of attacks targeting OpenClaw installations discovered in early 2026:

| Check | Severity | Indicator |
|-------|----------|-----------|
| SUPPLY-005 | Critical | A known ClawHavoc C2 IP address |
| SUPPLY-006 | Critical | A known ClawHavoc malware filename |
| SUPPLY-007 | High | A ClickFix-style instruction pattern |

## Step 4: Preview and apply fixes

Preview what auto-fix would change:

```bash
npx hackmyagent secure --fix --dry-run
```

**Example output** (same project, excerpt):

```
  openclaw-project  v1.0.0 · openclaw · 3 files analyzed
  7 critical issues found

  Security  ━━━━━━━━━━━━━━━━━━━━ 15/100
  [...]
  Dry run complete: 7 issues auto-fixable. Run without --dry-run to apply.
  No changes were made.
```

Apply the fixes:

```bash
npx hackmyagent secure --fix
```

**Example output** (same project, excerpt):

```
  openclaw-project  v1.0.0 · openclaw · 3 files analyzed
  3 critical issues found

  Security  ━━━━━━━━━━━━━━━━━━━━ 32/100
  Live tree: 35/100 — the 3-point difference is 1 finding inside the backup this run created at /home/user/openclaw-project/.hackmyagent-backup/2026-09-28-075030549-000-eae53fbb
  Those are the pre-fix copies, kept so `hackmyagent rollback` can undo this run. Rotate what was exposed, then delete that directory once you no longer need to roll back.
  [...]
Fixed 6 issues (6 verified):
  ✓✓ [GIT-002] .gitignore - Incomplete .gitignore
  ✓✓ [SKILL-001] skills/data-fetcher/SKILL.md - Unsigned Skill
    → Added SHA-256 signature block to skill file
  ✓✓ [GATEWAY-001] openclaw.json - Bound to 0.0.0.0
    → Changed gateway.host from 0.0.0.0 to 127.0.0.1
  ✓✓ [GATEWAY-003] openclaw.json - Token Exposed in Config
    → Replaced plaintext token with ${OPENCLAW_AUTH_TOKEN} env var reference. Set OPENCLAW_AUTH_TOKEN in your environment.
  ✓✓ [GATEWAY-004] openclaw.json - Approval Confirmations Disabled
    → Enabled approval confirmations for command execution
  ✓✓ [GATEWAY-005] openclaw.json - Sandbox Disabled
    → Enabled sandbox mode for isolated code execution

Backup created: /home/user/openclaw-project/.hackmyagent-backup/2026-09-28-075030549-000-eae53fbb
Something wrong? Run `hackmyagent rollback .` to undo all changes.
```

The CVE findings need the `openclaw` upgrade from Step 2, and the remaining findings carry their own `Fix:` lines. The `Live tree` line is the score without the pre-fix copies kept in the backup, which still hold the plaintext token.

## Step 5: Verify

```bash
npx hackmyagent secure
```

After upgrading OpenClaw and applying fixes, a clean scan exits with code `0`.

---

## Related resources

- [Securing OpenClaw: 6 PRs Merged Upstream](https://opena2a.org/blogs/securing-openclaw-6-prs-merged) -- details on the security improvements contributed to OpenClaw
- [CVE-2026-25253: OpenClaw WebSocket RCE](https://opena2a.org/blogs/cve-2026-25253-openclaw-rce) -- full disclosure and technical analysis

## Next steps

- [Red-team your MCP servers](red-team-mcp.md) with adversarial payloads
- [Add HMA to your CI/CD pipeline](ci-pipeline.md)
- See the full [Security Checks Reference](../SECURITY_CHECKS.md) for all check IDs

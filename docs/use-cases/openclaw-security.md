# Use Case: Secure My OpenClaw Installation

**Time:** 10 minutes
**Goal:** Run OpenClaw-specific security checks, detect known CVEs, scan for ClawHavoc IOCs, and auto-remediate.

---

## Background

HMA includes checks specifically for [OpenClaw](https://github.com/open-claw/open-claw) installations. They cover gateway configuration (`GATEWAY-*`), known OpenClaw CVEs (`CVE-*`), skill security, credential exposure and ClawHavoc indicators of compromise. Six of the findings led to [upstream PRs merged into OpenClaw](https://opena2a.org/blogs/securing-openclaw-6-prs-merged).

## Step 1: Run the scan

From your OpenClaw project directory:

```bash
npx hackmyagent secure
```

HMA reads the OpenClaw configuration file (`openclaw.json`, or `.openclaw/config.json`) for the gateway checks, and the `openclaw` version in `package.json` for the CVE checks. They run alongside the rest of the static suite; `npx hackmyagent check-metadata` prints the current check counts.

**Example output**, captured from a real run on a project that pins `openclaw` 2026.1.15, binds the gateway to `0.0.0.0`, keeps its auth token in `openclaw.json`, and disables approvals and the sandbox. Lines marked `...` are abridged:

```
Scanning /home/user/openclaw-project...
  ...
  openclaw-project  v1.0.0 · openclaw · 3 files analyzed
  7 critical issues found

  Security  ━━━━━━━━━━━━━━━━━━━━ 14/100

  ── Observations ────────────────────────────────────────────
  ...
  Categories  credentials (1 critical) · network (4 critical) · prompt (3 high) · supply-chain (4 medium) · skill (2 medium) · CVE (2 critical) · config (1 high) · git hygiene (1 low) · 9 others clear
  Verdict     Not safe to ship. Bound to 0.0.0.0 in openclaw.json + 20 more. Fix before using in production.

  ── Findings ────────────────────────────────────────────────
  7 critical  6 high  7 medium  1 low

  │ gateway                    5 crit  openclaw.json
  │ cve                        2 crit, 1 high, 1 med  package.json, openclaw.json
  ...

  ── Top Issues ──────────────────────────────────────────────
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

  Path forward: 14 -> 100 by fixing 7 critical + 6 high
```

With this many findings the default report groups them by category and shows the top three. Add `--verbose` to list every check, or `--json` for the full finding list.

## Step 2: CVE detection

HMA checks for these known OpenClaw vulnerabilities:

| CVE | Check | Severity | What the check reports | Fixed in |
|-----|-------|----------|------------------------|----------|
| CVE-2026-25253 | `CVE-001` | Critical | WebSocket hijacking enables one-click remote code execution | v2026.1.29 |
| CVE-2026-25157 | `CVE-003` | High | OS command injection through an unescaped SSH project path | v2026.1.29 |
| CVE-2026-24763 | `CVE-004` | Critical | Command injection through unsafe `PATH` handling in the Docker sandbox | v2026.1.29 |

The severities are the ones reported for `openclaw` 2026.1.15 in the run above. A version at or after v2026.1.29 reports each check as passing.

For details on CVE-2026-25253, see the [disclosure blog post](https://opena2a.org/blogs/cve-2026-25253-openclaw-rce).

**Upgrade to fix all CVEs:**

```bash
npm install openclaw@latest
```

Then re-run the scan to confirm the CVEs are resolved.

## Step 3: ClawHavoc IOC scanning

HMA checks for indicators of compromise (IOCs) associated with the ClawHavoc campaign -- a set of attacks targeting OpenClaw installations discovered in early 2026.

IOCs checked:

- Unauthorized skill installations in `skills/` directory
- Modified gateway configuration files with injected endpoints
- Unexpected cron jobs or heartbeat entries
- Outbound connections to known C2 domains

If IOCs are found, HMA reports them as CRITICAL findings with specific remediation steps.

## Step 4: Preview and apply fixes

Preview what auto-fix would change:

```bash
npx hackmyagent secure --fix --dry-run
```

**Example output** from the same project (abridged; the report above is printed first):

```
Scanning /home/user/openclaw-project (dry-run)...
  ...
  Dry run complete: 7 issues auto-fixable. Run without --dry-run to apply.
  No changes were made.
```

Apply the fixes:

```bash
npx hackmyagent secure --fix
```

**Example output** from the same project (abridged; the backup directory name carries the run's timestamp):

```
Scanning /home/user/openclaw-project...
Verifying applied fixes...
  ...
  3 critical issues found

  Security  ━━━━━━━━━━━━━━━━━━━━ 32/100
  Live tree: 35/100 — the 3-point difference is 1 finding inside the backup this run created at /home/user/openclaw-project/.hackmyagent-backup/2026-09-28-075626086-000-6fa3bced
  ...
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
13 remaining issues have fix guidance. Run `hackmyagent fix-all` to apply all available fixes.
Backup created: /home/user/openclaw-project/.hackmyagent-backup/2026-09-28-075626086-000-6fa3bced
Something wrong? Run `hackmyagent rollback .` to undo all changes.
```

The CVE findings are not auto-fixed: upgrading `openclaw` (Step 2) is what clears them. `GATEWAY-002` needs the `security.websocketOrigins` edit its `Fix:` line names. The auth token was on disk in plaintext, so rotate it.

## Step 5: Verify

```bash
npx hackmyagent secure
```

Once no critical or high finding remains, the scan exits with code `0`. In the run above that takes the upgrade, the fixes and the `security.websocketOrigins` edit.

---

## Related resources

- [Securing OpenClaw: 6 PRs Merged Upstream](https://opena2a.org/blogs/securing-openclaw-6-prs-merged) -- details on the security improvements contributed to OpenClaw
- [CVE-2026-25253: OpenClaw WebSocket RCE](https://opena2a.org/blogs/cve-2026-25253-openclaw-rce) -- full disclosure and technical analysis

## Next steps

- [Red-team your MCP servers](red-team-mcp.md) with adversarial payloads
- [Add HMA to your CI/CD pipeline](ci-pipeline.md)
- See the full [Security Checks Reference](../SECURITY_CHECKS.md) for all check IDs

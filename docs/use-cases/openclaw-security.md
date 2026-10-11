# Use Case: Secure My OpenClaw Installation

**Time:** 10 minutes
**Goal:** Run OpenClaw-specific security checks, detect known CVEs, scan for ClawHavoc IOCs, and auto-remediate.

---

## Background

HMA includes 56 checks specifically for [OpenClaw](https://github.com/open-claw/open-claw) installations. These cover gateway configuration, skill security, credential redaction, and known CVEs. Six of the findings led to [upstream PRs merged into OpenClaw](https://opena2a.org/blogs/securing-openclaw-6-prs-merged).

## Step 1: Run the scan

From your OpenClaw project directory:

```bash
npx hackmyagent secure
```

HMA detects OpenClaw from an `openclaw.json`, a `SKILL.md` or `HEARTBEAT.md`, or a `.openclaw`, `.moltbot` or `.clawdbot` directory. All 56 OpenClaw checks run automatically; they are part of the 317 static checks, not added to them.

**Output** from this repository's `test-fixtures/insecure-openclaw` (your findings depend on your installation):

```
Scanning .../insecure-openclaw...

Discovering assembly components...
NanoMind: 6 artifact(s) compiled, 11 semantic finding(s) added

  insecure-openclaw  openclaw · 6 files analyzed
  22 critical issues found

  Security  ━━━━━━━━━━━━━━━━━━━━ 0/100

  ── Observations ────────────────────────────────────────────
  Surfaces    openclaw · 6 semantic artifacts · 4 of 6 artifacts reached 0-2 of 7 analyzer families
  Checks      317 static declared · 63 of 63 check groups ran · 6 semantic (NanoMind AST, 0-7 of 7 analyzer families) · 6 files read by static checks
  Coverage    17 of 25 categories examined · 8 unexamined (read no file) · 5 checks reported an absent mitigation (not shown)
  Unexamined  A2A, governance, identity, injection, lifecycle, MCP, memory, sandbox-escape
  Artifacts   SKILL.md  skill · malicious · no inferred capabilities  (no declared constraints)
              skills/malicious-skill/SKILL.md  skill · malicious · no inferred capabilities  (no declared constraints)
  Categories  credentials (1 critical, 3 high, 2 medium) · network (5 critical) · prompt (6 high) · sandbox (1 high) · capabilities (1 high) · supply-chain (1 critical, 6 medium) · skill (7 critical, 1 high, 11 medium) · CVE (1 medium) · heartbeat (6 critical, 2 high, 1 medium) · config (1 critical, 2 high) · git hygiene (1 critical, 1 low) · 6 others clear
  Verdict     Not safe to ship. .env Not Ignored in .env + 59 more. Fix before using in production.


  ── Findings ────────────────────────────────────────────────
  22 critical  16 high  21 medium  1 low

  │ skill                      7 crit, 1 high, 13 med  SKILL.md, skills
  │ heartbeat                  6 crit, 2 high, 1 med  HEARTBEAT.md
  │ gateway                    6 crit  openclaw.json
  │ Prompt Security            6 high  SKILL.md, skills
  │ supply                     1 crit, 6 med  SKILL.md, skills
  │ config                     1 crit, 2 high  openclaw.json
  │ Credential Protection      3 high  .env
  │ git                        1 crit, 1 low  .gitignore, .env
  │ + 3 more categories

  ── Top Issues ──────────────────────────────────────────────

  │ CRITICAL  .env Not Ignored
  │ .env
  │ .env contains API keys or secrets. Without .gitignore protection, a single git add . can expose all credentials in your repository history.
  │ →  hackmyagent secure --fix

  │ CRITICAL  Remote Fetch Pattern
  │ SKILL.md:9
  │ Remote code execution patterns download and execute arbitrary code. Replace with a pinned dependency or vendored script with checksum verification.
  │ Verify: sed -n '9p' .../insecure-openclaw/SKILL.md
  │ Fix: Remove the curl|sh or wget|sh pattern from this file

  │ CRITICAL  Remote Fetch Pattern
  │ skills/malicious-skill/SKILL.md:15
  │ Remote code execution patterns download and execute arbitrary code. Replace with a pinned dependency or vendored script with checksum verification.
  │ Verify: sed -n '15p' .../insecure-openclaw/skills/malicious-skill/SKILL.md
  │ Fix: Remove the curl|sh or wget|sh pattern from this file

  Path forward: 0 -> 100 by fixing 22 critical + 16 high

  ── Next Steps ─────────────────────────────────────────────────
  Auto-fix governance:  hackmyagent harden-soul .
  Protect credentials:  npx opena2a-cli protect .
  Auto-fix all issues:  hackmyagent secure . --fix
  AI analysis:          hackmyagent check . --nanomind  (attack vectors + targeted remediation)
  All commands:         hackmyagent --help
  opena2a is a separate CLI — install with: npm i -g opena2a-cli

  Scanned with hackmyagent v0.33.2
```

## Step 2: CVE detection

HMA checks the `openclaw` (or `@openclaw/core`) version declared in `package.json` for these known OpenClaw vulnerabilities:

| CVE | Check ID | Severity | Description | Fixed in |
|-----|----------|----------|-------------|----------|
| CVE-2026-25253 | CVE-001 | Critical | WebSocket hijacking RCE: WebSocket hijacking enables 1-click RCE (CVSS 8.8) | v2026.1.29 |
| CVE-2026-25157 | CVE-003 | High | OS command injection via SSH path: unescaped project path enables command injection on SSH hosts (CVSS 7.8) | v2026.1.29 |
| CVE-2026-24763 | CVE-004 | Critical | Docker PATH command injection: unsafe PATH handling enables command injection in Docker sandbox (CVSS 8.8) | v2026.1.29 |

For details on CVE-2026-25253, see the [disclosure blog post](https://opena2a.org/blogs/cve-2026-25253-openclaw-rce).

**Upgrade to fix all CVEs:**

```bash
npm install openclaw@latest
```

Then re-run the scan to confirm the CVEs are resolved.

## Step 3: ClawHavoc IOC scanning

HMA checks for indicators of compromise (IOCs) associated with the ClawHavoc campaign, a set of attacks targeting OpenClaw installations discovered in early 2026.

IOCs checked:

- Unauthorized skill installations in `skills/` directory
- Modified gateway configuration files with injected endpoints
- Unexpected cron jobs or heartbeat entries
- Known ClawHavoc command-and-control (C2) IP addresses written in skill
  files (`SUPPLY-005`). This is a text match on file content. HMA does not
  observe network connections, so check your network logs for connections
  to any address it reports.

If IOCs are found, HMA reports them as CRITICAL findings with specific remediation steps.

## Step 4: Preview and apply fixes

Preview what auto-fix would change:

```bash
npx hackmyagent secure --fix --dry-run
```

**Output** on a copy of the same fixture (trimmed where marked `...`):

```
Scanning .../insecure-openclaw (dry-run)...

Discovering assembly components...
NanoMind: 6 artifact(s) compiled, 11 semantic finding(s) added

  insecure-openclaw  openclaw · 6 files analyzed
  22 critical issues found

  Security  ━━━━━━━━━━━━━━━━━━━━ 0/100

  ...

  Dry run complete: 8 issues auto-fixable. Run without --dry-run to apply.
  No changes were made.

  Scanned with hackmyagent v0.33.2
```

The text report groups findings by category. Add `--verbose` to list every finding, or use `--format json`, where each finding carries `"fixable"`.

Apply the fixes:

```bash
npx hackmyagent secure --fix
```

**Output** on a copy of the same fixture, run from inside it (the report above the fix list is cut at `...`):

```
  ...

Fixed 7 issues (7 verified):
  ✓✓ [PERM-001] .env - Sensitive File Permissions
    → Changed permissions to 600
  ✓✓ [GIT-001] .gitignore - Missing .gitignore
  ✓✓ [SKILL-004] SKILL.md:18 - Filesystem Write Outside Sandbox
    → Restricted filesystem access to sandbox scope
  ✓✓ [GATEWAY-001] openclaw.json - Bound to 0.0.0.0
    → Changed gateway.host from 0.0.0.0 to 127.0.0.1
  ✓✓ [GATEWAY-003] openclaw.json - Token Exposed in Config
    → Replaced plaintext token with ${OPENCLAW_AUTH_TOKEN} env var reference. Set OPENCLAW_AUTH_TOKEN in your environment.
  ✓✓ [GATEWAY-004] openclaw.json - Approval Confirmations Disabled
    → Enabled approval confirmations for command execution
  ✓✓ [GATEWAY-005] openclaw.json - Sandbox Disabled
    → Enabled sandbox mode for isolated code execution

48 remaining issues have fix guidance. Run `hackmyagent fix-all` to apply all available fixes.

Backup created: .../insecure-openclaw/.hackmyagent-backup/2026-10-11-103357213-000-c8f9f986
Something wrong? Run `hackmyagent rollback .` to undo all changes.

  Scanned with hackmyagent v0.33.2
```

Each fix is one line: the check ID, the file and the finding name, with `✓✓` when a re-check confirmed it. The run keeps its backup in one timestamped directory, the one the `Backup created:` line names, and `npx hackmyagent rollback` restores from it.

## Step 5: Verify

```bash
npx hackmyagent secure
```

After upgrading OpenClaw and applying fixes, a clean scan exits with code `0`.

---

## Related resources

- [Securing OpenClaw: 6 PRs Merged Upstream](https://opena2a.org/blogs/securing-openclaw-6-prs-merged): details on the security improvements contributed to OpenClaw
- [CVE-2026-25253: OpenClaw WebSocket RCE](https://opena2a.org/blogs/cve-2026-25253-openclaw-rce): full disclosure and technical analysis

## Next steps

- [Red-team your MCP servers](red-team-mcp.md) with adversarial payloads
- [Add HMA to your CI/CD pipeline](ci-pipeline.md)
- See the full [Security Checks Reference](../SECURITY_CHECKS.md) for all check IDs

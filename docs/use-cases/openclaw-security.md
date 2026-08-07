# Use Case: Secure My OpenClaw Installation

**Time:** 10 minutes
**Goal:** Run OpenClaw-specific security checks, detect known CVEs, scan for ClawHavoc IOCs, and auto-remediate.

---

## Background

HMA includes 34 checks specifically for [OpenClaw](https://github.com/open-claw/open-claw) installations. These cover gateway configuration, skill security, credential redaction, and known CVEs. Six of the findings led to [upstream PRs merged into OpenClaw](https://opena2a.org/blogs/securing-openclaw-6-prs-merged).

## Step 1: Run the scan

From your OpenClaw project directory:

```bash
npx hackmyagent secure
```

HMA auto-detects OpenClaw by looking for `gateway.yaml`, `skills/`, and OpenClaw configuration files. All 34 OpenClaw checks run automatically alongside the standard 310 static checks.

**Expected output (OpenClaw-specific findings):**

```
HackMyAgent v0.10.1 -- Security Scanner

Scanning: /home/user/openclaw-project
Checks:  310 across 69 categories (34 OpenClaw-specific)

  CRITICAL  CVE-001   CVE-2026-25253 -- OpenClaw WebSocket RCE
            Found: openclaw v0.3.2 in package-lock.json (affected: < 0.3.5)
            Fix:   Upgrade to openclaw >= 0.3.5
            Ref:   https://opena2a.org/blogs/cve-2026-25253-openclaw-rce

  CRITICAL  CVE-002   CVE-2026-25157 -- Skill sandbox escape
            Found: openclaw v0.3.2 (affected: < 0.3.4)
            Fix:   Upgrade to openclaw >= 0.3.4

  HIGH      CVE-003   CVE-2026-24763 -- Gateway auth bypass
            Found: openclaw v0.3.2 (affected: < 0.3.3)
            Fix:   Upgrade to openclaw >= 0.3.3

  HIGH      GATEWAY-001  Gateway bound to 0.0.0.0
            Found: gateway.yaml host: 0.0.0.0
            Fix:   Set host to 127.0.0.1

  HIGH      GATEWAY-003  Plaintext auth token in gateway.yaml
            Found: auth_token: "my-secret-token"
            Fix:   Use environment variable: ${OPENCLAW_AUTH_TOKEN}

  MEDIUM    GATEWAY-004  Human-in-the-loop approvals disabled
            Found: approval_required: false in gateway.yaml
            Fix:   Set approval_required: true

  MEDIUM    GATEWAY-005  Sandbox disabled for skills
            Found: sandbox: false in gateway.yaml
            Fix:   Set sandbox: true

  MEDIUM    SKILL-001    Unsigned skill package
            Found: skills/data-fetcher/ has no signature
            Fix:   Sign with hackmyagent fix-all --with-aim

  LOW       CONFIG-003   Debug mode enabled
            Found: debug: true in gateway.yaml
            Fix:   Set debug: false for production

Summary: 2 critical, 2 high, 3 medium, 1 low
         5 auto-fixable (run with --fix)
```

## Step 2: CVE detection

HMA checks for these known OpenClaw vulnerabilities:

| CVE | Severity | Description | Fixed in |
|-----|----------|-------------|----------|
| CVE-2026-25253 | Critical | WebSocket RCE via crafted skill message | >= 0.3.5 |
| CVE-2026-25157 | Critical | Skill sandbox escape via symlink traversal | >= 0.3.4 |
| CVE-2026-24763 | High | Gateway authentication bypass via header injection | >= 0.3.3 |

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

**Expected output:**

```
  CRITICAL  CVE-001   CVE-2026-25253 -- OpenClaw WebSocket RCE
            (manual fix required -- upgrade openclaw package)

  HIGH      GATEWAY-001  Gateway bound to 0.0.0.0
            Would fix: Set host to 127.0.0.1 in gateway.yaml

  HIGH      GATEWAY-003  Plaintext auth token in gateway.yaml
            Would fix: Replace "my-secret-token" with ${OPENCLAW_AUTH_TOKEN}

  MEDIUM    GATEWAY-004  Approvals disabled
            Would fix: Set approval_required: true in gateway.yaml

  MEDIUM    GATEWAY-005  Sandbox disabled
            Would fix: Set sandbox: true in gateway.yaml

Dry run complete. 4 fixes would be applied. 1 requires manual action.
```

Apply the fixes:

```bash
npx hackmyagent secure --fix
```

**Expected output:**

```
  FIXED     GATEWAY-001  Set host to 127.0.0.1 in gateway.yaml
            Backup: .hackmyagent-backup/gateway.yaml.1710504000

  FIXED     GATEWAY-003  Replaced plaintext token with ${OPENCLAW_AUTH_TOKEN}
            Backup: .hackmyagent-backup/gateway.yaml.1710504000

  FIXED     GATEWAY-004  Set approval_required: true in gateway.yaml
  FIXED     GATEWAY-005  Set sandbox: true in gateway.yaml

Summary: 4 fixed, 3 remaining (manual -- upgrade openclaw, sign skills)
Backups saved to .hackmyagent-backup/
```

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

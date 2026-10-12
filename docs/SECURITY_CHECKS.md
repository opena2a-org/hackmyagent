# Security Checks Reference

HackMyAgent performs 306 security checks across 82 categories (261 static checks plus the NanoMind semantic layer). This document describes representative checks by category; run `hackmyagent check-metadata --json` for the complete, authoritative list.

## Severity Levels

| Severity | Score Weight | Description |
|----------|--------------|-------------|
| **Critical** | 25 | Immediate risk, must fix before deployment |
| **High** | 15 | Significant risk, should fix promptly |
| **Medium** | 8 | Moderate risk, plan to address |
| **Low** | 3 | Minor risk, best practice improvement |

### How the score is computed

A weight is not a number of points subtracted from 100. Each open finding (failed, and not repaired by a `--fix` that its verification pass confirmed) adds its severity weight to a sum, and the score is:

```
score = round(100 * exp(-sum / 150))
```

A scan with no open finding scores 100. Two adjustments apply to a finding's weight before it is added:

- **Governance findings count at 0.4 of their weight.** These are findings in the `governance`, `injection-hardening` or `trust-hierarchy` category, or with a check ID starting `AST-GOV`, `AST-PROMPT` or `AST-HEARTBEAT`.
- **After the third finding from one check, each further finding counts at 0.1 of its weight.** The first three findings with the same check ID count in full. Every finding is still reported; only its share of the score is reduced.

When any critical or high finding is open, the score shown is capped at 69, the top of the band below 70, and the report gives the uncapped score beside it.

| Open findings | Sum | Score |
|---------------|-----|-------|
| 1 low | 3 | 98 |
| 1 medium | 8 | 95 |
| 1 medium, governance | 3.2 | 98 |
| 5 medium, one check | 25.6 | 84 |
| 1 high | 15 | 90, shown as 69 |
| 1 critical | 25 | 85, shown as 69 |
| 1 critical, 3 high, 4 medium, 1 low | 105 | 50 |

Rows without "governance" are findings outside the governance categories; rows without "one check" are findings from different checks.

---

## Credential Security (CRED)

### CRED-001: Exposed API Keys
- **Severity:** Critical
- **Fixable:** Yes
- **Description:** API keys or secrets found in plaintext configuration files
- **Remediation:** Use environment variables or secret management. Auto-fix replaces with `${ENV_VAR}` references.
- **Patterns Detected:** Anthropic, OpenAI, AWS, GitHub, Google, Stripe, Slack, SendGrid

### CRED-002: Sensitive File Types
- **Severity:** High
- **Fixable:** No
- **Description:** Private key files (.pem, .key) detected in repository
- **Remediation:** Remove private keys from repository, use secret management

### CRED-003: Hardcoded Secrets in Scripts
- **Severity:** Critical
- **Fixable:** No
- **Description:** API keys found in package.json scripts or shell commands
- **Remediation:** Use environment variables in scripts

### CRED-004: JWT/Session Secrets
- **Severity:** High
- **Fixable:** No
- **Description:** JWT secrets or session keys found in configuration
- **Remediation:** Load secrets from environment at runtime

---

## MCP Configuration (MCP)

### MCP-001: Root Filesystem Access
- **Severity:** High
- **Fixable:** Yes
- **Description:** MCP server configured with root "/" or home "~" directory access
- **Remediation:** Scope filesystem access to project directory only

### MCP-002: Unrestricted Shell Server
- **Severity:** Critical
- **Fixable:** No
- **Description:** MCP shell server without command restrictions
- **Remediation:** Configure allowedCommands whitelist

### MCP-003: Hardcoded Secrets in Env
- **Severity:** Critical
- **Fixable:** Yes
- **Description:** API keys hardcoded in MCP server environment variables
- **Remediation:** Use `${ENV_VAR}` references instead

### MCP-004: Default Credentials
- **Severity:** Critical
- **Fixable:** No
- **Description:** MCP server using default passwords (postgres, admin, etc.)
- **Remediation:** Use strong, unique passwords

### MCP-005: Wildcard Tool Access
- **Severity:** High
- **Fixable:** No
- **Description:** MCP server allows all tools without restrictions
- **Remediation:** Configure explicit allowedTools list

### MCP-006 to MCP-010: Extended Checks
- Transport security, authentication, logging, resource limits, tool isolation

---

## Claude Code Security (CLAUDE)

### CLAUDE-001: Sensitive Content in CLAUDE.md
- **Severity:** Critical
- **Fixable:** No
- **Description:** API keys or secrets found in CLAUDE.md instructions
- **Remediation:** Remove secrets, use environment variable references

### CLAUDE-002: Overly Permissive Permissions
- **Severity:** High
- **Fixable:** No
- **Description:** Claude Code settings allow unrestricted tool access
- **Remediation:** Scope permissions to specific tools and directories

### CLAUDE-003: Dangerous Bash Permissions
- **Severity:** Critical
- **Fixable:** No
- **Description:** Allows dangerous commands (rm -rf, sudo, etc.)
- **Remediation:** Remove dangerous command permissions

### CLAUDE-004 to CLAUDE-008: Extended Checks
- Permission escalation, hook security, skill trust, output validation

---

## Network Security (NET)

### NET-001: Bound to All Interfaces
- **Severity:** Critical
- **Fixable:** Yes
- **Description:** Server bound to 0.0.0.0 exposes to all network interfaces
- **Remediation:** Bind to 127.0.0.1 for local-only access

### NET-002: Remote MCP Without TLS
- **Severity:** High
- **Fixable:** No
- **Description:** Remote MCP server configured without HTTPS
- **Remediation:** Use HTTPS for all remote connections

### NET-003 to NET-006: Extended Checks
- CORS configuration, port exposure, firewall rules, certificate validation

---

## Prompt Security (PROMPT)

### PROMPT-001: Prompt Boundary Markers
- **Severity:** High
- **Fixable:** No
- **Description:** System prompts lack clear boundary markers
- **Remediation:** Add clear delimiters between system and user content

### PROMPT-002: Injection Defense Instructions
- **Severity:** Medium
- **Fixable:** No
- **Description:** No injection defense guidance in system prompts
- **Remediation:** Add instructions to validate and sanitize inputs

### PROMPT-003: Output Confidentiality Rules
- **Severity:** Medium
- **Fixable:** No
- **Description:** No rules about what information to keep confidential
- **Remediation:** Define what should not be disclosed

### PROMPT-004: Role Definition Protection
- **Severity:** Low
- **Fixable:** No
- **Description:** AI role not clearly defined
- **Remediation:** Explicitly define role to prevent confusion attacks

---

## Input Validation (INJ)

### INJ-001: Input Validation Library
- **Severity:** High
- **Fixable:** No
- **Description:** No schema validation library detected
- **Remediation:** Use zod, joi, yup, or similar for input validation

### INJ-002: XSS Protection
- **Severity:** High
- **Fixable:** No
- **Description:** No output escaping patterns detected
- **Remediation:** Implement escapeHtml, DOMPurify, or similar

### INJ-003: SQL Injection Protection
- **Severity:** Critical
- **Fixable:** No
- **Description:** Database queries may not use parameterized statements
- **Remediation:** Use parameterized queries or ORM

### INJ-004: Command Injection Protection
- **Severity:** Critical
- **Fixable:** No
- **Description:** Shell commands may be vulnerable to injection
- **Remediation:** Use execFile instead of exec, disable shell interpolation

---

## Rate Limiting (RATE)

### RATE-001: Rate Limiting Configuration
- **Severity:** Medium
- **Fixable:** No
- **Description:** No rate limiting library detected
- **Remediation:** Implement express-rate-limit or similar

### RATE-002: Retry with Backoff
- **Severity:** Low
- **Fixable:** No
- **Description:** No exponential backoff patterns detected
- **Remediation:** Implement retry logic with backoff

### RATE-003: Timeout Configuration
- **Severity:** Medium
- **Fixable:** No
- **Description:** No timeout configurations found
- **Remediation:** Set appropriate timeouts for external calls

### RATE-004: Concurrency Limits
- **Severity:** Low
- **Fixable:** No
- **Description:** No concurrency limiting detected
- **Remediation:** Use p-limit or similar to prevent resource exhaustion

---

## Session Security (SESSION)

### SESSION-001: Secure Cookie Settings
- **Severity:** High
- **Fixable:** No
- **Description:** Session cookies may lack secure flags
- **Remediation:** Set httpOnly, secure, and sameSite flags

### SESSION-002: Session Expiry
- **Severity:** Medium
- **Fixable:** No
- **Description:** No session expiry configuration found
- **Remediation:** Configure appropriate maxAge/TTL

### SESSION-003: CSRF Protection
- **Severity:** High
- **Fixable:** No
- **Description:** No CSRF protection library detected
- **Remediation:** Implement CSRF tokens for state-changing operations

### SESSION-004: Secure Token Storage
- **Severity:** Medium
- **Fixable:** No
- **Description:** Tokens may not use secure storage
- **Remediation:** Use keytar or OS keychain for sensitive tokens

---

## Encryption (ENCRYPT)

### ENCRYPT-001: Encryption Implementation
- **Severity:** High
- **Fixable:** No
- **Description:** No encryption patterns detected
- **Remediation:** Encrypt sensitive data at rest

### ENCRYPT-002: Secure Password Hashing
- **Severity:** Critical
- **Fixable:** No
- **Description:** No secure hashing algorithm detected
- **Remediation:** Use bcrypt, argon2, or scrypt

### ENCRYPT-003: Weak Cryptographic Algorithms
- **Severity:** High
- **Fixable:** No
- **Description:** MD5, SHA1, or DES detected
- **Remediation:** Use SHA-256+ and AES-256

### ENCRYPT-004: TLS Configuration
- **Severity:** High
- **Fixable:** No
- **Description:** TLS/HTTPS not configured
- **Remediation:** Use HTTPS for all communications

---

## Audit & Logging (AUDIT)

### AUDIT-001: Audit Logging
- **Severity:** Medium
- **Fixable:** No
- **Description:** No structured logging library detected
- **Remediation:** Implement winston, pino, or bunyan

### AUDIT-002: Log Rotation
- **Severity:** Low
- **Fixable:** No
- **Description:** No log rotation configured
- **Remediation:** Configure maxFiles and maxSize

### AUDIT-003: Error Tracking
- **Severity:** Low
- **Fixable:** No
- **Description:** No error tracking service detected
- **Remediation:** Use Sentry, Bugsnag, or similar

### AUDIT-004: Log Sanitization
- **Severity:** High
- **Fixable:** No
- **Description:** Sensitive data may appear in logs
- **Remediation:** Redact passwords, tokens, and PII from logs

---

## Sandboxing (SANDBOX)

### SANDBOX-001: Container Isolation
- **Severity:** Medium
- **Fixable:** No
- **Description:** No Docker/container configuration found
- **Remediation:** Run applications in isolated containers

### SANDBOX-002: Non-Root Execution
- **Severity:** High
- **Fixable:** No
- **Description:** Container may run as root
- **Remediation:** Add USER directive to Dockerfile

### SANDBOX-003: Resource Limits
- **Severity:** Medium
- **Fixable:** No
- **Description:** No CPU/memory limits configured
- **Remediation:** Set mem_limit and cpus in docker-compose

### SANDBOX-004: Read-Only Filesystem
- **Severity:** Low
- **Fixable:** No
- **Description:** Filesystem not read-only
- **Remediation:** Use read_only: true where possible

---

## Tool Boundaries (TOOL)

### TOOL-001: Tool Whitelisting
- **Severity:** High
- **Fixable:** No
- **Description:** MCP servers lack explicit tool whitelists
- **Remediation:** Configure allowedTools for each server

### TOOL-002: Tool Resource Constraints
- **Severity:** Medium
- **Fixable:** No
- **Description:** No maxTokens or timeout configured
- **Remediation:** Set resource limits for MCP tools

### TOOL-003: Dangerous Tool Detection
- **Severity:** High
- **Fixable:** No
- **Description:** Shell/exec tools detected
- **Remediation:** Ensure dangerous tools have proper restrictions

### TOOL-004: Tool Confirmation Requirements
- **Severity:** Medium
- **Fixable:** No
- **Description:** No confirmation requirement for destructive operations
- **Remediation:** Add confirmation prompts for dangerous actions

---

## Additional Categories

### GIT-001: Missing .gitignore
- **Severity:** Low. High when a private key file, `secrets.json` or `credentials.json` is present in the project, or when the project tree is too large or deep to scan in full
- **Fixable:** Yes
- **Description:** No .gitignore file to prevent accidental commits of sensitive files
- **Remediation:** Run `npx hackmyagent secure --fix` to create a .gitignore with standard security patterns. Without .gitignore, sensitive files (.env, secrets.json, *.pem, *.key) can be accidentally committed to version control and exposed.

### GIT-002: Incomplete .gitignore
- **Severity:** Low. High when a private key file, `secrets.json` or `credentials.json` is present and git would commit it, or when a pattern other than `.env` is missing and the project tree is too large or deep to scan in full
- **Fixable:** Yes
- **Description:** Critical patterns (.env, secrets.json, *.pem, *.key) are missing from .gitignore, allowing sensitive files to be accidentally committed
- **Remediation:** Run `npx hackmyagent secure --fix` to add missing patterns to .gitignore. Missing patterns mean sensitive files could be accidentally committed and pushed to remote repositories.

### GIT-003: .env Not Ignored
- **Severity:** Critical
- **Fixable:** Yes
- **Description:** .env file exists but is not listed in .gitignore, putting secrets at risk of being committed
- **Remediation:** Run `npx hackmyagent secure --fix` to add .env to .gitignore. .env files contain API keys and secrets. Without .gitignore protection, a single `git add .` can expose all credentials in your repository history.

### File Permissions (PERM-001 to PERM-003)
- World-readable files, executable permissions, ownership

### Environment Security (ENV-001 to ENV-004)
- .env files, environment validation, debug mode, production settings

### Logging Security (LOG-001 to LOG-004)
- Structured logging, sensitive data in logs, log levels, monitoring

### Dependency Security (DEP-001 to DEP-004)
- Outdated packages, known vulnerabilities, lock files, audit

### Authentication (AUTH-001 to AUTH-004)
- Auth configuration, token validation, session management, MFA

### Process Security (PROC-001 to PROC-004)
- Signal handling, graceful shutdown, memory management, process isolation

### API Security (API-001 to API-004)
- Rate limiting, authentication, input validation, error handling

### General Security (SEC-001 to SEC-004)
- Security headers, HTTPS enforcement, dependency scanning, secrets management

### I/O Security (IO-001 to IO-004)
- File validation, path traversal, output encoding, resource limits

### Cursor/VSCode (CURSOR-001, VSCODE-001 to VSCODE-002)
- IDE-specific configuration security

---

## OpenClaw Security Checks

OpenClaw (Moltbot) is a popular AI agent framework. HackMyAgent includes 56 specialized security checks targeting OpenClaw-specific attack vectors, including the ClawHavoc malware campaign, CVE-2026-25253, and related vulnerabilities.

### Usage

```bash
hackmyagent secure-openclaw                               # Scan the first of ~/.openclaw, ~/.moltbot, ~/.clawdbot that exists
hackmyagent secure-openclaw ~/.openclaw                   # Scan a specific directory
hackmyagent secure-openclaw ~/.openclaw --fix --dry-run   # Preview the fixes for that directory
hackmyagent secure-openclaw ~/.openclaw --fix             # Apply them; undo with: hackmyagent rollback ~/.openclaw
hackmyagent secure-openclaw ~/.openclaw --json            # JSON output for CI/CD
```

With no directory argument the command scans a real directory in your home folder, so `--fix`
there rewrites real files (skill files included). Name the directory and preview with
`--dry-run` first.

### SKILL Checks (SKILL-001 to SKILL-012, SKILL-018 to SKILL-025)

Detects malicious skills, including patterns from the ClawHavoc campaign.

| Check ID | Severity | Fixable | Description |
|----------|----------|---------|-------------|
| SKILL-001 | Medium | No | Unsigned skill: skill file lacks a cryptographic signature for authenticity verification |
| SKILL-002 | Critical | No | Remote fetch pattern: skill contains a pattern that fetches and executes remote code, such as a download piped to a shell |
| SKILL-003 | High | No | Heartbeat installation: skill installs periodic or scheduled tasks |
| SKILL-004 | Critical | Yes | Filesystem write outside sandbox: skill requests broad filesystem access (`filesystem:*`, `filesystem:~/`) |
| SKILL-005 | Critical or Medium | No | Credential file access: skill references credential or sensitive configuration files (Critical when declared in the frontmatter, Medium when only mentioned in the body) |
| SKILL-006 | Critical | No | Data exfiltration pattern: skill contains patterns commonly used to send data to external endpoints |
| SKILL-007 | Critical | No | ClickFix social engineering: skill tells the user to copy and run commands |
| SKILL-008 | Critical | No | Reverse shell pattern: skill contains patterns commonly used to open a reverse shell |
| SKILL-009 | High | No | Typosquatting name: skill name is close to the name of a popular skill |
| SKILL-010 | Critical | No | Env file exfiltration: skill reads environment files or variables |
| SKILL-011 | Critical | No | Browser data access: skill reads browser data, cookies or local storage |
| SKILL-012 | Critical | No | Crypto wallet access: skill reads cryptocurrency wallets or seed phrases |
| SKILL-018 | Medium | No | Undeclared capability: skill uses a capability not declared in its frontmatter |
| SKILL-019 | Medium | Yes | Stale skill signature: skill content changed after it was signed (signature hash mismatch) |
| SKILL-020 | Medium (High with a malice signal) | No | Missing YAML frontmatter: skill has no YAML frontmatter block (reported as Incomplete frontmatter when the block lacks name, version or capabilities) |
| SKILL-021 | High | No | Overprivileged permissions: skill declares a capability combination that enables exfiltration |
| SKILL-022 | Critical | No | Environment variable exfiltration risk: skill reads environment variables and has outbound network capability |
| SKILL-023 | High | No | Obfuscated code pattern: skill contains obfuscated code that may hide its behavior |
| SKILL-024 | Medium | No | Unbounded tool chaining: skill declares tool:chain without maxIterations or iterationLimit |
| SKILL-025 | Critical | No | Hardcoded credential in skill: skill file contains a credential value |

**ClawHavoc Campaign:** A malware campaign targeting OpenClaw users through malicious skills distributed via unofficial channels. Skills contain reverse shells, credential stealers, and persistence mechanisms.

**ClickFix Attacks:** Social engineering technique where malicious skills trick users into copying and pasting harmful commands.

### HEARTBEAT Checks (HEARTBEAT-001 to HEARTBEAT-007)

Checks heartbeat files for unverified sources, missing integrity controls, dangerous capabilities and schedule limits.

| Check ID | Severity | Fixable | Description |
|----------|----------|---------|-------------|
| HEARTBEAT-001 | Critical | No | Unverified heartbeat URL: heartbeat contacts an external URL without verification |
| HEARTBEAT-002 | High | No | No hash pinning: heartbeat lacks hash pinning for content integrity verification |
| HEARTBEAT-003 | High | No | Unsigned heartbeat: heartbeat file lacks a cryptographic signature |
| HEARTBEAT-004 | Critical | No | Dangerous capabilities: heartbeat requests dangerous capabilities |
| HEARTBEAT-005 | Medium | No | Excessive frequency: heartbeat runs more often than every 5 minutes |
| HEARTBEAT-006 | Medium | No | No active hours limit: heartbeat lacks time-of-day restrictions |
| HEARTBEAT-007 | High | Yes | Expired heartbeat: skill signature passed its expires_at date and needs renewal |

### GATEWAY Checks (GATEWAY-001 to GATEWAY-008)

Detects gateway misconfigurations related to GHSA-g8p2-7wf7-98mq and other vulnerabilities.

| Check ID | Severity | Fixable | Description |
|----------|----------|---------|-------------|
| GATEWAY-001 | Critical | Yes | Bound to 0.0.0.0: gateway is bound to all interfaces instead of 127.0.0.1 |
| GATEWAY-002 | Critical | No | Missing WebSocket origin validation: gateway config has no `security.websocketOrigins` (GHSA-g8p2) |
| GATEWAY-003 | Critical | Yes | Token exposed in config: plaintext authentication token stored in the configuration file |
| GATEWAY-004 | Critical | Yes | Approval confirmations disabled: execution approval confirmations are turned off |
| GATEWAY-005 | Critical | Yes | Sandbox disabled: `sandbox.enabled` is false in the configuration file |
| GATEWAY-006 | Critical | No | Container escape risk: Docker configuration allows container escape |
| GATEWAY-007 | Critical | No | Open DM policy with wildcard: direct message policy allows messages from any source |
| GATEWAY-008 | High | No | Tailscale Funnel exposure: Tailscale Funnel is enabled, exposing the agent to the public internet |

**Advisory reference:** [GHSA-g8p2-7wf7-98mq](https://github.com/advisories/GHSA-g8p2-7wf7-98mq). Without WebSocket origin validation, any website can connect to the gateway and send it commands. GATEWAY-002 reports a gateway config that does not set allowed origins.

### CONFIG Checks (CONFIG-001 to CONFIG-009)

Detects insecure configuration settings.

| Check ID | Severity | Fixable | Description |
|----------|----------|---------|-------------|
| CONFIG-001 | Critical | No | Session file exposure: a session or token file that may contain credentials is present |
| CONFIG-002 | High | No | SOUL.md injection vectors: SOUL.md contains potential prompt injection patterns |
| CONFIG-003 | Critical | No | Daemon running as root: daemon script runs with root privileges |
| CONFIG-004 | Critical | No | Plaintext API keys: plaintext API key found in an environment file |
| CONFIG-005 | High | No | Memory poisoning patterns: memory.json contains patterns that could poison agent memory |
| CONFIG-006 | High | No | Moltbook integration risk: Moltbook auto-follow is enabled, so the agent follows untrusted agents automatically |
| CONFIG-007 | Critical | No | Unrestricted elevated execution: elevated execution set to full access without restrictions or approvals bypassed |
| CONFIG-008 | High | No | Sandbox disabled: sandbox execution environment is explicitly disabled in configuration |
| CONFIG-009 | High | No | Weak gateway token: gateway authentication token is too short (< 24 characters) |

### SUPPLY Checks (SUPPLY-001 to SUPPLY-008)

Detects supply chain attack vectors and ClawHavoc indicators of compromise.

| Check ID | Severity | Fixable | Description |
|----------|----------|---------|-------------|
| SUPPLY-001 | Medium or High | No | Unverified publisher: skill publisher identity has not been verified (High when the skill also shows malicious signals) |
| SUPPLY-002 | Medium | No | Skill not in registry: skill has not been registered with a trusted skill registry |
| SUPPLY-003 | Critical | No | Known malicious skill pattern: skill matches known malicious patterns from the ClawHavoc campaign |
| SUPPLY-004 | Medium or High | No | Version drift detection: skill lacks an `installed_hash` for detecting unauthorized modifications (High when the skill also shows malicious signals) |
| SUPPLY-005 | Critical | No | ClawHavoc C2 IP detected: skill contains known command-and-control IP address |
| SUPPLY-006 | Critical | No | ClawHavoc malware filename: skill references known malware payload filename |
| SUPPLY-007 | High | No | ClawHavoc ClickFix pattern: skill contains social engineering instructions to execute malware |
| SUPPLY-008 | High | No | Suspicious archive password: skill contains password-protected archive reference typical of malware distribution |

### CVE Checks (CVE-001 to CVE-004)

Detects known CVEs affecting OpenClaw installations.

| Check ID | Severity | Fixable | Description |
|----------|----------|---------|-------------|
| CVE-001 | Critical | No | CVE-2026-25253: WebSocket Hijacking RCE. OpenClaw version vulnerable to WebSocket hijacking that enables 1-click RCE (CVSS 8.8) |
| CVE-002 | Medium | No | Control UI origin restrictions not configured: auth is configured but controlUi.allowedOrigins is not set for defense-in-depth |
| CVE-003 | High | No | CVE-2026-25157: OS command injection via SSH path. Unescaped project path enables command injection on SSH hosts (CVSS 7.8) |
| CVE-004 | Critical | No | CVE-2026-24763: Docker PATH command injection. Unsafe PATH handling enables command injection in Docker sandbox (CVSS 8.8) |

### Auto-Fix Capabilities

Of the checks in the tables above, `--fix` changes these:

| Check ID | Auto-Fix Action |
|----------|-----------------|
| SKILL-004 | Rewrite `filesystem:*` to `filesystem:./` and `filesystem:~/` to `filesystem:./data/` |
| SKILL-019 | Recompute the hash and rewrite the skill's signature block |
| HEARTBEAT-007 | Renew the skill signature with a 7-day expiry |
| GATEWAY-001 | Change `gateway.host` from 0.0.0.0 to 127.0.0.1 |
| GATEWAY-003 | Replace the plaintext token with `${OPENCLAW_AUTH_TOKEN}` |
| GATEWAY-004 | Turn execution approval confirmations back on |
| GATEWAY-005 | Set `sandbox.enabled` to true |

---

## Memory/Context Poisoning (MEM)

### MEM-001: Unvalidated Memory Persistence
- **Severity:** High
- **Fixable:** No
- **Description:** Memory file contains prototype pollution vectors or unvalidated external references ($ref, __proto__, constructor) that could be exploited to inject malicious context
- **Remediation:** Sanitize all memory entries before persistence. Remove __proto__ and constructor keys. Validate $ref URIs.

### MEM-002: No Memory Integrity Verification
- **Severity:** Medium
- **Fixable:** No
- **Description:** Agent configuration enables memory/context persistence without integrity verification. An attacker with file access could inject malicious context.
- **Remediation:** Enable memory integrity verification: add hash validation or signature checks for persisted context.

### MEM-003: No Context Size Limits
- **Severity:** Medium
- **Fixable:** No
- **Description:** Agent loads context/memory without size limits. An attacker could craft inputs that overflow the context window, pushing safety instructions out of scope.
- **Remediation:** Set explicit context size limits: maxContextSize, memory.maxEntries, or memory.maxSize.

### MEM-004: Shared Memory Without Isolation
- **Severity:** High
- **Fixable:** No
- **Description:** Multiple agents share memory without isolation boundaries. A compromised agent could poison the shared context to influence other agents.
- **Remediation:** Enable memory isolation: set sharedMemory.isolation=true or use per-agent memory scopes.

### MEM-005: Conversation History Injection
- **Severity:** High
- **Fixable:** No
- **Description:** System prompt includes unvalidated conversation history. An attacker could craft messages in history that inject instructions into the system prompt.
- **Remediation:** Sanitize conversation history before including in system prompts. Strip instruction-like patterns.

---

## RAG Poisoning (RAG)

### RAG-001: Unvalidated RAG Retrieval Source
- **Severity:** High
- **Fixable:** No
- **Description:** RAG pipeline retrieves from an unverified source. An attacker who controls the source could inject malicious content into agent responses.
- **Remediation:** Add source verification: set trustedSource=true only for validated endpoints, or enable signatureCheck.

### RAG-002: No RAG Content Sanitization
- **Severity:** High
- **Fixable:** No
- **Description:** Retrieved content is passed to the LLM without sanitization. Poisoned documents could inject instructions into the prompt.
- **Remediation:** Sanitize retrieved content before including in prompts. Strip instruction-like patterns and markup.

### RAG-003: Public-Writable Vector Store
- **Severity:** Critical
- **Fixable:** No
- **Description:** Vector store allows public write access. An attacker could insert poisoned documents that will be retrieved and influence agent responses.
- **Remediation:** Restrict vector store write access. Require authentication for document ingestion.

### RAG-004: No Provenance Tracking
- **Severity:** Medium
- **Fixable:** No
- **Description:** RAG pipeline does not track provenance of retrieved content. Without provenance, poisoned content cannot be traced back to its source.
- **Remediation:** Enable provenance tracking: set sourceTracking=true to track which source each document came from.

---

## Agent Identity Spoofing (AIM)

### AIM-001: No Agent Identity Declaration
- **Severity:** Medium
- **Fixable:** No
- **Description:** Project appears to be an AI agent but has no formal identity declaration. Without identity, the agent cannot be verified by other agents or registries.
- **Remediation:** Create an agent-card.json with agentId, name, publicKey, and capabilities fields.

### AIM-002: Identity Without Cryptographic Binding
- **Severity:** High
- **Fixable:** No
- **Description:** Agent declares an identity but has no cryptographic key binding. Any agent could claim this identity without proof.
- **Remediation:** Bind agent identity to a cryptographic key pair. Add publicKey or keyId field to the agent card.

### AIM-003: No Identity Verification Endpoint
- **Severity:** Medium
- **Fixable:** No
- **Description:** Agent identity has no verification endpoint. Other agents cannot verify this agent's identity claims.
- **Remediation:** Add a verification endpoint: verificationEndpoint URL or oidcIssuer for federated identity.

---

## Agent DNA Forgery (DNA)

### DNA-001: No Behavioral Fingerprint
- **Severity:** Medium
- **Fixable:** No
- **Description:** Agent has behavioral instructions (SOUL.md/system prompt) but no behavioral fingerprint. Without a fingerprint, behavioral integrity cannot be verified.
- **Remediation:** Create agent-dna.json with contentHash of SOUL.md, baselineHash, and signature for integrity verification.

### DNA-002: Unsigned Behavioral Profile
- **Severity:** High
- **Fixable:** No
- **Description:** Agent DNA/behavioral profile exists but is not signed. An attacker could modify the profile to change agent behavior without detection.
- **Remediation:** Sign the behavioral profile: add a contentHash (SHA-256) or signature field verified at startup.

### DNA-003: No Behavioral Drift Detection
- **Severity:** Medium
- **Fixable:** No
- **Description:** Agent DNA has no drift detection configured. Gradual behavioral changes would go undetected.
- **Remediation:** Enable behavioral drift detection: set baselineHash and driftThreshold for continuous monitoring.

---

## Skill Memory Manipulation (SKILL-MEM)

### SKILL-MEM-001: Skill With Unrestricted Memory Access
- **Severity:** High
- **Fixable:** No
- **Description:** A skill declares memory/context write capabilities without explicit restrictions. A malicious skill could manipulate agent memory to alter future behavior.
- **Remediation:** Restrict skill memory access: declare explicit read-only or scoped-write permissions in SKILL.md. Add read-only guards or scope memory writes to skill-specific namespaces.

---

## Check ID Format

Check IDs follow the pattern: `CATEGORY-NNN`

Examples:
- `CRED-001` - Credential check #1
- `MCP-003` - MCP configuration check #3
- `PROMPT-002` - Prompt security check #2

Use these IDs with `--ignore` to skip specific checks:
```bash
hackmyagent secure --ignore CRED-001,LOG-001
```

---

## Updating This Reference

This document is maintained alongside the scanner implementation. Check IDs and descriptions should match the scanner source code in `src/hardening/scanner.ts`.

## Auto-fix catalogue

Checks `hackmyagent secure --fix` can remediate.

| Check | Issue | Auto-fix |
|---|---|---|
| CRED-001 | Exposed API keys | Replace with env-var reference |
| GIT-001 | Missing .gitignore | Create with secure defaults |
| GIT-002 | Incomplete .gitignore | Add missing patterns |
| PERM-001 | Overly permissive files | Set restrictive permissions |
| MCP-001 | Root filesystem access | Scope to project directory |
| NET-001 | Bound to 0.0.0.0 | Bind to 127.0.0.1 |
| GATEWAY-001 | Gateway bound to 0.0.0.0 | Bind to 127.0.0.1 |
| GATEWAY-003 | Plaintext token | Replace with `${OPENCLAW_AUTH_TOKEN}` |
| GATEWAY-004 | Approvals disabled | Enable approvals |
| GATEWAY-005 | Sandbox disabled | Enable sandbox |

Use `--dry-run` to preview changes. Before fixing, each run copies the files a fix may change, `.env` included and whether or not a fix then changes them, into a per-user backup store outside the project (`$HMA_BACKUP_HOME`, else `$OPENA2A_HOME/backups`, else `~/.opena2a/backups`), one set per run, kept until you delete it or `hackmyagent rollback` restores from it. Deleting or re-creating the project, or moving it to another filesystem, does not delete its backups; the `Backups:` line of every `secure` text report prints the command that deletes that project's backups, and deleting the store root deletes every project's. Rollback with `hackmyagent rollback`.

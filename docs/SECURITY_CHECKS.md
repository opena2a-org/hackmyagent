# Security Checks Reference

HackMyAgent performs 163 security checks across 35 categories. This document provides detailed information about each check, including severity, description, and remediation guidance.

## Severity Levels

| Severity | Score Impact | Description |
|----------|--------------|-------------|
| **Critical** | -15 points | Immediate risk, must fix before deployment |
| **High** | -10 points | Significant risk, should fix promptly |
| **Medium** | -5 points | Moderate risk, plan to address |
| **Low** | -2 points | Minor risk, best practice improvement |

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

### Git Security (GIT-001 to GIT-003)
- Missing .gitignore, incomplete patterns, .env at risk

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

OpenClaw (Moltbot) is a popular AI agent framework. HackMyAgent includes 47 specialized security checks targeting OpenClaw-specific attack vectors, including the ClawHavoc malware campaign, CVE-2026-25253, and related vulnerabilities.

### Usage

```bash
hackmyagent secure-openclaw              # Scan default ~/.moltbot location
hackmyagent secure-openclaw ~/.moltbot   # Scan specific directory
hackmyagent secure-openclaw --fix        # Auto-fix issues
hackmyagent secure-openclaw --json       # JSON output for CI/CD
```

### SKILL Checks (SKILL-001 to SKILL-012)

Detects malicious skills, including patterns from the ClawHavoc campaign.

| Check ID | Severity | Fixable | Description |
|----------|----------|---------|-------------|
| SKILL-001 | Critical | No | Unsigned skill detected — skill lacks cryptographic signature |
| SKILL-002 | Critical | No | Invalid signature — skill signature fails verification |
| SKILL-003 | Critical | No | Revoked skill — skill is on global blocklist |
| SKILL-004 | Critical | No | Reverse shell detected — skill contains nc/bash reverse shell patterns |
| SKILL-005 | Critical | No | Credential exfiltration — skill accesses wallet/SSH keys/API keys |
| SKILL-006 | High | No | Network exfiltration — skill sends data to external endpoints |
| SKILL-007 | High | No | Obfuscated code — skill contains base64/hex encoded payloads |
| SKILL-008 | High | No | ClickFix pattern — skill uses clipboard manipulation for social engineering |
| SKILL-009 | Medium | Yes | Excessive permissions — skill requests more permissions than needed |
| SKILL-010 | Medium | No | Untrusted publisher — skill from unverified publisher |
| SKILL-011 | High | No | Persistence mechanism — skill installs cron/launchd/systemd entries |
| SKILL-012 | Critical | No | ClawHavoc signature — matches known ClawHavoc malware patterns |

**ClawHavoc Campaign:** A malware campaign targeting OpenClaw users through malicious skills distributed via unofficial channels. Skills contain reverse shells, credential stealers, and persistence mechanisms.

**ClickFix Attacks:** Social engineering technique where malicious skills manipulate clipboard contents to trick users into executing harmful commands.

### HEARTBEAT Checks (HEARTBEAT-001 to HEARTBEAT-006)

Detects heartbeat/cron abuse and persistence mechanisms.

| Check ID | Severity | Fixable | Description |
|----------|----------|---------|-------------|
| HEARTBEAT-001 | Critical | Yes | Unauthorized heartbeat — heartbeat configured without user consent |
| HEARTBEAT-002 | High | No | Excessive frequency — heartbeat interval under 60 seconds |
| HEARTBEAT-003 | High | No | External heartbeat URL — heartbeat sends data outside localhost |
| HEARTBEAT-004 | Medium | Yes | Missing heartbeat auth — heartbeat endpoint lacks authentication |
| HEARTBEAT-005 | High | No | Heartbeat data exfil — heartbeat payload contains sensitive data |
| HEARTBEAT-006 | Critical | No | Cron backdoor — heartbeat registered malicious cron entries |

### GATEWAY Checks (GATEWAY-001 to GATEWAY-008)

Detects gateway misconfigurations related to GHSA-g8p2-7wf7-98mq and other vulnerabilities.

| Check ID | Severity | Fixable | Description |
|----------|----------|---------|-------------|
| GATEWAY-001 | Critical | Yes | GHSA-g8p2 vulnerable — gateway allows unauthenticated skill installation |
| GATEWAY-002 | Critical | Yes | Open gateway port — gateway bound to 0.0.0.0 instead of 127.0.0.1 |
| GATEWAY-003 | High | Yes | Missing gateway auth — gateway lacks API key or token auth |
| GATEWAY-004 | High | No | Permissive CORS — gateway allows requests from any origin |
| GATEWAY-005 | Medium | Yes | Insecure transport — gateway uses HTTP instead of HTTPS |
| GATEWAY-006 | High | No | Gateway path traversal — gateway allows ../ in skill paths |
| GATEWAY-007 | Critical | No | Open DM policy with wildcard — direct message policy allows messages from any source |
| GATEWAY-008 | High | No | Tailscale Funnel exposure — Tailscale Funnel is enabled, exposing the agent to the public internet |

**CVE Reference:** [GHSA-g8p2-7wf7-98mq](https://github.com/advisories/GHSA-g8p2-7wf7-98mq) — Remote skill installation vulnerability allowing attackers to install arbitrary skills without authentication.

### CONFIG Checks (CONFIG-001 to CONFIG-009)

Detects insecure configuration settings.

| Check ID | Severity | Fixable | Description |
|----------|----------|---------|-------------|
| CONFIG-001 | Critical | Yes | Sandbox disabled — skill sandbox protection is disabled |
| CONFIG-002 | Critical | Yes | Approval disabled — skill execution approval prompts are disabled |
| CONFIG-003 | High | Yes | Debug mode enabled — debug mode exposes sensitive information |
| CONFIG-004 | High | No | Hardcoded secrets — API keys in configuration files |
| CONFIG-005 | Medium | Yes | Permissive file access — skills can access files outside project |
| CONFIG-006 | Medium | Yes | Missing skill allowlist — no explicit skill whitelist configured |
| CONFIG-007 | Critical | No | Unrestricted elevated execution — elevated execution set to full access without restrictions or approvals bypassed |
| CONFIG-008 | High | No | Sandbox disabled in config — sandbox execution environment is explicitly disabled in configuration |
| CONFIG-009 | High | No | Weak gateway token — gateway authentication token is too short (< 24 characters) |

### SUPPLY Checks (SUPPLY-001 to SUPPLY-008)

Detects supply chain attack vectors and ClawHavoc indicators of compromise.

| Check ID | Severity | Fixable | Description |
|----------|----------|---------|-------------|
| SUPPLY-001 | Critical | No | Unofficial skill source — skills installed from untrusted registries |
| SUPPLY-002 | High | No | Typosquatting detected — skill name similar to popular skill |
| SUPPLY-003 | High | No | Dependency confusion — skill loads dependencies from public registry |
| SUPPLY-004 | Medium | No | Missing lockfile — skill dependencies not pinned to specific versions |
| SUPPLY-005 | Critical | No | ClawHavoc C2 IP detected — skill contains known command-and-control IP address |
| SUPPLY-006 | Critical | No | ClawHavoc malware filename — skill references known malware payload filename |
| SUPPLY-007 | High | No | ClawHavoc ClickFix pattern — skill contains social engineering instructions to execute malware |
| SUPPLY-008 | High | No | Suspicious archive password — skill contains password-protected archive reference typical of malware distribution |

### CVE Checks (CVE-001 to CVE-004)

Detects known CVEs affecting OpenClaw installations.

| Check ID | Severity | Fixable | Description |
|----------|----------|---------|-------------|
| CVE-001 | Critical | No | CVE-2026-25253: WebSocket Hijacking RCE — OpenClaw version vulnerable to WebSocket hijacking that enables 1-click RCE (CVSS 8.8) |
| CVE-002 | Medium | No | Control UI origin restrictions not configured — auth is configured but controlUi.allowedOrigins is not set for defense-in-depth |
| CVE-003 | High | No | CVE-2026-25157: OS command injection via SSH path — unescaped project path enables command injection on SSH hosts (CVSS 7.8) |
| CVE-004 | Critical | No | CVE-2026-24763: Docker PATH command injection — unsafe PATH handling enables command injection in Docker sandbox (CVSS 8.8) |

### Auto-Fix Capabilities

The following OpenClaw checks can be automatically fixed:

| Check ID | Auto-Fix Action |
|----------|-----------------|
| SKILL-009 | Reduce skill permissions to minimum required |
| HEARTBEAT-001 | Remove unauthorized heartbeat configuration |
| HEARTBEAT-004 | Add authentication to heartbeat endpoint |
| GATEWAY-001 | Patch GHSA-g8p2 vulnerability |
| GATEWAY-002 | Bind gateway to 127.0.0.1 |
| GATEWAY-003 | Enable API key authentication |
| GATEWAY-005 | Configure HTTPS transport |
| CONFIG-001 | Enable sandbox protection |
| CONFIG-002 | Enable approval prompts |
| CONFIG-003 | Disable debug mode |
| CONFIG-005 | Restrict file access to project directory |
| CONFIG-006 | Generate skill allowlist from installed skills |

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

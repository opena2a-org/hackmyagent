# Security Checks Reference

HackMyAgent performs 100 security checks across 24 categories. This document provides detailed information about each check, including severity, description, and remediation guidance.

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

This document is maintained alongside the scanner implementation. Check IDs and descriptions should match the scanner source code in `packages/core/src/hardening/scanner.ts`.

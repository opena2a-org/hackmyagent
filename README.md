# HackMyAgent

> **AI Agent Security Scanner** — Detect exposed MCP servers, leaked API keys, and vulnerable Claude Code configurations. Free, no signup required.

[![npm version](https://img.shields.io/npm/v/hackmyagent.svg)](https://www.npmjs.com/package/hackmyagent)
[![npm downloads](https://img.shields.io/npm/dm/hackmyagent.svg)](https://www.npmjs.com/package/hackmyagent)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Website:** [hackmyagent.com](https://hackmyagent.com) — Scan external infrastructure for exposed MCP endpoints, configs, and credentials

```bash
npx hackmyagent check @publisher/skill     # verify a skill before installing
npx hackmyagent secure                      # harden your agent setup (100 checks)
npx hackmyagent secure --fix                # auto-fix security issues
npx hackmyagent scan example.com            # scan for exposed infrastructure
```

## Two Ways to Scan

| Tool | Use Case |
|------|----------|
| **[hackmyagent.com](https://hackmyagent.com)** | Scan external targets — check if your MCP servers, configs, or credentials are exposed on the internet |
| **`npx hackmyagent secure`** | Scan local projects — harden your agent setup before deploying |

## Why HackMyAgent?

AI agents are powerful but introduce new attack surfaces. Skills can be malicious. Configs can leak secrets. MCP servers can be exposed. HackMyAgent helps you:

- **Check** skills before installing (publisher verification, permission analysis)
- **Secure** your agent setup (100-point CIS-style security scan, auto-remediation)
- **Scan** external infrastructure (exposed MCP endpoints, leaked configs)

## Installation

```bash
# Use directly with npx (no install needed)
npx hackmyagent secure

# Or install globally
npm install -g hackmyagent

# Or add to your project
npm install --save-dev hackmyagent
```

## Commands

### `hackmyagent secure`

Scan and harden your local agent setup with 100 security checks across 24 categories.

```bash
# Basic scan
hackmyagent secure

# Scan specific directory
hackmyagent secure ./my-project

# Auto-fix issues
hackmyagent secure --fix

# Preview fixes without applying
hackmyagent secure --fix --dry-run

# Skip specific checks
hackmyagent secure --ignore CRED-001,GIT-002

# JSON output for CI/CD
hackmyagent secure --json

# Show all checks (including passed)
hackmyagent secure --verbose
```

**Security Categories:**

| Category | Checks | Description |
|----------|--------|-------------|
| CRED | 4 | Credential exposure detection |
| MCP | 12 | MCP server configuration |
| CLAUDE | 8 | Claude Code security |
| NET | 6 | Network security |
| PROMPT | 4 | Prompt injection defenses |
| INJ | 4 | Input validation (XSS, SQL, cmd) |
| ENCRYPT | 4 | Encryption at rest |
| SESSION | 4 | Session management |
| AUDIT | 4 | Audit trails |
| SANDBOX | 4 | Process isolation |
| TOOL | 4 | Tool permission boundaries |
| And 13 more... | 42 | Auth, deps, env, git, io, log, perm, proc, rate, sec, api, vscode, cursor |

**Exit Codes:**
- `0` - No critical/high issues
- `1` - Critical or high severity issues found

### `hackmyagent check`

Verify a skill's safety before installing.

```bash
hackmyagent check @publisher/skill-name
hackmyagent check @anthropic/claude-mcp --verbose
hackmyagent check @publisher/skill --json
hackmyagent check @publisher/skill --offline  # skip DNS verification
```

**Checks performed:**
- Publisher identity via DNS TXT records
- Permissions requested (filesystem, network, shell access)
- Revocation status against global blocklist

**Risk Levels:** `low`, `medium`, `high`, `critical`

### `hackmyagent scan`

Scan external infrastructure for exposed AI agent endpoints.

```bash
hackmyagent scan example.com
hackmyagent scan 192.168.1.100 -p 3000,8080
hackmyagent scan example.com --verbose
hackmyagent scan example.com --json
```

**Detects:**
- Exposed MCP SSE/tools endpoints
- Public configuration files
- API keys in responses
- Debug/admin interfaces

**Scoring:** A (90-100), B (80-89), C (70-79), D (60-69), F (<60)

### `hackmyagent rollback`

Undo auto-fix changes.

```bash
hackmyagent rollback              # rollback current directory
hackmyagent rollback ./my-project # rollback specific directory
```

Backups are automatically created in `.hackmyagent-backup/` with timestamps.

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npx hackmyagent secure --json > security-report.json
      - uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.json
```

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/sh
npx hackmyagent secure --ignore LOG-001,RATE-001
```

### JSON Output

All commands support `--json` for machine-readable output:

```bash
hackmyagent secure --json | jq '.findings[] | select(.severity == "critical")'
```

## Supported Platforms

- **Claude Code** - CLAUDE.md, skills, MCP servers
- **Cursor** - .cursor/ rules, MCP configurations
- **VSCode** - .vscode/mcp.json configurations
- **Generic MCP** - Any MCP server setup

## Security Check Reference

For the complete list of 100 security checks with descriptions and remediation guidance, see [SECURITY_CHECKS.md](docs/SECURITY_CHECKS.md).

## Auto-Fix Capabilities

The following issues can be automatically fixed with `--fix`:

| Check ID | Issue | Auto-Fix Action |
|----------|-------|-----------------|
| CRED-001 | Exposed API keys | Replace with env var reference |
| GIT-001 | Missing .gitignore | Create with secure defaults |
| GIT-002 | Incomplete .gitignore | Add missing patterns |
| PERM-001 | Overly permissive files | Set restrictive permissions |
| MCP-001 | Root filesystem access | Scope to project directory |
| NET-001 | Bound to 0.0.0.0 | Bind to 127.0.0.1 |

Always use `--dry-run` first to preview changes.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NO_COLOR` | Disable colored output |
| `HACKMYAGENT_TIMEOUT` | Default timeout for scans (ms) |

## Test Fixtures

Sample projects with intentional security issues for testing:

```bash
# Test the scanner against example projects
npx hackmyagent secure test-fixtures/insecure-api     # Score: 27/100
npx hackmyagent secure test-fixtures/insecure-mcp     # Score: 0/100
npx hackmyagent secure test-fixtures/insecure-library # Score: 60/100
npx hackmyagent secure test-fixtures/clean-project    # Score: 100/100

# Test auto-fix
npx hackmyagent secure test-fixtures/insecure-api --fix
```

See [test-fixtures/README.md](test-fixtures/README.md) for details.

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development setup
git clone https://github.com/ecolibria/hackmyagent.git
cd hackmyagent
npm install
npm run build
npm test
```

## License

Apache-2.0

---

**Need enterprise features?** Check out [AIM (Agent Identity Management)](https://github.com/opena2a-org/agent-identity-management) for centralized policy management, compliance, and audit trails.

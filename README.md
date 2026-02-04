# HackMyAgent CLI

[![npm version](https://img.shields.io/npm/v/hackmyagent.svg)](https://www.npmjs.com/package/hackmyagent)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Part of [OpenA2A](https://opena2a.org)** — open-source security for AI agents

**Website:** [hackmyagent.com](https://hackmyagent.com) — Scan external infrastructure for exposed MCP endpoints, configs, and credentials

## Disclaimer

HackMyAgent performs passive reconnaissance only (port checks and HTTP requests) — it does not exploit vulnerabilities. However, please only scan systems you own or have permission to test. The authors assume no liability for misuse of this tool.

```bash
npx hackmyagent check @publisher/skill     # verify a skill before installing
npx hackmyagent secure                      # harden your agent setup (100 checks)
npx hackmyagent secure --fix                # auto-fix security issues
npx hackmyagent scan example.com            # scan for exposed infrastructure
npx hackmyagent attack --local              # red team with 55 attack payloads
npx hackmyagent secure --benchmark oasb-1   # run OASB-1 security benchmark
```

## Two Ways to Scan

| Tool | Use Case |
|------|----------|
| **[hackmyagent.com](https://hackmyagent.com)** | Scan external targets — check if your MCP servers, configs, or credentials are exposed on the internet |
| **`npx hackmyagent secure`** | Scan local projects — harden your agent setup before deploying |

## Why HackMyAgent?

AI agents are powerful but introduce new attack surfaces. Skills can be malicious. Configs can leak secrets. MCP servers can be exposed. HackMyAgent helps you:

- **Check** skills before installing (publisher verification, permission analysis)
- **Secure** your agent setup (100-point CIS security scan, auto-remediation)
- **Scan** external infrastructure (exposed MCP endpoints, leaked configs)

## Installation

```bash
# Use directly with npx
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

**Note:** Only scan systems you own or have permission to test.

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

### `hackmyagent attack`

Red team your AI agent with adversarial security testing. 55 attack payloads across 5 categories.

```bash
# Local simulation (no API calls - test payloads locally)
hackmyagent attack --local
hackmyagent attack --local --system-prompt "You are a helpful assistant"

# Test an API endpoint
hackmyagent attack https://api.example.com/v1/chat
hackmyagent attack https://api.example.com --api-format anthropic

# Filter by category or intensity
hackmyagent attack --local --category prompt-injection
hackmyagent attack --local --intensity aggressive

# Output formats
hackmyagent attack --local -f json
hackmyagent attack --local -f sarif -o results.sarif

# Verbose mode (show each payload result)
hackmyagent attack --local --verbose
```

**Attack Categories:**

| Category | Payloads | Description |
|----------|----------|-------------|
| `prompt-injection` | 12 | Manipulate agent behavior via malicious input |
| `jailbreak` | 12 | Bypass safety guardrails and restrictions |
| `data-exfiltration` | 11 | Extract sensitive information from the agent |
| `capability-abuse` | 10 | Misuse agent tools and capabilities |
| `context-manipulation` | 10 | Poison agent context or memory |

**Intensity Levels:**

| Level | Description |
|-------|-------------|
| `passive` | Observation only, minimal risk |
| `active` | Standard attack payloads (default) |
| `aggressive` | Creative/risky payloads, full suite |

**Output Formats:**
- `text` - Human-readable report (default)
- `json` - Machine-readable JSON
- `sarif` - SARIF 2.1.0 for GitHub Security tab integration

**Risk Scoring:**
- 0-24: LOW - Minor issues, agent is reasonably secure
- 25-49: MEDIUM - Some vulnerabilities, review recommended
- 50-69: HIGH - Significant vulnerabilities, action required
- 70-100: CRITICAL - Severe vulnerabilities, immediate action needed

### `hackmyagent secure --benchmark`

Run the OASB-1 (OpenA2A Security Benchmark) against your agent configuration.

```bash
# Run benchmark (L1 by default)
hackmyagent secure --benchmark oasb-1

# Target specific directory
hackmyagent secure ./my-project --benchmark oasb-1

# Different maturity levels
hackmyagent secure -b oasb-1 -l L1    # Essential (baseline)
hackmyagent secure -b oasb-1 -l L2    # Standard
hackmyagent secure -b oasb-1 -l L3    # Hardened

# Output formats
hackmyagent secure -b oasb-1 -f json
hackmyagent secure -b oasb-1 -f sarif -o results.sarif
hackmyagent secure -b oasb-1 -f html -o report.html
hackmyagent secure -b oasb-1 -f asp -o profile.asp.json

# CI/CD with fail threshold
hackmyagent secure -b oasb-1 --fail-below 70
```

**Output Formats:**
- `text` - Human-readable report (default)
- `json` - Machine-readable JSON
- `sarif` - SARIF 2.1.0 for GitHub/IDE integration
- `html` - Standalone HTML report
- `asp` - Agent Security Profile (HackMyAgent format)

### `hackmyagent secure-openclaw`

Scan OpenClaw/Moltbot installations with 34 specialized security checks and auto-remediation.

```bash
hackmyagent secure-openclaw              # scan default location
hackmyagent secure-openclaw ~/.moltbot   # scan specific directory
hackmyagent secure-openclaw --fix        # auto-fix gateway misconfigurations
hackmyagent secure-openclaw --fix --dry-run  # preview fixes
hackmyagent secure-openclaw --json       # JSON output for CI/CD
```

**Detects:**
- Unsigned/malicious skills (ClawHavoc campaign patterns)
- ClickFix social engineering attacks
- Reverse shell backdoors
- Credential exfiltration (wallets, SSH keys, API keys)
- Heartbeat/cron abuse
- Gateway misconfigurations (GHSA-g8p2 vulnerability)
- Disabled sandbox/approval confirmations

**Auto-Fix (with `--fix`):**
| Check | Before | After |
|-------|--------|-------|
| GATEWAY-001 | `0.0.0.0` | `127.0.0.1` (local-only) |
| GATEWAY-003 | Plaintext token | `${OPENCLAW_AUTH_TOKEN}` env var |
| GATEWAY-004 | Approvals disabled | Approvals enabled |
| GATEWAY-005 | Sandbox disabled | Sandbox enabled |

**Check Categories:**
| Category | Checks | Description |
|----------|--------|-------------|
| SKILL | 12 | Malicious skill detection |
| HEARTBEAT | 6 | Heartbeat/cron abuse |
| GATEWAY | 6 | Gateway misconfigurations (4 auto-fixable) |
| CONFIG | 6 | Insecure settings |
| SUPPLY | 4 | Supply chain attacks |

See [SECURITY_CHECKS.md](docs/SECURITY_CHECKS.md#openclaw-security-checks) for full documentation.

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

### GitHub Actions with Attack Mode (SARIF)

```yaml
name: AI Agent Security
on: [push, pull_request]

jobs:
  attack-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Run attack simulation
        run: npx hackmyagent attack --local -f sarif -o attack-results.sarif
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: attack-results.sarif

  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Run OASB-1 benchmark
        run: npx hackmyagent secure -b oasb-1 --fail-below 70
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

**General (`hackmyagent secure --fix`):**
| Check ID | Issue | Auto-Fix Action |
|----------|-------|-----------------|
| CRED-001 | Exposed API keys | Replace with env var reference |
| GIT-001 | Missing .gitignore | Create with secure defaults |
| GIT-002 | Incomplete .gitignore | Add missing patterns |
| PERM-001 | Overly permissive files | Set restrictive permissions |
| MCP-001 | Root filesystem access | Scope to project directory |
| NET-001 | Bound to 0.0.0.0 | Bind to 127.0.0.1 |

**OpenClaw (`hackmyagent secure-openclaw --fix`):**
| Check ID | Issue | Auto-Fix Action |
|----------|-------|-----------------|
| GATEWAY-001 | Bound to 0.0.0.0 | Bind to 127.0.0.1 |
| GATEWAY-003 | Plaintext token in config | Replace with `${OPENCLAW_AUTH_TOKEN}` |
| GATEWAY-004 | Approvals disabled | Enable approval confirmations |
| GATEWAY-005 | Sandbox disabled | Enable sandbox mode |

Always use `--dry-run` first to preview changes. Backups are created automatically.

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
git clone https://github.com/opena2a-org/hackmyagent.git
cd hackmyagent
npm install
npm run build
npm test
```

## License

Apache-2.0

---

## Secure What You Find

HackMyAgent finds vulnerabilities. **[AIM](https://github.com/opena2a-org/agent-identity-management)** fixes them — the open-source NHI platform for AI agents with cryptographic identity, governance, and access control.

→ [Get started with AIM](https://opena2a.org/docs/quick-start) | [Learn about NHI governance](https://opena2a.org/nhi)

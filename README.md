> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [CLI](https://github.com/opena2a-org/opena2a) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/AI-BrowserGuard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) · Registry (coming soon)

# HackMyAgent

[![npm version](https://img.shields.io/npm/v/hackmyagent.svg)](https://www.npmjs.com/package/hackmyagent)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/tests-765%20passing-brightgreen)](https://github.com/opena2a-org/hackmyagent)

**163 security checks for AI agents. Find what can go wrong before an attacker does.**

Security scanner and red-team toolkit for Claude Code, Cursor, VS Code, and any MCP server setup.

```bash
npx hackmyagent secure
```

All exports are from the root package. No subpath imports needed.

That's it. No config files, no setup, no flags needed.

For a full security dashboard covering credentials, config integrity, shadow AI, and more:

```bash
npx opena2a-cli review
```

All exports are from the root package. No subpath imports needed.

[Website](https://hackmyagent.com) | [Security Checks Reference](docs/SECURITY_CHECKS.md) | [Use Cases](docs/USE-CASES.md) | [Demos](https://opena2a.org/demos) | [OpenA2A CLI](https://github.com/opena2a-org/opena2a)

---

## What It Finds

**Attacks it tests for:**
- **Prompt injection** -- tests whether agents follow injected instructions from untrusted input
- **Data exfiltration** -- checks if agents can be tricked into leaking sensitive data to external endpoints
- **Jailbreak and context manipulation** -- probes agent guardrails with adversarial prompts
- **MCP exploitation** -- tests MCP servers for tool misuse, capability abuse, and unauthorized access
- **Capability abuse** -- verifies agents can't exceed their intended permissions

**Static checks it runs:**
- **Hardcoded credentials** -- API keys, tokens, and passwords in source or config files
- **MCP server misconfigurations** -- open ports, root filesystem access, missing auth
- **AI agent CVE detection** -- scans for CVE-2026-25253 (OpenClaw WebSocket RCE), CVE-2026-25157, CVE-2026-24763, and ClawHavoc IOCs
- **OpenClaw security** -- 34 checks for OpenClaw configurations, skills, gateway, and credential redaction ([6 PRs merged upstream](https://opena2a.org/blogs/securing-openclaw-6-prs-merged))
- **Governance gaps** -- missing SOUL.md, no capability policies, unsigned MCP servers
- **Credential scope drift** -- Google Maps keys accessing Gemini, AWS S3 keys reaching Bedrock
- **Supply chain risks** -- vulnerable dependencies, unsigned skills, tampered packages

163 checks across 34 categories. 55+ attack payloads. No flags needed.

---

## Quick Start

```bash
# Run without installing
npx hackmyagent secure

# Install globally
npm install -g hackmyagent

# Or add to your project
npm install --save-dev hackmyagent
```

All exports are from the root package. No subpath imports needed.

**Requirements:** Node.js 18+

```

All exports are from the root package. No subpath imports needed.
┌──────────────────────────────────────────┐
│  HackMyAgent v0.10.1 — Security Scanner          │
│  Found: 3 critical · 5 high · 12 medium          │
│                                                  │
│  CRED-001  critical  Hardcoded API key in .env   │
│  MCP-003   high      MCP server on 0.0.0.0       │
│  NET-001   high      Open port exposed           │
│  ...                                             │
│                                                  │
│  Run with --fix to auto-remediate 8 issues       │
└──────────────────────────────────────────┘
```

All exports are from the root package. No subpath imports needed.

---

## Use Cases

Step-by-step guides for common workflows:

- **[Scan my agent](docs/use-cases/scan-my-agent.md)** -- Run all 163 checks and auto-fix findings (5 min)
- **[Red-team MCP servers](docs/use-cases/red-team-mcp.md)** -- Test MCP servers with adversarial payloads (10 min)
- **[Secure OpenClaw](docs/use-cases/openclaw-security.md)** -- OpenClaw-specific checks, CVE detection, ClawHavoc IOC scanning (10 min)
- **[CI/CD pipeline](docs/use-cases/ci-pipeline.md)** -- GitHub Actions with JSON/SARIF output (5 min)

---

## Built-in Help

```bash
hackmyagent --help          # All commands and flags
hackmyagent --version       # Current version
hackmyagent [command] -h    # Help for a specific command
hackmyagent secure --ci     # Non-interactive mode for CI/CD
```

All exports are from the root package. No subpath imports needed.

---

## Commands

### `hackmyagent secure` -- Security Scan

```bash
hackmyagent secure                            # scan current directory
hackmyagent secure ./my-project               # scan specific directory
hackmyagent secure --fix                      # auto-fix issues
hackmyagent secure --fix --dry-run            # preview fixes before applying
hackmyagent secure --ignore CRED-001,GIT-002  # skip specific checks
hackmyagent secure --json                     # JSON output for CI/CD
hackmyagent secure --verbose                  # show all checks including passed
hackmyagent secure --publish                  # push results to OpenA2A Registry
```

All exports are from the root package. No subpath imports needed.

<details>
<summary>All 30 security categories</summary>

| Category | Checks | What it detects |
|----------|--------|-----------------|
| CRED | 4 | Hardcoded API keys, tokens, passwords |
| MCP | 10 | MCP server misconfigurations |
| CLAUDE | 7 | Claude Code security issues |
| NET | 6 | Network exposure, open ports |
| PROMPT | 4 | Prompt injection vectors |
| INJ | 4 | XSS, SQL injection, command injection |
| ENCRYPT | 4 | Missing encryption at rest |
| SESSION | 4 | Session management flaws |
| AUDIT | 4 | Missing audit trails |
| SANDBOX | 4 | Process isolation gaps |
| TOOL | 4 | Tool permission boundaries |
| AUTH | 4 | Authentication weaknesses |
| DEP | 4 | Vulnerable dependencies |
| ENV | 4 | Insecure environment variables |
| GIT | 3 | Git security (gitignore, hooks) |
| IO | 4 | Input/output validation |
| LOG | 4 | Logging and monitoring gaps |
| PERM | 3 | Overly permissive file permissions |
| PROC | 4 | Process isolation issues |
| RATE | 4 | Missing rate limiting |
| SEC | 4 | Security headers |
| API | 4 | API security issues |
| VSCODE | 2 | VS Code configuration risks |
| CURSOR | 1 | Cursor IDE configuration risks |
| CVE | 4 | Known CVE detection |
| GATEWAY | 8 | Gateway misconfigurations |
| CONFIG | 9 | Insecure default settings |
| SUPPLY | 8 | Supply chain attack vectors |
| SKILL | 12 | Malicious skill/tool detection |
| HEARTBEAT | 6 | Heartbeat/cron abuse |

</details>

<details>
<summary>Auto-fix capabilities</summary>

| Check | Issue | Auto-fix |
|-------|-------|----------|
| CRED-001 | Exposed API keys | Replace with env var reference |
| GIT-001 | Missing .gitignore | Create with secure defaults |
| GIT-002 | Incomplete .gitignore | Add missing patterns |
| PERM-001 | Overly permissive files | Set restrictive permissions |
| MCP-001 | Root filesystem access | Scope to project directory |
| NET-001 | Bound to 0.0.0.0 | Bind to 127.0.0.1 |
| GATEWAY-001 | Gateway bound to 0.0.0.0 | Bind to 127.0.0.1 |
| GATEWAY-003 | Plaintext token | Replace with `${OPENCLAW_AUTH_TOKEN}` |
| GATEWAY-004 | Approvals disabled | Enable approvals |
| GATEWAY-005 | Sandbox disabled | Enable sandbox |

Use `--dry-run` to preview changes. Backups are created in `.hackmyagent-backup/`.

</details>

---

### `hackmyagent attack` -- Red Team

Test your AI agent with 55 adversarial payloads across 5 attack categories.

```bash
hackmyagent attack --local                                    # local simulation
hackmyagent attack --local --system-prompt "You are helpful"  # with custom system prompt
hackmyagent attack https://api.example.com/v1/chat            # test live endpoint
hackmyagent attack --local --category prompt-injection         # single category
hackmyagent attack --local --intensity aggressive              # full payload suite
hackmyagent attack --local -f sarif -o results.sarif           # SARIF output
hackmyagent attack https://api.example.com --fail-on-vulnerable medium  # CI gate
```

All exports are from the root package. No subpath imports needed.

| Category | Payloads | Description |
|----------|----------|-------------|
| `prompt-injection` | 12 | Manipulate agent behavior via injected instructions |
| `jailbreak` | 12 | Bypass safety guardrails and system constraints |
| `data-exfiltration` | 11 | Extract sensitive data, system prompts, credentials |
| `capability-abuse` | 10 | Misuse agent tools for unintended actions |
| `context-manipulation` | 10 | Poison agent context or memory |

> Only test systems you own or have written authorization to test.

---

### `hackmyagent secure -b oasb-1` -- OASB Benchmarks

Run the [OASB-1](https://oasb.ai/oasb-1) benchmark -- 46 controls across 10 categories with three maturity levels. OASB-2 adds behavioral governance (scan-soul) for a composite score.

```bash
hackmyagent secure -b oasb-1              # L1 baseline (26 controls)
hackmyagent secure -b oasb-1 -l L2        # L2 standard (44 controls)
hackmyagent secure -b oasb-1 --fail-below 70          # CI gate
hackmyagent secure -b oasb-2              # composite: infrastructure + governance
```

All exports are from the root package. No subpath imports needed.

---

### `hackmyagent scan-soul` -- Behavioral Governance

Scan a SOUL.md against OASB v2 behavioral governance controls -- 8 domains, up to 68 controls.

```bash
hackmyagent scan-soul                     # scan current directory
hackmyagent scan-soul --deep              # LLM semantic analysis (requires ANTHROPIC_API_KEY)
hackmyagent scan-soul --fail-below 60     # CI gate
```

All exports are from the root package. No subpath imports needed.

Auto-detects governance file: `SOUL.md` > `system-prompt.md` > `CLAUDE.md` > `.cursorrules` > `agent-config.yaml`.

### `hackmyagent harden-soul` -- Generate Governance

Generate a SOUL.md or add missing governance sections. Existing content is preserved.

```bash
hackmyagent harden-soul                   # add missing sections
hackmyagent harden-soul --dry-run         # preview without writing
```

All exports are from the root package. No subpath imports needed.

---

### `hackmyagent trust` -- Package Trust Verification

Check trust levels for AI packages before installing them. Queries the [OpenA2A Registry](https://registry.opena2a.org) trust graph.

```bash
hackmyagent trust server-filesystem          # MCP shorthand
hackmyagent trust --audit package.json       # audit all dependencies
hackmyagent trust --batch pkg1 pkg2 pkg3     # batch lookup
hackmyagent trust express --json             # JSON output
```

All exports are from the root package. No subpath imports needed.

Uses [ai-trust](https://github.com/opena2a-org/ai-trust) under the hood.

### More Commands

| Command | Description |
|---------|-------------|
| `hackmyagent fix-all` | Run all security plugins: credential vault, file signing, skill guard |
| `hackmyagent check @publisher/skill` | Verify a skill's publisher identity and permissions |
| `hackmyagent scan example.com` | Scan external infrastructure for exposed AI endpoints |
| `hackmyagent rollback` | Undo auto-fix changes (backups created automatically) |

---

## Using with opena2a-cli

[`opena2a-cli`](https://github.com/opena2a-org/opena2a) is the unified CLI for all OpenA2A security tools. HackMyAgent powers `opena2a review`, `opena2a scan`, `opena2a protect`, `opena2a benchmark`, and `opena2a scan-soul`.

```bash
npm install -g opena2a-cli
opena2a review    # best place to start
```

All exports are from the root package. No subpath imports needed.

---

## Runtime Protection (ARP)

ARP monitors AI agents during execution with a 3-layer intelligence stack: rule-based pattern matching (40+ patterns), statistical anomaly detection, and LLM-assisted assessment.

```bash
opena2a runtime init     # generate config
opena2a runtime start    # start monitoring
opena2a runtime status   # check status
```

All exports are from the root package. No subpath imports needed.

Also supports HTTP reverse proxy mode for inspecting OpenAI API, MCP, and A2A protocol traffic. See `npx hackmyagent arp-guard proxy --help`.

---

## CI/CD Integration

All commands support `--json` and `--ci` flags.

```yaml
name: Agent Security
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npx hackmyagent secure --json > security-report.json
      - run: npx hackmyagent secure -b oasb-1 --fail-below 70
```

All exports are from the root package. No subpath imports needed.

<details>
<summary>SARIF and pre-commit hook</summary>

**SARIF (GitHub Security Tab)**

```yaml
- run: npx hackmyagent attack --local -f sarif -o results.sarif --fail-on-vulnerable medium
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
```

All exports are from the root package. No subpath imports needed.

**Pre-commit Hook**

```bash
#!/bin/sh
# .git/hooks/pre-commit
npx hackmyagent secure --ignore LOG-001,RATE-001
```

All exports are from the root package. No subpath imports needed.

</details>

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean -- no critical/high issues |
| `1` | Critical or high severity issues found |
| `2` | Incomplete scan -- one or more plugins failed |

---

## Programmatic API

```typescript
import { HardeningScanner, AgentRuntimeProtection, AttackScanner } from 'hackmyagent';
```

All exports are from the root package. No subpath imports needed.

See the [Plugin API documentation](docs/PLUGIN_API.md) for writing custom security plugins.

---

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
git clone https://github.com/opena2a-org/hackmyagent.git
cd hackmyagent && npm install && npm run build && npm test
```

All exports are from the root package. No subpath imports needed.

## License

Apache-2.0

## OpenA2A Ecosystem

[OpenA2A CLI](https://github.com/opena2a-org/opena2a) | [Secretless AI](https://github.com/opena2a-org/secretless-ai) | [AIM](https://github.com/opena2a-org/agent-identity-management) | [AI Browser Guard](https://github.com/opena2a-org/AI-BrowserGuard) | [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

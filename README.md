> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [CLI](https://github.com/opena2a-org/opena2a) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/AI-BrowserGuard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)
# HackMyAgent

[![npm version](https://img.shields.io/npm/v/hackmyagent.svg)](https://www.npmjs.com/package/hackmyagent)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/tests-1301%20passing-brightgreen)](https://github.com/opena2a-org/hackmyagent)
[![NanoMind](https://img.shields.io/badge/NanoMind-semantic%20compiler-teal)](https://huggingface.co/ecolibria/nanomind-v0.1-security-classifier)

**204 security checks + 28 semantic checks + behavioral simulation. The first security scanner that secures itself.**

Security scanner, red-team toolkit, behavioral simulation engine, and skill builder for AI agents. Powered by the NanoMind Semantic Compiler -- a compiler-style architecture where every artifact is compiled into an Abstract Security Tree before analysis.

[Seven scanners agree on only 0.12% of skills](https://theweatherreport.ai/posts/skill-scanner-disagreement/). HackMyAgent uses semantic understanding instead of regex to achieve near-zero false positives.

```bash
npx hackmyagent secure
```


That's it. No config files, no setup, no flags needed.

![HackMyAgent Demo](docs/hackmyagent-demo.gif)

[More demos](https://opena2a.org/demos)

For a full security dashboard covering credentials, config integrity, shadow AI, and more:

```bash
npx opena2a-cli review
```


[Website](https://hackmyagent.com) | [Security Checks Reference](docs/SECURITY_CHECKS.md) | [Use Cases](docs/USE-CASES.md) | [Demos](https://opena2a.org/demos) | [OpenA2A CLI](https://github.com/opena2a-org/opena2a)

---

## What It Finds

**NanoMind Semantic Compiler** -- compiles every artifact (skills, MCP configs, SOUL.md, system prompts) into an Abstract Security Tree. 28 semantic checks query the AST instead of regex on raw text. Catches what pattern matching can't: undeclared capabilities, constraint weakness, scope mismatches, scanner evasion attempts.

**Self-securing** -- verifies its own binary integrity on every startup. Tampered binaries enter QUARANTINE mode (exit code 3). Tampered models fall back to baseline. The first security scanner that secures itself.

**Behavioral simulation** -- 20-probe simulation battery that observes what skills actually do, not what they look like. Run with `--deep`.

**Adaptive red team** -- `hackmyagent red-team <file>` generates target-specific attack payloads, observes responses, adapts after failures, and maps all defenses.

**Skills builder** -- `hackmyagent create-skill "describe what you need"` generates a complete, secured skill with SOUL.md governance, capability manifest, and security metadata.

**Attack testing** -- 115 adversarial payloads across 11 categories (prompt injection, data exfiltration, jailbreak, MCP exploitation, supply chain, memory weaponization, A2A protocol attacks, context window attacks).

**Static analysis** -- 204 security checks across 60 categories covering credentials, MCP configs, OpenClaw/NemoClaw, Unicode steganography, CVE detection, governance, supply chain, memory poisoning, agent identity, and sandbox escape patterns.

<details>
<summary>Attack testing details (115 payloads)</summary>

- **Prompt injection** -- tests whether agents follow injected instructions from untrusted input
- **Data exfiltration** -- checks if agents can be tricked into leaking sensitive data to external endpoints
- **Jailbreak and context manipulation** -- probes agent guardrails with adversarial prompts
- **MCP exploitation** -- tests MCP servers for tool misuse, capability abuse, and unauthorized access
- **Capability abuse** -- verifies agents can't exceed their intended permissions
- **Supply chain attacks** -- dependency confusion, tool shadowing, package impersonation
- **Memory weaponization** -- persistent instruction injection via agent memory systems
- **A2A protocol attacks** -- identity spoofing, capability escalation in multi-agent communication
- **Context window attacks** -- token flooding, attention manipulation, context poisoning

</details>

<details>
<summary>Static analysis details (204 checks)</summary>

- **Unicode steganography** -- invisible codepoints, zero-width chars, bidi attacks, homoglyph confusables, GlassWorm decoders ([real-world: os-info-checker-es6 npm attack, May 2025](https://thehackernews.com/2025/05/malicious-npm-package-leverages-unicode.html))
- **Hardcoded credentials** -- API keys, tokens, and passwords in source or config files
- **MCP server misconfigurations** -- open ports, root filesystem access, missing auth
- **AI agent CVE detection** -- CVE-2026-25253 (OpenClaw RCE), CVE-2026-25157, CVE-2026-24763, ClawHavoc IOCs
- **OpenClaw security** -- 34 checks for configurations, skills, gateway, credential redaction ([6 PRs merged upstream](https://opena2a.org/blogs/securing-openclaw-6-prs-merged))
- **NemoClaw/sandbox patterns** -- curl-pipe without checksum, empty artifact digests, exec() injection, predictable /tmp paths, process.env leakage, TOCTOU races, unsafe deserialization, messaging API egress
- **Governance gaps** -- missing SOUL.md, no capability policies, unsigned MCP servers
- **Credential scope drift** -- Google Maps keys accessing Gemini, AWS S3 keys reaching Bedrock
- **Supply chain risks** -- vulnerable dependencies, unsigned skills, tampered packages
- **Memory and RAG poisoning** -- persistent instruction injection, knowledge base contamination
- **Agent identity** -- missing cryptographic identity, capability claims without attestation

</details>

204 checks across 60 categories. 115 attack payloads. No flags needed.

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


**Requirements:** Node.js 18+

```
┌─────────────────────────────────────────────────────┐
│  HackMyAgent v0.12.1 -- Security Scanner             │
│  Found: 3 critical · 5 high · 12 medium             │
│                                                     │
│  CRED-001  critical  Hardcoded API key in .env      │
│  MCP-003   high      MCP server on 0.0.0.0          │
│  NET-001   high      Open port exposed              │
│  ...                                                │
│                                                     │
│  Run with --fix to auto-remediate 8 issues          │
└─────────────────────────────────────────────────────┘
```


---

## Use Cases

Step-by-step guides for common workflows:

- **[Scan my agent](docs/use-cases/scan-my-agent.md)** -- Run all 204 checks and auto-fix findings (5 min)
- **[Red-team MCP servers](docs/use-cases/red-team-mcp.md)** -- Test MCP servers with adversarial payloads (10 min)
- **[Secure OpenClaw](docs/use-cases/openclaw-security.md)** -- Auto-detected when OpenClaw files are present. Includes CVE detection and ClawHavoc IOC scanning (10 min)
- **[CI/CD pipeline](docs/use-cases/ci-pipeline.md)** -- GitHub Actions with JSON/SARIF output (5 min)

---

## Built-in Help

```bash
hackmyagent --help          # All commands and flags
hackmyagent --version       # Current version
hackmyagent [command] -h    # Help for a specific command
hackmyagent secure --ci     # Non-interactive mode for CI/CD
```


---

## Commands

### `hackmyagent secure` -- Security Scan

```bash
hackmyagent secure                            # scan current directory
hackmyagent secure ./my-project               # scan specific directory
hackmyagent secure --deep                     # full behavioral simulation (20 probes)
hackmyagent secure --static-only              # static checks only (fast, CI mode)
hackmyagent secure --fix                      # auto-fix issues
hackmyagent secure --fix --dry-run            # preview fixes before applying
hackmyagent secure --ignore CRED-001,GIT-002  # skip specific checks
hackmyagent secure --json                     # JSON output for CI/CD
hackmyagent secure --verbose                  # show all checks including passed
hackmyagent secure --publish                  # push results to OpenA2A Registry
```

### `hackmyagent red-team` -- Adaptive Attack Engine

```bash
hackmyagent red-team ./my-skill.md            # red-team a skill file
hackmyagent red-team ./SOUL.md --iterations 10 # more attack iterations
hackmyagent red-team ./mcp-config.json --json  # JSON output
```

Generates target-specific attacks from the skill's own language and constraints. Iterates up to 5x per attack category, maps all defenses, and produces specific remediation.

### `hackmyagent explain` -- Finding Explanations

```bash
hackmyagent explain CRED-001                  # explain a finding
hackmyagent explain SKILL-SEMANTIC-007        # explain NanoMind finding
```


<details>
<summary>All 35 security categories</summary>

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
| HEARTBEAT | 7 | Heartbeat/cron abuse |
| UNICODE-STEGO | 5 | Invisible codepoints, zero-width chars, bidi attacks, homoglyphs, GlassWorm decoders |
| MEM | 5 | Memory poisoning, context injection |
| RAG | 4 | RAG/knowledge base poisoning |
| AIM | 3 | Agent identity verification |
| NEMO | 10 | NemoClaw/sandbox patterns: curl-pipe, digest bypass, exec injection, /tmp races, env leakage |

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

Test your AI agent with 115 adversarial payloads across 11 attack categories.

```bash
hackmyagent attack --local                                    # local simulation
hackmyagent attack --local --system-prompt "You are helpful"  # with custom system prompt
hackmyagent attack https://api.example.com/v1/chat            # test live endpoint
hackmyagent attack --local --category prompt-injection         # single category
hackmyagent attack --local --intensity aggressive              # full payload suite
hackmyagent attack --local -f sarif -o results.sarif           # SARIF output
hackmyagent attack https://api.example.com --fail-on-vulnerable medium  # CI gate
```


| Category | Payloads | Description |
|----------|----------|-------------|
| `prompt-injection` | 12 | Manipulate agent behavior via injected instructions |
| `jailbreak` | 12 | Bypass safety guardrails and system constraints |
| `data-exfiltration` | 11 | Extract sensitive data, system prompts, credentials |
| `capability-abuse` | 10 | Misuse agent tools for unintended actions |
| `context-manipulation` | 10 | Poison agent context or memory |
| `supply-chain` | 10 | Dependency confusion, package impersonation |
| `tool-shadow` | 10 | Tool shadowing, capability escalation |
| `mcp-exploitation` | 10 | MCP protocol abuse, tool injection |
| `memory-weaponization` | 10 | Persistent memory poisoning attacks |
| `a2a-attacks` | 10 | Agent-to-agent identity spoofing |
| `context-window` | 10 | Token flooding, attention manipulation |

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


---

### `hackmyagent scan-soul` -- Behavioral Governance

Scan a SOUL.md against OASB v2 behavioral governance controls -- 8 domains, up to 68 controls.

```bash
hackmyagent scan-soul                     # scan current directory
hackmyagent scan-soul --deep              # LLM semantic analysis (requires ANTHROPIC_API_KEY)
hackmyagent scan-soul --fail-below 60     # CI gate
```


Auto-detects governance file: `SOUL.md` > `system-prompt.md` > `CLAUDE.md` > `.cursorrules` > `agent-config.yaml`.

### `hackmyagent harden-soul` -- Generate Governance

Generate a SOUL.md or add missing governance sections. Existing content is preserved.

```bash
hackmyagent harden-soul                   # add missing sections
hackmyagent harden-soul --dry-run         # preview without writing
```


---

### OpenClaw and NemoClaw Detection

`hackmyagent secure` auto-detects OpenClaw and NemoClaw installations by looking for `.openclaw/`, `.moltbot/`, `.nemoclaw/`, `openclaw.json`, and `openclaw.plugin.json`. When detected, it automatically runs platform-specific checks (28 NemoClaw checks, 34 OpenClaw checks) alongside the standard 204 security checks. No separate commands needed.


---

### `hackmyagent trust` -- Package Trust Verification

Check trust levels for AI packages before installing them. Queries the OpenA2A Registry trust graph (launching April 2026).

```bash
hackmyagent trust server-filesystem          # MCP shorthand
hackmyagent trust --audit package.json       # audit all dependencies
hackmyagent trust --batch pkg1 pkg2 pkg3     # batch lookup
hackmyagent trust express --json             # JSON output
```


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


---

## Runtime Protection (ARP)

ARP monitors AI agents during execution with a 3-layer intelligence stack: rule-based pattern matching (40+ patterns), statistical anomaly detection, and LLM-assisted assessment.

```bash
opena2a runtime init     # generate config
opena2a runtime start    # start monitoring
opena2a runtime status   # check status
```


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


<details>
<summary>SARIF and pre-commit hook</summary>

**SARIF (GitHub Security Tab)**

```yaml
- run: npx hackmyagent attack --local -f sarif -o results.sarif --fail-on-vulnerable medium
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
```


**Pre-commit Hook**

```bash
#!/bin/sh
# .git/hooks/pre-commit
npx hackmyagent secure --ignore LOG-001,RATE-001
```


</details>

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean -- no critical/high issues |
| `1` | Critical or high severity issues found |
| `2` | Incomplete scan -- one or more plugins failed |
| `3` | QUARANTINE -- binary integrity check failed (tampered installation) |

---

## Programmatic API

```typescript
import { HardeningScanner, AgentRuntimeProtection, AttackScanner } from 'hackmyagent';

// NanoMind Semantic Compiler -- compile artifacts into Abstract Security Trees
import {
  SemanticCompiler,
  analyzeCapabilities,
  analyzeCredentials,
  analyzeGovernance,
  analyzeScope,
  analyzePrompt,
  analyzeCode,
  getTMEClassifier,
} from 'hackmyagent/nanomind-core';

const compiler = new SemanticCompiler();
const { ast } = await compiler.compile(skillContent, 'my-skill.skill.md');
// ast.intentClassification: 'benign' | 'suspicious' | 'malicious'
// ast.inferredCapabilities, ast.declaredConstraints, ast.inferredRiskSurface
const findings = analyzeCapabilities(ast);
```


See the [Plugin API documentation](docs/PLUGIN_API.md) for writing custom security plugins.

---

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
git clone https://github.com/opena2a-org/hackmyagent.git
cd hackmyagent && npm install && npm run build && npm test
```


## License

Apache-2.0

HackMyAgent is part of the [OpenA2A](https://opena2a.org) security platform. See all tools: [opena2a.org](https://opena2a.org)

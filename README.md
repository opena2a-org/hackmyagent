> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [CLI](https://github.com/opena2a-org/opena2a) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/AI-BrowserGuard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)
# HackMyAgent

[![npm version](https://img.shields.io/npm/v/hackmyagent.svg)](https://www.npmjs.com/package/hackmyagent)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/tests-1757%20passing-brightgreen)](https://github.com/opena2a-org/hackmyagent)
[![NanoMind](https://img.shields.io/badge/NanoMind-semantic%20compiler-teal)](https://huggingface.co/opena2a/nanomind-security-classifier)

**209 static security checks + 29 NanoMind semantic checks + 164 adversarial payloads.**

Security scanner, red-team toolkit, and behavioural simulation engine for AI agents. Every artifact (skill, MCP config, SOUL.md, system prompt) is compiled into an Abstract Security Tree before analysis -- semantic understanding, not regex.

```bash
npx hackmyagent secure
```

No config files, no setup, no flags needed.

![HackMyAgent Demo](docs/hackmyagent-demo.gif)

[More demos](https://opena2a.org/demos)

For a full security dashboard covering credentials, config integrity, shadow AI, and more:

```bash
npx opena2a-cli review
```

[Website](https://hackmyagent.com) | [Security Checks Reference](docs/SECURITY_CHECKS.md) | [Use Cases](docs/USE-CASES.md) | [Demos](https://opena2a.org/demos) | [OpenA2A CLI](https://github.com/opena2a-org/opena2a)

---

## What It Finds

- **NanoMind Semantic Compiler** -- compiles every artifact into an Abstract Security Tree. 29 semantic checks query the AST instead of regex on raw text. Catches what pattern matching can't: undeclared capabilities, constraint weakness, scope mismatches, scanner evasion attempts.
- **209 static checks across 44 categories** -- credentials, MCP configs, OpenClaw / NemoClaw, Unicode steganography, CVEs, governance, supply chain, memory / RAG poisoning, agent identity, sandbox escape.
- **Adaptive red team** -- `hackmyagent red-team <file>` generates target-specific payloads, observes responses, adapts after failures, and maps every defence.
- **164 adversarial payloads across 16 categories** -- prompt injection, jailbreak, data exfiltration, capability abuse, context manipulation, MCP / A2A exploitation, memory weaponisation, context window, supply chain, tool shadow, parser differential, persistent agent, fake tool, context lifecycle, policy enforcement.
- **Behavioural simulation** -- 20-probe battery that observes what skills actually do (run with `--deep`).
- **Self-securing** -- verifies its own binary on startup against an embedded SHA-256 manifest. Post-install tampered binaries enter QUARANTINE mode (exit code 3) with a per-file forensics report. Symlink-redirected manifests are rejected. For end-to-end supply-chain verification against rebuild attacks, every release ships SLSA v1 provenance via npm Trusted Publishing -- verify with `npm view hackmyagent@<version> dist.attestations --json`.

Full catalogue in [`docs/SECURITY_CHECKS.md`](docs/SECURITY_CHECKS.md).

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
  my-project  v1.0.0 · library
  3 critical issues found

  Security  ━━━━━━━━━━━━━━━━━━━━ 42/100

  ── Observations ────────────────────────────────────────────
  Surfaces    library · 47 files
  Checks      209 static · 12 semantic (NanoMind AST) · 0 skipped
  Categories  credentials (3 critical) · MCP (2 high) · 18 others clear
  Verdict     Not safe to ship. Fix 3 critical issues before using this
              in production.

  ── Findings ────────────────────────────────────────────────
  │ CRITICAL  Hardcoded API key in .env
  │ .env:3
  │ sk-ant-api03-**** (Anthropic API key detected)
  │ →  hackmyagent secure --fix
```

---

## Scan Anything

`hackmyagent check <target>` accepts any of these. `secure` scans your own project. `scan-soul` scans governance.

| Surface                  | Command                                              | What gets scanned                                 |
|--------------------------|------------------------------------------------------|---------------------------------------------------|
| Your own project         | `hackmyagent secure`                                 | 209 static checks + NanoMind on current directory |
| A local directory        | `hackmyagent check ./my-agent/`                      | tree + auto-detected artifacts                    |
| An npm package           | `hackmyagent check express`                          | downloads tarball, scans before you install       |
| A PyPI package           | `hackmyagent check pip:requests`                     | downloads sdist, scans before you install         |
| A GitHub repo            | `hackmyagent check getsentry/sentry-mcp`             | clones, scans, reports                            |
| A published skill        | `hackmyagent check @publisher/skill`                 | signature verification + 29 semantic checks       |
| A local skill directory  | `hackmyagent check ./my-skill/`                      | skill files + SOUL.md + manifest                  |
| An MCP server config     | `hackmyagent check ./my-mcp-server/`                 | MCP config + declared tools + scope + dependencies (point at the directory, not the single JSON file) |
| An A2A agent card        | `hackmyagent check ./my-agent/`                      | agent-card capabilities + identity (point at the directory containing the card) |
| A URL tarball            | `hackmyagent check https://ex.com/pkg.tar.gz`        | downloads, scans                                  |
| External infrastructure  | `hackmyagent scan example.com`                       | external AI-endpoint inventory                    |
| Governance (SOUL.md)     | `hackmyagent scan-soul`                              | SOUL.md against OASB v2 behavioural controls      |

### secure vs. check vs. red-team vs. attack

- **`secure`** -- your own project. Full 209-check scan, auto-fix option, designed for recurring use and CI.
- **`check`** -- something you don't own yet. Pre-install trust check for any surface above.
- **`red-team`** -- generate adaptive attacks against a specific skill / MCP / SOUL. You've scanned it; now you want to see if it resists.
- **`attack`** -- test a live endpoint or local simulation with 164 pre-built adversarial payloads.

---

## Commands

### `hackmyagent secure` -- Security Scan

```bash
hackmyagent secure                            # scan current directory
hackmyagent secure --fix                      # auto-fix issues (backups in .hackmyagent-backup/)
hackmyagent secure --fix --dry-run            # preview fixes before applying
hackmyagent secure --deep                     # full behavioural simulation (20 probes)
hackmyagent secure --static-only              # static checks only (fast, CI mode)
hackmyagent secure --ignore CRED-001,GIT-002  # skip specific checks
hackmyagent secure --json                     # JSON output for CI/CD
hackmyagent secure --publish                  # push anonymised results to OpenA2A Registry
hackmyagent secure -b oasb-1                  # OASB-1 benchmark (46 controls, L1/L2/L3 levels)
hackmyagent secure -b oasb-1 --fail-below 70  # CI gate
```

Output shows an Observations block (surfaces · checks · categories · verdict) and a per-finding list. Every HIGH / CRITICAL finding has a `file:line` location and a runnable `Fix:` command.

### NanoMind Semantic Analysis

Runs automatically on every `secure` scan. On first use it downloads a ~5.5 MB ONNX classifier from HuggingFace and caches it locally.

- **7 AST analysers**: `capability`, `credential`, `governance`, `scope`, `prompt`, `code`, `stego`.
- **9 attack classes**: exfiltration, injection, privilege_escalation, persistence, credential_abuse, lateral_movement, social_engineering, policy_violation, benign.
- **Flags**: `--deep` adds 20-probe behavioural simulation; `--static-only` disables the semantic layer; `--nanomind` opts into per-finding AI threat narratives (specialist model -- does not produce scan-wide summaries).

### `hackmyagent red-team` -- Adaptive Attack Engine

```bash
hackmyagent red-team ./my-skill.md             # red-team a skill file
hackmyagent red-team ./SOUL.md --iterations 10 # more attack iterations
hackmyagent red-team ./mcp-config.json --json  # JSON output
```

Generates target-specific attacks from the artifact's own language and constraints. Iterates up to 5x per category, maps defences, produces specific remediation.

### `hackmyagent attack` -- Red-Team Payload Battery

```bash
hackmyagent attack --local                                              # local simulation
hackmyagent attack --local --system-prompt "You are helpful"            # with custom system prompt
hackmyagent attack https://api.example.com/v1/chat                      # test live endpoint
hackmyagent attack --local --category prompt-injection                  # single category
hackmyagent attack https://api.example.com --fail-on-vulnerable medium  # CI gate
```

164 payloads across 16 categories: `prompt-injection`, `jailbreak`, `data-exfiltration`, `capability-abuse`, `context-manipulation`, `mcp-exploitation`, `a2a-attack`, `memory-weaponization`, `context-window`, `supply-chain`, `tool-shadow`, `parser-differential`, `persistent-agent`, `fake-tool`, `context-lifecycle`, `policy-enforcement-integrity`. Full payload catalogue in [`docs/SECURITY_CHECKS.md`](docs/SECURITY_CHECKS.md).

> Only test systems you own or have written authorisation to test.

### `hackmyagent scan-soul` / `harden-soul` -- Governance

```bash
hackmyagent scan-soul                     # scan current directory for SOUL.md
hackmyagent scan-soul --deep              # LLM semantic analysis (requires ANTHROPIC_API_KEY)
hackmyagent scan-soul --fail-below 60     # CI gate
hackmyagent harden-soul                   # generate / add missing governance sections
hackmyagent harden-soul --dry-run         # preview without writing
```

Auto-detects governance file: `SOUL.md` > `system-prompt.md` > `CLAUDE.md` > `.cursorrules` > `agent-config.yaml`.

### `hackmyagent detect` -- Shadow AI Audit

```bash
hackmyagent detect                              # audit current directory
hackmyagent detect /path/to/project             # audit a specific project
hackmyagent detect --json                       # machine-readable output
hackmyagent detect --export-csv inventory.csv   # asset inventory for CMDB
```

Inventory of AI tools, MCP servers, and governance gaps across your machine. Detects Claude Code / Cursor / Copilot, MCP configurations (project-local and machine-wide), AI config files with credential references or broad permission grants, and SOUL.md files.

### `hackmyagent trust` / `explain` / `nanomind`

```bash
hackmyagent trust server-filesystem      # MCP shorthand trust lookup (Registry)
hackmyagent trust --audit package.json   # audit all dependencies
hackmyagent explain CRED-001             # explain a check finding
hackmyagent nanomind setup               # download optional generative model
hackmyagent nanomind status              # check model + runtime status
```

### OpenClaw / NemoClaw Auto-detection

`hackmyagent secure` auto-detects OpenClaw / NemoClaw installations (`.openclaw/`, `.moltbot/`, `.nemoclaw/`, `openclaw.json`, `openclaw.plugin.json`). When detected, 28 NemoClaw + 34 OpenClaw checks run alongside the standard 209. No separate command needed.

### Use-case walkthroughs

- [Scan my agent](docs/use-cases/scan-my-agent.md) -- 209 checks + auto-fix (5 min)
- [Red-team MCP servers](docs/use-cases/red-team-mcp.md) -- adversarial payloads (10 min)
- [Secure OpenClaw](docs/use-cases/openclaw-security.md) -- CVE detection + ClawHavoc IOCs (10 min)
- [CI/CD pipeline](docs/use-cases/ci-pipeline.md) -- GitHub Actions with JSON / SARIF (5 min)

### Built-in help

```bash
hackmyagent --help          # All commands and flags
hackmyagent --version       # Current version
hackmyagent <command> -h    # Help for a specific command
hackmyagent secure --ci     # Non-interactive mode for CI/CD
```

<details>
<summary>Auto-fix catalogue</summary>

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

Use `--dry-run` to preview changes. Backups in `.hackmyagent-backup/`.

</details>

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

Also supports HTTP reverse-proxy mode for inspecting OpenAI API, MCP, and A2A protocol traffic. See `npx hackmyagent arp-guard proxy --help`.

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
<summary>SARIF output and pre-commit hook</summary>

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
| `0` | Clean -- no critical / high issues |
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

See [Plugin API documentation](docs/PLUGIN_API.md) for writing custom security plugins.

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

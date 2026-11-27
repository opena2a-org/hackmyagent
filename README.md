# HackMyAgent

[![Status: stable](https://img.shields.io/badge/status-stable-green)](STATUS.md)
[![npm version](https://img.shields.io/npm/v/hackmyagent.svg)](https://www.npmjs.com/package/hackmyagent)
[![Tests](https://github.com/opena2a-org/hackmyagent/actions/workflows/test-matrix.yml/badge.svg?branch=main)](https://github.com/opena2a-org/hackmyagent/actions/workflows/test-matrix.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> **[OpenA2A](https://github.com/opena2a-org)**: [CLI](https://github.com/opena2a-org/opena2a) · **HackMyAgent** · [Secretless](https://github.com/opena2a-org/secretless-ai) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/ai-browserguard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

[Website](https://opena2a.org/hackmyagent) · [Demos](https://opena2a.org/demos) · [Discord](https://discord.gg/uRZa3KXgEn)

Security scanner for AI agents. It finds the shadow AI on a machine, scans agent projects and packages for credentials, risky MCP configs, prompt injection and weak governance, and tests agents with attack payloads.

## Quick start

Scan the project you are in:

```bash
npx hackmyagent secure
```

```
  support-agent  v1.0.0 · library · 5 files analyzed
  [...]
  ── Observations ────────────────────────────────────────────
  Surfaces    library · 5 semantic artifacts · all 5 artifacts reached 0-6 of 7 analyzer families
  Checks      261 static declared · 63 of 63 check groups ran · 5 semantic (NanoMind AST, 0-6 of 7 analyzer families) · 5 files read by static checks
  [...]
  ── Findings ────────────────────────────────────────────────
  [...]
  │ CRITICAL  Overprivileged MCP server scope
  │ .mcp.json:5
  │ Overprivileged filesystem access allows the agent (or an attacker via prompt injection) to read sensitive files like SSH keys, credentials, and system configs.
  │ Verify: sed -n '5p' /home/dev/workspace/support-agent/.mcp.json
  │ Fix: Scope "filesystem" to the project directory: replace "/" with "./" or a specific subdirectory.
  [...]
  Path forward: 53 -> 92 by fixing 1 critical + 3 high
```

No config file or flag is needed. `[...]` marks omitted lines. The full output, the sample workspace and the build that produced it are in [docs/quick-start-capture.txt](docs/quick-start-capture.txt). The run exits 1 because a critical or high finding fired.

<!-- chooser:start docs/chooser.json -->
## What do you want to check?

- **My own project, before I ship it:** `npx hackmyagent secure`. Next: `npx hackmyagent secure --fix`.
- **A package, repository or skill, before I install it:** `npx hackmyagent check <target>`. Next, for a local copy: `npx hackmyagent secure <dir> --fix`.
- **A running agent endpoint you own:** `npx hackmyagent attack <url>`. Next, with every payload: `npx hackmyagent attack <url> --intensity aggressive`.
- **One text, such as a pull request body:** `npx hackmyagent scan-text <file>`. Next, in a pipeline: `npx hackmyagent scan-text - --as pr-body --json`.
- **Every agent project under this folder:** `npx hackmyagent detect`. Next, for one project: `npx hackmyagent secure <project>`.
- **More.** A SOUL.md governance file: `npx hackmyagent scan-soul`. Attack payloads to run yourself against a skill, MCP config or SOUL.md: `npx hackmyagent red-team <file>`. MCP endpoints a host you own exposes: `npx hackmyagent scan <host>`.
<!-- chooser:end -->

## What it finds

- **Shadow AI**: the AI assistants, MCP servers and agent projects on a machine (`detect`). Example: `1 project MCP server with sensitive access`.
- **Credentials and risky configuration**: 261 static checks, from MCP configs to supply chain and sandbox escape. Example: `CRITICAL  Overprivileged MCP server scope`.
- **Undeclared capabilities and scanner evasion**: 29 semantic checks over skills, prompts and configs. Example: `CRITICAL  Data Exfiltration Surface`.
- **Weak governance**: SOUL.md graded against a 9-domain model (`scan-soul`). Example: `Missing   SOUL-IH-003  Role-play refusal`.
- **Text that gives orders**: pull-request bodies, issues and comments (`scan-text`). Example: `TEXT-001  HIGH  Instruction-override payload`.
- **Attacks an agent falls for**: 164 adversarial payloads (`attack`). Example: `Prompt Injection: 2/2 successful` against a deliberately vulnerable agent.

## Usage

### Fix what a scan finds

```bash
hackmyagent secure --fix --dry-run   # preview the fixes
hackmyagent secure --fix             # apply them
hackmyagent rollback                 # revert them
```

Backups go to a store outside the project. Which checks it fixes, and where the backups live: [docs/SECURITY_CHECKS.md](docs/SECURITY_CHECKS.md#auto-fix-catalogue).

- [hackmyagent secure: scores a sample agent project, then applies the fixes it can](docs/vhs/secure.gif): [text version](docs/vhs/secure-capture.txt), [provenance](docs/vhs/secure.json).

### Find the shadow AI on a machine

```bash
npx hackmyagent detect
```

```
  workspace  shadow ai audit · laptop · 2 agents · 3 agent projects
  [...]
  ── Shadow AI agents (3) ────────────────────────────────────
  project              identified by  mcp servers     governance   cred      verdict
  support-agent        Claude Code    2 mcp critical  gov   0/100  cred no   CRITICAL
  [...]
```

One row per agent project, worst first. Full output: [docs/quick-start-capture.txt](docs/quick-start-capture.txt).

### Gate a pull request in CI

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

`secure` exits 1 on a critical or high finding or a score below `--fail-below`, and 2 when it did not examine everything it found. Exit codes: [docs/commands.md](docs/commands.md#exit-codes). More recipes: [docs/ci.md](docs/ci.md).

### Use it from an AI assistant

```bash
hackmyagent init-mcp --root /absolute/path/to/your/project
```

That adds the server to Claude Code, Cursor or VS Code. Then ask the assistant: "Run a deep security scan on this project." The server reads only inside its roots, and no MCP tool writes to your files.

## Install

```bash
npm install -g hackmyagent
brew install opena2a-org/tap/hackmyagent
```

Installing runs the install script of `onnxruntime-node`, which on Linux x64 downloads an execution-provider package from nuget.org. Node.js versions, skipping that download, and verifying a release: [docs/install.md](docs/install.md).

## Telemetry

Usage telemetry is on by default, and `hackmyagent --version` says so on its second line: `Telemetry: on (opt-out: OPENA2A_TELEMETRY=off ...)`.

- **Sent:** one event per command, to the OpenA2A Registry.
- **Fields, and only these:** tool, version, install ID, event type, command name, success, duration, platform, Node major version.
- **Failed command:** an error code is added to the command name.
- **Install ID:** derived from a SHA-256 hash of the machine identifier, or of the hostname where none can be read.
- **Not sent:** the raw identifier, file paths, scanned content, arguments beyond the command name, environment variables.
- **Off under CI:** `CI`, `GITHUB_ACTIONS` and the other CI services' variables; `--version` then prints `Telemetry: off`.
- **Off under test runners:** Vitest, Jest, `node --test`, `NODE_ENV=test`; `--version` then prints `Telemetry: off`.
- **On under CI or a test runner:** only when `OPENA2A_TELEMETRY=on` is set for the run.
- **Policy:** [opena2a.org/telemetry](https://opena2a.org/telemetry).

```bash
OPENA2A_TELEMETRY=off hackmyagent secure          # off for one run
hackmyagent telemetry off                         # off on this machine; `telemetry status` shows the state
OPENA2A_TELEMETRY_DEBUG=print hackmyagent secure  # print each event on stderr before it is sent
```

Sharing scan findings with the Registry is a separate opt-in (`--contribute`, or `contribute.enabled` in `~/.opena2a/config.json`; `--no-contribute` or `--ci` turns it off for a run). `hackmyagent telemetry off` covers usage telemetry only.

## Documentation

- [Commands](docs/commands.md): the main commands and their flags, the MCP server, use through opena2a-cli, and exit codes.
- [CI/CD](docs/ci.md): non-interactive runs, pull-request gates, credentials in git history, and scanning a pipeline's text.
- [How it works](docs/how-it-works.md): discovery, static checks, the semantic layer, scoring, the simulation and the self-integrity check.
- [Install](docs/install.md): Node.js versions, Homebrew, building from source, the install-time download, verifying provenance.
- [Security checks](docs/SECURITY_CHECKS.md): check categories with representative checks, what each count includes, and what `--fix` changes.
- [Use cases](docs/USE-CASES.md): scanning an agent, red-teaming an MCP server, securing OpenClaw and wiring a CI pipeline.
- [Programmatic API](docs/PROGRAMMATIC_API.md): TypeScript entry points for the scanner, runtime protection and the NanoMind semantic compiler; [plugin authoring](docs/PLUGIN_API.md).
- [Contributing](CONTRIBUTING.md): outside pull requests are welcome. Report security issues through [SECURITY.md](SECURITY.md), not a public issue.

Part of the [OpenA2A](https://opena2a.org) security platform. Related: [opena2a-cli](https://github.com/opena2a-org/opena2a), the unified CLI that runs HackMyAgent behind `opena2a review`; [aicomply](https://github.com/opena2a-org/aicomply), which classifies PII, credentials and regulated data in agent I/O at runtime: HackMyAgent scans the code, aicomply guards the live stream. More in the [OpenA2A docs](https://opena2a.org/docs) and [research](https://research.opena2a.org).

## License

Apache-2.0. See [LICENSE](LICENSE).

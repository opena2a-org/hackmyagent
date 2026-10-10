# HackMyAgent

[![Status: stable](https://img.shields.io/badge/status-stable-green)](./STATUS.md)

> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [CLI](https://github.com/opena2a-org/opena2a) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [OpenA2A AIM (Agent Identity Management)](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/AI-BrowserGuard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

Security scanner for AI agents: finds the shadow AI on a machine (every AI assistant, MCP server and agent project, worst first), scans agent projects and packages for credentials, risky MCP configs and prompt injection, grades SOUL.md governance, and generates red-team payloads. Apache 2.0.

[![npm version](https://img.shields.io/npm/v/hackmyagent.svg)](https://www.npmjs.com/package/hackmyagent)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://github.com/opena2a-org/hackmyagent/actions/workflows/test-matrix.yml/badge.svg?branch=main)](https://github.com/opena2a-org/hackmyagent/actions/workflows/test-matrix.yml)
[![NanoMind](https://img.shields.io/badge/NanoMind-semantic%20layer-teal)](https://huggingface.co/opena2a/nanomind-security-classifier)

[Website](https://hackmyagent.com) · [Demos](https://opena2a.org/demos) · [Discord](https://discord.gg/uRZa3KXgEn)

## Quick start

Scan the project you are in:

```bash
npx hackmyagent secure
```

```
  support-agent  v1.0.0 · library · 5 files analyzed
  1 critical issue found

  Security  ━━━━━━━━━━━━━━━━━━━━ 53/100

  ── Observations ────────────────────────────────────────────
  Surfaces    library · 5 semantic artifacts · all 5 artifacts reached 0-6 of 7 analyzer families
  Checks      317 static declared · 63 of 63 check groups ran · 5 semantic (NanoMind AST, 0-6 of 7 analyzer families) · 5 files read by static checks
  [...]
  Verdict     Not safe to ship. Overprivileged MCP server scope in .mcp.json:5 + 8 more. Fix before using in production.

  ── Findings ────────────────────────────────────────────────
  1 critical  3 high  4 medium  1 low
  [...]
  │ CRITICAL  Overprivileged MCP server scope
  │ .mcp.json:5
  │ Overprivileged filesystem access allows the agent (or an attacker via prompt injection) to read sensitive files like SSH keys, credentials, and system configs.
  │ Verify: sed -n '5p' /home/dev/workspace/support-agent/.mcp.json
  │ Fix: Scope "filesystem" to the project directory: replace "/" with "./" or a specific subdirectory.
  [...]
  Path forward: 53 -> 92 by fixing 1 critical + 3 high
```

Find the shadow AI: run `detect` from the directory that holds your agent projects (a workspace, a home directory) for one row per project, worst first:

```bash
npx hackmyagent detect
```

```
  workspace  shadow ai audit · laptop · 2 agents · 3 agent projects
  2 of 3 agent projects need action (1 critical, 3 high)

  ── Shadow AI agents (3) ────────────────────────────────────
  project              identified by  mcp servers     governance   cred      verdict
  support-agent        Claude Code    2 mcp critical  gov   0/100  cred no   CRITICAL
  research-agent       Cursor         0 mcp           gov   4/100  cred no   HIGH
  release-notes-agent  SOUL.md        0 mcp           gov  74/100  cred no   MEDIUM

  support-agent  1 critical · 2 high · 1 medium · 1 low
  │ CRITICAL  1 project MCP server with sensitive access
  │ shell: can run any command on your computer
  │ Fix: hackmyagent secure support-agent
  [...]
```

Both captures: hackmyagent 0.33.2 built from this repository, run on 2026-10-10 (UTC) in a Linux container with hostname `laptop`, over a sample workspace of three agent projects with no real credentials. `[...]` marks omitted lines; the full output and the sample files are in [`docs/quick-start-capture.txt`](docs/quick-start-capture.txt). No config files or flags are required. Both runs exit 1, which means a critical or high finding fired; see [Exit codes](#exit-codes).

## What it finds

- **Shadow AI.** `detect` lists the AI assistants running or installed on a machine (Claude Code, Cursor, Copilot and similar), project and machine-wide MCP servers, AI config files with credential references or broad permission grants, and agents with no governance file, one row per agent project. `--export-csv` writes the same inventory for a CMDB.
- **317 static checks across 71 categories** (362 checks across 86 categories including the NanoMind semantic layer). Credentials, MCP configs, OpenClaw and NemoClaw, Unicode steganography, CVEs, governance, supply chain, memory and RAG poisoning, agent identity, sandbox escape. Run `hackmyagent check-metadata` for the live list.
- **29 NanoMind semantic checks.** Every artifact (skill, MCP config, SOUL.md, system prompt) compiles into an Abstract Security Tree. The seven AST analyzers run against the tree: `capability`, `credential`, `governance`, `scope`, `prompt`, `code`, `stego`. Pattern matching misses undeclared capabilities, constraint weakness, scope mismatches, and scanner-evasion attempts. AST queries catch them. (This 29 is the fixed catalog of check ids the seven analyzers emit. `hackmyagent check-metadata` reports `semanticChecks: 45`, a different count: every `AST-` and `SEM-` id in the check taxonomy, which adds the structural layer's 19 `SEM-` checks and leaves out the 3 `UNICODE-STEGO` ids the stego analyzer shares with the static catalog. The `Checks` line in scan output, `5 semantic (NanoMind AST, ...)` in the Quick start above, reports the number of artifacts compiled in that particular run, not this catalog size.)
- **164 adversarial payloads across 16 categories.** Prompt injection, jailbreak, data exfiltration, capability abuse, context manipulation, MCP and A2A exploitation, memory weaponisation, context window, supply chain, tool shadow, parser differential, persistent agent, fake tool, context lifecycle, policy enforcement integrity.
- **20-probe behavioural simulation** under `--deep`, when a probe executor is present (NanoMind daemon, Ollama or `ANTHROPIC_API_KEY`). Observes what a skill actually does, not only what it declares; without an executor it prints `NOT MEASURED` instead of a verdict.
- **Self-securing.** Every binary verifies itself on startup against an embedded SHA-256 manifest. Post-install tampered binaries enter QUARANTINE mode (exit code 3) with a per-file forensics report. Symlink-redirected manifests are rejected.

Full catalogue: [`docs/SECURITY_CHECKS.md`](docs/SECURITY_CHECKS.md).

## How it works

1. **Discover.** `secure` and `check` walk the target and sort what they find into surfaces: MCP configs, skills, governance files, system prompts, package manifests and source. `detect` also lists the AI assistants running on the machine and the machine-wide AI configs under your home directory.
2. **Static checks.** 63 check groups run over those surfaces. A finding that comes from one line carries `file:line`, a `Verify:` command that prints that line, and a `Fix:`.
3. **Semantic layer.** NanoMind compiles each agent artifact into an Abstract Security Tree, runs seven analyzers over it, and classifies it with a local ONNX model, downloaded once (8.7 MB) from Hugging Face. `--static-only` skips the layer.
4. **Score, verdict, exit code.** Findings roll up into a 0-100 score with the path forward (`53 -> 92 by fixing 1 critical + 3 high` above), a verdict and an exit code. A run that could not read part of its input says so and exits 2 instead of reporting that nothing was found.
5. **Local by default.** The scan runs on your machine. A local scan's findings reach the OpenA2A Registry only after you opt in to contribution or pass `--publish`. Usage telemetry is separate: see [Telemetry](#telemetry).

## Install

### npm

```bash
npx hackmyagent secure          # run without installing
npm install -g hackmyagent      # global install
npm install --save-dev hackmyagent
```

Requires Node.js 20.19 or later on the 20 line, or 22.12 or later: the first releases that load ES modules through `require()`, which the CLI does at startup.

### Homebrew

```bash
brew install opena2a-org/tap/hackmyagent
```

From source: see [Contributing](#contributing).

### Install-time download, and how to skip it

Installing this package runs the install script of `onnxruntime-node`, the dependency this tool uses for local NanoMind inference. On Linux x64 that script downloads an execution-provider package, `Microsoft.ML.OnnxRuntime.Gpu.Linux`, from nuget.org: about 236 MB at `onnxruntime-node` 1.30.0, the release a fresh install resolved on 2026-09-19. This tool does not use that provider: it requests no execution provider anywhere, so the CPU provider is the only one it runs. The check is `grep -rn "executionProviders" src/`, which prints nothing and exits 1, read on 2026-09-20.

To install without that download, set `ONNXRUNTIME_NODE_INSTALL=skip` in the environment of the install command, or run `npm config set onnxruntime-node-install skip` once so that every later install skips it. The CPU runtime this tool uses ships inside the npm package itself: at 1.27.0, `bin/napi-v6/linux/x64` carries `libonnxruntime.so.1` and `onnxruntime_binding.node`, read on 2026-09-20.

`--ignore-scripts` is safe for a CI install of this package: this tree carries exactly one non-dev dependency that declares an install script, `onnxruntime-node`. In `package-lock.json`, exactly one `"hasInstallScript": true` entry has no `"dev": true` beside it, and it is `node_modules/onnxruntime-node`, read on 2026-09-20.

### Verifying what was installed

Every release publishes via npm Trusted Publishing with SLSA v1 provenance. No long-lived `NPM_TOKEN`. GitHub Actions exchanges its OIDC token with npm at publish time.

```bash
npm view hackmyagent dist.attestations --json
# Expects non-empty result with predicateType "https://slsa.dev/provenance/v1"
```

## Scan anything

`hackmyagent check <target>` accepts each of these surfaces. `secure` scans your own project. `scan-soul` scans governance.

| Surface | Command | What gets scanned |
|---|---|---|
| Your own project | `hackmyagent secure` | 317 static checks + NanoMind on current directory |
| A local directory | `hackmyagent check ./my-agent/` | tree + auto-detected artifacts |
| An npm package | `hackmyagent check express` | downloads tarball, scans before you install |
| A PyPI package | `hackmyagent check pip:requests` | downloads sdist, scans before you install |
| A GitHub repo | `hackmyagent check getsentry/sentry-mcp` | clones, scans, reports |
| A published skill | `hackmyagent check @publisher/skill` | signature verification + semantic checks |
| A local skill directory | `hackmyagent check ./my-skill/` | skill files + SOUL.md + manifest |
| An MCP server config | `hackmyagent check ./my-mcp-server/` | MCP config + declared tools + scope + dependencies |
| An A2A agent card | `hackmyagent check ./my-agent/` | agent-card capabilities + identity |
| A URL tarball | `hackmyagent check https://ex.com/pkg.tar.gz` | downloads, scans |
| External infrastructure | `hackmyagent scan example.com` | external AI-endpoint inventory |
| One text (PR body, issue, comment, card) | `hackmyagent scan-text ./pr-body.md` | the text itself, for instruction-override and authority-claim payloads; no score |
| Governance (SOUL.md) | `hackmyagent scan-soul` | SOUL.md against OASB-2 behavioural controls |
| Every agent project on a machine | `hackmyagent detect` | running assistants, MCP servers, credential references in AI config files, governance; one row per project, worst first |

### secure vs check vs red-team vs attack

- `secure`: your own project. Full static + semantic scan, auto-fix option, designed for CI and recurring use.
- `check`: something you don't own yet. Pre-install trust check for any surface above.
- `red-team`: maps the attack surface of a specific skill, MCP, or SOUL and generates target-specific payloads. It does not execute them, so it does not tell you whether the artifact resists.
- `attack`: test a live endpoint or local simulation with 164 pre-built adversarial payloads.

## Commands

### `secure` (security scan)

```bash
hackmyagent secure                            # scan current directory
hackmyagent secure --fix                      # auto-fix issues with rollback
hackmyagent secure --fix --dry-run            # preview fixes
hackmyagent secure --deep                     # full behavioural simulation (20 probes)
hackmyagent secure --static-only              # static checks only, faster
hackmyagent secure --ignore CRED-001,GIT-002  # leave check IDs out of the findings list
hackmyagent secure --json                     # JSON output for CI
hackmyagent secure --ci                       # non-interactive, no contribution, exit code unchanged
hackmyagent secure --publish                  # push anonymised results to the OpenA2A Registry
hackmyagent secure -b oasb-1                  # OASB-1 benchmark (L1, L2, L3)
hackmyagent secure -b oasb-1 --fail-below 70  # CI gate (adds a floor; the rating gate still applies)
hackmyagent secure --nanomind                 # AI analyst: per-finding narratives + coverage escalations
```

**Reads stay inside the directory you scan.** A symbolic link inside the tree that resolves outside it (`.env -> ~/.aws/credentials`, `skills -> /`) is not followed by any `secure` check or MCP scan tool (the `scan-soul`, `harden-soul` and `detect` governance reads are not yet covered and are tracked as a follow-up): the report lists each such link with where it resolves, and to include that file you point the scan at the directory that really contains it, for example `hackmyagent secure ~/shared`. Withheld links do not change the exit code and are not counted as unread inputs; a link that resolves inside the tree is read normally. There is no flag that follows links out, because the tree being scanned is the one thing a scan must not let choose what it reads.

Every HIGH or CRITICAL finding names the file it came from. Findings from one line, such as a hardcoded credential, carry `file:line`, a `Verify:` command and a runnable `Fix:`. Findings about a file's overall configuration, such as an over-permissive `.claude/settings.json`, currently name the file without a line and describe the fix in prose ([#299](https://github.com/opena2a-org/hackmyagent/issues/299), [#368](https://github.com/opena2a-org/hackmyagent/issues/368)).

### NanoMind semantic analysis

Runs on every `secure` scan. On first use, HMA downloads an ONNX classifier from Hugging Face ([`opena2a/nanomind-security-classifier`](https://huggingface.co/opena2a/nanomind-security-classifier)) into `~/.nanomind/models`. Before the first request it prints on stderr, in every output format, the download size, the hosts (huggingface.co and Hugging Face's content CDN), the cache path and the flag that skips it (`--static-only`). Later scans use the cached copy and make no model request. Behind a proxy, the download goes through the one in `HTTPS_PROXY` (or `HTTP_PROXY` when that is unset), skipping hosts listed in `NO_PROXY`; the notice names the proxy by host and port, never by the credentials in its URL.

- 7 AST analyzers: `capability`, `credential`, `governance`, `scope`, `prompt`, `code`, `stego`.
- 9 attack classes: `exfiltration`, `injection`, `privilege_escalation`, `persistence`, `credential_abuse`, `lateral_movement`, `social_engineering`, `policy_violation`, `benign`.
- `--deep` adds the 20-probe behavioural simulation (needs a probe executor; otherwise `NOT MEASURED`). `--static-only` disables the semantic layer.
- `--nanomind` opts into the generative analyst: per-finding threat narratives on HIGH or CRITICAL findings, and a coverage sweep whose verdicts surface as advisory escalations for human review (never changing the score, findings, or exit code).

### `red-team` (attack surface and payload generation)

```bash
hackmyagent red-team ./my-skill.md             # map surface, generate payloads
hackmyagent red-team ./mcp-config.json --json  # JSON output, incl. payload text
```

Maps an artifact's attack surface from its own language and generates target-specific payloads for it. **It does not run them.** No agent is executed, so no resilience score is reported: `resilienceScore` is `null` and `evaluation.mode` is `not_executed` in `--json`, and the command exits **2** to mark that it reached no verdict. `--json` puts the payload text under `.results[].payloadInput`, to run against your own agent.

Treat any resilience score, defense map, or successful-attack count from versions **0.11.14 through 0.25.2** (the whole published life of the command until then) as void: it came from a regex over the artifact's own text, which rated a jailbreak document 100% resilient (#369). With the number, two `--json` fields were renamed because their old names asserted a polarity nothing established: `constraints` is now `modalStatements`, and `governanceMechanism: string` is now `governanceMentions: string[]`. Executing payloads for real is tracked in `docs/design/redteam-nanomind-judge.md`.

### `attack` (payload battery)

```bash
hackmyagent attack https://api.example.com/v1/chat                     # test a live endpoint
hackmyagent attack https://api.example.com --category prompt-injection # single category
hackmyagent attack https://api.example.com --fail-on-vulnerable medium # CI gate
hackmyagent attack --local                                             # generate payloads only
hackmyagent attack --local --system-prompt "You are helpful"           # with custom system prompt
```

164 payloads across 16 categories. Intensity tiers: `passive` (28 payloads, observation only), `active` (111 payloads, default), `aggressive` (164 payloads, includes creative or risky probes). `attack` probes the endpoint once before sending any payload and exits 2 without a score if nothing is there. `--local` generates payloads and checks that they parse; it contacts no agent, so it reports no risk score and exits 2, like `red-team`. Only test systems you own or have written authorisation to test.

Need a target to practice on? [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) is an intentionally vulnerable agent fleet:

```bash
docker run -p 7001-7008:7001-7008 -p 7010-7016:7010-7016 -p 7020-7021:7020-7021 -p 9000:9000 opena2a/dvaa:0.9.1
hackmyagent attack http://localhost:7003/v1/chat/completions --api-format openai --intensity passive
```

![hackmyagent attack red-teaming a live DVAA agent: 100/100 CRITICAL, 28 of 28 attacks successful across 14 categories](docs/vhs/attack-dvaa.gif)

### `scan-soul` and `harden-soul` (governance)

```bash
hackmyagent scan-soul                     # scan current directory for SOUL.md
hackmyagent scan-soul --deep              # LLM semantic analysis (requires ANTHROPIC_API_KEY)
hackmyagent scan-soul --fail-below 60     # add a score floor on top of the default gate
hackmyagent scan-soul --explain           # print the 9-domain governance model and exit
hackmyagent harden-soul                   # generate or update governance sections
hackmyagent harden-soul --dry-run         # preview without writing
```

Auto-detects governance file in this priority: `SOUL.md`, `system-prompt.md`, `CLAUDE.md`, `.cursorrules`, `agent-config.yaml`. `scan-soul` gates without a flag: it exits 1 when conformance is `none`, meaning a critical control was not detected, whatever the score (the same gate `secure -b oasb-2` and `detect` apply). Over a tree with no governance file it exits 2 and reports nothing. `--fail-below` adds a score floor on top. Run `hackmyagent scan-soul --help` for the full exit-code contract.

### `detect` (shadow AI audit)

```bash
hackmyagent detect                              # every agent project under the current directory
hackmyagent detect ~/workspace                  # every agent project under a workspace root
hackmyagent detect /path/to/project             # one project, the full report
hackmyagent detect --depth 0                    # the target directory only, no walk
hackmyagent detect --json                       # machine-readable output
hackmyagent detect --export-csv inventory.csv   # asset inventory for CMDB, one row per asset
```

Inventory of AI tools, MCP servers, and governance gaps across your machine. Detects Claude Code, Cursor, Copilot, and similar tools, both running (a process) and installed (a project config such as `.cursorrules` or a machine-wide config such as `~/.cursor/mcp.json`); MCP configurations (project-local and machine-wide, including Claude Desktop and `~/.claude.json`); AI config files with credential references or broad permission grants; and SOUL.md files. The governance finding applies to installed agents too: a tool that is closed right now still has its rules, servers and credentials in the tree.

A directory is an agent project when it holds an AI tool config (`.claude/settings.json`, `.cursorrules`, `CLAUDE.md`, ...), a project MCP file (`.mcp.json`, `mcp.json`), a governance file or a capability policy. The walk goes four levels down by default, does not enter `node_modules`, build output or hidden directories, and does not follow symbolic links. Each project's critical and high findings follow the table with their `file:line`, `Fix` and `Verify`; `hackmyagent detect <project>` prints the full report for one. The exit code is the worst project's. A target that is itself an agent project keeps its single-project report; the projects below it are named under Next Steps and in the JSON's `nestedProjects`, and `hackmyagent detect --workspace` lists them all, the target included.

![hackmyagent detect on demo-agents, five sample agent projects with fake credentials, recorded with hackmyagent 0.33.0, 2026-09-15, setup not shown. The terminal prints a table of the five projects worst first, reports 4 of 5 need action (4 critical, 5 high), and lists each project's critical and high findings with a Fix command and, where a finding comes from one line of a file, a Verify command that prints that line.](docs/vhs/detect.gif)

Recorded with hackmyagent 0.33.0 on 2026-09-15 over five sample agent projects with fake credentials, setup not shown. Text version: [docs/vhs/detect-capture.txt](docs/vhs/detect-capture.txt); provenance: [docs/vhs/detect.json](docs/vhs/detect.json); re-render: `docs/vhs/record-detect.sh`.

### `trust`, `explain`, `nanomind`

```bash
hackmyagent trust server-filesystem      # MCP shorthand trust lookup against the Registry
hackmyagent trust --audit package.json   # audit every dependency
hackmyagent explain CRED-001             # explain a check finding
hackmyagent nanomind setup               # install the optional generative analyst daemon
hackmyagent nanomind status              # check model and runtime status
hackmyagent trust express --grant grant://hackmyagent-trust --atx ~/.opena2a/atx.json
```

With `--grant`, `trust` is gated by the [Agent Authorization Protocol](https://github.com/opena2a-standards/agent-authorization-protocol): the CLI presents an ATX and a grant reference to the local Secretless broker before any Registry lookup and proceeds only if the broker authorizes. A denial (HTTP 403) exits 3 with a pointer to `~/.secretless-ai/policies/`, and its reasons live only in the broker's signed audit log (AAP §6.6); an unreachable broker exits 4 with a `secretless broker start` hint; an unexpected status exits 6 and the response body is never echoed. Without `--grant`, `trust` runs as before.

### OpenClaw and NemoClaw auto-detection

`hackmyagent secure` auto-detects OpenClaw and NemoClaw installations (`.openclaw/`, `.moltbot/`, `.nemoclaw/`, `openclaw.json`, `openclaw.plugin.json`) and runs their check groups alongside the standard suite. No separate command needed.

## Using with opena2a-cli

[`opena2a-cli`](https://github.com/opena2a-org/opena2a) is the unified CLI for the OpenA2A security tools (`npm install -g opena2a-cli`, then `opena2a review`). HackMyAgent powers `opena2a review`, `opena2a scan`, `opena2a protect`, `opena2a benchmark`, and `opena2a scan-soul`.

Runtime protection (ARP) is driven from `opena2a runtime`. ARP monitors agents during execution (rule-based patterns, statistical anomaly detection, and LLM-assisted assessment) and runs as an HTTP reverse proxy for OpenAI API, MCP and A2A traffic.

## MCP server

HackMyAgent runs as an MCP server, so an AI coding assistant can scan the project it is working in:

```bash
hackmyagent init-mcp --root /absolute/path/to/your/project
```

That writes the server into your client config (Claude Code, Cursor, VS Code), picked up on the client's next launch. Then ask the assistant: "Run a deep security scan on this project." Three tools are exposed: `hackmyagent_scan` (the full check suite, read-only), `hackmyagent_deep_scan` (pattern and structural analysis, plus the artifact contents for the assistant to reason over) and `hackmyagent_benchmark` (OASB-1 compliance at L1, L2 or L3).

**Roots.** The server reads only inside the directories it was started with, and there is no unconfined mode. `--root` is repeatable, so grant projects one at a time (`--root ~/work/api --root ~/work/web`). The filesystem root and your home directory are not accepted, because granting either hands every project and every credential file on the machine to whatever model is driving the session, the same thing HackMyAgent reports as `MCP-001` when it sees it in someone else's configuration. A path outside the roots is refused with the roots named and the command to grant one.

**Fixes are terminal-only.** No MCP tool writes to your files. Findings carry their fix command, such as `hackmyagent secure --fix .`, and you run it yourself. Verify what the server is allowed to reach:

```bash
grep -A3 hackmyagent .mcp.json    # Claude Code; or .cursor/mcp.json, .vscode/mcp.json
```

## CI/CD integration

`secure` and `scan-soul` take `--ci` for non-interactive, byte-stable output; it also turns contribution off for that run. Most scanning commands take `--json`: `check`, `secure`, `attack`, `scan`, `fix-all`, `scan-soul`, `scan-text`, `harden-soul`, `red-team`, `wild`, `detect`, `trust`. `secure` and `attack` also take `-f, --format <format>`; on those two commands `--json` is shorthand for `--format json`.

`--json` never changes the exit code. `--ci` mostly doesn't either; the one exception is `scan-soul`, which also exits 1 under `--ci` on a HIGH-severity SOUL finding that renders as a warning without the flag. To gate on severity, read the exit code; to gate on the score, use `--fail-below <n>`. A threshold only raises the exit code: a run that could not read one of its inputs still exits 2, not 1.

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

SARIF output, a pre-commit hook, and the `.hmaignore` rules for suppressing a check or excluding a path: [`docs/use-cases/ci-pipeline.md`](docs/use-cases/ci-pipeline.md). Suppressing a check changes what the report lists, not the score or the exit code; excluding a path is a scope statement, always disclosed on a `Scope` line.

### Gating a pull request on what it changes

`--range` reports only what the commits in a range introduce: both trees are read from git and scanned, and a finding the base already has (same check, file and cited line) is left out of the report, the score and the exit code. `--staged` does the same for the index against `HEAD`, for a pre-commit hook.

```yaml
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - run: npx hackmyagent secure --range origin/${{ github.base_ref }}...HEAD
```

### Scanning a text a pipeline was handed

`scan-text` takes ONE text rather than a tree (a pull-request body, an issue, a comment, an agent card) and reports every line that asks to be read as an instruction to the reader (`TEXT-001`) or as an authorization the text grants itself (`TEXT-002`). The operand is a path, or `-` for standard input. It reports no score on any channel.

```yaml
name: Scan the PR body
on: [pull_request]
jobs:
  scan-text:
    runs-on: ubuntu-latest
    steps:
      - env:
          PR_BODY: ${{ github.event.pull_request.body }}
        run: printf '%s' "$PR_BODY" | npx hackmyagent scan-text - --as pr-body --json
```

Exit codes, the same on both channels: **0** the text was read and no finding is high or critical; **1** the text was read and at least one is; **2** not measured: the operand does not exist or could not be read, so no text was scanned and no finding is reported. `--json` never changes the code, and neither does `--ci`. A clean result means only that no instruction-override or authority-claim payload was found in that text; it is not an approval of the text, or of the request the text belongs to.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Measured. No critical or high issues. |
| 1 | Measured. Critical or high severity issues found. For `scan-soul`, also conformance `none` — a critical governance control was not detected, whatever the score. |
| 2 | **Not measured.** For `scan-text`, the operand does not exist or could not be read, so no text was scanned and no finding is reported on either channel. For `red-team`, no score or risk level is reported. For `secure --deep`, the static results ARE reported and scored; the deep layer did not finish, so the run reaches no deep-scan verdict. For `secure` and `check`, a file or directory inside the target was discovered and could not be read (`EACCES`, `ELOOP`, an unreadable mount): what DID run is still reported and scored, and the score or risk level is an upper bound rather than a measurement of the tree — the run names each file and the errno (`SCAN-UNREAD-001`). The target does not exist (`check <missing path>`, an unknown package), was unreachable, answered no payload, or the command reaches no verdict by design. `red-team` and `attack --local` exit 2 on every run: both generate payloads without executing any against an agent, so neither concludes anything about the target. A scan whose plugins failed is also 2. `scan-soul` exits 2 over a tree with no governance file: no score or conformance level is reported, because nothing was read. `secure -b oasb-2` does the same for its governance half: the governance score, conformance and composite print as not measured. For `secure -b oasb-1`, also the rating ladder: when no scored L1 control produced a result the rating prints as `Not Assessed` at exit 2 and the category results are still printed; when nothing at all was measured there is no compliance figure and `--fail-below` is not evaluated; a `--category` whose L2 or L3 controls did produce results keeps its measured figure, and a `--fail-below` breach over it exits 1. |
| 3 | QUARANTINE. Binary integrity check failed (tampered installation). |

Exit 2 is non-zero on purpose. A CI job that asked for a security verdict and got "I could not reach the target" has not been told the target is safe. A benchmark run that reached no scored control has not been given a rating either: `Not Assessed` is the absence of one, not a low one.

## Auto-fix catalogue

`hackmyagent secure --fix` remediates the checks listed in [`docs/SECURITY_CHECKS.md`](docs/SECURITY_CHECKS.md); `--dry-run` previews the changes, backups live in `.hackmyagent-backup/`, and `hackmyagent rollback` reverts them.

## Telemetry

Usage telemetry is on by default, and `hackmyagent --version` says so on its second line: `Telemetry: on (opt-out: OPENA2A_TELEMETRY=off ...)`. Each command sends one event to the OpenA2A Registry with these fields only: tool, version, a random install ID, event type, command name, success, duration, platform and Node major version (a failed command adds an error code to the name). No file paths, scanned content, arguments beyond the command name, or environment variables. Policy: [opena2a.org/telemetry](https://opena2a.org/telemetry).

```bash
OPENA2A_TELEMETRY=off hackmyagent secure          # off for one run
hackmyagent telemetry off                         # off on this machine; `telemetry status` shows the state
OPENA2A_TELEMETRY_DEBUG=print hackmyagent secure  # print each event on stderr before it is sent
```

Sharing scan findings with the Registry is a separate opt-in (`--contribute`, or `contribute.enabled` in `~/.opena2a/config.json`; `--no-contribute` or `--ci` turns it off for a run). `hackmyagent telemetry off` covers usage telemetry only.

## Contributing

Apache 2.0. Pull requests from outside the organization are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) has the development loop and what happens to a pull request opened from a fork.

```bash
git clone https://github.com/opena2a-org/hackmyagent.git
cd hackmyagent && npm install && npm run build && npm test
node dist/cli.js secure      # run the build from source
```

Security issues: see [SECURITY.md](SECURITY.md). Do not open a public issue.

## Links

- [Use cases](docs/USE-CASES.md): step-by-step guides for scanning an agent, red-teaming an MCP server, securing OpenClaw and wiring a CI pipeline
- [Programmatic API](docs/PROGRAMMATIC_API.md): TypeScript entry points for the scanner, the runtime protection layer and the NanoMind semantic compiler; [plugin authoring](docs/PLUGIN_API.md)
- [Security Checks Reference](docs/SECURITY_CHECKS.md)
- [OpenA2A CLI](https://github.com/opena2a-org/opena2a)
- [aicomply](https://github.com/opena2a-org/aicomply) — inline PII, credential, and regulated-data classification for agent I/O at runtime (HMA scans the code; aicomply guards the live stream)
- [Documentation](https://opena2a.org/docs)
- [Research](https://research.opena2a.org)

Part of the [OpenA2A](https://opena2a.org) security platform.

## License

Apache-2.0. See [LICENSE](LICENSE).

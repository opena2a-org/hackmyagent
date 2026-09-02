# HackMyAgent

[![Status: stable](https://img.shields.io/badge/status-stable-green)](./STATUS.md)

> **[OpenA2A](https://github.com/opena2a-org/opena2a)**: [CLI](https://github.com/opena2a-org/opena2a) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/AI-BrowserGuard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

Security scanner, red-team toolkit, and behavioural simulator for AI agents. Apache 2.0.

[![npm version](https://img.shields.io/npm/v/hackmyagent.svg)](https://www.npmjs.com/package/hackmyagent)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-2072%20passing-brightgreen)](https://github.com/opena2a-org/hackmyagent)
[![NanoMind](https://img.shields.io/badge/NanoMind-semantic%20layer-teal)](https://huggingface.co/opena2a/nanomind-security-classifier)

[Website](https://hackmyagent.com) · [Demos](https://opena2a.org/demos) · [Discord](https://discord.gg/uRZa3KXgEn)

## Quick start

```bash
npx hackmyagent secure
```

```
  my-project  v1.0.0 · library · 47 files analyzed
  3 critical issues found

  Security  ━━━━━━━━━━━━━━━━━━━━ 42/100

  ── Observations ────────────────────────────────────────────
  Surfaces    library · 47 files
  Checks      317 static · 12 semantic (NanoMind AST) · 0 skipped
  Categories  credentials (3 critical) · MCP (2 high) · 18 others clear
  Verdict     Not safe to ship. Fix 3 critical issues before using this in production.

  ── Findings ────────────────────────────────────────────────
  │ CRITICAL  Exposed API key in .env
  │ .env:3
  │ Anthropic API key (sk-ant-api03-****) detected in plaintext.
  │ Verify: sed -n '3p' '.env'
  │ Fix: hackmyagent secure --fix
```

No config files. No flags required. Exit code 1 if any critical or high finding fires.

![HackMyAgent Demo](docs/hackmyagent-demo.gif)

## What it finds

- **317 static checks across 73 categories** (362 checks across 88 categories including the NanoMind semantic layer). Credentials, MCP configs, OpenClaw and NemoClaw, Unicode steganography, CVEs, governance, supply chain, memory and RAG poisoning, agent identity, sandbox escape. Run `hackmyagent check-metadata` for the live list.
- **29 NanoMind semantic checks.** Every artifact (skill, MCP config, SOUL.md, system prompt) compiles into an Abstract Security Tree. The seven AST analyzers run against the tree: `capability`, `credential`, `governance`, `scope`, `prompt`, `code`, `stego`. Pattern matching misses undeclared capabilities, constraint weakness, scope mismatches, and scanner-evasion attempts. AST queries catch them. (This 29 is the fixed catalog of semantic checks. The `Checks` line in scan output — e.g. `12 semantic (NanoMind AST)` above — reports the number of artifacts compiled in that particular run, not this catalog size.)
- **164 adversarial payloads across 16 categories.** Prompt injection, jailbreak, data exfiltration, capability abuse, context manipulation, MCP and A2A exploitation, memory weaponisation, context window, supply chain, tool shadow, parser differential, persistent agent, fake tool, context lifecycle, policy enforcement integrity.
- **20-probe behavioural simulation** under `--deep`. Observes what a skill actually does, not only what it declares.
- **Self-securing.** Every binary verifies itself on startup against an embedded SHA-256 manifest. Post-install tampered binaries enter QUARANTINE mode (exit code 3) with a per-file forensics report. Symlink-redirected manifests are rejected.

Full catalogue: [`docs/SECURITY_CHECKS.md`](docs/SECURITY_CHECKS.md).

## Install

### npm

```bash
npx hackmyagent secure          # run without installing
npm install -g hackmyagent      # global install
npm install --save-dev hackmyagent
```

Requires Node.js 18 or later.

### Homebrew

```bash
brew install opena2a-org/tap/hackmyagent
```

### From source

```bash
git clone https://github.com/opena2a-org/hackmyagent.git
cd hackmyagent
npm install
npm run build
node dist/cli.js secure
```

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
| Governance (SOUL.md) | `hackmyagent scan-soul` | SOUL.md against OASB-2 behavioural controls |

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

Output shows an Observations block (surfaces, checks, categories, verdict) and a per-finding list. Every HIGH or CRITICAL finding names the file it came from. Findings from a specific line — hardcoded credentials in source, for example — carry `file:line` and a runnable `Fix:` with a `Verify:` command. Findings about a file's overall configuration, such as an over-permissive `.claude/settings.json`, currently name the file without a line and describe the fix in prose rather than as a command ([#299](https://github.com/opena2a-org/hackmyagent/issues/299), [#368](https://github.com/opena2a-org/hackmyagent/issues/368)).

### NanoMind semantic analysis

Runs automatically on every `secure` scan. On first use, HMA downloads a 5.5 MB ONNX classifier from HuggingFace ([`opena2a/nanomind-security-classifier`](https://huggingface.co/opena2a/nanomind-security-classifier), a 3M-parameter Mamba TME model) and caches it locally. No external calls after that.

- 7 AST analyzers: `capability`, `credential`, `governance`, `scope`, `prompt`, `code`, `stego`.
- 9 attack classes: `exfiltration`, `injection`, `privilege_escalation`, `persistence`, `credential_abuse`, `lateral_movement`, `social_engineering`, `policy_violation`, `benign`.
- `--deep` adds the 20-probe behavioural simulation.
- `--static-only` disables the semantic layer.
- `--nanomind` opts into the generative analyst (specialist model, not the classifier). It produces per-finding threat narratives on HIGH or CRITICAL findings, and a coverage sweep over artifacts the deterministic checks did not flag — analyst verdicts there surface as advisory escalations for human review (never changing the score, findings, or exit code).

### `red-team` (attack surface and payload generation)

```bash
hackmyagent red-team ./my-skill.md             # map surface, generate payloads
hackmyagent red-team ./mcp-config.json --json  # JSON output, incl. payload text
```

Maps an artifact's attack surface from its own language and generates target-specific payloads for it.

**It does not run them.** No agent is executed, so nothing about resistance is measured and no resilience score is reported — `resilienceScore` is `null` and `evaluation.mode` is `not_executed` in `--json`. The command exits **2** to mark that it reached no verdict (`0` executed-and-clean, `1` findings). The payloads are the deliverable: `--json` puts their text under `.results[].payloadInput`, to run against your own agent.

In 0.25.2 and earlier this command scored resistance with a regex over the artifact's own text, which rated a jailbreak document 100% resilient and benign prose 0%, both at exit 0. The affected range is **0.11.14 through 0.25.2**, which is the whole published life of the command — `red-team` did not exist before 0.11.14 — so treat any resilience score, defense map, or successful-attack count from any of those versions as void. The number is removed rather than corrected (#369); executing payloads for real is tracked in `docs/design/redteam-nanomind-judge.md`.

Two `--json` fields were renamed with the number, because their old names asserted a polarity nothing established. `constraints` is now `modalStatements`: it is a list of modal-verb sentences extracted from the artifact, and "Never reveal secrets." and "Never refuse." are the same syntactic shape, so nothing here separates a rule from a jailbreak. `governanceMechanism: string` is now `governanceMentions: string[]`: governance vocabulary the artifact mentions, not a mechanism it has. A file cannot report whether the agent it describes is governed, and the old field suppressed an attack surface when it was non-`none`.

### `attack` (payload battery)

```bash
hackmyagent attack https://api.example.com/v1/chat                     # test a live endpoint
hackmyagent attack https://api.example.com --category prompt-injection # single category
hackmyagent attack https://api.example.com --fail-on-vulnerable medium # CI gate
hackmyagent attack --local                                             # generate payloads only
hackmyagent attack --local --system-prompt "You are helpful"           # with custom system prompt
```

164 payloads across 16 categories. Intensity tiers: `passive` (28 payloads, observation only), `active` (111 payloads, default), `aggressive` (164 payloads, includes creative or risky probes).

`attack` needs a running agent. It probes the endpoint once before sending any
payload and exits 2 without a score if nothing is there, so an unreachable
target costs one request instead of the whole suite.

`--local` generates payloads and checks that they parse. It contacts no agent,
so it reports no risk score and exits 2 — the same as `red-team`. Use it to
inspect the payload set, not as a CI gate.

Only test systems you own or have written authorisation to test.

Need a target to practice on? [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) is an intentionally vulnerable agent fleet. Break an agent there, then red-team it here:

```bash
# Start the DVAA fleet (separate terminal)
docker run -p 7001-7008:7001-7008 -p 7010-7016:7010-7016 -p 7020-7021:7020-7021 -p 9000:9000 opena2a/dvaa:0.9.1

# Red-team LegacyBot, the most vulnerable agent
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

Auto-detects governance file in this priority: `SOUL.md`, `system-prompt.md`, `CLAUDE.md`, `.cursorrules`, `agent-config.yaml`.

`scan-soul` already gates without a flag: it exits 1 when conformance is `none`,
meaning one of the critical controls was not detected. That is not a score
threshold — a file scoring well above zero still fails if a critical control is
missing, which is the same gate `secure -b oasb-2` and `detect` apply. Over a
tree with no governance file at all it exits 2 and reports nothing, because
there is nothing to grade. `--fail-below` adds a score floor on top of that.
Run `hackmyagent scan-soul --help` for the full exit-code contract.

### `detect` (shadow AI audit)

```bash
hackmyagent detect                              # audit current directory
hackmyagent detect /path/to/project             # audit a specific project
hackmyagent detect --json                       # machine-readable output
hackmyagent detect --export-csv inventory.csv   # asset inventory for CMDB
```

Inventory of AI tools, MCP servers, and governance gaps across your machine. Detects Claude Code, Cursor, Copilot, and similar tools; MCP configurations (project-local and machine-wide); AI config files with credential references or broad permission grants; and SOUL.md files.

### `trust`, `explain`, `nanomind`

```bash
hackmyagent trust server-filesystem      # MCP shorthand trust lookup against the Registry
hackmyagent trust --audit package.json   # audit every dependency
hackmyagent explain CRED-001             # explain a check finding
hackmyagent nanomind setup               # install the optional generative analyst daemon
hackmyagent nanomind status              # check model and runtime status
```

#### Optional AAP gate on `trust`

`hackmyagent trust` can be gated by the [Agent Authorization Protocol](https://github.com/opena2a-standards/agent-authorization-protocol). When `--grant` is set, the CLI presents an ATX and a grant reference to the local Secretless broker before any Registry lookup. The broker is the policy decision point; the CLI proceeds only if the broker authorizes.

```bash
hackmyagent trust express \
  --grant grant://hackmyagent-trust \
  --atx ~/.opena2a/atx.json
```

Outcomes:

- **Broker authorizes** -> trust proceeds.
- **Broker denies (HTTP 403)** -> exit 3 with a pointer to `~/.secretless-ai/policies/`. AAP §6.6: the denial is opaque; reasons live only in the broker's signed audit log.
- **Broker unreachable** -> exit 4 with a `secretless broker start` hint.
- **Broker returns an unexpected status** -> exit 6. The response body is never echoed to the user.
- **No `--grant` flag** -> trust runs exactly as before; the gate is opt-in.

This is the second TypeScript AAP consumer (after `opena2a protect --grant`, opena2a-org/opena2a#179). Defends T-3002 (cross-tenant grant leakage), T-3003 (over-broad credential scope), T-3006 (credential leaking into agent context), T-8002 (audit attribution gap) at the CLI surface.

### OpenClaw and NemoClaw auto-detection

`hackmyagent secure` auto-detects OpenClaw and NemoClaw installations (`.openclaw/`, `.moltbot/`, `.nemoclaw/`, `openclaw.json`, `openclaw.plugin.json`). When detected, 28 NemoClaw plus 34 OpenClaw checks run alongside the standard suite. No separate command needed.

## Using with opena2a-cli

[`opena2a-cli`](https://github.com/opena2a-org/opena2a) is the unified CLI for the OpenA2A security tools. HackMyAgent powers `opena2a review`, `opena2a scan`, `opena2a protect`, `opena2a benchmark`, and `opena2a scan-soul`.

```bash
npm install -g opena2a-cli
opena2a review
```

## MCP server

HackMyAgent runs as an MCP server, so an AI coding assistant can scan the project it
is working in.

```bash
hackmyagent init-mcp --root /absolute/path/to/your/project
```

That writes the server into your client config (Claude Code, Cursor, VS Code) and
restarts are picked up on the client's next launch. Then ask the assistant:
"Run a deep security scan on this project."

Three tools are exposed:

| Tool | What it does |
|---|---|
| `hackmyagent_scan` | The full check suite. Read-only. |
| `hackmyagent_deep_scan` | Pattern + structural analysis, plus the artifact contents for the assistant to reason over. |
| `hackmyagent_benchmark` | OASB-1 compliance assessment at L1, L2 or L3. |

**Roots.** The server reads only inside the directories it was started with, and
there is no unconfined mode. `--root` is repeatable, so grant projects one at a
time:

```bash
hackmyagent init-mcp --root ~/work/api --root ~/work/web
```

The filesystem root and your home directory are not accepted, because granting
either hands every project and every credential file on the machine to whatever
model is driving the session — the same thing HackMyAgent reports as `MCP-001`
when it sees it in someone else's configuration. A path outside the roots is
refused with the roots named and the command to grant one.

**Fixes are terminal-only.** No MCP tool writes to your files. Findings carry
their fix command and you run it yourself:

```bash
hackmyagent secure --fix .
```

Verify what the server is allowed to reach:

```bash
grep -A3 hackmyagent .claude/settings.json    # or .cursor/mcp.json, .vscode/mcp.json
```

## Runtime protection (ARP)

ARP monitors agents during execution — rule-based patterns, statistical anomaly
detection, and LLM-assisted assessment — and runs as an HTTP reverse proxy for
OpenAI API, MCP and A2A traffic. It is driven from `opena2a runtime`
([opena2a-cli](https://github.com/opena2a-org/opena2a)).

## CI/CD integration

`secure` and `scan-soul` take `--ci` for non-interactive, byte-stable output. It also
turns contribution off for that run, so a build server never shares scan results on the
strength of an opt-in recorded earlier on the same machine. Most scanning commands take
`--json` — `check`, `secure`, `attack`, `scan`, `fix-all`, `scan-soul`, `harden-soul`, `red-team`, `wild`, `detect`, `trust`.
`secure` and `attack` also take `-f, --format <format>`; on those two commands `--json` is shorthand for `--format json`.

`--json` never changes the exit code: a command that exits 1 on findings exits 1 in both
channels. `--ci` mostly doesn't either — it selects how a run reports, not what it
concludes. The one exception is `scan-soul`, which additionally exits 1 under `--ci` on a
HIGH-severity SOUL finding (a governance violation, a profile mismatch, or an unrecognized
`--profile` value) that renders as a warning and passes CI without the flag — deliberate,
so a pipeline can opt into treating a misleading SOUL verdict as a failure. To gate a
pipeline on severity, read the exit code the command already returns; to gate on the
score, use `--fail-below <n>` on any output channel. A threshold only raises the exit
code: a run that could not read one of its inputs still exits 2, not 1.

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

SARIF output and a pre-commit hook: [`docs/use-cases/ci-pipeline.md`](docs/use-cases/ci-pipeline.md).

Suppressing a **check** (`--ignore CRED-001`, or `!CRED-001` in `.hmaignore`)
changes what the report lists, not what it measures: it is still scored, still
in the verdict, still in the exit code, and named on a `Suppressed` line. Use
`--fail-below <score>` to let a build pass over findings you have accepted — a
threshold in your pipeline config is auditable, a missing finding is not.

Excluding a **path** (`test-fixtures/` in `.hmaignore`) is a scope statement:
those paths leave the score and the exit code, as if you had not scanned them.
Always disclosed on a `Scope` line and as `outOfScope` in `--json`.

Excluding **one check on one path** (`danger.py:NEMO-009 # canary fixture` in
`.hmaignore`) is the narrow form of the path rule, with the same scope
semantics: that one finding leaves the score and the exit code while every
other check still runs on the path. The trailing `# <reason>` is required on
this form. Any rule may carry `expires:<YYYY-MM-DD>` at the end of the line;
the rule is active through the named day (UTC), and from the next day the
line is reported as an error and its findings return to the report.

Every rule and its match count are disclosed under `hmaignore` in `--json`.
A line the parser cannot apply (a glob in a path rule, a missing reason, a
bad or lapsed `expires:` date) is never a silent no-op: it prints as a
`.hmaignore:<line>` error by default, appears in `hmaignore.errors`, and the
line is not applied. Errors never change the exit code: an inert line hides
nothing, so everything it would have covered is already in the score and the
exit code. To gate CI on a clean ignore file, test the `--json` document instead:
`hackmyagent secure --ci --json . | jq -e '.hmaignore.errors | length == 0'`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Measured. No critical or high issues. |
| 1 | Measured. Critical or high severity issues found. For `scan-soul`, also conformance `none` — a critical governance control was not detected, whatever the score. |
| 2 | **Not measured.** For `red-team`, no score or risk level is reported. For `secure --deep`, the static results ARE reported and scored; the deep layer did not finish, so the run reaches no deep-scan verdict. For `secure` and `check`, a file or directory inside the target was discovered and could not be read (`EACCES`, `ELOOP`, an unreadable mount): what DID run is still reported and scored, and the score or risk level is an upper bound rather than a measurement of the tree — the run names each file and the errno (`SCAN-UNREAD-001`). The target does not exist (`check <missing path>`, an unknown package), was unreachable, answered no payload, or the command reaches no verdict by design. `red-team` and `attack --local` exit 2 on every run: both generate payloads without executing any against an agent, so neither concludes anything about the target. A scan whose plugins failed is also 2. `scan-soul` exits 2 over a tree with no governance file: no score or conformance level is reported, because nothing was read. For `secure -b oasb-1`, also the rating ladder: when no scored L1 control produced a result the rating prints as `Not Assessed` at exit 2 and the category results are still printed; when nothing at all was measured there is no compliance figure and `--fail-below` is not evaluated; a `--category` whose L2 or L3 controls did produce results keeps its measured figure, and a `--fail-below` breach over it exits 1. |
| 3 | QUARANTINE. Binary integrity check failed (tampered installation). |

Exit 2 is non-zero on purpose. A CI job that asked for a security verdict and
got "I could not reach the target" has not been told the target is safe. A
benchmark run that reached no scored control has not been given a rating either:
`Not Assessed` is the absence of one, not a low one.

## Auto-fix catalogue

`hackmyagent secure --fix` remediates ten checks; `--dry-run` previews the changes,
backups live in `.hackmyagent-backup/`, and `hackmyagent rollback` reverts them. The
table is in [`docs/SECURITY_CHECKS.md`](docs/SECURITY_CHECKS.md).

## Programmatic API

TypeScript entry points for the scanner, the runtime protection layer and the
NanoMind semantic compiler: [`docs/PROGRAMMATIC_API.md`](docs/PROGRAMMATIC_API.md).
Plugin authoring: [`docs/PLUGIN_API.md`](docs/PLUGIN_API.md).

## Use cases

Step-by-step guides for scanning an agent, red-teaming an MCP server, securing
OpenClaw and wiring a CI pipeline: [`docs/USE-CASES.md`](docs/USE-CASES.md).

## Contributing

Apache 2.0. Pull requests from outside the organization are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) has the development loop and what happens to a pull request opened from a fork.

```bash
git clone https://github.com/opena2a-org/hackmyagent.git
cd hackmyagent && npm install && npm run build && npm test
```

Security issues: see [SECURITY.md](SECURITY.md). Do not open a public issue.

## Links

- [Website](https://hackmyagent.com)
- [Security Checks Reference](docs/SECURITY_CHECKS.md)
- [OpenA2A CLI](https://github.com/opena2a-org/opena2a)
- [aicomply](https://github.com/opena2a-org/aicomply) — inline PII, credential, and regulated-data classification for agent I/O at runtime (HMA scans the code; aicomply guards the live stream)
- [Demos](https://opena2a.org/demos)
- [Documentation](https://opena2a.org/docs)
- [Research](https://research.opena2a.org)

Part of the [OpenA2A](https://opena2a.org) security platform.

## License

Apache-2.0. See [LICENSE](LICENSE).

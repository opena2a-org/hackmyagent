# Command reference

HackMyAgent's main commands, their flags, and the exit codes. The [README](../README.md) shows one command per job. `hackmyagent --help` lists the commands, and `hackmyagent <command> --help` prints one command's options.

## Scan anything

`hackmyagent check <target>` accepts each of these surfaces. `secure` scans your own project. `scan-soul` scans governance.

| Surface | Command | What gets scanned |
|---|---|---|
| Your own project | `hackmyagent secure` | 261 static checks + NanoMind on current directory |
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
hackmyagent secure --deep                     # + LLM analysis and 20-probe simulation (sends redacted files to api.anthropic.com when ANTHROPIC_API_KEY is set)
hackmyagent secure --static-only              # static checks only, faster
hackmyagent secure --include-dist package     # extracted npm package: also scan dist/
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

Recording: [hackmyagent secure: scores a sample agent project, then applies the fixes it can](vhs/secure.gif). Recorded over a sample project with fake credentials, setup not shown. Text version: [docs/vhs/secure-capture.txt](vhs/secure-capture.txt); provenance: [docs/vhs/secure.json](vhs/secure.json); re-render: `docs/vhs/record-secure.sh`.

### NanoMind semantic analysis

Runs on every `secure` scan. On first use, HMA downloads an ONNX classifier from Hugging Face ([`opena2a/nanomind-security-classifier`](https://huggingface.co/opena2a/nanomind-security-classifier)) into `~/.nanomind/models`. Before the first request it prints on stderr, in every output format, the download size, the hosts (huggingface.co and Hugging Face's content CDN), the cache path and the flag that skips it (`--static-only`). Later scans use the cached copy and make no model request. Behind a proxy, the download goes through the one in `HTTPS_PROXY` (or `HTTP_PROXY` when that is unset), skipping hosts listed in `NO_PROXY`; the notice names the proxy by host and port, never by the credentials in its URL.

- 7 AST analyzers: `capability`, `credential`, `governance`, `scope`, `prompt`, `code`, `stego`. 9 attack classes: `exfiltration`, `injection`, `privilege_escalation`, `persistence`, `credential_abuse`, `lateral_movement`, `social_engineering`, `policy_violation`, `benign`.
- `--deep` adds LLM analysis and the 20-probe behavioural simulation in every output format (the simulation needs a probe executor; otherwise `NOT MEASURED`); `--json` carries the simulation result as the advisory `simulation` block. With `ANTHROPIC_API_KEY` set, the LLM analysis sends each agent instruction and MCP config file, with credential values removed, to `api.anthropic.com`, one request per file, and a stderr line before the first request names the host and the number of files and requests. `.env` files, `config.json`, `config.yaml`, `config.yml` and `settings.json` are never sent; `--json` lists the ones it found under `coverage.withheldFromLayer3`, and the static and semantic checks still examine them on your machine. `--static-only` disables the semantic layer. `--nanomind` opts into the generative analyst: per-finding threat narratives on HIGH or CRITICAL findings, and a coverage sweep whose verdicts surface as advisory escalations for human review (never changing the score, findings, or exit code).

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

![hackmyagent attack red-teaming a live DVAA agent at passive intensity, recorded with hackmyagent 0.33.2, 2026-10-10. The report prints Risk Score: 100/100 (CRITICAL) and Attacks: 28 sent, 28 answered, 28 successful, 0 blocked, then 14 categories with every attack in each one successful.](vhs/attack-dvaa.gif)

Recorded with hackmyagent 0.33.2 built from this repository on 2026-10-10 against `opena2a/dvaa:0.9.1`; the wait of over a minute while the 28 attacks run is cut, and the report's Duration line shows the real run time. Text version: [docs/vhs/attack-dvaa-capture.txt](vhs/attack-dvaa-capture.txt); re-render: `vhs docs/vhs/attack-dvaa.tape`.

### `scan-soul` and `harden-soul` (governance)

```bash
hackmyagent scan-soul                     # scan current directory for SOUL.md
hackmyagent scan-soul --deep              # LLM semantic analysis: sends the governance file, credential values removed, to api.anthropic.com (requires ANTHROPIC_API_KEY)
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

![hackmyagent detect on demo-agents, five sample agent projects with fake credentials, recorded with hackmyagent 0.33.0, 2026-09-15, setup not shown. The terminal prints a table of the five projects worst first, reports 4 of 5 need action (4 critical, 5 high), and lists each project's critical and high findings with a Fix command and, where a finding comes from one line of a file, a Verify command that prints that line.](vhs/detect.gif)

Recorded with hackmyagent 0.33.0 on 2026-09-15 over five sample agent projects with fake credentials, setup not shown. Text version: [docs/vhs/detect-capture.txt](vhs/detect-capture.txt); provenance: [docs/vhs/detect.json](vhs/detect.json); re-render: `docs/vhs/record-detect.sh`.

### `trust`, `explain`, `nanomind`

```bash
hackmyagent trust server-filesystem      # MCP shorthand trust lookup against the Registry
hackmyagent trust --audit package.json   # audit every dependency
hackmyagent explain CRED-001             # explain a check finding
hackmyagent nanomind setup               # install the optional generative analyst daemon
hackmyagent nanomind status              # check model and runtime status
hackmyagent trust express --grant grant://hackmyagent-trust --atx ~/.opena2a/atx.json
```

With `--grant`, `trust` is gated by the [Agent Authorization Protocol](https://github.com/opena2a-standards/agent-authorization-protocol): the CLI presents an ATX and a grant reference to the local Secretless broker before any Registry lookup and proceeds only if the broker authorizes. A denial (HTTP 403) exits 3 with a pointer to `~/.secretless-ai/policies/`, and its reasons live only in the broker's signed audit log (AAP §6.6); an unreachable broker exits 4 with a `npx secretless-ai broker start` hint; an unexpected status exits 6 and the response body is never echoed. Without `--grant`, `trust` runs as before.

### OpenClaw and NemoClaw auto-detection

`hackmyagent secure` runs the OpenClaw check groups and the NemoClaw sandbox checks (`NEMO-`) as part of the standard suite on any target. No separate command needed. The gateway (`GATEWAY-`) and CVE (`CVE-`) findings count only when the target is an OpenClaw project, one that holds `.openclaw/`, `.moltbot/`, `.clawdbot/`, `openclaw.json`, `HEARTBEAT.md`, `SKILL.md`, a `*.skill.md` file or a `skills/` directory. An install in your home directory outside the target (`~/.openclaw`, `~/.nemoclaw`, `~/.openshell`, `~/.moltbot`, `~/.clawdbot`) is listed under Machine Posture with the `secure` command that scans it; it is not scanned or scored in that run.

## Using with opena2a-cli

[`opena2a-cli`](https://github.com/opena2a-org/opena2a) is the unified CLI for the OpenA2A security tools (`npm install -g opena2a-cli`, then `opena2a review`). HackMyAgent powers `opena2a review`, `opena2a scan`, `opena2a protect`, `opena2a benchmark`, and `opena2a scan-soul`.

Runtime protection (ARP) is driven from `opena2a runtime`. ARP monitors agents during execution (rule-based patterns, statistical anomaly detection, and LLM-assisted assessment) and runs as an HTTP reverse proxy for OpenAI API, MCP and A2A traffic.

## MCP server

HackMyAgent runs as an MCP server, so an AI coding assistant can scan the project it is working in:

```bash
hackmyagent init-mcp --root /absolute/path/to/your/project
```

That writes the server into your client config (Claude Code, Cursor, VS Code), picked up on the client's next launch. Then ask the assistant: "Run a deep security scan on this project." Three tools are exposed: `hackmyagent_scan` (the full check suite, read-only), `hackmyagent_deep_scan` (pattern and structural analysis, plus the agent instruction and MCP config file contents for the assistant to reason over, with credential values removed; `.env` and config files are named under `filesWithheld` and their contents are not returned) and `hackmyagent_benchmark` (OASB-1 compliance at L1, L2 or L3).

**Roots.** The server reads only inside the directories it was started with, and there is no unconfined mode. `--root` is repeatable, so grant projects one at a time (`--root ~/work/api --root ~/work/web`). The filesystem root and your home directory are not accepted, because granting either hands every project and every credential file on the machine to whatever model is driving the session, the same thing HackMyAgent reports as `MCP-001` when it sees it in someone else's configuration. A path outside the roots is refused with the roots named and the command to grant one.

**Fixes are terminal-only.** No MCP tool writes to your files. Findings carry their fix command, such as `hackmyagent secure --fix .`, and you run it yourself. Verify what the server is allowed to reach:

```bash
grep -A3 hackmyagent .mcp.json    # Claude Code; or .cursor/mcp.json, .vscode/mcp.json
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Measured. No critical or high issues. |
| 1 | Measured. Critical or high severity issues found. For `scan-soul`, also conformance `none`: a critical governance control was not detected, whatever the score. |
| 2 | **Not measured.** Each case is in the table below. |
| 3 | QUARANTINE. Binary integrity check failed (tampered installation). |

### Exit 2, case by case

| Command | Exit 2 means |
|---|---|
| `scan-text` | The operand does not exist or could not be read, so no text was scanned and no finding is reported on either channel. |
| `red-team` | No score or risk level is reported. |
| `red-team`, `attack --local` | They exit 2 on every run: both generate payloads without executing any against an agent, so neither concludes anything about the target. |
| `secure --deep` | The static results ARE reported and scored; the deep layer did not finish, so the run reaches no deep-scan verdict. |
| `secure`, `check` | A file or directory inside the target was discovered and could not be read (`EACCES`, `ELOOP`, an unreadable mount): what DID run is still reported and scored, and the score or risk level is an upper bound rather than a measurement of the tree. The run names each file and the errno (`SCAN-UNREAD-001`). |
| any command | The target does not exist (`check <missing path>`, an unknown package), was unreachable, answered no payload, or the command reaches no verdict by design. |
| any scan | A scan whose plugins failed is also 2. |
| `scan-soul` | It exits 2 over a tree with no governance file: no score or conformance level is reported, because nothing was read. |
| `secure -b oasb-2` | It does the same for its governance half: the governance score, conformance and composite print as not measured. |
| `secure -b oasb-1` | Also the rating ladder: when no scored L1 control produced a result the rating prints as `Not Assessed` at exit 2 and the category results are still printed; when nothing at all was measured there is no compliance figure and `--fail-below` is not evaluated; a `--category` whose L2 or L3 controls did produce results keeps its measured figure, and a `--fail-below` breach over it exits 1. |

Exit 2 is non-zero on purpose. A CI job that asked for a security verdict and got "I could not reach the target" has not been told the target is safe. A benchmark run that reached no scored control has not been given a rating either: `Not Assessed` is the absence of one, not a low one.

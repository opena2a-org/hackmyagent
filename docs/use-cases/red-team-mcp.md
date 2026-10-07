# Use Case: Red-Team My MCP Servers

**Time:** 10 minutes
**Goal:** Test your MCP server configurations for prompt injection, data exfiltration, and capability abuse.

---

## Overview

This workflow combines two approaches:

1. **Static analysis** (`secure`) -- checks MCP config files for misconfigurations
2. **Adversarial testing** (`attack`) -- sends up to 164 attack payloads against your agent or MCP server

## Step 1: Check MCP configurations

```bash
npx hackmyagent secure
```

HMA auto-detects MCP configuration files in standard locations:

- `.cursor/mcp.json`
- `.vscode/mcp.json`
- `claude_desktop_config.json`
- `~/.config/claude/claude_desktop_config.json`

**Output** from this repository's `test-fixtures/insecure-mcp`, trimmed to the MCP findings (cuts marked `...`):

```
Scanning .../insecure-mcp...

Discovering assembly components...
Found 1 assembly components, simulating assembly...
Scanning assembled prompt for lifecycle attacks...
Assembly scan complete: 0 findings from 1 components
NanoMind: 3 artifact(s) compiled, 2 semantic finding(s) added

  insecure-mcp-server  v1.0.0 · mcp · 3 files analyzed
  7 critical issues found

  Security  ━━━━━━━━━━━━━━━━━━━━ 15/100

  ── Observations ────────────────────────────────────────────
  Surfaces    mcp · 3 semantic artifacts · all 3 artifacts reached 0-6 of 7 analyzer families
  Checks      317 static declared · 63 of 63 check groups ran · 3 semantic (NanoMind AST, 0-6 of 7 analyzer families) · 3 files read by static checks
  Coverage    19 of 25 categories examined · 6 unexamined (read no file) · 37 checks reported an absent mitigation (not shown)
  Unexamined  A2A, capabilities, governance, heartbeat, prompt, skill
  Artifacts   mcp.json  mcp_config · malicious · no inferred capabilities  (no declared constraints)
  Categories  credentials (5 critical) · MCP (2 critical) · sandbox (1 medium) · supply-chain (1 medium) · auth (1 high) · git hygiene (1 low) · 13 others clear
  Verdict     Not safe to ship. Exposed Credential in mcp.json:15 + 17 more. Fix before using in production.


  ── Findings ────────────────────────────────────────────────
  7 critical  5 high  4 medium  2 low

  ...

  │ CRITICAL  Unrestricted Shell Server
  │ mcp.json
  │ Unrestricted shell access lets the AI execute any command including destructive operations. Whitelisting specific commands limits what can be run.
  │ Fix: Add "allowedCommands": ["ls", "cat", "grep"] to the shell server config in mcp.json

  ...

  │ HIGH  MCP Root Filesystem Access
  │ mcp.json
  │ Root or home directory access lets MCP servers read/write any file on the system. Restrict to project-relative paths (./data or ./) to limit blast radius.
  │ →  hackmyagent secure --fix

  │ HIGH  Wildcard Tool Access
  │ mcp.json
  │ Wildcard tool access gives the AI unrestricted capabilities. Limit to only the tools your workflow actually needs to reduce attack surface.
  │ Fix: Replace "*" with specific tool names in allowedTools (e.g., ["read_file", "list_directory"])
  │ ...

  │ HIGH  Sensitive MCP Tools
  │ mcp.json
  │ Tools named shell, exec, or eval typically provide arbitrary code execution. A prompt injection that invokes these tools can fully compromise the host system.

  │ MEDIUM  MCP Request Timeout
  │ mcp.json
  │ Without request timeouts, a hung or malicious MCP server can block the agent indefinitely, causing denial-of-service and preventing other tools from executing.

  + 8 more findings (Missing .gitignore, MCP Retry Limits)  (run with --verbose to see all)

  Path forward: 15 -> 100 by fixing 7 critical + 5 high

  ── Next Steps ─────────────────────────────────────────────────
  Protect credentials:  npx opena2a-cli protect .
  Audit MCP servers:    npx opena2a-cli mcp audit  (run from project dir)
  Auto-fix all issues:  hackmyagent secure . --fix
  AI analysis:          hackmyagent check . --nanomind  (attack vectors + targeted remediation)
  All commands:         hackmyagent --help
  opena2a is a separate CLI — install with: npm i -g opena2a-cli

  Scanned with hackmyagent v0.33.2
```

Fix configuration issues before proceeding to adversarial testing.

## Step 2: Inspect the payload set

`--local` generates the payloads and checks that they parse. It contacts no
agent, so it reports no risk score:

```bash
npx hackmyagent attack --local --category prompt-injection
```

**Output:**

```
HackMyAgent Attack Mode
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Target: Local Simulation
Intensity: active
Categories: prompt-injection

NOT MEASURED — --local simulates the agent's response instead of contacting one, so no behaviour of any target was observed.
Duration: 1ms

Attacks: 7 sent | 0 answered | 7 unanswered

--local generates payloads and checks that they parse. It does not
test an agent. To measure one, point hackmyagent attack at its endpoint:

  $ hackmyagent attack https://your-agent.example/v1/chat
```

Exit code 2. Use this to see which payloads a category contains before you run
them against something. Every verdict about your agent comes from Step 3.

## Step 3: Test a live MCP server

If you have an MCP server running locally:

```bash
npx hackmyagent attack http://localhost:3010 --target-type mcp --category mcp-exploitation
```

This is the step that measures your server. Findings depend on what your server
answers.

**Abbreviated sample; your output will differ:**

```
Risk Score: 55/100 (HIGH)
Duration: 8420ms

Attacks: 10 sent | 10 answered | 3 successful | 5 blocked | 2 inconclusive
```

`attack` probes the endpoint once before sending any payload. If nothing is
listening, or if no payload is answered, it exits 2 and reports no score --
a suite that never arrived says nothing about the server.

## Step 4: Run the full payload suite

For thorough coverage, use aggressive intensity (all 164 payloads):

```bash
npx hackmyagent attack http://localhost:3010 --target-type mcp --intensity aggressive
```

This includes creative and risky payloads that test edge cases in agent behavior.

## Step 5: Fix and re-test

After addressing findings:

1. Update your system prompt to add instruction boundaries
2. Configure tool allowlists in your MCP server
3. Add authentication to MCP endpoints
4. Re-run the attack against the running server to verify fixes:

```bash
npx hackmyagent attack http://localhost:3010 --target-type mcp
```

A clean run shows 0 successful payloads and exits `0`. If it exits `2`, the
server was not reached and nothing was verified -- start it and re-run.

---

## Output formats

Generate reports for different consumers:

```bash
# JSON for scripting
npx hackmyagent attack http://localhost:3010 --target-type mcp --format json

# SARIF for GitHub Security tab
npx hackmyagent attack http://localhost:3010 --target-type mcp -f sarif -o results.sarif

# CI gate -- fail if medium+ vulnerabilities found
npx hackmyagent attack http://localhost:3010 --target-type mcp --fail-on-vulnerable medium
```

Each of these names an endpoint. `--local` is not a CI gate: it contacts no
agent, so it always exits 2 and never reports a vulnerability to fail on.

## Tips

- Use `--system-prompt "Your prompt here"` to test a specific system prompt against payloads.
- Use `--payload-file custom.json` to add your own attack payloads.
- Only test systems you own or have written authorization to test.

## Next steps

- [Secure your OpenClaw installation](openclaw-security.md)
- [Add HMA to your CI/CD pipeline](ci-pipeline.md)
- See the full [Security Checks Reference](../SECURITY_CHECKS.md) for all check IDs

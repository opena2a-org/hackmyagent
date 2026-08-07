# Use Case: Red-Team My MCP Servers

**Time:** 10 minutes
**Goal:** Test your MCP server configurations for prompt injection, data exfiltration, and capability abuse.

---

## Overview

This workflow combines two approaches:

1. **Static analysis** (`secure`) -- checks MCP config files for misconfigurations
2. **Adversarial testing** (`attack`) -- sends 75 attack payloads against your agent or MCP server

## Step 1: Check MCP configurations

```bash
npx hackmyagent secure
```

HMA auto-detects MCP configuration files in standard locations:

- `.cursor/mcp.json`
- `.vscode/mcp.json`
- `claude_desktop_config.json`
- `~/.config/claude/claude_desktop_config.json`

**Expected output (MCP-related findings):**

```
HackMyAgent v0.10.1 -- Security Scanner

Scanning: /home/user/my-agent

  HIGH      MCP-001   Root filesystem access in MCP server
            Found: server-filesystem allowed path: /
            Fix:   Scope to project directory only

  HIGH      MCP-003   MCP server bound to 0.0.0.0
            Found: everything server in .cursor/mcp.json
            Fix:   Bind to 127.0.0.1

  MEDIUM    MCP-005   MCP server with unrestricted tool access
            Found: 14 tools enabled, no allowlist configured
            Fix:   Define an explicit tool allowlist

  MEDIUM    MCP-007   No authentication on MCP server
            Found: stdio transport with no auth token
            Fix:   Add bearer token authentication

Summary: 0 critical, 2 high, 2 medium, 0 low
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
answers, so the report below is illustrative of the shape, not of your results:

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

# Use Case: Red-Team My MCP Servers

**Time:** 10 minutes
**Goal:** Test your MCP server configurations for prompt injection, data exfiltration, and capability abuse.

---

## Overview

This workflow combines two approaches:

1. **Static analysis** (`secure`) -- checks MCP config files for misconfigurations
2. **Adversarial testing** (`attack`) -- sends attack payloads against your agent or MCP server: up to 164 across 16 categories, all of them at `--intensity aggressive`

## Step 1: Check MCP configurations

```bash
npx hackmyagent secure
```

HMA auto-detects MCP configuration files in standard locations:

- `.cursor/mcp.json`
- `.vscode/mcp.json`
- `claude_desktop_config.json`
- `~/.config/claude/claude_desktop_config.json`

**Example output**, captured from a real run on a project whose `.cursor/mcp.json` grants `@modelcontextprotocol/server-filesystem` the root path `/`. Lines marked `...` are abridged:

```
Scanning /home/user/my-agent...

  my-agent  v1.0.0 · library · 1 file analyzed
  1 critical issue found

  Security  ━━━━━━━━━━━━━━━━━━━━ 69/100  (score capped from 80 to 69 — verdict is fail-direction)

  ── Observations ────────────────────────────────────────────
  ...
  Categories  MCP (1 critical) · supply-chain (1 medium) · 13 others clear
  Verdict     Not safe to ship. Overprivileged MCP server scope in .cursor/mcp.json:5 + 1 more. Fix before using in production.

  ── Findings ────────────────────────────────────────────────
  1 critical  1 medium

  │ CRITICAL  Overprivileged MCP server scope
  │ .cursor/mcp.json:5
  │ Overprivileged filesystem access allows the agent (or an attacker via prompt injection) to read sensitive files like SSH keys, credentials, and system configs.
  │ Verify: sed -n '5p' /home/user/my-agent/.cursor/mcp.json
  │ Fix: Scope "filesystem" to the project directory: replace "/" with "./" or a specific subdirectory.

  │ MEDIUM  Dependency Lock File
  │ package-lock.json
  │ Without a lock file, npm install can resolve to different package versions on different machines, including versions with known vulnerabilities or supply-chain backdoors.

  Path forward: 69 -> 95 by fixing 1 critical
  ...
  Audit MCP servers:    npx opena2a-cli mcp audit  (run from project dir)
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

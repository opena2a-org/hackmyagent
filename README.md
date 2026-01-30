# HackMyAgent

Security toolkit for AI agents. Verify skills, harden setups, scan for exposures.

```bash
npx hackmyagent check @publisher/skill    # verify a skill before installing
npx hackmyagent secure                     # harden your agent setup
npx hackmyagent scan example.com           # scan for exposures
```

## Why?

AI agents are powerful but vulnerable. Skills can be malicious. Configs can leak secrets. MCP servers can be exposed. HackMyAgent helps you:

- **Check** skills before installing them (publisher verification, permission analysis)
- **Secure** your agent setup (68-point scan, one-click hardening)
- **Scan** for exposed infrastructure (public MCP endpoints, leaked configs)

## Installation

```bash
# Use directly with npx (no install needed)
npx hackmyagent check @some/skill

# Or install globally
npm install -g hackmyagent
```

## Commands

### `hackmyagent check`

Verify a skill before installing.

```bash
hackmyagent check @publisher/skill-name
```

Checks:
- Publisher identity (DNS TXT, GitHub proof)
- Permissions requested (filesystem, network, shell)
- Revocation status (global blocklist)

### `hackmyagent secure`

Harden your local agent setup.

```bash
hackmyagent secure
```

Scans for and fixes:
- Network exposure (gateway binding, open ports)
- Authentication issues (missing auth, weak configs)
- Credential exposure (plaintext API keys)
- Permission problems (overly permissive files)
- MCP server misconfigurations
- Dependency vulnerabilities
- And more (68 checks across 16 categories)

### `hackmyagent scan`

Scan external infrastructure for exposures.

```bash
hackmyagent scan example.com
```

Finds:
- Exposed MCP endpoints
- Public Claude.md files
- Leaked API keys
- Debug modes enabled

## Supported Platforms

- Claude Code (CLAUDE.md, skills, MCP servers)
- Cursor (.cursor/ rules, MCP)
- Clawdbot/Moltbot
- Generic MCP servers

## Enterprise

Need centralized policy management, compliance, and audit trails? Check out [AIM (Agent Identity Management)](https://github.com/opena2a-org/agent-identity-management).

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache-2.0

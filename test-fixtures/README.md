# Test Fixtures

Sample projects with intentional security issues for testing the scanner.

## Usage

```bash
# Scan a specific test fixture
npx hackmyagent secure test-fixtures/insecure-api

# Scan with auto-fix (creates backup first)
npx hackmyagent secure test-fixtures/insecure-api --fix

# Preview fixes without applying
npx hackmyagent secure test-fixtures/insecure-api --fix --dry-run
```

## Test Fixtures

| Directory | Project Type | Issues |
|-----------|--------------|--------|
| `insecure-api` | API Server | Exposed credentials, insecure network binding, missing .gitignore |
| `insecure-mcp` | MCP Server | Root filesystem access, hardcoded API keys, unrestricted shell |
| `insecure-library` | Library | Missing .gitignore patterns, .env not ignored |
| `insecure-claude` | Library | Overly permissive Claude Code settings, dangerous bash commands |
| `insecure-openclaw` | OpenClaw Gateway | Unsigned skills, remote fetch patterns, data exfiltration, disabled security |
| `clean-project` | Library | No issues (should score 100/100) |

## Expected Results

### insecure-api (Score: 27/100)
- CRED-001: Anthropic/OpenAI API keys in config.json
- GIT-001: Missing .gitignore
- GIT-002: Missing security patterns in .gitignore
- NET-001: Server bound to 0.0.0.0

### insecure-mcp (Score: 0/100)
- CRED-001: OpenAI API key in mcp.json
- MCP-001: Root filesystem access (/)
- MCP-002: Unrestricted shell server
- MCP-003: Hardcoded secrets in MCP env vars
- MCP-005: Wildcard tool access (*)
- GIT-001/002: Missing .gitignore

### insecure-library (Score: 60/100)
- GIT-002: Missing .env, secrets.json, *.pem, *.key in .gitignore
- GIT-003: .env exists but not in .gitignore

### insecure-claude (Score: 60/100)
- CLAUDE-002: Overly permissive Bash(*), Read(*), Write(*)
- CLAUDE-003: Dangerous bash commands (rm -rf, sudo, chmod 777)

### insecure-openclaw (Score: 0/100)
- SKILL-001: Unsigned skills
- SKILL-002: Remote fetch patterns (curl | bash)
- SKILL-003: Heartbeat installation
- SKILL-004: Filesystem wildcard access
- SKILL-005: Credential file access (~/.aws, ~/.config/solana)
- SKILL-006: Data exfiltration (webhook.site)
- SKILL-007: ClickFix social engineering
- HEARTBEAT-001: Unverified URLs
- HEARTBEAT-004: Dangerous capabilities
- GATEWAY-001: Bound to 0.0.0.0
- GATEWAY-004: Approvals disabled
- GATEWAY-005: Sandbox disabled
- CONFIG-001: Session tokens in .env
- CONFIG-004: Plaintext API keys

### clean-project (Score: 100/100)
- No issues found

## Testing Auto-Fix

```bash
# Test auto-fix on insecure-api
npx hackmyagent secure test-fixtures/insecure-api --fix

# Verify the fix
npx hackmyagent secure test-fixtures/insecure-api

# Rollback if needed
npx hackmyagent rollback test-fixtures/insecure-api
```

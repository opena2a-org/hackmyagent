# Insecure OpenClaw Test Fixture

This fixture contains intentional security vulnerabilities for testing:

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

Expected score: ~0/100

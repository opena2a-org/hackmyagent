# support-triage-agent

Support team agent that answers first-line questions on incoming tickets, tags
them and hands the rest to a person. Its behaviour is set by `SOUL.md`, which
the triage code loads as the system prompt.

It starts one MCP server from `.mcp.json`, a Zendesk server.

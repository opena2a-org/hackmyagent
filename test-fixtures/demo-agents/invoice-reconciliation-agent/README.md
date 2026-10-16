# invoice-reconciliation-agent

Finance agent for month-end close. It matches supplier invoices against
purchase orders in the accounts payable ledger, posts the invoices without a
match to Slack and drafts reversing entries for duplicates.

The project is set up for Claude Code (`CLAUDE.md`, `.claude/settings.json` and
the `reconcile-ledger` skill) and starts three MCP servers from `.mcp.json`:
Postgres, a filesystem server and Slack.

# deploy-runbook-agent

Platform team agent for on-call. It takes a request from the incident channel,
asks a model which steps of the runbooks in `runbooks/` apply, and runs the
shell commands that come back.

The project is set up for Claude Code (`.claude/settings.json`) and starts three
MCP servers from `.mcp.json`: a shell server, a Kubernetes server and a GitHub
server. It has no governance file.

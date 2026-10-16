---
type: security
---
Deep analysis no longer sends `.env` files or `config.json`, `config.yaml`, `config.yml` and `settings.json` to the analysis provider. Every file it does send, and every file the `hackmyagent_deep_scan` MCP tool returns, passes through the same credential redaction as the behavioural simulation. A run that sends anything says so first on stderr, naming the host and the number of files.

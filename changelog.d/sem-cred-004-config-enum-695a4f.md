---
type: fixed
issue: 352
---
SEM-CRED-004 no longer reports a short lowercase configuration enum in an MCP server env block as a hardcoded secret: an authentication-method value such as `pat` or `oauth` under a key like `AZURE_DEVOPS_AUTH_METHOD` is a documented choice, not a credential. 0.33.2 reported it CRITICAL on the key name alone. A real token under a key of the same shape, such as `AUTH_TOKEN`, is reported as before. (#352)

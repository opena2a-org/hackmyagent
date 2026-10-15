# HackMyAgent Test Server

A configurable test server that simulates AI agents with different security postures. Use this to validate HackMyAgent attack mode.

## Security Modes

| Mode | Description | Measured result |
|------|-------------|-----------------|
| `secure` | Properly blocks all attacks with refusal messages | 0 of 111 successful, risk `secure`, exit 0 |
| `vulnerable` | Susceptible to some attacks (prompt injection, data leaks) | 7 of 111 successful, exit 1 |
| `very-vulnerable` | Falls for most attacks | 106 of 111 successful, exit 1 |

Measured with `hackmyagent attack <url> --api-format openai --delay 0` at the
default `active` intensity (111 payloads). `__tests__/attack/test-server-modes.test.ts`
runs all three modes as a regression gate.

The server listens on `127.0.0.1` by default. Set `HOST` to listen elsewhere,
and `PORT=0` to take a free port (the startup line prints the one bound).

## Quick Start

```bash
# Start vulnerable server (default)
node server.js

# Start secure server
SECURITY_MODE=secure node server.js

# Start very vulnerable server
SECURITY_MODE=very-vulnerable node server.js
```

## Test with HackMyAgent

```bash
# Basic attack test
npx hackmyagent attack http://localhost:3001/v1/chat/completions --api-format openai

# Full aggressive test
npx hackmyagent attack http://localhost:3001/v1/chat/completions --api-format openai --intensity aggressive

# Single category
npx hackmyagent attack http://localhost:3001/v1/chat/completions --api-format openai --category prompt-injection
```

## API Endpoints

- `POST /v1/chat/completions` - OpenAI-compatible chat endpoint
- `GET /health` - Health check (returns security mode)

## Request Format

```json
{
  "model": "test-agent",
  "messages": [
    {"role": "system", "content": "You are a helpful assistant"},
    {"role": "user", "content": "Hello!"}
  ]
}
```

## Response Format

Standard OpenAI chat completion response format.

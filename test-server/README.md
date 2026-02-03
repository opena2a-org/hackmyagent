# HackMyAgent Test Server

A configurable test server that simulates AI agents with different security postures. Use this to validate HackMyAgent attack mode.

## Security Modes

| Mode | Description | Expected Results |
|------|-------------|------------------|
| `secure` | Properly blocks all attacks with refusal messages | 0 successful attacks |
| `vulnerable` | Susceptible to some attacks (prompt injection, data leaks) | ~30-50% successful attacks |
| `very-vulnerable` | Falls for most attacks | ~80-100% successful attacks |

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

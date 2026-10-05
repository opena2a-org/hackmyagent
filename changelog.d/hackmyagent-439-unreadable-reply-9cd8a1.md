---
type: fixed
issue: 439
---
#### attack no longer scores a target SECURE when its replies carry no text it can read (#439)

- `attack -t a2a`, `-t mcp`, `--api-format custom`, `--api-format mcp-jsonrpc`
  and `--api-format a2a` analyzed the raw JSON of a reply they could not read.
  A gateway answering every payload with `200 {"error":"unauthorized"}` scored
  `0/100 (SECURE)` at exit 0, and under `-t a2a` the word `unauthorized` was
  counted as four blocked attacks the agent never blocked.
- A reply is now answered only when it carries text where its format puts it,
  for example `choices[0].message.content` for openai or `content` for a2a. A
  run in which no reply did reports NOT MEASURED at exit 2 under every
  `--target-type` and `--api-format`, and says the target replied and where
  the text was looked for, instead of "No payload reached".

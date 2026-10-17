---
type: added
---
#### The agent-endpoint choice in `docs/chooser.json` carries an example for `attack` and for its next command, run against a local agent endpoint that a committed fixture starts, with the exit code and the captured output held to the build

- `test-fixtures/prompt-leaking-agent/serve.mjs` answers OpenAI chat
  completion requests on 127.0.0.1. A message that names its prompt or
  instructions gets its instructions back in quotes, and any other message
  gets a refusal.
- `attack http://127.0.0.1:<port>/v1/chat/completions` against it exits 1:
  111 payloads sent, 18 successful, 93 blocked, risk score 100/100
  (CRITICAL). The same command with `--intensity aggressive` exits 1 with 164
  sent, 27 successful and 137 blocked. The output is in
  `docs/captures/agent-endpoint.txt` and `docs/captures/agent-endpoint-next.txt`.
- Both examples run the command as a reader copies it, with no `--delay`, so
  `attack` waits its default 1000 ms after each payload and the two runs last
  at least 111 and 164 seconds. `scripts/chooser-captures.mjs` now stops a run
  after 240 seconds instead of 150.
- The line on what the choice's exit codes mean now reads "Exit 1 is a high
  or critical risk score from the payloads that succeeded". It read "Exit 1 is
  a payload that succeeded", but a run in which one medium payload succeeds
  scores 15/100 (LOW) and exits 0.
- Every choice and next command in `docs/chooser.json` now has an example.

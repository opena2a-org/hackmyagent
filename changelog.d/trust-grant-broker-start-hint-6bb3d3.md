---
type: fixed
---
- `hackmyagent trust --grant` names a broker start command that runs. When the
  Secretless broker was unreachable, the hint called a `secretless` command,
  which the `secretless-ai` package does not install, so following it ended
  in "command not found". The hint now reads `npx secretless-ai broker start`.

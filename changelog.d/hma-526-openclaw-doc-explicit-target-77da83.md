---
type: fixed
issue: 526
---
#### `docs/SECURITY_CHECKS.md` names the directory in every `secure-openclaw --fix` example (#526)

- **The OpenClaw usage block no longer shows a `--fix` that acts on your home folder by
  default.** It documented `hackmyagent secure-openclaw` as scanning "default ~/.moltbot" and
  followed it with `hackmyagent secure-openclaw --fix` and no directory. The real default is
  the first of `~/.openclaw`, `~/.moltbot`, `~/.clawdbot` that exists, so running the two lines
  verbatim in a release walkthrough rewrote 250 real `SKILL.md` files under `~/.openclaw`
  (restored with `rollback`). The block now states the default order, names `~/.openclaw` in
  every `--fix` example, shows `--fix --dry-run` first and the `rollback` that undoes it, and
  says the no-argument form acts on a real home directory. The `[directory]` help text for
  `secure-openclaw` now lists `~/.clawdbot` as well. A repo test fails on any README or
  `docs/` line that shows `secure-openclaw` or `secure-nemoclaw` with `--fix` and no
  directory. Tests: `__tests__/repo/home-default-fix-examples.test.ts`.

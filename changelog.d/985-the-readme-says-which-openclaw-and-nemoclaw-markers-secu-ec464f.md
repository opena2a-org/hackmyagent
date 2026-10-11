---
type: fixed
issue: 985
---
#### The README says which OpenClaw and NemoClaw markers `secure` acts on (#985)

- The README said `secure` detects `.nemoclaw/` and `openclaw.plugin.json` and runs
  their check groups. Neither is read: a target holding only `openclaw.plugin.json` scans
  as a library, and a NemoClaw install in the home directory is listed under Machine
  Posture without being scanned. The paragraph now names the markers that make a target
  an OpenClaw project (`.openclaw/`, `.moltbot/`, `.clawdbot/`, `openclaw.json`,
  `HEARTBEAT.md`, `SKILL.md`, a `*.skill.md` file or a `skills/` directory), says that
  only the gateway and CVE findings depend on them, and says that `~/.openclaw`,
  `~/.nemoclaw`, `~/.openshell`, `~/.moltbot` and `~/.clawdbot` are listed under Machine
  Posture and not scored. What `secure` scans is unchanged.

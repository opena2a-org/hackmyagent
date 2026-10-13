---
type: fixed
---
#### detect says a project with a scored governance file has governance gaps, not that its agents have no governance

- `hackmyagent detect` on a project whose `CLAUDE.md`, `.cursorrules`,
  `SOUL.md` or other governance file it had just read and scored titled the
  governance finding `N AI agent(s) without governance`, said the agents
  "have no rules", and listed each agent as `ungoverned`, on the screen whose
  Governance meter showed that file's score. The finding is now titled
  `N AI agent(s) with governance gaps`, its explanation names the file that
  was read and scored, and the AI Agents table lists each agent as
  `governance gaps`. A project with no governance file keeps
  `without governance`, the existing explanation, `ungoverned` and the
  `harden-soul` fix.
- Severity, exit codes, the detail line, the fix command and every `--json`
  key are unchanged: `agents[].governanceStatus` still reads `no governance`
  and `summary.ungoverned` still counts these agents. A script that matched
  the title `without governance` to find the finding should read
  `summary.ungoverned`, or `identity.governanceFile` to tell the two states
  apart (null when no governance file was found).

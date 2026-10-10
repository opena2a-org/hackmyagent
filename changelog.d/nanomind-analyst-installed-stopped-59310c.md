---
type: fixed
---
#### `nanomind status` and `--nanomind` report an installed analyst whose daemon is stopped, and name the command that starts it

- With the `nanomind-analyst` agent installed and its daemon not running,
  `hackmyagent nanomind status` printed `Daemon: not running` with
  `Run: hackmyagent nanomind setup`, and a scan run with `--nanomind` printed
  `Model not set up. Run: hackmyagent nanomind setup`. The install was
  complete, and setup runs it again. Both now say the analyst is installed and
  its daemon is stopped, and name `nanomind-analyst start`.
- A machine with no analyst installed gets the same setup message as before.
  So does a daemon that is running and not answering, and a run where
  `NANOMIND_GUARD_SOCK` names a different socket from the installed agent's.
- Scores, findings and exit codes are unchanged.

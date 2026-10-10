---
type: fixed
---
#### `nanomind setup` leaves an installed analyst whose daemon is stopped as it is, and names the command that starts it

- With the `nanomind-analyst` agent installed and its daemon not running,
  `hackmyagent nanomind setup` ran `nanomind-analyst install` again, or, when
  the installer was not on `PATH`, printed one-time install instructions.
  Setup now says the analyst is installed and its daemon is stopped, names
  `nanomind-analyst start`, and does not run the install. The command to run
  the install again is printed with it.
- A machine with no analyst installed is set up as before.

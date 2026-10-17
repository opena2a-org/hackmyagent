---
type: added
---
#### The every-project choice in `docs/chooser.json` carries an example for `detect` and for its next command, run on the five demo-agents projects, with the exit code and the captured output held to the build

- An example whose fixture is written at run time names the script of the
  fixture folder that writes it (`materialize`). The examples of the
  every-project choice name `test-fixtures/demo-agents/materialize.mjs`,
  which writes the five projects with their fake credentials into a new
  temporary folder. `scripts/chooser.mjs` refuses a `materialize` path that
  leaves the fixture folder.
- `detect` in those projects exits 1 and reports that 4 of 5 agent projects
  need action (4 critical, 5 high); its output is in
  `docs/captures/every-project.txt`. `secure deploy-runbook-agent` exits 1
  with 3 critical, 3 medium and 1 low finding; its output is in
  `docs/captures/every-project-next.txt`.
- `detect` adds the processes running on the machine to its report, so a run
  of `detect` finds first on PATH a `ps` that lists no process, and its
  sidecar says so. A new normalizer, `host-name`, prints the machine name on
  the `shadow ai audit` line as `<host>`; it applies to runs of `detect`
  only. The captures and sidecars of the eight examples that were already
  there are unchanged.

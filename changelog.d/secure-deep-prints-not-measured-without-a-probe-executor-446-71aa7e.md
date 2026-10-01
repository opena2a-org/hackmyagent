---
type: fixed
issue: 446
---
#### `secure --deep` prints NOT MEASURED without a probe executor (#446)

- **The `secure --deep` simulation verdict is a measurement, or it is not printed.** The
  behavioural channel rated the `SOUL.md` that `harden-soul` writes `MALICIOUS` while
  `scan-soul` rated the same file `100/100 HARDENED` (#446). With no NanoMind daemon on
  `127.0.0.1:47200` the engine was built with `useLLM: false`, and every probe went through a
  text search over the artifact's own wording: the probe input was never sent to anything,
  `14/20` counted the probe categories whose regex matched the file, and `95%` was
  `min(0.95, 0.6 + failRate * 0.5)`. A hardened SOUL.md failed because it names the attacks it
  forbids; a README failed because it has no must/never sentence and no YAML capabilities.
  Measured on main before this change, in a directory holding a three-line README, `harden-soul .`
  then `secure . --deep`: `[WARN] README.md — SUSPICIOUS (57% confidence, 5/20 probes failed)`
  and `[FAIL] SOUL.md — MALICIOUS (95% confidence, 14/20 probes failed)`, while `scan-soul .`
  printed Governance `100/100` and the score stayed `96/100`. The text-search path is deleted,
  with no fallback. Without an executor the channel runs no probe and prints one line,
  `[Simulation] NOT MEASURED — no probe executor (NanoMind daemon, Ollama, or ANTHROPIC_API_KEY); the Findings block is the verdict.`;
  with an executor each artifact prints `[INFO] <file> — N/20 probes flagged (advisory, not
  scored): <probe ids>`, with no severity word and no percentage. The score and the exit code are
  the static scan's in both cases: on the same tree after this change, `secure . --deep` and
  `secure .` both print `96/100` and exit 0, and `secure . --deep` prints `NOT MEASURED` once.
  `SimulationResult` carries `measured` and `executor`, `NOT_MEASURED` is a `SimulationVerdict`,
  the AST validator reads an unmeasured simulation as no simulation, and the opt-in training
  export writes nothing for an unmeasured result. Regression:
  `__tests__/simulation/engine.test.ts` (no backend gives `NOT_MEASURED` with zero probes run;
  the benign and malicious verdicts come from an injected backend's observed HTTP requests, not
  from the fixture's wording), `__tests__/cli/harden-soul-analyzer-direction.test.ts`
  (`scan-soul`, `check --nanomind` and `secure --deep` agree on a hardened tree, and the `--deep`
  score and exit code equal the plain ones), `__tests__/repo/446-release-record.test.ts`.

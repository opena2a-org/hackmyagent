---
type: fixed
issue: 995
---
#### The NanoMind core README lists the check ids each analyzer emits (#995)

- **The analyzer table in `src/nanomind-core/README.md` now matches the code.** It listed
  `AST-GOVERN` under the capability analyzer, which stopped emitting it when the governance
  analyzer took over weak and missing constraints; it stopped the scope analyzer at
  `AST-SCOPE-003` while the analyzer also emits `AST-SCOPE-004` for adversarial configuration
  directives; and it had no row for the stego analyzer (`UNICODE-STEGO-001`,
  `UNICODE-STEGO-004`, `UNICODE-STEGO-005`). The Tests section claimed 172 tests across 7 test
  files against 80 files on disk; it now names the directory and the command that counts them.
  A docs test fails when a row lists an id its analyzer does not emit, misses one it does, or
  an analyzer has no row. Tests: `__tests__/docs/nanomind-core-readme-analyzers.test.ts`.

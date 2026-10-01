---
type: changed
issue: 740
breaking: true
---
#### Breaking: check <dir> --json carries the full-scan shape

`check <dir>` ran only the semantic pass and labelled the result "Quick scan". On
a tree whose `.claude/settings.json` held a plaintext API key, 0.33.0 printed a
score with `318 static not run (quick scan)` beside it, and the credential check
that reads that file never ran (#740). A local directory target now runs the
same checks `secure` runs and reports the same score, and `check <dir> --json`
carries the same `coverage` object `secure --json` carries.

Removed from `coverage`: `mode` (was `quick-scan`), `semanticArtifactsCompiled`,
`staticChecksNotRun`, and `fullAuditCommand` (was `secure <path>`). Changed:
`coverage.unit` is `file`, not `artifact`, and `coverage.executions` is
populated (one record per executed check) instead of always empty. Added at the
top level: `score`, `rawScore`, `scoreClamped`, `maxScore` and `projectType`;
0.33.0 carried no `score` on this path. Added under `coverage`: `filesExamined`,
`filesReadByCategory`, `decode`, `suppressedFailures`, `unevidencedFailures`,
`unreachableCheckPrefixes` and `semanticCompileSetTruncated`.

`--no-scan` on a local path is refused: one stderr line, exit 2, and on `--json`
a `type: "local-path"` document with `error` and an unmeasured `coverage`
(`reason: "scan-skipped"`). 0.33.0 ignored the flag on a local path and
scanned. `opena2a check skill:./local --no-scan` forwards the flag and now
exits 2 where it exited 0.

`check <existing empty directory>` exits 0 with `measured: true` and a
score in a non-failing risk band where 0.33.0 exited 2 with `NOT MEASURED`: the scanner walked
the directory and ran its checks over it, and a recorded absence is a
measurement, the same reading `secure` gives the same tree. A CI job that
relied on exit 2 for an empty tree changes behaviour. A directory whose
inputs were discovered and could not be read still exits 2.

A consumer keys on the shape, not on the version string: `score` present,
`coverage.mode` absent, `coverage.unit === "file"` and
`coverage.executions.length > 0` identify the full-scan document. A script that
read `coverage.staticChecksNotRun` or `coverage.fullAuditCommand` to decide
whether to run `secure` afterwards drops that step; the score it wanted is
`score`.

Scores move on trees the scanner types `library` or `sdk` that carry an agent
artifact named by its path (`SKILL.md`, `*.skill.md`, `mcp.json`, `.mcp.json`,
`mcpServers.json`, `SOUL.md`, `agent.json`, `agent-config*`, `*.agent.*`):
the governance, scope and prompt analyses and the capability analyzer's
unconstrained-capability, injection-surface and scope-mismatch checks now run
on that artifact in `secure` and `check` alike, where the sdk/library gate
silenced them since 0.17.9. The path tests are the parser's existing ones:
`agent-config` and `.agent.` anywhere in the path, `agent.json`, `SKILL.md`
and `.skill.md` as suffixes, `SOUL.md` anywhere in the path, the three MCP
basenames exactly; a file that matches one of them by accident (a
`salesforce-agent.json` target descriptor, a `src/agent-configs/` directory)
was already classified as that kind and now reaches the same analyses. Measured on the
opena2a-corpus fixtures with `secure`, on a main that already carries the
DEP-001 manifest-subject contract (#756): `mcp/benign/readonly-fs-mcp` and
`mcp/buggy/ibm-mcp-clone` 98 to 94 (`AST-GOV-001` and `AST-GOV-003`, medium,
on a root `mcp.json` with no `SOUL.md`), `mcp/malicious/shell-rce-mcp` 43 to 30
(the same two `AST-GOV` findings plus `AST-SCOPE-001` critical,
`AST-SCOPE-003` high, `AST-CAP-002`), `soul/buggy/partial-controls-soul`
unchanged at 69 with `AST-GOV-004` high added; exit codes unchanged on all
twelve fixtures, and the ten benign oracle fixtures still carry no HIGH or
CRITICAL. ai-trust, which runs `secure` on npm packages, re-scores packages of
that shape. An artifact whose kind is inferred from its content rather than
its name (a `capabilities:` block in an unnamed `.md`, an `mcpServers` key in
an unnamed JSON file) keeps the gate. The fix line for the two governance
findings is the one printed: `hackmyagent harden-soul <dir>`, and
`secure --fix` applies it on such a tree as it does on an agent-typed one: a
root `SOUL.md` with no controls gains the missing governance sections.

Why this is a minor rather than a patch: `check <dir> --json` loses four
`coverage` keys and changes the unit of its measurement, `--no-scan` gains
an exit-2 refusal on a target form it used to accept, and scores move on
library-typed trees that carry a path-named agent artifact.

Verify (measured on the #740 fixture, a directory holding only
`.claude/settings.json` with a plaintext key):

```sh
hackmyagent check <dir> --json | jq -c '{score, unit: .coverage.unit, mode: .coverage.mode, notRun: .coverage.staticChecksNotRun}'
# 0.33.0:       {"score":null,"unit":"artifact","mode":"quick-scan","notRun":318}
# this release: {"score":67,"unit":"file","mode":null,"notRun":null}
```

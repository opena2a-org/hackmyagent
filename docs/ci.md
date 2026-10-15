# CI/CD integration

Running HackMyAgent in a pipeline: the flags that make a run non-interactive, a GitHub Actions recipe, a pull-request gate, a git-history pass for credentials, and a scan of the text a pipeline is handed. Exit codes: [commands.md](commands.md#exit-codes).

`secure` and `scan-soul` take `--ci` for non-interactive, byte-stable output; it also turns contribution off for that run. Most scanning commands take `--json`: `check`, `secure`, `attack`, `scan`, `fix-all`, `scan-soul`, `scan-text`, `harden-soul`, `red-team`, `wild`, `detect`, `trust`. `secure` and `attack` also take `-f, --format <format>`; on those two commands `--json` is shorthand for `--format json`. `--json` never changes the exit code. `--ci` mostly doesn't either; the one exception is `scan-soul`, which also exits 1 under `--ci` on a HIGH-severity SOUL finding that renders as a warning without the flag. To gate on severity, read the exit code; to gate on the score, use `--fail-below <n>`. A threshold only raises the exit code: a run that could not read one of its inputs still exits 2, not 1.

```yaml
name: Agent Security
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npx hackmyagent secure --json > security-report.json
      - run: npx hackmyagent secure -b oasb-1 --fail-below 70
```

SARIF output, a pre-commit hook, and the `.hmaignore` rules for suppressing a check or excluding a path: [`docs/use-cases/ci-pipeline.md`](use-cases/ci-pipeline.md). Suppressing a check changes what the report lists, not the score or the exit code; excluding a path is a scope statement, always disclosed on a `Scope` line.

## Gating a pull request on what it changes

`--range` reports only what the commits in a range introduce: both trees are read from git and scanned, and a finding the base already has (same check, file and cited line) is left out of the report, the score and the exit code. `--staged` does the same for the index against `HEAD`, for a pre-commit hook.

```yaml
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - run: npx hackmyagent secure --range origin/${{ github.base_ref }}...HEAD
```

## Finding a credential a commit added, even one deleted since

`npx hackmyagent secure --scan-history` also reads every commit reachable from any ref, so check out with `fetch-depth: 0` as above; a one-commit checkout reads that one commit only. Each credential is reported once, at the commit that added it, as `CRED-HIST-001` (critical, exit 1) cited `<commit>:<file>:<line>`, including one a later commit deleted. Rotate it at its issuer first: every clone that holds the commit can still read it. After rotating, `--since <ref>` reads only the commits not reachable from `<ref>`. The pass matches Anthropic, OpenAI, AWS access key, GitHub, Slack, Google API, Stripe live and SendGrid key shapes, and never prints the value. Recipe and sample output: [`docs/use-cases/ci-pipeline.md`](use-cases/ci-pipeline.md#credentials-committed-in-git-history).

## Scanning a text a pipeline was handed

`scan-text` takes ONE text rather than a tree (a pull-request body, an issue, a comment, an agent card) and reports every line that asks to be read as an instruction to the reader (`TEXT-001`) or as an authorization the text grants itself (`TEXT-002`). The operand is a path, or `-` for standard input. It reports no score on any channel.

```yaml
name: Scan the PR body
on: [pull_request]
jobs:
  scan-text:
    runs-on: ubuntu-latest
    steps:
      - env:
          PR_BODY: ${{ github.event.pull_request.body }}
        run: printf '%s' "$PR_BODY" | npx hackmyagent scan-text - --as pr-body --json
```

Exit codes, the same on both channels: **0** the text was read and no finding is high or critical; **1** the text was read and at least one is; **2** not measured: the operand does not exist or could not be read, so no text was scanned and no finding is reported. `--json` never changes the code, and neither does `--ci`. A clean result means only that no instruction-override or authority-claim payload was found in that text; it is not an approval of the text, or of the request the text belongs to.

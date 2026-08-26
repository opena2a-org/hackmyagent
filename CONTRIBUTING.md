# Contributing to HackMyAgent

Contributions are welcome, including from outside the organization.

For a small, well scoped change, open a pull request. For anything larger, a new check, a change
to scoring or severity, a new command, [open an issue](https://github.com/opena2a-org/hackmyagent/issues/new)
first and describe the case. A detection change is easier to review against a fixture that
reproduces it than against a diff.

If you do not have write access here you will work from a fork, and one of the required checks
cannot pass on a pull request opened from a fork. Read
[Pull requests from a fork](#pull-requests-from-a-fork) before you push.

## Development setup

```bash
# Clone the repo
git clone https://github.com/opena2a-org/hackmyagent.git
cd hackmyagent

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test
```

## Project structure

```
src/
  cli.ts          # CLI entry point
  index.ts        # Main exports
  hardening/      # Core scanning engine
  plugins/        # Plugin system (credvault, signcrypt, skillguard)
  semantic/       # Semantic analysis engine
  arp/            # Agent Runtime Protection
  oasb/           # Open Agent Security Benchmark
```

## Making changes

With write access to this repository, branch here. Without it, work from a fork and read
[Pull requests from a fork](#pull-requests-from-a-fork) before you push.

1. Branch from `main`: `git checkout -b fix/short-description`
2. Make your changes
3. Build and run the suite: `npm run build && npm test`
4. Commit with a message that says what changed and why
5. Open a pull request against `main`

## Pull requests from a fork

None of this is specific to your change. It is how this repository is configured, and it is
cheaper to read now than to work out from a red check later.

**The checks do not start on their own.** This repository requires a maintainer to approve
workflow runs for contributors outside the organization. Until someone does, your pull request
reports no checks at all, passing or failing.

**One required check cannot pass from a fork, ever.** `Claude Code Review` calls a model API
using a repository secret. GitHub does not pass repository secrets to a workflow triggered from
a fork: "With the exception of `GITHUB_TOKEN`, secrets are not passed to the runner when a
workflow is triggered from a forked repository"
([GitHub documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets)).
Without the key the review cannot run, and a review that did not run is recorded as
inconclusive, which this repository treats as not passing rather than as an approval. So the
check reports failure. That is a platform rule and a deliberate policy, not a judgement about
your change.

**No comment will appear explaining it.** The workflow posts its result as a pull request
comment, and on a fork run its token is read only, so the post fails. The result is written to
the check's own summary instead. Open `Claude Code Review` from the checks list and read the
summary there.

`Claude Code Review` is the only required check in that position. You can confirm that in your
own clone:

```bash
grep -rn "secrets\." .github/workflows/
```

Every match is in `pr-review.yml`, the workflow behind `Claude Code Review`. The workflows behind
the other required checks reference no secret. Those are the checks to read on your change. No
pull request has been opened from a fork on this repository yet, so you would be the first.

We do not merge past a failing required check. The route is:

1. Open the pull request from your fork. Leave `Claude Code Review` alone.
2. A maintainer reviews the change and replies on your pull request.
3. When it is ready, a maintainer pushes your commits to a branch in this repository and opens a
   pull request from there. The review runs on that one with the key available, and the change
   merges through the same checks as anything else.
4. We close your original as superseded and link to the pull request that merged it.

Your commits keep you as their author. If a merge would collapse them, we add a
`Co-authored-by:` trailer naming you.

If that is more process than the change is worth, a typo, a dead link, a wrong path in the docs,
[open an issue](https://github.com/opena2a-org/hackmyagent/issues/new) instead and we will carry
it in.

## Parity gate

Every pull request runs a check named `parity / parity`: the cross-CLI output-parity
harness (`.github/workflows/parity-gate.yml`), built against your branch. It runs
unconditionally, even for changes that cannot affect CLI output -- a check that is
always present under one name is what allows it to be required on `main`.

If the parity leg fails, your change altered JSON output that downstream consumers pin as
golden files. If the output change is intentional, a maintainer re-baselines the goldens
in the harness repository,
[opena2a-standards/opena2a-parity](https://github.com/opena2a-standards/opena2a-parity),
golden-first (the procedure is in that repository's README), then re-runs the failed
parity job on your pull request. If the change was not meant to alter output, fix the
regression in your branch.

## Code style

- TypeScript with strict mode
- Tests for all new functionality
- Clear, descriptive variable names

## Adding a security check

New security checks go in `src/hardening/scanner.ts`. Each check needs:

- Unique check ID (e.g., `SEC-004`)
- Name and description
- Severity level (critical, high, medium, low)
- Category
- Detection logic
- Optional auto-fix logic

Add corresponding tests in `__tests__/hardening/scanner.test.ts`.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. [SECURITY.md](SECURITY.md) has the
reporting route, what to include, and the disclosure policy.

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.

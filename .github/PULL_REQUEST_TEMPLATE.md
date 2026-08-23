## What this changes


## How it was verified


---

If you opened this from a fork: the checks do not start until a maintainer approves the run, and
`Claude Code Review` will then report failure with no comment explaining it. That check needs a
repository secret, and GitHub does not pass secrets to workflows triggered from a fork, so its
result is not a judgement about this change. Its text is in the check's own summary. The other
required checks are the ones to read. A maintainer picks the change up from there:
[Pull requests from a fork](https://github.com/opena2a-org/hackmyagent/blob/main/CONTRIBUTING.md#pull-requests-from-a-fork).

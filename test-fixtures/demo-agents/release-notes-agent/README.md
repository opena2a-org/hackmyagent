# release-notes-agent

Developer experience agent that drafts the weekly release notes from merged
pull requests and opens them as a pull request for review.

This is the reviewed project of the five. `SOUL.md` sets its behaviour,
`.opena2a/policy.yml` lists the capabilities it may use, and its one MCP server
reads the GitHub token from the environment, where a secrets vault injects it at
run time. No credential is stored in the project.

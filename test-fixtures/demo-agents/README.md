# demo-agents

Five small AI agent projects for a `hackmyagent detect` walkthrough, and the
fixture the `detect` recording in `docs/vhs/` is rendered from. Four projects
carry the problems `detect` and `secure` report. `release-notes-agent` is the
governed one and stores no credential.

Every key, token and password in this fixture is fake, and none is stored whole
in this repository. `templates.json` holds the files that carry a value, with
each value split into fragments. `materialize.mjs` joins the fragments at run
time, with the marker `FAKE` inside every value, and writes the five projects
into a directory outside any git work tree.

## Materialize

From the repository root:

```bash
node test-fixtures/demo-agents/materialize.mjs
```

The script prints the path of a new directory under the system temporary
directory. Pass a directory to write there instead; it must be absent or empty.
A target inside a git work tree is refused with exit 2 and nothing is written,
so the materialized files cannot be committed by mistake. `--omit <path>` leaves
one template out.

```bash
cd "$(node test-fixtures/demo-agents/materialize.mjs)"
npx hackmyagent detect
npx hackmyagent secure invoice-reconciliation-agent
```

`docs/vhs/record-detect.sh` with no argument materializes the fixture the same
way and renders the recording from it.

## What each project makes the scanner report

| Project | Set up for | Reported |
|---|---|---|
| `deploy-runbook-agent` | Claude Code | `detect`: CRITICAL shell MCP server, CRITICAL Anthropic key in `.claude/settings.json`, no governance file. `secure` adds the GitHub token in `.mcp.json`. |
| `invoice-reconciliation-agent` | Claude Code | `detect`: CRITICAL Anthropic key in `CLAUDE.md`, HIGH `Bash(*)` grant. `secure` adds the database password and the Slack token in `.mcp.json` and the env file that is not ignored. The QuickBooks token in the `reconcile-ledger` skill is not detected yet. |
| `hr-onboarding-assistant` | Cursor | `detect`: CRITICAL OpenAI key in `.cursorrules`. `secure` adds the Slack token in `mcp.json`. |
| `support-triage-agent` | SOUL.md | `detect`: HIGH governance file that subverts one of its own controls. `secure` adds the Zendesk token in `.mcp.json`. |
| `release-notes-agent` | SOUL.md | Governed 100/100, a capability policy in `.opena2a/policy.yml`, and its token read from the environment. |

`__tests__/docs/demo-agents-fixture.test.ts` pins these rows.

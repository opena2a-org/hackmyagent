# Security Policy

## Reporting a vulnerability

Report privately. Do not open a public issue for a suspected vulnerability.

**Preferred:** [Report a vulnerability](https://github.com/opena2a-org/hackmyagent/security/advisories/new)
via GitHub private vulnerability reporting. It is enabled on this repository and the report stays
private until an advisory publishes.

**Alternative:** info@opena2a.org

Please include:

- What you observed, and the command that produced it
- Steps to reproduce, including the version (`hackmyagent --version`)
- What you expected instead
- Any output you are willing to share, with credentials removed

**Do not send us real credentials.** If a report involves a credential, redact it and describe its
shape (vendor prefix and length) rather than pasting the value. If you believe one of your own
credentials was exposed by this tool, rotate it first, then report.

We acknowledge receipt within 48 hours and give a remediation timeline in that reply.

## Scope

This policy covers `hackmyagent` — the CLI, its published npm package, and this repository. Other
repositories in the [opena2a-org](https://github.com/opena2a-org) organization have their own
policies.

Reports about a *scanned target* — a package or repository this tool reports on — should go to that
project, not to us. Reports about how this tool **handles** what it scans, including anything it
writes into its own output, are in scope here.

## Supported versions

Fixes land on the latest published minor. Upgrade to the current release before reporting, and say
which version you reproduced on.

## Disclosure

We publish a GitHub Security Advisory for defects that affect users of the published package, and
request a CVE where one applies. Advisories publish once a fixed version is installable from npm, so
that the advisory and its remedy arrive together. We credit reporters who want credit.

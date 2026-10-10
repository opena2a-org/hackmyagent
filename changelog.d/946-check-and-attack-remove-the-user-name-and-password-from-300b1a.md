---
type: security
issue: 946
breaking: true
---
#### Breaking: `check` scans a forge URL with a user name and no `.git` instead of ending unmeasured with exit 2, and `attack --registry-report` names the target as `--publish` does (#946)

- Breaking: `check https://<user>:<token>@gitlab.com/<org>/<repo>`, a forge
  URL without `.git`, was not cloned. The forge was matched on the URL as
  typed, where the user name comes before the host, so the URL went to
  `fetch`, which refuses a URL with a user name or password, and the run
  ended unmeasured, with nothing scanned, and exited 2. The forge is now
  matched on the URL without them, so the repository is cloned and scanned,
  the run reports a measured verdict and it exits on its findings. The
  forges are `gitlab.com`, `bitbucket.org`, `codeberg.org`, `gitea.com` and
  `sr.ht`. A `github.com` URL with a user name is not matched as one: it
  still goes to `fetch`, ends unmeasured and exits 2.
- `check` printed a URL's user name and password as typed when a raw `?` or
  `#` in the password, or a `\` in a URL it fetches, ends the host part
  early, no `/` comes before the `@`, and what comes before that character
  does not parse as a host and port. git and `fetch` reject such a URL, and
  the error line and the `--json` `target` quoted it whole. That part of the
  URL is now shown as `***`, for example
  `https://***@gitlab.com/<org>/<repo>.git`. A URL whose part before that
  character does parse as a host and port, as in
  `https://<user>:123?<rest>@gitlab.com/<org>/<repo>.git`, or that has a `/`
  before the `@` is still shown as typed. In a URL it fetches, a `\` right
  after `//` counts the same way, so
  `http://\<user>:<password>@<host>/<file>` is shown as
  `http://***@<host>/<file>`, although `fetch` reads its user name, password
  and host.
- A scan an earlier version queued for a URL with an empty user name, under
  the name `@<host>/<org>/<repo>`, was sent again under that name, while a
  new scan of the same URL is named `<host>/<org>/<repo>`. Both now use
  `<host>/<org>/<repo>`. A name shaped like a scoped package,
  `@<scope>/<name>`, is kept as it is. Reading a queued name with many `@`
  characters no longer takes time that grows with their square.
- `attack --registry-report` sent the target URL to the registry as typed,
  in the scan name and in the report's `target`, while `attack --publish`
  sent it without its user name and password, so one run with
  `http://@localhost:<port>/v1/chat/completions` sent two names for one
  target. `--registry-report` now sends it without them too, in the name and
  in the report's `target`, and so does `--version-id` in the report's
  `target`. `attack` still prints the target as typed, user name and
  password included, in its `Target:` line. A target with a non-empty user
  name or password is refused by `fetch` before any connection, so that run
  measures nothing and sends the registry nothing.
- With contribution on, the NanoMind classification statistics that `check`
  and `secure` send went to the default registry even when `REGISTRY_URL`
  named another one. They now go to the registry `REGISTRY_URL` names.

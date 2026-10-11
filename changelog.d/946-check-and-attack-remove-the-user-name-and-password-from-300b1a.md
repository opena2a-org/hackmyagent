---
type: security
issue: 946
breaking: true
---
#### Breaking: `check` clones a forge URL with no `.git` that has a user name, a password, or an `@` with neither, and `attack --registry-report` names the target as `--publish` does (#946)

- Breaking: `check` did not clone a forge URL without `.git` that has a user
  name, a password or both before its `@`, such as
  `check https://<user>:<token>@gitlab.com/<org>/<repo>` or
  `check https://:<token>@gitlab.com/<org>/<repo>`. The forge was matched on
  the URL as typed, where they come before the host, so the URL went to
  `fetch`, which refuses a URL with a user name or password, and the run
  ended unmeasured, with nothing scanned, and exited 2. A forge URL with an
  `@` and no user name or password before it, such as
  `check https://@gitlab.com/<org>/<repo>`, went to `fetch` as well, which
  accepts it, so `check` fetched the web page the forge serves at that
  address and scanned it as one file. The forge is now matched on the URL
  with its user name, password and `@` removed, so these URLs are handed to
  `git clone`, and a repository it clones is scanned: the run reports a
  measured verdict and exits on its findings. That holds when the `@` is
  the only one before the first `/`, the host after it is exactly
  `gitlab.com`, `bitbucket.org`, `codeberg.org`, `gitea.com` or `sr.ht`, and
  a `/` follows the host. A forge URL without `.git` that has two or more
  `@` before the first `/` is not cloned, as when the user name is an email
  address, `https://<name>@<domain>:<token>@bitbucket.org/<org>/<repo>`, or
  the password holds a raw `@`. git ends the user name at the first `@`, so
  it does not read the forge as the host, and its error line quotes the URL
  from that `@` on, with the part of the password that follows it. Such a
  URL goes to `fetch`, as before, and when `fetch` reads a user name or
  password in it the run ends unmeasured and exits 2. With that `@` written
  as `%40`, as in
  `https://<name>%40<domain>:<token>@bitbucket.org/<org>/<repo>`, the URL
  has one `@` before the host and is handed to `git clone`. A forge URL
  without `.git` whose password holds a raw `?` or `#` is still not cloned,
  because the host part ends at that character. When the clone of a forge
  URL without `.git` that has an `@` before the host fails, `check` prints
  `Error: Could not clone repository from "<URL>".`, with the URL as it
  shows it, and not the failed command and git's own error lines. git can
  quote the user name there as `<scheme>://<user>@<host>` when it cannot ask
  for a password, or the whole URL when it holds a line break, with a
  control character in it replaced. A failed clone of a URL that ends in
  `.git` is reported as before, with the failed command and git's error
  lines. A `github.com` URL with a user name is not matched as one: it still
  goes to `fetch`, ends unmeasured and exits 2.
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

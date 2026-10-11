---
type: fixed
issue: 956
---
#### `check` does not print git's error lines for a failed clone of a `.git` URL with a user name or password, and says when git was not found or the clone timed out (#956)

- When the clone of a URL that ends in `.git` failed, and git's error neither
  reported the repository as not found nor held the word `timeout`, `check`
  printed the failed command and git's own error lines with only the URL as
  typed replaced. git can quote part of
  the user name or password there in another form: the URL from its first
  `@` on when two come before the host, as in
  `check https://<name>@<domain>:<token>@bitbucket.org/<org>/<repo>.git`,
  which printed
  `fatal: unable to access 'https://<domain>:<token>@bitbucket.org/<org>/<repo>.git/'`,
  or `<scheme>://<user>@<host>` when it cannot ask for a password. Earlier
  releases printed the same lines. When the clone of a URL that `check`
  shows without a user name, a password or an `@` that was typed, or with
  `***` in their place, fails, `check` now prints
  `Error: Could not clone repository from "<URL>".`, with the URL as it shows
  it, and `Verify the URL is accessible and contains a git repository.`, as
  it does for a forge URL without `.git`. git's reason for the failure is
  not printed for such a URL. When git's error holds the word `timeout`, as
  in `Timeout was reached`, such a clone prints
  `Error: Fetching "<URL>" timed out. The target may be too large.` and
  `Try downloading manually and scanning the local path:` instead, as a
  `.git` URL did before and as the same URL without a user name or password
  does. A failed clone of a URL that is shown as typed
  still prints the failed command and git's error lines. If a log that other
  people can read kept the output of such a run, rotate that password or
  token.
- With no `git` on PATH, `check` of a URL that ends in `.git`, or of a
  `gitlab.com`, `bitbucket.org`, `codeberg.org`, `gitea.com` or `sr.ht` URL
  without it, printed `Error scanning URL: spawn git ENOENT`. For one of
  those forge URLs with an `@` before its host it printed
  `Error: Could not clone repository from "<URL>".` and
  `Verify the URL is accessible and contains a git repository.`, about a URL
  that was never tried. All of them now print
  `Error: git was not found on PATH, so "<URL>" was not cloned.` and
  `Install git and run the command again, or download the repository and scan the local path:`
  with `hackmyagent check ./downloaded-dir/`.
- When `check` ended the clone of one of those URLs at its 120 s limit, it
  printed `Error scanning URL: Command failed: git clone ...`, the failed
  command, and for a forge URL without `.git` that has an `@` before its host
  the `Could not clone repository` lines. The `timed out` message was chosen
  on the word `timeout` in the error's text, which the error for a command
  ended at its time limit does not hold. Such a clone now prints
  `Error: Fetching "<URL>" timed out. The target may be too large.` and
  `Try downloading manually and scanning the local path:` with
  `hackmyagent check ./downloaded-dir/`.
- In all three cases the run ends unmeasured and exits 2, as before, and
  `--json` is unchanged. A `github.com` repository given as `<org>/<repo>` or
  `https://github.com/<org>/<repo>` is cloned on another route and is
  reported as before.

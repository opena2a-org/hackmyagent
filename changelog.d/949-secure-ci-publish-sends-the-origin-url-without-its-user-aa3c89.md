---
type: fixed
issue: 949
---
#### `secure --ci-publish` sends a `scheme://` origin URL without its user name and password (#949)

- `secure --ci-publish` sends an origin remote URL that starts with
  `scheme://`, such as `https://` or `ssh://`, without its user name and
  password; the registry receives the URL with them removed. A remote such as
  `https://<user>:<token>@gitlab.com/org/repo.git`, the form a CI checkout
  often writes, was sent in the request's `repoUrl` field as it was, token
  included. It is now sent as `https://gitlab.com/org/repo.git`. A remote
  without a user name or password is sent as before.
- A remote that does not start with `scheme://` is also sent as before. An
  scp-style remote such as `git@github.com:org/repo.git` keeps its user name,
  and a remote written with a `<transport>::` prefix keeps the user name and
  password in the address after the prefix.

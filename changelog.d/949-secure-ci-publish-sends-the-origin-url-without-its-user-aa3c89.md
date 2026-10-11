---
type: security
issue: 949,954
---
#### `secure --ci-publish` sends the origin URL without its user name and password (#949, #954)

- `secure --ci-publish` sends the origin remote URL to the registry in the
  request's `repoUrl` field. A remote such as
  `https://<user>:<token>@gitlab.com/org/repo.git`, the form a CI checkout
  often writes, was sent as it was, token included. It is now sent as
  `https://gitlab.com/org/repo.git`. The same holds for every remote that
  starts with `scheme://`, including a scheme that starts with a digit, which
  git accepts for remote helpers, and for the address of a remote written
  with git's `<transport>::<address>` syntax:
  `https::https://<user>:<token>@gitlab.com/org/repo.git` is sent as
  `https::https://gitlab.com/org/repo.git`. If you ran `--ci-publish` with a
  password or a long-lived token in the origin URL, rotate that password or
  token.
- A remote without a user name or password is sent as before, and so is an
  scp-style remote such as `git@github.com:org/repo.git`, which keeps its
  user name. `ssh://git@github.com/org/repo.git` is sent as
  `ssh://github.com/org/repo.git`.
- An origin that is a path on this machine, such as `/srv/git/org/repo.git`
  or a `file://` URL, names no repository the registry can link to. It was
  sent as it was. Now nothing is sent, and the run prints that origin is a
  local path, with the commands to check it and to set it to the
  repository's URL.

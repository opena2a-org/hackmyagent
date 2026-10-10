---
type: fixed
issue: 949
---
#### `secure --ci-publish` sends the origin URL without its user name and password (#949)

- `secure --ci-publish` sends the origin remote URL without its user name and
  password; the registry receives the URL with them removed. A remote such as
  `https://<user>:<token>@gitlab.com/org/repo.git`, the form a CI checkout
  often writes, was sent in the request's `repoUrl` field as it was, token
  included. It is now sent as `https://gitlab.com/org/repo.git`. A remote
  without a user name or password is sent as before.

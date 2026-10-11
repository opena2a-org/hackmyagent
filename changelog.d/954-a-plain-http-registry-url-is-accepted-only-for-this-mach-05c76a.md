---
type: security
issue: 954
breaking: true
---
#### A plain-http registry URL is accepted only for this machine (#954)

- A registry URL, from `REGISTRY_URL` or `--registry-url`, must use https,
  with one exception for local development: plain http to this machine. That
  exception was tested as a URL that starts with `http://localhost`, so
  `http://localhost.example.com` and `http://localhost@example.com` passed it,
  and a publishing run such as `secure --ci-publish` sent its scan result over
  plain http to the remote host. The host the URL names is now compared, and
  plain http is accepted for `localhost`, `127.0.0.1` and `[::1]` only.
- Any other plain-http URL ends the run with exit 1 and
  `Error: Registry URL must use HTTPS.`, as `http://example.com` already did,
  and so does a value that does not parse as a URL. `http://127.0.0.1` and
  `http://[::1]`, refused before, are now accepted.

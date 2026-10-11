---
type: security
---
#### `attack <url>` names the target to the registry without the URL's query string and fragment

- `hackmyagent attack <url> --publish` and `attack <url> --registry-report`
  sent the target URL's query string and fragment to the registry in the
  scan's name and in the report's `target`, so a key passed to the endpoint
  as `?api_key=...` went to the registry, and the printed `Profile:` link
  carried it too. The name is now the URL up to its first `?` or `#`, with
  the user name and password already removed as before. If you ran `attack`
  with `--publish` or `--registry-report` on a URL whose query held a key,
  rotate that key.

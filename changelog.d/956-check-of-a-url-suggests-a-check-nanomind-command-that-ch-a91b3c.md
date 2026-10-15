---
type: fixed
issue: 956
---
#### check of a URL suggests a `check ... --nanomind` command that check accepts (#956)

- After a scan of a URL, the `AI analysis:` line in Next Steps named the scan
  as its header does: a cloned repository as `<host>/<org>/<repo>`, without
  its scheme, and a downloaded file by its file name, as in
  `hackmyagent check gitlab.com/<org>/<repo> --nanomind`. `check` refuses both
  with `Invalid skill identifier: unrecognized format.` and exits 1. The line
  now names the URL that was scanned, with its user name and password taken
  out, as in `hackmyagent check https://gitlab.com/<org>/<repo> --nanomind`.

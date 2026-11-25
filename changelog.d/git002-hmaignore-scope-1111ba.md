---
type: fixed
---
#### GIT-002 counts only the committable files an `.hmaignore` scope rule leaves in scope

- A committable key file under a path the `.hmaignore` excludes kept GIT-002 in `findings` at high, with `.gitignore` listed in `details.files` in place of the excluded file. GIT-002 now sets its severity from in-scope files only: high when one of them is committable, low when patterns are missing and none is, and no finding otherwise. The excluded files are reported on their own GIT-002 record, which `outOfScope` counts at high. A `.gitignore:GIT-002` rule still never scopes out a committable file, and a scan with no `.hmaignore` reports GIT-002 as before.

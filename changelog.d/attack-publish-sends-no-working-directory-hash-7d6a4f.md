---
type: security
---
#### `attack <url> --publish` no longer sends a hash of the working directory as the target's content hash

- `hackmyagent attack <url> --publish` posted a `treeHash` to the registry:
  the content hash of the directory the shell was in when the command ran,
  which has nothing to do with the remote target. The publish path computes
  that hash from the directory it is given, and the attack command gave it
  the working directory. The payload for a URL target now carries no
  `treeHash`.
